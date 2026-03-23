/**
 * Zule: Loyalty Cards CRUD
 *
 * GET - List user's loyalty cards
 * POST - Add a loyalty card
 * DELETE - Remove a loyalty card (pass id in body)
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import {
  handleCors,
  jsonResponse,
  errorResponse,
} from '../_shared/cors.ts';
import { checkRateLimit } from '../_shared/rate-limit.ts';
import { requireVerifiedEmail } from '../_shared/security.ts';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

Deno.serve(async (req) => {
  const origin = req.headers.get('Origin');

  const corsResponse = handleCors(req);
  if (corsResponse) return corsResponse;

  try {
    const authHeader = req.headers.get('authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return errorResponse('Missing authorization header', 401, origin);
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, {
      global: { headers: { Authorization: authHeader } },
    });

    const { data: { user }, error: authError } = await supabase.auth.getUser();
    if (authError || !user) {
      return errorResponse('Invalid or expired token', 401, origin);
    }

    // Rate limiting
    const rateLimited = await checkRateLimit(supabase, req, 'loyalty-cards', user.id);
    if (rateLimited) return rateLimited;

    const adminClient = createClient(SUPABASE_URL, SUPABASE_KEY, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    if (req.method === 'GET') {
      const { data, error } = await adminClient
        .from('user_loyalty_cards')
        .select('id, program_name, member_number, barcode_format, created_at')
        .eq('user_id', user.id)
        .order('created_at', { ascending: true });

      if (error) {
        console.error('[LOYALTY] Fetch error:', error);
        return errorResponse('Failed to fetch loyalty cards', 500, origin);
      }

      return jsonResponse(data || [], 200, origin);

    } else if (req.method === 'POST') {
      // Email verification required for write operations
      const unverified = requireVerifiedEmail(user, origin);
      if (unverified) return unverified;
      let body: { program_name: string; member_number: string; barcode_format?: string };
      try {
        body = await req.json();
      } catch {
        return errorResponse('Invalid JSON body', 400, origin);
      }

      if (!body.program_name || !body.member_number) {
        return errorResponse('program_name and member_number are required', 400, origin);
      }

      const { data, error } = await adminClient
        .from('user_loyalty_cards')
        .insert({
          user_id: user.id,
          program_name: body.program_name,
          member_number: body.member_number,
          barcode_format: body.barcode_format || null,
        })
        .select()
        .single();

      if (error) {
        console.error('[LOYALTY] Insert error:', error);
        return errorResponse('Failed to add loyalty card', 500, origin);
      }

      return jsonResponse(data, 201, origin);

    } else if (req.method === 'DELETE') {
      // Email verification required for write operations
      const unverifiedDel = requireVerifiedEmail(user, origin);
      if (unverifiedDel) return unverifiedDel;
      let body: { id: string };
      try {
        body = await req.json();
      } catch {
        return errorResponse('Invalid JSON body', 400, origin);
      }

      if (!body.id) {
        return errorResponse('id is required', 400, origin);
      }

      const { error } = await adminClient
        .from('user_loyalty_cards')
        .delete()
        .eq('id', body.id)
        .eq('user_id', user.id);

      if (error) {
        console.error('[LOYALTY] Delete error:', error);
        return errorResponse('Failed to remove loyalty card', 500, origin);
      }

      return jsonResponse({ success: true }, 200, origin);

    } else {
      return errorResponse('Method not allowed', 405, origin);
    }

  } catch (error) {
    console.error('[LOYALTY] Error:', error);
    return errorResponse('Internal server error', 500, origin);
  }
});
