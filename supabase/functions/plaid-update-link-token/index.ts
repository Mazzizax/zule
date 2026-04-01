/**
 * Zule: Create Plaid Link Token for Update Mode
 *
 * Generates a Link token for re-authenticating or updating an existing Plaid Item.
 * Used when an item enters login_required, pending_expiration, or pending_disconnect state.
 *
 * Request body:
 * - account_id: The plaid_accounts row ID to update
 *
 * Response:
 * - link_token: Token for initializing Plaid Link in update mode
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
const PLAID_CLIENT_ID = Deno.env.get('PLAID_CLIENT_ID');
const PLAID_SECRET = Deno.env.get('PLAID_SECRET');
const PLAID_ENV = Deno.env.get('PLAID_ENV') || 'sandbox';

const PLAID_BASE_URL: Record<string, string> = {
  sandbox: 'https://sandbox.plaid.com',
  development: 'https://development.plaid.com',
  production: 'https://production.plaid.com',
};

Deno.serve(async (req) => {
  const origin = req.headers.get('Origin');

  const corsResponse = handleCors(req);
  if (corsResponse) return corsResponse;

  if (req.method !== 'POST') {
    return errorResponse('Method not allowed', 405, origin);
  }

  try {
    if (!PLAID_CLIENT_ID || !PLAID_SECRET) {
      return errorResponse('Plaid integration not configured', 500, origin);
    }

    // 1. AUTHENTICATE USER
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

    const rateLimited = await checkRateLimit(supabase, req, 'plaid-update-link-token', user.id);
    if (rateLimited) return rateLimited;

    const unverified = requireVerifiedEmail(user, origin);
    if (unverified) return unverified;

    // 2. PARSE REQUEST
    let body: { account_id: string };
    try {
      body = await req.json();
    } catch {
      return errorResponse('Invalid JSON body', 400, origin);
    }

    if (!body.account_id) {
      return errorResponse('account_id is required', 400, origin);
    }

    // 3. FETCH THE PLAID ACCOUNT (verify ownership)
    const adminClient = createClient(SUPABASE_URL, SUPABASE_KEY, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    const { data: account, error: accountError } = await adminClient
      .from('plaid_accounts')
      .select('plaid_access_token')
      .eq('id', body.account_id)
      .eq('user_id', user.id)
      .single();

    if (accountError || !account) {
      return errorResponse('Account not found', 404, origin);
    }

    // 4. CREATE UPDATE-MODE LINK TOKEN
    const baseUrl = PLAID_BASE_URL[PLAID_ENV] || PLAID_BASE_URL.sandbox;
    const webhookUrl = `${SUPABASE_URL}/functions/v1/plaid-webhook`;

    const plaidResponse = await fetch(`${baseUrl}/link/token/create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: PLAID_CLIENT_ID,
        secret: PLAID_SECRET,
        user: { client_user_id: user.id },
        client_name: 'Mazzizax',
        access_token: account.plaid_access_token,
        country_codes: ['US'],
        language: 'en',
        webhook: webhookUrl,
      }),
    });

    if (!plaidResponse.ok) {
      const err = await plaidResponse.json().catch(() => ({}));
      console.error('[PLAID-UPDATE] Plaid API error:', err);
      return errorResponse('Failed to create update link token', 500, origin);
    }

    const plaidData = await plaidResponse.json();

    // 5. AUDIT LOG
    const clientIp = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || null;
    await supabase.rpc('log_audit_event', {
      p_user_id: user.id,
      p_action: 'plaid_update_link_token_created',
      p_category: 'plaid',
      p_ip_address: clientIp,
      p_user_agent: req.headers.get('user-agent'),
      p_metadata: { account_id: body.account_id },
    });

    return jsonResponse({ link_token: plaidData.link_token }, 200, origin);

  } catch (error) {
    console.error('[PLAID-UPDATE] Error:', error);
    return errorResponse('Internal server error', 500, origin);
  }
});
