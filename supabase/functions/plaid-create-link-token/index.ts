/**
 * Zule: Create Plaid Link Token
 *
 * Generates a Link token for the Plaid Link widget.
 * User must be authenticated via JWT.
 *
 * Response:
 * - link_token: Token for initializing Plaid Link
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

  // Handle CORS preflight
  const corsResponse = handleCors(req);
  if (corsResponse) return corsResponse;

  // Only accept POST
  if (req.method !== 'POST') {
    return errorResponse('Method not allowed', 405, origin);
  }

  try {
    // Check Plaid configuration
    if (!PLAID_CLIENT_ID || !PLAID_SECRET) {
      console.error('[PLAID-LINK] Plaid not configured');
      return errorResponse('Plaid integration not configured', 500, origin);
    }

    // 1. AUTHENTICATE USER
    const authHeader = req.headers.get('authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return errorResponse('Missing authorization header', 401, origin);
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, {
      global: {
        headers: { Authorization: authHeader },
      },
    });

    const { data: { user }, error: authError } = await supabase.auth.getUser();
    if (authError || !user) {
      console.error('[PLAID-LINK] Auth error:', authError?.message);
      return errorResponse('Invalid or expired token', 401, origin);
    }

    // Rate limiting
    const rateLimited = await checkRateLimit(supabase, req, 'plaid-create-link-token', user.id);
    if (rateLimited) return rateLimited;

    // Email verification required for financial operations
    const unverified = requireVerifiedEmail(user, origin);
    if (unverified) return unverified;

    // 2. CREATE LINK TOKEN via Plaid API
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
        products: ['transactions'],
        country_codes: ['US'],
        language: 'en',
        webhook: webhookUrl,
      }),
    });

    if (!plaidResponse.ok) {
      const err = await plaidResponse.json().catch(() => ({}));
      console.error('[PLAID-LINK] Plaid API error:', err);
      return errorResponse('Failed to create link token', 500, origin);
    }

    const plaidData = await plaidResponse.json();

    console.log(`[PLAID-LINK] Link token created for user ${user.id.substring(0, 8)}...`);

    // 3. AUDIT LOG
    const clientIp = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || null;
    await supabase.rpc('log_audit_event', {
      p_user_id: user.id,
      p_action: 'plaid_link_token_created',
      p_category: 'plaid',
      p_ip_address: clientIp,
      p_user_agent: req.headers.get('user-agent'),
      p_metadata: {},
    });

    return jsonResponse({ link_token: plaidData.link_token }, 200, origin);

  } catch (error) {
    console.error('[PLAID-LINK] Error:', error);
    return errorResponse('Internal server error', 500, origin);
  }
});
