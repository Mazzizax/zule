/**
 * Zule: Exchange Plaid Public Token
 *
 * Exchanges a public_token from Plaid Link for a permanent access_token.
 * Stores the access_token in user_profiles for future transaction pulls.
 *
 * Request body:
 * - public_token: Token from Plaid Link onSuccess callback
 *
 * Response:
 * - success: boolean
 * - institution_name: Name of the connected institution
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import {
  handleCors,
  jsonResponse,
  errorResponse,
} from '../_shared/cors.ts';

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
      console.error('[PLAID-EXCHANGE] Plaid not configured');
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
      console.error('[PLAID-EXCHANGE] Auth error:', authError?.message);
      return errorResponse('Invalid or expired token', 401, origin);
    }

    // 2. PARSE REQUEST
    let body: { public_token: string };
    try {
      body = await req.json();
    } catch {
      return errorResponse('Invalid JSON body', 400, origin);
    }

    if (!body.public_token) {
      return errorResponse('public_token is required', 400, origin);
    }

    // 3. EXCHANGE TOKEN via Plaid API
    const baseUrl = PLAID_BASE_URL[PLAID_ENV] || PLAID_BASE_URL.sandbox;

    const exchangeResponse = await fetch(`${baseUrl}/item/public_token/exchange`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: PLAID_CLIENT_ID,
        secret: PLAID_SECRET,
        public_token: body.public_token,
      }),
    });

    if (!exchangeResponse.ok) {
      const err = await exchangeResponse.json().catch(() => ({}));
      console.error('[PLAID-EXCHANGE] Plaid exchange error:', err);
      return errorResponse('Failed to exchange token', 500, origin);
    }

    const exchangeData = await exchangeResponse.json();
    const { access_token, item_id } = exchangeData;

    // 4. GET INSTITUTION NAME
    const itemResponse = await fetch(`${baseUrl}/item/get`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: PLAID_CLIENT_ID,
        secret: PLAID_SECRET,
        access_token,
      }),
    });

    let institutionName = 'Connected Card';
    if (itemResponse.ok) {
      const itemData = await itemResponse.json();
      const institutionId = itemData.item?.institution_id;

      if (institutionId) {
        const instResponse = await fetch(`${baseUrl}/institutions/get_by_id`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            client_id: PLAID_CLIENT_ID,
            secret: PLAID_SECRET,
            institution_id: institutionId,
            country_codes: ['US'],
          }),
        });

        if (instResponse.ok) {
          const instData = await instResponse.json();
          institutionName = instData.institution?.name || institutionName;
        }
      }
    }

    // 5. UPDATE USER PROFILE with Plaid credentials
    const { error: updateError } = await supabase
      .from('user_profiles')
      .update({
        plaid_access_token: access_token,
        plaid_item_id: item_id,
        plaid_institution_name: institutionName,
        plaid_connected_at: new Date().toISOString(),
      })
      .eq('id', user.id);

    if (updateError) {
      console.error('[PLAID-EXCHANGE] Profile update error:', updateError);
      return errorResponse('Failed to save connection', 500, origin);
    }

    console.log(`[PLAID-EXCHANGE] Connected ${institutionName} for user ${user.id.substring(0, 8)}...`);

    // 6. AUDIT LOG
    const clientIp = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || null;
    await supabase.rpc('log_audit_event', {
      p_user_id: user.id,
      p_action: 'plaid_account_connected',
      p_category: 'plaid',
      p_ip_address: clientIp,
      p_user_agent: req.headers.get('user-agent'),
      p_metadata: { institution_name: institutionName },
    });

    return jsonResponse({ success: true, institution_name: institutionName }, 200, origin);

  } catch (error) {
    console.error('[PLAID-EXCHANGE] Error:', error);
    return errorResponse('Internal server error', 500, origin);
  }
});
