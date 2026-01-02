/**
 * GATEKEEPER: Token Revocation Endpoint
 *
 * Allows users to revoke their blind tokens (e.g., on logout from all devices).
 * Also used by admins to revoke tokens for security incidents.
 */

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

serve(async (req) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (req.method !== 'POST') {
    return new Response(
      JSON.stringify({ error: 'Method not allowed' }),
      { status: 405, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }

  try {
    const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

    // 1. AUTHENTICATE USER
    const authHeader = req.headers.get('authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return new Response(
        JSON.stringify({ error: 'Missing authorization header' }),
        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const jwt = authHeader.split(' ')[1];
    const { data: { user }, error: authError } = await supabase.auth.getUser(jwt);

    if (authError || !user) {
      return new Response(
        JSON.stringify({ error: 'Invalid or expired token' }),
        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // 2. PARSE REQUEST
    const body = await req.json();
    const { token_nonce, revoke_all } = body;

    let revokedCount = 0;

    if (revoke_all) {
      // Revoke all active tokens for this user
      const { data, error } = await supabase
        .from('blind_token_log')
        .update({
          revoked_at: new Date().toISOString(),
          revocation_reason: 'user_revoke_all',
        })
        .eq('user_id', user.id)
        .is('revoked_at', null)
        .gt('expires_at', new Date().toISOString());

      if (error) {
        console.error('[REVOKE] Revoke all error:', error);
      }
      revokedCount = data?.length || 0;

    } else if (token_nonce) {
      // Revoke specific token
      const { data: tokenData } = await supabase
        .from('blind_token_log')
        .select('user_id')
        .eq('token_nonce', token_nonce)
        .single();

      // Ensure user owns this token
      if (tokenData?.user_id !== user.id) {
        return new Response(
          JSON.stringify({ error: 'Token not found or not owned by user' }),
          { status: 404, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      const success = await supabase.rpc('revoke_blind_token', {
        p_token_nonce: token_nonce,
        p_reason: 'user_revocation',
      });

      revokedCount = success ? 1 : 0;

    } else {
      return new Response(
        JSON.stringify({ error: 'Must provide token_nonce or revoke_all: true' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // 3. LOG AUDIT EVENT
    const clientIp = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim();
    const userAgent = req.headers.get('user-agent');

    await supabase.rpc('log_audit_event', {
      p_user_id: user.id,
      p_action: revoke_all ? 'tokens_revoked_all' : 'token_revoked',
      p_category: 'security',
      p_ip_address: clientIp,
      p_user_agent: userAgent,
      p_metadata: {
        revoked_count: revokedCount,
        token_nonce: token_nonce || null,
      },
    });

    console.log(`[REVOKE] User ${user.id.slice(0, 8)}... revoked ${revokedCount} tokens`);

    return new Response(
      JSON.stringify({
        success: true,
        revoked_count: revokedCount,
      }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );

  } catch (error) {
    console.error('[REVOKE] Error:', error);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
