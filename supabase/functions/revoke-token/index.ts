/**
 * GATEKEEPER: Token Revocation Endpoint
 *
 * Allows users to revoke their blind tokens (e.g., on logout from all devices).
 * Also used by admins to revoke tokens for security incidents.
 */

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { getCorsHeaders } from '../_shared/security.ts';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

// Allowed origins
const DEFAULT_ALLOWED_ORIGINS = [
  'http://localhost:3000',
  'http://localhost:5173',
  'http://localhost:8080',
  'http://localhost:19006',
];
const PRODUCTION_ORIGINS = Deno.env.get('ALLOWED_ORIGINS')?.split(',') || [];
const ALLOWED_ORIGINS = [...DEFAULT_ALLOWED_ORIGINS, ...PRODUCTION_ORIGINS];

// Rate limiting for revocation (prevent abuse)
const REVOKE_RATE_LIMIT_MAX = 10;  // 10 revocations per hour
const REVOKE_RATE_LIMIT_WINDOW = 3600;  // 1 hour

interface RevokeRequest {
  token_nonce?: string;
  revoke_all?: boolean;
}

/**
 * Create JSON response with CORS headers
 */
function jsonResponse(
  data: unknown,
  status: number,
  corsHeaders: Record<string, string>
): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

serve(async (req) => {
  const requestOrigin = req.headers.get('origin');
  const corsHeaders = getCorsHeaders(requestOrigin, { allowedOrigins: ALLOWED_ORIGINS });

  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (req.method !== 'POST') {
    return jsonResponse({ error: 'Method not allowed' }, 405, corsHeaders);
  }

  try {
    const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

    // 1. AUTHENTICATE USER
    const authHeader = req.headers.get('authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return jsonResponse({ error: 'Missing authorization header' }, 401, corsHeaders);
    }

    const jwt = authHeader.split(' ')[1];
    const { data: authData, error: authError } = await supabase.auth.getUser(jwt);

    if (authError || !authData.user) {
      return jsonResponse({ error: 'Invalid or expired token' }, 401, corsHeaders);
    }

    const user = authData.user;

    // 2. CHECK RATE LIMIT
    const { data: rateCheck, error: rateError } = await supabase
      .rpc('check_rate_limit', {
        p_identifier: `user:${user.id}`,
        p_action: 'token_revoke',
        p_max_requests: REVOKE_RATE_LIMIT_MAX,
        p_window_seconds: REVOKE_RATE_LIMIT_WINDOW,
      });

    if (rateError) {
      console.error('[REVOKE] Rate limit check error:', rateError);
      // Continue anyway
    } else if (rateCheck?.[0] && !rateCheck[0].allowed) {
      const retryAfter = Math.ceil(
        (new Date(rateCheck[0].reset_at).getTime() - Date.now()) / 1000
      );
      return jsonResponse(
        {
          error: 'Rate limit exceeded',
          retry_after: Math.max(0, retryAfter),
        },
        429,
        corsHeaders
      );
    }

    // 3. PARSE REQUEST
    let body: RevokeRequest;
    try {
      body = await req.json();
    } catch {
      return jsonResponse({ error: 'Invalid JSON body' }, 400, corsHeaders);
    }

    const { token_nonce, revoke_all } = body;

    if (!token_nonce && !revoke_all) {
      return jsonResponse(
        { error: 'Must provide token_nonce or revoke_all: true' },
        400,
        corsHeaders
      );
    }

    let revokedCount = 0;

    if (revoke_all) {
      // Revoke all active tokens for this user
      const { count, error } = await supabase
        .from('blind_token_log')
        .update({
          revoked_at: new Date().toISOString(),
          revocation_reason: 'user_revoke_all',
        })
        .eq('user_id', user.id)
        .is('revoked_at', null)
        .gt('expires_at', new Date().toISOString())
        .select('*', { count: 'exact', head: true });

      if (error) {
        console.error('[REVOKE] Revoke all error:', error);
        return jsonResponse({ error: 'Failed to revoke tokens' }, 500, corsHeaders);
      }

      revokedCount = count || 0;

    } else if (token_nonce) {
      // Validate token_nonce format (UUID)
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
      if (!uuidRegex.test(token_nonce)) {
        return jsonResponse({ error: 'Invalid token_nonce format' }, 400, corsHeaders);
      }

      // Verify token exists and belongs to user
      const { data: tokenData, error: tokenError } = await supabase
        .from('blind_token_log')
        .select('user_id, revoked_at')
        .eq('token_nonce', token_nonce)
        .maybeSingle();

      if (tokenError) {
        console.error('[REVOKE] Token lookup error:', tokenError);
        return jsonResponse({ error: 'Failed to lookup token' }, 500, corsHeaders);
      }

      if (!tokenData) {
        return jsonResponse({ error: 'Token not found' }, 404, corsHeaders);
      }

      // Ensure user owns this token
      if (tokenData.user_id !== user.id) {
        return jsonResponse({ error: 'Token not found' }, 404, corsHeaders);
      }

      // Check if already revoked
      if (tokenData.revoked_at) {
        return jsonResponse(
          { success: true, revoked_count: 0, message: 'Token already revoked' },
          200,
          corsHeaders
        );
      }

      // Revoke the token
      const { data: revokeResult, error: revokeError } = await supabase.rpc('revoke_blind_token', {
        p_token_nonce: token_nonce,
        p_reason: 'user_revocation',
      });

      if (revokeError) {
        console.error('[REVOKE] Revoke error:', revokeError);
        return jsonResponse({ error: 'Failed to revoke token' }, 500, corsHeaders);
      }

      revokedCount = revokeResult ? 1 : 0;
    }

    // 4. LOG AUDIT EVENT
    const clientIp = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || null;
    const userAgent = req.headers.get('user-agent') || null;

    const { error: auditError } = await supabase.rpc('log_audit_event', {
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

    if (auditError) {
      console.error('[REVOKE] Audit log error:', auditError);
    }

    // Log with truncated user ID
    console.log(`[REVOKE] User ${user.id.slice(0, 8)}... revoked ${revokedCount} tokens`);

    return jsonResponse(
      {
        success: true,
        revoked_count: revokedCount,
      },
      200,
      corsHeaders
    );

  } catch (error) {
    console.error('[REVOKE] Unexpected error:', error);
    const corsHeaders = getCorsHeaders(req.headers.get('origin'), { allowedOrigins: ALLOWED_ORIGINS });
    return jsonResponse({ error: 'Internal server error' }, 500, corsHeaders);
  }
});
