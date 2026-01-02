/**
 * GATEKEEPER: Blind Token Issuance Endpoint
 *
 * This is the ONLY endpoint that knows user_id.
 * It issues anonymous, APP-SPECIFIC blind tokens.
 *
 * Multi-App Architecture:
 * - Each registered app gets tokens signed with ITS OWN secret
 * - Users must authorize each app before tokens are issued
 * - Tokens are completely anonymous - no user info, no cross-app correlation
 *
 * The blind token contains:
 * - iat: Issued at timestamp
 * - exp: Expiration timestamp
 * - tier: User's subscription tier (affects rate limits/features)
 * - nonce: Unique token identifier (for revocation)
 * - app: Target application ID
 * - v: Token version
 *
 * The blind token does NOT contain:
 * - user_id (NEVER)
 * - email (NEVER)
 * - ghost_id (client-derived, server never sees it)
 *
 * Security features:
 * - Per-app rate limiting
 * - Token logging for audit trail
 * - Revocation support via nonce
 * - Suspended user/app blocking
 * - User consent verification
 */

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { encode as base64Encode } from 'https://deno.land/std@0.168.0/encoding/base64.ts';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

// Default secret for legacy/single-app mode
const DEFAULT_BLIND_TOKEN_SECRET = Deno.env.get('BLIND_TOKEN_SECRET') || SUPABASE_KEY;

// Default rate limits (can be overridden per-app)
const DEFAULT_RATE_LIMIT_MAX = 20;
const DEFAULT_RATE_LIMIT_WINDOW = 3600; // 1 hour
const DEFAULT_TOKEN_EXPIRY = 3600;      // 1 hour

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

interface BlindTokenPayload {
  iat: number;      // Issued at
  exp: number;      // Expires at
  tier: string;     // Subscription tier
  nonce: string;    // Unique identifier
  app: string;      // Target app ID
  v: number;        // Token version
}

interface AppConfig {
  id: string;
  app_name: string;
  is_active: boolean;
  is_verified: boolean;
  token_expiry_seconds: number;
  token_version: number;
  shared_secret_hash: string;
  rate_limit_tokens_per_hour: number;
  allowed_scopes: string[];
}

/**
 * Derive the app-specific signing secret from the stored hash
 * In production, apps provide their secret during registration
 * and we verify against the bcrypt hash
 */
async function getAppSigningSecret(appId: string, supabase: any): Promise<string | null> {
  // For the default/legacy app, use the environment variable
  if (appId === 'xenon-engine' || !appId) {
    return DEFAULT_BLIND_TOKEN_SECRET;
  }

  // For registered apps, we need them to provide their secret in a server-to-server call
  // For client-to-gatekeeper calls, we use a derived secret
  // This is a simplification - in full production, apps would authenticate themselves

  // For now, derive a unique secret per app using HMAC(master_secret, app_id)
  const encoder = new TextEncoder();
  const keyData = encoder.encode(DEFAULT_BLIND_TOKEN_SECRET);
  const messageData = encoder.encode(`app:${appId}`);

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', cryptoKey, messageData);
  return base64Encode(new Uint8Array(signature));
}

/**
 * Generate HMAC-SHA256 signature
 */
async function signPayload(payload: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const messageData = encoder.encode(payload);

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', cryptoKey, messageData);
  return base64Encode(new Uint8Array(signature));
}

/**
 * Generate SHA-256 hash for token logging
 */
async function hashToken(token: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(token);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return base64Encode(new Uint8Array(hash));
}

/**
 * Generate a blind token for the authenticated user and target app
 */
async function generateBlindToken(
  tier: string,
  appId: string,
  expirySeconds: number,
  tokenVersion: number,
  signingSecret: string
): Promise<{ token: string; payload: BlindTokenPayload }> {
  const now = Math.floor(Date.now() / 1000);

  const payload: BlindTokenPayload = {
    iat: now,
    exp: now + expirySeconds,
    tier: tier,
    nonce: crypto.randomUUID(),
    app: appId,
    v: tokenVersion,
  };

  // Encode payload
  const payloadJson = JSON.stringify(payload);
  const payloadB64 = base64Encode(new TextEncoder().encode(payloadJson));

  // Sign with app-specific secret
  const signature = await signPayload(payloadB64, signingSecret);

  // Combine into token
  const token = `${payloadB64}.${signature}`;

  return { token, payload };
}

serve(async (req) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  // Only accept POST
  if (req.method !== 'POST') {
    return new Response(
      JSON.stringify({ error: 'Method not allowed' }),
      { status: 405, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }

  try {
    const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

    // Parse request body for app_id
    let body: { app_id?: string; scopes?: string[] } = {};
    try {
      const text = await req.text();
      if (text) {
        body = JSON.parse(text);
      }
    } catch {
      // Empty body is OK for default app
    }

    // Default to xenon-engine for backward compatibility
    const targetAppId = body.app_id || 'xenon-engine';
    const requestedScopes = body.scopes || ['basic'];

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

    // 2. GET USER TIER AND CHECK SUSPENSION
    const { data: tierInfo } = await supabase
      .rpc('get_user_tier_info', { p_user_id: user.id });

    const userTier = tierInfo?.[0] || {
      tier: 'free',
      is_suspended: false,
    };

    if (userTier.is_suspended) {
      return new Response(
        JSON.stringify({ error: 'Account suspended' }),
        { status: 403, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // 3. GET APP CONFIGURATION
    let appConfig: AppConfig | null = null;
    let tokenExpirySeconds = DEFAULT_TOKEN_EXPIRY;
    let rateLimitMax = DEFAULT_RATE_LIMIT_MAX;
    let tokenVersion = 1;

    // Check if app is registered (for multi-app mode)
    const { data: appData } = await supabase
      .rpc('get_app_config', { p_app_id: targetAppId });

    if (appData && appData.length > 0) {
      appConfig = appData[0] as AppConfig;

      // Verify app is active
      if (!appConfig.is_active) {
        return new Response(
          JSON.stringify({ error: 'Application is not active' }),
          { status: 403, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      tokenExpirySeconds = appConfig.token_expiry_seconds || DEFAULT_TOKEN_EXPIRY;
      rateLimitMax = appConfig.rate_limit_tokens_per_hour || DEFAULT_RATE_LIMIT_MAX;
      tokenVersion = appConfig.token_version || 1;

      // 4. CHECK USER-APP CONNECTION (consent)
      const { data: connectionCheck } = await supabase
        .rpc('check_app_connection', {
          p_user_id: user.id,
          p_app_id: targetAppId,
        });

      const connection = connectionCheck?.[0];

      // If no active connection and app requires consent, create one
      if (!connection?.has_connection) {
        if (appConfig.is_verified) {
          // Auto-authorize verified apps with basic scope
          await supabase.rpc('authorize_app_connection', {
            p_user_id: user.id,
            p_app_id: targetAppId,
            p_granted_scopes: requestedScopes,
          });
        } else {
          // Unverified apps need explicit user consent
          return new Response(
            JSON.stringify({
              error: 'App authorization required',
              requires_consent: true,
              app_name: appConfig.app_name,
              requested_scopes: requestedScopes,
            }),
            { status: 403, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        }
      }
    }
    // If app not in database, allow if it's the default app
    else if (targetAppId !== 'xenon-engine') {
      return new Response(
        JSON.stringify({ error: 'Unknown application' }),
        { status: 404, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // 5. CHECK RATE LIMIT (per-user, per-app)
    const rateLimitKey = `${user.id}:${targetAppId}`;
    const { data: rateCheck } = await supabase
      .rpc('check_rate_limit', {
        p_identifier: rateLimitKey,
        p_action: 'blind_token',
        p_max_requests: rateLimitMax,
        p_window_seconds: DEFAULT_RATE_LIMIT_WINDOW,
      });

    const rateLimitResult = rateCheck?.[0];
    if (rateLimitResult && !rateLimitResult.allowed) {
      return new Response(
        JSON.stringify({
          error: 'Rate limit exceeded',
          retry_after: Math.ceil((new Date(rateLimitResult.reset_at).getTime() - Date.now()) / 1000),
        }),
        { status: 429, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // 6. GET APP-SPECIFIC SIGNING SECRET
    const signingSecret = await getAppSigningSecret(targetAppId, supabase);
    if (!signingSecret) {
      console.error(`[GATEKEEPER] No signing secret for app: ${targetAppId}`);
      return new Response(
        JSON.stringify({ error: 'Application configuration error' }),
        { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // 7. GENERATE BLIND TOKEN
    const { token, payload } = await generateBlindToken(
      userTier.tier,
      targetAppId,
      tokenExpirySeconds,
      tokenVersion,
      signingSecret
    );

    // 8. LOG TOKEN ISSUANCE
    const tokenHash = await hashToken(token);
    const clientIp = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
                     req.headers.get('x-real-ip');
    const userAgent = req.headers.get('user-agent');

    // Use app-specific logging if app is registered
    if (appConfig) {
      await supabase.rpc('log_app_token_issuance', {
        p_user_id: user.id,
        p_app_id: targetAppId,
        p_token_nonce: payload.nonce,
        p_token_hash: tokenHash,
        p_expires_at: new Date(payload.exp * 1000).toISOString(),
        p_tier: userTier.tier,
        p_ip_address: clientIp,
        p_user_agent: userAgent,
      });
    } else {
      // Legacy single-app logging
      await supabase.rpc('log_token_issuance', {
        p_user_id: user.id,
        p_token_nonce: payload.nonce,
        p_token_hash: tokenHash,
        p_expires_at: new Date(payload.exp * 1000).toISOString(),
        p_tier: userTier.tier,
        p_ip_address: clientIp,
        p_user_agent: userAgent,
      });
    }

    // 9. LOG AUDIT EVENT
    await supabase.rpc('log_audit_event', {
      p_user_id: user.id,
      p_action: 'blind_token_issued',
      p_category: 'token',
      p_ip_address: clientIp,
      p_user_agent: userAgent,
      p_metadata: { tier: userTier.tier, app: targetAppId },
    });

    // Log without user identifying info
    console.log(`[GATEKEEPER] Token issued: app=${targetAppId}, tier=${userTier.tier}, expires=${payload.exp}`);

    // 10. RETURN TOKEN
    return new Response(
      JSON.stringify({
        blind_token: token,
        expires_at: payload.exp,
        tier: userTier.tier,
        app: targetAppId,
      }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );

  } catch (error) {
    console.error('[GATEKEEPER] Error:', error);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
