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
 * - User consent verification (explicit for unverified apps)
 * - CORS origin validation
 */

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { createClient, SupabaseClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { encode as base64Encode } from 'https://deno.land/std@0.168.0/encoding/base64.ts';
import { getCorsHeaders, validateOrigin } from '../_shared/security.ts';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

// Default secret for legacy/single-app mode
const DEFAULT_BLIND_TOKEN_SECRET = Deno.env.get('BLIND_TOKEN_SECRET') || SUPABASE_KEY;

// Default rate limits (can be overridden per-app)
const DEFAULT_RATE_LIMIT_MAX = 20;
const DEFAULT_RATE_LIMIT_WINDOW = 3600; // 1 hour
const DEFAULT_TOKEN_EXPIRY = 3600;      // 1 hour

// Default allowed origins
const DEFAULT_ALLOWED_ORIGINS = [
  'http://localhost:3000',
  'http://localhost:5173',
  'http://localhost:8080',
  'http://localhost:19006', // Expo
];
const PRODUCTION_ORIGINS = Deno.env.get('ALLOWED_ORIGINS')?.split(',') || [];
const GLOBAL_ALLOWED_ORIGINS = [...DEFAULT_ALLOWED_ORIGINS, ...PRODUCTION_ORIGINS];

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
  allowed_origins: string[];
}

interface TokenRequest {
  app_id?: string;
  scopes?: string[];
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

/**
 * Derive the app-specific signing secret
 * For the default app, uses the environment variable
 * For registered apps, derives using HMAC(master_secret, app_id)
 */
async function getAppSigningSecret(appId: string): Promise<string | null> {
  // For the default/legacy app, use the environment variable
  if (appId === 'xenon-engine' || !appId) {
    return DEFAULT_BLIND_TOKEN_SECRET;
  }

  // For registered apps, derive a unique secret per app using HMAC(master_secret, app_id)
  // NOTE: In production, apps should authenticate with their API key for server-to-server calls
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
  const requestOrigin = req.headers.get('origin');

  // Initial CORS headers (will be refined after we know the target app)
  let corsHeaders = getCorsHeaders(requestOrigin, { allowedOrigins: GLOBAL_ALLOWED_ORIGINS });

  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  // Only accept POST
  if (req.method !== 'POST') {
    return jsonResponse({ error: 'Method not allowed' }, 405, corsHeaders);
  }

  try {
    const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

    // Parse request body for app_id
    let body: TokenRequest = {};
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
      return jsonResponse({ error: 'Missing authorization header' }, 401, corsHeaders);
    }

    const jwt = authHeader.split(' ')[1];
    const { data: authData, error: authError } = await supabase.auth.getUser(jwt);

    if (authError || !authData.user) {
      return jsonResponse({ error: 'Invalid or expired token' }, 401, corsHeaders);
    }

    const user = authData.user;

    // 2. GET USER TIER AND CHECK SUSPENSION
    const { data: tierInfo, error: tierError } = await supabase
      .rpc('get_user_tier_info', { p_user_id: user.id });

    if (tierError) {
      console.error('[GATEKEEPER] Tier lookup error:', tierError);
    }

    const userTier = tierInfo?.[0] || {
      tier: 'free',
      is_suspended: false,
    };

    if (userTier.is_suspended) {
      return jsonResponse({ error: 'Account suspended' }, 403, corsHeaders);
    }

    // 3. GET APP CONFIGURATION
    let appConfig: AppConfig | null = null;
    let tokenExpirySeconds = DEFAULT_TOKEN_EXPIRY;
    let rateLimitMax = DEFAULT_RATE_LIMIT_MAX;
    let tokenVersion = 1;
    let appAllowedOrigins: string[] = GLOBAL_ALLOWED_ORIGINS;

    // Check if app is registered (for multi-app mode)
    const { data: appData, error: appError } = await supabase
      .rpc('get_app_config', { p_app_id: targetAppId });

    if (appError) {
      console.error('[GATEKEEPER] App config error:', appError);
    }

    if (appData && appData.length > 0) {
      appConfig = appData[0] as AppConfig;

      // Verify app is active
      if (!appConfig.is_active) {
        return jsonResponse({ error: 'Application is not active' }, 403, corsHeaders);
      }

      tokenExpirySeconds = appConfig.token_expiry_seconds || DEFAULT_TOKEN_EXPIRY;
      rateLimitMax = appConfig.rate_limit_tokens_per_hour || DEFAULT_RATE_LIMIT_MAX;
      tokenVersion = appConfig.token_version || 1;

      // Get app-specific allowed origins
      if (appConfig.allowed_origins && appConfig.allowed_origins.length > 0) {
        appAllowedOrigins = [...appConfig.allowed_origins, ...DEFAULT_ALLOWED_ORIGINS];
      }

      // SECURITY: Validate CORS origin against app's allowed origins
      if (requestOrigin && !validateOrigin(requestOrigin, { allowedOrigins: appAllowedOrigins })) {
        console.warn(`[GATEKEEPER] Origin ${requestOrigin} not allowed for app ${targetAppId}`);
        return jsonResponse({ error: 'Origin not allowed' }, 403, corsHeaders);
      }

      // Update CORS headers with app-specific origins
      corsHeaders = getCorsHeaders(requestOrigin, { allowedOrigins: appAllowedOrigins });

      // 4. CHECK USER-APP CONNECTION (consent)
      const { data: connectionCheck, error: connectionError } = await supabase
        .rpc('check_app_connection', {
          p_user_id: user.id,
          p_app_id: targetAppId,
        });

      if (connectionError) {
        console.error('[GATEKEEPER] Connection check error:', connectionError);
      }

      const connection = connectionCheck?.[0];

      // SECURITY FIX: Require explicit consent for ALL apps (including verified)
      // Previously verified apps were auto-authorized, which is a privacy concern
      if (!connection?.has_connection) {
        return jsonResponse(
          {
            error: 'App authorization required',
            requires_consent: true,
            app_id: targetAppId,
            app_name: appConfig.app_name,
            is_verified: appConfig.is_verified,
            requested_scopes: requestedScopes,
            allowed_scopes: appConfig.allowed_scopes,
            message: 'Please authorize this app before requesting tokens. Use the /app-connections endpoint to grant access.',
          },
          403,
          corsHeaders
        );
      }
    }
    // If app not in database, only allow the default app
    else if (targetAppId !== 'xenon-engine') {
      return jsonResponse({ error: 'Unknown application' }, 404, corsHeaders);
    }

    // 5. CHECK RATE LIMIT (per-user, per-app)
    const rateLimitKey = `${user.id}:${targetAppId}`;
    const { data: rateCheck, error: rateError } = await supabase
      .rpc('check_rate_limit', {
        p_identifier: rateLimitKey,
        p_action: 'blind_token',
        p_max_requests: rateLimitMax,
        p_window_seconds: DEFAULT_RATE_LIMIT_WINDOW,
      });

    if (rateError) {
      console.error('[GATEKEEPER] Rate limit error:', rateError);
      // Continue anyway - don't block if rate limit check fails
    }

    const rateLimitResult = rateCheck?.[0];
    if (rateLimitResult && !rateLimitResult.allowed) {
      const retryAfter = Math.ceil(
        (new Date(rateLimitResult.reset_at).getTime() - Date.now()) / 1000
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

    // 6. GET APP-SPECIFIC SIGNING SECRET
    const signingSecret = await getAppSigningSecret(targetAppId);
    if (!signingSecret) {
      console.error(`[GATEKEEPER] No signing secret for app: ${targetAppId}`);
      return jsonResponse({ error: 'Application configuration error' }, 500, corsHeaders);
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
                     req.headers.get('x-real-ip') ||
                     null;
    const userAgent = req.headers.get('user-agent') || null;

    // Use app-specific logging if app is registered
    if (appConfig) {
      const { error: logError } = await supabase.rpc('log_app_token_issuance', {
        p_user_id: user.id,
        p_app_id: targetAppId,
        p_token_nonce: payload.nonce,
        p_token_hash: tokenHash,
        p_expires_at: new Date(payload.exp * 1000).toISOString(),
        p_tier: userTier.tier,
        p_ip_address: clientIp,
        p_user_agent: userAgent,
      });

      if (logError) {
        console.error('[GATEKEEPER] Token log error:', logError);
        // Continue anyway - token was issued successfully
      }
    } else {
      // Legacy single-app logging
      const { error: logError } = await supabase.rpc('log_token_issuance', {
        p_user_id: user.id,
        p_token_nonce: payload.nonce,
        p_token_hash: tokenHash,
        p_expires_at: new Date(payload.exp * 1000).toISOString(),
        p_tier: userTier.tier,
        p_ip_address: clientIp,
        p_user_agent: userAgent,
      });

      if (logError) {
        console.error('[GATEKEEPER] Token log error:', logError);
      }
    }

    // 9. LOG AUDIT EVENT
    const { error: auditError } = await supabase.rpc('log_audit_event', {
      p_user_id: user.id,
      p_action: 'blind_token_issued',
      p_category: 'token',
      p_ip_address: clientIp,
      p_user_agent: userAgent,
      p_metadata: { tier: userTier.tier, app: targetAppId },
    });

    if (auditError) {
      console.error('[GATEKEEPER] Audit log error:', auditError);
    }

    // Log without user identifying info
    console.log(`[GATEKEEPER] Token issued: app=${targetAppId}, tier=${userTier.tier}, expires=${payload.exp}`);

    // 10. RETURN TOKEN
    return jsonResponse(
      {
        blind_token: token,
        expires_at: payload.exp,
        tier: userTier.tier,
        app: targetAppId,
      },
      200,
      corsHeaders
    );

  } catch (error) {
    console.error('[GATEKEEPER] Unexpected error:', error);
    return jsonResponse({ error: 'Internal server error' }, 500, corsHeaders);
  }
});
