/**
 * GATEKEEPER: Application Registration Endpoint
 *
 * Allows third-party applications to register with Gatekeeper
 * to receive blind tokens for their users.
 *
 * Registration returns:
 * - app_id: The unique identifier for the app
 * - shared_secret: The secret used to sign tokens (SHOWN ONCE!)
 * - api_key: For server-to-server API calls (SHOWN ONCE!)
 *
 * SECURITY: This endpoint should be protected in production
 * Options:
 * 1. Require admin authentication
 * 2. Use invite codes
 * 3. Manual approval process
 * 4. Rate limit by IP
 */

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { createClient, SupabaseClient } from 'https://esm.sh/@supabase/supabase-js@2';
import {
  timingSafeEqual,
  isValidUrl,
  isValidEmail,
  getCorsHeaders,
  validateOrigin,
  getRateLimitIdentifier,
} from '../_shared/security.ts';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

// Admin API key for protected registration
const ADMIN_API_KEY = Deno.env.get('GATEKEEPER_ADMIN_KEY') || '';

// Default allowed origins (can be overridden per-app)
const DEFAULT_ALLOWED_ORIGINS = [
  'http://localhost:3000',
  'http://localhost:5173',
  'http://localhost:8080',
];

// Add production origins from environment
const PRODUCTION_ORIGINS = Deno.env.get('ALLOWED_ORIGINS')?.split(',') || [];
const ALLOWED_ORIGINS = [...DEFAULT_ALLOWED_ORIGINS, ...PRODUCTION_ORIGINS];

interface RegisterAppRequest {
  app_id: string;
  app_name: string;
  owner_email: string;
  callback_urls: string[];
  allowed_origins?: string[];
  organization_name?: string;
  description?: string;
}

interface ValidationResult {
  valid: boolean;
  error?: string;
}

/**
 * Validate all fields in the registration request
 */
function validateRegistrationRequest(body: RegisterAppRequest): ValidationResult {
  // Required fields
  if (!body.app_id || !body.app_name || !body.owner_email) {
    return {
      valid: false,
      error: 'Missing required fields: app_id, app_name, owner_email',
    };
  }

  // Validate app_id format (lowercase alphanumeric with hyphens)
  if (!/^[a-z0-9][a-z0-9-]{2,48}[a-z0-9]$/.test(body.app_id)) {
    return {
      valid: false,
      error: 'Invalid app_id format. Must be 4-50 lowercase alphanumeric characters with hyphens, starting and ending with alphanumeric.',
    };
  }

  // Validate app_name length
  if (body.app_name.length < 2 || body.app_name.length > 100) {
    return {
      valid: false,
      error: 'App name must be 2-100 characters',
    };
  }

  // Validate email format
  if (!isValidEmail(body.owner_email)) {
    return {
      valid: false,
      error: 'Invalid owner email format',
    };
  }

  // Validate callback URLs
  if (!body.callback_urls || body.callback_urls.length === 0) {
    return {
      valid: false,
      error: 'At least one callback URL is required',
    };
  }

  if (body.callback_urls.length > 10) {
    return {
      valid: false,
      error: 'Maximum 10 callback URLs allowed',
    };
  }

  for (const url of body.callback_urls) {
    if (!isValidUrl(url)) {
      return {
        valid: false,
        error: `Invalid callback URL: ${url}`,
      };
    }
  }

  // Validate allowed origins if provided
  if (body.allowed_origins) {
    if (body.allowed_origins.length > 20) {
      return {
        valid: false,
        error: 'Maximum 20 allowed origins',
      };
    }

    for (const origin of body.allowed_origins) {
      // Origins can be URLs or wildcard patterns like *.example.com
      if (!origin.startsWith('*.') && !isValidUrl(origin)) {
        return {
          valid: false,
          error: `Invalid allowed origin: ${origin}`,
        };
      }
    }
  }

  // Validate organization name if provided
  if (body.organization_name && body.organization_name.length > 100) {
    return {
      valid: false,
      error: 'Organization name must be under 100 characters',
    };
  }

  // Validate description if provided
  if (body.description && body.description.length > 500) {
    return {
      valid: false,
      error: 'Description must be under 500 characters',
    };
  }

  return { valid: true };
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
  const corsConfig = { allowedOrigins: ALLOWED_ORIGINS };
  const corsHeaders = getCorsHeaders(requestOrigin, corsConfig);

  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  try {
    const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
    const clientIp = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
                     req.headers.get('x-real-ip') ||
                     'unknown';

    // GET: List user's registered apps
    if (req.method === 'GET') {
      const authHeader = req.headers.get('authorization');
      if (!authHeader?.startsWith('Bearer ')) {
        return jsonResponse({ error: 'Authentication required' }, 401, corsHeaders);
      }

      const jwt = authHeader.split(' ')[1];
      const { data: { user }, error: authError } = await supabase.auth.getUser(jwt);

      if (authError || !user) {
        return jsonResponse({ error: 'Invalid or expired token' }, 401, corsHeaders);
      }

      // Get apps owned by this user
      const { data: apps, error: appsError } = await supabase
        .from('registered_apps')
        .select(`
          id,
          app_id,
          app_name,
          app_description,
          organization_name,
          callback_urls,
          allowed_origins,
          is_active,
          is_verified,
          total_tokens_issued,
          total_users_connected,
          created_at,
          last_token_issued_at
        `)
        .eq('owner_user_id', user.id)
        .order('created_at', { ascending: false });

      if (appsError) {
        console.error('[APP-REGISTER] Error fetching apps:', appsError);
        return jsonResponse({ error: 'Failed to fetch apps' }, 500, corsHeaders);
      }

      return jsonResponse({ apps: apps || [] }, 200, corsHeaders);
    }

    // POST: Register new app
    if (req.method !== 'POST') {
      return jsonResponse({ error: 'Method not allowed' }, 405, corsHeaders);
    }

    // Check rate limit for registration (by IP)
    const { data: rateCheck, error: rateError } = await supabase
      .rpc('check_rate_limit', {
        p_identifier: `ip:${clientIp}`,
        p_action: 'app_register',
        p_max_requests: 5,  // Max 5 registrations per hour per IP
        p_window_seconds: 3600,
      });

    if (rateError) {
      console.error('[APP-REGISTER] Rate limit check error:', rateError);
      // Continue anyway - don't block registration if rate limit check fails
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

    // Authenticate - either admin key or user JWT
    let ownerUserId: string | null = null;

    const adminKey = req.headers.get('x-admin-key');
    const authHeader = req.headers.get('authorization');

    // SECURITY FIX: Use timing-safe comparison for admin key
    if (adminKey && ADMIN_API_KEY && await timingSafeEqual(adminKey, ADMIN_API_KEY)) {
      // Admin registration - no owner
      ownerUserId = null;
    } else if (authHeader?.startsWith('Bearer ')) {
      // User registration
      const jwt = authHeader.split(' ')[1];
      const { data: { user }, error: authError } = await supabase.auth.getUser(jwt);

      if (authError || !user) {
        return jsonResponse({ error: 'Invalid or expired token' }, 401, corsHeaders);
      }

      ownerUserId = user.id;

      // Check how many apps this user has registered
      const { count, error: countError } = await supabase
        .from('registered_apps')
        .select('*', { count: 'exact', head: true })
        .eq('owner_user_id', user.id);

      if (countError) {
        console.error('[APP-REGISTER] Error counting apps:', countError);
        return jsonResponse({ error: 'Failed to check app limit' }, 500, corsHeaders);
      }

      if (count && count >= 10) {
        return jsonResponse(
          { error: 'Maximum apps per user exceeded (10)' },
          403,
          corsHeaders
        );
      }
    } else {
      return jsonResponse(
        { error: 'Authentication required (admin key or user JWT)' },
        401,
        corsHeaders
      );
    }

    // Parse request body
    let body: RegisterAppRequest;
    try {
      body = await req.json();
    } catch {
      return jsonResponse({ error: 'Invalid JSON body' }, 400, corsHeaders);
    }

    // Validate all fields
    const validation = validateRegistrationRequest(body);
    if (!validation.valid) {
      return jsonResponse({ error: validation.error }, 400, corsHeaders);
    }

    // Check if app_id already exists
    const { data: existing, error: existingError } = await supabase
      .from('registered_apps')
      .select('app_id')
      .eq('app_id', body.app_id)
      .maybeSingle();

    if (existingError) {
      console.error('[APP-REGISTER] Error checking existing:', existingError);
      return jsonResponse({ error: 'Failed to check app availability' }, 500, corsHeaders);
    }

    if (existing) {
      return jsonResponse({ error: 'App ID already registered' }, 409, corsHeaders);
    }

    // Register the app
    const { data: result, error: registerError } = await supabase
      .rpc('register_app', {
        p_app_id: body.app_id,
        p_app_name: body.app_name,
        p_owner_email: body.owner_email,
        p_callback_urls: body.callback_urls,
        p_allowed_origins: body.allowed_origins || [],
        p_owner_user_id: ownerUserId,
        p_organization_name: body.organization_name || null,
        p_description: body.description || null,
      });

    if (registerError) {
      console.error('[APP-REGISTER] Registration error:', registerError);
      return jsonResponse({ error: 'Failed to register app' }, 500, corsHeaders);
    }

    const appResult = result?.[0];
    if (!appResult) {
      return jsonResponse(
        { error: 'Registration failed - no result returned' },
        500,
        corsHeaders
      );
    }

    // Log audit event
    await supabase.rpc('log_audit_event', {
      p_user_id: ownerUserId,
      p_action: 'app_registered',
      p_category: 'admin',
      p_ip_address: clientIp,
      p_user_agent: req.headers.get('user-agent'),
      p_metadata: { app_id: body.app_id, app_name: body.app_name },
    });

    console.log(`[APP-REGISTER] New app registered: ${body.app_id}`);

    // Return credentials (ONLY TIME THEY ARE SHOWN)
    return jsonResponse(
      {
        success: true,
        app: {
          id: appResult.id,
          app_id: appResult.app_id,
          app_name: body.app_name,
        },
        credentials: {
          shared_secret: appResult.shared_secret,
          api_key: appResult.api_key,
        },
        warning: 'SAVE THESE CREDENTIALS NOW. They will NOT be shown again.',
        next_steps: [
          '1. Store the shared_secret securely in your app\'s environment',
          '2. Store the api_key for server-to-server Gatekeeper API calls',
          '3. Configure your app to request blind tokens from Gatekeeper',
          '4. Implement token verification using the shared_secret',
        ],
      },
      201,
      corsHeaders
    );

  } catch (error) {
    console.error('[APP-REGISTER] Unexpected error:', error);
    const corsHeaders = getCorsHeaders(req.headers.get('origin'), { allowedOrigins: ALLOWED_ORIGINS });
    return jsonResponse({ error: 'Internal server error' }, 500, corsHeaders);
  }
});
