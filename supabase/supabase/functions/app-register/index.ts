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
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

// Admin API key for protected registration
const ADMIN_API_KEY = Deno.env.get('GATEKEEPER_ADMIN_KEY');

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-admin-key',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
};

interface RegisterAppRequest {
  app_id: string;
  app_name: string;
  owner_email: string;
  callback_urls: string[];
  allowed_origins?: string[];
  organization_name?: string;
  description?: string;
}

serve(async (req) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  try {
    const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
    const clientIp = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
                     req.headers.get('x-real-ip');

    // GET: List user's registered apps
    if (req.method === 'GET') {
      const authHeader = req.headers.get('authorization');
      if (!authHeader?.startsWith('Bearer ')) {
        return new Response(
          JSON.stringify({ error: 'Authentication required' }),
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
        return new Response(
          JSON.stringify({ error: 'Failed to fetch apps' }),
          { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      return new Response(
        JSON.stringify({ apps: apps || [] }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // POST: Register new app
    if (req.method !== 'POST') {
      return new Response(
        JSON.stringify({ error: 'Method not allowed' }),
        { status: 405, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Check rate limit for registration (by IP)
    const { data: rateCheck } = await supabase
      .rpc('check_rate_limit', {
        p_identifier: `ip:${clientIp}`,
        p_action: 'app_register',
        p_max_requests: 5,  // Max 5 registrations per hour per IP
        p_window_seconds: 3600,
      });

    if (rateCheck?.[0] && !rateCheck[0].allowed) {
      return new Response(
        JSON.stringify({
          error: 'Rate limit exceeded',
          retry_after: Math.ceil((new Date(rateCheck[0].reset_at).getTime() - Date.now()) / 1000),
        }),
        { status: 429, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Authenticate - either admin key or user JWT
    let ownerUserId: string | null = null;

    const adminKey = req.headers.get('x-admin-key');
    const authHeader = req.headers.get('authorization');

    if (adminKey && ADMIN_API_KEY && adminKey === ADMIN_API_KEY) {
      // Admin registration - no owner
      ownerUserId = null;
    } else if (authHeader?.startsWith('Bearer ')) {
      // User registration
      const jwt = authHeader.split(' ')[1];
      const { data: { user }, error: authError } = await supabase.auth.getUser(jwt);

      if (authError || !user) {
        return new Response(
          JSON.stringify({ error: 'Invalid or expired token' }),
          { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      ownerUserId = user.id;

      // Check how many apps this user has registered
      const { count } = await supabase
        .from('registered_apps')
        .select('*', { count: 'exact', head: true })
        .eq('owner_user_id', user.id);

      if (count && count >= 10) {
        return new Response(
          JSON.stringify({ error: 'Maximum apps per user exceeded (10)' }),
          { status: 403, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }
    } else {
      return new Response(
        JSON.stringify({ error: 'Authentication required (admin key or user JWT)' }),
        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Parse request body
    const body: RegisterAppRequest = await req.json();

    // Validate required fields
    if (!body.app_id || !body.app_name || !body.owner_email) {
      return new Response(
        JSON.stringify({
          error: 'Missing required fields',
          required: ['app_id', 'app_name', 'owner_email'],
        }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Validate app_id format (lowercase alphanumeric with hyphens)
    if (!/^[a-z0-9][a-z0-9-]{2,48}[a-z0-9]$/.test(body.app_id)) {
      return new Response(
        JSON.stringify({
          error: 'Invalid app_id format',
          requirements: 'Lowercase alphanumeric with hyphens, 4-50 characters, must start/end with alphanumeric',
        }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Validate callback URLs
    if (!body.callback_urls || body.callback_urls.length === 0) {
      return new Response(
        JSON.stringify({ error: 'At least one callback URL is required' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Check if app_id already exists
    const { data: existing } = await supabase
      .from('registered_apps')
      .select('app_id')
      .eq('app_id', body.app_id)
      .single();

    if (existing) {
      return new Response(
        JSON.stringify({ error: 'App ID already registered' }),
        { status: 409, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
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
      console.error('[APP-REGISTER] Error:', registerError);
      return new Response(
        JSON.stringify({ error: 'Failed to register app' }),
        { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const appResult = result?.[0];
    if (!appResult) {
      return new Response(
        JSON.stringify({ error: 'Registration failed - no result returned' }),
        { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    console.log(`[APP-REGISTER] New app registered: ${body.app_id}`);

    // Return credentials (ONLY TIME THEY ARE SHOWN)
    return new Response(
      JSON.stringify({
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
      }),
      {
        status: 201,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      }
    );

  } catch (error) {
    console.error('[APP-REGISTER] Error:', error);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
