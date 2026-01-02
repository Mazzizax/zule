/**
 * GATEKEEPER: User App Connections Management
 *
 * Allows users to:
 * - View all apps they've authorized
 * - Revoke access to specific apps
 * - See usage statistics per app
 *
 * This gives users full control over their data sharing.
 */

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
};

serve(async (req) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  try {
    const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

    // Authenticate user
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

    const url = new URL(req.url);

    // GET: List all authorized apps for this user
    if (req.method === 'GET') {
      const { data: connections, error: connError } = await supabase
        .from('user_app_connections')
        .select(`
          id,
          granted_scopes,
          authorized_at,
          last_used_at,
          tokens_issued,
          is_active,
          revoked_at,
          app:app_id (
            app_id,
            app_name,
            app_description,
            organization_name,
            is_verified
          )
        `)
        .eq('user_id', user.id)
        .order('authorized_at', { ascending: false });

      if (connError) {
        console.error('[APP-CONNECTIONS] Error fetching:', connError);
        return new Response(
          JSON.stringify({ error: 'Failed to fetch connections' }),
          { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      // Format response
      const apps = (connections || []).map(conn => ({
        connection_id: conn.id,
        app_id: (conn.app as any)?.app_id,
        app_name: (conn.app as any)?.app_name,
        app_description: (conn.app as any)?.app_description,
        organization: (conn.app as any)?.organization_name,
        is_verified: (conn.app as any)?.is_verified,
        scopes: conn.granted_scopes,
        authorized_at: conn.authorized_at,
        last_used_at: conn.last_used_at,
        tokens_issued: conn.tokens_issued,
        is_active: conn.is_active,
        revoked_at: conn.revoked_at,
      }));

      return new Response(
        JSON.stringify({
          connections: apps,
          active_count: apps.filter(a => a.is_active).length,
          total_count: apps.length,
        }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // POST: Authorize a new app connection
    if (req.method === 'POST') {
      const body = await req.json();
      const { app_id, scopes = ['basic'] } = body;

      if (!app_id) {
        return new Response(
          JSON.stringify({ error: 'app_id is required' }),
          { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      // Check if app exists and is active
      const { data: appData } = await supabase
        .rpc('get_app_config', { p_app_id: app_id });

      if (!appData || appData.length === 0) {
        return new Response(
          JSON.stringify({ error: 'App not found' }),
          { status: 404, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      const app = appData[0];
      if (!app.is_active) {
        return new Response(
          JSON.stringify({ error: 'App is not active' }),
          { status: 403, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      // Validate requested scopes against allowed scopes
      const allowedScopes = app.allowed_scopes || ['basic'];
      const invalidScopes = scopes.filter((s: string) => !allowedScopes.includes(s));
      if (invalidScopes.length > 0) {
        return new Response(
          JSON.stringify({
            error: 'Invalid scopes requested',
            invalid: invalidScopes,
            allowed: allowedScopes,
          }),
          { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      // Create connection
      const { data: result, error: authzError } = await supabase
        .rpc('authorize_app_connection', {
          p_user_id: user.id,
          p_app_id: app_id,
          p_granted_scopes: scopes,
        });

      if (authzError) {
        console.error('[APP-CONNECTIONS] Authorization error:', authzError);
        return new Response(
          JSON.stringify({ error: 'Failed to authorize app' }),
          { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      const connection = result?.[0];
      return new Response(
        JSON.stringify({
          success: true,
          connection_id: connection?.connection_id,
          is_new: connection?.is_new,
          app_id: app_id,
          scopes: scopes,
        }),
        {
          status: connection?.is_new ? 201 : 200,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        }
      );
    }

    // DELETE: Revoke an app connection
    if (req.method === 'DELETE') {
      const appId = url.searchParams.get('app_id');

      if (!appId) {
        return new Response(
          JSON.stringify({ error: 'app_id query parameter is required' }),
          { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      // Revoke the connection
      const { data: revoked, error: revokeError } = await supabase
        .rpc('revoke_app_connection', {
          p_user_id: user.id,
          p_app_id: appId,
          p_revoked_by: 'user',
        });

      if (revokeError) {
        console.error('[APP-CONNECTIONS] Revoke error:', revokeError);
        return new Response(
          JSON.stringify({ error: 'Failed to revoke app' }),
          { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      if (!revoked) {
        return new Response(
          JSON.stringify({ error: 'No active connection found' }),
          { status: 404, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      console.log(`[APP-CONNECTIONS] User revoked app: ${appId}`);

      return new Response(
        JSON.stringify({
          success: true,
          message: 'App access revoked',
          app_id: appId,
        }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    return new Response(
      JSON.stringify({ error: 'Method not allowed' }),
      { status: 405, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );

  } catch (error) {
    console.error('[APP-CONNECTIONS] Error:', error);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
