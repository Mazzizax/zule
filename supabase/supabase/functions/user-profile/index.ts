/**
 * GATEKEEPER: User Profile Endpoint
 *
 * Handles user profile read/update operations.
 * This endpoint knows user_id (Gatekeeper privilege).
 *
 * Endpoints:
 * - GET: Retrieve user profile
 * - PUT/PATCH: Update user profile (limited fields)
 */

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'GET, PUT, PATCH, OPTIONS',
};

// Fields that users are allowed to update
const ALLOWED_UPDATE_FIELDS = [
  'display_name',
  'avatar_url',
  'timezone',
  'locale',
  'marketing_consent',
];

serve(async (req) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
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

    // 2. HANDLE REQUEST METHOD
    if (req.method === 'GET') {
      // Fetch profile
      const { data: profile, error: fetchError } = await supabase
        .from('user_profiles')
        .select(`
          display_name,
          avatar_url,
          timezone,
          locale,
          subscription_tier,
          subscription_status,
          subscription_expires_at,
          features,
          created_at,
          last_seen_at,
          marketing_consent,
          privacy_policy_accepted_at,
          terms_accepted_at
        `)
        .eq('id', user.id)
        .single();

      if (fetchError) {
        console.error('[PROFILE] Fetch error:', fetchError);
        return new Response(
          JSON.stringify({ error: 'Failed to fetch profile' }),
          { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      // Update last_seen
      await supabase
        .from('user_profiles')
        .update({ last_seen_at: new Date().toISOString() })
        .eq('id', user.id);

      return new Response(
        JSON.stringify({
          email: user.email,
          ...profile,
        }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );

    } else if (req.method === 'PUT' || req.method === 'PATCH') {
      // Update profile
      const body = await req.json();

      // Filter to only allowed fields
      const updates: Record<string, unknown> = {};
      for (const field of ALLOWED_UPDATE_FIELDS) {
        if (field in body) {
          updates[field] = body[field];
        }
      }

      if (Object.keys(updates).length === 0) {
        return new Response(
          JSON.stringify({ error: 'No valid fields to update' }),
          { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      // Special handling for legal acceptances
      if (body.accept_privacy_policy) {
        updates.privacy_policy_accepted_at = new Date().toISOString();
        updates.privacy_policy_version = body.privacy_policy_version || '1.0';
      }
      if (body.accept_terms) {
        updates.terms_accepted_at = new Date().toISOString();
        updates.terms_version = body.terms_version || '1.0';
      }

      const { data: updated, error: updateError } = await supabase
        .from('user_profiles')
        .update(updates)
        .eq('id', user.id)
        .select()
        .single();

      if (updateError) {
        console.error('[PROFILE] Update error:', updateError);
        return new Response(
          JSON.stringify({ error: 'Failed to update profile' }),
          { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      // Log audit event
      const clientIp = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim();
      const userAgent = req.headers.get('user-agent');

      await supabase.rpc('log_audit_event', {
        p_user_id: user.id,
        p_action: 'profile_updated',
        p_category: 'profile',
        p_ip_address: clientIp,
        p_user_agent: userAgent,
        p_metadata: { fields_updated: Object.keys(updates) },
      });

      return new Response(
        JSON.stringify({
          success: true,
          profile: updated,
        }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );

    } else {
      return new Response(
        JSON.stringify({ error: 'Method not allowed' }),
        { status: 405, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

  } catch (error) {
    console.error('[PROFILE] Error:', error);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
