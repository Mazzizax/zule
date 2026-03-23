/**
 * Zule: Cancel Subscription
 *
 * Cancels a Stripe subscription at period end.
 * User must be authenticated via JWT.
 *
 * Request body:
 * - service_id: Which service subscription to cancel ('aca', etc.)
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import Stripe from 'https://esm.sh/stripe@14.14.0?target=deno';
import {
  handleCors,
  jsonResponse,
  errorResponse,
} from '../_shared/cors.ts';
import { checkRateLimit } from '../_shared/rate-limit.ts';
import { requireVerifiedEmail } from '../_shared/security.ts';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const STRIPE_SECRET_KEY = Deno.env.get('STRIPE_SECRET_KEY');

const stripe = STRIPE_SECRET_KEY
  ? new Stripe(STRIPE_SECRET_KEY, {
      apiVersion: '2023-10-16',
      httpClient: Stripe.createFetchHttpClient(),
    })
  : null;

Deno.serve(async (req) => {
  const origin = req.headers.get('Origin');

  const corsResponse = handleCors(req);
  if (corsResponse) return corsResponse;

  if (req.method !== 'POST') {
    return errorResponse('Method not allowed', 405, origin);
  }

  try {
    if (!stripe || !STRIPE_SECRET_KEY) {
      return errorResponse('Payment system not configured', 500, origin);
    }

    // Authenticate
    const authHeader = req.headers.get('authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return errorResponse('Missing authorization header', 401, origin);
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, {
      global: { headers: { Authorization: authHeader } },
    });

    const { data: { user }, error: authError } = await supabase.auth.getUser();
    if (authError || !user) {
      return errorResponse('Invalid or expired token', 401, origin);
    }

    // Rate limiting
    const rateLimited = await checkRateLimit(supabase, req, 'cancel-subscription', user.id);
    if (rateLimited) return rateLimited;

    // Email verification required
    const unverified = requireVerifiedEmail(user, origin);
    if (unverified) return unverified;

    // Parse request
    let body: { service_id: string };
    try {
      body = await req.json();
    } catch {
      return errorResponse('Invalid JSON body', 400, origin);
    }

    if (!body.service_id) {
      return errorResponse('service_id is required', 400, origin);
    }

    // Look up the subscription
    const adminClient = createClient(SUPABASE_URL, SUPABASE_KEY, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    const { data: sub, error: subError } = await adminClient
      .from('user_subscriptions')
      .select('stripe_subscription_id, status')
      .eq('user_id', user.id)
      .eq('service_id', body.service_id)
      .single();

    if (subError || !sub) {
      return errorResponse('Subscription not found', 404, origin);
    }

    if (!sub.stripe_subscription_id) {
      return errorResponse('No Stripe subscription to cancel', 400, origin);
    }

    if (sub.status === 'canceled') {
      return errorResponse('Subscription already canceled', 400, origin);
    }

    // Cancel at period end via Stripe
    await stripe.subscriptions.update(sub.stripe_subscription_id, {
      cancel_at_period_end: true,
    });

    // Update our record
    await adminClient
      .from('user_subscriptions')
      .update({ status: 'canceled', updated_at: new Date().toISOString() })
      .eq('user_id', user.id)
      .eq('service_id', body.service_id);

    console.log(`[CANCEL] User ${user.id} canceled ${body.service_id}`);

    return jsonResponse({ success: true }, 200, origin);

  } catch (error) {
    console.error('[CANCEL] Error:', error);
    return errorResponse('Internal server error', 500, origin);
  }
});
