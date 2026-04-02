/**
 * Zule: Upgrade/Downgrade Subscription
 *
 * Changes the price on an existing Stripe subscription.
 * Bills the same card, prorates automatically.
 *
 * Request body:
 * - service_id: Which service to change ('aca')
 * - new_price_id: The Stripe price ID to switch to
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
    const rateLimited = await checkRateLimit(supabase, req, 'upgrade-subscription', user.id);
    if (rateLimited) return rateLimited;

    // Email verification required
    const unverified = requireVerifiedEmail(user, origin);
    if (unverified) return unverified;

    // Parse request
    let body: { service_id: string; new_price_id: string };
    try {
      body = await req.json();
    } catch {
      return errorResponse('Invalid JSON body', 400, origin);
    }

    if (!body.service_id || !body.new_price_id) {
      return errorResponse('service_id and new_price_id are required', 400, origin);
    }

    // Look up existing subscription
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
      return errorResponse('No active subscription found', 404, origin);
    }

    if (!sub.stripe_subscription_id) {
      return errorResponse('No Stripe subscription to modify', 400, origin);
    }

    if (sub.status !== 'active') {
      return errorResponse('Subscription is not active', 400, origin);
    }

    // Get the current subscription from Stripe to find the subscription item ID
    const stripeSubscription = await stripe.subscriptions.retrieve(sub.stripe_subscription_id);
    const subscriptionItemId = stripeSubscription.items.data[0]?.id;

    if (!subscriptionItemId) {
      return errorResponse('Could not find subscription item', 500, origin);
    }

    // Update the subscription price — Stripe prorates automatically
    await stripe.subscriptions.update(sub.stripe_subscription_id, {
      items: [{
        id: subscriptionItemId,
        price: body.new_price_id,
      }],
      proration_behavior: 'create_prorations',
      // If it was set to cancel, undo that
      cancel_at_period_end: false,
    });

    console.log(`[UPGRADE] User ${user.id} changed ${body.service_id} to price ${body.new_price_id}`);

    // The webhook will handle updating user_subscriptions with the new tier

    const clientIp = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || null;
    await adminClient.rpc('log_audit_event', {
      p_user_id: user.id,
      p_action: 'subscription_upgraded',
      p_category: 'billing',
      p_ip_address: clientIp,
      p_user_agent: req.headers.get('user-agent'),
      p_metadata: { service_id: body.service_id, new_price_id: body.new_price_id },
    });

    return jsonResponse({ success: true }, 200, origin);

  } catch (error) {
    console.error('[UPGRADE] Error:', error);

    if (error instanceof Stripe.errors.StripeError) {
      return errorResponse(`Stripe error: ${error.message}`, 400, origin);
    }

    return errorResponse('Internal server error', 500, origin);
  }
});
