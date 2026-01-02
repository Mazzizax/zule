/**
 * GATEKEEPER: Stripe Webhook Handler
 *
 * Handles Stripe subscription events to update user tiers.
 * This endpoint knows user_id (Gatekeeper privilege).
 *
 * Supported events:
 * - customer.subscription.created
 * - customer.subscription.updated
 * - customer.subscription.deleted
 * - invoice.payment_succeeded
 * - invoice.payment_failed
 */

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const STRIPE_WEBHOOK_SECRET = Deno.env.get('STRIPE_WEBHOOK_SECRET')!;

// Map Stripe price IDs to tiers
// Update these with your actual Stripe price IDs
const PRICE_TO_TIER: Record<string, string> = {
  'price_standard_monthly': 'standard',
  'price_standard_yearly': 'standard',
  'price_premium_monthly': 'premium',
  'price_premium_yearly': 'premium',
  'price_enterprise_monthly': 'enterprise',
  'price_enterprise_yearly': 'enterprise',
};

// Tier feature configurations
const TIER_FEATURES: Record<string, Record<string, unknown>> = {
  free: {
    max_events_per_day: 50,
    max_queue_depth: 10,
    priority_processing: false,
    advanced_analytics: false,
    api_access: false,
  },
  standard: {
    max_events_per_day: 500,
    max_queue_depth: 50,
    priority_processing: false,
    advanced_analytics: true,
    api_access: false,
  },
  premium: {
    max_events_per_day: 5000,
    max_queue_depth: 200,
    priority_processing: true,
    advanced_analytics: true,
    api_access: true,
  },
  enterprise: {
    max_events_per_day: -1, // Unlimited
    max_queue_depth: 1000,
    priority_processing: true,
    advanced_analytics: true,
    api_access: true,
  },
};

/**
 * Verify Stripe webhook signature
 */
async function verifyStripeSignature(
  payload: string,
  signature: string,
  secret: string
): Promise<boolean> {
  try {
    const parts = signature.split(',');
    const timestamp = parts.find(p => p.startsWith('t='))?.split('=')[1];
    const v1Sig = parts.find(p => p.startsWith('v1='))?.split('=')[1];

    if (!timestamp || !v1Sig) return false;

    // Check timestamp is within 5 minutes
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - parseInt(timestamp)) > 300) return false;

    // Compute expected signature
    const signedPayload = `${timestamp}.${payload}`;
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(signedPayload));
    const expectedSig = Array.from(new Uint8Array(sig))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    return expectedSig === v1Sig;
  } catch {
    return false;
  }
}

serve(async (req) => {
  // Only accept POST
  if (req.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }

  try {
    const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
    const payload = await req.text();
    const signature = req.headers.get('stripe-signature');

    if (!signature) {
      return new Response('Missing signature', { status: 400 });
    }

    // Verify webhook signature
    const isValid = await verifyStripeSignature(payload, signature, STRIPE_WEBHOOK_SECRET);
    if (!isValid) {
      console.error('[STRIPE] Invalid signature');
      return new Response('Invalid signature', { status: 400 });
    }

    const event = JSON.parse(payload);
    console.log(`[STRIPE] Event: ${event.type}`);

    // Handle different event types
    switch (event.type) {
      case 'customer.subscription.created':
      case 'customer.subscription.updated': {
        const subscription = event.data.object;
        const customerId = subscription.customer;
        const priceId = subscription.items.data[0]?.price?.id;
        const status = subscription.status;

        // Map price to tier
        const tier = PRICE_TO_TIER[priceId] || 'standard';
        const features = TIER_FEATURES[tier] || TIER_FEATURES.free;

        // Map Stripe status to our status
        const subscriptionStatus = status === 'active' ? 'active' :
                                   status === 'past_due' ? 'past_due' :
                                   status === 'trialing' ? 'trialing' : 'canceled';

        // Update user profile
        const { error } = await supabase
          .from('user_profiles')
          .update({
            subscription_tier: tier,
            subscription_status: subscriptionStatus,
            subscription_expires_at: subscription.current_period_end
              ? new Date(subscription.current_period_end * 1000).toISOString()
              : null,
            stripe_subscription_id: subscription.id,
            features: features,
          })
          .eq('stripe_customer_id', customerId);

        if (error) {
          console.error('[STRIPE] Update error:', error);
        } else {
          console.log(`[STRIPE] Updated customer ${customerId} to tier ${tier}`);
        }
        break;
      }

      case 'customer.subscription.deleted': {
        const subscription = event.data.object;
        const customerId = subscription.customer;

        // Downgrade to free tier
        const { error } = await supabase
          .from('user_profiles')
          .update({
            subscription_tier: 'free',
            subscription_status: 'canceled',
            subscription_expires_at: null,
            stripe_subscription_id: null,
            features: TIER_FEATURES.free,
          })
          .eq('stripe_customer_id', customerId);

        if (error) {
          console.error('[STRIPE] Downgrade error:', error);
        } else {
          console.log(`[STRIPE] Downgraded customer ${customerId} to free`);
        }
        break;
      }

      case 'invoice.payment_failed': {
        const invoice = event.data.object;
        const customerId = invoice.customer;

        // Mark as past due
        const { error } = await supabase
          .from('user_profiles')
          .update({ subscription_status: 'past_due' })
          .eq('stripe_customer_id', customerId);

        if (error) {
          console.error('[STRIPE] Past due update error:', error);
        }
        break;
      }

      case 'checkout.session.completed': {
        // Link Stripe customer to user
        const session = event.data.object;
        const customerId = session.customer;
        const userId = session.client_reference_id; // Pass user_id when creating checkout

        if (userId && customerId) {
          const { error } = await supabase
            .from('user_profiles')
            .update({ stripe_customer_id: customerId })
            .eq('id', userId);

          if (error) {
            console.error('[STRIPE] Customer link error:', error);
          } else {
            console.log(`[STRIPE] Linked customer ${customerId} to user ${userId}`);
          }
        }
        break;
      }

      default:
        console.log(`[STRIPE] Unhandled event type: ${event.type}`);
    }

    return new Response(JSON.stringify({ received: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('[STRIPE] Webhook error:', error);
    return new Response('Webhook error', { status: 500 });
  }
});
