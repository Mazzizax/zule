/**
 * Zule: Stripe Webhook Handler
 *
 * Handles Stripe subscription events to update user tiers.
 * This endpoint knows user_id (Zule privilege).
 *
 * Supported events:
 * - customer.subscription.created
 * - customer.subscription.updated
 * - customer.subscription.deleted
 * - invoice.payment_succeeded
 * - invoice.payment_failed
 * - checkout.session.completed
 * - payment_intent.succeeded (one-time purchases)
 * - payment_intent.payment_failed (one-time purchases)
 * - identity.verification_session.verified (KYC)
 * - identity.verification_session.requires_input (KYC failed)
 */

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { timingSafeHmacEqual } from '../_shared/security.ts';
import { checkRateLimit } from '../_shared/rate-limit.ts';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const STRIPE_WEBHOOK_SECRET = Deno.env.get('STRIPE_WEBHOOK_SECRET')!;

// Map Stripe price IDs to { service, tier }
// Update these with your actual Stripe price IDs
const PRICE_TO_SERVICE_TIER: Record<string, { service: string; tier: string }> = {
  // Goals tiers (one-time purchases, but keep mapping for reference)
  'price_standard_monthly': { service: 'goals', tier: 'standard' },
  'price_standard_yearly': { service: 'goals', tier: 'standard' },
  'price_premium_monthly': { service: 'goals', tier: 'premium' },
  'price_premium_yearly': { service: 'goals', tier: 'premium' },
  'price_enterprise_monthly': { service: 'goals', tier: 'enterprise' },
  'price_enterprise_yearly': { service: 'goals', tier: 'enterprise' },
  // ACA tiers
  'price_1SuhgaDRpCHsf7InZqtoYRA3': { service: 'aca', tier: 'standard' },
  'price_1SuhqgDRpCHsf7InpPL2w5d9': { service: 'aca', tier: 'enthusiast' },
  'price_1SuhvuDRpCHsf7In7c52Ovn1': { service: 'aca', tier: 'padawan' },
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
 * Verify Stripe webhook signature using timing-safe comparison
 */
async function verifyStripeSignature(
  payload: string,
  signature: string,
  secret: string
): Promise<boolean> {
  try {
    const parts = signature.split(',');
    const timestampPart = parts.find(p => p.startsWith('t='));
    const v1SigPart = parts.find(p => p.startsWith('v1='));

    if (!timestampPart || !v1SigPart) {
      console.error('[STRIPE] Missing signature parts');
      return false;
    }

    const timestamp = timestampPart.split('=')[1];
    const v1Sig = v1SigPart.split('=')[1];

    if (!timestamp || !v1Sig) {
      console.error('[STRIPE] Invalid signature format');
      return false;
    }

    // Check timestamp is within 5 minutes (300 seconds)
    const now = Math.floor(Date.now() / 1000);
    const signatureTimestamp = parseInt(timestamp, 10);

    if (isNaN(signatureTimestamp)) {
      console.error('[STRIPE] Invalid timestamp');
      return false;
    }

    if (Math.abs(now - signatureTimestamp) > 300) {
      console.error('[STRIPE] Signature timestamp too old or in future');
      return false;
    }

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

    // SECURITY FIX: Use timing-safe comparison
    return await timingSafeHmacEqual(expectedSig, v1Sig);
  } catch (error) {
    console.error('[STRIPE] Signature verification error:', error);
    return false;
  }
}

/**
 * Map Stripe subscription status to internal status
 */
function mapSubscriptionStatus(stripeStatus: string): string {
  switch (stripeStatus) {
    case 'active':
      return 'active';
    case 'past_due':
      return 'past_due';
    case 'trialing':
      return 'trialing';
    case 'canceled':
    case 'unpaid':
    case 'incomplete_expired':
      return 'canceled';
    case 'incomplete':
      return 'incomplete';
    case 'paused':
      return 'paused';
    default:
      return 'canceled';
  }
}

serve(async (req) => {
  // Only accept POST
  if (req.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }

  try {
    const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

    // Rate limiting (by IP — server-to-server, generous limit)
    const rateLimited = await checkRateLimit(supabase, req, 'stripe-webhook');
    if (rateLimited) return rateLimited;

    const payload = await req.text();
    const signature = req.headers.get('stripe-signature');

    if (!signature) {
      console.error('[STRIPE] Missing signature header');
      return new Response('Missing signature', { status: 400 });
    }

    if (!STRIPE_WEBHOOK_SECRET) {
      console.error('[STRIPE] Webhook secret not configured');
      return new Response('Webhook not configured', { status: 500 });
    }

    // Verify webhook signature
    const isValid = await verifyStripeSignature(payload, signature, STRIPE_WEBHOOK_SECRET);
    if (!isValid) {
      console.error('[STRIPE] Invalid signature');
      return new Response('Invalid signature', { status: 400 });
    }

    let event;
    try {
      event = JSON.parse(payload);
    } catch {
      console.error('[STRIPE] Invalid JSON payload');
      return new Response('Invalid payload', { status: 400 });
    }

    console.log(`[STRIPE] Event: ${event.type}, ID: ${event.id}`);

    // Idempotency check — skip if we've already processed this exact event
    const { count: existingCount } = await supabase
      .from('audit_logs')
      .select('id', { count: 'exact', head: true })
      .eq('action', 'stripe_webhook_processed')
      .filter('metadata->>stripe_event_id', 'eq', event.id);

    if (existingCount && existingCount > 0) {
      console.log(`[STRIPE] Event ${event.id} already processed, skipping`);
      return new Response(JSON.stringify({ received: true, duplicate: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Mark this event as processed BEFORE handling — prevents race conditions
    // on concurrent retries
    await supabase.from('audit_logs').insert({
      action: 'stripe_webhook_processed',
      action_category: 'subscription',
      metadata: { stripe_event_id: event.id, event_type: event.type },
      success: true,
    });

    // Handle different event types
    switch (event.type) {
      case 'customer.subscription.created':
      case 'customer.subscription.updated': {
        const subscription = event.data?.object;
        if (!subscription) {
          console.error('[STRIPE] Missing subscription data');
          break;
        }

        const customerId = subscription.customer;
        if (!customerId) {
          console.error('[STRIPE] Missing customer ID');
          break;
        }

        // Safely get price ID
        const priceId = subscription.items?.data?.[0]?.price?.id;
        const status = subscription.status || 'canceled';

        // Map price to service + tier
        const serviceTier = priceId ? PRICE_TO_SERVICE_TIER[priceId] : null;
        const serviceId = serviceTier?.service || subscription.metadata?.service_id || 'goals';
        const tier = serviceTier?.tier || 'standard';
        const features = TIER_FEATURES[tier] || TIER_FEATURES.free;

        // Map Stripe status to our status
        // If cancel_at_period_end is set, treat as canceled even though Stripe says active
        const subscriptionStatus = subscription.cancel_at_period_end
          ? 'canceled'
          : mapSubscriptionStatus(status);

        // Calculate expiration
        let expiresAt: string | null = null;
        if (subscription.current_period_end) {
          expiresAt = new Date(subscription.current_period_end * 1000).toISOString();
        }

        // Look up user_id from stripe_customer_id
        const { data: profileRow } = await supabase
          .from('user_profiles')
          .select('id')
          .eq('stripe_customer_id', customerId)
          .single();

        const userId = profileRow?.id;

        // Upsert into user_subscriptions
        if (userId) {
          const { error: upsertError } = await supabase
            .from('user_subscriptions')
            .upsert({
              user_id: userId,
              service_id: serviceId,
              tier: tier,
              status: subscriptionStatus,
              stripe_subscription_id: subscription.id,
              stripe_price_id: priceId || null,
              expires_at: expiresAt,
              updated_at: new Date().toISOString(),
            }, { onConflict: 'user_id,service_id' });

          if (upsertError) {
            console.error('[STRIPE] user_subscriptions upsert error:', upsertError);
          }
        }

        // Legacy: also update user_profiles for backward compat
        const { error } = await supabase
          .from('user_profiles')
          .update({
            subscription_tier: tier,
            subscription_status: subscriptionStatus,
            subscription_expires_at: expiresAt,
            stripe_subscription_id: subscription.id,
            features: features,
          })
          .eq('stripe_customer_id', customerId);

        if (error) {
          console.error('[STRIPE] Update error:', error);
        } else {
          console.log(`[STRIPE] Updated customer ${customerId} to ${serviceId}/${tier} (status: ${subscriptionStatus})`);

          // Log audit event
          await supabase.rpc('log_audit_event', {
            p_user_id: userId || null,
            p_action: 'subscription_updated',
            p_category: 'subscription',
            p_ip_address: null,
            p_user_agent: null,
            p_metadata: {
              customer_id: customerId,
              service_id: serviceId,
              tier,
              status: subscriptionStatus,
              subscription_id: subscription.id,
            },
          });
        }
        break;
      }

      case 'customer.subscription.deleted': {
        const subscription = event.data?.object;
        if (!subscription) {
          console.error('[STRIPE] Missing subscription data');
          break;
        }

        const customerId = subscription.customer;
        if (!customerId) {
          console.error('[STRIPE] Missing customer ID');
          break;
        }

        // Update user_subscriptions by stripe_subscription_id
        const { error: subDeleteError } = await supabase
          .from('user_subscriptions')
          .update({
            status: 'canceled',
            updated_at: new Date().toISOString(),
          })
          .eq('stripe_subscription_id', subscription.id);

        if (subDeleteError) {
          console.error('[STRIPE] user_subscriptions cancel error:', subDeleteError);
        }

        // Legacy: downgrade user_profiles to free tier
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
          console.log(`[STRIPE] Canceled subscription ${subscription.id} for customer ${customerId}`);

          // Log audit event
          await supabase.rpc('log_audit_event', {
            p_user_id: null,
            p_action: 'subscription_canceled',
            p_category: 'subscription',
            p_ip_address: null,
            p_user_agent: null,
            p_metadata: {
              customer_id: customerId,
              subscription_id: subscription.id,
            },
          });
        }
        break;
      }

      case 'invoice.payment_failed': {
        const invoice = event.data?.object;
        if (!invoice) {
          console.error('[STRIPE] Missing invoice data');
          break;
        }

        const customerId = invoice.customer;
        if (!customerId) {
          console.error('[STRIPE] Missing customer ID');
          break;
        }

        // Mark user_subscriptions as past_due by stripe_subscription_id
        if (invoice.subscription) {
          await supabase
            .from('user_subscriptions')
            .update({ status: 'past_due', updated_at: new Date().toISOString() })
            .eq('stripe_subscription_id', invoice.subscription);
        }

        // Legacy: mark user_profiles as past due
        const { error } = await supabase
          .from('user_profiles')
          .update({ subscription_status: 'past_due' })
          .eq('stripe_customer_id', customerId);

        if (error) {
          console.error('[STRIPE] Past due update error:', error);
        } else {
          console.log(`[STRIPE] Marked customer ${customerId} as past_due`);

          // Log audit event
          await supabase.rpc('log_audit_event', {
            p_user_id: null,
            p_action: 'payment_failed',
            p_category: 'subscription',
            p_ip_address: null,
            p_user_agent: null,
            p_metadata: {
              customer_id: customerId,
              invoice_id: invoice.id,
            },
          });
        }
        break;
      }

      case 'invoice.payment_succeeded': {
        const invoice = event.data?.object;
        if (!invoice) {
          console.error('[STRIPE] Missing invoice data');
          break;
        }

        const customerId = invoice.customer;
        if (!customerId) {
          console.error('[STRIPE] Missing customer ID');
          break;
        }

        // Ensure status is active if payment succeeded
        const { error } = await supabase
          .from('user_profiles')
          .update({ subscription_status: 'active' })
          .eq('stripe_customer_id', customerId)
          .eq('subscription_status', 'past_due');

        if (error) {
          console.error('[STRIPE] Payment success update error:', error);
        } else {
          console.log(`[STRIPE] Payment succeeded for customer ${customerId}`);
        }
        break;
      }

      case 'checkout.session.completed': {
        // Link Stripe customer to user
        const session = event.data?.object;
        if (!session) {
          console.error('[STRIPE] Missing session data');
          break;
        }

        const customerId = session.customer;
        const userId = session.client_reference_id; // Pass user_id when creating checkout

        if (userId && customerId) {
          // Link Stripe customer to user profile
          const { error } = await supabase
            .from('user_profiles')
            .update({ stripe_customer_id: customerId })
            .eq('id', userId);

          if (error) {
            console.error('[STRIPE] Customer link error:', error);
          } else {
            console.log(`[STRIPE] Linked customer ${customerId} to user ${userId}`);
          }

          // Create subscription row from checkout metadata
          // This is the reliable path — subscription events may arrive before
          // the customer_id is linked, so we create the row here where we have user_id directly
          const sessionServiceId = session.metadata?.service_id;
          const sessionSubscriptionId = session.subscription;
          if (sessionServiceId && sessionSubscriptionId) {
            // Get price/tier from metadata (set by create-checkout)
            const priceId = session.metadata?.price_id;
            const serviceTier = priceId ? PRICE_TO_SERVICE_TIER[priceId] : null;
            const tier = serviceTier?.tier || 'standard';

            const { error: subError } = await supabase
              .from('user_subscriptions')
              .upsert({
                user_id: userId,
                service_id: sessionServiceId,
                tier: tier,
                status: 'active',
                stripe_subscription_id: sessionSubscriptionId,
                stripe_price_id: priceId || null,
                updated_at: new Date().toISOString(),
              }, { onConflict: 'user_id,service_id' });

            if (subError) {
              console.error('[STRIPE] Checkout subscription upsert error:', subError);
            } else {
              console.log(`[STRIPE] Created subscription ${sessionServiceId}/${tier} for user ${userId}`);
            }
          }

          // Handle one-time purchases (no subscription ID means payment mode)
          const sessionProductId = session.metadata?.product_id;
          if (sessionServiceId && sessionProductId && !sessionSubscriptionId && session.payment_status === 'paid') {
            const { error: purchaseError } = await supabase.rpc('log_purchase', {
              p_user_id: userId,
              p_payment_intent_id: session.payment_intent || session.id,
              p_product_type: 'one_time',
              p_product_id: sessionProductId,
              p_amount_cents: session.amount_total || 0,
              p_app_id: null,
              p_metadata: { service_id: sessionServiceId, price_id: session.metadata?.price_id },
            });

            if (purchaseError) {
              // Unique constraint on payment_intent_id means this is a duplicate — not an error
              if (purchaseError.code === '23505' || purchaseError.message?.includes('unique') || purchaseError.message?.includes('duplicate')) {
                console.log(`[STRIPE] Purchase already logged for payment intent ${session.payment_intent} (idempotent)`);
              } else {
                console.error('[STRIPE] Purchase log error:', purchaseError);
              }
            } else {
              console.log(`[STRIPE] Logged purchase ${sessionProductId} for user ${userId}`);
            }

            // Auto-complete the purchase since checkout payment is already confirmed
            if (session.payment_intent) {
              await supabase.rpc('complete_purchase', {
                p_payment_intent_id: session.payment_intent,
              });
            }
          }

          // Log audit event
          await supabase.rpc('log_audit_event', {
            p_user_id: userId,
            p_action: 'stripe_customer_linked',
            p_category: 'subscription',
            p_ip_address: null,
            p_user_agent: null,
            p_metadata: { customer_id: customerId, service_id: sessionServiceId, product_id: sessionProductId },
          });
        } else {
          console.log('[STRIPE] Checkout completed but missing user_id or customer_id for linking');
        }
        break;
      }

      // ============================================
      // ONE-TIME PURCHASE EVENTS
      // ============================================
      case 'payment_intent.succeeded': {
        const paymentIntent = event.data?.object;
        if (!paymentIntent) {
          console.error('[STRIPE] Missing payment intent data');
          break;
        }

        const paymentIntentId = paymentIntent.id;

        // Complete the purchase in our database
        const { data: completed, error: completeError } = await supabase.rpc('complete_purchase', {
          p_payment_intent_id: paymentIntentId,
        });

        if (completeError) {
          console.error('[STRIPE] Complete purchase error:', completeError);
        } else if (completed) {
          console.log(`[STRIPE] Purchase completed for payment intent ${paymentIntentId}`);
        } else {
          // No matching purchase found - might be a subscription payment
          console.log(`[STRIPE] No pending purchase found for payment intent ${paymentIntentId}`);
        }
        break;
      }

      case 'payment_intent.payment_failed': {
        const paymentIntent = event.data?.object;
        if (!paymentIntent) {
          console.error('[STRIPE] Missing payment intent data');
          break;
        }

        const paymentIntentId = paymentIntent.id;

        // Mark the purchase as failed
        const { error: failError } = await supabase
          .from('user_purchases')
          .update({ status: 'failed' })
          .eq('stripe_payment_intent_id', paymentIntentId)
          .eq('status', 'pending');

        if (failError) {
          console.error('[STRIPE] Mark purchase failed error:', failError);
        } else {
          console.log(`[STRIPE] Purchase marked as failed for payment intent ${paymentIntentId}`);
        }
        break;
      }

      // ============================================
      // IDENTITY VERIFICATION EVENTS
      // ============================================
      case 'identity.verification_session.verified': {
        const verificationSession = event.data?.object;
        if (!verificationSession) {
          console.error('[STRIPE] Missing verification session data');
          break;
        }

        const sessionId = verificationSession.id;

        // Determine verification level based on what was verified
        let level = 'document';
        if (verificationSession.options?.document?.require_matching_selfie) {
          level = verificationSession.options?.document?.require_id_number ? 'full' : 'selfie';
        }

        // Update user's identity verification status
        const { data: updated, error: verifyError } = await supabase.rpc('update_identity_verification', {
          p_verification_session_id: sessionId,
          p_verified: true,
          p_level: level,
        });

        if (verifyError) {
          console.error('[STRIPE] Identity verification update error:', verifyError);
        } else if (updated) {
          console.log(`[STRIPE] Identity verified for session ${sessionId} (level: ${level})`);
        } else {
          console.log(`[STRIPE] No user found for verification session ${sessionId}`);
        }
        break;
      }

      case 'identity.verification_session.requires_input': {
        const verificationSession = event.data?.object;
        if (!verificationSession) {
          console.error('[STRIPE] Missing verification session data');
          break;
        }

        const sessionId = verificationSession.id;
        const lastError = verificationSession.last_error;

        console.log(`[STRIPE] Verification session ${sessionId} requires input: ${lastError?.code || 'unknown'}`);

        // Log the failure but don't update verified status
        // User can try again
        await supabase.rpc('log_audit_event', {
          p_user_id: null,
          p_action: 'identity_verification_needs_input',
          p_category: 'security',
          p_ip_address: null,
          p_user_agent: null,
          p_metadata: {
            session_id: sessionId,
            error_code: lastError?.code,
            error_reason: lastError?.reason,
          },
        });
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
