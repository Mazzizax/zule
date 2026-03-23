/**
 * Zule: Create Stripe Checkout Session
 *
 * Creates a Stripe Checkout session for subscription purchases.
 * User must be authenticated via JWT.
 *
 * Request body:
 * - price_id: Stripe price ID for the subscription
 * - success_url: URL to redirect on success
 * - cancel_url: URL to redirect on cancel
 *
 * Response:
 * - url: Stripe Checkout URL to redirect user
 * - session_id: Stripe session ID
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

// Initialize Stripe
const stripe = STRIPE_SECRET_KEY
  ? new Stripe(STRIPE_SECRET_KEY, {
      apiVersion: '2023-10-16',
      httpClient: Stripe.createFetchHttpClient(),
    })
  : null;

/**
 * Server-side price → product mapping. Single source of truth.
 * The client CANNOT specify product_id — it is derived from price_id.
 * This prevents purchase limit bypass (e.g. sending a cheap price_id
 * with dragon_eye product_id to skip the 1-per-account limit).
 */
const PRICE_TO_PRODUCT: Record<string, { product_id: string; service_id: string; mode: 'subscription' | 'payment' }> = {
  // ACA subscriptions
  'price_1SuhgaDRpCHsf7InZqtoYRA3': { product_id: 'aca_standard', service_id: 'aca', mode: 'subscription' },
  'price_1SuhqgDRpCHsf7InpPL2w5d9': { product_id: 'aca_enthusiast', service_id: 'aca', mode: 'subscription' },
  'price_1SuhvuDRpCHsf7In7c52Ovn1': { product_id: 'aca_padawan', service_id: 'aca', mode: 'subscription' },
  // One-time purchases (add real Stripe price IDs when created in live mode)
  // 'price_xxx': { product_id: 'dragon_eye', service_id: 'goals', mode: 'payment' },
  // 'price_yyy': { product_id: 'secret_door_key', service_id: 'goals', mode: 'payment' },
  // 'price_zzz': { product_id: 'need_more_data', service_id: 'goals', mode: 'payment' },
};

// Purchase limits per product (for one-time purchases)
const PURCHASE_LIMITS: Record<string, number> = {
  'dragon_eye': 1,
  'secret_door_key': 33,
  'need_more_data': 5,
};

interface CheckoutRequest {
  price_id: string;
  service_id?: string;  // Optional — server derives from price_id for known prices
  product_id?: string;  // IGNORED — server derives from price_id
  mode?: 'subscription' | 'payment'; // Optional — server derives from price_id for known prices
  quantity?: number;
  success_url: string;
  cancel_url: string;
}

Deno.serve(async (req) => {
  const origin = req.headers.get('Origin');

  // Handle CORS preflight
  const corsResponse = handleCors(req);
  if (corsResponse) return corsResponse;

  // Only accept POST
  if (req.method !== 'POST') {
    return errorResponse('Method not allowed', 405, origin);
  }

  try {
    // Check Stripe configuration
    if (!stripe || !STRIPE_SECRET_KEY) {
      console.error('[CHECKOUT] Stripe not configured');
      return errorResponse('Payment system not configured', 500, origin);
    }

    // 1. AUTHENTICATE USER
    const authHeader = req.headers.get('authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return errorResponse('Missing authorization header', 401, origin);
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, {
      global: {
        headers: { Authorization: authHeader },
      },
    });

    const { data: { user }, error: authError } = await supabase.auth.getUser();
    if (authError || !user) {
      console.error('[CHECKOUT] Auth error:', authError?.message);
      return errorResponse('Invalid or expired token', 401, origin);
    }

    // Rate limiting
    const rateLimited = await checkRateLimit(supabase, req, 'create-checkout', user.id);
    if (rateLimited) return rateLimited;

    // Email verification required for purchases
    const unverified = requireVerifiedEmail(user, origin);
    if (unverified) return unverified;

    // 2. PARSE REQUEST
    let body: CheckoutRequest;
    try {
      body = await req.json();
    } catch {
      return errorResponse('Invalid JSON body', 400, origin);
    }

    const { price_id, quantity = 1, success_url, cancel_url } = body;

    if (!price_id) {
      return errorResponse('price_id is required', 400, origin);
    }
    if (!success_url) {
      return errorResponse('success_url is required', 400, origin);
    }
    if (!cancel_url) {
      return errorResponse('cancel_url is required', 400, origin);
    }

    // Resolve product/service/mode from server-side map
    // Client-supplied product_id and service_id are IGNORED for mapped prices
    const mapped = PRICE_TO_PRODUCT[price_id];
    const product_id = mapped?.product_id || null;
    const service_id = mapped?.service_id || body.service_id;
    const mode = mapped?.mode || body.mode || 'subscription';

    if (!service_id) {
      return errorResponse('Unknown price_id and no service_id provided', 400, origin);
    }

    // 3. GET USER PROFILE (check for existing Stripe customer)
    const { data: profile, error: profileError } = await supabase
      .from('user_profiles')
      .select('stripe_customer_id, subscription_status')
      .eq('id', user.id)
      .single();

    if (profileError) {
      console.error('[CHECKOUT] Profile fetch error:', profileError);
      return errorResponse('Failed to fetch user profile', 500, origin);
    }

    // 4. CHECK PURCHASE LIMITS (for one-time purchases)
    // product_id comes from server-side map only — cannot be spoofed
    if (mode === 'payment' && product_id) {
      const adminClient = createClient(SUPABASE_URL, SUPABASE_KEY, {
        auth: { autoRefreshToken: false, persistSession: false },
      });

      const { data: count } = await adminClient.rpc('get_purchase_count', {
        p_user_id: user.id,
        p_product_id: product_id,
      });

      const purchaseCount = count || 0;
      const limit = PURCHASE_LIMITS[product_id];
      if (limit !== undefined && purchaseCount >= limit) {
        return errorResponse(
          limit === 1 ? 'You already own this item' : `Purchase limit reached (${limit})`,
          400,
          origin
        );
      }
    }

    // 5. CREATE CHECKOUT SESSION
    const sessionParams: Stripe.Checkout.SessionCreateParams = {
      mode: mode,
      line_items: [
        {
          price: price_id,
          quantity: quantity,
        },
      ],
      success_url: `${success_url}${success_url.includes('?') ? '&' : '?'}session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: cancel_url,
      client_reference_id: user.id,
      metadata: {
        user_id: user.id,
        service_id: service_id,
        price_id: price_id,
        product_id: product_id || '',
      },
    };

    // Payment mode needs invoice for receipts
    if (mode === 'payment') {
      sessionParams.invoice_creation = { enabled: true };
    }

    // If user already has a Stripe customer, use it
    if (profile?.stripe_customer_id) {
      sessionParams.customer = profile.stripe_customer_id;
    } else {
      // Create new customer with user's email
      sessionParams.customer_email = user.email;
    }

    // Allow promotion codes
    sessionParams.allow_promotion_codes = true;

    // Create the session
    const session = await stripe.checkout.sessions.create(sessionParams);

    console.log(`[CHECKOUT] Session created for user ${user.id}: ${session.id}`);

    // 5. AUDIT LOG
    const clientIp = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || null;
    await supabase.rpc('log_audit_event', {
      p_user_id: user.id,
      p_action: 'checkout_session_created',
      p_category: 'subscription',
      p_ip_address: clientIp,
      p_user_agent: req.headers.get('user-agent'),
      p_metadata: {
        session_id: session.id,
        price_id: price_id,
      },
    });

    // 6. RETURN SESSION URL
    return jsonResponse(
      {
        url: session.url,
        session_id: session.id,
      },
      200,
      origin
    );

  } catch (error) {
    console.error('[CHECKOUT] Error:', error);

    // Handle Stripe-specific errors
    if (error instanceof Stripe.errors.StripeError) {
      return errorResponse(`Stripe error: ${error.message}`, 400, origin);
    }

    return errorResponse('Internal server error', 500, origin);
  }
});
