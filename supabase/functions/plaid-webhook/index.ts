/**
 * Zule: Plaid Webhook Handler
 *
 * Receives webhook events from Plaid and triggers appropriate actions.
 * Plaid signs webhooks with JWTs using ES256 (ECDSA P-256).
 *
 * Supported webhook types:
 * - TRANSACTIONS: DEFAULT_UPDATE, INITIAL_UPDATE, HISTORICAL_UPDATE, TRANSACTIONS_REMOVED
 * - ITEM: ERROR, NEW_ACCOUNTS_AVAILABLE, PENDING_EXPIRATION, USER_PERMISSION_REVOKED, WEBHOOK_UPDATE_ACKNOWLEDGED
 * - HOLDINGS: DEFAULT_UPDATE
 * - INVESTMENTS_TRANSACTIONS: DEFAULT_UPDATE
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const PLAID_CLIENT_ID = Deno.env.get('PLAID_CLIENT_ID');
const PLAID_SECRET = Deno.env.get('PLAID_SECRET');
const PLAID_ENV = Deno.env.get('PLAID_ENV') || 'sandbox';

const PLAID_BASE_URL: Record<string, string> = {
  sandbox: 'https://sandbox.plaid.com',
  development: 'https://development.plaid.com',
  production: 'https://production.plaid.com',
};

// Cache for JWK keys (kid -> JWK), refreshed on miss
const jwkCache: Record<string, CryptoKey> = {};

/**
 * Fetch and cache Plaid's JWK verification key by key ID
 */
async function getVerificationKey(kid: string): Promise<CryptoKey | null> {
  if (jwkCache[kid]) return jwkCache[kid];

  const baseUrl = PLAID_BASE_URL[PLAID_ENV] || PLAID_BASE_URL.sandbox;
  const response = await fetch(`${baseUrl}/webhook_verification_key/get`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: PLAID_CLIENT_ID,
      secret: PLAID_SECRET,
      key_id: kid,
    }),
  });

  if (!response.ok) {
    console.error(`[PLAID-WEBHOOK] Failed to fetch JWK for kid=${kid}: ${response.status}`);
    return null;
  }

  const data = await response.json();
  const jwk = data.key;

  if (!jwk) {
    console.error('[PLAID-WEBHOOK] No key in response');
    return null;
  }

  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  );

  jwkCache[kid] = key;
  return key;
}

/**
 * Base64url decode
 */
function base64urlDecode(str: string): Uint8Array {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4;
  const padded = pad ? base64 + '='.repeat(4 - pad) : base64;
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Verify Plaid webhook JWT signature and body hash
 */
async function verifyPlaidWebhook(
  body: string,
  jwtToken: string,
): Promise<{ valid: boolean; claims?: Record<string, unknown> }> {
  try {
    const parts = jwtToken.split('.');
    if (parts.length !== 3) {
      console.error('[PLAID-WEBHOOK] JWT does not have 3 parts');
      return { valid: false };
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    // Decode header
    const header = JSON.parse(new TextDecoder().decode(base64urlDecode(headerB64)));

    // Verify algorithm is ES256
    if (header.alg !== 'ES256') {
      console.error(`[PLAID-WEBHOOK] Unexpected algorithm: ${header.alg}`);
      return { valid: false };
    }

    // Get verification key by kid
    const key = await getVerificationKey(header.kid);
    if (!key) {
      return { valid: false };
    }

    // Verify signature
    const signedData = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const signature = base64urlDecode(signatureB64);

    const valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      signature,
      signedData,
    );

    if (!valid) {
      console.error('[PLAID-WEBHOOK] JWT signature verification failed');
      return { valid: false };
    }

    // Decode claims
    const claims = JSON.parse(new TextDecoder().decode(base64urlDecode(payloadB64)));

    // Check iat — reject webhooks older than 5 minutes
    const now = Math.floor(Date.now() / 1000);
    if (claims.iat && Math.abs(now - claims.iat) > 300) {
      console.error('[PLAID-WEBHOOK] JWT too old or in future');
      return { valid: false };
    }

    // Verify body hash
    const bodyHash = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(body),
    );
    const bodyHashHex = Array.from(new Uint8Array(bodyHash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    if (claims.request_body_sha256 !== bodyHashHex) {
      console.error('[PLAID-WEBHOOK] Body hash mismatch');
      return { valid: false };
    }

    return { valid: true, claims };
  } catch (error) {
    console.error('[PLAID-WEBHOOK] Verification error:', error);
    return { valid: false };
  }
}

Deno.serve(async (req) => {
  if (req.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }

  try {
    if (!PLAID_CLIENT_ID || !PLAID_SECRET) {
      console.error('[PLAID-WEBHOOK] Plaid not configured');
      return new Response('Not configured', { status: 500 });
    }

    const body = await req.text();

    // Verify webhook signature
    const plaidVerification = req.headers.get('plaid-verification') ||
      req.headers.get('Plaid-Verification');

    if (!plaidVerification) {
      console.error('[PLAID-WEBHOOK] Missing Plaid-Verification header');
      return new Response('Missing verification header', { status: 400 });
    }

    const { valid } = await verifyPlaidWebhook(body, plaidVerification);
    if (!valid) {
      return new Response('Invalid signature', { status: 400 });
    }

    let event;
    try {
      event = JSON.parse(body);
    } catch {
      console.error('[PLAID-WEBHOOK] Invalid JSON');
      return new Response('Invalid payload', { status: 400 });
    }

    const webhookType = event.webhook_type;
    const webhookCode = event.webhook_code;
    const itemId = event.item_id;

    console.log(`[PLAID-WEBHOOK] ${webhookType}.${webhookCode} for item ${itemId}`);

    const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    // Idempotency — use webhook_type + webhook_code + item_id + new_transactions (if present)
    // Plaid doesn't provide a unique event ID, so we log and handle duplicates gracefully

    switch (webhookType) {
      case 'TRANSACTIONS': {
        switch (webhookCode) {
          case 'SYNC_UPDATES_AVAILABLE':
          case 'DEFAULT_UPDATE':
          case 'INITIAL_UPDATE':
          case 'HISTORICAL_UPDATE': {
            // New transactions available — trigger a sync for this item
            const { data: accounts } = await supabase
              .from('plaid_accounts')
              .select('id, user_id')
              .eq('plaid_item_id', itemId);

            if (accounts && accounts.length > 0) {
              for (const account of accounts) {
                console.log(`[PLAID-WEBHOOK] Triggering transaction sync for user ${account.user_id.substring(0, 8)}...`);

                // Call plaid-pull-transactions internally via Supabase edge function invoke
                // Using service role to bypass auth since this is server-to-server
                const baseUrl = SUPABASE_URL.replace(/\/$/, '');
                await fetch(`${baseUrl}/functions/v1/plaid-pull-transactions`, {
                  method: 'POST',
                  headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${SUPABASE_KEY}`,
                  },
                  body: JSON.stringify({ account_id: account.id }),
                });
              }
            } else {
              console.log(`[PLAID-WEBHOOK] No accounts found for item ${itemId}`);
            }
            break;
          }

          case 'TRANSACTIONS_REMOVED': {
            const removedIds = event.removed_transactions || [];
            if (removedIds.length > 0) {
              const { error } = await supabase
                .from('user_transactions')
                .delete()
                .in('plaid_transaction_id', removedIds);

              if (error) {
                console.error('[PLAID-WEBHOOK] Remove transactions error:', error);
              } else {
                console.log(`[PLAID-WEBHOOK] Removed ${removedIds.length} transactions`);
              }
            }
            break;
          }

          default:
            console.log(`[PLAID-WEBHOOK] Unhandled TRANSACTIONS code: ${webhookCode}`);
        }
        break;
      }

      case 'ITEM': {
        switch (webhookCode) {
          case 'ERROR': {
            const plaidError = event.error;
            console.error(`[PLAID-WEBHOOK] Item error for ${itemId}:`, plaidError);

            // ITEM_LOGIN_REQUIRED specifically needs update mode
            const errorStatus = plaidError?.error_code === 'ITEM_LOGIN_REQUIRED'
              ? 'login_required'
              : 'error';

            await supabase
              .from('plaid_accounts')
              .update({
                status: errorStatus,
                error_code: plaidError?.error_code || 'UNKNOWN',
                error_message: plaidError?.error_message || 'Unknown error',
              })
              .eq('plaid_item_id', itemId);
            break;
          }

          case 'NEW_ACCOUNTS_AVAILABLE': {
            console.log(`[PLAID-WEBHOOK] New accounts available for item ${itemId}`);

            // Fetch the account that owns this item
            const { data: itemAccounts } = await supabase
              .from('plaid_accounts')
              .select('id, user_id, plaid_access_token')
              .eq('plaid_item_id', itemId);

            if (itemAccounts && itemAccounts.length > 0) {
              const account = itemAccounts[0];

              // Fetch current accounts from Plaid to see what's new
              const baseUrl = PLAID_BASE_URL[PLAID_ENV] || PLAID_BASE_URL.sandbox;
              const accountsResponse = await fetch(`${baseUrl}/accounts/get`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  client_id: PLAID_CLIENT_ID,
                  secret: PLAID_SECRET,
                  access_token: account.plaid_access_token,
                }),
              });

              if (accountsResponse.ok) {
                const accountsData = await accountsResponse.json();
                const accountCount = accountsData.accounts?.length || 0;
                console.log(`[PLAID-WEBHOOK] Item ${itemId} now has ${accountCount} accounts available`);

                // Mark the plaid_account so the user knows new accounts can be linked
                await supabase
                  .from('plaid_accounts')
                  .update({ status: 'new_accounts_available' })
                  .eq('plaid_item_id', itemId);
              } else {
                console.error(`[PLAID-WEBHOOK] Failed to fetch accounts for item ${itemId}`);
              }
            } else {
              console.log(`[PLAID-WEBHOOK] No local account found for item ${itemId}`);
            }
            break;
          }

          case 'PENDING_EXPIRATION': {
            console.log(`[PLAID-WEBHOOK] Item ${itemId} consent expiring`);
            // Access token will expire — user needs to re-authenticate
            await supabase
              .from('plaid_accounts')
              .update({ status: 'pending_expiration' })
              .eq('plaid_item_id', itemId);
            break;
          }

          case 'PENDING_DISCONNECT': {
            console.log(`[PLAID-WEBHOOK] Item ${itemId} pending disconnect`);
            await supabase
              .from('plaid_accounts')
              .update({ status: 'pending_disconnect' })
              .eq('plaid_item_id', itemId);
            break;
          }

          case 'USER_PERMISSION_REVOKED': {
            console.log(`[PLAID-WEBHOOK] User revoked permission for item ${itemId}`);
            await supabase
              .from('plaid_accounts')
              .update({ status: 'revoked' })
              .eq('plaid_item_id', itemId);
            break;
          }

          case 'LOGIN_REPAIRED': {
            console.log(`[PLAID-WEBHOOK] Login repaired for item ${itemId}`);
            await supabase
              .from('plaid_accounts')
              .update({ status: 'active', error_code: null, error_message: null })
              .eq('plaid_item_id', itemId);
            break;
          }

          case 'WEBHOOK_UPDATE_ACKNOWLEDGED': {
            console.log(`[PLAID-WEBHOOK] Webhook URL update acknowledged for item ${itemId}`);
            break;
          }

          default:
            console.log(`[PLAID-WEBHOOK] Unhandled ITEM code: ${webhookCode}`);
        }
        break;
      }

      default:
        console.log(`[PLAID-WEBHOOK] Unhandled webhook type: ${webhookType}`);
    }

    // Audit log
    await supabase.rpc('log_audit_event', {
      p_user_id: null,
      p_action: 'plaid_webhook_received',
      p_category: 'plaid',
      p_ip_address: req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || null,
      p_user_agent: req.headers.get('user-agent'),
      p_metadata: {
        webhook_type: webhookType,
        webhook_code: webhookCode,
        item_id: itemId,
      },
    });

    return new Response(JSON.stringify({ received: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('[PLAID-WEBHOOK] Error:', error);
    return new Response('Webhook error', { status: 500 });
  }
});
