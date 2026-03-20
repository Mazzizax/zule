/**
 * Zule: Pull Transactions from Plaid
 *
 * Uses Plaid's transactions/sync endpoint to pull new transactions
 * into the user_transactions table. Uses cursor-based pagination
 * for incremental sync.
 *
 * Response:
 * - added: Number of new transactions added
 * - modified: Number of transactions updated
 * - removed: Number of transactions removed
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import {
  handleCors,
  jsonResponse,
  errorResponse,
} from '../_shared/cors.ts';

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

Deno.serve(async (req) => {
  const origin = req.headers.get('Origin');

  const corsResponse = handleCors(req);
  if (corsResponse) return corsResponse;

  if (req.method !== 'POST') {
    return errorResponse('Method not allowed', 405, origin);
  }

  try {
    if (!PLAID_CLIENT_ID || !PLAID_SECRET) {
      console.error('[PLAID-PULL] Plaid not configured');
      return errorResponse('Plaid integration not configured', 500, origin);
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
      console.error('[PLAID-PULL] Auth error:', authError?.message);
      return errorResponse('Invalid or expired token', 401, origin);
    }

    // 2. GET PLAID CREDENTIALS from user profile
    const { data: profile, error: profileError } = await supabase
      .from('user_profiles')
      .select('plaid_access_token, plaid_cursor')
      .eq('id', user.id)
      .single();

    if (profileError || !profile?.plaid_access_token) {
      return errorResponse('No Plaid account connected', 400, origin);
    }

    // 3. SYNC TRANSACTIONS via Plaid API
    const baseUrl = PLAID_BASE_URL[PLAID_ENV] || PLAID_BASE_URL.sandbox;
    let hasMore = true;
    let cursor = profile.plaid_cursor || '';
    let totalAdded = 0;
    let totalModified = 0;
    let totalRemoved = 0;

    while (hasMore) {
      const syncBody: Record<string, unknown> = {
        client_id: PLAID_CLIENT_ID,
        secret: PLAID_SECRET,
        access_token: profile.plaid_access_token,
      };
      if (cursor) {
        syncBody.cursor = cursor;
      }

      const syncResponse = await fetch(`${baseUrl}/transactions/sync`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(syncBody),
      });

      if (!syncResponse.ok) {
        const err = await syncResponse.json().catch(() => ({}));
        console.error('[PLAID-PULL] Sync error:', err);
        return errorResponse('Failed to sync transactions', 500, origin);
      }

      const syncData = await syncResponse.json();

      // Process added transactions
      if (syncData.added?.length > 0) {
        // GATE: Shred any transaction without a plaid_transaction_id.
        // If Plaid didn't give it an ID, it's not a real transaction.
        const certified = syncData.added.filter((tx: Record<string, unknown>) => {
          if (!tx.transaction_id) {
            console.log('[PLAID-PULL] Shredded transaction without plaid ID:', tx.name || 'unknown');
            return false;
          }
          return true;
        });

        const rows = certified.map((tx: Record<string, unknown>) => ({
          user_id: user.id,
          merchant_name: (tx.merchant_name as string) || (tx.name as string) || null,
          amount: Math.abs(tx.amount as number), // Plaid uses negative for debits
          date: tx.date as string,
          category: Array.isArray(tx.personal_finance_category)
            ? null
            : (tx.personal_finance_category as Record<string, string>)?.primary || null,
          subcategory: Array.isArray(tx.personal_finance_category)
            ? null
            : (tx.personal_finance_category as Record<string, string>)?.detailed || null,
          location_city: (tx.location as Record<string, string>)?.city || null,
          location_state: (tx.location as Record<string, string>)?.region || null,
          iso_currency_code: (tx.iso_currency_code as string) || 'USD',
          plaid_transaction_id: tx.transaction_id as string,
        }));

        const { error: insertError } = await supabase
          .from('user_transactions')
          .upsert(rows, { onConflict: 'plaid_transaction_id' });

        if (insertError) {
          console.error('[PLAID-PULL] Insert error:', insertError);
        } else {
          totalAdded += rows.length;
        }
      }

      // Process modified transactions
      if (syncData.modified?.length > 0) {
        for (const tx of syncData.modified) {
          const { error: modError } = await supabase
            .from('user_transactions')
            .update({
              merchant_name: tx.merchant_name || tx.name || null,
              amount: Math.abs(tx.amount),
              date: tx.date,
              category: tx.personal_finance_category?.primary || null,
              subcategory: tx.personal_finance_category?.detailed || null,
              location_city: tx.location?.city || null,
              location_state: tx.location?.region || null,
              minted: false, // Mark as needing re-mint
            })
            .eq('plaid_transaction_id', tx.transaction_id);

          if (!modError) totalModified++;
        }
      }

      // Process removed transactions
      if (syncData.removed?.length > 0) {
        const removedIds = syncData.removed.map((tx: Record<string, string>) => tx.transaction_id);
        const { error: delError } = await supabase
          .from('user_transactions')
          .delete()
          .in('plaid_transaction_id', removedIds);

        if (!delError) totalRemoved += removedIds.length;
      }

      cursor = syncData.next_cursor;
      hasMore = syncData.has_more;
    }

    // 4. UPDATE CURSOR for next sync
    const { error: cursorError } = await supabase
      .from('user_profiles')
      .update({ plaid_cursor: cursor })
      .eq('id', user.id);

    if (cursorError) {
      console.error('[PLAID-PULL] Cursor update error:', cursorError);
    }

    console.log(`[PLAID-PULL] User ${user.id.substring(0, 8)}...: +${totalAdded} ~${totalModified} -${totalRemoved}`);

    // 5. AUDIT LOG
    const clientIp = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || null;
    await supabase.rpc('log_audit_event', {
      p_user_id: user.id,
      p_action: 'plaid_transactions_pulled',
      p_category: 'plaid',
      p_ip_address: clientIp,
      p_user_agent: req.headers.get('user-agent'),
      p_metadata: { added: totalAdded, modified: totalModified, removed: totalRemoved },
    });

    return jsonResponse(
      { added: totalAdded, modified: totalModified, removed: totalRemoved },
      200,
      origin
    );

  } catch (error) {
    console.error('[PLAID-PULL] Error:', error);
    return errorResponse('Internal server error', 500, origin);
  }
});
