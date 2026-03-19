/**
 * Zule: Get Pending Transactions
 *
 * Returns transactions that haven't been synced to Goals yet.
 * Called BY Vinzrik (using Zule session) to relay to Goals.
 *
 * After returning, marks all returned transactions as synced.
 * No user_id is included in the response — Vinzrik tags with ghost_id.
 *
 * Response:
 * - transactions: Array of sanitized transactions (no user_id)
 * - count: Number of transactions returned
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import {
  handleCors,
  jsonResponse,
  errorResponse,
} from '../_shared/cors.ts';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

Deno.serve(async (req) => {
  const origin = req.headers.get('Origin');

  const corsResponse = handleCors(req);
  if (corsResponse) return corsResponse;

  if (req.method !== 'GET' && req.method !== 'POST') {
    return errorResponse('Method not allowed', 405, origin);
  }

  try {
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
      console.error('[GET-PENDING-TX] Auth error:', authError?.message);
      return errorResponse('Invalid or expired token', 401, origin);
    }

    // 2. FETCH UNSYNCED TRANSACTIONS
    const { data: transactions, error: fetchError } = await supabase
      .from('user_transactions')
      .select(`
        id,
        merchant_name,
        amount,
        date,
        category,
        subcategory,
        location_city,
        location_state,
        iso_currency_code,
        plaid_transaction_id,
        created_at
      `)
      .eq('user_id', user.id)
      .eq('synced_to_goals', false)
      .order('date', { ascending: false });

    if (fetchError) {
      console.error('[GET-PENDING-TX] Fetch error:', fetchError);
      return errorResponse('Failed to fetch transactions', 500, origin);
    }

    // 3. MARK AS SYNCED
    if (transactions && transactions.length > 0) {
      const txIds = transactions.map((tx: { id: string }) => tx.id);
      const { error: updateError } = await supabase
        .from('user_transactions')
        .update({ synced_to_goals: true })
        .in('id', txIds);

      if (updateError) {
        console.error('[GET-PENDING-TX] Mark synced error:', updateError);
        // Don't fail — transactions were fetched, sync flag is best-effort
      }
    }

    console.log(`[GET-PENDING-TX] User ${user.id.substring(0, 8)}...: ${transactions?.length || 0} pending`);

    return jsonResponse(
      {
        transactions: transactions || [],
        count: transactions?.length || 0,
      },
      200,
      origin
    );

  } catch (error) {
    console.error('[GET-PENDING-TX] Error:', error);
    return errorResponse('Internal server error', 500, origin);
  }
});
