/**
 * Zule: Remove Card (Disconnect Plaid)
 *
 * Clears Plaid credentials from user_profiles and deletes
 * any user_transactions for this user.
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { handleCors, jsonResponse, errorResponse } from '../_shared/cors.ts'
import { checkRateLimit } from '../_shared/rate-limit.ts'

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!
const SUPABASE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!

Deno.serve(async (req) => {
  const origin = req.headers.get('Origin')

  const preflight = handleCors(req)
  if (preflight) return preflight

  if (req.method !== 'POST') {
    return errorResponse('Method not allowed', 405, origin)
  }

  try {
    const authHeader = req.headers.get('authorization')
    if (!authHeader?.startsWith('Bearer ')) {
      return errorResponse('Missing authorization header', 401, origin)
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, {
      global: { headers: { Authorization: authHeader } },
    })

    const { data: { user }, error: authError } = await supabase.auth.getUser()
    if (authError || !user) {
      return errorResponse('Invalid or expired token', 401, origin)
    }

    // Rate limiting
    const rateLimited = await checkRateLimit(supabase, req, 'remove-card', user.id)
    if (rateLimited) return rateLimited

    let body: { account_id?: string } = {}
    try { body = await req.json() } catch { /* no body is fine for remove-all */ }

    const adminClient = createClient(SUPABASE_URL, SUPABASE_KEY, {
      auth: { autoRefreshToken: false, persistSession: false },
    })

    if (body.account_id) {
      // Remove specific account + its transactions
      await adminClient
        .from('user_transactions')
        .delete()
        .eq('user_id', user.id)
        .eq('plaid_account_id', body.account_id)

      await adminClient
        .from('plaid_accounts')
        .delete()
        .eq('id', body.account_id)
        .eq('user_id', user.id)

      console.log(`[REMOVE-CARD] Removed account ${body.account_id} for user ${user.id.substring(0, 8)}...`)
    } else {
      // Remove all
      await adminClient
        .from('user_transactions')
        .delete()
        .eq('user_id', user.id)

      await adminClient
        .from('plaid_accounts')
        .delete()
        .eq('user_id', user.id)

      console.log(`[REMOVE-CARD] Removed all accounts for user ${user.id.substring(0, 8)}...`)
    }

    // Update display fields based on remaining accounts
    const { data: remaining } = await adminClient
      .from('plaid_accounts')
      .select('institution_name, connected_at')
      .eq('user_id', user.id)
      .order('connected_at', { ascending: false })
      .limit(1)

    await adminClient
      .from('user_profiles')
      .update({
        plaid_institution_name: remaining?.[0]?.institution_name || null,
        plaid_connected_at: remaining?.[0]?.connected_at || null,
      })
      .eq('id', user.id)

    return jsonResponse({ removed: true }, 200, origin)

  } catch (error) {
    console.error('[REMOVE-CARD] Error:', error)
    return errorResponse('Internal server error', 500, origin)
  }
})
