/**
 * Zule: Remove Card (Disconnect Plaid)
 *
 * Clears Plaid credentials from user_profiles and deletes
 * any user_transactions for this user.
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { handleCors, jsonResponse, errorResponse } from '../_shared/cors.ts'
import { checkRateLimit } from '../_shared/rate-limit.ts'
import { requireVerifiedEmail } from '../_shared/security.ts'

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!
const SUPABASE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
const PLAID_CLIENT_ID = Deno.env.get('PLAID_CLIENT_ID')
const PLAID_SECRET = Deno.env.get('PLAID_SECRET')
const PLAID_ENV = Deno.env.get('PLAID_ENV') || 'sandbox'

const PLAID_BASE_URL: Record<string, string> = {
  sandbox: 'https://sandbox.plaid.com',
  development: 'https://development.plaid.com',
  production: 'https://production.plaid.com',
}

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

    // Email verification required
    const unverified = requireVerifiedEmail(user, origin)
    if (unverified) return unverified

    let body: { account_id?: string } = {}
    try { body = await req.json() } catch { /* no body is fine for remove-all */ }

    const adminClient = createClient(SUPABASE_URL, SUPABASE_KEY, {
      auth: { autoRefreshToken: false, persistSession: false },
    })

    const baseUrl = PLAID_BASE_URL[PLAID_ENV] || PLAID_BASE_URL.sandbox

    if (body.account_id) {
      // Fetch the access token before deleting
      const { data: account } = await adminClient
        .from('plaid_accounts')
        .select('plaid_access_token')
        .eq('id', body.account_id)
        .eq('user_id', user.id)
        .single()

      // Call Plaid /item/remove to deactivate the item on Plaid's side
      if (account?.plaid_access_token && PLAID_CLIENT_ID && PLAID_SECRET) {
        const removeRes = await fetch(`${baseUrl}/item/remove`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            client_id: PLAID_CLIENT_ID,
            secret: PLAID_SECRET,
            access_token: account.plaid_access_token,
          }),
        })
        if (!removeRes.ok) {
          console.error(`[REMOVE-CARD] Plaid /item/remove failed:`, await removeRes.text())
        }
      }

      // Remove from our DB
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
      // Fetch all access tokens before deleting
      const { data: accounts } = await adminClient
        .from('plaid_accounts')
        .select('plaid_access_token')
        .eq('user_id', user.id)

      // Call Plaid /item/remove for each
      if (accounts && PLAID_CLIENT_ID && PLAID_SECRET) {
        for (const acct of accounts) {
          const removeRes = await fetch(`${baseUrl}/item/remove`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              client_id: PLAID_CLIENT_ID,
              secret: PLAID_SECRET,
              access_token: acct.plaid_access_token,
            }),
          })
          if (!removeRes.ok) {
            console.error(`[REMOVE-CARD] Plaid /item/remove failed:`, await removeRes.text())
          }
        }
      }

      // Remove from our DB
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
