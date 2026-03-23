/**
 * Zule: Delete Account
 *
 * Permanently deletes the authenticated user's Zule account and all associated data:
 * - user_transactions
 * - pool_claims
 * - user_profiles (Plaid tokens, etc.)
 * - passkey_credentials
 * - auth.users entry
 *
 * This does NOT touch Goals. Anonymous game data is retained
 * and ownership transfers to Mazz Ink's in-game account.
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { handleCors, jsonResponse, errorResponse } from '../_shared/cors.ts'
import { checkRateLimit } from '../_shared/rate-limit.ts'
import { requireVerifiedEmail } from '../_shared/security.ts'

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
    const rateLimited = await checkRateLimit(supabase, req, 'delete-account', user.id)
    if (rateLimited) return rateLimited

    // Email verification required
    const unverified = requireVerifiedEmail(user, origin)
    if (unverified) return unverified

    const userId = user.id
    console.log(`[DELETE-ACCOUNT] Deleting user ${userId.substring(0, 8)}...`)

    const adminClient = createClient(SUPABASE_URL, SUPABASE_KEY, {
      auth: { autoRefreshToken: false, persistSession: false },
    })

    // Delete user data in order (respect foreign keys)
    await adminClient.from('pool_claims').delete().eq('user_id', userId)
    await adminClient.from('user_transactions').delete().eq('user_id', userId)
    await adminClient.from('passkey_credentials').delete().eq('user_id', userId)

    // Delete auth user (cascades to user_profiles via Supabase auth triggers)
    const { error: deleteError } = await adminClient.auth.admin.deleteUser(userId)
    if (deleteError) {
      console.error('[DELETE-ACCOUNT] Failed to delete auth user:', deleteError)
      return errorResponse('Failed to delete account', 500, origin)
    }

    console.log(`[DELETE-ACCOUNT] User ${userId.substring(0, 8)}... permanently deleted`)

    return jsonResponse({ deleted: true }, 200, origin)

  } catch (error) {
    console.error('[DELETE-ACCOUNT] Error:', error)
    return errorResponse('Internal server error', 500, origin)
  }
})
