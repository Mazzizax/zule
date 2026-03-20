/**
 * Zule: Remove Card (Disconnect Plaid)
 *
 * Clears Plaid credentials from user_profiles and deletes
 * any user_transactions for this user.
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { handleCors, jsonResponse, errorResponse } from '../_shared/cors.ts'

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

    const adminClient = createClient(SUPABASE_URL, SUPABASE_KEY, {
      auth: { autoRefreshToken: false, persistSession: false },
    })

    // Clear Plaid fields
    await adminClient
      .from('user_profiles')
      .update({
        plaid_access_token: null,
        plaid_item_id: null,
        plaid_institution_name: null,
        plaid_connected_at: null,
      })
      .eq('id', user.id)

    // Delete any transactions
    await adminClient
      .from('user_transactions')
      .delete()
      .eq('user_id', user.id)

    console.log(`[REMOVE-CARD] Disconnected Plaid for user ${user.id.substring(0, 8)}...`)

    return jsonResponse({ removed: true }, 200, origin)

  } catch (error) {
    console.error('[REMOVE-CARD] Error:', error)
    return errorResponse('Internal server error', 500, origin)
  }
})
