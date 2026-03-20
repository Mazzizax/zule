/**
 * Zule: Shred Minted Transactions
 *
 * Deletes raw transaction data after it has been enriched and minted.
 * 24-hour grace period handles Plaid modified/removed syncs.
 *
 * Called manually for v1 — automate later via cron.
 *
 * This is the final step in the privacy lifecycle:
 * 1. Plaid dump → user_transactions (temporary buffer)
 * 2. Enrichment service → game event cards (JWT signed)
 * 3. Cards sent to Goals via Vinzrik
 * 4. THIS: shred the original dump
 *
 * After shredding, the raw financial data is gone forever.
 * Goals has only game events. Zule has only pool_claims.
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { handleCors, jsonResponse, errorResponse } from '../_shared/cors.ts'

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!
const SUPABASE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!

// Grace period: 24 hours after minting before shredding
const GRACE_PERIOD_HOURS = 24

Deno.serve(async (req) => {
  const origin = req.headers.get('Origin')

  const preflight = handleCors(req)
  if (preflight) return preflight

  if (req.method !== 'POST') {
    return errorResponse('Method not allowed', 405, origin)
  }

  try {
    // Authenticate — service role or authenticated Zule admin
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

    // Use admin client for the delete operation
    const adminClient = createClient(SUPABASE_URL, SUPABASE_KEY, {
      auth: { autoRefreshToken: false, persistSession: false },
    })

    // Calculate cutoff: minted_at must be older than grace period
    const cutoff = new Date(Date.now() - GRACE_PERIOD_HOURS * 60 * 60 * 1000).toISOString()

    // Count before delete (for reporting)
    const { count: eligibleCount } = await adminClient
      .from('user_transactions')
      .select('id', { count: 'exact', head: true })
      .eq('minted', true)
      .lt('minted_at', cutoff)

    if (!eligibleCount || eligibleCount === 0) {
      return jsonResponse({
        shredded: 0,
        message: 'No minted transactions past grace period',
      }, 200, origin)
    }

    // DELETE minted transactions past grace period
    const { error: deleteError } = await adminClient
      .from('user_transactions')
      .delete()
      .eq('minted', true)
      .lt('minted_at', cutoff)

    if (deleteError) {
      console.error('[SHRED] Delete error:', deleteError)
      return errorResponse('Failed to shred transactions', 500, origin)
    }

    console.log(`[SHRED] Shredded ${eligibleCount} minted transactions (grace: ${GRACE_PERIOD_HOURS}h)`)

    return jsonResponse({
      shredded: eligibleCount,
      grace_period_hours: GRACE_PERIOD_HOURS,
      cutoff,
    }, 200, origin)

  } catch (error) {
    console.error('[SHRED] Error:', error)
    return errorResponse('Internal server error', 500, origin)
  }
})
