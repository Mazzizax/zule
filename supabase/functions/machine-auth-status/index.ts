/**
 * Machine Auth Status Endpoint
 *
 * Polled by the Windows Auth Service to check if a login session
 * has been approved, denied, or expired.
 *
 * Auth: X-Api-Key header (machine API key)
 *
 * GET ?session_id=<uuid>
 *   → Returns { status, approved_by_user_id?, auth_level? }
 *
 * Implements simple long-polling: holds the connection for up to 10 seconds
 * before returning 'pending', reducing HTTP round-trips.
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { checkRateLimit } from '../_shared/rate-limit.ts'
import {
  verifyMachineApiKey,
  machineJsonResponse,
  machineErrorResponse,
} from '../_shared/machine-auth.ts'

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!
const SUPABASE_SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!

/** Check session status once */
async function checkSession(
  supabase: ReturnType<typeof createClient>,
  sessionId: string,
  machineId: string,
): Promise<{ status: string; approved_by_user_id?: string; auth_level?: string; expired?: boolean } | null> {
  const { data: session, error } = await supabase
    .from('machine_login_sessions')
    .select('status, approved_by_user_id, auth_level, expires_at, machine_id')
    .eq('id', sessionId)
    .single()

  if (error || !session) return null

  // Verify session belongs to this machine
  if (session.machine_id !== machineId) return null

  // Check if expired but not yet marked
  if (session.status === 'pending' && new Date(session.expires_at) < new Date()) {
    await supabase
      .from('machine_login_sessions')
      .update({ status: 'expired' })
      .eq('id', sessionId)
      .eq('status', 'pending')

    return { status: 'expired', expired: true }
  }

  return {
    status: session.status,
    approved_by_user_id: session.approved_by_user_id || undefined,
    auth_level: session.auth_level || undefined,
  }
}

/** Sleep for ms */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return machineJsonResponse(null, 204)
  }

  if (req.method !== 'GET') {
    return machineErrorResponse('Method not allowed', 405)
  }

  try {
    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY)

    // Authenticate machine
    const apiKey = req.headers.get('x-api-key')
    if (!apiKey) {
      return machineErrorResponse('Missing X-Api-Key header', 401)
    }

    const machine = await verifyMachineApiKey(supabase, apiKey)
    if (!machine) {
      return machineErrorResponse('Invalid API key', 401)
    }

    // Rate limit
    const rateLimited = await checkRateLimit(supabase, req, 'machine-auth-status', `machine:${machine.id}`)
    if (rateLimited) return rateLimited

    // Get session_id from query params
    const url = new URL(req.url)
    const sessionId = url.searchParams.get('session_id')
    if (!sessionId) {
      return machineErrorResponse('session_id query parameter is required', 400)
    }

    // Long-poll: check up to 5 times with 2-second intervals (10 seconds total)
    for (let i = 0; i < 5; i++) {
      const result = await checkSession(supabase, sessionId, machine.id)

      if (!result) {
        return machineErrorResponse('Session not found', 404)
      }

      // If not pending, return immediately
      if (result.status !== 'pending') {
        return machineJsonResponse(result)
      }

      // Still pending — wait before next check (skip wait on last iteration)
      if (i < 4) {
        await sleep(2000)
      }
    }

    // Still pending after long-poll window
    return machineJsonResponse({ status: 'pending' })

  } catch (error) {
    console.error('[MACHINE-AUTH-STATUS] Error:', error)
    return machineErrorResponse('Internal server error', 500)
  }
})
