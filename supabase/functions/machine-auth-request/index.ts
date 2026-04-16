/**
 * Machine Auth Request Endpoint
 *
 * Called by the Windows Auth Service when a user clicks the Zule tile
 * on the login screen. Creates a pending login session.
 *
 * Auth: X-Api-Key header (machine API key, not user Bearer token)
 *
 * POST: Create a new login session
 *   → Returns { session_id, session_code, expires_at }
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { checkRateLimit } from '../_shared/rate-limit.ts'
import {
  verifyMachineApiKey,
  createLoginSession,
  getClientIp,
  machineJsonResponse,
  machineErrorResponse,
} from '../_shared/machine-auth.ts'

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!
const SUPABASE_SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!

Deno.serve(async (req) => {
  // Permissive CORS for native clients
  if (req.method === 'OPTIONS') {
    return machineJsonResponse(null, 204)
  }

  if (req.method !== 'POST') {
    return machineErrorResponse('Method not allowed', 405)
  }

  try {
    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY)

    // Authenticate machine via API key
    const apiKey = req.headers.get('x-api-key')
    if (!apiKey) {
      return machineErrorResponse('Missing X-Api-Key header', 401)
    }

    const machine = await verifyMachineApiKey(supabase, apiKey)
    if (!machine) {
      return machineErrorResponse('Invalid API key', 401)
    }

    // Rate limit by machine ID
    const rateLimited = await checkRateLimit(supabase, req, 'machine-auth-request', `machine:${machine.id}`)
    if (rateLimited) return rateLimited

    // Create login session (or return existing pending one)
    const session = await createLoginSession(supabase, machine.id)
    if (!session) {
      return machineErrorResponse('Failed to create login session', 500)
    }

    // Audit log
    const clientIp = getClientIp(req)
    await supabase.from('audit_logs').insert({
      action: 'machine_auth_requested',
      action_category: 'machine',
      ip_address: clientIp,
      metadata: {
        machine_id: machine.id,
        machine_name: machine.machine_name,
        session_id: session.session_id,
        session_code: session.session_code,
      },
      success: true,
    })

    return machineJsonResponse({
      session_id: session.session_id,
      session_code: session.session_code,
      expires_at: session.expires_at,
      machine_name: machine.machine_name,
    }, 201)

  } catch (error) {
    console.error('[MACHINE-AUTH-REQUEST] Error:', error)
    return machineErrorResponse('Internal server error', 500)
  }
})
