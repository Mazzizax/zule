/**
 * Machine Auth Pending Endpoint
 *
 * Called by the Android surface (Zule Auth app) to discover pending
 * login sessions for machines the user is allowed to unlock.
 *
 * Auth: Bearer token (Supabase user session)
 *
 * GET: List pending sessions for user's machines
 *   → Returns [{ session_id, machine_name, session_code, expires_at, created_at }]
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { handleCors, jsonResponse, errorResponse } from '../_shared/cors.ts'
import { checkRateLimit } from '../_shared/rate-limit.ts'

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!
const SUPABASE_SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!

Deno.serve(async (req) => {
  const corsResponse = handleCors(req)
  if (corsResponse) return corsResponse

  const origin = req.headers.get('Origin')

  if (req.method !== 'GET') {
    return errorResponse('Method not allowed', 405, origin)
  }

  try {
    // Authenticate user
    const authHeader = req.headers.get('authorization')
    if (!authHeader?.startsWith('Bearer ')) {
      return errorResponse('Missing authorization header', 401, origin)
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY)
    const token = authHeader.split(' ')[1]
    const { data: { user }, error: authError } = await supabase.auth.getUser(token)

    if (authError || !user) {
      return errorResponse('Invalid or expired token', 401, origin)
    }

    // Rate limit
    const rateLimited = await checkRateLimit(supabase, req, 'machine-auth-pending', user.id)
    if (rateLimited) return rateLimited

    // Clean up expired sessions
    await supabase.rpc('cleanup_expired_machine_sessions').catch(() => {})

    // Find machines this user can unlock
    const { data: machines, error: machinesError } = await supabase
      .from('fleet_machines')
      .select('id, machine_name')
      .eq('is_active', true)
      .or(`owner_user_id.eq.${user.id},allowed_user_ids.cs.{${user.id}}`)

    if (machinesError || !machines || machines.length === 0) {
      return jsonResponse({ sessions: [] }, 200, origin)
    }

    const machineIds = machines.map(m => m.id)
    const machineNameMap = Object.fromEntries(machines.map(m => [m.id, m.machine_name]))

    // Find pending sessions for those machines
    const { data: sessions, error: sessionsError } = await supabase
      .from('machine_login_sessions')
      .select('id, machine_id, session_code, expires_at, created_at')
      .in('machine_id', machineIds)
      .eq('status', 'pending')
      .gt('expires_at', new Date().toISOString())
      .order('created_at', { ascending: false })

    if (sessionsError) {
      console.error('[MACHINE-AUTH-PENDING] Query error:', sessionsError)
      return errorResponse('Failed to query sessions', 500, origin)
    }

    const result = (sessions || []).map(s => ({
      session_id: s.id,
      machine_name: machineNameMap[s.machine_id] || 'Unknown',
      machine_id: s.machine_id,
      session_code: s.session_code,
      expires_at: s.expires_at,
      created_at: s.created_at,
    }))

    return jsonResponse({ sessions: result }, 200, origin)

  } catch (error) {
    console.error('[MACHINE-AUTH-PENDING] Error:', error)
    return errorResponse('Internal server error', 500, origin)
  }
})
