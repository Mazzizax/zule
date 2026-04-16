/**
 * Machine Register Endpoint
 *
 * Register a fleet machine with Zule for native OS authentication.
 * The machine receives an API key (shown once) for server-to-server communication.
 *
 * ENDPOINTS:
 * - GET: List machines owned by or accessible to the authenticated user
 * - POST: Register a new machine
 * - PUT: Update machine (name, allowed_user_ids)
 * - DELETE: Deactivate a machine (soft delete)
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { handleCors, jsonResponse, errorResponse } from '../_shared/cors.ts'
import { checkRateLimit } from '../_shared/rate-limit.ts'
import { generateMachineApiKey } from '../_shared/machine-auth.ts'

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!
const SUPABASE_SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!

Deno.serve(async (req) => {
  const corsResponse = handleCors(req)
  if (corsResponse) return corsResponse

  const origin = req.headers.get('Origin')

  try {
    // Authenticate the user
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

    const userId = user.id

    // Rate limiting
    const rateLimited = await checkRateLimit(supabase, req, 'machine-register', userId)
    if (rateLimited) return rateLimited

    switch (req.method) {
      case 'GET':
        return await handleListMachines(supabase, userId, origin)
      case 'POST':
        return await handleRegisterMachine(supabase, userId, req, origin)
      case 'PUT':
        return await handleUpdateMachine(supabase, userId, req, origin)
      case 'DELETE':
        return await handleDeactivateMachine(supabase, userId, req, origin)
      default:
        return errorResponse('Method not allowed', 405, origin)
    }
  } catch (error) {
    console.error('[MACHINE-REGISTER] Error:', error)
    return errorResponse('Internal server error', 500, origin)
  }
})

async function handleListMachines(
  supabase: ReturnType<typeof createClient>,
  userId: string,
  origin: string | null,
) {
  const { data: machines, error } = await supabase
    .from('fleet_machines')
    .select('id, machine_name, machine_identifier, owner_user_id, allowed_user_ids, is_active, created_at, last_seen_at')
    .or(`owner_user_id.eq.${userId},allowed_user_ids.cs.{${userId}}`)
    .eq('is_active', true)
    .order('created_at', { ascending: false })

  if (error) {
    console.error('[MACHINE-REGISTER] List error:', error)
    return errorResponse('Failed to list machines', 500, origin)
  }

  return jsonResponse({ machines: machines || [] }, 200, origin)
}

async function handleRegisterMachine(
  supabase: ReturnType<typeof createClient>,
  userId: string,
  req: Request,
  origin: string | null,
) {
  let body
  try {
    body = await req.json()
  } catch {
    return errorResponse('Invalid JSON body', 400, origin)
  }

  const { machine_name, machine_identifier } = body

  if (!machine_name || !machine_identifier) {
    return errorResponse('machine_name and machine_identifier are required', 400, origin)
  }

  if (machine_name.length > 100) {
    return errorResponse('machine_name must be 100 characters or less', 400, origin)
  }

  if (machine_identifier.length > 200) {
    return errorResponse('machine_identifier must be 200 characters or less', 400, origin)
  }

  // Check for duplicate identifier
  const { data: existing } = await supabase
    .from('fleet_machines')
    .select('id')
    .eq('machine_identifier', machine_identifier)
    .single()

  if (existing) {
    return errorResponse('A machine with this identifier already exists', 409, origin)
  }

  // Generate API key
  const { apiKey, apiKeyHash } = await generateMachineApiKey()

  // Insert machine — owner is automatically in allowed_user_ids
  const { data: machine, error } = await supabase
    .from('fleet_machines')
    .insert({
      machine_name,
      machine_identifier,
      owner_user_id: userId,
      allowed_user_ids: [userId],
      api_key_hash: apiKeyHash,
    })
    .select('id, machine_name, machine_identifier, created_at')
    .single()

  if (error) {
    console.error('[MACHINE-REGISTER] Insert error:', error)
    if (error.code === '23505') {
      return errorResponse('A machine with this identifier already exists', 409, origin)
    }
    return errorResponse('Failed to register machine', 500, origin)
  }

  // Audit log
  await supabase.from('audit_logs').insert({
    user_id: userId,
    action: 'machine_registered',
    action_category: 'machine',
    metadata: { machine_id: machine.id, machine_name, machine_identifier },
    success: true,
  })

  return jsonResponse({
    machine: {
      id: machine.id,
      machine_name: machine.machine_name,
      machine_identifier: machine.machine_identifier,
      created_at: machine.created_at,
    },
    credentials: {
      api_key: apiKey,
    },
    message: 'Save this API key now — it will not be shown again!',
  }, 201, origin)
}

async function handleUpdateMachine(
  supabase: ReturnType<typeof createClient>,
  userId: string,
  req: Request,
  origin: string | null,
) {
  let body
  try {
    body = await req.json()
  } catch {
    return errorResponse('Invalid JSON body', 400, origin)
  }

  const { machine_id, ...updates } = body

  if (!machine_id) {
    return errorResponse('machine_id is required', 400, origin)
  }

  // Verify ownership
  const { data: existing } = await supabase
    .from('fleet_machines')
    .select('id, owner_user_id')
    .eq('id', machine_id)
    .single()

  if (!existing) {
    return errorResponse('Machine not found', 404, origin)
  }

  if (existing.owner_user_id !== userId) {
    return errorResponse('You do not own this machine', 403, origin)
  }

  // Allowed update fields
  const allowedFields = ['machine_name', 'allowed_user_ids', 'windows_credential_encrypted']
  const sanitized: Record<string, unknown> = {}
  for (const field of allowedFields) {
    if (updates[field] !== undefined) {
      sanitized[field] = updates[field]
    }
  }

  if (Object.keys(sanitized).length === 0) {
    return errorResponse('No valid fields to update', 400, origin)
  }

  // Ensure owner is always in allowed_user_ids
  if (sanitized.allowed_user_ids) {
    const ids = sanitized.allowed_user_ids as string[]
    if (!ids.includes(userId)) {
      ids.push(userId)
    }
  }

  const { data: updated, error } = await supabase
    .from('fleet_machines')
    .update(sanitized)
    .eq('id', machine_id)
    .select()
    .single()

  if (error) {
    console.error('[MACHINE-REGISTER] Update error:', error)
    return errorResponse('Failed to update machine', 500, origin)
  }

  await supabase.from('audit_logs').insert({
    user_id: userId,
    action: 'machine_updated',
    action_category: 'machine',
    metadata: { machine_id, fields_updated: Object.keys(sanitized) },
    success: true,
  })

  return jsonResponse({ machine: updated }, 200, origin)
}

async function handleDeactivateMachine(
  supabase: ReturnType<typeof createClient>,
  userId: string,
  req: Request,
  origin: string | null,
) {
  let body
  try {
    body = await req.json()
  } catch {
    return errorResponse('Invalid JSON body', 400, origin)
  }

  const { machine_id } = body

  if (!machine_id) {
    return errorResponse('machine_id is required', 400, origin)
  }

  const { data: existing } = await supabase
    .from('fleet_machines')
    .select('id, owner_user_id')
    .eq('id', machine_id)
    .single()

  if (!existing) {
    return errorResponse('Machine not found', 404, origin)
  }

  if (existing.owner_user_id !== userId) {
    return errorResponse('You do not own this machine', 403, origin)
  }

  const { error } = await supabase
    .from('fleet_machines')
    .update({ is_active: false })
    .eq('id', machine_id)

  if (error) {
    console.error('[MACHINE-REGISTER] Deactivate error:', error)
    return errorResponse('Failed to deactivate machine', 500, origin)
  }

  await supabase.from('audit_logs').insert({
    user_id: userId,
    action: 'machine_deactivated',
    action_category: 'machine',
    metadata: { machine_id },
    success: true,
  })

  return jsonResponse({ success: true, message: 'Machine deactivated' }, 200, origin)
}
