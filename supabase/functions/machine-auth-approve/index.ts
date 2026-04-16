/**
 * Machine Auth Approve Endpoint
 *
 * Called by the Android surface (Zule Auth app) to approve a pending
 * machine login session using passkey biometric authentication.
 *
 * Auth: Bearer token (Supabase user session)
 *
 * Two-step flow (same pattern as passkey-auth):
 *
 * GET ?action=challenge&session_id=<uuid>&credential_id=<base64url>
 *   → Returns passkey challenge options
 *
 * POST { session_id, challenge_key, response: AuthenticationResponseJSON }
 *   → Verifies passkey, approves session
 *
 * POST { session_id, action: 'deny' }
 *   → Explicitly denies the session
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { handleCors, jsonResponse, errorResponse } from '../_shared/cors.ts'
import { checkRateLimit as checkEndpointRateLimit } from '../_shared/rate-limit.ts'
import {
  RP_ID,
  EXPECTED_ORIGINS,
  CHALLENGE_EXPIRY_MS,
  RATE_LIMIT,
  base64urlToBytes,
} from '../_shared/webauthn-config.ts'
import { getClientIp } from '../_shared/machine-auth.ts'
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from 'jsr:@simplewebauthn/server'
import type {
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
} from 'jsr:@simplewebauthn/types'

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!
const SUPABASE_SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!

Deno.serve(async (req) => {
  const corsResponse = handleCors(req)
  if (corsResponse) return corsResponse

  const origin = req.headers.get('Origin')

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
    const rateLimited = await checkEndpointRateLimit(supabase, req, 'machine-auth-approve', user.id)
    if (rateLimited) return rateLimited

    if (req.method === 'GET') {
      return await handleGetChallenge(supabase, req, user.id, origin)
    } else if (req.method === 'POST') {
      return await handleApproveOrDeny(supabase, req, user.id, origin)
    } else {
      return errorResponse('Method not allowed', 405, origin)
    }
  } catch (error) {
    console.error('[MACHINE-AUTH-APPROVE] Error:', error)
    return errorResponse('Internal server error', 500, origin)
  }
})

/**
 * Verify the user is allowed to approve sessions for a given machine.
 */
async function verifyUserAccess(
  supabase: ReturnType<typeof createClient>,
  sessionId: string,
  userId: string,
): Promise<{ session: any; machine: any } | null> {
  // Get the session
  const { data: session, error: sessionError } = await supabase
    .from('machine_login_sessions')
    .select('id, machine_id, status, session_code, expires_at')
    .eq('id', sessionId)
    .single()

  if (sessionError || !session) return null
  if (session.status !== 'pending') return null
  if (new Date(session.expires_at) < new Date()) return null

  // Verify user has access to this machine
  const { data: machine, error: machineError } = await supabase
    .from('fleet_machines')
    .select('id, machine_name, owner_user_id, allowed_user_ids')
    .eq('id', session.machine_id)
    .eq('is_active', true)
    .single()

  if (machineError || !machine) return null

  const hasAccess = machine.owner_user_id === userId
    || (machine.allowed_user_ids && machine.allowed_user_ids.includes(userId))

  if (!hasAccess) return null

  return { session, machine }
}

/**
 * GET: Generate passkey challenge for session approval
 */
async function handleGetChallenge(
  supabase: ReturnType<typeof createClient>,
  req: Request,
  userId: string,
  origin: string | null,
) {
  const url = new URL(req.url)
  const action = url.searchParams.get('action')
  const sessionId = url.searchParams.get('session_id')
  const credentialId = url.searchParams.get('credential_id')

  if (action !== 'challenge') {
    return errorResponse('Use ?action=challenge&session_id=X&credential_id=Y', 400, origin)
  }

  if (!sessionId || !credentialId) {
    return errorResponse('session_id and credential_id are required', 400, origin)
  }

  // Verify user access to this session's machine
  const access = await verifyUserAccess(supabase, sessionId, userId)
  if (!access) {
    return errorResponse('Session not found, expired, or access denied', 404, origin)
  }

  // Look up the credential (must belong to this user)
  const { data: credential, error: credError } = await supabase
    .from('user_passkeys')
    .select('user_id, public_key, counter, transports')
    .eq('credential_id', credentialId)
    .eq('user_id', userId)
    .eq('is_active', true)
    .single()

  if (credError || !credential) {
    return errorResponse('Passkey not found', 401, origin)
  }

  // Generate challenge
  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: 'preferred',
    timeout: CHALLENGE_EXPIRY_MS,
    allowCredentials: [{
      id: credentialId,
      transports: (credential.transports || ['internal', 'hybrid']) as AuthenticatorTransportFuture[],
    }],
  })

  // Store challenge — key includes session_id for binding
  const challengeKey = `machine:${sessionId}:${credentialId}:${Date.now()}`
  const expiresAt = new Date(Date.now() + CHALLENGE_EXPIRY_MS).toISOString()

  const { error: insertError } = await supabase
    .from('passkey_challenges')
    .insert({
      challenge_key: challengeKey,
      challenge: options.challenge,
      user_id: userId,
      expires_at: expiresAt,
    })

  if (insertError) {
    console.error('[MACHINE-AUTH-APPROVE] Failed to store challenge:', insertError)
    return errorResponse('Failed to generate challenge', 500, origin)
  }

  return jsonResponse({
    challenge: options.challenge,
    challenge_key: challengeKey,
    timeout: CHALLENGE_EXPIRY_MS,
    rp_id: RP_ID,
    session_code: access.session.session_code,
    machine_name: access.machine.machine_name,
    options,
  }, 200, origin)
}

/**
 * POST: Approve (with passkey) or deny a session
 */
async function handleApproveOrDeny(
  supabase: ReturnType<typeof createClient>,
  req: Request,
  userId: string,
  origin: string | null,
) {
  let body
  try {
    body = await req.json()
  } catch {
    return errorResponse('Invalid JSON body', 400, origin)
  }

  const { session_id, action } = body
  if (!session_id) {
    return errorResponse('session_id is required', 400, origin)
  }

  const clientIp = getClientIp(req)

  // Handle explicit denial
  if (action === 'deny') {
    return await handleDeny(supabase, session_id, userId, clientIp, origin)
  }

  // Otherwise, this is an approval with passkey
  return await handleApprove(supabase, body, userId, clientIp, origin)
}

/**
 * Deny a session
 */
async function handleDeny(
  supabase: ReturnType<typeof createClient>,
  sessionId: string,
  userId: string,
  clientIp: string | null,
  origin: string | null,
) {
  const access = await verifyUserAccess(supabase, sessionId, userId)
  if (!access) {
    return errorResponse('Session not found, expired, or access denied', 404, origin)
  }

  const { error } = await supabase
    .from('machine_login_sessions')
    .update({
      status: 'denied',
      approved_by_user_id: userId,
    })
    .eq('id', sessionId)
    .eq('status', 'pending')

  if (error) {
    console.error('[MACHINE-AUTH-APPROVE] Deny error:', error)
    return errorResponse('Failed to deny session', 500, origin)
  }

  await supabase.from('audit_logs').insert({
    user_id: userId,
    action: 'machine_auth_denied',
    action_category: 'machine',
    ip_address: clientIp,
    metadata: {
      session_id: sessionId,
      machine_name: access.machine.machine_name,
    },
    success: true,
  })

  return jsonResponse({ success: true, status: 'denied' }, 200, origin)
}

/**
 * Approve a session with passkey verification
 */
async function handleApprove(
  supabase: ReturnType<typeof createClient>,
  body: any,
  userId: string,
  clientIp: string | null,
  origin: string | null,
) {
  const { session_id, challenge_key, response: authResponse } = body

  if (!challenge_key || !authResponse?.id) {
    return errorResponse('challenge_key and response are required for approval', 400, origin)
  }

  const credentialId = authResponse.id

  // Verify user access
  const access = await verifyUserAccess(supabase, session_id, userId)
  if (!access) {
    return errorResponse('Session not found, expired, or access denied', 404, origin)
  }

  // Retrieve and consume challenge (one-time use)
  const { data: storedChallenge, error: fetchError } = await supabase
    .from('passkey_challenges')
    .select('challenge, user_id, expires_at')
    .eq('challenge_key', challenge_key)
    .single()

  if (fetchError || !storedChallenge) {
    return errorResponse('Challenge expired or not found', 401, origin)
  }

  // Delete immediately (one-time use)
  await supabase.from('passkey_challenges').delete().eq('challenge_key', challenge_key)

  if (new Date(storedChallenge.expires_at) < new Date()) {
    return errorResponse('Challenge has expired', 401, origin)
  }

  // Verify challenge was issued to this user
  if (storedChallenge.user_id !== userId) {
    return errorResponse('Authentication failed', 401, origin)
  }

  // Look up credential
  const { data: credential, error: credError } = await supabase
    .from('user_passkeys')
    .select('id, user_id, public_key, counter, transports')
    .eq('credential_id', credentialId)
    .eq('user_id', userId)
    .eq('is_active', true)
    .single()

  if (credError || !credential) {
    await supabase.from('audit_logs').insert({
      user_id: userId,
      action: 'machine_auth_approve_failed',
      action_category: 'machine',
      ip_address: clientIp,
      metadata: { reason: 'credential_not_found', session_id },
      success: false,
    })
    return errorResponse('Passkey not found', 401, origin)
  }

  // Get allowed origins (same pattern as passkey-auth)
  let allowedOrigins = [...EXPECTED_ORIGINS]
  try {
    const { data: userOrigins } = await supabase.rpc('get_user_trusted_origins', {
      p_user_id: userId,
    })
    if (userOrigins && Array.isArray(userOrigins)) {
      allowedOrigins = [...allowedOrigins, ...userOrigins]
    }
  } catch {
    // Continue with default origins
  }

  // Verify the assertion
  let verification
  try {
    const publicKeyBytes = base64urlToBytes(
      credential.public_key
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '')
    )

    verification = await verifyAuthenticationResponse({
      response: authResponse as AuthenticationResponseJSON,
      expectedChallenge: storedChallenge.challenge,
      expectedOrigin: allowedOrigins,
      expectedRPID: RP_ID,
      credential: {
        id: credentialId,
        publicKey: publicKeyBytes,
        counter: credential.counter || 0,
        transports: (credential.transports || ['internal']) as AuthenticatorTransportFuture[],
      },
    })

    if (!verification.verified) {
      await supabase.from('audit_logs').insert({
        user_id: userId,
        action: 'machine_auth_approve_failed',
        action_category: 'machine',
        ip_address: clientIp,
        metadata: { reason: 'signature_invalid', session_id },
        success: false,
      })
      return errorResponse('Biometric verification failed', 401, origin)
    }
  } catch (verifyError) {
    console.error('[MACHINE-AUTH-APPROVE] Verification exception:', verifyError)
    await supabase.from('audit_logs').insert({
      user_id: userId,
      action: 'machine_auth_approve_failed',
      action_category: 'machine',
      ip_address: clientIp,
      metadata: { reason: 'verification_exception', error: String(verifyError), session_id },
      success: false,
    })
    return errorResponse('Authentication failed', 401, origin)
  }

  // Update passkey counter
  await supabase
    .from('user_passkeys')
    .update({
      counter: verification.authenticationInfo.newCounter,
      last_used_at: new Date().toISOString(),
    })
    .eq('id', credential.id)

  // Approve the session
  const { error: approveError } = await supabase
    .from('machine_login_sessions')
    .update({
      status: 'approved',
      approved_by_user_id: userId,
      auth_level: 'biometric',
      approved_at: new Date().toISOString(),
    })
    .eq('id', session_id)
    .eq('status', 'pending')

  if (approveError) {
    console.error('[MACHINE-AUTH-APPROVE] Approve update error:', approveError)
    return errorResponse('Failed to approve session', 500, origin)
  }

  // Audit log
  await supabase.from('audit_logs').insert({
    user_id: userId,
    action: 'machine_auth_approved',
    action_category: 'machine',
    ip_address: clientIp,
    metadata: {
      session_id,
      machine_id: access.machine.id,
      machine_name: access.machine.machine_name,
      session_code: access.session.session_code,
      auth_level: 'biometric',
    },
    success: true,
  })

  return jsonResponse({
    success: true,
    status: 'approved',
    machine_name: access.machine.machine_name,
    session_code: access.session.session_code,
  }, 200, origin)
}
