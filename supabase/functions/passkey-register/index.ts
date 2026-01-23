/**
 * Passkey Registration Endpoint
 *
 * PURPOSE: Register WebAuthn passkeys for users to enable biometric authentication.
 *
 * FLOW:
 * 1. Client requests registration options (GET ?action=options)
 * 2. Client registers passkey with device
 * 3. Client sends RegistrationResponseJSON (POST)
 * 4. Server verifies using @simplewebauthn/server and stores credential
 *
 * ENDPOINTS:
 * - GET: List passkeys or get registration options
 * - POST: Register new passkey
 * - DELETE: Remove a passkey
 *
 * SECURITY:
 * - Requires valid user session (verified via service role)
 * - Full WebAuthn verification using battle-tested @simplewebauthn/server library
 * - Credentials stored with COSE-encoded public keys
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { handleCors, jsonResponse, errorResponse } from '../_shared/cors.ts'
import {
  RP_ID,
  RP_NAME,
  EXPECTED_ORIGINS,
  CHALLENGE_EXPIRY_MS,
} from '../_shared/webauthn-config.ts'
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from 'jsr:@simplewebauthn/server'
import type { RegistrationResponseJSON } from 'jsr:@simplewebauthn/types'

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!

Deno.serve(async (req) => {
  console.log(`[PASSKEY-REGISTER] Incoming ${req.method} request`)

  const corsResponse = handleCors(req)
  if (corsResponse) return corsResponse

  const origin = req.headers.get('Origin')

  try {
    const authHeader = req.headers.get('Authorization')
    console.log('[PASSKEY-REGISTER] Authorization header:', authHeader ? authHeader.substring(0, 30) + '...' : 'MISSING')

    if (!authHeader) {
      console.error('[PASSKEY-REGISTER] Missing Authorization header')
      return errorResponse('Authorization required', 401, origin)
    }

    // Verify the User Session using service role (can verify any token)
    const token = authHeader.replace('Bearer ', '')
    const supabaseAuth = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    const { data: { user }, error: authError } = await supabaseAuth.auth.getUser(token)

    if (authError || !user) {
      console.error('[PASSKEY-REGISTER] Auth failed:', authError?.message)
      return errorResponse('Invalid or expired session', 401, origin)
    }
    console.log(`[PASSKEY-REGISTER] Authenticated user: ${user.id}`)

    // Initialize Admin Client for DB
    const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

    // GET: List passkeys or get registration options
    if (req.method === 'GET') {
      const url = new URL(req.url)
      const action = url.searchParams.get('action')

      if (action === 'options') {
        return await handleGetOptions(supabaseAdmin, user, origin)
      }

      // Default: List passkeys
      return await handleListPasskeys(supabaseAdmin, user, origin)
    }

    // POST: Register new passkey
    if (req.method === 'POST') {
      return await handleRegister(supabaseAdmin, user, req, origin)
    }

    // DELETE: Remove a passkey
    if (req.method === 'DELETE') {
      return await handleDelete(supabaseAdmin, user, req, origin)
    }

    return errorResponse('Method not allowed', 405, origin)
  } catch (err: any) {
    console.error('[PASSKEY-REGISTER] Uncaught exception:', err.message)
    return errorResponse('Internal server error', 500, origin)
  }
})

/**
 * GET ?action=options: Generate registration options
 */
async function handleGetOptions(
  supabase: ReturnType<typeof createClient>,
  user: { id: string; email?: string },
  origin: string | null
) {
  console.log('[PASSKEY-REGISTER] Generating registration options...')

  // Get existing credentials to exclude
  const { data: existingCredentials } = await supabase
    .from('user_passkeys')
    .select('credential_id')
    .eq('user_id', user.id)
    .eq('is_active', true)

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userName: user.email || user.id,
    userDisplayName: user.email?.split('@')[0] || 'User',
    userID: new TextEncoder().encode(user.id),
    attestationType: 'none',
    authenticatorSelection: {
      userVerification: 'preferred',
      residentKey: 'preferred',
    },
    timeout: CHALLENGE_EXPIRY_MS,
    excludeCredentials: existingCredentials?.map(c => ({
      id: c.credential_id,
    })) || [],
  })

  // Store challenge for verification
  const challengeKey = `reg:${user.id}:${Date.now()}`
  const { error: insertError } = await supabase
    .from('passkey_challenges')
    .insert({
      challenge_key: challengeKey,
      challenge: options.challenge,
      user_id: user.id,
      expires_at: new Date(Date.now() + CHALLENGE_EXPIRY_MS).toISOString(),
    })

  if (insertError) {
    console.error('[PASSKEY-REGISTER] Failed to store challenge:', insertError)
    return errorResponse('Failed to generate registration options', 500, origin)
  }

  return jsonResponse({
    options,
    challenge_key: challengeKey,
  }, 200, origin)
}

/**
 * GET: List user's passkeys
 */
async function handleListPasskeys(
  supabase: ReturnType<typeof createClient>,
  user: { id: string },
  origin: string | null
) {
  console.log('[PASSKEY-REGISTER] Fetching passkeys...')

  const { data, error } = await supabase
    .from('user_passkeys')
    .select('id, credential_id, device_name, authenticator_type, created_at, last_used_at, is_active')
    .eq('user_id', user.id)
    .eq('is_active', true)

  if (error) {
    console.error('[PASSKEY-REGISTER] Database error (List):', error.message)
    return errorResponse('Failed to fetch passkeys', 500, origin)
  }

  return jsonResponse({ passkeys: data }, 200, origin)
}

/**
 * POST: Register new passkey
 * Body: { challenge_key, response: RegistrationResponseJSON, device_name? }
 */
async function handleRegister(
  supabase: ReturnType<typeof createClient>,
  user: { id: string },
  req: Request,
  origin: string | null
) {
  let body
  try {
    body = await req.json()
  } catch {
    return errorResponse('Invalid request body', 400, origin)
  }

  console.log('[PASSKEY-REGISTER] Registering new passkey...')

  const { challenge_key, response, device_name } = body

  if (!challenge_key || !response) {
    return errorResponse('Challenge key and response are required', 400, origin)
  }

  // Retrieve stored challenge
  const { data: storedChallenge, error: fetchError } = await supabase
    .from('passkey_challenges')
    .select('challenge, user_id, expires_at')
    .eq('challenge_key', challenge_key)
    .single()

  if (fetchError || !storedChallenge) {
    console.error('[PASSKEY-REGISTER] Challenge not found')
    return errorResponse('Challenge expired or not found', 401, origin)
  }

  // Delete challenge (one-time use)
  await supabase
    .from('passkey_challenges')
    .delete()
    .eq('challenge_key', challenge_key)

  // Check expiry
  if (new Date(storedChallenge.expires_at) < new Date()) {
    return errorResponse('Challenge has expired', 401, origin)
  }

  // Verify user matches
  if (storedChallenge.user_id !== user.id) {
    return errorResponse('Session mismatch', 401, origin)
  }

  // Verify registration response
  let verification
  try {
    verification = await verifyRegistrationResponse({
      response: response as RegistrationResponseJSON,
      expectedChallenge: storedChallenge.challenge,
      expectedOrigin: EXPECTED_ORIGINS,
      expectedRPID: RP_ID,
    })

    if (!verification.verified || !verification.registrationInfo) {
      console.error('[PASSKEY-REGISTER] Verification failed')
      return errorResponse('Registration verification failed', 401, origin)
    }
    console.log('[PASSKEY-REGISTER] Verification successful')
  } catch (verifyError) {
    console.error('[PASSKEY-REGISTER] Verification exception:', verifyError)
    return errorResponse('Registration verification failed', 401, origin)
  }

  const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo

  // Convert public key to base64 for storage
  const publicKeyB64 = btoa(String.fromCharCode(...credential.publicKey))

  // Store the credential
  const { data, error } = await supabase
    .from('user_passkeys')
    .upsert({
      user_id: user.id,
      credential_id: credential.id,
      public_key: publicKeyB64,
      device_name: device_name || 'Device',
      authenticator_type: credentialDeviceType,
      transports: credential.transports || ['internal'],
      is_active: true,
      counter: credential.counter,
      backed_up: credentialBackedUp,
    }, {
      onConflict: 'credential_id',
    })
    .select()

  if (error) {
    console.error('[PASSKEY-REGISTER] Database error:', error.message)
    return errorResponse('Failed to save passkey', 500, origin)
  }

  // Log successful registration
  await supabase.from('audit_logs').insert({
    user_id: user.id,
    action: 'passkey_registered',
    action_category: 'auth',
    metadata: {
      credential_id: credential.id.substring(0, 16),
      device_type: credentialDeviceType,
      backed_up: credentialBackedUp,
    },
    success: true,
  })

  console.log('[PASSKEY-REGISTER] Registration successful')
  return jsonResponse({ success: true, data }, 201, origin)
}

/**
 * DELETE: Remove a passkey
 * Body: { passkey_id }
 */
async function handleDelete(
  supabase: ReturnType<typeof createClient>,
  user: { id: string },
  req: Request,
  origin: string | null
) {
  let body
  try {
    body = await req.json()
  } catch {
    return errorResponse('Invalid request body', 400, origin)
  }

  const { passkey_id } = body

  if (!passkey_id) {
    return errorResponse('Passkey ID is required', 400, origin)
  }

  // Soft delete (set is_active = false)
  const { error } = await supabase
    .from('user_passkeys')
    .update({ is_active: false })
    .eq('id', passkey_id)
    .eq('user_id', user.id)

  if (error) {
    console.error('[PASSKEY-REGISTER] Delete error:', error.message)
    return errorResponse('Failed to delete passkey', 500, origin)
  }

  // Log deletion
  await supabase.from('audit_logs').insert({
    user_id: user.id,
    action: 'passkey_deleted',
    action_category: 'auth',
    metadata: { passkey_id },
    success: true,
  })

  return jsonResponse({ success: true }, 200, origin)
}
