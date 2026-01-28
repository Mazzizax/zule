/**
 * Passkey Authentication Endpoint
 *
 * PURPOSE: Authenticate users via WebAuthn passkeys and return user_id to Dawg Tag.
 *
 * This is an alternative to email/password auth via auth-validate.
 * Both endpoints serve the same purpose: authenticate user, return user_id + tier.
 *
 * FLOW:
 * 1. Client requests challenge (GET with credential_id)
 * 2. Client signs challenge with passkey
 * 3. Client sends signed assertion (POST)
 * 4. Server verifies using @simplewebauthn/server and returns user_id + tier
 *
 * ENDPOINTS:
 * - GET: Request authentication challenge
 * - POST: Verify signed assertion
 *
 * SECURITY:
 * - Dawg Tag receives user_id, computes ghost_id locally, discards user_id
 * - Gatekeeper never knows which app the user is accessing
 * - Gatekeeper never knows the resulting ghost_id
 * - Full WebAuthn verification using battle-tested @simplewebauthn/server library
 * - Rate limiting on failed attempts with lockout protection
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { SignJWT, importJWK } from 'https://deno.land/x/jose@v5.2.0/index.ts'
import { handleCors, jsonResponse, errorResponse } from '../_shared/cors.ts'
import {
  RP_ID,
  EXPECTED_ORIGINS,
  CHALLENGE_EXPIRY_MS,
  RATE_LIMIT,
  base64urlToBytes,
} from '../_shared/webauthn-config.ts'
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from 'jsr:@simplewebauthn/server'
import type {
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
} from 'jsr:@simplewebauthn/types'

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!

/**
 * Clean up expired challenges from database
 */
async function cleanupExpiredChallenges(supabase: ReturnType<typeof createClient>) {
  try {
    await supabase.from('passkey_challenges').delete().lt('expires_at', new Date().toISOString())
  } catch {
    // Ignore cleanup errors
  }
}

/**
 * Check rate limit for failed authentication attempts
 * Returns { allowed: boolean, retryAfter?: number }
 */
async function checkRateLimit(
  supabase: ReturnType<typeof createClient>,
  identifier: string
): Promise<{ allowed: boolean; retryAfter?: number }> {
  try {
    const windowStart = new Date(Date.now() - RATE_LIMIT.ATTEMPT_WINDOW_MS).toISOString()

    // Count failed attempts in the window
    const { count } = await supabase
      .from('audit_logs')
      .select('*', { count: 'exact', head: true })
      .eq('action', 'passkey_auth_failed')
      .gte('created_at', windowStart)
      .or(`ip_address.eq.${identifier},metadata->>credential_id.eq.${identifier}`)

    if ((count || 0) >= RATE_LIMIT.MAX_FAILED_ATTEMPTS) {
      // Get the most recent failed attempt to calculate retry time
      const { data: recentAttempt } = await supabase
        .from('audit_logs')
        .select('created_at')
        .eq('action', 'passkey_auth_failed')
        .or(`ip_address.eq.${identifier},metadata->>credential_id.eq.${identifier}`)
        .order('created_at', { ascending: false })
        .limit(1)
        .single()

      if (recentAttempt) {
        const lockoutEnd = new Date(recentAttempt.created_at).getTime() + RATE_LIMIT.LOCKOUT_DURATION_MS
        const now = Date.now()
        if (now < lockoutEnd) {
          return { allowed: false, retryAfter: Math.ceil((lockoutEnd - now) / 1000) }
        }
      }
    }

    return { allowed: true }
  } catch {
    // On rate limit check failure, allow the request (fail open for availability)
    return { allowed: true }
  }
}

Deno.serve(async (req) => {
  console.log('[PASSKEY-AUTH] Request:', req.method, req.url)

  // Handle CORS preflight
  const corsResponse = handleCors(req)
  if (corsResponse) return corsResponse

  const origin = req.headers.get('Origin')

  // Debug: Check if secrets are loaded
  console.log('[PASSKEY-AUTH] SUPABASE_URL:', SUPABASE_URL ? 'set' : 'MISSING')
  console.log('[PASSKEY-AUTH] SUPABASE_SERVICE_ROLE_KEY:', SUPABASE_SERVICE_ROLE_KEY ? 'set' : 'MISSING')

  if (!SUPABASE_SERVICE_ROLE_KEY) {
    console.error('[PASSKEY-AUTH] SUPABASE_SERVICE_ROLE_KEY is not set!')
    return errorResponse('Server configuration error', 500, origin)
  }

  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

  // Clean up expired challenges periodically
  await cleanupExpiredChallenges(supabase)

  // Get client IP for rate limiting
  const clientIp = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown'

  try {
    if (req.method === 'GET') {
      // Request challenge for authentication
      return await handleGetChallenge(supabase, req, origin, clientIp)
    } else if (req.method === 'POST') {
      // Verify signed assertion
      return await handleVerifyAssertion(supabase, req, origin, clientIp)
    } else {
      return errorResponse('Method not allowed', 405, origin)
    }
  } catch (error) {
    console.error('[PASSKEY-AUTH] Error:', error)
    return errorResponse('Internal server error', 500, origin)
  }
})

/**
 * GET: Request authentication challenge
 * Query params: credential_id (base64url encoded)
 */
async function handleGetChallenge(
  supabase: ReturnType<typeof createClient>,
  req: Request,
  origin: string | null,
  clientIp: string
) {
  const url = new URL(req.url)
  const credentialId = url.searchParams.get('credential_id')

  if (!credentialId) {
    return errorResponse('Credential ID is required', 400, origin)
  }

  // Check rate limit before processing
  const rateCheck = await checkRateLimit(supabase, clientIp)
  if (!rateCheck.allowed) {
    return errorResponse(
      `Too many failed attempts. Try again in ${rateCheck.retryAfter} seconds.`,
      429,
      origin
    )
  }

  // Look up the credential to get the user
  const { data: credential, error: credError } = await supabase
    .from('user_passkeys')
    .select('user_id, public_key, counter, transports')
    .eq('credential_id', credentialId)
    .eq('is_active', true)
    .single()

  if (credError || !credential) {
    // Don't reveal if credential exists or not
    return errorResponse('Invalid credential', 401, origin)
  }

  // Generate authentication options using @simplewebauthn/server
  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: 'preferred',
    timeout: CHALLENGE_EXPIRY_MS,
    allowCredentials: [{
      id: credentialId,
      transports: (credential.transports || ['internal', 'hybrid']) as AuthenticatorTransportFuture[],
    }],
  })

  // Store challenge in database for verification
  const challengeKey = `${credentialId}:${Date.now()}`
  const expiresAt = new Date(Date.now() + CHALLENGE_EXPIRY_MS).toISOString()

  const { error: insertError } = await supabase
    .from('passkey_challenges')
    .insert({
      challenge_key: challengeKey,
      challenge: options.challenge,
      user_id: credential.user_id,
      expires_at: expiresAt,
    })

  if (insertError) {
    console.error('[PASSKEY-AUTH] Failed to store challenge:', insertError)
    return errorResponse('Failed to generate challenge', 500, origin)
  }

  return jsonResponse({
    challenge: options.challenge,
    challenge_key: challengeKey,
    timeout: CHALLENGE_EXPIRY_MS,
    rp_id: RP_ID,
    // Include full options for clients that want them
    options: options,
  }, 200, origin)
}

/**
 * POST: Verify signed assertion
 * Body: { challenge_key, response: AuthenticationResponseJSON }
 */
async function handleVerifyAssertion(
  supabase: ReturnType<typeof createClient>,
  req: Request,
  origin: string | null,
  clientIp: string
) {
  let body
  try {
    body = await req.json()
  } catch {
    return errorResponse('Invalid request body', 400, origin)
  }

  const { challenge_key, response: authResponse } = body

  if (!challenge_key) {
    return errorResponse('Challenge key is required', 400, origin)
  }

  if (!authResponse || !authResponse.id) {
    return errorResponse('Authentication response is required', 400, origin)
  }

  const credentialId = authResponse.id

  // Check rate limit before processing
  const rateCheck = await checkRateLimit(supabase, clientIp)
  if (!rateCheck.allowed) {
    return errorResponse(
      `Too many failed attempts. Try again in ${rateCheck.retryAfter} seconds.`,
      429,
      origin
    )
  }

  // Retrieve challenge from database
  console.log('[PASSKEY-AUTH] Looking up challenge_key:', challenge_key)
  const { data: storedChallenge, error: fetchError } = await supabase
    .from('passkey_challenges')
    .select('challenge, user_id, expires_at')
    .eq('challenge_key', challenge_key)
    .single()

  if (fetchError || !storedChallenge) {
    console.error('[PASSKEY-AUTH] Challenge not found:', challenge_key, fetchError)
    return errorResponse('Challenge expired or not found', 401, origin)
  }
  console.log('[PASSKEY-AUTH] Challenge found for user:', storedChallenge.user_id)

  // Remove challenge immediately (one-time use)
  await supabase.from('passkey_challenges').delete().eq('challenge_key', challenge_key)

  // Check expiry
  if (new Date(storedChallenge.expires_at) < new Date()) {
    return errorResponse('Challenge has expired', 401, origin)
  }

  // Look up credential
  console.log('[PASSKEY-AUTH] Looking up credential_id:', credentialId)
  const { data: credential, error: credError } = await supabase
    .from('user_passkeys')
    .select('id, user_id, public_key, counter, transports')
    .eq('credential_id', credentialId)
    .eq('is_active', true)
    .single()

  if (credError || !credential) {
    console.error('[PASSKEY-AUTH] Credential not found:', credentialId, credError)

    // Log failed attempt for rate limiting
    await supabase.from('audit_logs').insert({
      user_id: storedChallenge.user_id,
      action: 'passkey_auth_failed',
      action_category: 'auth',
      ip_address: clientIp,
      metadata: { reason: 'credential_not_found', credential_id: credentialId.substring(0, 16) },
      success: false,
    })

    return errorResponse('Passkey not found or has been revoked', 401, origin)
  }
  console.log('[PASSKEY-AUTH] Credential found, user_id:', credential.user_id)

  // Verify user matches
  if (credential.user_id !== storedChallenge.user_id) {
    console.error('[PASSKEY-AUTH] User mismatch:', credential.user_id, 'vs', storedChallenge.user_id)

    await supabase.from('audit_logs').insert({
      user_id: credential.user_id,
      action: 'passkey_auth_failed',
      action_category: 'auth',
      ip_address: clientIp,
      metadata: { reason: 'user_mismatch' },
      success: false,
    })

    return errorResponse('Authentication failed', 401, origin)
  }

  // Get user's trusted client origins (for Dawg Tag, etc.)
  let allowedOrigins = [...EXPECTED_ORIGINS]
  let originsDebug = 'not fetched'
  try {
    // First check if table has ANY data
    const { data: allOrigins, count } = await supabase
      .from('trusted_client_origins')
      .select('user_id, origin, is_active', { count: 'exact' })
      .limit(5)

    originsDebug = `table_count=${count}, user=${credential.user_id.substring(0,8)}`
    console.log('[PASSKEY-AUTH] All origins in table:', allOrigins)

    // Then get this user's origins
    const { data: userOrigins, error: originsError } = await supabase.rpc('get_user_trusted_origins', {
      p_user_id: credential.user_id,
    })
    originsDebug += `, rpc_result=${JSON.stringify(userOrigins)}`
    if (originsError) {
      console.log('[PASSKEY-AUTH] RPC error:', originsError)
    } else if (userOrigins && Array.isArray(userOrigins)) {
      allowedOrigins = [...allowedOrigins, ...userOrigins]
      console.log('[PASSKEY-AUTH] Including user trusted origins:', userOrigins.length, userOrigins)
    }
  } catch (originsError) {
    originsDebug = `exception: ${originsError}`
    console.log('[PASSKEY-AUTH] Could not fetch user origins:', originsError)
  }

  // Decode clientDataJSON to see the actual origin being sent
  let receivedOrigin = 'unknown'
  try {
    const clientDataJSON = authResponse.response?.clientDataJSON
    if (clientDataJSON) {
      const decoded = JSON.parse(new TextDecoder().decode(base64urlToBytes(clientDataJSON)))
      receivedOrigin = decoded.origin || 'not found'
      console.log('[PASSKEY-AUTH] Received origin from client:', receivedOrigin)
      console.log('[PASSKEY-AUTH] Allowed origins:', JSON.stringify(allowedOrigins))
    }
  } catch (decodeErr) {
    console.log('[PASSKEY-AUTH] Could not decode clientDataJSON:', decodeErr)
  }

  // Verify the assertion using @simplewebauthn/server
  let verification
  try {
    // Decode public key from base64 to Uint8Array
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
      console.error('[PASSKEY-AUTH] Verification failed')

      await supabase.from('audit_logs').insert({
        user_id: credential.user_id,
        action: 'passkey_auth_failed',
        action_category: 'auth',
        ip_address: clientIp,
        metadata: { reason: 'signature_invalid', credential_id: credentialId.substring(0, 16) },
        success: false,
      })

      return errorResponse('Biometric verification failed', 401, origin)
    }
    console.log('[PASSKEY-AUTH] Signature verified successfully')
  } catch (verifyError) {
    console.error('[PASSKEY-AUTH] Verification exception:', verifyError)
    console.error('[PASSKEY-AUTH] Received origin:', receivedOrigin)
    console.error('[PASSKEY-AUTH] Allowed origins:', JSON.stringify(allowedOrigins))

    await supabase.from('audit_logs').insert({
      user_id: credential.user_id,
      action: 'passkey_auth_failed',
      action_category: 'auth',
      ip_address: clientIp,
      metadata: { reason: 'verification_exception', error: String(verifyError), credential_id: credentialId.substring(0, 16), received_origin: receivedOrigin },
      success: false,
    })

    // Include origin info in error for debugging
    const isInList = allowedOrigins.includes(receivedOrigin)
    return errorResponse(`InList: ${isInList}, Count: ${allowedOrigins.length}, RPC: ${originsDebug.substring(0, 100)}`, 401, origin)
  }

  // Update counter (replay protection handled by simplewebauthn)
  const newCounter = verification.authenticationInfo.newCounter
  console.log('[PASSKEY-AUTH] Counter update: old=', credential.counter, 'new=', newCounter)

  // Update counter and last used
  await supabase
    .from('user_passkeys')
    .update({
      counter: newCounter,
      last_used_at: new Date().toISOString(),
    })
    .eq('id', credential.id)

  // ------------------------------------------------------------------
  // Generate verification_token for mint-session
  // ------------------------------------------------------------------
  const attestationKeyJson = Deno.env.get('ATTESTATION_SIGNING_KEY')
  if (!attestationKeyJson) {
    console.error('[PASSKEY-AUTH] ATTESTATION_SIGNING_KEY not configured')
    return errorResponse('Server configuration error', 500, origin)
  }

  let verificationToken: string
  let attestation: string
  try {
    const attestationKey = JSON.parse(attestationKeyJson)
    const privateKey = await importJWK(attestationKey, 'ES256')
    const now = Math.floor(Date.now() / 1000)

    // Verification token for mint-session (30 seconds, single use)
    verificationToken = await new SignJWT({
      type: 'passkey_verified',
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'JWT' })
      .setIssuer('gatekeeper-passkey')
      .setAudience('mint-session')
      .setSubject(credential.user_id)
      .setIssuedAt(now)
      .setExpirationTime(now + 30)
      .setJti(crypto.randomUUID())
      .sign(privateKey)

    // Attestation for Dawg Tag flow (5 minutes)
    attestation = await new SignJWT({
      type: 'attestation',
      valid: true,
      auth_level: 'biometric',
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'JWT' })
      .setIssuer('gatekeeper')
      .setAudience('ghost-auth')
      .setIssuedAt(now)
      .setExpirationTime(now + 300)
      .setJti(crypto.randomUUID())
      .sign(privateKey)

    console.log('[PASSKEY-AUTH] Generated verification token and attestation')
  } catch (err) {
    console.error('[PASSKEY-AUTH] Failed to generate tokens:', err)
    return errorResponse('Failed to generate session', 500, origin)
  }

  // Get user's subscription tier
  const { data: profile } = await supabase
    .from('user_profiles')
    .select('subscription_tier, subscription_status')
    .eq('id', credential.user_id)
    .single()

  const tier = (profile?.subscription_status === 'active')
    ? (profile?.subscription_tier || 'free')
    : 'free'

  // Log successful auth
  await supabase.from('audit_logs').insert({
    user_id: credential.user_id,
    action: 'passkey_authenticated',
    action_category: 'auth',
    ip_address: clientIp,
    metadata: { tier, credential_id: credentialId.substring(0, 16) },
    success: true,
  })

  // Update last_seen_at
  await supabase
    .from('user_profiles')
    .update({ last_seen_at: new Date().toISOString() })
    .eq('id', credential.user_id)

  // Return tokens and user info
  return jsonResponse({
    user_id: credential.user_id,
    tier: tier,
    verification_token: verificationToken,
    attestation: attestation,
  }, 200, origin)
}
