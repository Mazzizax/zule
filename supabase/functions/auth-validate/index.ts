/**
 * Auth Validate Endpoint
 *
 * PURPOSE: Validate user credentials and return a blind attestation to Vinzrik.
 *
 * SECURITY:
 * - Vinzrik receives ONLY an attestation (proof of auth, no user identity)
 * - Attestation contains NO user_id, NO email, NO identifying information
 * - Zule never knows which app the user is accessing
 *
 * REQUEST:
 * POST /auth-validate
 * {
 *   "email": "user@example.com",
 *   "password": "..."
 * }
 *
 * RESPONSE (success):
 * {
 *   "attestation": "jwt...",
 *   "tier": "free|standard|premium|enterprise"
 * }
 *
 * RESPONSE (error):
 * {
 *   "error": "Invalid credentials"
 * }
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { SignJWT, importJWK } from 'https://deno.land/x/jose@v5.2.0/index.ts'
import { handleCors, jsonResponse, errorResponse, getCorsHeaders } from '../_shared/cors.ts'
import { checkRateLimit } from '../_shared/rate-limit.ts'

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!
const SUPABASE_SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!

Deno.serve(async (req) => {
  // Handle CORS preflight
  const corsResponse = handleCors(req)
  if (corsResponse) return corsResponse

  const origin = req.headers.get('Origin')

  // Only allow POST
  if (req.method !== 'POST') {
    return errorResponse('Method not allowed', 405, origin)
  }

  try {
    const { email, password } = await req.json()

    if (!email || !password) {
      return errorResponse('Email and password are required', 400, origin)
    }

    // Extract client IP for audit logging
    const clientIp = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
      || req.headers.get('x-real-ip')
      || 'unknown'

    // Create service client
    const serviceClient = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY)

    // Centralized rate limiting (by IP — no user ID available yet)
    const rateLimited = await checkRateLimit(serviceClient, req, 'auth-validate')
    if (rateLimited) return rateLimited

    // Create anonymous client for authentication
    const anonClient = createClient(SUPABASE_URL, Deno.env.get('SUPABASE_ANON_KEY')!)

    // Attempt authentication
    const { data: authData, error: authError } = await anonClient.auth.signInWithPassword({
      email,
      password
    })

    if (authError || !authData.user) {
      // Log failed attempt
      await serviceClient.from('audit_logs').insert({
        action: 'auth_failed',
        action_category: 'auth',
        ip_address: clientIp,
        metadata: { email: email.toLowerCase() },
        success: false,
        error_message: 'Invalid credentials'
      })

      // Return generic error (don't reveal if email exists)
      return errorResponse('Invalid credentials', 401, origin)
    }

    // Reject unverified email
    if (!authData.user.email_confirmed_at) {
      await serviceClient.from('audit_logs').insert({
        action: 'auth_rejected_unverified',
        action_category: 'auth',
        ip_address: clientIp,
        metadata: { email: email.toLowerCase() },
        success: false,
        error_message: 'Email not verified'
      })

      return errorResponse('Email not verified. Please check your inbox and verify your email.', 403, origin)
    }

    const userId = authData.user.id

    // Get user's subscription tier
    const { data: profile } = await serviceClient
      .from('user_profiles')
      .select('subscription_tier, subscription_status')
      .eq('id', userId)
      .single()

    const tier = (profile?.subscription_status === 'active')
      ? (profile?.subscription_tier || 'free')
      : 'free'

    // Log successful auth
    await serviceClient.from('audit_logs').insert({
      user_id: userId,
      action: 'auth_validated',
      action_category: 'auth',
      ip_address: clientIp,
      metadata: { tier },
      success: true
    })

    // Update last_seen_at
    await serviceClient
      .from('user_profiles')
      .update({ last_seen_at: new Date().toISOString() })
      .eq('id', userId)

    // Check if user has a registered passkey (for biometric login on future visits)
    // We return the credential_id so Vinzrik can store it locally
    const { data: passkeys } = await serviceClient
      .from('user_passkeys')
      .select('credential_id')
      .eq('user_id', userId)
      .eq('is_active', true)
      .limit(1)

    const credentialId = passkeys?.[0]?.credential_id || null

    // ------------------------------------------------------------------
    // Generate blind attestation (NO user_id, NO email, NO identifying info)
    // ------------------------------------------------------------------
    const attestationKeyJson = Deno.env.get('ATTESTATION_SIGNING_KEY')
    if (!attestationKeyJson) {
      console.error('[AUTH-VALIDATE] ATTESTATION_SIGNING_KEY not configured')
      return errorResponse('Server configuration error', 500, origin)
    }

    let attestation: string
    try {
      const attestationKey = JSON.parse(attestationKeyJson)
      const privateKey = await importJWK(attestationKey, 'ES256')
      const now = Math.floor(Date.now() / 1000)

      // Attestation for Vinzrik (5 minutes)
      // Contains NO user_id, NO email - just proof that someone authenticated
      attestation = await new SignJWT({
        type: 'attestation',
        valid: true,
        auth_level: 'password',
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'JWT' })
        .setIssuer('zule')
        .setAudience('ghozerauth')
        .setIssuedAt(now)
        .setExpirationTime(now + 300)
        .setJti(crypto.randomUUID())
        .sign(privateKey)

      console.log('[AUTH-VALIDATE] Generated attestation')
    } catch (err) {
      console.error('[AUTH-VALIDATE] Failed to generate attestation:', err)
      return errorResponse('Failed to generate attestation', 500, origin)
    }

    // Return attestation, tier, and credential_id to Vinzrik
    // NO user_id, NO email - just blind proof of authentication
    // credential_id allows biometric login on future visits
    return jsonResponse({
      attestation: attestation,
      tier: tier,
      credential_id: credentialId
    }, 200, origin)

  } catch (error) {
    console.error('Auth validate error:', error)
    return errorResponse('Internal server error', 500, origin)
  }
})
