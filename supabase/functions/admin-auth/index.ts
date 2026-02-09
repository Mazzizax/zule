/**
 * Admin Authentication Endpoint
 *
 * PURPOSE: Authenticate admins and issue admin JWTs for Goals admin panel.
 *
 * CRITICAL: This is SEPARATE from ghost auth. Admin auth uses REAL identity
 * (user_id, email) so admin actions can be audited. Ghost auth keeps user
 * identity hidden for regular users.
 *
 * FLOW:
 * 1. User authenticates via email/password OR passkey verification_token
 * 2. Check admin_level in user_profiles (must be > 0)
 * 3. Issue admin JWT with {user_id, email, admin_level, display_name}
 * 4. Return admin_jwt for use in Goals admin panel
 *
 * ADMIN LEVELS:
 *   0     = No admin access (rejected)
 *   1     = Basic Admin (view stats, basic moderation)
 *   2     = Full Admin (user management, content control)
 *   3-98  = Reserved for future
 *   99    = SageLevel (system-awarded, full access)
 *
 * REQUEST:
 * POST /admin-auth
 * {
 *   "email": "admin@example.com",
 *   "password": "..."
 * }
 * OR
 * {
 *   "verification_token": "jwt...",
 *   "user_id": "uuid..."
 * }
 *
 * RESPONSE (success):
 * {
 *   "admin_jwt": "jwt...",
 *   "admin_level": 2,
 *   "email": "admin@example.com",
 *   "display_name": "Admin Name",
 *   "expires_in": 3600
 * }
 *
 * RESPONSE (error):
 * {
 *   "error": "Admin access denied"
 * }
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { SignJWT, jwtVerify, importJWK } from 'https://deno.land/x/jose@v5.2.0/index.ts'
import { handleCors, jsonResponse, errorResponse } from '../_shared/cors.ts'

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
const SUPABASE_ANON_KEY = Deno.env.get('SUPABASE_ANON_KEY')!

Deno.serve(async (req) => {
  console.log('[ADMIN-AUTH] Request:', req.method)

  // Handle CORS preflight
  const corsResponse = handleCors(req)
  if (corsResponse) return corsResponse

  const origin = req.headers.get('Origin')

  if (req.method !== 'POST') {
    return errorResponse('Method not allowed', 405, origin)
  }

  try {
    const body = await req.json()
    const { email, password, verification_token, user_id: providedUserId } = body

    const serviceClient = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    const clientIp = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
                     req.headers.get('x-real-ip') ||
                     'unknown'

    let authenticatedUserId: string

    // ------------------------------------------------------------------
    // Route 1: Email/Password Authentication
    // ------------------------------------------------------------------
    if (email && password) {
      console.log('[ADMIN-AUTH] Attempting email/password auth for:', email)

      const anonClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY)

      const { data: authData, error: authError } = await anonClient.auth.signInWithPassword({
        email,
        password
      })

      if (authError || !authData.user) {
        await serviceClient.from('audit_logs').insert({
          action: 'admin_auth_failed',
          action_category: 'auth',
          ip_address: clientIp,
          metadata: { email: email.toLowerCase(), reason: 'invalid_credentials' },
          success: false,
          error_message: 'Invalid credentials'
        })
        return errorResponse('Invalid credentials', 401, origin)
      }

      authenticatedUserId = authData.user.id
      console.log('[ADMIN-AUTH] Password auth successful for:', authenticatedUserId.substring(0, 8))
    }
    // ------------------------------------------------------------------
    // Route 2: Passkey Verification Token
    // ------------------------------------------------------------------
    else if (verification_token && providedUserId) {
      console.log('[ADMIN-AUTH] Attempting passkey auth for user:', providedUserId.substring(0, 8))

      const attestationKeyJson = Deno.env.get('ATTESTATION_SIGNING_KEY')
      if (!attestationKeyJson) {
        console.error('[ADMIN-AUTH] ATTESTATION_SIGNING_KEY not configured')
        return errorResponse('Server configuration error', 500, origin)
      }

      try {
        const attestationKey = JSON.parse(attestationKeyJson)
        // Extract public key only (remove private key 'd' component)
        const { d: _privateKey, ...publicKeyOnly } = attestationKey
        const publicKey = await importJWK(publicKeyOnly, 'ES256')

        const { payload } = await jwtVerify(verification_token, publicKey, {
          issuer: 'zule-passkey',
          audience: 'mint-session'
        })

        if (payload.type !== 'passkey_verified') {
          throw new Error('Invalid token type')
        }

        if (payload.sub !== providedUserId) {
          throw new Error('User ID mismatch')
        }

        authenticatedUserId = payload.sub as string
        console.log('[ADMIN-AUTH] Passkey auth successful for:', authenticatedUserId.substring(0, 8))
      } catch (err: unknown) {
        const errorMsg = err instanceof Error ? err.message : 'Unknown error'
        console.error('[ADMIN-AUTH] Verification token invalid:', errorMsg)
        await serviceClient.from('audit_logs').insert({
          action: 'admin_auth_failed',
          action_category: 'auth',
          ip_address: clientIp,
          metadata: { reason: 'invalid_verification_token', error: errorMsg },
          success: false,
          error_message: 'Invalid verification token'
        })
        return errorResponse('Invalid verification token', 401, origin)
      }
    }
    else {
      return errorResponse('Email/password or verification_token required', 400, origin)
    }

    // ------------------------------------------------------------------
    // Check Admin Level
    // ------------------------------------------------------------------
    const { data: adminInfo, error: adminError } = await serviceClient
      .rpc('get_admin_info', { p_user_id: authenticatedUserId })
      .single()

    if (adminError || !adminInfo || adminInfo.admin_level < 1) {
      console.log('[ADMIN-AUTH] Admin access denied for user:', authenticatedUserId.substring(0, 8))
      console.log('[ADMIN-AUTH] Admin level:', adminInfo?.admin_level ?? 0)

      await serviceClient.from('audit_logs').insert({
        user_id: authenticatedUserId,
        action: 'admin_auth_denied',
        action_category: 'auth',
        ip_address: clientIp,
        metadata: { reason: 'not_admin', admin_level: adminInfo?.admin_level ?? 0 },
        success: false,
        error_message: 'Admin access denied'
      })
      return errorResponse('Admin access denied', 403, origin)
    }

    console.log('[ADMIN-AUTH] Admin verified:', adminInfo.email, 'level:', adminInfo.admin_level)

    // ------------------------------------------------------------------
    // Issue Admin JWT
    // ------------------------------------------------------------------
    const privateKeyJson = Deno.env.get('ZULE_JWT_PRIVATE_KEY') || Deno.env.get('GATEKEEPER_JWT_PRIVATE_KEY')
    if (!privateKeyJson) {
      console.error('[ADMIN-AUTH] ZULE_JWT_PRIVATE_KEY not configured')
      return errorResponse('Server configuration error', 500, origin)
    }

    let adminJwt: string
    try {
      const keyData = JSON.parse(privateKeyJson)
      const privateKey = await importJWK(keyData, 'ES256')
      const now = Math.floor(Date.now() / 1000)
      const expiresIn = 3600 // 1 hour for admin sessions

      adminJwt = await new SignJWT({
        type: 'admin',
        admin_level: adminInfo.admin_level,
        email: adminInfo.email,
        display_name: adminInfo.display_name
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: keyData.kid })
        .setIssuer('zule')
        .setAudience('goals-admin')
        .setSubject(authenticatedUserId)
        .setIssuedAt(now)
        .setExpirationTime(now + expiresIn)
        .setJti(crypto.randomUUID())
        .sign(privateKey)

      console.log('[ADMIN-AUTH] Admin JWT issued for:', adminInfo.email)
    } catch (err) {
      console.error('[ADMIN-AUTH] Failed to sign admin JWT:', err)
      return errorResponse('Failed to issue admin token', 500, origin)
    }

    // Log successful admin auth
    await serviceClient.from('audit_logs').insert({
      user_id: authenticatedUserId,
      action: 'admin_authenticated',
      action_category: 'admin',
      ip_address: clientIp,
      metadata: { admin_level: adminInfo.admin_level },
      success: true
    })

    // Update last_seen_at
    await serviceClient
      .from('user_profiles')
      .update({ last_seen_at: new Date().toISOString() })
      .eq('id', authenticatedUserId)

    return jsonResponse({
      admin_jwt: adminJwt,
      admin_level: adminInfo.admin_level,
      email: adminInfo.email,
      display_name: adminInfo.display_name,
      expires_in: 3600
    }, 200, origin)

  } catch (error) {
    console.error('[ADMIN-AUTH] Error:', error)
    return errorResponse('Internal server error', 500, origin)
  }
})
