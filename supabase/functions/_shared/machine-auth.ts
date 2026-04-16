/**
 * Machine Authentication Utilities
 *
 * Shared helpers for fleet machine registration and login session management.
 * Used by: machine-register, machine-auth-request, machine-auth-status,
 *          machine-auth-pending, machine-auth-approve
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { timingSafeEqual } from './security.ts'

/**
 * Verify a machine API key against stored hash.
 * Returns the machine record if valid, null if invalid.
 */
export async function verifyMachineApiKey(
  supabase: ReturnType<typeof createClient>,
  apiKey: string,
): Promise<{ id: string; machine_name: string; machine_identifier: string; owner_user_id: string; allowed_user_ids: string[]; is_active: boolean } | null> {
  if (!apiKey || !apiKey.startsWith('zm_')) {
    return null
  }

  // Hash the provided key
  const encoder = new TextEncoder()
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(apiKey))
  const apiKeyHash = Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')

  // Look up by hash
  const { data: machine, error } = await supabase
    .from('fleet_machines')
    .select('id, machine_name, machine_identifier, owner_user_id, allowed_user_ids, is_active')
    .eq('api_key_hash', apiKeyHash)
    .eq('is_active', true)
    .single()

  if (error || !machine) {
    return null
  }

  // Update last_seen_at
  await supabase
    .from('fleet_machines')
    .update({ last_seen_at: new Date().toISOString() })
    .eq('id', machine.id)
    .then(() => {}) // fire and forget

  return machine
}

/**
 * Generate a machine API key with zm_ prefix.
 * Returns { apiKey, apiKeyHash } — apiKey shown once, hash stored.
 */
export async function generateMachineApiKey(): Promise<{ apiKey: string; apiKeyHash: string }> {
  const bytes = new Uint8Array(24)
  crypto.getRandomValues(bytes)
  const apiKey = `zm_${Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')}`

  const encoder = new TextEncoder()
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(apiKey))
  const apiKeyHash = Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')

  return { apiKey, apiKeyHash }
}

/**
 * Create a machine login session.
 * Returns session_id, session_code, expires_at.
 */
export async function createLoginSession(
  supabase: ReturnType<typeof createClient>,
  machineId: string,
  ttlSeconds = 120,
): Promise<{ session_id: string; session_code: string; expires_at: string } | null> {
  // Clean up expired sessions first
  await supabase.rpc('cleanup_expired_machine_sessions').catch(() => {})

  // Check for existing pending session for this machine
  const { data: existing } = await supabase
    .from('machine_login_sessions')
    .select('id, session_code, expires_at')
    .eq('machine_id', machineId)
    .eq('status', 'pending')
    .gt('expires_at', new Date().toISOString())
    .single()

  if (existing) {
    return {
      session_id: existing.id,
      session_code: existing.session_code,
      expires_at: existing.expires_at,
    }
  }

  // Generate session code
  const { data: codeData, error: codeError } = await supabase.rpc('generate_session_code')
  if (codeError || !codeData) {
    console.error('[MACHINE-AUTH] Failed to generate session code:', codeError)
    return null
  }

  const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString()

  const { data: session, error } = await supabase
    .from('machine_login_sessions')
    .insert({
      machine_id: machineId,
      session_code: codeData,
      status: 'pending',
      expires_at: expiresAt,
    })
    .select('id, session_code, expires_at')
    .single()

  if (error || !session) {
    console.error('[MACHINE-AUTH] Failed to create session:', error)
    return null
  }

  return {
    session_id: session.id,
    session_code: session.session_code,
    expires_at: session.expires_at,
  }
}

/**
 * Get the client IP from request headers.
 */
export function getClientIp(req: Request): string | null {
  return req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    || req.headers.get('x-real-ip')
    || null
}

/**
 * Create a JSON response for machine endpoints.
 * Machine endpoints use permissive CORS (native HTTP client, no browser).
 */
export function machineJsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'content-type, x-api-key',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Cache-Control': 'no-store',
    },
  })
}

/**
 * Create an error response for machine endpoints.
 */
export function machineErrorResponse(message: string, status = 400): Response {
  return machineJsonResponse({ error: message }, status)
}
