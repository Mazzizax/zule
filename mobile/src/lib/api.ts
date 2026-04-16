/**
 * Zule Machine Auth API
 *
 * Functions for discovering and approving machine login sessions.
 */

import { supabase, SUPABASE_URL } from './supabase'

export interface PendingSession {
  session_id: string
  machine_name: string
  machine_id: string
  session_code: string
  expires_at: string
  created_at: string
}

export interface Machine {
  id: string
  machine_name: string
  machine_identifier: string
  is_active: boolean
  created_at: string
  last_seen_at: string | null
}

/**
 * Get pending machine login sessions for the current user.
 */
export async function fetchPendingSessions(): Promise<PendingSession[]> {
  const { data: { session } } = await supabase.auth.getSession()
  if (!session) throw new Error('Not authenticated')

  const response = await fetch(`${SUPABASE_URL}/functions/v1/machine-auth-pending`, {
    headers: {
      'Authorization': `Bearer ${session.access_token}`,
      'Content-Type': 'application/json',
    },
  })

  if (!response.ok) {
    const err = await response.json().catch(() => ({}))
    throw new Error(err.error || `HTTP ${response.status}`)
  }

  const data = await response.json()
  return data.sessions || []
}

/**
 * Get the passkey challenge for approving a session.
 */
export async function getApprovalChallenge(sessionId: string, credentialId: string) {
  const { data: { session } } = await supabase.auth.getSession()
  if (!session) throw new Error('Not authenticated')

  const params = new URLSearchParams({
    action: 'challenge',
    session_id: sessionId,
    credential_id: credentialId,
  })

  const response = await fetch(
    `${SUPABASE_URL}/functions/v1/machine-auth-approve?${params}`,
    {
      headers: {
        'Authorization': `Bearer ${session.access_token}`,
        'Content-Type': 'application/json',
      },
    }
  )

  if (!response.ok) {
    const err = await response.json().catch(() => ({}))
    throw new Error(err.error || `HTTP ${response.status}`)
  }

  return response.json()
}

/**
 * Submit passkey approval for a machine login session.
 */
export async function approveSession(
  sessionId: string,
  challengeKey: string,
  passkeyResponse: any,
) {
  const { data: { session } } = await supabase.auth.getSession()
  if (!session) throw new Error('Not authenticated')

  const response = await fetch(`${SUPABASE_URL}/functions/v1/machine-auth-approve`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${session.access_token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      session_id: sessionId,
      challenge_key: challengeKey,
      response: passkeyResponse,
    }),
  })

  if (!response.ok) {
    const err = await response.json().catch(() => ({}))
    throw new Error(err.error || `HTTP ${response.status}`)
  }

  return response.json()
}

/**
 * Deny a machine login session.
 */
export async function denySession(sessionId: string) {
  const { data: { session } } = await supabase.auth.getSession()
  if (!session) throw new Error('Not authenticated')

  const response = await fetch(`${SUPABASE_URL}/functions/v1/machine-auth-approve`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${session.access_token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      session_id: sessionId,
      action: 'deny',
    }),
  })

  if (!response.ok) {
    const err = await response.json().catch(() => ({}))
    throw new Error(err.error || `HTTP ${response.status}`)
  }

  return response.json()
}

/**
 * List machines accessible to the current user.
 */
export async function fetchMachines(): Promise<Machine[]> {
  const { data: { session } } = await supabase.auth.getSession()
  if (!session) throw new Error('Not authenticated')

  const response = await fetch(`${SUPABASE_URL}/functions/v1/machine-register`, {
    headers: {
      'Authorization': `Bearer ${session.access_token}`,
      'Content-Type': 'application/json',
    },
  })

  if (!response.ok) {
    const err = await response.json().catch(() => ({}))
    throw new Error(err.error || `HTTP ${response.status}`)
  }

  const data = await response.json()
  return data.machines || []
}
