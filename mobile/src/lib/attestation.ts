import { supabase } from './supabase';
import { Session } from '@supabase/supabase-js';

/**
 * Attestation Service for Gatekeeper Mobile
 *
 * Issues signed attestations that prove a user authenticated
 * WITHOUT revealing their identity (no user_id, no email).
 *
 * Flow:
 * 1. User authenticates with Gatekeeper
 * 2. Call issue-attestation edge function
 * 3. Returns signed JWT for Dawg Tag to send to ghozerauth
 */

export interface AttestationResult {
  attestation: string;
  expires_in: number;
}

/**
 * Request an attestation from the Gatekeeper backend
 *
 * @param session - The authenticated user's session
 * @returns Signed attestation JWT
 */
export async function issueAttestation(session: Session): Promise<AttestationResult> {
  const { data, error } = await supabase.functions.invoke('issue-attestation', {
    headers: {
      Authorization: `Bearer ${session.access_token}`,
    },
  });

  if (error) {
    throw new Error(`Attestation failed: ${error.message}`);
  }

  if (!data?.attestation) {
    throw new Error('No attestation returned from server');
  }

  return {
    attestation: data.attestation,
    expires_in: data.expires_in,
  };
}

/**
 * Build the callback URL with attestation for Dawg Tag
 *
 * @param callbackUrl - The callback URL from Dawg Tag
 * @param attestation - The signed attestation JWT
 * @returns Full callback URL with attestation parameter
 */
export function buildCallbackUrl(callbackUrl: string, attestation: string): string {
  const url = new URL(callbackUrl);
  url.searchParams.set('attestation', attestation);
  url.searchParams.set('status', 'success');
  return url.toString();
}

/**
 * Build a cancelled callback URL
 *
 * @param callbackUrl - The callback URL from Dawg Tag
 * @returns Callback URL indicating cancellation
 */
export function buildCancelledCallbackUrl(callbackUrl: string): string {
  const url = new URL(callbackUrl);
  url.searchParams.set('status', 'cancelled');
  return url.toString();
}
