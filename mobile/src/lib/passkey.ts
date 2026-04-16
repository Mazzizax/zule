/**
 * Passkey Authentication
 *
 * Wraps react-native-passkey for WebAuthn operations.
 * Used for both login to Zule and approving machine login sessions.
 */

import { Passkey } from 'react-native-passkey'
import * as SecureStore from 'expo-secure-store'

const CREDENTIAL_ID_KEY = 'zule_passkey_credential_id'

/**
 * Check if a stored credential ID exists (user has registered a passkey).
 */
export async function hasStoredCredential(): Promise<boolean> {
  const id = await SecureStore.getItemAsync(CREDENTIAL_ID_KEY)
  return !!id
}

/**
 * Get the stored credential ID.
 */
export async function getStoredCredentialId(): Promise<string | null> {
  return SecureStore.getItemAsync(CREDENTIAL_ID_KEY)
}

/**
 * Store a credential ID after registration.
 */
export async function storeCredentialId(credentialId: string): Promise<void> {
  await SecureStore.setItemAsync(CREDENTIAL_ID_KEY, credentialId)
}

/**
 * Authenticate with a passkey (biometric).
 * Takes server-provided options and returns the signed assertion.
 */
export async function authenticateWithPasskey(options: {
  challenge: string
  rpId: string
  timeout?: number
  allowCredentials?: Array<{ id: string; transports?: string[] }>
  userVerification?: string
}): Promise<any> {
  const result = await Passkey.get({
    challenge: options.challenge,
    rpId: options.rpId,
    timeout: options.timeout || 300000,
    allowCredentials: options.allowCredentials || [],
    userVerification: options.userVerification || 'preferred',
  })

  return result
}
