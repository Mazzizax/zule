/**
 * Shared WebAuthn Configuration for Zule (formerly Gatekeeper)
 *
 * Centralized configuration for passkey registration and authentication.
 * Both passkey-register and passkey-auth should import from here.
 */

// Relying Party configuration
// IMPORTANT: Must match what the mobile app uses in passkey.ts
// Supporting both old and new RP_ID during transition period
export const RP_ID = 'zule.mazzizax.net'
export const RP_ID_LEGACY = 'gatekeeper-nine.vercel.app'
export const RP_NAME = 'Zule'

// List of valid RP_IDs (for verification - accept both during transition)
export const VALID_RP_IDS = [
  'zule.mazzizax.net',           // New primary
  'gatekeeper-nine.vercel.app',  // Legacy (remove after migration)
] as const

// Expected origins for WebAuthn verification
// - Web/iOS: https://zule.mazzizax.net (new) or https://gatekeeper-nine.vercel.app (legacy)
// - Android: android:apk-key-hash:<base64url of SHA256 cert fingerprint>
// SHA256 fingerprint from assetlinks.json: 52:88:BF:97:26:03:DA:44:20:87:C4:3E:84:F1:B7:8F:28:A3:D0:09:F9:9F:D7:BC:C8:A9:F1:6D:D7:3C:CD:F9
export const EXPECTED_ORIGINS = [
  // New domains
  'https://zule.mazzizax.net',
  'https://goals.mazzizax.com',
  // Legacy domains (keep during transition)
  'https://gatekeeper-nine.vercel.app',
  // Android
  'android:apk-key-hash:Uoi_lyYD2kQgh8Q-hPG3jyij0Bn5n9e8yKnxbdc8zfk',
]

// Challenge expiry time (5 minutes)
export const CHALLENGE_EXPIRY_MS = 5 * 60 * 1000

// Rate limiting configuration
export const RATE_LIMIT = {
  // Max failed authentication attempts before lockout
  MAX_FAILED_ATTEMPTS: 5,
  // Lockout duration after max failed attempts (15 minutes)
  LOCKOUT_DURATION_MS: 15 * 60 * 1000,
  // Window for counting failed attempts (5 minutes)
  ATTEMPT_WINDOW_MS: 5 * 60 * 1000,
}

/**
 * Check if an RP_ID is valid (supports transition period)
 */
export function isValidRpId(rpId: string): boolean {
  return VALID_RP_IDS.includes(rpId as typeof VALID_RP_IDS[number])
}

/**
 * Decode base64url to Uint8Array
 * Handles both base64url (from WebAuthn) and standard base64
 */
export function base64urlToBytes(base64url: string): Uint8Array {
  // Convert base64url to standard base64
  let base64 = base64url
    .replace(/-/g, '+')
    .replace(/_/g, '/')

  // Add padding if needed
  while (base64.length % 4 !== 0) {
    base64 += '='
  }

  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

/**
 * Encode Uint8Array to base64url string
 */
export function bytesToBase64url(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}
