import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { decode as decodeCbor } from 'https://esm.sh/cbor-x@1.5.4'
import { handleCors, jsonResponse, errorResponse } from '../_shared/cors.ts'

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!
const GATEKEEPER_PUBLISHABLE_KEY = Deno.env.get('GATEKEEPER_PUBLISHABLE_KEY')!
const GATEKEEPER_SECRET_KEY = Deno.env.get('GATEKEEPER_SECRET_KEY')!

/**
 * Decode base64url to Uint8Array
 */
function base64urlToBytes(base64url: string): Uint8Array {
  let base64 = base64url
    .replace(/-/g, '+')
    .replace(/_/g, '/')
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
 * Extract public key from attestation object
 * The attestation object is CBOR encoded and contains authData which has the public key
 */
function extractPublicKeyFromAttestation(attestationObjectB64: string): string {
  const attestationObject = base64urlToBytes(attestationObjectB64)
  const decoded = decodeCbor(attestationObject) as { authData: Uint8Array }

  const authData = decoded.authData
  // authData structure:
  // - rpIdHash: 32 bytes
  // - flags: 1 byte
  // - signCount: 4 bytes
  // - attestedCredentialData (if AT flag set):
  //   - aaguid: 16 bytes
  //   - credentialIdLength: 2 bytes (big endian)
  //   - credentialId: credentialIdLength bytes
  //   - credentialPublicKey: remaining bytes (COSE encoded)

  const flags = authData[32]
  const hasAttestedCredentialData = (flags & 0x40) !== 0

  if (!hasAttestedCredentialData) {
    throw new Error('No attested credential data in authenticator data')
  }

  // Skip to credentialIdLength (32 + 1 + 4 + 16 = 53)
  const credIdLenOffset = 53
  const credentialIdLength = (authData[credIdLenOffset] << 8) | authData[credIdLenOffset + 1]

  // Public key starts after credential ID
  const publicKeyOffset = credIdLenOffset + 2 + credentialIdLength
  const publicKeyBytes = authData.slice(publicKeyOffset)

  // The public key is COSE encoded - we need to convert it to SPKI format for WebCrypto
  const coseKey = decodeCbor(publicKeyBytes) as Map<number, unknown>

  // COSE key for EC2 (P-256):
  // 1 (kty) = 2 (EC2)
  // 3 (alg) = -7 (ES256)
  // -1 (crv) = 1 (P-256)
  // -2 (x) = x coordinate (32 bytes)
  // -3 (y) = y coordinate (32 bytes)

  const x = coseKey.get(-2) as Uint8Array
  const y = coseKey.get(-3) as Uint8Array

  if (!x || !y) {
    throw new Error('Missing x or y coordinate in COSE key')
  }

  // Build SPKI format for P-256 public key
  // SPKI = SEQUENCE { algorithm SEQUENCE { oid, namedCurve }, publicKey BIT STRING }
  const spkiPrefix = new Uint8Array([
    0x30, 0x59, // SEQUENCE, 89 bytes
    0x30, 0x13, // SEQUENCE, 19 bytes (algorithm)
    0x06, 0x07, // OID, 7 bytes
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // 1.2.840.10045.2.1 (ecPublicKey)
    0x06, 0x08, // OID, 8 bytes
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // 1.2.840.10045.3.1.7 (prime256v1/P-256)
    0x03, 0x42, // BIT STRING, 66 bytes
    0x00, // no unused bits
    0x04, // uncompressed point
  ])

  const spki = new Uint8Array(spkiPrefix.length + 64)
  spki.set(spkiPrefix, 0)
  spki.set(x, spkiPrefix.length)
  spki.set(y, spkiPrefix.length + 32)

  // Return as base64
  return btoa(String.fromCharCode(...spki))
}

Deno.serve(async (req) => {
  console.log(`[Passkey] Incoming ${req.method} request`)
  
  const corsResponse = handleCors(req)
  if (corsResponse) return corsResponse

  const origin = req.headers.get('Origin')

  try {
    // Log all headers to debug
    console.log('[Passkey] All headers:', JSON.stringify(Object.fromEntries(req.headers.entries())))

    const authHeader = req.headers.get('Authorization')
    console.log('[Passkey] Authorization header:', authHeader ? authHeader.substring(0, 30) + '...' : 'MISSING')

    if (!authHeader) {
      console.error('[Passkey] Missing Authorization header')
      return errorResponse('Missing Auth Header', 401, origin)
    }

    // 1. Verify the User Session
    const supabaseUser = createClient(SUPABASE_URL, GATEKEEPER_PUBLISHABLE_KEY, {
      global: { headers: { Authorization: authHeader } },
    })
    const { data: { user }, error: authError } = await supabaseUser.auth.getUser()

    if (authError || !user) {
      console.error('[Passkey] Auth failed:', authError?.message)
      console.error('[Passkey] Auth error details:', JSON.stringify(authError, null, 2))
      console.error('[Passkey] Using publishable key prefix:', GATEKEEPER_PUBLISHABLE_KEY?.substring(0, 20))
      return errorResponse('Unauthorized', 401, origin)
    }
    console.log(`[Passkey] Authenticated user: ${user.id}`)

    // 2. Initialize Admin Client for DB
    const supabaseAdmin = createClient(SUPABASE_URL, GATEKEEPER_SECRET_KEY)

    if (req.method === 'GET') {
      console.log('[Passkey] Fetching keys...')
      const { data, error } = await supabaseAdmin
        .from('user_passkeys')
        .select('id, device_name, created_at')
        .eq('user_id', user.id)
        .eq('is_active', true)

      if (error) {
        console.error('[Passkey] Database error (List):', error.message)
        return errorResponse(`DB Error: ${error.message}`, 500, origin)
      }
      return jsonResponse({ passkeys: data }, 200, origin)
    }

    if (req.method === 'POST') {
      const body = await req.json()
      console.log('[Passkey] Registering new key...')
      console.log('[Passkey] Body:', JSON.stringify(body, null, 2))

      // Get public key - prefer direct public_key from react-native-passkey
      let publicKey: string
      if (body.public_key) {
        // react-native-passkey provides publicKey directly (SPKI format, base64url encoded)
        publicKey = body.public_key
        console.log('[Passkey] Using direct public key from client')
      } else if (body.attestation_object) {
        // Fallback: extract from attestation object
        try {
          publicKey = extractPublicKeyFromAttestation(body.attestation_object)
          console.log('[Passkey] Extracted public key from attestation')
        } catch (err: any) {
          console.error('[Passkey] Failed to extract public key:', err.message)
          return errorResponse(`Failed to extract public key: ${err.message}`, 400, origin)
        }
      } else {
        return errorResponse('Missing public_key or attestation_object', 400, origin)
      }

      // Use upsert to handle re-registration (same credential_id)
      const { data, error } = await supabaseAdmin
        .from('user_passkeys')
        .upsert({
          user_id: user.id,
          credential_id: body.credential_id,
          public_key: publicKey,
          device_name: body.device_name || 'Mobile Device',
          is_active: true,
          counter: 0,
        }, {
          onConflict: 'credential_id',
        })
        .select()

      if (error) {
        console.error('[Passkey] Database error (Upsert):', error.message)
        return errorResponse(`DB Error: ${error.message}`, 500, origin)
      }
      console.log('[Passkey] Registration successful')
      return jsonResponse({ success: true, data }, 201, origin)
    }

    return errorResponse('Method not allowed', 405, origin)
  } catch (err: any) {
    console.error('[Passkey] Uncaught exception:', err.message)
    return errorResponse(err.message, 500, origin)
  }
})
