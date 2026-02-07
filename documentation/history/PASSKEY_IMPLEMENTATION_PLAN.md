# Passkey Implementation Plan

## Problem Statement

The mobile app currently uses a **legacy registration flow** that stores public keys in SPKI format, but authentication uses `@simplewebauthn/server` which expects public keys in COSE format. This format mismatch causes authentication to fail.

---

## Research Findings

### 1. @simplewebauthn/server Requirements

**Registration (`verifyRegistrationResponse`)**:
- Input: `RegistrationResponseJSON` object
- Format:
```json
{
  "id": "base64url credential id",
  "rawId": "base64url credential id",
  "type": "public-key",
  "response": {
    "clientDataJSON": "base64url",
    "attestationObject": "base64url",
    "transports": ["internal"]
  },
  "clientExtensionResults": {}
}
```
- Output: `verification.registrationInfo.credential.publicKey` = Uint8Array (~77 bytes COSE format)

**Authentication (`verifyAuthenticationResponse`)**:
- Input: `AuthenticationResponseJSON` object
- Format:
```json
{
  "id": "base64url credential id",
  "rawId": "base64url credential id",
  "type": "public-key",
  "response": {
    "clientDataJSON": "base64url",
    "authenticatorData": "base64url",
    "signature": "base64url",
    "userHandle": "base64url (optional)"
  },
  "clientExtensionResults": {},
  "authenticatorAttachment": "platform"
}
```
- Credential parameter requires: `{ id, publicKey: Uint8Array, counter, transports }`
- **publicKey must be the same bytes stored from registration** (COSE format)

Sources:
- [SimpleWebAuthn Server Docs](https://simplewebauthn.dev/docs/packages/server)
- [SimpleWebAuthn GitHub](https://github.com/MasterKale/SimpleWebAuthn)

### 2. react-native-passkey Output

**`Passkey.create()` returns**:
```javascript
{
  id: "base64 credential id",
  response: {
    clientDataJSON: "base64",
    attestationObject: "base64"
  }
}
```

**`Passkey.get()` returns**:
```javascript
{
  id: "base64 credential id",
  response: {
    clientDataJSON: "base64",
    authenticatorData: "base64",
    signature: "base64",
    userHandle: "base64 (optional)"
  }
}
```

**Note**: react-native-passkey returns standard base64, not base64url. Conversion required.

Sources:
- [react-native-passkey npm](https://www.npmjs.com/package/react-native-passkey)
- [react-native-passkey GitHub](https://github.com/f-23/react-native-passkey)

### 3. Current Server Implementation

**passkey-register GET `?action=options`** (lines 164-211):
- Generates options via `generateRegistrationOptions()`
- Stores challenge in `passkey_challenges` table
- Returns `{ options, challenge_key }`

**passkey-register POST new format** (lines 234-328):
- Expects `{ challenge_key, response: RegistrationResponseJSON, device_name }`
- Uses `verifyRegistrationResponse()`
- Stores `credential.publicKey` as base64 via `btoa()`
- **This is the correct flow - already implemented!**

**passkey-register POST legacy format** (lines 331-373):
- Expects `{ attestation_object, credential_id, device_name }`
- Manually extracts public key and converts to SPKI format
- **This is the problematic flow currently used by mobile**

**passkey-auth GET** (lines 150-223):
- Generates options via `generateAuthenticationOptions()`
- Stores challenge in `passkey_challenges` table
- Returns `{ challenge, challenge_key, options }`

**passkey-auth POST** (lines 230-487):
- Supports both new format (`body.response`) and legacy format
- Calls `verifyAuthenticationResponse()` with stored publicKey
- **Expects publicKey in COSE format (what @simplewebauthn registration stores)**

---

## Root Cause Analysis

```
Current Flow (BROKEN):
┌─────────────────────────────────────────────────────────────────────┐
│ REGISTRATION (mobile)                                               │
│   1. Generate local challenge (WRONG - should get from server)      │
│   2. Call Passkey.create()                                          │
│   3. Send attestation_object to server (legacy format)              │
│   4. Server extracts key → converts to SPKI → stores as base64      │
│                                                                     │
│   Stored public_key: SPKI format (91 bytes with ASN.1 headers)      │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ AUTHENTICATION (mobile)                                             │
│   1. GET challenge from server (correct)                            │
│   2. Call Passkey.get()                                             │
│   3. Send legacy format to server                                   │
│   4. Server converts to AuthenticationResponseJSON                  │
│   5. Server calls verifyAuthenticationResponse()                    │
│   6. Library tries to verify signature with SPKI key                │
│   7. FAILS - library expects COSE format (~77 bytes)                │
└─────────────────────────────────────────────────────────────────────┘

                    SPKI (91 bytes) ≠ COSE (77 bytes)
                           ↓
                    VERIFICATION FAILS
```

---

## Solution

Update the mobile app to use the **new @simplewebauthn-compatible format** for both registration and authentication. **The server already supports this format.**

### Files to Change

| File | Change |
|------|--------|
| `gatekeeper/mobile/src/lib/passkey.ts` | Update `registerPasskey()` and `authenticateWithPasskey()` |

### Server Changes Required

**NONE.** The server at `passkey-register/index.ts` and `passkey-auth/index.ts` already supports the new format. The code paths at:
- passkey-register lines 234-328 (new format handling)
- passkey-auth lines 275-311 (new format handling)

These are already implemented and working.

---

## Implementation Details

### 1. Update `registerPasskey()` Function

**Current flow (WRONG)**:
```javascript
// 1. Generate LOCAL challenge (wrong)
const challenge = toBase64URL(Crypto.getRandomBytes(32));

// 2. Create request with local values
const request = {
  challenge,
  rp: { name: 'Zule', id: rpId },
  user: { id, name, displayName },
  // ...
};

// 3. Call Passkey.create()
const credential = await Passkey.create(request);

// 4. Send attestation_object directly (legacy format)
await fetch(url, {
  body: JSON.stringify({
    credential_id: credential.id,
    attestation_object: credential.response.attestationObject,
    device_name: '...',
  })
});
```

**New flow (CORRECT)**:
```javascript
// 1. GET registration options FROM SERVER
const optionsResponse = await fetch(
  `${ZULE_URL}/functions/v1/passkey-register?action=options`,
  { headers: { Authorization: `Bearer ${token}`, apikey: '...' } }
);
const { options, challenge_key } = await optionsResponse.json();

// 2. Call Passkey.create() with SERVER-PROVIDED options
const credential = await Passkey.create({
  challenge: options.challenge,
  rp: options.rp,
  user: options.user,
  pubKeyCredParams: options.pubKeyCredParams,
  authenticatorSelection: options.authenticatorSelection,
  timeout: options.timeout,
  excludeCredentials: options.excludeCredentials,
});

// 3. Convert response to base64url and send as RegistrationResponseJSON
await fetch(url, {
  body: JSON.stringify({
    challenge_key: challenge_key,
    response: {
      id: credential.id,
      rawId: credential.id,
      type: 'public-key',
      response: {
        clientDataJSON: base64ToBase64url(credential.response.clientDataJSON),
        attestationObject: base64ToBase64url(credential.response.attestationObject),
        transports: ['internal'],
      },
      clientExtensionResults: {},
    },
    device_name: 'Android - Device Key',
  })
});
```

### 2. Update `authenticateWithPasskey()` Function

**Current flow (partially correct)**:
```javascript
// 1. GET challenge from server (correct)
const challengeData = await fetch(`${url}?credential_id=${id}`).then(r => r.json());

// 2. Call Passkey.get() (correct)
const assertion = await Passkey.get({
  challenge: challengeData.challenge,
  rpId: 'zule.mazzizax.net',
  // ...
});

// 3. Send LEGACY format (WRONG)
await fetch(url, {
  body: JSON.stringify({
    challenge_key: challengeData.challenge_key,
    credential_id: assertion.id,
    authenticator_data: assertion.response.authenticatorData,
    client_data_json: assertion.response.clientDataJSON,
    signature: assertion.response.signature,
  })
});
```

**New flow (CORRECT)**:
```javascript
// 1. GET challenge from server (same)
const challengeData = await fetch(`${url}?credential_id=${id}`).then(r => r.json());

// 2. Call Passkey.get() (same)
const assertion = await Passkey.get({
  challenge: challengeData.challenge,
  rpId: 'zule.mazzizax.net',
  // ...
});

// 3. Send NEW format as AuthenticationResponseJSON
await fetch(url, {
  body: JSON.stringify({
    challenge_key: challengeData.challenge_key,
    response: {
      id: assertion.id,
      rawId: assertion.id,
      type: 'public-key',
      response: {
        clientDataJSON: base64ToBase64url(assertion.response.clientDataJSON),
        authenticatorData: base64ToBase64url(assertion.response.authenticatorData),
        signature: base64ToBase64url(assertion.response.signature),
        userHandle: assertion.response.userHandle
          ? base64ToBase64url(assertion.response.userHandle)
          : undefined,
      },
      clientExtensionResults: {},
      authenticatorAttachment: 'platform',
    },
  })
});
```

### 3. Helper Function Needed

```javascript
/**
 * Convert standard base64 to base64url
 * react-native-passkey returns standard base64, but WebAuthn expects base64url
 */
function base64ToBase64url(base64: string): string {
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}
```

---

## Testing Plan

1. **Delete existing passkeys** from the user's account (they have SPKI format keys that won't work)
2. **Register a new passkey** using the updated flow
3. **Verify** the public key is stored in COSE format (~77 bytes as base64)
4. **Authenticate** using the updated flow
5. **Confirm** verification succeeds

---

## Rollback Plan

If issues arise, the server still supports the legacy format. We can revert mobile code changes without any server changes.

---

## Summary

| Component | Current State | Required Change |
|-----------|---------------|-----------------|
| Mobile `registerPasskey()` | Uses local challenge, sends `attestation_object` | GET options from server, send `RegistrationResponseJSON` |
| Mobile `authenticateWithPasskey()` | Sends legacy flat fields | Send `AuthenticationResponseJSON` |
| Server `passkey-register` | Supports both formats | **No change** |
| Server `passkey-auth` | Supports both formats | **No change** |
| Public key format | SPKI (91 bytes) | COSE (~77 bytes) |

**Total files to modify: 1** (`gatekeeper/mobile/src/lib/passkey.ts`)
