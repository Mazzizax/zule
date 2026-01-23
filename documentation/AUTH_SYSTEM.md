# Gatekeeper Authentication System

## Overview

Gatekeeper provides secure authentication for the platform using two methods:
1. **Email/Password** - Traditional authentication via Supabase Auth
2. **Passkey/Biometric** - WebAuthn-based passwordless authentication

Both methods result in a verified user session that can be used across the platform.

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Mobile App    │     │  Edge Functions │     │    Supabase     │
│  (React Native) │────▶│   (Deno Edge)   │────▶│   (Postgres)    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │
        │                       ▼
        │               ┌─────────────────┐
        └──────────────▶│  Device Secure  │
                        │     Enclave     │
                        └─────────────────┘
```

## Passkey Authentication

### Security Model

Passkey authentication uses the WebAuthn standard with the following security properties:

- **Phishing Resistant** - Credentials are bound to the origin (`gatekeeper-nine.vercel.app`)
- **No Shared Secrets** - Uses asymmetric cryptography (private key never leaves device)
- **Biometric Protection** - Private key is unlocked by fingerprint/face via device secure enclave
- **Replay Protection** - Challenge-response with incrementing counters

### Flow

#### Registration
```
1. Client requests registration options (GET /passkey-register?action=options)
2. Server generates challenge, stores in DB, returns PublicKeyCredentialCreationOptions
3. Client calls device passkey API with options
4. User authenticates with biometric
5. Device creates key pair, returns RegistrationResponseJSON
6. Client sends response to server (POST /passkey-register)
7. Server verifies with @simplewebauthn/server, stores public key
```

#### Authentication
```
1. Client requests challenge (GET /passkey-auth?credential_id=...)
2. Server generates challenge, stores in DB, returns PublicKeyCredentialRequestOptions
3. Client calls device passkey API with options
4. User authenticates with biometric
5. Device signs challenge, returns AuthenticationResponseJSON
6. Client sends response to server (POST /passkey-auth)
7. Server verifies signature with stored public key
8. Server returns verification_token + attestation
```

### Edge Functions

#### passkey-register
- **Purpose**: Register new passkeys for authenticated users
- **Auth**: Requires valid Supabase session (verified via service role)
- **Endpoints**:
  - `GET ?action=options` - Get registration options
  - `GET` - List user's passkeys
  - `POST` - Register new passkey
  - `DELETE` - Remove a passkey

#### passkey-auth
- **Purpose**: Authenticate users via passkey (alternative to email/password)
- **Auth**: None required (authenticates via passkey)
- **Rate Limiting**: 5 failed attempts triggers 15-minute lockout
- **Endpoints**:
  - `GET ?credential_id=...` - Get authentication challenge
  - `POST` - Verify signed assertion

### Database Schema

#### user_passkeys
```sql
CREATE TABLE user_passkeys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  credential_id TEXT UNIQUE NOT NULL,
  public_key TEXT NOT NULL,           -- COSE-encoded, base64
  device_name TEXT DEFAULT 'Device',
  authenticator_type TEXT,            -- 'singleDevice' or 'multiDevice'
  transports TEXT[],                  -- ['internal', 'hybrid', etc.]
  counter INTEGER DEFAULT 0,          -- Replay protection
  backed_up BOOLEAN DEFAULT false,
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT now(),
  last_used_at TIMESTAMPTZ
);
```

#### passkey_challenges
```sql
CREATE TABLE passkey_challenges (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  challenge_key TEXT UNIQUE NOT NULL,
  challenge TEXT NOT NULL,
  user_id UUID REFERENCES auth.users(id),
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);
```

### Configuration

#### Relying Party (RP)
```typescript
const RP_ID = 'gatekeeper-nine.vercel.app'
const RP_NAME = 'Gatekeeper'
```

#### Expected Origins
```typescript
const EXPECTED_ORIGINS = [
  'https://gatekeeper-nine.vercel.app',
  'android:apk-key-hash:Uoi_lyYD2kQgh8Q-hPG3jyij0Nn5n9e8yKnxbdc8zfk',
]
```

The Android APK key hash is derived from the SHA256 fingerprint of the app signing certificate.

#### Rate Limits
```typescript
const RATE_LIMIT = {
  MAX_FAILED_ATTEMPTS: 5,
  LOCKOUT_DURATION_MS: 15 * 60 * 1000,  // 15 minutes
  ATTEMPT_WINDOW_MS: 5 * 60 * 1000,      // 5 minutes
}
```

### Mobile Implementation

Location: `mobile/src/lib/passkey.ts`

Key functions:
- `registerPasskey(email)` - Register device passkey
- `authenticateWithPasskey()` - Authenticate with stored passkey
- `hasStoredPasskey()` - Check if credential is stored locally
- `clearStoredPasskey()` - Remove local credential reference

Storage: Credentials are stored in `expo-secure-store` (KeyStore on Android, Keychain on iOS).

## Email/Password Authentication

Standard Supabase Auth flow:
1. User signs up/signs in via `supabase.auth.signUp()` / `supabase.auth.signInWithPassword()`
2. Supabase returns JWT session tokens
3. Tokens are automatically managed by Supabase client

## Session Management

After successful authentication (either method), the user receives:
- **Supabase Session** - JWT tokens for API access
- **verification_token** (passkey only) - Short-lived token for mint-session
- **attestation** (passkey only) - Token for Dawg Tag ghost-auth flow

## Security Considerations

### What's Protected
- Private keys never leave the device secure enclave
- Biometric data never transmitted (only used locally)
- Public keys are safe to store (can't derive private key)
- Challenges are single-use and expire in 5 minutes

### Rate Limiting
- Failed passkey attempts are logged with IP and credential_id
- After 5 failures in 5 minutes, 15-minute lockout
- Rate limits apply per IP address

### Audit Logging
All auth events are logged to `audit_logs`:
- `passkey_registered` - New passkey registered
- `passkey_authenticated` - Successful passkey auth
- `passkey_auth_failed` - Failed attempt (with reason)
- `passkey_deleted` - Passkey removed

## Environment Variables

Required for Edge Functions:
```
SUPABASE_URL              # Project URL
SUPABASE_SERVICE_ROLE_KEY # Service role key (for auth verification)
ATTESTATION_SIGNING_KEY   # ES256 JWK for signing tokens
```

## Dependencies

- `@simplewebauthn/server` (jsr) - WebAuthn verification
- `react-native-passkey` - Native passkey API wrapper
- `expo-secure-store` - Secure credential storage
