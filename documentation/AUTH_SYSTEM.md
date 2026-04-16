# Zule Authentication System

## Overview

Zule provides secure authentication for the platform using two methods:
1. **Email/Password** - Traditional authentication via Supabase Auth
2. **Passkey/Biometric** - WebAuthn-based passwordless authentication

Both methods result in a verified user session that can be used across the platform.

## Clients

| Client | Technology | Passkey API | Session Storage |
|--------|-----------|-------------|-----------------|
| Web (zule-web/) | React/Vite | Browser WebAuthn API | sessionStorage (per-tab) |
| Mobile (zule-android/) | Kotlin/Jetpack Compose | Android Credential Manager | EncryptedSharedPreferences |

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Web App       │     │  Edge Functions  │     │    Supabase     │
│  (React/Vite)   │────▶│   (Deno Edge)    │────▶│   (Postgres)    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                │                        │
┌─────────────────┐             │                        │
│  Mobile App     │─────────────┘                        │
│  (Kotlin/JPC)   │                                      │
└─────────────────┘                                      │
        │                                                │
        ▼                                                │
┌─────────────────┐     ┌─────────────────┐              │
│  Android Key-   │     │  Windows Cred   │              │
│  store/Biometric│     │  Provider (C++) │──────────────┘
└─────────────────┘     └─────────────────┘
                          (Machine Auth)
```

## Session Security

- Inactivity timeout: 8 minutes (resets on user interaction)
- Hard timeout: 25 minutes (never resets)
- Web: sessionStorage isolation (new tab = new login)
- Mobile: EncryptedSharedPreferences with AES-256-GCM
- Web cross-tab kill signal: new login displaces all other tabs

## Passkey Authentication

### Security Model

- **Phishing Resistant** - Credentials are bound to the RP ID (`zule.mazzizax.net`)
- **No Shared Secrets** - Asymmetric cryptography (private key never leaves device)
- **Biometric Protection** - Private key unlocked by fingerprint/face via device secure enclave
- **Replay Protection** - Challenge-response with incrementing counters

### Flow

#### Registration
```
1. Client requests registration options (GET /passkey-register?action=options)
2. Server generates challenge, stores in DB, returns PublicKeyCredentialCreationOptions
3. Client calls device passkey API with options
   - Web: navigator.credentials.create()
   - Android: CredentialManager.createCredential()
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
   - Web: navigator.credentials.get()
   - Android: CredentialManager.getCredential()
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
- **Purpose**: Authenticate users via passkey
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
  public_key TEXT NOT NULL,
  device_name TEXT DEFAULT 'Device',
  authenticator_type TEXT,
  transports TEXT[],
  counter INTEGER DEFAULT 0,
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
const RP_ID = 'zule.mazzizax.net'
const RP_NAME = 'Zule'
```

#### Expected Origins
```typescript
const EXPECTED_ORIGINS = [
  'https://zule.mazzizax.net',
  'https://goals.mazzizax.com',
  'https://gatekeeper-nine.vercel.app',           // legacy
  'https://xenon-engine-web.vercel.app',           // legacy
  'android:apk-key-hash:-sYXRdwJA3hvue3mKpYrOZ9zSPC7b4mbgzJmdZEDO5w',  // Vinzrik
  'android:apk-key-hash:Uoi_lyYD2kQgh8Q-hPG3jyij0Bn5n9e8yKnxbdc8zfk',  // Legacy
  'android:apk-key-hash:7XrT7DwGTOXZgUhB78XwgBc-sQatZaRGvJvEEDhDvPU',  // Zule Mobile (debug)
]
```

Android APK key hashes are derived from SHA-256 fingerprint of the app signing certificate, base64url encoded. Must be updated when switching from debug to release keystore.

### Mobile Implementation (Android)

Location: `zule-android/app/src/main/java/com/mazzizax/zule/data/repository/PasskeyRepository.kt`

Uses raw HTTP calls (Ktor HttpClient) to edge functions — same pattern as the web app's `fetch()` calls. Does NOT use `supabase.functions.invoke()` because the Supabase Kotlin SDK does not reliably set HTTP methods or query parameters for function calls.

Key functions:
- `listPasskeys()` - GET /passkey-register
- `getRegistrationOptions()` - GET /passkey-register?action=options
- `registerPasskey()` - POST /passkey-register
- `deletePasskey()` - DELETE /passkey-register
- `getAuthChallenge()` - GET /passkey-auth?credential_id=...
- `verifyPasskeyAuth()` - POST /passkey-auth

Credential Manager integration: `SecurityViewModel.registerPasskey(activity)` handles the full 3-step registration flow. `AuthRequestsViewModel.approveSession(sessionId, activity)` handles biometric approval for machine auth.

## Machine Auth

Fleet machines run a Windows Credential Provider that replaces the Windows login screen. The user approves login requests from their phone via passkey biometric. A stolen fleet machine is a brick without the phone.

### Flow
```
1. Machine locks → Credential Provider creates session (machine-auth-request)
2. Login screen shows session code + "Waiting for approval..."
3. Phone polls machine-auth-pending → shows pending session
4. User taps Approve → phone gets passkey challenge (machine-auth-approve GET)
5. Biometric prompt → phone sends assertion (machine-auth-approve POST)
6. Machine polls machine-auth-status → sees approved
7. Credential Provider decrypts DPAPI credential → passes to Windows LSA → unlocked
```

### Edge Functions

| Function | Method | Auth | Purpose |
|----------|--------|------|---------|
| machine-auth-request | POST | Machine API key | Create login session |
| machine-auth-status | GET | Machine API key | Poll session status |
| machine-auth-pending | GET | User Bearer token | List pending sessions for user's machines |
| machine-auth-approve | GET | User Bearer token | Get passkey challenge for session approval |
| machine-auth-approve | POST | User Bearer token | Approve (with passkey) or deny session |
| machine-register | POST | User Bearer token | Register a new machine |

### Windows Components

Source: `C:\Users\o2bma\zule-windows-auth\` on Raiden (not in this repo)

- `ZuleCredentialProvider.dll` - COM DLL, registered as Windows Credential Provider
- `ZuleAuthService.exe` - Windows Service, runs as LocalSystem, manages pipe IPC + backend communication
- Named pipe `\\.\pipe\ZuleAuth` - IPC between Credential Provider and service
- `credential.dat` - DPAPI-encrypted Windows password (wide-string binary format)
- `machine.key` - DPAPI-encrypted machine API key
- `config.json` - Machine ID, name, backend URL

### Mobile Component

Location: `zule-android/app/src/main/java/com/mazzizax/zule/ui/screen/machineauth/`

- `AuthRequestsScreen.kt` - Shows pending sessions, approve/deny buttons
- `AuthRequestsViewModel.kt` - Polls machine-auth-pending, handles Credential Manager flow for approval
- `MachineAuthRepository.kt` - Raw HTTP calls to machine-auth edge functions

Accessible from Dashboard → Fleet Auth → Auth Requests.

## Email/Password Authentication

Standard Supabase Auth flow:
1. User signs up/signs in via Supabase client
2. Supabase returns JWT session tokens
3. Web: sessionStorage per-tab isolation
4. Mobile: EncryptedSharedPreferences

## Rate Limiting

- Failed passkey attempts logged with IP and credential_id
- After 5 failures in 5 minutes: 15-minute lockout
- Rate limits apply per IP address

## Audit Logging

All auth events logged to `audit_logs`:
- `passkey_registered` - New passkey registered
- `passkey_authenticated` - Successful passkey auth
- `passkey_auth_failed` - Failed attempt (with reason)
- `passkey_deleted` - Passkey removed
- `machine_auth_approved` - Machine login approved via biometric
- `machine_auth_denied` - Machine login denied
- `machine_auth_approve_failed` - Approval attempt failed

## Dependencies

### Server (Edge Functions)
- `@simplewebauthn/server` (jsr) - WebAuthn verification

### Web (zule-web/)
- Browser WebAuthn API (native)

### Mobile (zule-android/)
- `androidx.credentials` - Android Credential Manager
- `io.ktor:ktor-client-okhttp` - HTTP client for edge function calls
- `androidx.security:security-crypto` - EncryptedSharedPreferences
- `androidx.biometric` - BiometricPrompt
