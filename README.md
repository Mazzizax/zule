# Zule

Zero-knowledge User License Enclave. Privacy-first identity provider with anonymous identity separation.

## Overview

Zule is a user authentication system where real identity (email, credentials, payment info) and application activity (XP, gear, quests) are stored in completely separate databases with no shared identifiers. The only link between them is a cryptographic secret on the user's physical device.

## Architecture

```
zule/
├── zule-web/          # React/Vite web app (user portal)
├── zule-android/      # Kotlin/Jetpack Compose mobile app
├── supabase/          # Edge functions + database migrations (shared backend)
├── documentation/     # Documentation
├── vercel.json        # Web app deploy config
└── README.md
```

### Shared Backend

Both the web and mobile apps connect to the same Supabase project. Edge functions handle all server-side logic. Database migrations define the schema. Neither client has direct database access — everything goes through edge functions.

### Web App (zule-web/)

React + Vite, deployed on Vercel at zule.mazzizax.net. Four authenticated screens: Dashboard, Identity, Security, Services. Plus Loyalty, Apps, and Vinzrik attestation endpoint.

```bash
cd zule-web
npm install
npm run dev
```

### Mobile App (zule-android/)

Native Android in Kotlin + Jetpack Compose. Full parity with the web app — same screens, same edge function calls, same design system (dark theme, Cormorant Garamond, rose gold metallic accents). Plus machine auth for fleet hardware.

- Package: `com.mazzizax.zule`
- Min SDK: 28 (Android 9)
- Target SDK: 35 (Android 15)
- Auth: Supabase Kotlin SDK + Android Credential Manager (passkeys)
- Build: `cd zule-android && ./gradlew assembleDebug`
- Install: `adb install -r app/build/outputs/apk/debug/app-debug.apk`

### Machine Auth

Fleet machines run a Windows Credential Provider (C++ COM DLL) that replaces the Windows login screen. The user approves login requests from their phone via passkey biometric. The machine is a brick without the phone.

Flow: Machine locks → Credential Provider creates session → phone sees pending request → user approves with biometric → machine unlocks.

Components:
- `supabase/functions/machine-auth-request/` — machine creates login session (API key auth)
- `supabase/functions/machine-auth-pending/` — phone polls for pending sessions (user auth)
- `supabase/functions/machine-auth-approve/` — phone approves/denies with passkey (user auth)
- `supabase/functions/machine-auth-status/` — machine polls for approval (API key auth)
- `supabase/functions/machine-register/` — register a machine to a user account

### Supabase Edge Functions

Deploy all functions:
```bash
npx supabase functions deploy --no-verify-jwt
```

Deploy a single function:
```bash
npx supabase functions deploy function-name --no-verify-jwt
```

Note: `--no-verify-jwt` is required. Functions verify auth internally via `supabase.auth.getUser(token)`. The `sb_publishable_` key format is not compatible with Supabase gateway JWT verification.

## Security

- Session inactivity timeout: 8 minutes
- Session hard timeout: 25 minutes
- Passkeys via WebAuthn (web) / Android Credential Manager (mobile)
- EncryptedSharedPreferences for mobile session storage
- Certificate pinning on Supabase domain (mobile)
- DPAPI-encrypted Windows credentials for machine auth
- All data encrypted at rest (AES-256) and in transit (TLS 1.2+)

## Legal

- Mazz Ink, LLC — Illinois, USA
- Privacy policy: zule.mazzizax.net/privacy
- Terms of service: zule.mazzizax.net/terms
