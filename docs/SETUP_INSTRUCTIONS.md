# Gatekeeper Project Setup Instructions

## What is Gatekeeper?

**Gatekeeper is a dedicated secure user authentication service.**

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│   "I know WHO you are. I will NEVER know WHAT you do."                  │
│                                                                         │
│   - Gatekeeper authenticates identity                                   │
│   - Gatekeeper issues anonymous tokens per-app                          │
│   - Gatekeeper cannot see inside any connected application              │
│   - Connected applications cannot see each other's users                │
│   - Physical token holder controls their identity absolutely            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

This guide walks you through setting up the Gatekeeper Supabase project for the privacy-preserving multi-app architecture.

## Architecture Overview

```
                         ┌─────────────────────────┐
                         │       GATEKEEPER        │
                         │  (Universal Auth Hub)   │
                         │                         │
                         │  • User authentication  │
                         │  • Blind token issuance │
                         │  • App registration     │
                         │  • Physical tokens      │
                         └───────────┬─────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
              ▼                      ▼                      ▼
     ┌────────────────┐    ┌────────────────┐    ┌────────────────┐
     │  Xenon Engine  │    │   Third-Party  │    │   Third-Party  │
     │  (Your Data)   │    │    App "A"     │    │    App "B"     │
     │                │    │                │    │                │
     │  ghost_id_1    │    │  ghost_id_2    │    │  ghost_id_3    │
     └────────────────┘    └────────────────┘    └────────────────┘

     Each app gets a DIFFERENT ghost_id for the same user.
     Apps cannot correlate users across each other.
```

## Prerequisites

- Supabase account with Pro plan (recommended for production features)
- Access to your existing Engine project (xenon-engine)
- Password manager for storing credentials

---

## Step 1: Create Gatekeeper Supabase Project

1. Go to [supabase.com/dashboard](https://supabase.com/dashboard)
2. Click **"New Project"**
3. Configure:
   - **Name:** `xenon-gatekeeper`
   - **Database Password:** Generate a strong 32+ character password
   - **Region:** Same as your Engine project for lowest latency
   - **Plan:** Pro (recommended)
4. Click **Create new project**
5. Wait for project to be provisioned (~2 minutes)

### Save These Values

After creation, save these from **Project Settings > API**:
- **Project URL:** `https://xxxxx.supabase.co`
- **anon public key:** `eyJhbG...`
- **service_role key:** `eyJhbG...` (keep secret!)

---

## Step 2: Generate Shared Secret

Generate a cryptographically secure secret for blind token signing:

```bash
# On macOS/Linux:
openssl rand -base64 32

# On Windows (PowerShell):
[Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Maximum 256 }) -as [byte[]])
```

**Save this secret** - you'll add it to both projects.

---

## Step 3: Run Gatekeeper Database Migration

1. Go to **SQL Editor** in your new Gatekeeper project
2. Copy the contents of `gatekeeper-project/migrations/00001_gatekeeper_schema.sql`
3. Paste and click **Run**
4. Verify tables were created:
   - `user_profiles`
   - `audit_logs`
   - `rate_limits`
   - `blind_token_log`
   - `passkey_credentials`
   - `device_links`

---

## Step 4: Configure Gatekeeper Secrets

Go to **Project Settings > Edge Functions > Secrets** and add:

| Name | Value |
|------|-------|
| `BLIND_TOKEN_SECRET` | The secret you generated in Step 2 |
| `STRIPE_SECRET_KEY` | Your Stripe secret key (optional, for billing) |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signing secret (optional) |

---

## Step 5: Deploy Gatekeeper Edge Functions

From your terminal, in the `gatekeeper-project` directory:

```bash
# Link to your new Gatekeeper project
npx supabase login
npx supabase link --project-ref YOUR_GATEKEEPER_PROJECT_REF

# Deploy core functions
npx supabase functions deploy blind-token-issue
npx supabase functions deploy user-profile
npx supabase functions deploy revoke-token

# Deploy multi-app functions
npx supabase functions deploy app-register
npx supabase functions deploy app-connections

# Deploy billing (optional)
npx supabase functions deploy stripe-webhook
```

---

## Step 6: Configure Engine Project

Add the shared secret to your existing Engine project:

1. Go to your Engine project in Supabase Dashboard
2. Go to **Project Settings > Edge Functions > Secrets**
3. Add:

| Name | Value |
|------|-------|
| `BLIND_TOKEN_SECRET` | Same value as Gatekeeper (from Step 2) |

---

## Step 7: Configure Authentication

In your Gatekeeper project, go to **Authentication > Settings**:

### Email Auth
- [x] Enable Email Signup
- [x] Confirm email
- [x] Secure email change
- Minimum password length: **12**

### URLs
- Site URL: `https://xenontotem.com` (or your domain)
- Redirect URLs:
  - `https://xenontotem.com/*`
  - `https://*.xenontotem.com/*`
  - `exp://localhost:*` (for Expo dev)
  - `xenon://auth/*` (for mobile deep links)

### Security
- JWT expiry: `3600` (1 hour)
- Enable refresh token rotation: **ON**

---

## Step 8: Update Frontend Configuration

1. Copy `gatekeeper-project/config.template.js` to `config.js`
2. Fill in the values:

```javascript
const CONFIG = {
  GATEKEEPER_URL: 'https://YOUR_GATEKEEPER_REF.supabase.co',
  GATEKEEPER_ANON_KEY: 'eyJhbG...',
  ENGINE_URL: 'https://YOUR_ENGINE_REF.supabase.co',
  ENGINE_ANON_KEY: 'eyJhbG...',
};
```

---

## Step 9: Update Mobile Configuration

1. Copy `gatekeeper-project/mobile-updates/env.template` to `mobile/.env`
2. Fill in the values
3. Copy the new TypeScript files:
   - `supabase.ts.new` → `mobile/src/lib/supabase.ts`
   - `BlindTokenManager.ts` → `mobile/src/lib/BlindTokenManager.ts`

---

## Step 10: Test the Setup

### Test 1: Gatekeeper Auth
```bash
# Should return user profile
curl -X GET \
  'https://YOUR_GATEKEEPER_REF.supabase.co/functions/v1/user-profile' \
  -H 'Authorization: Bearer YOUR_JWT_TOKEN'
```

### Test 2: Blind Token Issuance
```bash
# Should return blind_token
curl -X POST \
  'https://YOUR_GATEKEEPER_REF.supabase.co/functions/v1/blind-token-issue' \
  -H 'Authorization: Bearer YOUR_JWT_TOKEN' \
  -H 'Content-Type: application/json'
```

### Test 3: Engine with Blind Token
```bash
# Should return queue status
curl -X GET \
  'https://YOUR_ENGINE_REF.supabase.co/functions/v1/queue-status' \
  -H 'x-blind-token: YOUR_BLIND_TOKEN' \
  -H 'x-ghost-id: YOUR_GHOST_ID'
```

---

## Verification Checklist

- [ ] Gatekeeper project created
- [ ] Migration applied successfully
- [ ] BLIND_TOKEN_SECRET set on both projects
- [ ] Edge functions deployed to Gatekeeper
- [ ] Authentication settings configured
- [ ] Frontend config updated
- [ ] Mobile config updated
- [ ] Test endpoints working

---

## Rollback Plan

If issues arise:

1. **Frontend:** Revert `config.js` to use single project URLs
2. **Engine still works:** The Engine project is unchanged and operational
3. **Auth fallback:** Users can still log in directly to Engine (transitional mode)

---

## Step 11: Register Xenon Engine as First App

After migration, run this SQL in Gatekeeper's SQL Editor to register Xenon Engine:

```sql
-- Register Xenon Engine as first app
-- SAVE THE RETURNED CREDENTIALS!
SELECT * FROM register_app(
    'xenon-engine',
    'Xenon Totem Engine',
    'admin@xenontotem.com',
    ARRAY['https://xenontotem.com/callback', 'exp://localhost:*/--/callback'],
    ARRAY['https://xenontotem.com', 'http://localhost:*'],
    NULL,
    'Xenon Totem',
    'The privacy-preserving personal data engine'
);
```

**IMPORTANT:** This returns `shared_secret` and `api_key` - save them immediately!
They are shown ONCE and cannot be retrieved later.

Add the `shared_secret` to your Engine project's Edge Functions secrets as `BLIND_TOKEN_SECRET`.

---

## Registering Third-Party Apps

When other applications want to use Gatekeeper for authentication:

### Via API (Authenticated User)
```bash
curl -X POST \
  'https://YOUR_GATEKEEPER_REF.supabase.co/functions/v1/app-register' \
  -H 'Authorization: Bearer USER_JWT' \
  -H 'Content-Type: application/json' \
  -d '{
    "app_id": "my-app",
    "app_name": "My Application",
    "owner_email": "developer@example.com",
    "callback_urls": ["https://myapp.com/callback"],
    "allowed_origins": ["https://myapp.com"],
    "organization_name": "My Company",
    "description": "A privacy-preserving app"
  }'
```

### Response (SAVE THIS!)
```json
{
  "success": true,
  "app": {
    "id": "uuid",
    "app_id": "my-app",
    "app_name": "My Application"
  },
  "credentials": {
    "shared_secret": "base64-secret-SAVE-THIS",
    "api_key": "gk_hex-key-SAVE-THIS"
  },
  "warning": "SAVE THESE CREDENTIALS NOW. They will NOT be shown again."
}
```

---

## Physical Token Support

The schema includes full support for RFID/NFC physical tokens:

```sql
-- Register a physical token
SELECT * FROM register_physical_token(
    'user-uuid',
    'XNT-00001-2024',  -- Serial number
    'nfc',             -- Token type
    'public-key-base64',
    'My Primary Token'
);

-- Activate the token
SELECT * FROM activate_physical_token('XNT-00001-2024', TRUE);

-- Report token as lost
SELECT * FROM report_token_lost('user-uuid', 'XNT-00001-2024', 'lost');
```

---

## Next Steps After Setup

1. Set up custom domains (`auth.xenontotem.com`, `api.xenontotem.com`)
2. Configure Stripe webhooks (if using billing)
3. Enable Point-in-Time Recovery on both projects
4. Set up monitoring and alerts
5. Remove transitional `user_bridges` code from Engine
6. Plan physical token hardware integration

---

## Phase 2: Gatekeeper Portal Frontend

After the Gatekeeper backend is deployed and tested, build the **Gatekeeper Portal** - a user-facing app for managing identity and app connections.

### Starting Point

Use the existing React Native mobile app (`mobile/`) as the foundation. It already has:
- Complete auth flow (Login, Register, QR Scan)
- Ghost identity management (`src/lib/ghostKeys.ts`)
- Secure storage (iOS Keychain / Android Keystore)
- Device linking via QR code
- Passkey/biometric support

### Current Mobile App Structure
```
mobile/
├── App.tsx                      # Navigation setup
├── src/
│   ├── contexts/
│   │   └── AuthContext.tsx      # Auth state management
│   ├── screens/
│   │   ├── LoginScreen.tsx
│   │   ├── RegisterScreen.tsx
│   │   ├── QRScanScreen.tsx
│   │   └── HomeScreen.tsx       # Shows ghost_id, privacy status
│   └── lib/
│       ├── supabase.ts
│       ├── ghostKeys.ts         # Client-side secret management
│       └── passkey.ts
```

### Changes Required

#### 1. Point Auth to Gatekeeper Project
Update `src/lib/supabase.ts` to connect to Gatekeeper instead of Engine.

#### 2. Add Multi-App Ghost ID Derivation
Modify `src/lib/ghostKeys.ts`:
```typescript
// Current (single app):
async function deriveGhostId(userId: string, secret: string): Promise<string>

// Multi-app (add app_id parameter):
async function deriveGhostId(userId: string, secret: string, appId: string): Promise<string> {
  const data = userId + secret + appId;  // Include app_id in hash
  // ... rest remains the same
}
```

#### 3. Add New Screens

| Screen | Purpose |
|--------|---------|
| `SettingsScreen` | Profile settings, security options |
| `ConnectedAppsScreen` | View/revoke authorized apps (uses `app-connections` API) |
| `PhysicalTokenScreen` | Manage RFID/NFC tokens |
| `TokenBackupScreen` | Export QR for recovery/multi-device |

#### 4. Add BlindTokenManager
Copy `gatekeeper-project/mobile-updates/BlindTokenManager.ts` to handle:
- Requesting blind tokens from Gatekeeper
- Caching tokens with expiry
- Per-app token management

### Navigation Structure (Target)
```
App
├── Auth Navigator (unauthenticated)
│   ├── LoginScreen
│   ├── RegisterScreen
│   └── QRScanScreen
│
└── Main Navigator (authenticated)
    ├── HomeScreen (dashboard)
    ├── ConnectedAppsScreen
    │   └── AppDetailScreen (per-app settings)
    ├── PhysicalTokensScreen
    │   └── TokenDetailScreen
    ├── BackupScreen (QR export)
    └── SettingsScreen
```

### Implementation Order

1. **Update Supabase connection** - Point to Gatekeeper project
2. **Modify ghostKeys.ts** - Add app_id to derivation
3. **Add BlindTokenManager** - Token request/caching
4. **ConnectedAppsScreen** - View/revoke apps (uses existing API)
5. **PhysicalTokensScreen** - Token management UI
6. **BackupScreen** - QR export improvements
7. **SettingsScreen** - Profile and security

---

## Security Notes

- The `BLIND_TOKEN_SECRET` must be identical on both projects
- Never expose `service_role` keys to clients
- Rotate secrets every 90 days
- Monitor audit logs for suspicious activity
- Set up rate limiting alerts
