# Zule Project Status

**Last Updated:** 2026-01-01

---

## What is Zule?

Zule is the **user-facing identity provider** for the Xenon ecosystem. It's the single place where users:
- Create and manage their account
- Control which apps can access their data
- Manage subscriptions and billing
- Export/backup their ghost identity

**Key Privacy Property:** Zule knows WHO you are (email, payment info). Apps only know your `ghost_id` - an anonymous identifier derived client-side that cannot be linked back to your identity.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         USER DEVICE                                  │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐  │
│  │  Zule App │    │   Mobile App    │    │   Engine Web    │  │
│  │  (Identity)     │    │   (Data Entry)  │    │   (Dashboard)   │  │
│  └────────┬────────┘    └────────┬────────┘    └────────┬────────┘  │
│           │                      │                      │           │
│           │         ┌────────────┴────────────┐         │           │
│           │         │  ghost_secret (secure)  │         │           │
│           │         │  ghost_id = SHA256(     │         │           │
│           │         │    user_id + secret)    │         │           │
│           │         └─────────────────────────┘         │           │
└───────────┼─────────────────────┼───────────────────────┼───────────┘
            │                     │                       │
            ▼                     ▼                       ▼
┌───────────────────────┐         │         ┌───────────────────────────┐
│   GATEKEEPER PROJECT  │         │         │      ENGINE PROJECT       │
│   (Supabase)          │         │         │      (Supabase)           │
│                       │         │         │                           │
│  KNOWS:               │         │         │  KNOWS:                   │
│  - user_id            │         │         │  - ghost_id               │
│  - email              │         │         │  - cosmic_ledger data     │
│  - subscription tier  │         │         │  - quests, achievements   │
│  - payment info       │         │         │                           │
│                       │         │         │  NEVER KNOWS:             │
│  NEVER KNOWS:         │         │         │  - user_id                │
│  - ghost_id           │◄────────┘         │  - email                  │
│  - cosmic data        │  blind_token      │  - who owns what data     │
│                       │  (anonymous)      │                           │
└───────────────────────┘                   └───────────────────────────┘
```

---

## Current State (January 2026)

### What's Built

#### Backend (Supabase Edge Functions)

| Function | Purpose | Status |
|----------|---------|--------|
| `blind-token-issue` | Issue anonymous tokens to apps | Deployed |
| `user-profile` | Read/update user profile (GET/PUT/PATCH) | Deployed |
| `app-register` | Register third-party apps | Deployed |
| `app-connections` | Manage user-app authorizations | Deployed |
| `revoke-token` | Revoke issued blind tokens | Deployed |
| `stripe-webhook` | Handle subscription payments | Deployed |

#### Database Schema

| Table | Purpose |
|-------|---------|
| `user_profiles` | Subscription tier, Stripe customer ID, privacy settings |
| `registered_apps` | Third-party app configuration |
| `user_app_connections` | Which apps each user has authorized |
| `blind_token_log` | Audit trail of token issuance |
| `passkey_credentials` | WebAuthn/biometric credentials |
| `audit_logs` | Security audit trail |
| `rate_limits` | Per-user/app/IP rate limiting |

#### Security Utilities (`_shared/security.ts`)

- CORS origin validation (whitelist approach)
- Timing-safe secret comparison
- Input validation (email, URL, UUID, display name)
- Rate limiting helpers

#### Test Web App (`gatekeeper-test-app/`)

| Feature | Status |
|---------|--------|
| Login/Register | Working |
| Ghost ID derivation | Working |
| QR backup export | Working |
| Profile display | Working |
| Logout | Working |

**Tech Stack:** React 18, TypeScript, Vite, Supabase JS

---

### What's Planned (Not Yet Built)

#### 1. Phone Session Authorization

**Purpose:** After web login, require phone approval for session. Ghost secret NEVER leaves the phone.

**Components Needed:**

| Component | Location | Status |
|-----------|----------|--------|
| Database migration | `gatekeeper-project/migrations/00003_phone_session_authorization.sql` | Not created |
| `session-request-create` | Edge Function | Not created |
| `session-request-approve` | Edge Function | Not created |
| `session-request-status` | Edge Function | Not created |
| `session-validate` | Edge Function | Not created |
| `SessionApprovalScreen` | Mobile app | Not created |
| `phoneAuth.js` | Web frontend | Not created |

**Flow:**
1. User logs in on web (email/password)
2. Web shows QR code with session request
3. User scans QR with phone app
4. Phone prompts for biometric (Face ID / Touch ID)
5. Phone signs challenge with ghost_secret, sends to Zule
6. Web polls for approval, receives session_token + ghost_id
7. Web can now access Engine with ghost_id

#### 2. Zule Web Portal (Full Version)

**Purpose:** The user-facing Zule app for managing identity and connected apps.

**Current:** Basic test app with login/register/ghost_id display

**Needed Pages:**

| Page | Purpose | Status |
|------|---------|--------|
| `/` | Dashboard overview | Basic |
| `/login` | Login | Done |
| `/register` | Registration | Done |
| `/profile` | Edit profile (display name, avatar, timezone) | Not done |
| `/apps` | View/revoke connected apps | Not done |
| `/security` | Change password, view sessions, 2FA | Not done |
| `/billing` | Subscription management, payment methods | Not done |
| `/backup` | Export ghost secret QR code | Basic (JSON only) |

#### 3. Project Separation

**Current:** Edge Functions deployed to existing Zule Supabase project

**Needed:**
- Deploy Zule web portal to Vercel (separate from Engine web)
- Configure custom domain (`auth.xenontotem.com` or similar)
- Update CORS to include production Zule URL

#### 4. Physical Token Support

**Purpose:** Hardware tokens (RFID/NFC) for ghost_id derivation instead of phone

**Status:** Database schema supports it, no hardware integration

---

## Priority Roadmap

### Phase 1: Zule Portal MVP (Current Focus)

**Goal:** Deployable Zule web app that users can access

1. Rename `gatekeeper-test-app` → `gatekeeper-app`
2. Add Profile page (call `user-profile` Edge Function)
3. Add Connected Apps page (call `app-connections` Edge Function)
4. Add `vercel.json` for SPA routing
5. Deploy to Vercel
6. Add Vercel URL to CORS allowed origins
7. Deploy updated Edge Functions

**Result:** Users can visit `gatekeeper.vercel.app`, log in, manage profile and connected apps.

### Phase 2: Phone Session Authorization

**Goal:** Web sessions require phone approval

1. Create database migration (session_requests, web_sessions tables)
2. Implement 4 session-request Edge Functions
3. Add SessionApprovalScreen to mobile app
4. Add phoneAuth.js to Engine web
5. Test full flow
6. Deploy with `PHONE_AUTH_ENABLED=false` initially
7. Gradual rollout

**Result:** Ghost secret never touches web browser, XSS-immune.

### Phase 3: Production Hardening

**Goal:** Production-ready security and infrastructure

1. Custom domain setup
2. Remaining 17 security issues from audit
3. PITR and backup configuration
4. Monitoring and alerting
5. Stripe billing completion
6. Read replicas for scale

### Phase 4: Advanced Features

**Goal:** Full multi-app ecosystem support

1. Developer portal for app registration
2. OAuth-style consent flow
3. Hardware token integration
4. Per-app rate limit configuration
5. Analytics dashboard for app developers

---

## Key Files Reference

### Zule Backend

```
gatekeeper-project/
├── functions/
│   ├── _shared/
│   │   ├── cors.ts          # CORS utilities
│   │   ├── security.ts      # Input validation, timing-safe compare
│   │   └── auth.ts          # JWT verification
│   ├── blind-token-issue/   # Core token issuance
│   ├── user-profile/        # Profile CRUD
│   ├── app-register/        # App registration
│   ├── app-connections/     # User-app authorizations
│   ├── revoke-token/        # Token revocation
│   └── stripe-webhook/      # Payment handling
├── migrations/
│   ├── 00001_gatekeeper_schema.sql
│   └── 00002_fix_security_and_performance.sql
└── supabase/
    └── config.toml
```

### Zule Web App

```
gatekeeper-test-app/          # Will become gatekeeper-app/
├── src/
│   ├── contexts/
│   │   └── AuthContext.tsx   # Auth state + ghost_id
│   ├── lib/
│   │   ├── supabase.ts       # Supabase client
│   │   └── ghostKeys.ts      # Ghost secret management
│   └── pages/
│       ├── Login.tsx
│       ├── Register.tsx
│       └── Home.tsx          # Dashboard
├── .env                      # Zule credentials
├── package.json
└── vite.config.ts
```

### Documentation

```
documentation/
├── gatekeeper/
│   ├── GATEKEEPER_STATUS.md        # This file
│   ├── GHOST_ID_ALGORITHM.md       # Technical spec for ghost_id
│   ├── SETUP_INSTRUCTIONS.md       # Deployment guide
│   └── SESSION_NOTES.md            # Session progress notes
├── GATEKEEPER_SEPARATION_PLAN.md   # Two-project architecture
├── PHONE_AUTH_IMPLEMENTATION_PLAN.md # Phone auth spec
└── SECURITY_MODEL.md               # Security architecture
```

---

## Environment Variables

### Zule Edge Functions

```bash
BLIND_TOKEN_SECRET=<32-byte-secret>      # Token signing (MUST match Engine)
ALLOWED_ORIGINS=https://...              # Comma-separated CORS origins
STRIPE_SECRET_KEY=sk_live_xxx            # Stripe API key
STRIPE_WEBHOOK_SECRET=whsec_xxx          # Stripe webhook verification
ADMIN_API_KEY=<secure-key>               # For app registration
```

### Zule Web App

```bash
VITE_ZULE_URL=https://sgjulzvgcyotebbexfue.supabase.co
VITE_GATEKEEPER_ANON_KEY=eyJhbGci...
```

---

## Success Metrics

| Metric | Target | Current |
|--------|--------|---------|
| Edge Functions deployed | 6 | 6 |
| Security issues resolved | 20 | 3 |
| Web app pages | 6+ | 3 |
| Phone auth implemented | Yes | No |
| Production deployed | Yes | No (local only) |
| Custom domain | Yes | No |

---

## Next Action

**Immediate:** Expand `gatekeeper-test-app` into full Zule portal with Profile and Connected Apps pages, then deploy to Vercel.
