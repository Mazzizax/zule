# Ghost ID Algorithm - Technical Specification

## Overview

The Ghost ID system provides **privacy-preserving user identification** across the Xenon Engine platform. It enables users to interact with third-party applications without revealing their true identity, while still maintaining data continuity and security.

## Design Principles

1. **Zero-Knowledge Identity**: The Engine (data layer) never learns who the user is
2. **Client-Side Derivation**: Ghost IDs are computed on the user's device, not the server
3. **Deterministic**: Same inputs always produce the same Ghost ID
4. **Irreversible**: Cannot derive user_id from ghost_id without the secret
5. **App-Isolated**: Each app gets its own blind token; Ghost ID is user-controlled

---

## Architecture

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│     CLIENT      │      │   GATEKEEPER    │      │     ENGINE      │
│  (Mobile App)   │      │  (Auth Layer)   │      │  (Data Layer)   │
├─────────────────┤      ├─────────────────┤      ├─────────────────┤
│                 │      │                 │      │                 │
│ ghost_secret    │      │ user_id         │      │ ghost_id        │
│ user_id (auth)  │─────▶│ subscription    │      │ blind_token     │
│ ghost_id        │      │ blind_token     │─────▶│ tier            │
│                 │      │                 │      │                 │
│ Derives ghost_id│      │ Issues tokens   │      │ Stores user data│
│ locally         │      │ Knows identity  │      │ NEVER sees      │
│                 │      │                 │      │ user_id         │
└─────────────────┘      └─────────────────┘      └─────────────────┘
```

---

## Ghost ID Derivation Algorithm

### Input Components

| Component | Description | Storage |
|-----------|-------------|---------|
| `user_id` | Supabase Auth UUID | From authentication |
| `ghost_secret` | 32-byte random value | iOS Keychain / Android Keystore |

### Derivation Process

```typescript
// Step 1: Concatenate inputs
const data = user_id + ghost_secret;

// Step 2: Hash with SHA-256
const hashHex = SHA256(data);

// Step 3: Format as UUID v4 (for database compatibility)
const ghost_id = formatAsUUID(hashHex);
```

### UUID Formatting

The SHA-256 hash (64 hex characters) is formatted as a UUID v4:

```
hashHex = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"

ghost_id = "a1b2c3d4-e5f6-4a7b-c9d0-e1f2a3b4c5d6"
           ^^^^^^^^ ^^^^ ^^^^ ^^^^ ^^^^^^^^^^^^
           [0:8]   [8:12] "4"+[13:16] [16:20] [20:32]
```

Note: Position 12 is hardcoded to `4` to indicate UUID version 4.

### Implementation Reference

**Mobile App** - [mobile/src/lib/ghostKeys.ts](../../mobile/src/lib/ghostKeys.ts):

```typescript
async function deriveGhostId(userId: string, secret: string): Promise<string> {
  const data = userId + secret;

  // Native: expo-crypto
  const hashHex = await Crypto.digestStringAsync(
    Crypto.CryptoDigestAlgorithm.SHA256,
    data
  );

  // Format as UUID v4
  return `${hashHex.slice(0, 8)}-${hashHex.slice(8, 12)}-4${hashHex.slice(13, 16)}-${hashHex.slice(16, 20)}-${hashHex.slice(20, 32)}`;
}
```

---

## Ghost Secret Generation

### Algorithm

```typescript
// Generate 32 cryptographically secure random bytes
const randomBytes = crypto.getRandomBytes(32);

// Convert to hex string (64 characters)
const ghost_secret = randomBytes.map(byte =>
  byte.toString(16).padStart(2, '0')
).join('');
```

### Platform Implementation

| Platform | API | Storage |
|----------|-----|---------|
| iOS | `SecRandomCopyBytes` via expo-crypto | iOS Keychain |
| Android | `SecureRandom` via expo-crypto | Android Keystore |
| Web | `crypto.getRandomValues` | localStorage (dev only) |

---

## Security Properties

### What Each Component Knows

| Component | Knows | Does NOT Know |
|-----------|-------|---------------|
| **Client** | user_id, ghost_secret, ghost_id | - |
| **Zule** | user_id, subscription tier | ghost_secret, ghost_id |
| **Engine** | ghost_id, tier (from token) | user_id, ghost_secret |
| **Third-Party App** | blind_token, tier | user_id, ghost_id, ghost_secret |

### Attack Resistance

| Attack Vector | Protection |
|---------------|------------|
| **Server compromise (Engine)** | Engine only has ghost_id; cannot reverse to user_id |
| **Server compromise (Zule)** | Has user_id but not ghost_secret; cannot compute ghost_id |
| **Network interception** | Blind tokens are signed and expire; ghost_id never transmitted with user_id |
| **Brute force derivation** | 32 bytes = 256 bits of entropy; computationally infeasible |
| **Rainbow table** | Per-user random secret makes precomputation useless |

### Collision Resistance

SHA-256 provides 128-bit collision resistance. The probability of two users having the same ghost_id is approximately 1 in 2^128 (negligible).

---

## Blind Token System

Blind tokens are issued by Zule and validated by Engine. They carry authorization without identity.

### Token Structure

```typescript
interface BlindTokenPayload {
  iat: number;   // Issued at (Unix timestamp)
  exp: number;   // Expiration (Unix timestamp)
  tier: string;  // Subscription tier (free, premium, etc.)
  nonce: string; // Unique identifier (UUID, for revocation)
  app: string;   // Target application ID
  v: number;     // Token version
}
```

### Token Format

```
<base64(payload)>.<base64(HMAC-SHA256(payload, secret))>
```

### What Blind Tokens NEVER Contain

- `user_id` - NEVER
- `email` - NEVER
- `ghost_id` - Client-derived, server never sees it

---

## Data Flow

### Authentication Flow

```
1. User authenticates with Supabase Auth (email/password, OAuth, etc.)
   └─▶ Returns: user_id (JWT)

2. Client checks for existing ghost_secret
   └─▶ If none: Generate and store securely

3. Client derives ghost_id = SHA256(user_id + ghost_secret)
   └─▶ Formatted as UUID v4

4. Client requests blind token from Zule
   └─▶ Sends: Authorization: Bearer <supabase_jwt>
   └─▶ Receives: blind_token (contains tier, NOT user_id)

5. Client sends requests to Engine
   └─▶ Headers: X-Blind-Token: <token>, X-Ghost-Id: <ghost_id>

6. Engine validates token, uses ghost_id for data operations
   └─▶ NEVER sees user_id
```

### Device Recovery Flow (QR Code)

```
1. User exports QR from original device
   └─▶ QR contains: { ghost_secret, user_id, created_at }

2. User scans QR on new device
   └─▶ Stores ghost_secret securely
   └─▶ Stores pending user_id for verification

3. User authenticates on new device
   └─▶ System verifies authenticated user_id matches QR user_id
   └─▶ Derives ghost_id using imported secret
   └─▶ User's data is accessible (same ghost_id)
```

---

## QR Code Backup Format

```json
{
  "ghost_secret": "a1b2c3d4...64 hex chars...",
  "user_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "created_at": "2025-01-01T00:00:00.000Z"
}
```

### Security Considerations

- QR code should be treated as a password
- Store printed copies securely (safe deposit box, etc.)
- Do not share electronically
- If compromised, user must generate new ghost_secret (loses data continuity)

---

## Database Schema

### Engine Tables (ghost_id only)

```sql
-- All user data tables reference ghost_id, NEVER user_id
CREATE TABLE cosmic_ledger (
  id UUID PRIMARY KEY,
  ghost_id UUID NOT NULL,  -- Links to user anonymously
  transaction_type TEXT,
  ...
);

CREATE TABLE user_quests (
  id UUID PRIMARY KEY,
  ghost_id UUID NOT NULL,
  quest_id UUID REFERENCES quests(id),
  ...
);
```

### Zule Tables (user_id only)

```sql
-- Auth-related tables use user_id
CREATE TABLE user_subscriptions (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES auth.users(id),
  tier TEXT,
  ...
);

CREATE TABLE blind_token_log (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES auth.users(id),
  token_nonce UUID,
  ...
);
```

---

## Implementation Checklist

### Client Requirements

- [ ] Secure storage for ghost_secret (Keychain/Keystore)
- [ ] SHA-256 hashing capability
- [ ] QR code generation and scanning
- [ ] Proper UUID formatting

### Zule Requirements

- [ ] Never log or store ghost_id
- [ ] Issue blind tokens without identity info
- [ ] Rate limit token issuance per user
- [ ] Require explicit app consent

### Engine Requirements

- [ ] Validate blind tokens (signature, expiration)
- [ ] Never accept user_id in requests
- [ ] All queries by ghost_id only
- [ ] No reverse lookup capability

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-01 | Initial specification |

---

## References

- [ghostKeys.ts](../../mobile/src/lib/ghostKeys.ts) - Client-side implementation
- [blind-token-issue/index.ts](../functions/blind-token-issue/index.ts) - Token issuance
- [_shared/blind-token.ts](../../supabase/functions/_shared/blind-token.ts) - Token validation
- [GHOST_ID_MIGRATION_PLAN.md](../GHOST_ID_MIGRATION_PLAN.md) - Migration from server-side ghost_id
