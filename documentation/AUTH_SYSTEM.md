# Zule Authentication System

Authoritative description of the authentication and session architecture as it stands in the **live build** of zule on main (through commit `eca89ac`). Reflects the V2 zule fix plan closeout, the blind-card pipeline wiring, and the post-signup passkey enrollment flow.

This document supersedes any earlier version that described the pre-hardening flow (legacy `passkey-register` / `passkey-auth` as the primary path, `analyzeAndSend` / `shredAndSend` as button names, etc.). Those still exist in the codebase where Vinzrik still depends on them but are no longer the primary paths for zule's own authentication.

---

## 1. Client surfaces

| Client | Tech | Passkey API | Session storage | FLAG_SECURE |
|---|---|---|---|---|
| `zule-web/` | React + Vite | Browser WebAuthn API | `sessionStorage` (per tab) | N/A (web) |
| `zule-android/` | Kotlin + Jetpack Compose | AndroidX Credential Manager 1.6.0 | `MemorySessionManager` (RAM only, no disk) | Yes, set in `MainActivity.onCreate` |

Both clients share the same Supabase Edge Function backend.

## 2. Authentication methods supported

1. **Email + password** — `Register`, `Login`, `Forgot password → Recovery`.
2. **Passkey (WebAuthn)** — strict server-driven ceremony with platform authenticator, resident key, and user verification all required.
3. **Machine authorization** — paired machines request a login session; the user approves or denies from their phone via biometric passkey.

Every method ends at a live Supabase session on the client.

## 3. Session lifecycle (zule-android)

### Storage
- `MemorySessionManager` on the Supabase client — no disk persistence. Process death erases the session unconditionally.
- `DeviceFlags` (EncryptedSharedPreferences) — a single boolean `passkey_enrolled_v1`, device-scoped, for UX decisions only (not security).

### Timers
- Inactivity: 8 minutes, resets on every UI touch, translated from the web app's `ACTIVITY_EVENTS` pattern via `SessionTimeoutWrapper`'s `pointerInput` → `SessionManager.onUserActivity()`.
- Hard cap: 25 minutes, never resets. Expiry fires `forceLogout()` → `auth.signOut()` → `_sessionExpired = true`.

### Explicit invalidation
- **Swipe-away from Recents** → `MachineAuthService.onTaskRemoved` fires `supabase.auth.signOut()`. Distinct from transient backgrounding (notification check, app switch) which does not sign out.
- **Explicit sign-out** — from the Security screen.
- **Sign out all devices** — from Security; calls `signOutGlobal` + clears `DeviceFlags`.
- **Delete account** — from Security; calls the `delete-account` Edge Function, signs out, clears `DeviceFlags`.
- **Delete all passkeys** — clears `DeviceFlags` (no stable credential_id → device mapping).

### Legacy purge
- `ZuleApplication.onCreate` runs once per process start: strips any pre-hardening Supabase session blob that an older build wrote to the default `SharedPreferences`, and deletes the legacy `zule_passkey.xml` if present. Protects upgrading installs from an old disk-persisted session resurfacing against the new memory-only manager.

### FLAG_SECURE
- Set unconditionally in `MainActivity.onCreate`. Blocks screenshots, screen recording, AssistantUI captures, and screen-sharing across every surface.

## 4. Hardened passkey ceremony (the live path)

The live primary path is the **strict split** Edge Function pair: `passkey-register-begin` / `passkey-register-finish` for enrollment, `passkey-auth-begin` / `passkey-auth-finish` for sign-in. The legacy `passkey-register` / `passkey-auth` Edge Functions remain deployed because Vinzrik still consumes them for the attestation hand-off, but zule's own clients no longer use them.

### Registration (from Security screen or post-signup enrollment prompt)

```
Client                                       Server
  │                                            │
  │ POST /passkey-register-begin               │
  │────────────────────────────────────────────▶
  │                                            │ admin.auth.getUser(bearer)
  │                                            │ generateRegistrationOptions(
  │                                            │   rpID=zule.mazzizax.net,
  │                                            │   authenticatorAttachment=platform,
  │                                            │   residentKey=required,
  │                                            │   userVerification=required,
  │                                            │   excludeCredentials=existing)
  │                                            │ store(challenge_key=reg-strict:…,
  │                                            │       challenge, user_id, expires_at+10min)
  │ 200 {handle, options}                      │
  │◀───────────────────────────────────────────│
  │ CredentialManager.createCredential(options)│
  │ — biometric prompt, platform auth only     │
  │ POST /passkey-register-finish              │
  │  {handle, response}                        │
  │────────────────────────────────────────────▶
  │                                            │ lookup challenge by handle
  │                                            │ verifyRegistrationResponse(
  │                                            │   response, expectedChallenge,
  │                                            │   expectedOrigin=EXPECTED_ORIGINS,
  │                                            │   expectedRPID=zule.mazzizax.net,
  │                                            │   requireUserVerification=true)
  │                                            │ persist to user_passkeys with
  │                                            │   public_key as base64url text
  │                                            │ delete consumed challenge
  │ 200 {verified, credentialId}               │
  │◀───────────────────────────────────────────│
```

A failure at the finish step throws `OrphanedPasskeyException` on the client — the credential is live in Google Password Manager but unknown to the server; retry overwrites the orphan.

### Authentication (from Login screen with strict sign-in)

```
Client                                       Server
  │                                            │
  │ POST /passkey-auth-begin                   │
  │────────────────────────────────────────────▶
  │                                            │ generateAuthenticationOptions(
  │                                            │   rpID=zule.mazzizax.net,
  │                                            │   userVerification=required,
  │                                            │   allowCredentials=[] usernameless)
  │                                            │ store(challenge_key=auth-strict:…,
  │                                            │       challenge, user_id=null,
  │                                            │       expires_at+10min)
  │ 200 {handle, options}                      │
  │◀───────────────────────────────────────────│
  │ CredentialManager.getCredential()          │
  │ — biometric, usernameless discovery        │
  │ POST /passkey-auth-finish                  │
  │  {handle, response}                        │
  │────────────────────────────────────────────▶
  │                                            │ lookup challenge (auth-strict prefix)
  │                                            │ lookup credential by id+is_active
  │                                            │ per-credential rate limit check
  │                                            │   (5 failures in 5 min → 429)
  │                                            │ verifyAuthenticationResponse(...)
  │                                            │   — on counter error: log
  │                                            │     POTENTIAL_CLONE, return
  │                                            │     {error:counter_rollback,
  │                                            │      hint:clone_suspected}
  │                                            │ update user_passkeys counter+last_used_at
  │                                            │ admin.generateLink(magiclink, email)
  │                                            │ anon.verifyOtp(otp) → session
  │ 200 {verified, access_token, refresh_token,│
  │      expires_in, token_type, user}         │
  │◀───────────────────────────────────────────│
  │ auth.importSession(tokens)                 │
  │ auth.retrieveUserForCurrentSession(true)   │
```

The minted session is a real Supabase session, not a custom one — so every downstream `supabase.auth.*` call works normally.

### What's *not* in either response
- No plaintext `user_id` in any response body (removed in commit `107a629` / function redeploy). `passkey-auth-finish` returns `{verified, access_token, refresh_token, expires_in, token_type, user}`; `user` is the populated Supabase user record returned by the SDK's session import, not a mint-side emission.
- The legacy `passkey-auth` function continues to return `{tier, verification_token, attestation}` to Vinzrik — the blind-attestation promise is preserved there because plaintext `user_id` was removed from that response too (same commit).

## 5. Email flows

All three rate-limited via per-email + per-IP attempt logs in `auth_email_attempts` (3/email/15min, 10/IP/15min). All three send via Resend with Mazzizax-branded HTML templates. All three generate a Supabase magic/signup/recovery link and rewrite the action URL so it points at `https://${AUTH_HOST}/auth/callback?token_hash=…&type=…` — Android App Links catch that path and resume the app directly.

| Flow | Edge Function | Link type | Client entry |
|---|---|---|---|
| Signup confirmation | `auth-signup` | `type=signup` | `AuthRepository.signUp` (wired from Register screen) |
| Resend sign-in / confirmation link | `auth-resend` | `type=magiclink` | `AuthRepository.resendVerification` |
| Password reset | `auth-reset` | `type=recovery` | `AuthRepository.requestPasswordReset` (wired from Forgot-password screen) |

`auth-reset` always returns `{ok: true}` regardless of whether the email corresponds to a real account — prevents email enumeration.

### Deep-link callback
`MainActivity.handleAuthDeepLink` intercepts `https://${AUTH_HOST}/auth/callback?token_hash=…&type=…`, maps `type` to the Supabase `OtpType.Email` enum, sets `RecoverySignal.pendingRecovery = true` if `type=recovery`, and calls `auth.verifyEmailOtp(type, tokenHash)`. The session transitions to Authenticated, the nav graph routes.

## 6. Nav graph routing after Authenticated

`ZuleNavGraph` observes `SessionStatus.Authenticated` and waits for `session.user` to be populated (passkey sign-in imports with `user=null` and fills via `retrieveUserForCurrentSession` — routing before the user loads briefly flashes VERIFY_EMAIL). Once user is present:

```
when {
    pendingRecovery (RecoverySignal)  → PASSWORD_RECOVERY
    !isVerified                        → VERIFY_EMAIL
    !DeviceFlags.isPasskeyEnrolled     → PASSKEY_ENROLL   (post-signup nudge)
    else                               → MAIN
}
```

`PASSKEY_ENROLL` shows "Enable fingerprint sign-in" (runs the strict enrol ceremony, marks `DeviceFlags`, routes to MAIN) or "Skip for now" (routes to MAIN; the nudge re-fires on the next sign-in until the user enrols).

## 7. Login screen — compact mode

When `DeviceFlags.isPasskeyEnrolledOnDevice(context)` is true and the user hasn't clicked "Use password instead", the Login screen hides the email + password fields and the "Forgot password?" link, leaving only the passkey button and the "Use password instead" opt-out. After a sign-out, the flag persists, so the next launch comes up compact — one-tap biometric sign-in.

After tapping "Use password instead," a "Back to passkey sign-in" link appears below the sign-in button to restore compact mode.

## 8. Password policy

- **Minimum 12 characters** — enforced client-side in `RegisterViewModel.signUp` and `SecurityViewModel.updatePassword` and `PasswordRecoveryScreen.validate`. Enforced server-side by `config.toml` + the `auth-signup` Edge Function.
- **HIBP k-anonymity breach check** — runs on every password-set path (signup, change, recovery). Sends only first 5 hex chars of `SHA-1(password)` to `api.pwnedpasswords.com/range`. Rejects passwords found in breach corpus. Fails open on network error (unreachable ≠ blocked signup).

## 9. Transaction pipeline (dev mode, 4 phases)

End-game: collapse into a single auto-trigger on Plaid-pull completion for Play-store builds. Today every phase is a separate button so each step is independently testable.

| Phase | zule-web | zule-android | Edge Function / action |
|---|---|---|---|
| 0. Pull | "0. Pull" on each account row | "Pull Transactions" on each account row | `plaid-pull-transactions` |
| 1. Mint | "1. Mint cards" in Transaction Pipeline card | "1. Mint cards" in Transaction Pipeline card | `mint-transaction-cards` → returns `card_attestation` JWT |
| 2. Send | "2. Send to Vinzrik" | "2. Send to Vinzrik" | fires `vinzrik://receive-cards?attestation=<jwt>` deep link |
| 3. Shred | "3. Shred raw" | "3. Shred raw" | `shred-minted-transactions` |

The `card_attestation` JWT is a signed blind payload — decodable by Vinzrik to see the cards, verified by Goals against zule's public key, and stripped of any real-world identifier (Vinzrik's `FORBIDDEN_FIELDS` firewall rejects cards containing `user_id`, `plaid_transaction_id`, `date`, `amount`, `merchant*`, `card_last_four`, `location_*`, `description`, `iso_currency_code`, `plaid_access_token`).

## 10. Machine authentication

Already integrated end-to-end: `MachineAuthRepository` polls `machine-auth-pending` via a foreground service (`MachineAuthService`), shows a notification when a pending session arrives, user taps through to approve-or-deny via biometric passkey, approval signs an assertion bound to a per-session session_code which updates `machine_login_sessions.status = "approved"`. Charlemagne's `zule-windows-auth` service watches that row via Supabase Realtime and unlocks on approval.

## 11. Vinzrik attestation hand-off

Two deep-link surfaces on zule-android map to Vinzrik:

- `zule://auth?callback=<vinzrik-url>` → `VinzrikAuthScreen` (Vinzrik-initiated login-to-zule-then-hand-back-attestation).
- `https://${AUTH_HOST}/auth?token_hash=…&type=…` — Supabase OTP callback, not Vinzrik-related.

`VinzrikAuthScreen` offers both email/password and passkey sign-in paths. On successful zule sign-in it calls `issue-attestation` (blind JWT, iss=zule, aud=ghozerauth, no user identifier), signs out of zule locally (keeps attestation only), and fires a return intent to the Vinzrik callback URL with `?attestation=<jwt>&status=success`.

Vinzrik on the other side (current release APK, commit `3137d37` at bundle id `com.mazzizax.vinzrik`) receives the attestation, uses its locally-held `ghost_secret` to compute `ghost_id`, and mints a Goals JWT via Ghozerauth.

## 12. Rate limiting + audit

| Table | What it records | Where it's consulted |
|---|---|---|
| `auth_email_attempts` | email, kind (signup/resend/reset), IP, success, timestamp | `_shared/email-rate-limit.ts` for 3/email/15min and 10/IP/15min |
| `passkey_auth_attempts` | credential_id, user_id, success, reason (`rate_limited` / `counter_rollback` / `verify_threw` / `not_verified`), IP, timestamp | `passkey-auth-finish` for 5 failures in 5 min → 429 lockout |
| `audit_logs` | every `auth_validated` / `auth_failed` / `passkey_authenticated` / `machine_auth_*` / `rate_limited` event + metadata | cross-function telemetry |

`passkey_challenges` carries the single-use challenge per begin→finish pair; consumed on finish.

## 13. Legal surfaces

`LegalFooter` component (Privacy · Terms · Contact) appears on: Login, Register, Security, Forgot Password, Password Recovery. URLs are BuildConfig fields (`LEGAL_PRIVACY_URL`, `LEGAL_TERMS_URL`, `LEGAL_CONTACT_URL`), overridable at integration time. Opens in Chrome Custom Tabs with toolbar color matching the app surface.

## 14. What's live vs what's dormant in the codebase

**Live in this build (primary paths):**
- `auth-signup`, `auth-resend`, `auth-reset` (branded email + rate-limited)
- `passkey-register-begin`, `passkey-register-finish` (strict ceremony)
- `passkey-auth-begin`, `passkey-auth-finish` (strict, session-minting)
- `mint-transaction-cards`, `shred-minted-transactions`
- `delete-account`
- `plaid-*`, `stripe-*`, `loyalty-cards`, `user-profile`, `machine-auth-*`

**Dormant but retained:**
- Legacy `passkey-register` and `passkey-auth` — still deployed because Vinzrik's attestation flow and `issue-attestation` / `mint-session` chain for zule-web's (unmigrated) passkey sign-in continue to call them. Eligible for removal once Vinzrik is rebuilt to hit the new strict pair.

**Outstanding caveats for distribution:**
- APKs are debug-signed (`debug.keystore`). Release signing procedure is documented in `PLAY-APP-SIGNING.md` §4 but not executed.
- Neither zule nor vinzrik has been submitted to Play Console. No listings, no AAB uploads.
- iOS: nothing built.
- The blind-card pipeline's 4-phase buttons are intentional dev UI; Play-store builds will collapse the chain into a single auto-trigger on Plaid-pull completion.

## 15. Cross-references
- `PLAY-DATA-SAFETY.md` — Play Console Data Safety form (per-data-type disclosure).
- `PLAY-APP-SIGNING.md` — upload-key vs app-signing-key procedure, EXPECTED_ORIGINS management, rotation playbooks.
- `ZULE-FIX-PLAN-V2.md` (on Desktop) — the audit-vs-login-standard document that drove the hardening pass. All 32 defects closed as of commit `eca89ac`.
- `E3 evolution/` (on Desktop) — post-E2 design notes: Identity Container, Zule Architecture consolidation, Fleet Mechanics merge.
