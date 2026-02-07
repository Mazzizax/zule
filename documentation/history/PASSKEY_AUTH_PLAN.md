# Plan: Zule Passkey Authentication

## Goal
Enable passkey/biometric login via Zule web app. Vinzrik delegates authentication to Zule, receives user_id via callback.

## Architecture

```
Vinzrik                         Zule Web                    Device
   |                                  |                               |
   |-- Open browser to /login ------->|                               |
   |   (with callback URL)            |                               |
   |                                  |                               |
   |                          User taps "Sign in with Passkey"        |
   |                                  |                               |
   |                                  |-- WebAuthn API --------------->|
   |                                  |                               |
   |                                  |<-- Biometric prompt ----------|
   |                                  |                               |
   |                                  |<-- Signed assertion ----------|
   |                                  |                               |
   |                          Verify with passkey-auth endpoint       |
   |                                  |                               |
   |<-- Redirect to callback ---------|                               |
   |    with user_id + token          |                               |
   |                                  |                               |
   Compute ghost_id, discard user_id                                  |
```

---

## GATEKEEPER TASKS (This machine)

### 1. Add WebAuthn helper library
Create: `app/src/lib/webauthn.ts`
- `registerPasskey()` - Create and register a new passkey
- `authenticateWithPasskey()` - Sign challenge with existing passkey
- Handle browser WebAuthn API calls

### 2. Update Security page - Passkey Registration
Modify: `app/src/pages/Security.tsx`
- Add "Passkeys" section
- List registered passkeys (name, created date, last used)
- "Register New Passkey" button → triggers WebAuthn registration
- Delete passkey option
- Calls `passkey-register` endpoint

### 3. Update Login page - Passkey Authentication
Modify: `app/src/pages/Login.tsx`
- Add "Sign in with Passkey" button below email/password form
- Check if user has any registered passkeys (conditional render)
- On click: trigger WebAuthn authentication flow
- On success:
  - If callback URL present → redirect with user_id token
  - If no callback → normal login to dashboard

### 4. Add callback handling for Vinzrik
Create: `app/src/pages/AuthCallback.tsx` (or handle in Login.tsx)
- Parse callback URL from query params
- After successful passkey auth, redirect to callback with secure token
- Token format: short-lived JWT or signed payload with user_id

### 5. Add route for auth callback
Modify: `app/src/App.tsx`
- Add `/auth` route that handles Vinzrik auth requests
- Accepts `callback` and `app_id` query params

---

## VINZRIK TASKS (Other machine)

### 1. Create Zule auth launcher
Create: `src/auth/gatekeeperAuth.ts`
- `launchZuleLogin(appId?: string)` - Opens Zule in browser
  - Constructs URL: `https://zule.mazzizax.net/auth?callback=vinzrik://auth-callback&app_id=X`
  - Opens URL with `Linking.openURL()`

### 2. Handle auth callback deep link
Modify: `src/navigation/deepLinkHandler.ts`
- Add handler for `vinzrik://auth-callback`
- Parse token from URL params
- Validate token (check signature/expiry)
- Extract user_id from token
- Compute ghost_id, discard user_id
- Update auth state

### 3. Update Login screen
Modify: `src/screens/Auth/LoginScreen.tsx`
- Replace email/password form with single "Login with Zule" button
- Button calls `launchZuleLogin()`
- Keep email/password as fallback/secondary option for now

### 4. Update app-initiated auth flow
Modify: `src/auth/bridge.ts`
- When app requests auth and user not logged in:
  - Launch Zule instead of showing Vinzrik login
  - After callback, compute ghost_id and return to app

### 5. Register deep link scheme
Modify: `app.json`
- Ensure `vinzrik://` scheme is registered
- Add `auth-callback` path handling

---

## TOKEN SECURITY

The callback token must be:
1. **Short-lived** - Expires in 60 seconds
2. **Single-use** - Invalidated after first use
3. **Signed** - HMAC or JWT signed by Zule
4. **Contains**: user_id, issued_at, expires_at, nonce

Option A: JWT signed with Zule secret
Option B: Store token in Zule DB, Vinzrik exchanges token for user_id via API call

---

## IMPLEMENTATION ORDER

**Phase 1: Zule (do first)**
1. WebAuthn helper library
2. Security page passkey registration
3. Login page passkey auth (basic, no callback yet)
4. Test in browser

**Phase 2: Zule callback flow**
5. Add /auth route with callback support
6. Token generation for callbacks
7. Test callback flow manually

**Phase 3: Vinzrik integration**
8. Zule auth launcher
9. Deep link callback handler
10. Update Login screen
11. Update bridge for app-initiated auth
12. End-to-end test

---

## FILES SUMMARY

### Zule
| File | Action |
|------|--------|
| `app/src/lib/webauthn.ts` | NEW - WebAuthn browser API helpers |
| `app/src/pages/Security.tsx` | MODIFY - Add passkey management |
| `app/src/pages/Login.tsx` | MODIFY - Add passkey login option |
| `app/src/pages/AuthCallback.tsx` | NEW - Handle Vinzrik auth requests |
| `app/src/App.tsx` | MODIFY - Add /auth route |

### Vinzrik
| File | Action |
|------|--------|
| `src/auth/gatekeeperAuth.ts` | NEW - Launch Zule for auth |
| `src/navigation/deepLinkHandler.ts` | MODIFY - Handle auth callback |
| `src/screens/Auth/LoginScreen.tsx` | MODIFY - Use Zule login |
| `src/auth/bridge.ts` | MODIFY - Launch Zule for app auth |
| `app.json` | VERIFY - Deep link scheme |
