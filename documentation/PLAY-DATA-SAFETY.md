# Play Store — Data Safety Declarations (Zule)

Authoritative disclosure of what Zule collects, what it shares, how it protects data, and how a user can get their data deleted. Matches the field names on Google Play Console's **Data Safety** form verbatim so a publisher can fill the form by copying the tables below.

Scope: the Zule Android app as shipped from `Mazzizax/zule`. This is a superset of the login module's surface — Zule inherits login-module-equivalent auth behavior and adds machine authorization, Vinzrik attestation (blind-handoff to downstream apps), Stripe subscriptions + identity verification, and Plaid banking link.

For the login-module baseline declarations that also apply here, see `assets/login/PLAY-DATA-SAFETY.md`. This document adds the zule-specific items on top.

---

## 1. Data collection & sharing — per Play data type

### Play field definitions used throughout

- **Collected:** user data is transmitted off the device (even briefly, even to your own servers).
- **Shared:** data is transferred to a third party that uses it for its own purposes. Data handed to a service-provider / processor that uses it only to deliver the app's requested service is **not** "shared" by Play's definition.
- **Processed ephemerally:** data is received by your servers but not retained.
- **Required:** user cannot use the relevant feature without providing it.
- **Optional:** user can decline and the feature still works at reduced fidelity.

### Purposes (Play enumeration)

- **App functionality** — core features work
- **Analytics** — understanding usage patterns
- **Developer communications** — reaching the user
- **Advertising or marketing** — targeting ads / marketing
- **Fraud prevention, security, and compliance** — defending the app and users against abuse
- **Personalization** — tailoring the app UX
- **Account management** — authenticating, setting up, and managing accounts

### Personal info

| Data type | Collected | Shared | Ephemeral | Required | Purposes | Notes |
|---|---|---|---|---|---|---|
| Name | No | — | — | — | — | Not collected. |
| **Email address** | **Yes** | **No** | No | **Required** | **App functionality; Account management; Fraud prevention, security, and compliance; Developer communications** | Primary account identifier. Used to: sign the user in (password flow), deliver signup confirmation / password-reset / magic-link emails (developer communications), rate-limit abuse by address (fraud prevention). Stored in Zule's Supabase backend. Delivered to Resend for email transport (processor, not a share). Never sold. Never used for advertising. |
| **User IDs** | **Yes** | **No** | No | **Required** | **App functionality; Account management; Fraud prevention, security, and compliance** | Supabase-issued UUID (`auth.users.id`). Internal only — not shown to the user, never appears in URLs. Used to scope row-level security, passkey ownership, subscription ownership, machine ownership, rate-limit attribution. **Explicitly NOT leaked to Vinzrik** — the Vinzrik attestation carries a blind `{type:"attestation", valid:true, auth_level:"..."}` JWT with no user identifier (see `supabase/functions/issue-attestation/index.ts:97-98`). |
| Address | No | — | — | — | — | Not collected by Zule. (Stripe may collect billing address under its own processor agreement during checkout; Zule does not store the address.) |
| Phone number | No | — | — | — | — | Not collected. Plaid identity flow may surface phone to the user but Zule does not store it. |
| Race and ethnicity | No | — | — | — | — | Not collected. |
| Political or religious beliefs | No | — | — | — | — | Not collected. |
| Sexual orientation | No | — | — | — | — | Not collected. |
| Other info | No | — | — | — | — | Not collected. |

### Financial info

| Data type | Collected | Shared | Ephemeral | Notes |
|---|---|---|---|---|
| **User payment info** | **Yes** (via Stripe) | **No** | — | Credit-card / payment-method details collected **only inside Stripe's hosted Checkout / Customer Portal iframes**. Zule never sees the raw PAN, CVV, or expiry. Stripe is a processor under Stripe's own terms. The only thing Zule persists is `stripe_customer_id` + `stripe_subscription_id` references (`user_profiles` table). |
| **Purchase history** | **Yes** | No | No | Subscription tier + status (`subscription_tier`, `subscription_status`, `subscription_expires_at` in `user_profiles`) and purchase records in `stripe_purchases` (migration `00011_stripe_purchases_and_identity.sql`). Purpose: **App functionality; Account management**. |
| Credit score | No | — | — | Not collected. |
| **Other financial info** | **Yes** (via Plaid) | **No** | — | Bank-account link tokens + account metadata (`plaid_accounts` table) + transaction records (per the Plaid pull flow). Transactions are decorated server-side into the minted-card ledger (`mint-transaction-cards`, `shred-minted-transactions` functions). Collected when the user opts into a banking link via Plaid's hosted flow. Plaid is a processor under its own data-handling terms. |

### Health and fitness

All data types: **Not collected.**

### Messages

All data types (emails, SMS/MMS, other in-app messages): **Not collected.** The app **sends** transactional email to the user's own address (signup confirmation, recovery, resend) but does not access the user's messaging content.

### Photos and videos

| Data type | Collected | Notes |
|---|---|---|
| Photos | No | — |
| Videos | No | — |
| **Identity-verification selfie / document image** | **Yes — via Stripe Identity** (when the user initiates identity verification) | Collected inside Stripe's hosted Identity flow; Zule never receives the image. Stripe acts as the identity-verification processor. Only the verification status reference is stored. |

### Audio files

All data types: **Not collected.**

### Files and docs

All data types: **Not collected.**

### Calendar

All data types: **Not collected.**

### Contacts

All data types: **Not collected.**

### App activity

| Data type | Collected | Shared | Notes |
|---|---|---|---|
| App interactions | No | — | No analytics on screen visits, button taps, time-in-app. |
| In-app search history | No | — | No in-app search. |
| Installed apps | No | — | `QUERY_ALL_PACKAGES` not declared. |
| Other user-generated content | No | — | Loyalty-card metadata (`loyalty-cards` function) stores card titles/barcodes scanned by the user into their own vault; this is user-authored content but it's stored encrypted against the user's own row, not shared. Still marked **No** here because it's not distributed to any other user or third party. |
| **Authentication attempts** (under "Other actions") | **Yes** | **No** | Per-passkey attempt rows (`passkey_auth_attempts`) and per-email attempt rows (`auth_email_attempts`) on the server, used for rate limiting and clone detection. Rows carry: credential_id, user_id, email, IP address, attempt outcome, timestamp. Purposes: **Fraud prevention, security, and compliance**. Never used for advertising. Not shared. |
| **Machine-login approvals** (under "Other actions") | **Yes** | **No** | When the user approves a machine sign-in session from their phone, an entry is written to `machine_login_sessions` with the approving user's id + timestamp + authenticator type (biometric/password). Retained for the session's lifetime then expired. Purposes: **App functionality** (unlocking the paired machine) and **Fraud prevention**. Not shared. |
| **Audit log** (under "Other actions") | **Yes** | **No** | `audit_logs` table captures every auth and high-privilege action: `auth_validated`, `auth_failed`, `auth_rejected_unverified`, `passkey_registered`, `passkey_authenticated`, `machine_auth_approved`, `machine_auth_denied`, `rate_limited`, plus subscription / admin events. Captures user_id, action, category, ip_address, user_agent, metadata. Purpose: **Fraud prevention, security, and compliance**. |

### Web browsing

| Data type | Collected | Notes |
|---|---|---|
| Web browsing history | No | The app opens Privacy/Terms/Contact pages via Chrome Custom Tabs — that's the system browser's own session, not tracked by the app. Stripe / Plaid hosted flows open via Custom Tabs and execute inside their own processor domains. |

### App info and performance

| Data type | Collected | Notes |
|---|---|---|
| Crash logs | No | No crash reporting service integrated. |
| Diagnostics | No | — |
| Other app performance data | No | — |

### Device or other IDs

| Data type | Collected | Notes |
|---|---|---|
| **Machine identifier** (under "Other IDs") | **Yes** | For the machine-authorization feature only. When the user pairs a physical machine (`fleet_machines.machine_identifier`, e.g., Tailscale node ID or hostname), the machine's identifier is stored alongside the user's ownership record. This is a **machine** identifier, not a user identifier — the user's phone never carries it as a device ID. Purpose: **App functionality**. |
| Device or other IDs | No | No Android ID, no Advertising ID (ad APIs not linked), no device fingerprint, no installation ID. The only device-scoped identifier is the cryptographic public-key fingerprint used for App Links / WebAuthn origin binding — which is not an identifier of the user, only of the app binary. |

---

## 2. Biometric & on-device material (not in Play's form, but users ask)

- **Fingerprint / Face / Iris biometric data is NEVER transmitted.** Ever. The biometric readout stays inside the device's Trusted Execution Environment (TEE) / StrongBox. Android Credential Manager + the user's chosen credential provider handle the biometric gesture locally and produce a cryptographic assertion. The assertion is a signature, not biometric data.
- **Passkey private keys** stay in the device's platform authenticator (Google Password Manager). The app never sees the private key. Only the public key component is transmitted to the server at enrollment, as the standard WebAuthn ceremony requires.
- **Local device flag** (`DeviceFlags` via `EncryptedSharedPreferences`) — a boolean `passkey_enrolled_v1` flag — never leaves the device. Used by the login screen to decide whether to collapse email/password fields behind the passkey button.
- **Session access tokens and refresh tokens** live in memory only (`MemorySessionManager`). Process death invalidates them. No backup, no device-transfer, no disk.
- **Machine API keys** (`zm_<48 hex>`) are generated server-side and their SHA-256 hashes stored in `fleet_machines.api_key_hash`. The plaintext key is shown to the user once during pairing; if the user chooses to save it, they save it to their device's credential store or write it down — the app does not persist the plaintext.

---

## 3. Third parties — role classification

Play distinguishes between **sharing** (third parties that use data for their own purposes) and **processors** (vendors that act on the app's behalf under contract). Zule's third parties are all processors, but the scope is wider than the login-module baseline:

| Vendor | Role | Data handed over | Retention |
|---|---|---|---|
| **Supabase** | Hosting / backend / auth platform | Email, password hash, user_id, passkey public keys, attempt logs, subscription metadata, audit logs, machine ownership rows, Plaid account records, loyalty card vault, minted-transaction cards | Retained until user deletes their account; then cascaded delete on `auth.users` removes every dependent row. |
| **Resend** | Email delivery transport | Recipient email + transactional email body (signup confirm, magic link, password reset) | Retained per Resend's data retention terms (delivery logs). User email may appear in Resend's logs until their standard purge window. |
| **Have I Been Pwned (HIBP)** | Breached-password lookup (k-anonymity) | **First 5 hex characters of SHA-1(password)**. The plaintext password, the full hash, and any user identifier are **never** sent. HIBP returns a list of hash suffixes matching that 5-character prefix; the app compares the remaining 35 chars locally. | Not retained — HIBP stateless API. |
| **Stripe** | Payment processing + Customer Portal + Identity Verification | Card data inside hosted iframes; billing address; optional identity documents during verification | Retained per Stripe's own retention policy. Zule only stores reference ids (`stripe_customer_id`, `stripe_subscription_id`) plus subscription state. |
| **Plaid** | Bank-account link + transaction pulls | Institution credentials (inside Plaid Link's hosted flow); transaction data returned via `plaid-pull-transactions` | Retained per Plaid's terms. Zule stores account metadata and transaction records on its own Supabase for the user's own vault. |
| **Google Play Services (Credential Manager)** | Platform passkey provider | Passkey ceremony (on-device, OS-level) | Subject to Google's own handling of Google Password Manager data. Out of scope for Zule's collection since the app never receives biometric or private-key material. |
| **Android App Links verifier** | One-time install-time DNS fetch of `/.well-known/assetlinks.json` | None. Fetches a public file. | N/A. |
| **Ghozerauth** (Mazzizax-operated) | Mints a Goals/Iterations JWT from a Zule attestation + ghost_id | The blind attestation JWT (no user identifier) + the device-local ghost_id provided by Vinzrik | Not retained as user-identifying data; it only knows `ghost_id`. |

**No advertising SDK.** **No analytics SDK.** **No attribution SDK.** **No tag manager.**

---

## 4. Security practices — Play form questions

### Is all data encrypted in transit between devices and your servers?

**Yes.**

- Every network call from the app travels over TLS 1.2+.
- Cleartext HTTP is explicitly disabled at the manifest level (`android:usesCleartextTraffic="false"`) and reinforced by the `network_security_config.xml` which sets `cleartextTrafficPermitted="false"` for every domain.
- **Certificate pinning** on the Supabase host (`sgjulzvgcyotebbexfue.supabase.co`) with leaf + intermediate + root SPKI hashes (2027-01-01 expiration).
- User-installed CAs are not trusted — only system CAs. This prevents MITM via a malicious certificate installed in a corporate MDM profile or injected by an evil-twin Wi-Fi setup.
- Supabase's Edge Functions, Auth, and Postgrest all enforce TLS 1.2+ server-side.
- Resend API, HIBP API, Stripe API, Plaid API, Ghozerauth API all served over TLS.

### Do you provide a way for users to request that their data is deleted?

**Yes.**

- In-app: signed-in user opens **Security → Delete Account**, confirms through the two-step destructive dialog. The client calls the `delete-account` Edge Function, which invokes `supabase.auth.admin.deleteUser(user.id)`. The `auth.users` row is removed; PostgreSQL `ON DELETE CASCADE` removes every dependent row across `user_profiles`, `user_passkeys`, `fleet_machines`, `machine_login_sessions`, `plaid_accounts`, `stripe_purchases`, `loyalty-cards`, `blind_token_log`, and `audit_logs`. The user is locally signed out and every local identifier (`DeviceFlags`) cleared.
- Audit-log rows retained as security logs (non-PII once `auth.users` is gone).
- For compliance requests routed outside the app, the contact email on the Privacy page is the deletion-request channel; the operator uses the same Edge Function or direct admin API to fulfill.

### Do you commit to follow the Google Play Families Policy?

**N/A** for general-purpose distribution. Zule is not designed for or directed at children under 13.

### Has your app been independently security reviewed?

**Not yet** (as of this revision). The app has not undergone an external penetration test, SOC 2 audit, or MASA assessment. It implements practices aligned with the OWASP MASVS Level 1 controls (secure storage, secure communications, platform-interaction hardening) and adds certificate pinning on the primary backend host, but this is an internal claim, not a certified one.

### Has your app been reviewed against the Mobile Application Security Assessment (MASA) standard?

**No.** A MASA audit is an external attestation and has not been performed. If a future audit is commissioned, update this section.

---

## 5. User-visible disclosure links

Linked at the bottom of every authentication surface (via `LegalFooter`) and from `SecurityScreen`:

- Privacy Policy: https://zule.mazzizax.net/privacy
- Terms of Service: https://zule.mazzizax.net/terms
- Contact: https://mazzizax.org/contact

These URLs are `BuildConfig` fields — override at integration time.

---

## 6. When to revise this document

Any of the following changes require updating both this document and the Play Console submission:

- Adding a third-party SDK (advertising, analytics, attribution, crash reporting, push, anything).
- Collecting a new data type that's not already listed.
- Changing a "No" to "Yes" for any data type row.
- Adding or replacing a processor vendor.
- Changing the retention policy for any server-side record.
- Integrating Play Integrity (introduces device-attestation data — classify carefully before Yes/No).
- Adding a new payment surface beyond Stripe, a new banking surface beyond Plaid, or a new identity-verification vendor beyond Stripe Identity.

The app `versionCode` / `versionName` at the time of each revision should be noted in the Play Console submission comment so the declaration is traceable to a specific code commit.

---

## 7. Exact fill-in-the-form summary (copy/paste)

Condensed version for the Play Console submission. Every field below matches a question on the form.

```
Does your app collect or share any of the required user data types?
    Yes.

Is all of the user data collected by your app encrypted in transit?
    Yes.

Do you provide a way for users to request that their data is deleted?
    Yes.

Data types collected:

    Personal info:
        - Email address: YES (required). Purpose: App functionality,
          Account management, Fraud prevention, Developer communications.
          Not shared. Not ephemeral.
        - User IDs: YES (required). Purpose: App functionality,
          Account management, Fraud prevention.
          Not shared. Not ephemeral.

    Financial info:
        - User payment info: YES (via Stripe processor). Purpose:
          App functionality, Account management. Not shared.
        - Purchase history: YES. Purpose: App functionality,
          Account management. Not shared.
        - Other financial info (Plaid bank link + transactions): YES.
          Purpose: App functionality. Not shared.

    Photos and videos:
        - Identity-verification document / selfie via Stripe Identity: YES
          (optional; only when user triggers identity verification).
          Purpose: Fraud prevention, security, and compliance.
          Not shared beyond Stripe processor.

    App activity → Other actions:
        - Authentication attempts: YES.
          Purpose: Fraud prevention, security, and compliance.
          Not shared.
        - Machine-login approvals: YES.
          Purpose: App functionality, Fraud prevention.
          Not shared.
        - Audit log: YES.
          Purpose: Fraud prevention, security, and compliance.
          Not shared.

    Other IDs:
        - Machine identifier (paired machines): YES.
          Purpose: App functionality. Not shared.

Every other data type in the Play taxonomy: NOT COLLECTED.
```
