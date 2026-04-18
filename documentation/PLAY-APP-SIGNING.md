# Play App Signing — Keys, Fingerprints, and Publishing (Zule)

Authoritative reference for how Zule is signed, how the certificates relate to Android App Links / passkey origin binding / the Vinzrik attestation hand-off, and the exact operator steps to produce a release that Google Play will accept and that will continue to pass the `/.well-known/assetlinks.json` verification.

Scope: Zule's publishing pipeline. This is a superset of the login-module's `PLAY-APP-SIGNING.md` with zule-specific wrinkles around the Vinzrik / Ghozerauth / Goals ecosystem.

---

## 1. Why signing matters for Zule specifically

Three features depend on certificate fingerprints being correct:

1. **Android App Links.** The system verifies the first time the app is installed that `https://zule.mazzizax.net/.well-known/assetlinks.json` declares the installed APK's signing cert's SHA-256 fingerprint. If it doesn't match, the intent filter with `android:autoVerify="true"` silently falls back to the browser-disambiguation dialog. That breaks the deep-link return from signup confirmation / password reset / magic-link emails — the link loads in a browser tab instead of resuming the app.
2. **WebAuthn / passkey origin binding.** Credential Manager and Google Password Manager use the signing certificate (via the Play Services digital-asset-links lookup) to establish the app's "origin" for WebAuthn purposes. A passkey enrolled against one signing identity is not usable from an APK signed with a different identity. This is why you **cannot** test passkeys with a debug APK and expect the same passkey to work on a Play-distributed release.
3. **Vinzrik hand-off / `EXPECTED_ORIGINS` allowlist.** Zule's Supabase Edge Functions pin `EXPECTED_ORIGINS` in `supabase/functions/_shared/webauthn-config.ts` including `android:apk-key-hash:7XrT7DwGTOXZgUhB78XwgBc-sQatZaRGvJvEEDhDvPU` (the current debug cert). When you rotate to a Play-signed release, you must add the Play app-signing-key's apk-key-hash to that array, redeploy the functions, and keep both hashes during a transition window — otherwise production-signed APKs will see their assertions fail origin validation.

Two of these (App Links + WebAuthn origin) are server-side lookups of a public file; one (`EXPECTED_ORIGINS`) is a server-side array inside the Edge Function code. There is no runtime secret to rotate. Everything hinges on getting the fingerprint right in three places consistently.

---

## 2. The two keys in Play App Signing — concept

Google Play App Signing separates two distinct certificates:

- **Upload key** (also called "upload certificate") — the cert you sign the AAB with locally before uploading. Google Play verifies an upload-key match on every submission, so the upload key is the one you guard against being replaced if your developer account is compromised. It can be rotated through the Play Console if lost.
- **App signing key** (also called "Play signing key" or "distribution key") — the cert Google uses to re-sign the APK before serving it to end devices. This is the cert users' phones actually see. It is stored in Google's HSM. You cannot export it; you can only retrieve its fingerprint from the Play Console.

For App Links, passkeys, and the Vinzrik attestation hand-off to work on a Play-installed APK, the following must all list the **app signing key's** SHA-256 fingerprint (the one users' devices verify):

- `assetlinks.json` at `https://zule.mazzizax.net/.well-known/assetlinks.json`
- `EXPECTED_ORIGINS` in `supabase/functions/_shared/webauthn-config.ts` (as `android:apk-key-hash:<base64url-of-first-32-bytes-of-SHA-256>`)

You can also include the upload key's fingerprint in both of the above to make App Links and passkeys work for APKs you install from Android Studio / `adb install` using the upload key directly. Both fingerprints can coexist — verification succeeds if any listed fingerprint matches.

---

## 3. Current state (as of this revision)

| Item | Value |
|---|---|
| Application ID | `com.mazzizax.zule` |
| Current debug signing cert (SHA-256) | `ED:7A:D3:EC:3C:06:4C:E5:D9:81:48:41:EF:C5:F0:80:17:3E:B1:06:AD:65:A4:46:BC:9B:C4:10:38:43:BC:F5` |
| Same cert as `android:apk-key-hash` | `7XrT7DwGTOXZgUhB78XwgBc-sQatZaRGvJvEEDhDvPU` (base64url of the first 32 bytes of the SHA-256) |
| Debug keystore location | `~/.android/debug.keystore` (standard Android Gradle Plugin default) |
| Release signing config in `zule-android/app/build.gradle.kts` | **Not configured.** The `release { ... }` block enables minify / shrink / proguard but has no `signingConfig`. |
| Upload keystore | **Does not exist yet.** Must be generated before first Play upload. |
| Play App Signing enrolled | **No.** No Play Console listing exists for Zule yet. |
| `assetlinks.json` (at `zule-web/public/.well-known/assetlinks.json`) | Contains **two** entries: one for `com.mazzizax.zule` with the debug cert above, and one for `com.xenon.vinzrik` with Vinzrik's debug cert (`FA:C6:17:45:…`). Served from Vercel via `zule-web`. |
| `EXPECTED_ORIGINS` current entries | `https://zule.mazzizax.net`, legacy `gatekeeper-nine.vercel.app`, legacy `xenon-engine-web.vercel.app`, Vinzrik debug apk-key-hash, legacy gatekeeper apk-key-hash, Zule Mobile debug apk-key-hash. Legacy entries have a hard removal date of May 8, 2026. |
| `AUTH_HOST` / App Links host | `zule.mazzizax.net` |
| Intent filter path prefix | `/auth` |

**Important:** the current `assetlinks.json` cert is the operator's local debug cert (same across machines because a shared debug keystore is committed to — or at least matched across — team machines). For solo development that has been acceptable. For Play-adjacent testing or production, a deliberate upload-key setup is required (section 4 below).

---

## 4. Operator procedure — first Play upload

Do this once. Below assumes Zule is being published as its own app, separately from Vinzrik (which is a different package and publishing track).

### 4.1 Generate an upload keystore locally

```cmd
keytool -genkey -v ^
  -keystore zule-upload-keystore.jks ^
  -alias upload ^
  -keyalg RSA -keysize 4096 ^
  -validity 10000 ^
  -storetype JKS
```

Notes:
- `-keysize 4096` matches the strength Play App Signing uses for its own key.
- `-validity 10000` (≈27 years) — Play's best-practice minimum.
- Store the `.jks` file **outside the git repo** (e.g., `~/.android/zule-upload-keystore.jks`).
- Store both the **keystore password** and the **key alias password** in a password manager.

### 4.2 Wire the upload key into release builds

Create `zule-android/keystore.properties` (NOT checked in; add to `.gitignore`):

```
storeFile=C:/Users/o2bma/.android/zule-upload-keystore.jks
storePassword=<keystore password>
keyAlias=upload
keyPassword=<key alias password>
```

Add to `zule-android/app/build.gradle.kts` (outside the `android { ... }` block, at top of file):

```kotlin
import java.util.Properties
import java.io.FileInputStream

val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = Properties().apply {
    if (keystorePropertiesFile.exists()) {
        load(FileInputStream(keystorePropertiesFile))
    }
}
```

Inside the `android { ... }` block, before `buildTypes`:

```kotlin
signingConfigs {
    create("release") {
        if (keystorePropertiesFile.exists()) {
            storeFile = file(keystoreProperties.getProperty("storeFile"))
            storePassword = keystoreProperties.getProperty("storePassword")
            keyAlias = keystoreProperties.getProperty("keyAlias")
            keyPassword = keystoreProperties.getProperty("keyPassword")
        }
    }
}
```

Modify the existing `release` build type:

```kotlin
buildTypes {
    release {
        isMinifyEnabled = true
        isShrinkResources = true
        proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        if (keystorePropertiesFile.exists()) {
            signingConfig = signingConfigs.getByName("release")
        }
    }
}
```

### 4.3 Extract the upload key's fingerprints

```cmd
keytool -list -v ^
  -keystore zule-upload-keystore.jks ^
  -alias upload
```

Copy:
- The `SHA256:` line for `assetlinks.json`.
- The SHA-256 bytes → convert to base64url of the first 32 bytes → that's the `android:apk-key-hash:…` string for `EXPECTED_ORIGINS`.

Quick base64url conversion (PowerShell):

```powershell
$hex = "AA:BB:CC:..."  # the full SHA-256 colon-hex from keytool
$bytes = $hex.Split(':') | ForEach-Object { [byte]::Parse($_, 'HexNumber') }
[Convert]::ToBase64String($bytes).Replace('+','-').Replace('/','_').TrimEnd('=')
```

### 4.4 Build the release AAB

```cmd
cd zule-android
gradlew.bat :app:bundleRelease
```

Output: `app/build/outputs/bundle/release/app-release.aab`. Verify:

```cmd
jarsigner -verify -verbose -certs app\build\outputs\bundle\release\app-release.aab
```

Look for `jar verified.` and the expected `Subject:` CN.

### 4.5 Create the Play Console listing

Go to `play.google.com/console` → **Create app** → fill listing details with the `com.mazzizax.zule` package name.

Navigate to **Setup → App integrity → App signing**:
- Choose **Let Google manage and protect your app signing key (recommended)** — this is Play App Signing.
- Accept the generated app signing key.

Play will show **two** fingerprints:
- **App signing key certificate** → SHA-256 → this is the fingerprint `assetlinks.json` and `EXPECTED_ORIGINS` must both trust for Play-distributed APKs.
- **Upload key certificate** → SHA-256 → should match the one from step 4.3.

### 4.6 Upload the AAB to Internal Testing

Navigate to **Release → Testing → Internal testing → Create new release** → upload `app-release.aab`. On first upload Play imprints the upload key onto the listing — subsequent uploads must use the same upload keystore or be rejected.

### 4.7 Update `assetlinks.json` with BOTH fingerprints

Edit `zule-web/public/.well-known/assetlinks.json` to include the upload-key + app-signing-key SHA-256 fingerprints for `com.mazzizax.zule`:

```json
{
  "relation": [
    "delegate_permission/common.handle_all_urls",
    "delegate_permission/common.get_login_creds"
  ],
  "target": {
    "namespace": "android_app",
    "package_name": "com.mazzizax.zule",
    "sha256_cert_fingerprints": [
      "<upload key SHA-256 from step 4.3 / 4.5>",
      "<app signing key SHA-256 from step 4.5>"
    ]
  }
}
```

Leave the existing debug fingerprint in the array only if debug builds will continue to hit `zule.mazzizax.net` — otherwise remove it.

### 4.8 Update `EXPECTED_ORIGINS`

Edit `supabase/functions/_shared/webauthn-config.ts` — add both `android:apk-key-hash:<upload-key-base64url>` and `android:apk-key-hash:<app-signing-key-base64url>` entries alongside the existing debug entry.

Redeploy **every** function that imports `_shared/webauthn-config.ts`:

```cmd
cd sandbox\zule
npx supabase functions deploy passkey-register-begin --no-verify-jwt --project-ref sgjulzvgcyotebbexfue
npx supabase functions deploy passkey-register-finish --no-verify-jwt --project-ref sgjulzvgcyotebbexfue
npx supabase functions deploy passkey-auth-begin --no-verify-jwt --project-ref sgjulzvgcyotebbexfue
npx supabase functions deploy passkey-auth-finish --no-verify-jwt --project-ref sgjulzvgcyotebbexfue
npx supabase functions deploy passkey-register --no-verify-jwt --project-ref sgjulzvgcyotebbexfue
npx supabase functions deploy passkey-auth --no-verify-jwt --project-ref sgjulzvgcyotebbexfue
```

`passkey-register` + `passkey-auth` are the legacy pair that still serve the Vinzrik attestation flow — they must be redeployed too.

### 4.9 Deploy assetlinks.json and verify

1. Push `zule-web` (Vercel auto-deploys on push to main).
2. Confirm `https://zule.mazzizax.net/.well-known/assetlinks.json` is reachable with `Content-Type: application/json`, no redirects, no auth wall.
3. Verify Google's crawler sees it: `https://developers.google.com/digital-asset-links/tools/generator` — paste the host and package name, generate, then "Test".
4. On an Android device after installing the Play build (or `adb install` of the upload-signed build):
   ```cmd
   adb shell pm get-app-links com.mazzizax.zule
   ```
   Expect `verified` next to `zule.mazzizax.net`.

---

## 5. Interaction with Vinzrik

Vinzrik is a separate Android app (`com.xenon.vinzrik`) with its own Play Console listing and its own signing identity. Zule's `assetlinks.json` already carries Vinzrik's debug cert so Vinzrik can `zule://auth?callback=…` back into Zule reliably. When **Vinzrik** is released, its own `assetlinks.json` + package's cert fingerprints need to be maintained in lockstep.

Scenarios that require coordinated updates:

- **Zule rotates its app signing key:** Vinzrik's `EXPECTED_ORIGINS` doesn't reference Zule's cert (Vinzrik doesn't verify Zule assertions), but Vinzrik's UI may trust Zule's origin in its own deep-link handler. Re-test the Vinzrik callback flow after rotation.
- **Vinzrik rotates its app signing key:** Zule's `_shared/webauthn-config.ts` currently lists `android:apk-key-hash:-sYXRdwJA3hvue3mKpYrOZ9zSPC7b4mbgzJmdZEDO5w` for Vinzrik debug. Update that entry with Vinzrik's new Play app-signing-key apk-key-hash and redeploy all 6 passkey functions.

---

## 6. Key rotation scenarios

### 6.1 Upload key lost or compromised

Recoverable. Procedure:

1. Generate a new upload keystore (repeat section 4.1).
2. Play Console → Setup → App integrity → Upload key → **Request upload key reset**. Google requires proof-of-identity email confirmation; turnaround typically ≤ 48 hours.
3. Once approved, update `keystore.properties` to point at the new keystore.
4. Add the new upload key's SHA-256 to both `assetlinks.json` and `EXPECTED_ORIGINS`. Leave the old fingerprint in place for 48h to cover in-flight installs, then remove.
5. Next AAB upload must be signed with the new upload key.

### 6.2 App signing key compromise

App signing key compromise is a **much** more severe event. Because Google stores the key in an HSM and never exports it, the user-facing risk of key theft from Google is low. The practical scenarios:

- **Key rotation by choice:** Play Console → App integrity → supports app signing key rotation for devices running Android 28+. Rotated devices get the new key; pre-28 devices keep the old one. Both fingerprints must stay in `assetlinks.json` + `EXPECTED_ORIGINS` during the rotation window.
- **Key must be replaced due to algorithm weakening:** handled the same way.

**Before** rotating the app signing key, consider whether passkey invalidation is acceptable. A change of signing identity changes the app's origin for WebAuthn purposes → existing passkeys can fail to resolve → users get pushed onto email recovery paths. If passkeys have been in the field for any meaningful time, rotation has a user-visible cost. The Vinzrik attestation flow also breaks transiently until Vinzrik's trust config is updated.

### 6.3 Package name change

Changing `applicationId` from `com.mazzizax.zule` is equivalent to shipping a new app. Play does not allow re-using a published `applicationId` on a different listing. It also cascades through:
- `assetlinks.json` needs a new entry for the new package.
- `EXPECTED_ORIGINS` apk-key-hash lines are package-agnostic (they encode the cert fingerprint, not the package) — no change.
- The manifest placeholder `appAuthHost` is unaffected.
- Existing passkeys enrolled against the old package will NOT work with the new package unless you build a migration path.

---

## 7. Verification checklist (run these after any signing-related change)

Compact checklist for end-to-end confirmation:

1. **Build & inspect**
   ```cmd
   cd zule-android
   gradlew.bat :app:bundleRelease
   jarsigner -verify -verbose -certs app\build\outputs\bundle\release\app-release.aab
   ```
   Expect `jar verified.` and the expected CN.

2. **Fingerprint echo**
   ```cmd
   keytool -list -v -keystore zule-upload-keystore.jks -alias upload
   ```
   Compare to `assetlinks.json` and Play Console → App integrity.

3. **Public file serves**
   ```cmd
   curl -I https://zule.mazzizax.net/.well-known/assetlinks.json
   curl https://zule.mazzizax.net/.well-known/assetlinks.json
   ```
   Expect `HTTP/2 200`, `Content-Type: application/json`, no redirects.

4. **Google's verifier**
   `https://developers.google.com/digital-asset-links/tools/generator` — host + package → **Test Statement**.

5. **On-device App Links verification**
   ```cmd
   adb shell pm get-app-links com.mazzizax.zule
   ```
   Expect `verified` next to `zule.mazzizax.net`.

6. **Live flow smoke test**
   - Trigger email confirmation from signup → tap the link in the email on the device → app should resume directly (no browser disambiguation).
   - Sign out, attempt "Sign in with Passkey" from Login → must succeed without being routed through email.
   - Trigger Vinzrik flow (`zule://auth?callback=…`) → tap Passkey on the Vinzrik auth screen → must produce an attestation and redirect back to the Vinzrik callback.
   - Unlock a paired machine (machine-auth) → must surface the pending-session notification and approve via biometric.

If any of 1–5 fails, don't distribute. If 6 fails with 1–5 passing, the problem is in Edge Function code, Resend config, or the Vinzrik integration — not signing.

---

## 8. Local builds signed with the debug keystore

For Android Studio "Run" or `gradlew :app:installDebug`, the build is signed with `~/.android/debug.keystore`. That key's SHA-256 must be listed in `assetlinks.json` **and** the apk-key-hash form must be in `EXPECTED_ORIGINS` if you want App Links + passkeys to work against `zule.mazzizax.net` during debugging. Because every developer's debug keystore can be different, either:

- **Shared-debug-keystore approach (preferred for teams):** commit a team-standard `debug.keystore` to an internal private location and point every developer's `~/.android/debug.keystore` at it. One debug fingerprint in `assetlinks.json` + `EXPECTED_ORIGINS`.
- **Per-developer fingerprint entries (solo OK):** each developer adds their own debug fingerprint.

Today Zule's `assetlinks.json` carries a single debug fingerprint belonging to the current operator machine. Expected state after first Play release: upload-key SHA-256 + Play app-signing-key SHA-256 + (optionally) the operator's debug fingerprint retained if debug builds still hit `zule.mazzizax.net`. Same for `EXPECTED_ORIGINS`.

---

## 9. What must never be committed

- `zule-upload-keystore.jks` or any `.jks` / `.keystore` file
- `keystore.properties` (contains plaintext passwords)
- Any file named `*.pepk` (Play Encryption Private Key — only exists if the operator ever chose the "export-and-upload" flow instead of Play-generated signing)

Add to `.gitignore` before first upload (append to `zule-android/.gitignore` if not already):

```
zule-upload-keystore.jks
*.jks
*.keystore
keystore.properties
*.pepk
```

The debug keystore at `~/.android/debug.keystore` lives in the user's home directory, not the repo, so it's out-of-repo by construction.

---

## 10. Integrity signals Play may also ask about

Two related signing-adjacent features to know about, both **not** currently enabled:

- **Play Integrity API** — server-side attestation that the APK was installed from Play and hasn't been tampered with. Useful for defending backend endpoints against bot traffic. **Not integrated in Zule.** If adopted later, the integrity verdict would be checked inside Supabase Edge Functions on signup / passkey enrollment / machine approval / Stripe checkout callback. Would add a data-collection entry to `PLAY-DATA-SAFETY.md` (device integrity token).
- **APK signature scheme v2 / v3 / v4** — Android's internal APK signing schemes. Play App Signing picks these automatically based on `minSdkVersion` (currently 28, so v2+v3 are in use). No operator action required.

If either is adopted later, update both this document and `PLAY-DATA-SAFETY.md`.

---

## 11. When to revise this document

- First Play upload (current state → "debug-only" becomes "Play-enrolled").
- Any upload-key reset.
- Any app signing key rotation.
- Any change to `applicationId` or `AUTH_HOST`.
- Adding a second distribution target (e.g., Galaxy Store, Amazon, sideloadable APK) that uses a different signing identity.
- Any Vinzrik package / signing change that affects the `android:apk-key-hash` allowlist in `_shared/webauthn-config.ts`.

The app `versionCode` / `versionName` at the time of each revision should be noted in the Play Console submission comment so revisions trace back to specific commits.

---

## 12. Quick summary — the one-page version

- Two keys: **upload** (you hold) + **app signing** (Google holds). Both `assetlinks.json` and `EXPECTED_ORIGINS` must trust both.
- Current Zule: debug-signed only, one debug fingerprint (`ED:7A:D3:EC:…`) in `assetlinks.json` and `EXPECTED_ORIGINS` (as `7XrT7DwGTOXZgUhB78XwgBc-sQatZaRGvJvEEDhDvPU`). No Play listing.
- To publish:
  1. `keytool -genkey` → upload keystore, 4096 RSA, 10000-day validity.
  2. Wire into `zule-android/app/build.gradle.kts` via `keystore.properties` (gitignored).
  3. `gradlew :app:bundleRelease` → upload AAB to Play Console.
  4. Enroll in Play App Signing.
  5. Copy both fingerprints into **`assetlinks.json` + `EXPECTED_ORIGINS`**.
  6. Deploy `zule-web` (assetlinks) + redeploy all six passkey functions (EXPECTED_ORIGINS).
  7. Verify end-to-end with `adb shell pm get-app-links com.mazzizax.zule`.
- Never commit `.jks`, `keystore.properties`, or `.pepk`.
- Any rotation → update `assetlinks.json` + `EXPECTED_ORIGINS` with new + old fingerprints, keep both until old APK installs age out.
- Vinzrik lives in a separate package / signing identity — coordinate when either side rotates.
