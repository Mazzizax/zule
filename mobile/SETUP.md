# Zule Mobile Setup Guide

## Overview

Zule Mobile is the identity provider app for the Xenon ecosystem. It authenticates users and issues attestations for Vinzrik without revealing user identity.

## Prerequisites

- Node.js 18+
- EAS CLI: `npm install -g eas-cli`
- Expo account with access to create projects
- Access to Vercel (for assetlinks.json deployment)

## 1. Environment Setup

Copy the environment template and fill in your Supabase credentials:

```bash
cp .env.example .env
```

Edit `.env`:
```
EXPO_PUBLIC_ZULE_URL=https://your-project.supabase.co
EXPO_PUBLIC_ZULE_PUBLISHABLE_KEY=your-publishable-key
```

## 2. EAS Project Initialization

Initialize the EAS project:

```bash
cd mobile
eas init
```

When prompted:
- Create a new project or link to existing
- Project name: `gatekeeper`

This will populate the `projectId` in `app.json`.

## 3. Android App Links Setup

Android App Links require a `/.well-known/assetlinks.json` file on your domain that verifies app ownership.

### Step 1: Get the signing key fingerprint

After your first EAS build, get the SHA-256 fingerprint:

```bash
eas credentials --platform android
```

Look for the SHA-256 certificate fingerprint (format: `XX:XX:XX:...`).

### Step 2: Create assetlinks.json

Create this file to be served at `https://zule.mazzizax.net/.well-known/assetlinks.json`:

```json
[
  {
    "relation": ["delegate_permission/common.handle_all_urls"],
    "target": {
      "namespace": "android_app",
      "package_name": "com.xenon.gatekeeper",
      "sha256_cert_fingerprints": [
        "YOUR_SHA256_FINGERPRINT_HERE"
      ]
    }
  }
]
```

### Step 3: Deploy to Vercel

In your Zule web project, create the file:

```
gatekeeper/
├── app/
│   └── public/
│       └── .well-known/
│           └── assetlinks.json
```

Or add a Vercel rewrite in `vercel.json`:

```json
{
  "rewrites": [
    {
      "source": "/.well-known/assetlinks.json",
      "destination": "/api/assetlinks"
    }
  ]
}
```

Then create `api/assetlinks.js`:

```javascript
export default function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.json([
    {
      relation: ["delegate_permission/common.handle_all_urls"],
      target: {
        namespace: "android_app",
        package_name: "com.xenon.gatekeeper",
        sha256_cert_fingerprints: [
          "YOUR_SHA256_FINGERPRINT_HERE"
        ]
      }
    }
  ]);
}
```

## 4. iOS Universal Links Setup (Optional)

For iOS, create `apple-app-site-association` at `https://zule.mazzizax.net/.well-known/apple-app-site-association`:

```json
{
  "applinks": {
    "apps": [],
    "details": [
      {
        "appID": "TEAM_ID.com.xenon.gatekeeper",
        "paths": ["/auth/*"]
      }
    ]
  }
}
```

Replace `TEAM_ID` with your Apple Developer Team ID.

## 5. Building the App

### Development Build

```bash
npm run build:android:preview
```

This creates an APK for testing.

### Production Build

```bash
npm run build:android
```

This creates an AAB for Play Store submission.

## 6. Testing the Auth Flow

1. Install the Zule app on your device
2. From Vinzrik, trigger authentication
3. Vinzrik should open: `https://zule.mazzizax.net/auth?callback=vinzrik://auth-callback`
4. If App Links are configured correctly, this opens Zule mobile (not the browser)
5. User logs in
6. Zule issues attestation and redirects to `vinzrik://auth-callback?attestation=...&status=success`

## Troubleshooting

### App Links not working

1. Verify assetlinks.json is accessible:
   ```bash
   curl https://zule.mazzizax.net/.well-known/assetlinks.json
   ```

2. Check the fingerprint matches your signing key

3. On Android 12+, manually verify in Settings > Apps > Zule > Open by default

### Attestation fails

1. Check Supabase credentials in `.env`
2. Verify the `issue-attestation` edge function is deployed
3. Check the `ATTESTATION_SIGNING_KEY` secret is set in Supabase

## Project Structure

```
mobile/
├── app/                    # expo-router pages
│   ├── _layout.tsx         # Root layout with AuthProvider
│   ├── index.tsx           # Entry point (redirects based on auth)
│   ├── auth.tsx            # Vinzrik auth flow (primary function)
│   ├── login.tsx           # Direct login screen
│   ├── register.tsx        # Account creation
│   └── (tabs)/             # Authenticated screens
│       ├── _layout.tsx     # Tab navigation
│       ├── index.tsx       # Dashboard
│       ├── profile.tsx     # Profile settings
│       └── security.tsx    # Security settings
├── src/
│   ├── lib/
│   │   ├── supabase.ts     # Supabase client with SecureStore
│   │   ├── attestation.ts  # Attestation service
│   │   └── linking.ts      # Deep link utilities
│   └── contexts/
│       └── AuthContext.tsx # Authentication state
├── app.json                # Expo config with App Links
├── eas.json                # EAS build config
└── package.json
```
