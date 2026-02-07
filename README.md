# Zule

Universal privacy-first identity provider with the Ghost ID system.

## Overview

Zule is a user authentication system that provides anonymous identities to applications. Users authenticate once with Zule, and apps only ever see a `ghost_id` - a pseudonymous identifier that cannot be linked back to the user's real identity.

### Key Features

- **Ghost Identity**: Cryptographic identity system where `ghost_id = SHA256(user_id + ghost_secret)`
- **Client-Side Secret**: The `ghost_secret` is stored only on the user's device - the server never knows it
- **Blind Tokens**: Apps receive tokens that prove identity without revealing who the user is
- **User Control**: Users manage which apps can access their ghost identity

## Architecture

```
gatekeeper/
├── app/           # React frontend (user portal)
├── supabase/      # Edge Functions and database migrations
└── docs/          # Documentation
```

### Two-Project Separation

Zule is designed to work alongside application backends (like Xenon Engine) with strict separation:

- **Zule** (this repo): Knows user identity (email, payment info), issues blind tokens
- **Application Backend**: Only knows `ghost_id`, validates blind tokens, never sees user identity

## Setup

### Frontend (app/)

```bash
cd app
npm install
npm run dev
```

Environment variables needed:
- `VITE_SUPABASE_URL` - Supabase project URL
- `VITE_SUPABASE_ANON_KEY` - Supabase anon key
- `VITE_ZULE_URL` - Same as Supabase URL (for Edge Functions)

### Supabase (supabase/)

Deploy Edge Functions:
```bash
cd supabase
supabase functions deploy
```

## Documentation

See the [docs/](docs/) folder for detailed documentation:
- `GATEKEEPER_STATUS.md` - Current status and roadmap
- `GHOST_ID_ALGORITHM.md` - Technical specification of the Ghost ID system
