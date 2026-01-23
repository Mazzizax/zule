# Frontend Updates for Dual Project Architecture

This document describes the changes needed to `index.html` to support the Gatekeeper/Engine separation.

## 1. Configuration Section

Replace the existing config loading with:

```javascript
// Load configuration
const GATEKEEPER_URL = CONFIG.GATEKEEPER_URL;
const GATEKEEPER_KEY = CONFIG.GATEKEEPER_ANON_KEY;
const ENGINE_URL = CONFIG.ENGINE_URL;
const ENGINE_KEY = CONFIG.ENGINE_ANON_KEY;

// Create separate clients for each project
const gatekeeperClient = window.supabase.createClient(GATEKEEPER_URL, GATEKEEPER_KEY);
const engineClient = window.supabase.createClient(ENGINE_URL, ENGINE_KEY, {
  auth: {
    persistSession: false, // Engine doesn't use sessions
    autoRefreshToken: false,
  }
});

// For backward compatibility during transition
const supabase = gatekeeperClient;
```

## 2. BlindTokenManager Update

The BlindTokenManager should call the GATEKEEPER for token issuance:

```javascript
class BlindTokenManager {
  constructor() {
    this.blindToken = null;
    this.tokenExpiry = null;
  }

  isValid() {
    if (!this.blindToken || !this.tokenExpiry) return false;
    const bufferMs = (CONFIG.TOKEN?.REFRESH_BUFFER_MINUTES || 5) * 60 * 1000;
    return Date.now() < (this.tokenExpiry - bufferMs);
  }

  async getToken(forceRefresh = false) {
    if (!currentSession) return null;
    if (this.isValid() && !forceRefresh) return this.blindToken;

    try {
      // Call GATEKEEPER (not Engine) to get blind token
      const response = await fetch(`${GATEKEEPER_URL}/functions/v1/blind-token-issue`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${currentSession.access_token}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        console.error('[BlindToken] Failed to obtain token:', response.status, error);

        // Handle rate limiting
        if (response.status === 429) {
          const retryAfter = error.retry_after || 60;
          console.warn(`[BlindToken] Rate limited, retry after ${retryAfter}s`);
        }
        return null;
      }

      const data = await response.json();
      this.blindToken = data.blind_token;
      this.tokenExpiry = data.expires_at * 1000; // Convert to ms

      if (CONFIG.FEATURES?.DEBUG) {
        console.log('[BlindToken] Token obtained, tier:', data.tier,
                    'expires in', Math.round((this.tokenExpiry - Date.now()) / 60000), 'minutes');
      }

      return this.blindToken;
    } catch (e) {
      console.error('[BlindToken] Error obtaining token:', e);
      return null;
    }
  }

  async revokeAll() {
    if (!currentSession) return false;

    try {
      const response = await fetch(`${GATEKEEPER_URL}/functions/v1/revoke-token`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${currentSession.access_token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ revoke_all: true })
      });

      if (response.ok) {
        this.clear();
        return true;
      }
      return false;
    } catch (e) {
      console.error('[BlindToken] Revoke failed:', e);
      return false;
    }
  }

  clear() {
    this.blindToken = null;
    this.tokenExpiry = null;
  }
}
```

## 3. XenonQueueManager Update

The queue manager should call ENGINE endpoints with blind tokens:

```javascript
class XenonQueueManager {
  // ... existing constructor and IndexedDB methods ...

  async syncToServer() {
    if (!currentSession) return { synced: 0 };

    const pending = await this.getAllPending();
    if (pending.length === 0) return { synced: 0 };

    // Get blind token from GATEKEEPER
    const blindToken = await blindTokenManager.getToken();
    if (!blindToken) {
      console.warn('[Queue] No blind token available, skipping sync');
      return { synced: 0 };
    }

    let synced = 0;
    for (const item of pending) {
      try {
        // Call ENGINE (not Gatekeeper) with blind token
        const response = await fetch(`${ENGINE_URL}/functions/v1/queue-enqueue`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-blind-token': blindToken,
            'x-ghost-id': item.ghost_id
            // NOTE: No Authorization header - Engine doesn't use JWT
          },
          body: JSON.stringify({
            input_text: item.input_text,
            idempotency_key: item.idempotency_key,
            source_type: 'user_input'
          })
        });

        if (response.ok) {
          await this.markSynced(item.id);
          synced++;
        } else {
          const error = await response.json().catch(() => ({}));
          console.warn('[Queue] Sync failed:', response.status, error);
        }
      } catch (e) {
        console.warn('[Queue] Sync failed for item:', item.id, e);
      }
    }

    this.updateQueueIndicator();
    return { synced, remaining: pending.length - synced };
  }

  async getStatus(ghostId) {
    const blindToken = await blindTokenManager.getToken();
    if (!blindToken) return null;

    try {
      // Call ENGINE for queue status
      const response = await fetch(`${ENGINE_URL}/functions/v1/queue-status`, {
        headers: {
          'x-blind-token': blindToken,
          'x-ghost-id': ghostId
        }
      });
      if (response.ok) {
        return await response.json();
      }
    } catch (e) {
      console.warn('[Queue] Status check failed:', e);
    }
    return null;
  }
}
```

## 4. Data Fetching Functions

Update data fetching to use the ENGINE client:

```javascript
async function fetchLedger() {
  if (!currentSession) return;

  const ghostId = localStorage.getItem('ghost_id');
  if (!ghostId) {
    console.error("No ghost_id found in localStorage");
    return;
  }

  // Use ENGINE client for data queries
  const { data: ledger } = await engineClient
    .from('cosmic_ledger')
    .select('*')
    .eq('ghost_id', ghostId)
    .order('created_at', { ascending: false });

  window.currentLedger = ledger || [];
  renderDashboard(ledger || []);
}

async function fetchActiveQuest() {
  if (!currentSession) return;

  const ghostId = localStorage.getItem('ghost_id');
  if (!ghostId) {
    console.error("No ghost_id found in localStorage");
    return;
  }

  // Use ENGINE client for quest queries
  const { data: quests } = await engineClient
    .from('user_quests')
    .select('*')
    .eq('ghost_id', ghostId)
    .eq('status', 'active')
    .order('created_at', { ascending: false });

  // ... rest of rendering logic
}
```

## 5. Authentication Flow

Keep auth on the GATEKEEPER client:

```javascript
window.handleLogin = async function () {
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;
  const msg = document.getElementById("auth-msg");

  try {
    // Use GATEKEEPER for auth
    const { error } = await gatekeeperClient.auth.signInWithPassword({ email, password });
    if (error) msg.innerText = error.message;
  } catch (err) {
    msg.innerText = err.message;
  }
};

window.handleLogout = async function () {
  // Revoke all blind tokens first (security best practice)
  await blindTokenManager.revokeAll();

  // Then sign out from GATEKEEPER
  await gatekeeperClient.auth.signOut();
};
```

## 6. Profile Fetching (Optional Enhancement)

Add profile fetching from GATEKEEPER:

```javascript
async function fetchUserProfile() {
  if (!currentSession) return null;

  try {
    const response = await fetch(`${GATEKEEPER_URL}/functions/v1/user-profile`, {
      headers: {
        'Authorization': `Bearer ${currentSession.access_token}`
      }
    });

    if (response.ok) {
      return await response.json();
    }
  } catch (e) {
    console.error('[Profile] Fetch failed:', e);
  }
  return null;
}
```

## Summary of Endpoint Routing

| Action | Project | Endpoint |
|--------|---------|----------|
| Login/Signup | Gatekeeper | Supabase Auth |
| Get blind token | Gatekeeper | `/functions/v1/blind-token-issue` |
| Get/update profile | Gatekeeper | `/functions/v1/user-profile` |
| Revoke tokens | Gatekeeper | `/functions/v1/revoke-token` |
| Enqueue event | Engine | `/functions/v1/queue-enqueue` |
| Get queue status | Engine | `/functions/v1/queue-status` |
| Query ledger | Engine | Direct table query via client |
| Query quests | Engine | Direct table query via client |
