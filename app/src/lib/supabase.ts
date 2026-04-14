import { createClient, SupabaseClient } from '@supabase/supabase-js';

/**
 * Supabase Client Configuration for Zule Test App
 *
 * This test app connects to the Zule Supabase project
 * for authentication testing purposes.
 */

// Zule project credentials (from environment)
const zuleUrl = import.meta.env.ZULE_URL;
const zulePublishableKey = import.meta.env.ZULE_PUBLISHABLE_KEY;

if (!zuleUrl || !zulePublishableKey) {
  console.warn(
    'Zule configuration missing. Create .env file with ZULE_URL and ZULE_PUBLISHABLE_KEY'
  );
}

// Purge any legacy localStorage session tokens.
// Supabase previously stored auth tokens in localStorage which persisted
// across tabs and browser restarts. We now use sessionStorage for per-tab
// isolation. Without this cleanup, Supabase internals may still find and
// use the old localStorage tokens.
(() => {
  const keysToRemove: string[] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (key && (key.startsWith('sb-') || key === 'zule_active_session')) {
      keysToRemove.push(key);
    }
  }
  keysToRemove.forEach((key) => localStorage.removeItem(key));
})();

/**
 * Zule Supabase client
 * Used for: Authentication, user management
 */
export const supabase: SupabaseClient = createClient(
  zuleUrl || '',
  zulePublishableKey || '',
  {
    auth: {
      autoRefreshToken: true,
      persistSession: true,
      detectSessionInUrl: true,
      storage: sessionStorage, // Per-tab sessions — new tab = login required
    },
  }
);

export default supabase;
