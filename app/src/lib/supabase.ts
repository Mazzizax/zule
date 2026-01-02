import { createClient, SupabaseClient } from '@supabase/supabase-js';

/**
 * Supabase Client Configuration for Gatekeeper Test App
 *
 * This test app connects to the Gatekeeper Supabase project
 * for authentication testing purposes.
 */

// Gatekeeper project credentials (from environment)
const gatekeeperUrl = import.meta.env.VITE_GATEKEEPER_URL;
const gatekeeperAnonKey = import.meta.env.VITE_GATEKEEPER_ANON_KEY;

if (!gatekeeperUrl || !gatekeeperAnonKey) {
  console.warn(
    'Gatekeeper configuration missing. Create .env file with VITE_GATEKEEPER_URL and VITE_GATEKEEPER_ANON_KEY'
  );
}

/**
 * Gatekeeper Supabase client
 * Used for: Authentication, user management
 */
export const supabase: SupabaseClient = createClient(
  gatekeeperUrl || '',
  gatekeeperAnonKey || '',
  {
    auth: {
      autoRefreshToken: true,
      persistSession: true,
      detectSessionInUrl: true,
    },
  }
);

export default supabase;
