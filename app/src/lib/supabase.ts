import { createClient, SupabaseClient } from '@supabase/supabase-js';

/**
 * Supabase Client Configuration for Gatekeeper Test App
 *
 * This test app connects to the Gatekeeper Supabase project
 * for authentication testing purposes.
 */

// Gatekeeper project credentials (from environment)
const gatekeeperUrl = import.meta.env.GATEKEEPER_URL;
const gatekeeperPublishableKey = import.meta.env.GATEKEEPER_PUBLISHABLE_KEY;

if (!gatekeeperUrl || !gatekeeperPublishableKey) {
  console.warn(
    'Gatekeeper configuration missing. Create .env file with GATEKEEPER_URL and GATEKEEPER_PUBLISHABLE_KEY'
  );
}

/**
 * Gatekeeper Supabase client
 * Used for: Authentication, user management
 */
export const supabase: SupabaseClient = createClient(
  gatekeeperUrl || '',
  gatekeeperPublishableKey || '',
  {
    auth: {
      autoRefreshToken: true,
      persistSession: true,
      detectSessionInUrl: true,
    },
  }
);

export default supabase;
