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
    },
  }
);

export default supabase;
