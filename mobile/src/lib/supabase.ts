import { createClient, SupabaseClient } from '@supabase/supabase-js';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { Platform } from 'react-native';

/**
 * Supabase Client Configuration for Zule Mobile App
 *
 * Uses AsyncStorage for session persistence on mobile.
 * Note: ghost_secret is stored separately in SecureStore for maximum security.
 */

// Zule project credentials
const zuleUrl = process.env.EXPO_PUBLIC_ZULE_URL || '';
const gatekeeperPublishableKey = process.env.EXPO_PUBLIC_ZULE_PUBLISHABLE_KEY || '';

/**
 * Zule Supabase client
 * Uses AsyncStorage for token persistence on mobile.
 */
export const supabase: SupabaseClient = createClient(
  zuleUrl,
  gatekeeperPublishableKey,
  {
    auth: {
      storage: AsyncStorage,
      autoRefreshToken: true,
      persistSession: true,
      detectSessionInUrl: false, // Disabled for mobile - we handle deep links manually
    },
  }
);

export default supabase;
