import { createClient, SupabaseClient } from '@supabase/supabase-js';
import * as SecureStore from 'expo-secure-store';
import { Platform } from 'react-native';

/**
 * Supabase Client Configuration for Gatekeeper Mobile App
 *
 * Uses SecureStore for token persistence on mobile (Keychain/Keystore)
 */

// Gatekeeper project credentials
const gatekeeperUrl = process.env.EXPO_PUBLIC_GATEKEEPER_URL || '';
const gatekeeperPublishableKey = process.env.EXPO_PUBLIC_GATEKEEPER_PUBLISHABLE_KEY || '';

// Custom storage adapter using SecureStore for mobile
const SecureStoreAdapter = {
  getItem: async (key: string): Promise<string | null> => {
    if (Platform.OS === 'web') {
      return localStorage.getItem(key);
    }
    return await SecureStore.getItemAsync(key);
  },
  setItem: async (key: string, value: string): Promise<void> => {
    if (Platform.OS === 'web') {
      localStorage.setItem(key, value);
      return;
    }
    await SecureStore.setItemAsync(key, value);
  },
  removeItem: async (key: string): Promise<void> => {
    if (Platform.OS === 'web') {
      localStorage.removeItem(key);
      return;
    }
    await SecureStore.deleteItemAsync(key);
  },
};

/**
 * Gatekeeper Supabase client
 * Uses SecureStore for secure token storage on mobile
 */
export const supabase: SupabaseClient = createClient(
  gatekeeperUrl,
  gatekeeperPublishableKey,
  {
    auth: {
      storage: SecureStoreAdapter,
      autoRefreshToken: true,
      persistSession: true,
      detectSessionInUrl: false, // Disabled for mobile - we handle deep links manually
    },
  }
);

export default supabase;
