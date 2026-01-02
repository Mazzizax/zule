/**
 * Blind Token Manager for React Native
 *
 * Handles obtaining and managing anonymous blind tokens from the Gatekeeper.
 * These tokens are used to authenticate with the Engine without revealing user_id.
 *
 * Privacy guarantees:
 * - Token contains NO user identifying information
 * - Token is signed by shared secret known to Gatekeeper and Engine
 * - Engine can verify token authenticity without knowing who the user is
 */

import AsyncStorage from '@react-native-async-storage/async-storage';
import { gatekeeperClient, URLS } from './supabase';

// Storage keys
const STORAGE_KEYS = {
  BLIND_TOKEN: 'xenon_blind_token',
  TOKEN_EXPIRY: 'xenon_token_expiry',
  TOKEN_TIER: 'xenon_token_tier',
} as const;

// Configuration
const CONFIG = {
  // Refresh token this many minutes before expiry
  REFRESH_BUFFER_MINUTES: 5,
  // Maximum retry attempts
  MAX_RETRIES: 3,
  // Retry delay in ms (doubles each attempt)
  RETRY_DELAY_MS: 1000,
};

export interface BlindTokenData {
  token: string;
  expiresAt: number; // Unix timestamp in ms
  tier: string;
}

export interface BlindTokenResult {
  success: boolean;
  data?: BlindTokenData;
  error?: string;
  retryAfter?: number; // Seconds until rate limit resets
}

class BlindTokenManager {
  private token: string | null = null;
  private expiresAt: number | null = null;
  private tier: string | null = null;
  private refreshPromise: Promise<BlindTokenResult> | null = null;

  /**
   * Initialize manager from stored token
   */
  async initialize(): Promise<void> {
    try {
      const [token, expiry, tier] = await Promise.all([
        AsyncStorage.getItem(STORAGE_KEYS.BLIND_TOKEN),
        AsyncStorage.getItem(STORAGE_KEYS.TOKEN_EXPIRY),
        AsyncStorage.getItem(STORAGE_KEYS.TOKEN_TIER),
      ]);

      if (token && expiry) {
        this.token = token;
        this.expiresAt = parseInt(expiry, 10);
        this.tier = tier;
      }
    } catch (e) {
      console.warn('[BlindToken] Failed to load stored token:', e);
    }
  }

  /**
   * Check if current token is valid (not expired, with buffer)
   */
  isValid(): boolean {
    if (!this.token || !this.expiresAt) return false;
    const bufferMs = CONFIG.REFRESH_BUFFER_MINUTES * 60 * 1000;
    return Date.now() < (this.expiresAt - bufferMs);
  }

  /**
   * Get current token, refreshing if necessary
   */
  async getToken(forceRefresh = false): Promise<BlindTokenResult> {
    // Return valid cached token
    if (!forceRefresh && this.isValid()) {
      return {
        success: true,
        data: {
          token: this.token!,
          expiresAt: this.expiresAt!,
          tier: this.tier || 'free',
        },
      };
    }

    // If already refreshing, wait for that request
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    // Start refresh
    this.refreshPromise = this.refreshToken();
    const result = await this.refreshPromise;
    this.refreshPromise = null;

    return result;
  }

  /**
   * Refresh the blind token from Gatekeeper
   */
  private async refreshToken(attempt = 1): Promise<BlindTokenResult> {
    try {
      // Get current session
      const { data: { session } } = await gatekeeperClient.auth.getSession();

      if (!session?.access_token) {
        return { success: false, error: 'No active session' };
      }

      // Request new blind token from Gatekeeper
      const response = await fetch(`${URLS.GATEKEEPER}/functions/v1/blind-token-issue`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${session.access_token}`,
          'Content-Type': 'application/json',
        },
      });

      // Handle rate limiting
      if (response.status === 429) {
        const data = await response.json().catch(() => ({}));
        return {
          success: false,
          error: 'Rate limit exceeded',
          retryAfter: data.retry_after || 60,
        };
      }

      // Handle other errors
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        const error = data.error || `HTTP ${response.status}`;

        // Retry on server errors
        if (response.status >= 500 && attempt < CONFIG.MAX_RETRIES) {
          const delay = CONFIG.RETRY_DELAY_MS * Math.pow(2, attempt - 1);
          await new Promise(r => setTimeout(r, delay));
          return this.refreshToken(attempt + 1);
        }

        return { success: false, error };
      }

      // Parse response
      const data = await response.json();
      const tokenData: BlindTokenData = {
        token: data.blind_token,
        expiresAt: data.expires_at * 1000, // Convert to ms
        tier: data.tier,
      };

      // Update state
      this.token = tokenData.token;
      this.expiresAt = tokenData.expiresAt;
      this.tier = tokenData.tier;

      // Persist to storage
      await Promise.all([
        AsyncStorage.setItem(STORAGE_KEYS.BLIND_TOKEN, tokenData.token),
        AsyncStorage.setItem(STORAGE_KEYS.TOKEN_EXPIRY, tokenData.expiresAt.toString()),
        AsyncStorage.setItem(STORAGE_KEYS.TOKEN_TIER, tokenData.tier),
      ]);

      console.log('[BlindToken] Token refreshed, tier:', tokenData.tier);

      return { success: true, data: tokenData };

    } catch (e) {
      const error = e instanceof Error ? e.message : 'Unknown error';
      console.error('[BlindToken] Refresh failed:', error);

      // Retry on network errors
      if (attempt < CONFIG.MAX_RETRIES) {
        const delay = CONFIG.RETRY_DELAY_MS * Math.pow(2, attempt - 1);
        await new Promise(r => setTimeout(r, delay));
        return this.refreshToken(attempt + 1);
      }

      return { success: false, error };
    }
  }

  /**
   * Revoke all tokens for this user (e.g., on logout)
   */
  async revokeAll(): Promise<boolean> {
    try {
      const { data: { session } } = await gatekeeperClient.auth.getSession();

      if (!session?.access_token) {
        this.clear();
        return true;
      }

      const response = await fetch(`${URLS.GATEKEEPER}/functions/v1/revoke-token`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${session.access_token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ revoke_all: true }),
      });

      this.clear();
      return response.ok;

    } catch (e) {
      console.error('[BlindToken] Revoke failed:', e);
      this.clear();
      return false;
    }
  }

  /**
   * Clear stored token
   */
  async clear(): Promise<void> {
    this.token = null;
    this.expiresAt = null;
    this.tier = null;

    await Promise.all([
      AsyncStorage.removeItem(STORAGE_KEYS.BLIND_TOKEN),
      AsyncStorage.removeItem(STORAGE_KEYS.TOKEN_EXPIRY),
      AsyncStorage.removeItem(STORAGE_KEYS.TOKEN_TIER),
    ]).catch(() => {});
  }

  /**
   * Get current tier (if token exists)
   */
  getTier(): string | null {
    return this.tier;
  }
}

// Export singleton instance
export const blindTokenManager = new BlindTokenManager();

// Initialize on module load
blindTokenManager.initialize().catch(console.error);
