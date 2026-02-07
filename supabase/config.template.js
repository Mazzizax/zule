/**
 * XENON CONFIGURATION - DUAL PROJECT ARCHITECTURE
 *
 * This configuration file supports the privacy-preserving split architecture:
 * - GATEKEEPER: Handles authentication, knows user_id, issues blind tokens
 * - ENGINE: Handles data processing, only knows ghost_id + blind tokens
 *
 * Copy this file to config.js and fill in the actual values.
 */

const CONFIG = {
  // ============================================================================
  // GATEKEEPER PROJECT (Authentication & Identity)
  // ============================================================================
  // This is the NEW Supabase project that handles:
  // - User authentication (login, signup, password reset)
  // - Blind token issuance
  // - User profiles and billing
  // - Passkey/WebAuthn credentials

  ZULE_URL: 'https://YOUR_GATEKEEPER_PROJECT_REF.supabase.co',
  GATEKEEPER_ANON_KEY: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.YOUR_GATEKEEPER_ANON_KEY...',

  // ============================================================================
  // ENGINE PROJECT (Data Processing)
  // ============================================================================
  // This is your EXISTING Supabase project that handles:
  // - Event queue processing
  // - Cosmic ledger entries
  // - Quest chains and achievements
  // - All data that uses ghost_id (NEVER user_id)

  ENGINE_URL: 'https://YOUR_ENGINE_PROJECT_REF.supabase.co',
  ENGINE_ANON_KEY: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.YOUR_ENGINE_ANON_KEY...',

  // ============================================================================
  // LEGACY ALIASES (for backward compatibility during transition)
  // ============================================================================
  // These will be removed after full migration

  get SUPABASE_URL() {
    console.warn('[DEPRECATED] Use CONFIG.ENGINE_URL instead of CONFIG.SUPABASE_URL');
    return this.ENGINE_URL;
  },

  get SUPABASE_KEY() {
    console.warn('[DEPRECATED] Use CONFIG.ENGINE_ANON_KEY instead of CONFIG.SUPABASE_KEY');
    return this.ENGINE_ANON_KEY;
  },

  // ============================================================================
  // FEATURE FLAGS
  // ============================================================================

  FEATURES: {
    // Enable the new blind token auth flow
    USE_BLIND_TOKENS: true,

    // Enable offline queue (IndexedDB)
    OFFLINE_QUEUE: true,

    // Enable debug logging
    DEBUG: false,
  },

  // ============================================================================
  // TOKEN CONFIGURATION
  // ============================================================================

  TOKEN: {
    // How many minutes before expiry to refresh the blind token
    REFRESH_BUFFER_MINUTES: 5,

    // Maximum retries for token refresh
    MAX_REFRESH_RETRIES: 3,
  },
};

// Freeze to prevent accidental modification
Object.freeze(CONFIG);
Object.freeze(CONFIG.FEATURES);
Object.freeze(CONFIG.TOKEN);

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
  module.exports = CONFIG;
}
