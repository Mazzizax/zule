-- ============================================================================
-- GATEKEEPER DATABASE SCHEMA
-- ============================================================================
--
-- GATEKEEPER: A Dedicated Secure User Authentication Service
--
-- Core Guarantees:
-- ┌─────────────────────────────────────────────────────────────────────────┐
-- │  "I know WHO you are. I will NEVER know WHAT you do."                   │
-- │                                                                         │
-- │  - Authenticates user identity                                          │
-- │  - Issues anonymous, app-specific blind tokens                          │
-- │  - Cannot see inside any connected application                          │
-- │  - Connected applications cannot see each other's users                 │
-- │  - Physical token holder controls their identity absolutely             │
-- └─────────────────────────────────────────────────────────────────────────┘
--
-- Architecture:
-- - This database knows user_id but NEVER knows ghost_id
-- - All ghost_id derivation happens client-side only (or on physical token)
-- - Each registered app receives its own blind token format
-- - Tokens contain NO user-identifying information
--
-- Deploy this to the NEW Gatekeeper Supabase project
-- ============================================================================

-- ============================================================================
-- USER PROFILES (extends auth.users)
-- ============================================================================
CREATE TABLE IF NOT EXISTS user_profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,

    -- Display info
    display_name TEXT,
    avatar_url TEXT,
    timezone TEXT DEFAULT 'UTC',
    locale TEXT DEFAULT 'en-US',

    -- Subscription/tier info (used for blind token claims)
    subscription_tier TEXT DEFAULT 'free'
        CHECK (subscription_tier IN ('free', 'standard', 'premium', 'enterprise')),
    subscription_status TEXT DEFAULT 'active'
        CHECK (subscription_status IN ('active', 'past_due', 'canceled', 'trialing')),
    subscription_expires_at TIMESTAMPTZ,

    -- Feature flags (tier-specific capabilities)
    features JSONB DEFAULT '{
        "max_events_per_day": 50,
        "max_queue_depth": 10,
        "priority_processing": false,
        "advanced_analytics": false,
        "api_access": false
    }'::jsonb,

    -- Billing (Stripe integration)
    stripe_customer_id TEXT UNIQUE,
    stripe_subscription_id TEXT,

    -- Metadata
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ DEFAULT NOW(),
    last_token_issued_at TIMESTAMPTZ,

    -- GDPR/Privacy compliance
    data_retention_consent BOOLEAN DEFAULT TRUE,
    marketing_consent BOOLEAN DEFAULT FALSE,
    privacy_policy_accepted_at TIMESTAMPTZ,
    privacy_policy_version TEXT,
    terms_accepted_at TIMESTAMPTZ,
    terms_version TEXT,

    -- Account status
    is_suspended BOOLEAN DEFAULT FALSE,
    suspension_reason TEXT,
    suspended_at TIMESTAMPTZ
);

-- ============================================================================
-- AUDIT LOG (Security & Compliance)
-- ============================================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,

    -- Action details
    action TEXT NOT NULL,
    action_category TEXT NOT NULL CHECK (action_category IN (
        'auth',           -- Login, logout, password change
        'token',          -- Blind token issuance
        'profile',        -- Profile updates
        'subscription',   -- Billing changes
        'security',       -- Suspicious activity
        'admin'           -- Admin actions
    )),

    -- Request context
    ip_address INET,
    user_agent TEXT,
    request_id TEXT,

    -- Additional data
    metadata JSONB DEFAULT '{}',

    -- Outcome
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,

    -- Timestamp
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- RATE LIMITING
-- ============================================================================
CREATE TABLE IF NOT EXISTS rate_limits (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    identifier TEXT NOT NULL,      -- IP address, user_id, or composite key
    action TEXT NOT NULL,          -- 'blind_token', 'login', 'signup', etc.
    count INTEGER DEFAULT 1,
    window_start TIMESTAMPTZ DEFAULT date_trunc('minute', NOW()),

    UNIQUE(identifier, action, window_start)
);

-- ============================================================================
-- BLIND TOKEN LOG (Security Monitoring)
-- ============================================================================
-- NOTE: This tracks token issuance but does NOT store ghost_id
-- Used for: revocation, security monitoring, abuse detection
CREATE TABLE IF NOT EXISTS blind_token_log (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,

    -- Token identification (for revocation)
    token_nonce TEXT NOT NULL UNIQUE,  -- The nonce from the token payload
    token_hash TEXT NOT NULL,          -- SHA256 of full token for verification

    -- Validity
    issued_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,

    -- Revocation
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,

    -- Request context
    ip_address INET,
    user_agent TEXT,

    -- Usage tracking
    tier_at_issuance TEXT NOT NULL
);

-- ============================================================================
-- PASSKEY CREDENTIALS (WebAuthn)
-- ============================================================================
-- Stores passkey/biometric credentials for passwordless auth
CREATE TABLE IF NOT EXISTS passkey_credentials (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,

    -- WebAuthn credential data
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    counter INTEGER DEFAULT 0,

    -- Device info
    device_name TEXT,
    device_type TEXT CHECK (device_type IN ('platform', 'cross-platform')),

    -- Metadata
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,

    -- Transports (for credential hints)
    transports TEXT[] DEFAULT '{}'
);

-- ============================================================================
-- DEVICE LINKS (QR Code Device Pairing)
-- ============================================================================
-- Tracks linked devices for the same user
CREATE TABLE IF NOT EXISTS device_links (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,

    -- Device identification
    device_id TEXT NOT NULL,
    device_name TEXT,
    device_type TEXT,  -- 'mobile', 'desktop', 'tablet'

    -- Link status
    is_active BOOLEAN DEFAULT TRUE,
    linked_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ DEFAULT NOW(),

    -- Security
    link_method TEXT CHECK (link_method IN ('qr_code', 'passkey', 'rfid', 'nfc', 'manual')),

    UNIQUE(user_id, device_id)
);

-- ============================================================================
-- PHYSICAL TOKENS (RFID/NFC Hardware Authentication)
-- ============================================================================
-- Stores registered physical authentication tokens
-- The ghost_secret lives ON THE PHYSICAL TOKEN, not here
-- This table only tracks token registration and status
CREATE TABLE IF NOT EXISTS physical_tokens (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,

    -- Token identification (public identifier, NOT the secret)
    token_serial TEXT NOT NULL UNIQUE,        -- Printed on token, e.g., "XNT-00001-2024"
    token_type TEXT NOT NULL CHECK (token_type IN ('rfid', 'nfc', 'hybrid')),

    -- Token metadata
    token_name TEXT,                          -- User-friendly name, e.g., "My Black Card"
    manufacturer TEXT,
    hardware_version TEXT,

    -- Cryptographic binding (does NOT contain ghost_secret)
    public_key TEXT,                          -- For challenge-response auth
    key_algorithm TEXT DEFAULT 'ECDSA-P256',  -- Signing algorithm

    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    is_primary BOOLEAN DEFAULT FALSE,         -- Primary token for this user
    activation_status TEXT DEFAULT 'pending' CHECK (
        activation_status IN ('pending', 'active', 'suspended', 'revoked', 'lost')
    ),

    -- Security events
    registered_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    last_auth_ip INET,
    failed_auth_count INTEGER DEFAULT 0,
    locked_until TIMESTAMPTZ,

    -- Revocation
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,
    replacement_token_id UUID REFERENCES physical_tokens(id),

    -- Audit
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- REGISTERED APPS (Third-Party Application Registry)
-- ============================================================================
-- Gatekeeper as a universal auth service - each app registers here
-- Each app gets its own blind token signing secret
-- Users get a DIFFERENT ghost_id for each app (privacy firewall)
CREATE TABLE IF NOT EXISTS registered_apps (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,

    -- App identification
    app_id TEXT NOT NULL UNIQUE,              -- Short identifier, e.g., "xenon-engine"
    app_name TEXT NOT NULL,                   -- Display name, e.g., "Xenon Totem Engine"
    app_description TEXT,

    -- App owner/developer
    owner_user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    owner_email TEXT NOT NULL,
    organization_name TEXT,

    -- Security credentials
    -- IMPORTANT: shared_secret is used for HMAC signing of blind tokens
    -- It is ONLY known to Gatekeeper and the registered app
    -- NEVER exposed to users or other apps
    shared_secret_hash TEXT NOT NULL,         -- Bcrypt hash of the secret (original given once at registration)
    api_key_hash TEXT NOT NULL,               -- Bcrypt hash of API key for server-to-server calls

    -- Token configuration
    token_expiry_seconds INTEGER DEFAULT 3600,-- How long blind tokens last
    token_version INTEGER DEFAULT 1,          -- For token format upgrades

    -- Callback/redirect URLs (for OAuth-style flows)
    callback_urls TEXT[] NOT NULL DEFAULT '{}',
    allowed_origins TEXT[] NOT NULL DEFAULT '{}',  -- CORS origins

    -- Rate limiting (per-app limits)
    rate_limit_tokens_per_hour INTEGER DEFAULT 1000,
    rate_limit_auth_per_minute INTEGER DEFAULT 60,

    -- App status
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,        -- Verified by Gatekeeper admin
    requires_user_consent BOOLEAN DEFAULT TRUE,  -- Show consent screen?

    -- Permissions/Scopes this app can request
    allowed_scopes TEXT[] DEFAULT ARRAY['basic'],
    -- Available: 'basic', 'profile', 'email', 'tier', 'devices'

    -- Statistics
    total_tokens_issued BIGINT DEFAULT 0,
    total_users_connected BIGINT DEFAULT 0,
    last_token_issued_at TIMESTAMPTZ,

    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    verified_at TIMESTAMPTZ,

    -- Suspension
    suspended_at TIMESTAMPTZ,
    suspension_reason TEXT
);

-- ============================================================================
-- USER APP CONNECTIONS (User-to-App Authorizations)
-- ============================================================================
-- Tracks which users have authorized which apps
-- This is the consent record - user explicitly allowed this app
CREATE TABLE IF NOT EXISTS user_app_connections (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    app_id UUID NOT NULL REFERENCES registered_apps(id) ON DELETE CASCADE,

    -- Authorization status
    is_active BOOLEAN DEFAULT TRUE,
    authorized_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,

    -- Granted scopes (subset of app's allowed_scopes)
    granted_scopes TEXT[] DEFAULT ARRAY['basic'],

    -- Revocation
    revoked_at TIMESTAMPTZ,
    revoked_by TEXT CHECK (revoked_by IN ('user', 'app', 'admin', 'system')),

    -- Statistics for this connection
    tokens_issued INTEGER DEFAULT 0,

    UNIQUE(user_id, app_id)
);

-- ============================================================================
-- APP TOKEN LOG (Per-App Token Tracking)
-- ============================================================================
-- Extends blind_token_log to track which app each token was issued for
-- Essential for per-app revocation and analytics
CREATE TABLE IF NOT EXISTS app_token_log (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    blind_token_log_id UUID REFERENCES blind_token_log(id) ON DELETE CASCADE,
    app_id UUID NOT NULL REFERENCES registered_apps(id) ON DELETE CASCADE,
    user_app_connection_id UUID REFERENCES user_app_connections(id) ON DELETE SET NULL,

    -- Token identification (for app-specific revocation)
    token_nonce TEXT NOT NULL,

    -- Issued timestamp
    issued_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(blind_token_log_id)
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- User profiles
CREATE INDEX IF NOT EXISTS idx_user_profiles_stripe ON user_profiles(stripe_customer_id)
    WHERE stripe_customer_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_user_profiles_tier ON user_profiles(subscription_tier);
CREATE INDEX IF NOT EXISTS idx_user_profiles_suspended ON user_profiles(is_suspended)
    WHERE is_suspended = TRUE;

-- Audit logs (time-series optimized)
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_time ON audit_logs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_category_time ON audit_logs(action_category, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_ip ON audit_logs(ip_address);

-- Rate limits
CREATE INDEX IF NOT EXISTS idx_rate_limits_lookup ON rate_limits(identifier, action, window_start);

-- Blind token log
CREATE INDEX IF NOT EXISTS idx_blind_token_user ON blind_token_log(user_id, issued_at DESC);
CREATE INDEX IF NOT EXISTS idx_blind_token_nonce ON blind_token_log(token_nonce);
CREATE INDEX IF NOT EXISTS idx_blind_token_active ON blind_token_log(expires_at)
    WHERE revoked_at IS NULL;

-- Passkey credentials
CREATE INDEX IF NOT EXISTS idx_passkey_user ON passkey_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_passkey_credential_id ON passkey_credentials(credential_id);

-- Device links
CREATE INDEX IF NOT EXISTS idx_device_links_user ON device_links(user_id)
    WHERE is_active = TRUE;

-- Physical tokens
CREATE INDEX IF NOT EXISTS idx_physical_tokens_user ON physical_tokens(user_id)
    WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_physical_tokens_serial ON physical_tokens(token_serial);
CREATE INDEX IF NOT EXISTS idx_physical_tokens_status ON physical_tokens(activation_status)
    WHERE activation_status != 'revoked';

-- Registered apps
CREATE INDEX IF NOT EXISTS idx_registered_apps_app_id ON registered_apps(app_id);
CREATE INDEX IF NOT EXISTS idx_registered_apps_owner ON registered_apps(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_registered_apps_active ON registered_apps(is_active)
    WHERE is_active = TRUE;

-- User app connections
CREATE INDEX IF NOT EXISTS idx_user_app_connections_user ON user_app_connections(user_id)
    WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_user_app_connections_app ON user_app_connections(app_id)
    WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_user_app_connections_lookup ON user_app_connections(user_id, app_id);

-- App token log
CREATE INDEX IF NOT EXISTS idx_app_token_log_app ON app_token_log(app_id, issued_at DESC);
CREATE INDEX IF NOT EXISTS idx_app_token_log_nonce ON app_token_log(token_nonce);

-- ============================================================================
-- ROW LEVEL SECURITY
-- ============================================================================

ALTER TABLE user_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE rate_limits ENABLE ROW LEVEL SECURITY;
ALTER TABLE blind_token_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE passkey_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_links ENABLE ROW LEVEL SECURITY;

-- User Profiles: Users can read/update their own
CREATE POLICY "Users can view own profile" ON user_profiles
    FOR SELECT USING (auth.uid() = id);

CREATE POLICY "Users can update own profile" ON user_profiles
    FOR UPDATE USING (auth.uid() = id)
    WITH CHECK (
        -- Prevent users from changing their own tier/billing fields
        subscription_tier = (SELECT subscription_tier FROM user_profiles WHERE id = auth.uid()) AND
        subscription_status = (SELECT subscription_status FROM user_profiles WHERE id = auth.uid()) AND
        stripe_customer_id = (SELECT stripe_customer_id FROM user_profiles WHERE id = auth.uid())
    );

-- Passkey Credentials: Users can manage their own
CREATE POLICY "Users can view own passkeys" ON passkey_credentials
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own passkeys" ON passkey_credentials
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can delete own passkeys" ON passkey_credentials
    FOR DELETE USING (auth.uid() = user_id);

-- Device Links: Users can view/manage their own
CREATE POLICY "Users can view own devices" ON device_links
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can manage own devices" ON device_links
    FOR ALL USING (auth.uid() = user_id);

-- Service role has full access to all tables
CREATE POLICY "Service role full access - profiles" ON user_profiles
    FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "Service role full access - audit" ON audit_logs
    FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "Service role full access - rate_limits" ON rate_limits
    FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "Service role full access - tokens" ON blind_token_log
    FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "Service role full access - passkeys" ON passkey_credentials
    FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "Service role full access - devices" ON device_links
    FOR ALL USING (auth.role() = 'service_role');

-- Physical Tokens: Users can view/manage their own
ALTER TABLE physical_tokens ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own physical tokens" ON physical_tokens
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can update own physical tokens" ON physical_tokens
    FOR UPDATE USING (auth.uid() = user_id)
    WITH CHECK (
        -- Users can update name, but not security fields
        auth.uid() = user_id
    );

CREATE POLICY "Service role full access - physical_tokens" ON physical_tokens
    FOR ALL USING (auth.role() = 'service_role');

-- Registered Apps: Public read for active apps, owner can manage
ALTER TABLE registered_apps ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Anyone can view active verified apps" ON registered_apps
    FOR SELECT USING (is_active = TRUE AND is_verified = TRUE);

CREATE POLICY "App owners can view own apps" ON registered_apps
    FOR SELECT USING (auth.uid() = owner_user_id);

CREATE POLICY "App owners can update own apps" ON registered_apps
    FOR UPDATE USING (auth.uid() = owner_user_id)
    WITH CHECK (
        -- Owners cannot change verification status
        is_verified = (SELECT is_verified FROM registered_apps WHERE id = registered_apps.id)
    );

CREATE POLICY "Service role full access - registered_apps" ON registered_apps
    FOR ALL USING (auth.role() = 'service_role');

-- User App Connections: Users can view/manage their own connections
ALTER TABLE user_app_connections ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own app connections" ON user_app_connections
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can revoke own app connections" ON user_app_connections
    FOR UPDATE USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Service role full access - user_app_connections" ON user_app_connections
    FOR ALL USING (auth.role() = 'service_role');

-- App Token Log: Only service role (internal tracking)
ALTER TABLE app_token_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role full access - app_token_log" ON app_token_log
    FOR ALL USING (auth.role() = 'service_role');

-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Auto-create profile on user signup
CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    INSERT INTO user_profiles (id, created_at)
    VALUES (NEW.id, NOW())
    ON CONFLICT (id) DO NOTHING;

    -- Log the signup
    INSERT INTO audit_logs (user_id, action, action_category, metadata)
    VALUES (NEW.id, 'user_created', 'auth', jsonb_build_object(
        'email', NEW.email,
        'provider', NEW.raw_app_meta_data->>'provider'
    ));

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW
    EXECUTE FUNCTION handle_new_user();

-- Update timestamps
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS user_profiles_updated_at ON user_profiles;
CREATE TRIGGER user_profiles_updated_at
    BEFORE UPDATE ON user_profiles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- FUNCTIONS
-- ============================================================================

-- Rate limiting check
CREATE OR REPLACE FUNCTION check_rate_limit(
    p_identifier TEXT,
    p_action TEXT,
    p_max_requests INTEGER,
    p_window_seconds INTEGER
)
RETURNS TABLE (
    allowed BOOLEAN,
    current_count INTEGER,
    reset_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_window_start TIMESTAMPTZ;
    v_current_count INTEGER;
BEGIN
    v_window_start := NOW() - (p_window_seconds || ' seconds')::INTERVAL;

    -- Get current count within window
    SELECT COALESCE(SUM(count), 0)::INTEGER INTO v_current_count
    FROM rate_limits
    WHERE identifier = p_identifier
      AND action = p_action
      AND window_start > v_window_start;

    IF v_current_count >= p_max_requests THEN
        -- Rate limited
        RETURN QUERY SELECT
            FALSE,
            v_current_count,
            v_window_start + (p_window_seconds || ' seconds')::INTERVAL;
        RETURN;
    END IF;

    -- Increment counter
    INSERT INTO rate_limits (identifier, action, count, window_start)
    VALUES (p_identifier, p_action, 1, date_trunc('minute', NOW()))
    ON CONFLICT (identifier, action, window_start)
    DO UPDATE SET count = rate_limits.count + 1;

    RETURN QUERY SELECT
        TRUE,
        v_current_count + 1,
        NOW() + (p_window_seconds || ' seconds')::INTERVAL;
END;
$$;

-- Log audit event
CREATE OR REPLACE FUNCTION log_audit_event(
    p_user_id UUID,
    p_action TEXT,
    p_category TEXT,
    p_ip_address INET DEFAULT NULL,
    p_user_agent TEXT DEFAULT NULL,
    p_metadata JSONB DEFAULT '{}'
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_id UUID;
BEGIN
    INSERT INTO audit_logs (user_id, action, action_category, ip_address, user_agent, metadata)
    VALUES (p_user_id, p_action, p_category, p_ip_address, p_user_agent, p_metadata)
    RETURNING id INTO v_id;

    RETURN v_id;
END;
$$;

-- Log blind token issuance
CREATE OR REPLACE FUNCTION log_token_issuance(
    p_user_id UUID,
    p_token_nonce TEXT,
    p_token_hash TEXT,
    p_expires_at TIMESTAMPTZ,
    p_tier TEXT,
    p_ip_address INET DEFAULT NULL,
    p_user_agent TEXT DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_id UUID;
BEGIN
    -- Log the token
    INSERT INTO blind_token_log (
        user_id, token_nonce, token_hash, expires_at,
        tier_at_issuance, ip_address, user_agent
    )
    VALUES (
        p_user_id, p_token_nonce, p_token_hash, p_expires_at,
        p_tier, p_ip_address, p_user_agent
    )
    RETURNING id INTO v_id;

    -- Update last token issued timestamp
    UPDATE user_profiles
    SET last_token_issued_at = NOW()
    WHERE id = p_user_id;

    RETURN v_id;
END;
$$;

-- Revoke a blind token
CREATE OR REPLACE FUNCTION revoke_blind_token(
    p_token_nonce TEXT,
    p_reason TEXT DEFAULT 'manual_revocation'
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_updated BOOLEAN;
BEGIN
    UPDATE blind_token_log
    SET revoked_at = NOW(),
        revocation_reason = p_reason
    WHERE token_nonce = p_token_nonce
      AND revoked_at IS NULL;

    GET DIAGNOSTICS v_updated = ROW_COUNT;
    RETURN v_updated > 0;
END;
$$;

-- Check if token is revoked
CREATE OR REPLACE FUNCTION is_token_revoked(p_token_nonce TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_revoked BOOLEAN;
BEGIN
    SELECT revoked_at IS NOT NULL INTO v_revoked
    FROM blind_token_log
    WHERE token_nonce = p_token_nonce;

    RETURN COALESCE(v_revoked, FALSE);
END;
$$;

-- Get user tier and features
CREATE OR REPLACE FUNCTION get_user_tier_info(p_user_id UUID)
RETURNS TABLE (
    tier TEXT,
    status TEXT,
    features JSONB,
    is_suspended BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    RETURN QUERY
    SELECT
        up.subscription_tier,
        up.subscription_status,
        up.features,
        up.is_suspended
    FROM user_profiles up
    WHERE up.id = p_user_id;
END;
$$;

-- ============================================================================
-- MULTI-APP FUNCTIONS
-- ============================================================================

-- Register a new application
CREATE OR REPLACE FUNCTION register_app(
    p_app_id TEXT,
    p_app_name TEXT,
    p_owner_email TEXT,
    p_callback_urls TEXT[],
    p_allowed_origins TEXT[] DEFAULT '{}',
    p_owner_user_id UUID DEFAULT NULL,
    p_organization_name TEXT DEFAULT NULL,
    p_description TEXT DEFAULT NULL
)
RETURNS TABLE (
    id UUID,
    app_id TEXT,
    shared_secret TEXT,  -- Returned ONCE at registration, never again
    api_key TEXT         -- Returned ONCE at registration, never again
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_id UUID;
    v_shared_secret TEXT;
    v_api_key TEXT;
BEGIN
    -- Generate cryptographically secure secrets
    v_shared_secret := encode(gen_random_bytes(32), 'base64');
    v_api_key := 'gk_' || encode(gen_random_bytes(24), 'hex');

    -- Insert the app
    INSERT INTO registered_apps (
        app_id, app_name, app_description,
        owner_user_id, owner_email, organization_name,
        shared_secret_hash, api_key_hash,
        callback_urls, allowed_origins
    )
    VALUES (
        p_app_id, p_app_name, p_description,
        p_owner_user_id, p_owner_email, p_organization_name,
        crypt(v_shared_secret, gen_salt('bf')),
        crypt(v_api_key, gen_salt('bf')),
        p_callback_urls, p_allowed_origins
    )
    RETURNING registered_apps.id INTO v_id;

    -- Log the registration
    PERFORM log_audit_event(
        p_owner_user_id,
        'app_registered',
        'admin',
        NULL,
        NULL,
        jsonb_build_object('app_id', p_app_id, 'app_name', p_app_name)
    );

    RETURN QUERY SELECT v_id, p_app_id, v_shared_secret, v_api_key;
END;
$$;

-- Verify app API key (for server-to-server calls)
CREATE OR REPLACE FUNCTION verify_app_api_key(
    p_app_id TEXT,
    p_api_key TEXT
)
RETURNS TABLE (
    valid BOOLEAN,
    app_uuid UUID,
    app_name TEXT,
    is_active BOOLEAN,
    shared_secret_hash TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    RETURN QUERY
    SELECT
        ra.api_key_hash = crypt(p_api_key, ra.api_key_hash) AS valid,
        ra.id AS app_uuid,
        ra.app_name,
        ra.is_active,
        ra.shared_secret_hash
    FROM registered_apps ra
    WHERE ra.app_id = p_app_id;
END;
$$;

-- Get app configuration for token issuance
CREATE OR REPLACE FUNCTION get_app_config(p_app_id TEXT)
RETURNS TABLE (
    id UUID,
    app_name TEXT,
    is_active BOOLEAN,
    is_verified BOOLEAN,
    token_expiry_seconds INTEGER,
    token_version INTEGER,
    shared_secret_hash TEXT,
    rate_limit_tokens_per_hour INTEGER,
    allowed_scopes TEXT[]
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    RETURN QUERY
    SELECT
        ra.id,
        ra.app_name,
        ra.is_active,
        ra.is_verified,
        ra.token_expiry_seconds,
        ra.token_version,
        ra.shared_secret_hash,
        ra.rate_limit_tokens_per_hour,
        ra.allowed_scopes
    FROM registered_apps ra
    WHERE ra.app_id = p_app_id;
END;
$$;

-- Create or update user-app connection (consent)
CREATE OR REPLACE FUNCTION authorize_app_connection(
    p_user_id UUID,
    p_app_id TEXT,
    p_granted_scopes TEXT[] DEFAULT ARRAY['basic']
)
RETURNS TABLE (
    connection_id UUID,
    is_new BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_app_uuid UUID;
    v_connection_id UUID;
    v_is_new BOOLEAN;
BEGIN
    -- Get app UUID
    SELECT id INTO v_app_uuid FROM registered_apps WHERE app_id = p_app_id AND is_active = TRUE;
    IF v_app_uuid IS NULL THEN
        RAISE EXCEPTION 'App not found or inactive: %', p_app_id;
    END IF;

    -- Check if connection exists
    SELECT uac.id INTO v_connection_id
    FROM user_app_connections uac
    WHERE uac.user_id = p_user_id AND uac.app_id = v_app_uuid;

    IF v_connection_id IS NOT NULL THEN
        -- Reactivate if revoked
        UPDATE user_app_connections
        SET is_active = TRUE,
            granted_scopes = p_granted_scopes,
            revoked_at = NULL,
            revoked_by = NULL,
            last_used_at = NOW()
        WHERE id = v_connection_id;
        v_is_new := FALSE;
    ELSE
        -- Create new connection
        INSERT INTO user_app_connections (user_id, app_id, granted_scopes)
        VALUES (p_user_id, v_app_uuid, p_granted_scopes)
        RETURNING id INTO v_connection_id;
        v_is_new := TRUE;

        -- Update app stats
        UPDATE registered_apps
        SET total_users_connected = total_users_connected + 1
        WHERE id = v_app_uuid;
    END IF;

    -- Log the authorization
    PERFORM log_audit_event(
        p_user_id,
        CASE WHEN v_is_new THEN 'app_authorized' ELSE 'app_reauthorized' END,
        'auth',
        NULL,
        NULL,
        jsonb_build_object('app_id', p_app_id, 'scopes', p_granted_scopes)
    );

    RETURN QUERY SELECT v_connection_id, v_is_new;
END;
$$;

-- Revoke user-app connection
CREATE OR REPLACE FUNCTION revoke_app_connection(
    p_user_id UUID,
    p_app_id TEXT,
    p_revoked_by TEXT DEFAULT 'user'
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_app_uuid UUID;
    v_updated INTEGER;
BEGIN
    -- Get app UUID
    SELECT id INTO v_app_uuid FROM registered_apps WHERE app_id = p_app_id;
    IF v_app_uuid IS NULL THEN
        RETURN FALSE;
    END IF;

    -- Revoke the connection
    UPDATE user_app_connections
    SET is_active = FALSE,
        revoked_at = NOW(),
        revoked_by = p_revoked_by
    WHERE user_id = p_user_id AND app_id = v_app_uuid AND is_active = TRUE;

    GET DIAGNOSTICS v_updated = ROW_COUNT;

    IF v_updated > 0 THEN
        -- Log the revocation
        PERFORM log_audit_event(
            p_user_id,
            'app_revoked',
            'auth',
            NULL,
            NULL,
            jsonb_build_object('app_id', p_app_id, 'revoked_by', p_revoked_by)
        );
    END IF;

    RETURN v_updated > 0;
END;
$$;

-- Log token issuance for a specific app
CREATE OR REPLACE FUNCTION log_app_token_issuance(
    p_user_id UUID,
    p_app_id TEXT,
    p_token_nonce TEXT,
    p_token_hash TEXT,
    p_expires_at TIMESTAMPTZ,
    p_tier TEXT,
    p_ip_address INET DEFAULT NULL,
    p_user_agent TEXT DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_token_log_id UUID;
    v_app_uuid UUID;
    v_connection_id UUID;
BEGIN
    -- Get app UUID
    SELECT id INTO v_app_uuid FROM registered_apps WHERE app_id = p_app_id;

    -- Get connection ID
    SELECT uac.id INTO v_connection_id
    FROM user_app_connections uac
    WHERE uac.user_id = p_user_id AND uac.app_id = v_app_uuid AND uac.is_active = TRUE;

    -- Log to main token log
    INSERT INTO blind_token_log (
        user_id, token_nonce, token_hash, expires_at,
        tier_at_issuance, ip_address, user_agent
    )
    VALUES (
        p_user_id, p_token_nonce, p_token_hash, p_expires_at,
        p_tier, p_ip_address, p_user_agent
    )
    RETURNING id INTO v_token_log_id;

    -- Log to app-specific token log
    INSERT INTO app_token_log (
        blind_token_log_id, app_id, user_app_connection_id, token_nonce
    )
    VALUES (
        v_token_log_id, v_app_uuid, v_connection_id, p_token_nonce
    );

    -- Update statistics
    UPDATE user_profiles
    SET last_token_issued_at = NOW()
    WHERE id = p_user_id;

    UPDATE user_app_connections
    SET last_used_at = NOW(),
        tokens_issued = tokens_issued + 1
    WHERE id = v_connection_id;

    UPDATE registered_apps
    SET total_tokens_issued = total_tokens_issued + 1,
        last_token_issued_at = NOW()
    WHERE id = v_app_uuid;

    RETURN v_token_log_id;
END;
$$;

-- Check if user has active connection to app
CREATE OR REPLACE FUNCTION check_app_connection(
    p_user_id UUID,
    p_app_id TEXT
)
RETURNS TABLE (
    has_connection BOOLEAN,
    connection_id UUID,
    granted_scopes TEXT[]
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_app_uuid UUID;
BEGIN
    -- Get app UUID
    SELECT id INTO v_app_uuid FROM registered_apps WHERE app_id = p_app_id AND is_active = TRUE;

    RETURN QUERY
    SELECT
        uac.id IS NOT NULL AND uac.is_active AS has_connection,
        uac.id AS connection_id,
        uac.granted_scopes
    FROM user_app_connections uac
    WHERE uac.user_id = p_user_id AND uac.app_id = v_app_uuid
    LIMIT 1;

    -- If no row found, return false
    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, NULL::UUID, NULL::TEXT[];
    END IF;
END;
$$;

-- Register a physical token for a user
CREATE OR REPLACE FUNCTION register_physical_token(
    p_user_id UUID,
    p_token_serial TEXT,
    p_token_type TEXT,
    p_public_key TEXT,
    p_token_name TEXT DEFAULT NULL,
    p_key_algorithm TEXT DEFAULT 'ECDSA-P256'
)
RETURNS TABLE (
    token_id UUID,
    activation_status TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_token_id UUID;
BEGIN
    INSERT INTO physical_tokens (
        user_id, token_serial, token_type, public_key,
        token_name, key_algorithm, activation_status
    )
    VALUES (
        p_user_id, p_token_serial, p_token_type, p_public_key,
        p_token_name, p_key_algorithm, 'pending'
    )
    RETURNING id INTO v_token_id;

    -- Log the registration
    PERFORM log_audit_event(
        p_user_id,
        'physical_token_registered',
        'security',
        NULL,
        NULL,
        jsonb_build_object(
            'token_serial', p_token_serial,
            'token_type', p_token_type
        )
    );

    RETURN QUERY SELECT v_token_id, 'pending'::TEXT;
END;
$$;

-- Activate a physical token (after verification)
CREATE OR REPLACE FUNCTION activate_physical_token(
    p_token_serial TEXT,
    p_make_primary BOOLEAN DEFAULT FALSE
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_user_id UUID;
    v_token_id UUID;
BEGIN
    -- Get token info
    SELECT id, user_id INTO v_token_id, v_user_id
    FROM physical_tokens
    WHERE token_serial = p_token_serial AND activation_status = 'pending';

    IF v_token_id IS NULL THEN
        RETURN FALSE;
    END IF;

    -- If making primary, unset other primaries
    IF p_make_primary THEN
        UPDATE physical_tokens
        SET is_primary = FALSE
        WHERE user_id = v_user_id AND is_primary = TRUE;
    END IF;

    -- Activate the token
    UPDATE physical_tokens
    SET activation_status = 'active',
        is_primary = p_make_primary,
        updated_at = NOW()
    WHERE id = v_token_id;

    -- Log activation
    PERFORM log_audit_event(
        v_user_id,
        'physical_token_activated',
        'security',
        NULL,
        NULL,
        jsonb_build_object(
            'token_serial', p_token_serial,
            'is_primary', p_make_primary
        )
    );

    RETURN TRUE;
END;
$$;

-- Report physical token as lost/stolen
CREATE OR REPLACE FUNCTION report_token_lost(
    p_user_id UUID,
    p_token_serial TEXT,
    p_reason TEXT DEFAULT 'lost'
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_updated INTEGER;
BEGIN
    UPDATE physical_tokens
    SET activation_status = 'lost',
        is_active = FALSE,
        revoked_at = NOW(),
        revocation_reason = p_reason,
        updated_at = NOW()
    WHERE user_id = p_user_id
      AND token_serial = p_token_serial
      AND activation_status IN ('active', 'pending');

    GET DIAGNOSTICS v_updated = ROW_COUNT;

    IF v_updated > 0 THEN
        -- Log the report
        PERFORM log_audit_event(
            p_user_id,
            'physical_token_reported_lost',
            'security',
            NULL,
            NULL,
            jsonb_build_object(
                'token_serial', p_token_serial,
                'reason', p_reason
            )
        );
    END IF;

    RETURN v_updated > 0;
END;
$$;

-- ============================================================================
-- CLEANUP FUNCTIONS (for pg_cron)
-- ============================================================================

-- Clean old rate limit entries
CREATE OR REPLACE FUNCTION cleanup_rate_limits()
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM rate_limits
    WHERE window_start < NOW() - INTERVAL '2 hours';
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$;

-- Clean old audit logs (keep 90 days)
CREATE OR REPLACE FUNCTION cleanup_audit_logs()
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM audit_logs
    WHERE created_at < NOW() - INTERVAL '90 days';
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$;

-- Clean expired token logs (keep 30 days past expiry)
CREATE OR REPLACE FUNCTION cleanup_token_logs()
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM blind_token_log
    WHERE expires_at < NOW() - INTERVAL '30 days';
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$;

-- ============================================================================
-- GRANTS
-- ============================================================================

GRANT EXECUTE ON FUNCTION check_rate_limit(TEXT, TEXT, INTEGER, INTEGER) TO service_role;
GRANT EXECUTE ON FUNCTION log_audit_event(UUID, TEXT, TEXT, INET, TEXT, JSONB) TO service_role;
GRANT EXECUTE ON FUNCTION log_token_issuance(UUID, TEXT, TEXT, TIMESTAMPTZ, TEXT, INET, TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION revoke_blind_token(TEXT, TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION is_token_revoked(TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION get_user_tier_info(UUID) TO service_role;
GRANT EXECUTE ON FUNCTION cleanup_rate_limits() TO service_role;
GRANT EXECUTE ON FUNCTION cleanup_audit_logs() TO service_role;
GRANT EXECUTE ON FUNCTION cleanup_token_logs() TO service_role;

-- Multi-app functions
GRANT EXECUTE ON FUNCTION register_app(TEXT, TEXT, TEXT, TEXT[], TEXT[], UUID, TEXT, TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION verify_app_api_key(TEXT, TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION get_app_config(TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION authorize_app_connection(UUID, TEXT, TEXT[]) TO service_role;
GRANT EXECUTE ON FUNCTION revoke_app_connection(UUID, TEXT, TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION log_app_token_issuance(UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ, TEXT, INET, TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION check_app_connection(UUID, TEXT) TO service_role;

-- Physical token functions
GRANT EXECUTE ON FUNCTION register_physical_token(UUID, TEXT, TEXT, TEXT, TEXT, TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION activate_physical_token(TEXT, BOOLEAN) TO service_role;
GRANT EXECUTE ON FUNCTION report_token_lost(UUID, TEXT, TEXT) TO service_role;

-- ============================================================================
-- SEED DATA: Register Xenon Engine as first app
-- ============================================================================
-- This creates the Xenon Engine app registration
-- The shared_secret will be displayed ONCE - save it!

-- NOTE: Run this separately after migration to capture the returned secrets:
-- SELECT * FROM register_app(
--     'xenon-engine',
--     'Xenon Totem Engine',
--     'admin@xenontotem.com',
--     ARRAY['https://xenontotem.com/callback', 'exp://localhost:*/--/callback'],
--     ARRAY['https://xenontotem.com', 'http://localhost:*'],
--     NULL,
--     'Xenon Totem',
--     'The privacy-preserving personal data engine'
-- );
