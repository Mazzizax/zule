-- ============================================================================
-- GATEKEEPER: Security and Performance Fixes
-- ============================================================================
-- Fixes:
-- 1. SECURITY: update_updated_at() function missing SECURITY DEFINER and search_path
-- 2. PERFORMANCE: RLS policies using auth.uid()/auth.role() evaluated per-row
--
-- The performance fix wraps auth.uid() in (SELECT auth.uid()) which PostgreSQL
-- treats as a scalar subquery and caches for the duration of the query.
-- ============================================================================

-- ============================================================================
-- SECURITY FIX: update_updated_at function
-- ============================================================================

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

-- ============================================================================
-- PERFORMANCE FIX: Drop and recreate ALL RLS policies with optimized auth calls
-- Using (SELECT auth.uid()) instead of auth.uid() to cache the value
-- ============================================================================

-- Helper function to drop all policies on a table
CREATE OR REPLACE FUNCTION gatekeeper_drop_all_policies(p_table TEXT)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    pol record;
BEGIN
    FOR pol IN
        SELECT policyname
        FROM pg_policies
        WHERE schemaname = 'public' AND tablename = p_table
    LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I', pol.policyname, p_table);
    END LOOP;
END;
$$;

-- ============================================================================
-- USER_PROFILES
-- ============================================================================
SELECT gatekeeper_drop_all_policies('user_profiles');

-- Users can view their own profile
CREATE POLICY "user_profiles_select_own"
ON user_profiles FOR SELECT TO authenticated
USING (id = (SELECT auth.uid()));

-- Users can update their own profile (but not billing/subscription fields)
-- The WITH CHECK prevents changing subscription_tier, subscription_status, stripe_customer_id
CREATE POLICY "user_profiles_update_own"
ON user_profiles FOR UPDATE TO authenticated
USING (id = (SELECT auth.uid()))
WITH CHECK (
    id = (SELECT auth.uid()) AND
    subscription_tier IS NOT DISTINCT FROM (SELECT subscription_tier FROM user_profiles WHERE id = (SELECT auth.uid())) AND
    subscription_status IS NOT DISTINCT FROM (SELECT subscription_status FROM user_profiles WHERE id = (SELECT auth.uid())) AND
    stripe_customer_id IS NOT DISTINCT FROM (SELECT stripe_customer_id FROM user_profiles WHERE id = (SELECT auth.uid()))
);

-- Service role has full access
CREATE POLICY "user_profiles_service_role"
ON user_profiles FOR ALL TO service_role
USING (true)
WITH CHECK (true);

-- ============================================================================
-- AUDIT_LOGS
-- ============================================================================
SELECT gatekeeper_drop_all_policies('audit_logs');

-- Only service role can access audit logs (for security)
CREATE POLICY "audit_logs_service_role"
ON audit_logs FOR ALL TO service_role
USING (true)
WITH CHECK (true);

-- ============================================================================
-- RATE_LIMITS
-- ============================================================================
SELECT gatekeeper_drop_all_policies('rate_limits');

-- Only service role can access rate limits (internal use)
CREATE POLICY "rate_limits_service_role"
ON rate_limits FOR ALL TO service_role
USING (true)
WITH CHECK (true);

-- ============================================================================
-- BLIND_TOKEN_LOG
-- ============================================================================
SELECT gatekeeper_drop_all_policies('blind_token_log');

-- Only service role can access token logs (security/audit)
CREATE POLICY "blind_token_log_service_role"
ON blind_token_log FOR ALL TO service_role
USING (true)
WITH CHECK (true);

-- ============================================================================
-- PASSKEY_CREDENTIALS
-- ============================================================================
SELECT gatekeeper_drop_all_policies('passkey_credentials');

-- Users can manage their own passkeys
CREATE POLICY "passkey_credentials_select_own"
ON passkey_credentials FOR SELECT TO authenticated
USING (user_id = (SELECT auth.uid()));

CREATE POLICY "passkey_credentials_insert_own"
ON passkey_credentials FOR INSERT TO authenticated
WITH CHECK (user_id = (SELECT auth.uid()));

CREATE POLICY "passkey_credentials_delete_own"
ON passkey_credentials FOR DELETE TO authenticated
USING (user_id = (SELECT auth.uid()));

-- Service role has full access
CREATE POLICY "passkey_credentials_service_role"
ON passkey_credentials FOR ALL TO service_role
USING (true)
WITH CHECK (true);

-- ============================================================================
-- DEVICE_LINKS
-- ============================================================================
SELECT gatekeeper_drop_all_policies('device_links');

-- Users can manage their own devices
CREATE POLICY "device_links_all_own"
ON device_links FOR ALL TO authenticated
USING (user_id = (SELECT auth.uid()))
WITH CHECK (user_id = (SELECT auth.uid()));

-- Service role has full access
CREATE POLICY "device_links_service_role"
ON device_links FOR ALL TO service_role
USING (true)
WITH CHECK (true);

-- ============================================================================
-- PHYSICAL_TOKENS
-- ============================================================================
SELECT gatekeeper_drop_all_policies('physical_tokens');

-- Users can view their own physical tokens
CREATE POLICY "physical_tokens_select_own"
ON physical_tokens FOR SELECT TO authenticated
USING (user_id = (SELECT auth.uid()));

-- Users can update their own physical tokens (name only, security fields protected by function)
CREATE POLICY "physical_tokens_update_own"
ON physical_tokens FOR UPDATE TO authenticated
USING (user_id = (SELECT auth.uid()))
WITH CHECK (user_id = (SELECT auth.uid()));

-- Service role has full access
CREATE POLICY "physical_tokens_service_role"
ON physical_tokens FOR ALL TO service_role
USING (true)
WITH CHECK (true);

-- ============================================================================
-- REGISTERED_APPS
-- ============================================================================
SELECT gatekeeper_drop_all_policies('registered_apps');

-- Anyone can view active verified apps (public app directory)
CREATE POLICY "registered_apps_public_view"
ON registered_apps FOR SELECT
USING (is_active = TRUE AND is_verified = TRUE);

-- App owners can view all their own apps (including unverified)
CREATE POLICY "registered_apps_owner_view"
ON registered_apps FOR SELECT TO authenticated
USING (owner_user_id = (SELECT auth.uid()));

-- App owners can update their own apps (except verification status)
CREATE POLICY "registered_apps_owner_update"
ON registered_apps FOR UPDATE TO authenticated
USING (owner_user_id = (SELECT auth.uid()))
WITH CHECK (
    owner_user_id = (SELECT auth.uid()) AND
    is_verified IS NOT DISTINCT FROM (SELECT is_verified FROM registered_apps ra WHERE ra.id = registered_apps.id)
);

-- Service role has full access
CREATE POLICY "registered_apps_service_role"
ON registered_apps FOR ALL TO service_role
USING (true)
WITH CHECK (true);

-- ============================================================================
-- USER_APP_CONNECTIONS
-- ============================================================================
SELECT gatekeeper_drop_all_policies('user_app_connections');

-- Users can view their own app connections
CREATE POLICY "user_app_connections_select_own"
ON user_app_connections FOR SELECT TO authenticated
USING (user_id = (SELECT auth.uid()));

-- Users can update (revoke) their own app connections
CREATE POLICY "user_app_connections_update_own"
ON user_app_connections FOR UPDATE TO authenticated
USING (user_id = (SELECT auth.uid()))
WITH CHECK (user_id = (SELECT auth.uid()));

-- Service role has full access
CREATE POLICY "user_app_connections_service_role"
ON user_app_connections FOR ALL TO service_role
USING (true)
WITH CHECK (true);

-- ============================================================================
-- APP_TOKEN_LOG
-- ============================================================================
SELECT gatekeeper_drop_all_policies('app_token_log');

-- Only service role can access app token logs (internal tracking)
CREATE POLICY "app_token_log_service_role"
ON app_token_log FOR ALL TO service_role
USING (true)
WITH CHECK (true);

-- ============================================================================
-- CLEANUP: Remove helper function
-- ============================================================================
DROP FUNCTION IF EXISTS gatekeeper_drop_all_policies(TEXT);

-- ============================================================================
-- VERIFICATION: Check that all tables have RLS enabled and policies
-- ============================================================================
DO $$
DECLARE
    tbl record;
    policy_count integer;
BEGIN
    FOR tbl IN
        SELECT tablename
        FROM pg_tables
        WHERE schemaname = 'public'
        AND tablename IN (
            'user_profiles', 'audit_logs', 'rate_limits', 'blind_token_log',
            'passkey_credentials', 'device_links', 'physical_tokens',
            'registered_apps', 'user_app_connections', 'app_token_log'
        )
    LOOP
        SELECT COUNT(*) INTO policy_count
        FROM pg_policies
        WHERE schemaname = 'public' AND tablename = tbl.tablename;

        RAISE NOTICE 'Table % has % policies', tbl.tablename, policy_count;

        IF policy_count = 0 THEN
            RAISE WARNING 'Table % has no RLS policies!', tbl.tablename;
        END IF;
    END LOOP;
END $$;
