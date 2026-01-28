-- ============================================================================
-- FIX MULTIPLE PERMISSIVE POLICIES
-- ============================================================================
-- Multiple permissive policies on the same table/action means ALL policies
-- are evaluated for every query. Using the TO clause targets specific roles
-- so each role only has ONE policy to evaluate.
-- ============================================================================

-- Drop all existing policies on trusted_client_origins
DROP POLICY IF EXISTS "Users can view own trusted origins" ON trusted_client_origins;
DROP POLICY IF EXISTS "Users can delete own trusted origins" ON trusted_client_origins;
DROP POLICY IF EXISTS "Service role full access - trusted_client_origins" ON trusted_client_origins;

-- Create role-specific policies for authenticated users
CREATE POLICY "authenticated_select_own_origins" ON trusted_client_origins
    FOR SELECT TO authenticated
    USING ((select auth.uid()) = user_id);

CREATE POLICY "authenticated_delete_own_origins" ON trusted_client_origins
    FOR DELETE TO authenticated
    USING ((select auth.uid()) = user_id);

-- Create separate policy for service_role (full access)
CREATE POLICY "service_role_full_access_origins" ON trusted_client_origins
    FOR ALL TO service_role
    USING (true)
    WITH CHECK (true);

-- Drop existing policy on pairing_challenges
DROP POLICY IF EXISTS "Service role full access - pairing_challenges" ON pairing_challenges;

-- Create service_role only policy (no user access needed for this table)
CREATE POLICY "service_role_full_access_challenges" ON pairing_challenges
    FOR ALL TO service_role
    USING (true)
    WITH CHECK (true);

-- ============================================================================
-- FIX user_passkeys (00008 fixed auth.uid() caching but not the TO clause)
-- ============================================================================

-- Drop all existing policies on user_passkeys
DROP POLICY IF EXISTS "Users can view own passkeys" ON user_passkeys;
DROP POLICY IF EXISTS "Users can register passkeys" ON user_passkeys;
DROP POLICY IF EXISTS "Users can update own passkeys" ON user_passkeys;
DROP POLICY IF EXISTS "Users can delete own passkeys" ON user_passkeys;
DROP POLICY IF EXISTS "Service role full access to passkeys" ON user_passkeys;

-- Create role-specific policies for authenticated users
CREATE POLICY "authenticated_select_passkeys" ON user_passkeys
    FOR SELECT TO authenticated
    USING ((select auth.uid()) = user_id);

CREATE POLICY "authenticated_insert_passkeys" ON user_passkeys
    FOR INSERT TO authenticated
    WITH CHECK ((select auth.uid()) = user_id);

CREATE POLICY "authenticated_update_passkeys" ON user_passkeys
    FOR UPDATE TO authenticated
    USING ((select auth.uid()) = user_id)
    WITH CHECK ((select auth.uid()) = user_id);

CREATE POLICY "authenticated_delete_passkeys" ON user_passkeys
    FOR DELETE TO authenticated
    USING ((select auth.uid()) = user_id);

-- Create separate policy for service_role (full access)
CREATE POLICY "service_role_full_access_passkeys" ON user_passkeys
    FOR ALL TO service_role
    USING (true)
    WITH CHECK (true);
