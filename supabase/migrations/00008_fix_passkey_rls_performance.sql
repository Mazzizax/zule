-- ============================================================================
-- FIX PASSKEY RLS PERFORMANCE
-- ============================================================================
-- Replace auth.uid() with (select auth.uid()) to avoid re-evaluation per row
-- ============================================================================

-- Drop existing policies
DROP POLICY IF EXISTS "Users can view own passkeys" ON user_passkeys;
DROP POLICY IF EXISTS "Users can register passkeys" ON user_passkeys;
DROP POLICY IF EXISTS "Users can update own passkeys" ON user_passkeys;
DROP POLICY IF EXISTS "Users can delete own passkeys" ON user_passkeys;

-- Recreate with optimized auth.uid() call
CREATE POLICY "Users can view own passkeys"
    ON user_passkeys FOR SELECT
    USING ((select auth.uid()) = user_id);

CREATE POLICY "Users can register passkeys"
    ON user_passkeys FOR INSERT
    WITH CHECK ((select auth.uid()) = user_id);

CREATE POLICY "Users can update own passkeys"
    ON user_passkeys FOR UPDATE
    USING ((select auth.uid()) = user_id)
    WITH CHECK ((select auth.uid()) = user_id);

CREATE POLICY "Users can delete own passkeys"
    ON user_passkeys FOR DELETE
    USING ((select auth.uid()) = user_id);
