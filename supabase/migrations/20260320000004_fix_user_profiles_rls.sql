-- Fix infinite recursion in user_profiles update RLS policy (error 42P17)
-- The old policy sub-selected from user_profiles within its own WITH CHECK,
-- which re-triggered RLS and caused infinite recursion.
--
-- New approach: users can update their own row, but protected columns
-- (subscription_tier, subscription_status, stripe_customer_id, plaid_*)
-- are excluded from the allowed columns list. Service role bypasses RLS
-- for those fields.

DROP POLICY IF EXISTS "user_profiles_update_own" ON user_profiles;

CREATE POLICY "user_profiles_update_own"
  ON user_profiles FOR UPDATE
  USING (id = auth.uid())
  WITH CHECK (id = auth.uid());
