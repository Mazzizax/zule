-- ============================================================================
-- GATEKEEPER: Fix registered_apps RLS policy performance
-- ============================================================================
-- Merges two SELECT policies into one to avoid PostgreSQL evaluating both
-- for every query.
-- ============================================================================

-- Drop the two separate SELECT policies
DROP POLICY IF EXISTS registered_apps_owner_view ON public.registered_apps;
DROP POLICY IF EXISTS registered_apps_public_view ON public.registered_apps;

-- Create a single merged SELECT policy
-- Allows:
-- 1. Anyone (including anon) can view active, verified apps
-- 2. Authenticated users can view their own apps (even if unverified)
CREATE POLICY registered_apps_select ON public.registered_apps
FOR SELECT
USING (
  -- Public view: active AND verified apps visible to everyone
  (is_active = true AND is_verified = true)
  OR
  -- Owner view: owners can see their own apps regardless of status
  (owner_user_id = (SELECT auth.uid()))
);

-- Add index for owner_user_id if not exists (for performance)
CREATE INDEX IF NOT EXISTS idx_registered_apps_owner_user_id
ON public.registered_apps(owner_user_id);

-- Verify the policy was created
DO $$
DECLARE
  policy_count integer;
BEGIN
  SELECT COUNT(*) INTO policy_count
  FROM pg_policies
  WHERE schemaname = 'public'
    AND tablename = 'registered_apps'
    AND policyname LIKE 'registered_apps%'
    AND cmd = 'SELECT';

  RAISE NOTICE 'registered_apps SELECT policies: %', policy_count;

  IF policy_count != 1 THEN
    RAISE WARNING 'Expected 1 SELECT policy, found %', policy_count;
  END IF;
END $$;
