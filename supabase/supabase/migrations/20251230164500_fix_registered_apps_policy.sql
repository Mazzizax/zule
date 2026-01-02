-- ============================================================================
-- Fix: Consolidate registered_apps SELECT policies
-- ============================================================================
-- Issue: Multiple permissive SELECT policies for authenticated role
-- Solution: Combine into single policy with OR condition
-- ============================================================================

-- Drop the existing SELECT policies
DROP POLICY IF EXISTS "registered_apps_public_view" ON registered_apps;
DROP POLICY IF EXISTS "registered_apps_owner_view" ON registered_apps;

-- Create single consolidated SELECT policy
-- Users can see: (1) active verified apps (public), OR (2) their own apps
CREATE POLICY "registered_apps_select"
ON registered_apps FOR SELECT TO authenticated
USING (
    (is_active = TRUE AND is_verified = TRUE)
    OR
    owner_user_id = (SELECT auth.uid())
);

-- Also need a policy for anonymous users to view public apps
CREATE POLICY "registered_apps_anon_view"
ON registered_apps FOR SELECT TO anon
USING (is_active = TRUE AND is_verified = TRUE);
