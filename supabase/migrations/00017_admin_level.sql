-- ============================================================================
-- ADMIN LEVEL SUPPORT
-- ============================================================================
-- Adds admin_level column to user_profiles for admin authorization.
--
-- Admin Level Definitions:
--   0     = No admin access (default)
--   1     = Basic Admin (view stats, basic moderation)
--   2     = Full Admin (user management, content control)
--   3-98  = Reserved for future expansion
--   99    = SageLevel (system-awarded only, full access)
--
-- Level 99 is initially assigned manually for development.
-- Future: only awarded by system verification process.
-- ============================================================================

-- Add admin_level column to user_profiles
ALTER TABLE user_profiles
ADD COLUMN IF NOT EXISTS admin_level INTEGER DEFAULT 0;

-- Add constraint to ensure valid admin levels (0-99)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'user_profiles_admin_level_check'
    ) THEN
        ALTER TABLE user_profiles
        ADD CONSTRAINT user_profiles_admin_level_check
        CHECK (admin_level >= 0 AND admin_level <= 99);
    END IF;
END $$;

-- Index for admin queries (only index rows with admin access)
CREATE INDEX IF NOT EXISTS idx_user_profiles_admin
    ON user_profiles(admin_level)
    WHERE admin_level > 0;

-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

-- Function to check if user is admin at a minimum level
CREATE OR REPLACE FUNCTION is_admin(p_user_id UUID, p_min_level INTEGER DEFAULT 1)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_level INTEGER;
BEGIN
    SELECT admin_level INTO v_level
    FROM user_profiles
    WHERE id = p_user_id;

    RETURN COALESCE(v_level, 0) >= p_min_level;
END;
$$;

-- Function to get admin info for JWT claims
-- Returns NULL if user is not an admin
CREATE OR REPLACE FUNCTION get_admin_info(p_user_id UUID)
RETURNS TABLE (
    user_id UUID,
    email TEXT,
    admin_level INTEGER,
    display_name TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    RETURN QUERY
    SELECT
        up.id as user_id,
        au.email::TEXT,
        up.admin_level,
        up.display_name::TEXT
    FROM user_profiles up
    JOIN auth.users au ON au.id = up.id
    WHERE up.id = p_user_id
      AND up.admin_level > 0;
END;
$$;

-- Grants for service role
GRANT EXECUTE ON FUNCTION is_admin(UUID, INTEGER) TO service_role;
GRANT EXECUTE ON FUNCTION get_admin_info(UUID) TO service_role;

-- Documentation
COMMENT ON COLUMN user_profiles.admin_level IS
    'Admin authorization level: 0=none, 1=basic, 2=full, 3-98=reserved, 99=SageLevel (system-awarded)';
COMMENT ON FUNCTION is_admin(UUID, INTEGER) IS
    'Check if user has admin access at specified minimum level';
COMMENT ON FUNCTION get_admin_info(UUID) IS
    'Get admin claims for JWT (returns NULL for non-admins)';
