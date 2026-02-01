-- Fix type mismatch in get_admin_info function
-- auth.users.email is varchar(255), needs to be cast to TEXT

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
