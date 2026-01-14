-- ============================================================================
-- PASSKEY CHALLENGES TABLE
-- ============================================================================
--
-- Stores temporary authentication challenges for passkey login.
-- Challenges are single-use and expire after 5 minutes.
-- This is needed because edge functions are stateless (no in-memory storage).
--
-- ============================================================================

-- Create passkey_challenges table
CREATE TABLE IF NOT EXISTS passkey_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge_key TEXT NOT NULL UNIQUE,
    challenge TEXT NOT NULL,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for lookups by challenge_key
CREATE INDEX IF NOT EXISTS idx_passkey_challenges_key ON passkey_challenges(challenge_key);

-- Index for cleanup of expired challenges
CREATE INDEX IF NOT EXISTS idx_passkey_challenges_expires ON passkey_challenges(expires_at);

-- RLS - Only service role should access this table
ALTER TABLE passkey_challenges ENABLE ROW LEVEL SECURITY;

-- Service role full access
CREATE POLICY "Service role full access to challenges"
    ON passkey_challenges FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

-- Grant permissions only to service_role
GRANT ALL ON passkey_challenges TO service_role;

-- Comment
COMMENT ON TABLE passkey_challenges IS 'Temporary storage for WebAuthn authentication challenges. Challenges expire after 5 minutes.';

-- Function to clean up expired challenges (can be called periodically)
CREATE OR REPLACE FUNCTION cleanup_expired_passkey_challenges()
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM passkey_challenges WHERE expires_at < NOW();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$;
