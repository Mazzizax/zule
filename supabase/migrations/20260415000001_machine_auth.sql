-- ============================================================================
-- MACHINE AUTHENTICATION
-- ============================================================================
--
-- Extends Zule to authenticate users at the OS level.
-- Fleet machines request login, users approve from their phone with biometric.
-- Real identity, real accountability, full audit trail.
--
-- ============================================================================

-- ============================================================================
-- WIDEN AUDIT LOG CONSTRAINT
-- ============================================================================
-- The existing CHECK constraint on action_category doesn't include 'machine'
-- or 'developer' (which app-register already uses via service_role).
-- Widen it to support both.

ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS audit_logs_action_category_check;
ALTER TABLE audit_logs ADD CONSTRAINT audit_logs_action_category_check
    CHECK (action_category IN (
        'auth',
        'token',
        'profile',
        'subscription',
        'security',
        'admin',
        'developer',
        'machine'
    ));

-- ============================================================================
-- FLEET MACHINES
-- ============================================================================
-- Registered machines that can request authentication via Zule.
-- Each machine gets an API key (shown once at registration, stored as SHA-256 hash).

CREATE TABLE IF NOT EXISTS fleet_machines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Identity
    machine_name TEXT NOT NULL,
    machine_identifier TEXT NOT NULL UNIQUE,   -- Tailscale node ID, hostname, or custom

    -- Ownership & access
    owner_user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    allowed_user_ids UUID[] NOT NULL DEFAULT '{}',

    -- Machine authentication
    api_key_hash TEXT NOT NULL,                -- SHA-256 hex of the API key

    -- Encrypted Windows credential (released on approval)
    windows_credential_encrypted TEXT,         -- DPAPI + Zule double-encrypted blob

    -- Status
    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_fleet_machines_owner ON fleet_machines(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_fleet_machines_active ON fleet_machines(is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_fleet_machines_identifier ON fleet_machines(machine_identifier);
CREATE INDEX IF NOT EXISTS idx_fleet_machines_api_key ON fleet_machines(api_key_hash);

-- RLS
ALTER TABLE fleet_machines ENABLE ROW LEVEL SECURITY;

-- Users can see machines they own or are allowed to unlock
CREATE POLICY "Users can view accessible machines"
    ON fleet_machines FOR SELECT
    USING (
        auth.uid() = owner_user_id
        OR auth.uid() = ANY(allowed_user_ids)
    );

-- Only owners can insert/update/delete
CREATE POLICY "Owners can manage machines"
    ON fleet_machines FOR INSERT
    WITH CHECK (auth.uid() = owner_user_id);

CREATE POLICY "Owners can update machines"
    ON fleet_machines FOR UPDATE
    USING (auth.uid() = owner_user_id)
    WITH CHECK (auth.uid() = owner_user_id);

CREATE POLICY "Owners can delete machines"
    ON fleet_machines FOR DELETE
    USING (auth.uid() = owner_user_id);

-- Service role full access (for API-key-authenticated machine endpoints)
CREATE POLICY "Service role full access - fleet_machines"
    ON fleet_machines FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

-- Grants
GRANT SELECT ON fleet_machines TO authenticated;
GRANT ALL ON fleet_machines TO service_role;

-- ============================================================================
-- MACHINE LOGIN SESSIONS
-- ============================================================================
-- The coordination point between Windows and Android surfaces.
-- Machine creates a pending session, user approves it from their phone.

CREATE TABLE IF NOT EXISTS machine_login_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    machine_id UUID NOT NULL REFERENCES fleet_machines(id) ON DELETE CASCADE,

    -- Human-readable session code (e.g., "BLUE-TIGER-42")
    session_code TEXT NOT NULL,

    -- Status lifecycle: pending → approved / denied / expired
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'denied', 'expired')),

    -- Approval details (populated when status = 'approved')
    approved_by_user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    auth_level TEXT,                      -- 'biometric', 'password'
    approved_at TIMESTAMPTZ,

    -- Timing
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Prevent duplicate active session codes
CREATE UNIQUE INDEX IF NOT EXISTS idx_mls_active_session_code
    ON machine_login_sessions(session_code)
    WHERE status = 'pending';

-- Fast lookup by machine + status (polling)
CREATE INDEX IF NOT EXISTS idx_mls_machine_status
    ON machine_login_sessions(machine_id, status);

-- Cleanup expired sessions
CREATE INDEX IF NOT EXISTS idx_mls_expires
    ON machine_login_sessions(expires_at)
    WHERE status = 'pending';

-- RLS
ALTER TABLE machine_login_sessions ENABLE ROW LEVEL SECURITY;

-- Users can see sessions for machines they're allowed to unlock
CREATE POLICY "Users can view sessions for their machines"
    ON machine_login_sessions FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM fleet_machines fm
            WHERE fm.id = machine_login_sessions.machine_id
              AND fm.is_active = TRUE
              AND (
                  auth.uid() = fm.owner_user_id
                  OR auth.uid() = ANY(fm.allowed_user_ids)
              )
        )
    );

-- Service role full access (for machine API-key endpoints)
CREATE POLICY "Service role full access - machine_login_sessions"
    ON machine_login_sessions FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

-- Grants
GRANT SELECT ON machine_login_sessions TO authenticated;
GRANT ALL ON machine_login_sessions TO service_role;

-- ============================================================================
-- SESSION CODE GENERATOR
-- ============================================================================
-- Produces codes like "BLUE-TIGER-42" — memorable, speakable, visually distinct.
-- ~250,000 combinations, more than enough for 2-minute TTL windows.

CREATE OR REPLACE FUNCTION generate_session_code()
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    adjectives TEXT[] := ARRAY[
        'RED','BLUE','GREEN','GOLD','IRON','DARK','BOLD','FAST',
        'COLD','WARM','WILD','DEEP','HIGH','LONG','CALM','KEEN',
        'FIRE','JADE','NEON','PALE','RUST','SILK','VOID','ZINC',
        'DUSK','DAWN','GREY','ONYX','RUBY','SAGE','TEAL','COAL',
        'FERN','GRIM','HAZE','MOSS','OPAL','PINE','SAND','VOLT',
        'AQUA','BONE','CLAY','FLAX','GLOW','HUSK','IVORY','LAVA'
    ];
    animals TEXT[] := ARRAY[
        'WOLF','BEAR','HAWK','LYNX','CROW','DEER','DOVE','FISH',
        'FROG','HARE','LION','MOLE','ORCA','PUMA','SEAL','SWAN',
        'VIPER','EAGLE','HORSE','RAVEN','SHARK','TIGER','COBRA',
        'CRANE','DRAKE','FINCH','GECKO','HERON','IBEX','MOOSE',
        'OTTER','QUAIL','ROBIN','SNAKE','TROUT','WHALE','BISON',
        'COYOTE','EGRET','FALCON','GROUSE','HYENA','JACKAL','KITE',
        'LEMUR','MACAW','NEWT','OWL','PIKE'
    ];
    code TEXT;
    attempts INTEGER := 0;
BEGIN
    LOOP
        code := adjectives[1 + floor(random() * array_length(adjectives, 1))::int]
            || '-'
            || animals[1 + floor(random() * array_length(animals, 1))::int]
            || '-'
            || lpad((floor(random() * 100))::text, 2, '0');

        -- Check uniqueness among pending sessions
        IF NOT EXISTS (
            SELECT 1 FROM machine_login_sessions
            WHERE session_code = code AND status = 'pending'
        ) THEN
            RETURN code;
        END IF;

        attempts := attempts + 1;
        IF attempts > 10 THEN
            -- Fallback: append extra random digits
            RETURN code || '-' || lpad((floor(random() * 1000))::text, 3, '0');
        END IF;
    END LOOP;
END;
$$;

-- ============================================================================
-- CLEANUP EXPIRED SESSIONS
-- ============================================================================

CREATE OR REPLACE FUNCTION cleanup_expired_machine_sessions()
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    expired_count INTEGER;
BEGIN
    UPDATE machine_login_sessions
    SET status = 'expired'
    WHERE status = 'pending'
      AND expires_at < NOW();

    GET DIAGNOSTICS expired_count = ROW_COUNT;
    RETURN expired_count;
END;
$$;

-- ============================================================================
-- AUTO-UPDATE TIMESTAMPS
-- ============================================================================

CREATE TRIGGER fleet_machines_updated_at
    BEFORE UPDATE ON fleet_machines
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- GRANTS FOR NEW FUNCTIONS
-- ============================================================================

GRANT EXECUTE ON FUNCTION generate_session_code() TO service_role;
GRANT EXECUTE ON FUNCTION cleanup_expired_machine_sessions() TO service_role;

-- ============================================================================
-- ENABLE REALTIME FOR SESSION NOTIFICATIONS
-- ============================================================================
-- The Android surface subscribes to new sessions via Supabase Realtime.
-- RLS ensures users only see sessions for machines they can unlock.

ALTER PUBLICATION supabase_realtime ADD TABLE machine_login_sessions;

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE fleet_machines IS 'Registered fleet machines that authenticate via Zule. Each machine has an API key for server-to-server communication.';
COMMENT ON TABLE machine_login_sessions IS 'Coordination point for machine authentication. Machine creates pending session, user approves from phone.';
COMMENT ON COLUMN fleet_machines.api_key_hash IS 'SHA-256 hex hash of the machine API key (zm_ prefix). Key shown once at registration.';
COMMENT ON COLUMN fleet_machines.windows_credential_encrypted IS 'DPAPI + Zule double-encrypted Windows credential blob. Released to machine on approved login.';
COMMENT ON COLUMN machine_login_sessions.session_code IS 'Human-readable code (e.g., BLUE-TIGER-42) for visual confirmation between login screen and phone.';
COMMENT ON FUNCTION generate_session_code() IS 'Generates unique ADJECTIVE-ANIMAL-NN session codes for machine login requests.';
