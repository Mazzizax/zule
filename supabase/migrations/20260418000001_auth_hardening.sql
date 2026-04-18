-- Auth hardening: per-email + per-IP rate limit table for signup/resend/reset,
-- plus per-credential passkey attempt log for counter-rollback / clone
-- detection and brute-force lockout.
--
-- Both tables are service-role-only; no RLS grants to authenticated. They
-- capture security telemetry, not user-owned data.

-- ---------------------------------------------------------------
-- auth_email_attempts — per-email + per-IP rate limit windows for the
-- auth-signup, auth-resend, auth-reset Edge Functions. Insert a row every
-- time an outbound email attempt completes (success or failure). The Edge
-- Function counts rows in the last 15 min to decide whether to allow the
-- next attempt.
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS auth_email_attempts (
  id            BIGSERIAL PRIMARY KEY,
  email         TEXT NOT NULL,
  kind          TEXT NOT NULL CHECK (kind IN ('signup','resend','reset')),
  ip            TEXT,
  succeeded     BOOLEAN NOT NULL,
  attempted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS auth_email_attempts_email_kind_at
  ON auth_email_attempts (LOWER(email), kind, attempted_at DESC);

CREATE INDEX IF NOT EXISTS auth_email_attempts_ip_at
  ON auth_email_attempts (ip, attempted_at DESC)
  WHERE ip IS NOT NULL;

ALTER TABLE auth_email_attempts ENABLE ROW LEVEL SECURITY;
-- Service role only. No policies granted to authenticated.
GRANT ALL ON auth_email_attempts TO service_role;
GRANT USAGE, SELECT ON SEQUENCE auth_email_attempts_id_seq TO service_role;

-- ---------------------------------------------------------------
-- passkey_auth_attempts — per-credential success/failure log used by the
-- new passkey-auth-finish Edge Function for (a) counter-rollback / clone
-- detection, (b) brute-force rate limiting (5 failures in 5 min → lockout).
--
-- Retains failed reasons: 'rate_limited', 'counter_rollback',
-- 'verify_threw', 'not_verified'. Succeeded rows store reason NULL.
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS passkey_auth_attempts (
  id            BIGSERIAL PRIMARY KEY,
  credential_id TEXT NOT NULL,
  user_id       UUID NOT NULL,
  succeeded     BOOLEAN NOT NULL,
  reason        TEXT,
  ip            TEXT,
  attempted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS passkey_auth_attempts_cred_at
  ON passkey_auth_attempts (credential_id, attempted_at DESC);

CREATE INDEX IF NOT EXISTS passkey_auth_attempts_user_at
  ON passkey_auth_attempts (user_id, attempted_at DESC);

ALTER TABLE passkey_auth_attempts ENABLE ROW LEVEL SECURITY;
-- Service role only. Security log; no user-facing reads.
GRANT ALL ON passkey_auth_attempts TO service_role;
GRANT USAGE, SELECT ON SEQUENCE passkey_auth_attempts_id_seq TO service_role;

-- Retention note: both tables are cheap for now. Revisit with pg_cron (or a
-- scheduled cleanup Edge Function) when row count justifies purge.
