-- passkey-auth-begin runs before the user is known (usernameless WebAuthn
-- flow). The challenge row is inserted with NULL user_id and the real user
-- is resolved at passkey-auth-finish once the authenticator response carries
-- the credential_id. Relax the NOT NULL on user_id to unblock that path.
--
-- Registration-time challenges still carry user_id (passkey-register-begin
-- inserts with the authenticated user), so the column remains populated for
-- that kind.

ALTER TABLE passkey_challenges
  ALTER COLUMN user_id DROP NOT NULL;
