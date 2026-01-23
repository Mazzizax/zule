ALTER TABLE user_passkeys ADD COLUMN IF NOT EXISTS backed_up boolean DEFAULT false;
