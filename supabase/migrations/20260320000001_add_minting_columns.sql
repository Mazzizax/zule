-- Add minting columns to user_transactions
-- Replaces synced_to_goals with proper minting infrastructure

-- Add minting columns
ALTER TABLE user_transactions ADD COLUMN IF NOT EXISTS minted BOOLEAN DEFAULT false;
ALTER TABLE user_transactions ADD COLUMN IF NOT EXISTS minted_at TIMESTAMPTZ;

-- Drop the old synced_to_goals index (wrong model — Vinzrik was pulling)
DROP INDEX IF EXISTS idx_user_tx_unsynced;

-- Drop the old column
ALTER TABLE user_transactions DROP COLUMN IF EXISTS synced_to_goals;

-- Add index for unminted transactions (used by mint-transaction-cards)
CREATE INDEX IF NOT EXISTS idx_user_tx_unminted ON user_transactions(user_id, minted)
  WHERE minted = false;
