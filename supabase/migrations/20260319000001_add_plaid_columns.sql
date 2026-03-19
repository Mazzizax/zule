-- Add Plaid integration columns to user_profiles and create user_transactions table
-- Track 2: Plaid / AmEx Transaction Ingestion

ALTER TABLE user_profiles
  ADD COLUMN IF NOT EXISTS plaid_access_token TEXT,
  ADD COLUMN IF NOT EXISTS plaid_item_id TEXT,
  ADD COLUMN IF NOT EXISTS plaid_institution_name TEXT,
  ADD COLUMN IF NOT EXISTS plaid_cursor TEXT,
  ADD COLUMN IF NOT EXISTS plaid_connected_at TIMESTAMPTZ;

-- Transactions stored by user_id in Zule (identity side)
CREATE TABLE user_transactions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id),
  merchant_name TEXT,
  amount DECIMAL(12,2) NOT NULL,
  date DATE NOT NULL,
  category TEXT,
  subcategory TEXT,
  location_city TEXT,
  location_state TEXT,
  iso_currency_code TEXT DEFAULT 'USD',
  plaid_transaction_id TEXT UNIQUE,
  synced_to_goals BOOLEAN DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT now()
);

ALTER TABLE user_transactions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users see own transactions" ON user_transactions
  FOR SELECT USING (user_id = auth.uid());

CREATE POLICY "Service role manages transactions" ON user_transactions
  FOR ALL USING (auth.role() = 'service_role');

CREATE INDEX idx_user_tx_user ON user_transactions(user_id);
CREATE INDEX idx_user_tx_unsynced ON user_transactions(user_id, synced_to_goals)
  WHERE synced_to_goals = false;
