-- Support multiple linked Plaid accounts per user
CREATE TABLE plaid_accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  plaid_access_token TEXT NOT NULL,
  plaid_item_id TEXT NOT NULL UNIQUE,
  institution_name TEXT,
  connected_at TIMESTAMPTZ DEFAULT now()
);

ALTER TABLE plaid_accounts ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users see own plaid accounts"
  ON plaid_accounts FOR SELECT USING (user_id = auth.uid());

CREATE POLICY "Service role manages plaid accounts"
  ON plaid_accounts FOR ALL USING (auth.role() = 'service_role');

CREATE INDEX idx_plaid_accounts_user ON plaid_accounts(user_id);

-- Link user_transactions to specific plaid account
ALTER TABLE user_transactions ADD COLUMN IF NOT EXISTS plaid_account_id UUID REFERENCES plaid_accounts(id) ON DELETE CASCADE;
