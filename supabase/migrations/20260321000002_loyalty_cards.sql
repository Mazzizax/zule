-- Loyalty program member cards
CREATE TABLE user_loyalty_cards (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  program_name TEXT NOT NULL,
  member_number TEXT NOT NULL,
  barcode_format TEXT,  -- 'CODE_128', 'QR', 'EAN_13', etc.
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_loyalty_cards_user_id ON user_loyalty_cards(user_id);

ALTER TABLE user_loyalty_cards ENABLE ROW LEVEL SECURITY;

CREATE POLICY "users_select_own_loyalty"
  ON user_loyalty_cards FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "service_role_all_loyalty"
  ON user_loyalty_cards FOR ALL
  USING (auth.role() = 'service_role')
  WITH CHECK (auth.role() = 'service_role');
