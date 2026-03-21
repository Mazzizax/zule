-- Multi-subscription support: user_subscriptions table
-- Tracks per-service subscription state (goals, aca, etc.)

CREATE TABLE user_subscriptions (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  service_id TEXT NOT NULL,        -- 'goals', 'aca', etc.
  tier TEXT NOT NULL,              -- 'citizen', 'standard', 'enthusiast', 'padawan'
  status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'past_due', 'canceled', 'trialing')),
  stripe_subscription_id TEXT,
  stripe_price_id TEXT,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id, service_id)
);

-- Index for user lookups
CREATE INDEX idx_user_subscriptions_user_id ON user_subscriptions(user_id);

-- RLS
ALTER TABLE user_subscriptions ENABLE ROW LEVEL SECURITY;

-- Users can read their own subscriptions
CREATE POLICY "users_select_own_subscriptions"
  ON user_subscriptions FOR SELECT
  USING (auth.uid() = user_id);

-- Service role manages all (inserts, updates, deletes happen via edge functions)
CREATE POLICY "service_role_all_subscriptions"
  ON user_subscriptions FOR ALL
  USING (auth.role() = 'service_role')
  WITH CHECK (auth.role() = 'service_role');

-- Auto-grant Goals/citizen on new user creation
CREATE OR REPLACE FUNCTION grant_default_subscription()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO user_subscriptions (user_id, service_id, tier, status)
  VALUES (NEW.id, 'goals', 'citizen', 'active')
  ON CONFLICT (user_id, service_id) DO NOTHING;
  RETURN NEW;
END;
$$;

-- Fire after user_profiles row is created (which is triggered by auth.users insert)
CREATE TRIGGER on_user_profile_created_grant_subscription
  AFTER INSERT ON user_profiles
  FOR EACH ROW
  EXECUTE FUNCTION grant_default_subscription();

-- Backfill existing users with Goals/citizen
INSERT INTO user_subscriptions (user_id, service_id, tier, status)
SELECT id, 'goals', 'citizen', 'active'
FROM user_profiles
ON CONFLICT (user_id, service_id) DO NOTHING;
