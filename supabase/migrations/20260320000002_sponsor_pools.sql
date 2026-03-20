-- Sponsor Pools: Brand reward conditions and budgets, caged in Zule
-- Sponsors set up reward pools with conditions. The enrichment service
-- matches purchases against those pools. Goals never knows the sponsor
-- exists. The sponsor never knows the ghost exists.

-- sponsor_accounts: brand identity, caged in Zule
CREATE TABLE sponsor_accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  brand_name TEXT NOT NULL,
  brand_slug TEXT NOT NULL UNIQUE,
  contact_email TEXT,
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT now()
);

ALTER TABLE sponsor_accounts ENABLE ROW LEVEL SECURITY;

-- Service role only — sponsors are Zule-internal
CREATE POLICY "Service role manages sponsors"
  ON sponsor_accounts FOR ALL
  USING (auth.role() = 'service_role');

-- sponsor_pools: reward conditions and budgets
CREATE TABLE sponsor_pools (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sponsor_id UUID NOT NULL REFERENCES sponsor_accounts(id),
  pool_name TEXT NOT NULL,
  pool_slug TEXT NOT NULL,
  match_conditions JSONB NOT NULL,
  -- [{"type":"merchant","op":"contains","value":"REI"},
  --  {"type":"category","op":"equals","value":"RECREATION"},
  --  {"type":"keyword","op":"any_of","values":["cycling","bike"]},
  --  {"type":"amount","op":"gte","value":25.00}]
  reward_tags JSONB NOT NULL,
  -- {"xp_bonus":50,"xp_multiplier":1.5,"gear_category":"cycling",
  --  "activity_tag":"outdoor_ride","badge_slug":"rei_summer_rider"}
  budget_max_claims INTEGER,
  budget_max_per_user INTEGER DEFAULT 1,
  claims_used INTEGER DEFAULT 0,
  campaign_start BIGINT NOT NULL,  -- cosmic ticks
  campaign_end BIGINT NOT NULL,
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE(sponsor_id, pool_slug)
);

ALTER TABLE sponsor_pools ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role manages pools"
  ON sponsor_pools FOR ALL
  USING (auth.role() = 'service_role');

CREATE INDEX idx_sponsor_pools_active ON sponsor_pools(is_active, campaign_start, campaign_end)
  WHERE is_active = true;

-- pool_claims: dedup + budget tracking (Zule-internal, never crosses)
CREATE TABLE pool_claims (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  pool_id UUID NOT NULL REFERENCES sponsor_pools(id),
  user_id UUID NOT NULL,
  transaction_id UUID NOT NULL,
  xp_awarded INTEGER NOT NULL,
  claimed_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE(pool_id, transaction_id)
);

ALTER TABLE pool_claims ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role manages claims"
  ON pool_claims FOR ALL
  USING (auth.role() = 'service_role');

CREATE INDEX idx_pool_claims_pool ON pool_claims(pool_id);
CREATE INDEX idx_pool_claims_user ON pool_claims(user_id, pool_id);

-- RPC to atomically increment pool claims counter
CREATE OR REPLACE FUNCTION increment_pool_claims(p_pool_id UUID, p_count INTEGER)
RETURNS VOID AS $$
BEGIN
  UPDATE sponsor_pools
  SET claims_used = claims_used + p_count
  WHERE id = p_pool_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
