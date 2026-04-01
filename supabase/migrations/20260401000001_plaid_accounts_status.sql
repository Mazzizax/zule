-- Add status tracking columns to plaid_accounts for webhook state management
ALTER TABLE plaid_accounts ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active';
ALTER TABLE plaid_accounts ADD COLUMN IF NOT EXISTS error_code TEXT;
ALTER TABLE plaid_accounts ADD COLUMN IF NOT EXISTS error_message TEXT;
