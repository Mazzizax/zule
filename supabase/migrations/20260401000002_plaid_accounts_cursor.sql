-- Store sync cursor per plaid account for incremental transaction sync
ALTER TABLE plaid_accounts ADD COLUMN IF NOT EXISTS sync_cursor TEXT DEFAULT '';
