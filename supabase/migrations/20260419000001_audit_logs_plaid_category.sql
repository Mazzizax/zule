-- ============================================================================
-- WIDEN AUDIT LOG CONSTRAINT — add 'plaid'
-- ============================================================================
-- plaid-pull-transactions, shred-minted-transactions, and (after this migration)
-- mint-transaction-cards all call log_audit_event with p_category='plaid'.
-- Without this constraint update every one of those audit writes is rejected
-- by the action_category CHECK and silently swallowed (the callers don't check
-- the RPC return), leaving the entire Plaid pipeline with no audit trail even
-- though the pulls/mints/shreds themselves succeed.

ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS audit_logs_action_category_check;
ALTER TABLE audit_logs ADD CONSTRAINT audit_logs_action_category_check
    CHECK (action_category IN (
        'auth',
        'token',
        'profile',
        'subscription',
        'security',
        'admin',
        'developer',
        'machine',
        'plaid'
    ));
