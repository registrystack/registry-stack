ALTER TABLE scheduling_policy_revisions
    ADD COLUMN IF NOT EXISTS policy_document jsonb;
