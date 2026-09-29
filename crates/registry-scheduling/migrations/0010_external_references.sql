ALTER TABLE scheduling_claims
    ADD COLUMN IF NOT EXISTS external_references jsonb NOT NULL DEFAULT '[]'::jsonb;

CREATE INDEX IF NOT EXISTS scheduling_claims_external_references_idx
    ON scheduling_claims USING gin (external_references jsonb_path_ops)
    WHERE kind = 'booking';
