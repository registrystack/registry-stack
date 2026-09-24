ALTER TABLE casework_source_status
    ADD COLUMN IF NOT EXISTS consecutive_failures integer NOT NULL DEFAULT 0
        CHECK (consecutive_failures >= 0),
    ADD COLUMN IF NOT EXISTS last_succeeded_at timestamptz,
    ADD COLUMN IF NOT EXISTS last_failed_at timestamptz,
    ADD COLUMN IF NOT EXISTS last_failure text CHECK (
        last_failure IS NULL
        OR last_failure IN ('source-unavailable', 'source-refused', 'store', 'configuration')
    );
