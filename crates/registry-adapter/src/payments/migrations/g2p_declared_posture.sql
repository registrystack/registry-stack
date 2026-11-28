DO $$
BEGIN
    IF NOT EXISTS (
        SELECT FROM pg_constraint
        WHERE conrelid = 'adapter_g2p_events'::regclass
          AND conname = 'adapter_g2p_events_declared_posture_check'
    ) THEN
        ALTER TABLE adapter_g2p_events ADD COLUMN IF NOT EXISTS posture text;
        ALTER TABLE adapter_g2p_events
            ADD CONSTRAINT adapter_g2p_events_declared_posture_check
            CHECK (posture IS NOT NULL AND posture IN ('production', 'development')) NOT VALID;
    END IF;
END
$$;
