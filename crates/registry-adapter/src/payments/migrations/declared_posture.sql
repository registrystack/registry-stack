DO $$
BEGIN
    IF NOT EXISTS (
        SELECT FROM pg_constraint
        WHERE conrelid = 'adapter_payment_events'::regclass
          AND conname = 'adapter_payment_events_posture_check'
    ) THEN
        ALTER TABLE adapter_payment_events ADD COLUMN posture text;
        ALTER TABLE adapter_payment_events
            ADD CONSTRAINT adapter_payment_events_posture_check
            CHECK (posture IS NOT NULL AND posture IN ('production', 'development')) NOT VALID;
    END IF;
END
$$;
