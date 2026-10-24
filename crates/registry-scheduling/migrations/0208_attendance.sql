-- Appointment attendance is an observation stream separate from the
-- capacity lifecycle. Rows are immutable corrections: the latest revision is
-- current, while every earlier fact remains attributable in history.
CREATE TABLE scheduling_attendance_observations (
    observation_id uuid PRIMARY KEY,
    claim_id uuid NOT NULL REFERENCES scheduling_claims(claim_id),
    -- The latest confirmed/rescheduled history revision identifies one visit.
    -- Cancellation advances the appointment revision but not this binding,
    -- so it does not hide an observation. Rescheduling away and back mints a
    -- distinct visit revision even when the displayed interval repeats.
    visit_revision bigint NOT NULL CHECK (visit_revision > 0),
    appointment_revision bigint NOT NULL CHECK (appointment_revision > 0),
    revision bigint NOT NULL CHECK (revision > 0),
    state text NOT NULL CHECK (state IN ('arrived', 'completed', 'no-show')),
    observed_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    actor text NOT NULL CHECK (actor <> ''),
    grant_reference text NOT NULL CHECK (grant_reference ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT scheduling_attendance_observations_revision_key
        UNIQUE (claim_id, revision),
    CONSTRAINT scheduling_attendance_observations_effective_time_check
        CHECK (observed_at <= recorded_at)
);

CREATE INDEX scheduling_attendance_observations_current_idx
    ON scheduling_attendance_observations(claim_id, visit_revision, revision DESC);

-- Only the Scheduling attendance transaction may change this append-only
-- stream. PostgreSQL clears the marker on commit or rollback.
CREATE FUNCTION scheduling_require_attendance_writer_v1()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF current_setting('registry_scheduling.attendance_writer', true) IS DISTINCT FROM 'v1' THEN
        RAISE EXCEPTION 'attendance observations are owned by the Scheduling attendance transaction';
    END IF;
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'attendance observations are append-only';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER scheduling_attendance_observations_writer_v1
    BEFORE INSERT OR UPDATE OR DELETE ON scheduling_attendance_observations
    FOR EACH ROW EXECUTE FUNCTION scheduling_require_attendance_writer_v1();
