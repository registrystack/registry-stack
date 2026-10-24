CREATE TABLE IF NOT EXISTS scheduling_meta (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    scheduling_id text NOT NULL,
    policy_revision bigint NOT NULL CHECK (policy_revision > 0),
    policy_digest text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    facts_revision bigint NOT NULL DEFAULT 0
);
-- The empty scheduling_id marks a database no deployment has adopted yet;
-- `schedulingctl apply` claims it for the policy's scheduling id, and every
-- serve refuses both an empty and a mismatched one.
INSERT INTO scheduling_meta (singleton, scheduling_id, policy_revision, policy_digest)
VALUES (true, '', 1, '')
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS scheduling_policy_revisions (
    policy_revision bigint PRIMARY KEY CHECK (policy_revision > 0),
    policy_digest text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now(),
    policy_document jsonb
);

CREATE TABLE IF NOT EXISTS scheduling_locations (
    location_id text PRIMARY KEY,
    timezone text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scheduling_pools (
    pool_id text PRIMARY KEY,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scheduling_pool_members (
    resource_id text PRIMARY KEY,
    pool_id text NOT NULL REFERENCES scheduling_pools(pool_id),
    capabilities text[] NOT NULL DEFAULT '{}',
    available boolean NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    availability jsonb,
    -- Counted resources describe physical stock. Zero is a valid current fact:
    -- confirmed commitments remain historical truth while new allocations stop.
    capacity_units integer NOT NULL DEFAULT 1,
    CONSTRAINT scheduling_pool_members_availability_object CHECK (
        availability IS NULL OR jsonb_typeof(availability) = 'object'
    ),
    CONSTRAINT scheduling_pool_members_capacity_units_check
        CHECK (capacity_units BETWEEN 0 AND 2147483647)
);
CREATE INDEX IF NOT EXISTS scheduling_pool_members_pool_idx
    ON scheduling_pool_members(pool_id);

CREATE TABLE IF NOT EXISTS scheduling_exceptions (
    exception_id text PRIMARY KEY,
    location text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('closure','opening')),
    date date NOT NULL,
    start_time text NOT NULL,
    end_time text NOT NULL,
    reopens text,
    authority text,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS scheduling_exceptions_location_idx
    ON scheduling_exceptions(location, date);

-- The capacity transaction's lock anchor. One row per separately locked
-- supply: every resource pool backing exact-time offerings, and every
-- published window. The anchor is the pool, not the offering, because two
-- offerings on one pool sell the same members and must serialize against
-- each other.
CREATE TABLE IF NOT EXISTS scheduling_supply (
    supply_id text PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN ('pool','window'))
);

CREATE TABLE IF NOT EXISTS scheduling_claims (
    claim_id uuid PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN ('booking','hold','window')),
    state text NOT NULL CHECK (state IN ('active','released','cancelled','consumed','expired')),
    offering text NOT NULL,
    supply_id text NOT NULL,
    channel text,
    displayed_start timestamptz NOT NULL,
    displayed_end timestamptz NOT NULL,
    occupied_start timestamptz NOT NULL,
    occupied_end timestamptz NOT NULL,
    units integer NOT NULL CHECK (units > 0),
    -- The caller chooses this value, so the column bounds it: 256 octets,
    -- the same ceiling the evaluator gives every other caller-supplied
    -- string. The edge refuses the same size first, so the bound is not
    -- reached by an ordinary request.
    --
    -- The uniqueness the key promises is not a UNIQUE index here. The
    -- evaluator refuses a duplicate against the snapshot it locked, scoped to
    -- the offering and to the interval under consideration, while a partial
    -- UNIQUE over active claims would be a different and stronger rule: it
    -- would collide across two offerings that share one pool, and it would
    -- fire inside a hold confirmation, which writes the booking while the
    -- hold carrying the same key is still active in the same transaction.
    duplicate_key text CHECK (duplicate_key IS NULL OR octet_length(duplicate_key) <= 256),
    hold_expires_at timestamptz,
    revision bigint NOT NULL CHECK (revision > 0),
    policy_revision bigint NOT NULL CHECK (policy_revision > 0),
    occurrence_id uuid,
    actor text NOT NULL,
    reason text CHECK (reason IS NULL OR octet_length(reason) <= 4096),
    created_at timestamptz NOT NULL DEFAULT now(),
    changed_at timestamptz NOT NULL DEFAULT now(),
    closed_at timestamptz,
    external_references jsonb NOT NULL DEFAULT '[]'::jsonb,
    owner_issuer text,
    owner_subject text,
    owner_reference text,
    owner_erased_at timestamptz,
    -- The scope check requires every immutable security label, so no writer
    -- creates an unlabeled claim by omission.
    operational_service text,
    operational_location text,
    operational_mode text,
    recipient_count integer,
    attendee_count integer,
    party_references jsonb NOT NULL DEFAULT '[]'::jsonb,
    manager_source_issuer text,
    manager_subject text,
    CONSTRAINT scheduling_claims_owner_check CHECK (
        (owner_issuer IS NULL AND owner_subject IS NULL)
        OR (owner_issuer IS NOT NULL AND owner_issuer <> ''
            AND owner_subject IS NOT NULL AND owner_subject <> '')
    ),
    CONSTRAINT scheduling_claims_owner_reference_check CHECK (
        owner_reference IS NULL OR owner_reference ~ '^sha256:[0-9a-f]{64}$'
    ),
    CONSTRAINT scheduling_claims_owner_erasure_check CHECK (
        (owner_erased_at IS NULL AND owner_reference IS NULL)
        OR (owner_erased_at IS NOT NULL AND owner_reference IS NOT NULL
            AND owner_issuer IS NULL AND owner_subject IS NULL)
    ),
    CONSTRAINT scheduling_claims_operational_scope_check CHECK (
        operational_service IS NOT NULL AND operational_service <> ''
        AND operational_location IS NOT NULL AND operational_location <> ''
        AND operational_mode IN ('exact-time', 'arrival-window')
    ),
    CONSTRAINT scheduling_claims_party_counts_check CHECK (
        (recipient_count IS NULL AND attendee_count IS NULL)
        OR (recipient_count IS NOT NULL AND recipient_count >= 0
            AND attendee_count IS NOT NULL AND attendee_count > 0
            AND attendee_count >= recipient_count)
    ),
    CONSTRAINT scheduling_claims_party_references_check CHECK (
        jsonb_typeof(party_references) = 'array'
        AND jsonb_array_length(party_references) <= 16
    ),
    CONSTRAINT scheduling_claims_source_manager_check CHECK (
        (manager_source_issuer IS NULL AND manager_subject IS NULL)
        OR (manager_source_issuer IS NOT NULL
            AND manager_source_issuer <> ''
            AND octet_length(manager_source_issuer) <= 512
            AND manager_subject IS NOT NULL
            AND manager_subject <> ''
            AND octet_length(manager_subject) <= 512)
    )
);
CREATE INDEX IF NOT EXISTS scheduling_claims_supply_active_idx
    ON scheduling_claims(supply_id, occupied_start, occupied_end)
    WHERE state = 'active';
CREATE INDEX IF NOT EXISTS scheduling_claims_duplicate_lookup_idx
    ON scheduling_claims(duplicate_key, offering, occupied_end)
    WHERE state = 'active' AND duplicate_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS scheduling_claims_external_references_idx
    ON scheduling_claims USING gin (external_references jsonb_path_ops)
    WHERE kind = 'booking';
CREATE INDEX IF NOT EXISTS scheduling_claims_expiry_idx
    ON scheduling_claims(hold_expires_at)
    WHERE state = 'active' AND kind = 'hold';
CREATE INDEX IF NOT EXISTS scheduling_claims_operational_displayed_idx
    ON scheduling_claims(
        operational_service,
        operational_location,
        displayed_start,
        claim_id
    )
    WHERE kind = 'booking';
CREATE INDEX IF NOT EXISTS scheduling_claims_operational_occupied_idx
    ON scheduling_claims(
        operational_service,
        operational_location,
        occupied_start,
        claim_id
    )
    WHERE kind = 'booking';

-- Published windows reserve physical resources once through the same
-- claim-allocation ledger as every exact reservation. Window booking claims
-- point to the window but carry only units; they never duplicate its room,
-- facilitator, or equipment allocations.
--
-- A window parent is the window's own reservation of the resources its record
-- declares, written with the records and named by the window it serves. One
-- window has at most one, so its allocations are never counted twice.
CREATE UNIQUE INDEX IF NOT EXISTS scheduling_window_parent_claim_idx
    ON scheduling_claims(supply_id)
    WHERE kind = 'window';

-- One claim remains the logical hold or appointment. These rows are its
-- physical allocations. Resource and anchor identifiers intentionally do not
-- reference current fact tables: an operator must be able to record loss or
-- retirement without deleting what a retained commitment allocated.
CREATE TABLE IF NOT EXISTS scheduling_claim_allocations (
    claim_id uuid NOT NULL REFERENCES scheduling_claims(claim_id),
    requirement_kind text NOT NULL
        CHECK (requirement_kind IN ('primary', 'additional')),
    requirement_index smallint NOT NULL,
    part_index smallint NOT NULL CHECK (part_index BETWEEN 0 AND 255),
    offering text NOT NULL CHECK (offering <> ''),
    operational_service text,
    operational_location text,
    operational_mode text,
    anchor_id text,
    resource_id text NOT NULL CHECK (resource_id <> ''),
    occupied_start timestamptz NOT NULL,
    occupied_end timestamptz NOT NULL,
    units integer NOT NULL CHECK (units > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (claim_id, requirement_kind, requirement_index, part_index),
    UNIQUE (claim_id, resource_id),
    CONSTRAINT scheduling_claim_allocations_requirement_check CHECK (
        (requirement_kind = 'primary' AND requirement_index = 0)
        OR
        (requirement_kind = 'additional' AND requirement_index BETWEEN 0 AND 14)
    ),
    CONSTRAINT scheduling_claim_allocations_interval_check
        CHECK (occupied_start < occupied_end),
    CONSTRAINT scheduling_claim_allocations_scope_check CHECK (
        operational_service IS NOT NULL
        AND operational_service <> ''
        AND operational_location IS NOT NULL
        AND operational_location <> ''
        AND operational_mode IN ('exact-time', 'arrival-window')
        AND anchor_id IS NOT NULL
        AND anchor_id <> ''
    )
);
CREATE INDEX IF NOT EXISTS scheduling_claim_allocations_anchor_interval_idx
    ON scheduling_claim_allocations(anchor_id, occupied_start, occupied_end, claim_id);
CREATE INDEX IF NOT EXISTS scheduling_claim_allocations_resource_interval_idx
    ON scheduling_claim_allocations(resource_id, occupied_start, occupied_end, claim_id);
CREATE INDEX IF NOT EXISTS scheduling_claim_allocations_offering_idx
    ON scheduling_claim_allocations(offering, claim_id);

CREATE TABLE IF NOT EXISTS scheduling_history (
    event_id uuid PRIMARY KEY,
    claim_id uuid NOT NULL REFERENCES scheduling_claims(claim_id),
    revision bigint NOT NULL,
    kind text NOT NULL,
    occurred_at timestamptz NOT NULL,
    actor text NOT NULL,
    detail jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS scheduling_history_claim_idx
    ON scheduling_history(claim_id, occurred_at, event_id);

-- Appointment attendance is an observation stream separate from the
-- capacity lifecycle. Rows are immutable corrections: the latest revision is
-- current, while every earlier fact remains attributable in history.
CREATE TABLE IF NOT EXISTS scheduling_attendance_observations (
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
CREATE INDEX IF NOT EXISTS scheduling_attendance_observations_current_idx
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

CREATE TABLE IF NOT EXISTS scheduling_outbox (
                 outbox_id uuid NOT NULL,
                 purpose text NOT NULL
                     CHECK (purpose <> '' AND octet_length(purpose) <= 256),
                 generation bigint NOT NULL CHECK (generation > 0),
                 state text NOT NULL
                     CONSTRAINT scheduling_outbox_state_values CHECK (
                         state IN ('pending', 'leased', 'delivered', 'dead-lettered',
                                   'expired', 'unknown', 'cancelled')
                     ),
                 attempt smallint NOT NULL CHECK (attempt >= 0),
                 next_attempt_at timestamptz,
                 attempt_started_at timestamptz,
                 lease_expires_at timestamptz,
                 lease_token uuid,
                 delivered_at timestamptz,
                 dead_lettered_at timestamptz,
                 expired_at timestamptz,
                 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 PRIMARY KEY (outbox_id, purpose),
                 CONSTRAINT scheduling_outbox_shape CHECK (
                     (state = 'pending'
                         AND next_attempt_at IS NOT NULL
                         AND attempt_started_at IS NULL
                         AND lease_expires_at IS NULL
                         AND lease_token IS NULL
                         AND delivered_at IS NULL
                         AND dead_lettered_at IS NULL
                         AND expired_at IS NULL)
                     OR (state = 'leased'
                         AND attempt > 0
                         AND next_attempt_at IS NULL
                         AND attempt_started_at IS NOT NULL
                         AND lease_expires_at IS NOT NULL
                         AND lease_expires_at > attempt_started_at
                         AND lease_token IS NOT NULL
                         AND delivered_at IS NULL
                         AND dead_lettered_at IS NULL
                         AND expired_at IS NULL)
                     OR (state = 'delivered'
                         AND attempt > 0
                         AND next_attempt_at IS NULL
                         AND attempt_started_at IS NULL
                         AND lease_expires_at IS NULL
                         AND lease_token IS NULL
                         AND delivered_at IS NOT NULL
                         AND dead_lettered_at IS NULL
                         AND expired_at IS NULL)
                     OR (state = 'dead-lettered'
                         AND attempt > 0
                         AND next_attempt_at IS NULL
                         AND attempt_started_at IS NULL
                         AND lease_expires_at IS NULL
                         AND lease_token IS NULL
                         AND delivered_at IS NULL
                         AND dead_lettered_at IS NOT NULL)
                     OR (state = 'expired'
                         AND next_attempt_at IS NULL
                         AND attempt_started_at IS NULL
                         AND lease_expires_at IS NULL
                         AND lease_token IS NULL
                         AND delivered_at IS NULL
                         AND dead_lettered_at IS NULL
                         AND expired_at IS NOT NULL)
                     OR (state = 'unknown'
                         AND attempt > 0
                         AND next_attempt_at IS NULL
                         AND attempt_started_at IS NULL
                         AND lease_expires_at IS NULL
                         AND lease_token IS NULL
                         AND delivered_at IS NULL
                         AND dead_lettered_at IS NULL
                         AND expired_at IS NULL)
                     OR (state = 'cancelled'
                         AND next_attempt_at IS NULL
                         AND attempt_started_at IS NULL
                         AND lease_expires_at IS NULL
                         AND lease_token IS NULL
                         AND delivered_at IS NULL
                         AND dead_lettered_at IS NULL
                         AND expired_at IS NULL)
                 )
             );
CREATE INDEX IF NOT EXISTS scheduling_outbox_due_idx
                 ON scheduling_outbox (next_attempt_at, outbox_id, purpose)
                 WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS scheduling_outbox_lease_idx
                 ON scheduling_outbox (lease_expires_at, outbox_id, purpose)
                 WHERE state = 'leased';
ALTER TABLE scheduling_outbox
    ADD COLUMN claim_id uuid NOT NULL REFERENCES scheduling_claims(claim_id),
    ADD COLUMN appointment_revision bigint NOT NULL,
    ADD COLUMN due_at timestamptz NOT NULL,
    ADD COLUMN payload jsonb NOT NULL,
    ADD COLUMN created_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN last_failure_class text
        CHECK (last_failure_class IS NULL OR octet_length(last_failure_class) BETWEEN 1 AND 64),
    ADD CONSTRAINT scheduling_outbox_purpose_values
        CHECK (purpose IN ('confirmation','change','cancellation','reminder')),
    ADD CONSTRAINT scheduling_outbox_one_purpose UNIQUE (outbox_id),
    -- An intent the dispatcher carries no further names why, so an operator can
    -- tell a deployment without a destination from a refused delivery.
    ADD CONSTRAINT scheduling_outbox_set_aside_class
        CHECK (state NOT IN ('dead-lettered','expired') OR last_failure_class IS NOT NULL),
    ADD CONSTRAINT scheduling_outbox_delivered_class
        CHECK (state <> 'delivered' OR last_failure_class IS NULL);
CREATE INDEX IF NOT EXISTS scheduling_outbox_claim_idx
    ON scheduling_outbox(claim_id, purpose);

CREATE TABLE IF NOT EXISTS scheduling_attempts (
    attempt_id uuid PRIMARY KEY,
    actor_issuer text,
    actor_subject text,
    scope text NOT NULL,
    idempotency_key text,
    request_hash text NOT NULL,
    state text NOT NULL CHECK (state IN ('completed','refused')),
    status_code integer NOT NULL,
    -- The retention sweep tombstones a receipt rather than deleting it: the
    -- row keeps the key and the request it answered, and drops only the
    -- answer. A key whose receipt is gone is spent, not free, so a retry
    -- after the period is refused instead of executed a second time.
    receipt jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    erased_at timestamptz,
    key_reference text NOT NULL CHECK (key_reference ~ '^sha256:[0-9a-f]{64}$'),
    CHECK (erased_at IS NOT NULL OR receipt IS NOT NULL),
    CONSTRAINT scheduling_attempts_key_reference_key UNIQUE (key_reference),
    CONSTRAINT scheduling_attempts_raw_caller_check CHECK (
        (erased_at IS NULL
            AND actor_issuer IS NOT NULL AND actor_issuer <> ''
            AND actor_subject IS NOT NULL AND actor_subject <> ''
            AND idempotency_key IS NOT NULL AND idempotency_key <> '')
        OR (erased_at IS NOT NULL
            AND actor_issuer IS NULL AND actor_subject IS NULL AND idempotency_key IS NULL)
    )
);
CREATE INDEX IF NOT EXISTS scheduling_attempts_expiry_idx
    ON scheduling_attempts(expires_at)
    WHERE erased_at IS NULL;

CREATE TABLE IF NOT EXISTS scheduling_cursors (
    cursor_id uuid PRIMARY KEY,
    context text NOT NULL,
    position jsonb NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS scheduling_cursors_expiry_idx
    ON scheduling_cursors(expires_at);

CREATE TABLE IF NOT EXISTS scheduling_windows (
    window_id text PRIMARY KEY,
    window_record jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scheduling_window_revision_heads (
    window_id text PRIMARY KEY,
    window_record jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Source heads serialize one independently authorized reconciliation stream.
-- The source id is an operator binding, never selected from a request body.
-- Exact-digest replay returns the bounded result of the original mutation;
-- the runtime refuses a replay whose recorded outcome is absent instead of
-- fabricating one.
CREATE TABLE IF NOT EXISTS scheduling_busy_source_heads (
    source_id text PRIMARY KEY
        CHECK (source_id <> '' AND octet_length(source_id) <= 128),
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    last_request_digest text
        CHECK (last_request_digest ~ '^sha256:[0-9a-f]{64}$'),
    updated_at timestamptz NOT NULL DEFAULT now(),
    last_outcome jsonb,
    CONSTRAINT scheduling_busy_source_heads_digest_check CHECK (
        (revision = 0 AND last_request_digest IS NULL)
        OR (revision > 0 AND last_request_digest IS NOT NULL)
    ),
    CONSTRAINT scheduling_busy_source_heads_outcome_check CHECK (
        last_outcome IS NULL OR jsonb_typeof(last_outcome) = 'object'
    )
);

-- Coverage is per source and resource. Allocation admission treats absent,
-- expired, or unavailable coverage conservatively. A source outage updates
-- this row without erasing the last known busy facts.
CREATE TABLE IF NOT EXISTS scheduling_busy_source_coverage (
    source_id text NOT NULL
        REFERENCES scheduling_busy_source_heads(source_id),
    resource_id text NOT NULL
        CHECK (resource_id <> '' AND octet_length(resource_id) <= 128),
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    status text NOT NULL CHECK (status IN ('fresh', 'unavailable')),
    coverage_start timestamptz NOT NULL,
    coverage_end timestamptz NOT NULL,
    observed_at timestamptz NOT NULL,
    fresh_until timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (source_id, resource_id),
    CONSTRAINT scheduling_busy_source_coverage_interval_check
        CHECK (coverage_start < coverage_end),
    CONSTRAINT scheduling_busy_source_coverage_freshness_check CHECK (
        (status = 'fresh'
            AND fresh_until IS NOT NULL
            AND observed_at < fresh_until)
        OR (status = 'unavailable' AND fresh_until IS NULL)
    )
);
CREATE INDEX IF NOT EXISTS scheduling_busy_source_coverage_resource_idx
    ON scheduling_busy_source_coverage(resource_id, source_id);

-- One external occurrence is stable across retries and process restarts.
-- Rows deliberately contain only correlation, version, resource, and time;
-- event text, attendees, organizers, and absence reasons have no column.
CREATE TABLE IF NOT EXISTS scheduling_busy_intervals (
    source_id text NOT NULL
        REFERENCES scheduling_busy_source_heads(source_id),
    resource_id text NOT NULL
        CHECK (resource_id <> '' AND octet_length(resource_id) <= 128),
    external_uid text NOT NULL
        CHECK (external_uid <> '' AND octet_length(external_uid) <= 512),
    external_revision text NOT NULL
        CHECK (external_revision <> '' AND octet_length(external_revision) <= 256),
    busy_start timestamptz NOT NULL,
    busy_end timestamptz NOT NULL,
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    observed_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (source_id, resource_id, external_uid),
    CONSTRAINT scheduling_busy_intervals_interval_check
        CHECK (busy_start < busy_end)
);
CREATE INDEX IF NOT EXISTS scheduling_busy_intervals_resource_interval_idx
    ON scheduling_busy_intervals(resource_id, busy_start, busy_end, source_id);

-- The activation ledger is append-only. The latest apply_order names the
-- package this database serves.
CREATE TABLE IF NOT EXISTS scheduling_activations (
    activation_id uuid PRIMARY KEY,
    apply_order bigint NOT NULL UNIQUE CHECK (apply_order > 0),
    package_digest text NOT NULL CHECK (package_digest ~ '^sha256:[0-9a-f]{64}$'),
    predecessor_package_digest text
        CHECK (predecessor_package_digest ~ '^sha256:[0-9a-f]{64}$'),
    database_id text NOT NULL CHECK (octet_length(database_id) BETWEEN 1 AND 256),
    plan_kind text NOT NULL CHECK (plan_kind IN ('initial', 'successor')),
    applied_at timestamptz NOT NULL,
    operator_reference_hash text CHECK (octet_length(operator_reference_hash) <= 256),
    backup_references text[] NOT NULL DEFAULT '{}'
        CHECK (cardinality(backup_references) <= 16),
    role_mode text NOT NULL CHECK (role_mode IN ('single', 'split')),
    runtime_role text NOT NULL CHECK (octet_length(runtime_role) BETWEEN 1 AND 256),
    CHECK ((plan_kind = 'initial') = (predecessor_package_digest IS NULL))
);

-- Every runtime transaction that mutates logical claims or current physical
-- supply must first execute:
--
--     SET LOCAL registry_scheduling.allocation_writer = 'v2'
--
-- A writer that knows only the single supply column on scheduling_claims
-- could overbook child allocations or change only one part of a logical
-- bundle, so these triggers refuse a write without that marker. This is a
-- fail-closed writer fence, not an authorization boundary. The activation
-- trust check recognizes these migration-owned triggers.
CREATE FUNCTION scheduling_require_allocation_writer_v2()
RETURNS trigger
LANGUAGE plpgsql
AS $body$
BEGIN
    IF current_setting('registry_scheduling.allocation_writer', true) IS DISTINCT FROM 'v2' THEN
        RAISE EXCEPTION 'the Scheduling writer predates atomic allocations'
            USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$body$;

CREATE TRIGGER scheduling_claims_allocation_writer_v2
    BEFORE INSERT OR UPDATE OR DELETE ON scheduling_claims
    FOR EACH ROW EXECUTE FUNCTION scheduling_require_allocation_writer_v2();
CREATE TRIGGER scheduling_claim_allocations_writer_v2
    BEFORE INSERT OR UPDATE OR DELETE ON scheduling_claim_allocations
    FOR EACH ROW EXECUTE FUNCTION scheduling_require_allocation_writer_v2();
CREATE TRIGGER scheduling_pool_members_allocation_writer_v2
    BEFORE INSERT OR UPDATE OR DELETE ON scheduling_pool_members
    FOR EACH ROW EXECUTE FUNCTION scheduling_require_allocation_writer_v2();
CREATE TRIGGER scheduling_pools_allocation_writer_v2
    BEFORE INSERT OR UPDATE OR DELETE ON scheduling_pools
    FOR EACH ROW EXECUTE FUNCTION scheduling_require_allocation_writer_v2();
CREATE TRIGGER scheduling_supply_allocation_writer_v2
    BEFORE INSERT OR UPDATE OR DELETE ON scheduling_supply
    FOR EACH ROW EXECUTE FUNCTION scheduling_require_allocation_writer_v2();
CREATE TRIGGER scheduling_windows_allocation_writer_v2
    BEFORE INSERT OR UPDATE OR DELETE ON scheduling_windows
    FOR EACH ROW EXECUTE FUNCTION scheduling_require_allocation_writer_v2();
CREATE TRIGGER scheduling_window_revision_heads_allocation_writer_v2
    BEFORE INSERT OR UPDATE OR DELETE ON scheduling_window_revision_heads
    FOR EACH ROW EXECUTE FUNCTION scheduling_require_allocation_writer_v2();
CREATE TRIGGER scheduling_meta_allocation_writer_v2
    BEFORE UPDATE OR DELETE ON scheduling_meta
    FOR EACH ROW EXECUTE FUNCTION scheduling_require_allocation_writer_v2();
