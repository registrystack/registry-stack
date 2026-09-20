-- Unified producer and standalone review model.
--
-- The earlier source-item and hosted-item schemas were experimental and cannot
-- be translated without inventing a policy snapshot, producer correlation, or
-- task ownership. Refuse occupied legacy state. An operator must deliberately
-- finish or discard disposable workflow state before this migration runs.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM casework_items LIMIT 1)
       OR EXISTS (SELECT 1 FROM casework_hosted_items LIMIT 1)
       OR EXISTS (SELECT 1 FROM casework_task_grants LIMIT 1)
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'legacy Casework workflow state cannot be migrated to unified reviews',
            HINT = 'finish or export retained work under the old runtime, back up the database, then perform the documented deliberate cutover; disposable development state may be recreated explicitly';
    END IF;
END
$$;

CREATE TABLE casework_review_requests (
    request_id uuid PRIMARY KEY,
    producer_id text NOT NULL CHECK (octet_length(producer_id) BETWEEN 1 AND 128),
    producer_issuer text NOT NULL CHECK (octet_length(producer_issuer) BETWEEN 1 AND 2048),
    producer_subject text NOT NULL CHECK (octet_length(producer_subject) BETWEEN 1 AND 2048),
    source_namespace text NOT NULL CHECK (octet_length(source_namespace) BETWEEN 1 AND 128),
    subject_source text NOT NULL CHECK (octet_length(subject_source) BETWEEN 1 AND 128),
    subject_type text NOT NULL CHECK (octet_length(subject_type) BETWEEN 1 AND 128),
    subject_id text NOT NULL CHECK (octet_length(subject_id) BETWEEN 1 AND 128),
    subject_version text NOT NULL CHECK (octet_length(subject_version) BETWEEN 1 AND 128),
    subject_digest text NOT NULL CHECK (subject_digest ~ '^sha256:[0-9a-f]{64}$'),
    requester_reference text NOT NULL CHECK (octet_length(requester_reference) BETWEEN 1 AND 256),
    initiator_issuer text CHECK (initiator_issuer IS NULL OR octet_length(initiator_issuer) BETWEEN 1 AND 2048),
    initiator_subject text CHECK (initiator_subject IS NULL OR octet_length(initiator_subject) BETWEEN 1 AND 2048),
    context_strategy text NOT NULL CHECK (context_strategy IN ('submitted','source')),
    context jsonb NOT NULL CHECK (octet_length(context::text) <= 65536),
    -- JCS admits compact exponent-form binary64 values that PostgreSQL jsonb
    -- renders as expanded decimal text. One MiB covers the worst-case expansion
    -- of an admitted 16 KiB canonical value while retaining a hard storage bound.
    result_constraints jsonb CHECK (result_constraints IS NULL OR octet_length(result_constraints::text) <= 1048576),
    policy_id text NOT NULL CHECK (octet_length(policy_id) BETWEEN 1 AND 128),
    policy_version text NOT NULL CHECK (octet_length(policy_version) BETWEEN 1 AND 128),
    policy_digest text NOT NULL CHECK (policy_digest ~ '^sha256:[0-9a-f]{64}$'),
    -- Canonical policy snapshots are capped at 256 KiB. PostgreSQL jsonb text
    -- can expand compact JCS exponent-form binary64 values, so the same 64x
    -- storage factor used for other bounded review JSON permits up to 16 MiB.
    policy_snapshot jsonb NOT NULL CHECK (octet_length(policy_snapshot::text) <= 16777216),
    submission_digest text NOT NULL CHECK (submission_digest ~ '^sha256:[0-9a-f]{64}$'),
    completion_destination text CHECK (completion_destination IS NULL OR octet_length(completion_destination) BETWEEN 1 AND 128),
    completion_recipient_binding text CHECK (completion_recipient_binding IS NULL OR octet_length(completion_recipient_binding) BETWEEN 1 AND 256),
    lifecycle text NOT NULL CHECK (lifecycle IN ('reviewing','approved','rejected','changes_requested','answered','cancelled','superseded')),
    active_stage_index integer CHECK (active_stage_index IS NULL OR active_stage_index >= 0),
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    terminal_at timestamptz,
    result_available_until timestamptz,
    accountability_retained_until timestamptz,
    CHECK ((lifecycle = 'reviewing') = (terminal_at IS NULL)),
    CHECK ((lifecycle = 'reviewing') = (active_stage_index IS NOT NULL)),
    CHECK ((lifecycle = 'reviewing') = (result_available_until IS NULL)),
    CHECK ((lifecycle = 'reviewing') = (accountability_retained_until IS NULL)),
    CHECK ((initiator_issuer IS NULL) = (initiator_subject IS NULL)),
    CHECK ((completion_destination IS NULL) = (completion_recipient_binding IS NULL)),
    CHECK (result_available_until IS NULL OR result_available_until > terminal_at),
    CHECK (accountability_retained_until IS NULL OR accountability_retained_until >= result_available_until)
);
ALTER TABLE casework_review_requests
    ADD CONSTRAINT casework_review_requests_request_producer_unique
    UNIQUE (request_id, producer_id);
ALTER TABLE casework_review_requests
    ADD CONSTRAINT casework_review_requests_completion_binding_unique
    UNIQUE (request_id, completion_destination, completion_recipient_binding);
ALTER TABLE casework_review_requests
    ADD CONSTRAINT casework_review_requests_submission_binding_unique
    UNIQUE (
        request_id,
        producer_id,
        source_namespace,
        subject_source,
        subject_type,
        subject_id,
        subject_version,
        policy_id,
        submission_digest
    );
CREATE UNIQUE INDEX casework_review_request_subject_idx
    ON casework_review_requests(
        producer_id,
        source_namespace,
        subject_source,
        subject_type,
        subject_id,
        subject_version,
        policy_id
    );
CREATE INDEX casework_review_request_retention_idx
    ON casework_review_requests(result_available_until, request_id)
    WHERE terminal_at IS NOT NULL;

CREATE TABLE casework_review_submission_reservations (
    binding_digest text NOT NULL UNIQUE CHECK (binding_digest ~ '^sha256:[0-9a-f]{64}$'),
    producer_id text NOT NULL CHECK (octet_length(producer_id) BETWEEN 1 AND 128),
    source_namespace text NOT NULL CHECK (octet_length(source_namespace) BETWEEN 1 AND 128),
    subject_source text NOT NULL CHECK (octet_length(subject_source) BETWEEN 1 AND 128),
    subject_type text NOT NULL CHECK (octet_length(subject_type) BETWEEN 1 AND 128),
    subject_id text NOT NULL CHECK (octet_length(subject_id) BETWEEN 1 AND 128),
    subject_version text NOT NULL CHECK (octet_length(subject_version) BETWEEN 1 AND 128),
    policy_id text NOT NULL CHECK (octet_length(policy_id) BETWEEN 1 AND 128),
    submission_digest text NOT NULL CHECK (submission_digest ~ '^sha256:[0-9a-f]{64}$'),
    request_id uuid,
    recovery_deadline timestamptz NOT NULL,
    retained_until timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (
        producer_id,
        source_namespace,
        subject_source,
        subject_type,
        subject_id,
        subject_version,
        policy_id
    ),
    CHECK (retained_until >= recovery_deadline),
    FOREIGN KEY (request_id) REFERENCES casework_review_requests(request_id)
        ON DELETE SET NULL
);
CREATE INDEX casework_review_submission_retention_idx
    ON casework_review_submission_reservations(retained_until, producer_id, subject_id);

CREATE TABLE casework_review_tasks (
    task_id uuid PRIMARY KEY,
    request_id uuid NOT NULL REFERENCES casework_review_requests(request_id) ON DELETE CASCADE,
    stage_index integer NOT NULL CHECK (stage_index >= 0),
    stage_id text NOT NULL CHECK (octet_length(stage_id) BETWEEN 1 AND 128),
    slot integer NOT NULL CHECK (slot >= 0),
    queue_id text NOT NULL CHECK (octet_length(queue_id) BETWEEN 1 AND 128),
    state text NOT NULL CHECK (state IN ('open','claimed','decided','closed')),
    holder_issuer text CHECK (holder_issuer IS NULL OR octet_length(holder_issuer) BETWEEN 1 AND 2048),
    holder_subject text CHECK (holder_subject IS NULL OR octet_length(holder_subject) BETWEEN 1 AND 2048),
    assignment_kind text CHECK (assignment_kind IS NULL OR assignment_kind IN ('claim','nomination','delegation','absence_cover')),
    assignment_owner_issuer text CHECK (assignment_owner_issuer IS NULL OR octet_length(assignment_owner_issuer) BETWEEN 1 AND 2048),
    assignment_owner_subject text CHECK (assignment_owner_subject IS NULL OR octet_length(assignment_owner_subject) BETWEEN 1 AND 2048),
    assigned_by_issuer text CHECK (assigned_by_issuer IS NULL OR octet_length(assigned_by_issuer) BETWEEN 1 AND 2048),
    assigned_by_subject text CHECK (assigned_by_subject IS NULL OR octet_length(assigned_by_subject) BETWEEN 1 AND 2048),
    assignment_absence_ids uuid[] NOT NULL DEFAULT '{}',
    staffing_diagnostic text CHECK (staffing_diagnostic IS NULL OR staffing_diagnostic = 'no_cover_available'),
    deadline_at timestamptz,
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    settled_at timestamptz,
    UNIQUE (request_id, stage_index, slot),
    UNIQUE (task_id, request_id),
    UNIQUE (task_id, request_id, stage_index),
    CHECK ((holder_issuer IS NULL) = (holder_subject IS NULL)),
    CHECK ((holder_issuer IS NULL) = (assignment_kind IS NULL)),
    CHECK ((assignment_owner_issuer IS NULL) = (assignment_owner_subject IS NULL)),
    CHECK ((assigned_by_issuer IS NULL) = (assigned_by_subject IS NULL)),
    CHECK (
        (state = 'open' AND holder_issuer IS NULL)
        OR (state IN ('claimed','decided') AND holder_issuer IS NOT NULL)
        OR state = 'closed'
    ),
    CHECK ((state IN ('decided','closed')) = (settled_at IS NOT NULL))
);
CREATE INDEX casework_review_task_inbox_idx
    ON casework_review_tasks(queue_id, deadline_at, created_at, task_id)
    WHERE state IN ('open','claimed');
CREATE UNIQUE INDEX casework_review_task_holder_stage_idx
    ON casework_review_tasks(request_id, stage_index, holder_issuer, holder_subject)
    WHERE holder_issuer IS NOT NULL AND state IN ('open','claimed');

CREATE TABLE casework_review_task_drafts (
    task_id uuid PRIMARY KEY REFERENCES casework_review_tasks(task_id) ON DELETE CASCADE,
    actor_issuer text NOT NULL CHECK (octet_length(actor_issuer) BETWEEN 1 AND 2048),
    actor_subject text NOT NULL CHECK (octet_length(actor_subject) BETWEEN 1 AND 2048),
    body jsonb NOT NULL CHECK (octet_length(body::text) <= 16384),
    revision bigint NOT NULL CHECK (revision > 0),
    updated_at timestamptz NOT NULL
);

CREATE TABLE casework_review_decisions (
    decision_id uuid PRIMARY KEY,
    request_id uuid NOT NULL REFERENCES casework_review_requests(request_id) ON DELETE CASCADE,
    task_id uuid NOT NULL UNIQUE,
    stage_index integer NOT NULL CHECK (stage_index >= 0),
    actor_issuer text NOT NULL CHECK (octet_length(actor_issuer) BETWEEN 1 AND 2048),
    actor_subject text NOT NULL CHECK (octet_length(actor_subject) BETWEEN 1 AND 2048),
    profile_id text NOT NULL CHECK (octet_length(profile_id) BETWEEN 1 AND 128),
    decision text NOT NULL CHECK (decision IN ('approve','reject','changes_requested','answer')),
    outcome text CHECK (outcome IS NULL OR octet_length(outcome) BETWEEN 1 AND 128),
    result jsonb CHECK (result IS NULL OR octet_length(result::text) <= 1048576),
    private_reason text CHECK (private_reason IS NULL OR octet_length(private_reason) <= 2000),
    decided_at timestamptz NOT NULL,
    UNIQUE (request_id, stage_index, actor_issuer, actor_subject),
    FOREIGN KEY (task_id, request_id, stage_index)
        REFERENCES casework_review_tasks(task_id, request_id, stage_index) ON DELETE CASCADE,
    CHECK (
        (decision = 'approve' AND outcome IS NULL AND result IS NULL)
        OR (decision IN ('reject','changes_requested','answer') AND outcome IS NOT NULL)
    )
);

CREATE TABLE casework_review_results (
    result_id uuid PRIMARY KEY,
    request_id uuid NOT NULL UNIQUE REFERENCES casework_review_requests(request_id) ON DELETE CASCADE,
    status text NOT NULL CHECK (status IN ('approved','rejected','changes_requested','answered','cancelled','superseded')),
    outcome text CHECK (outcome IS NULL OR octet_length(outcome) BETWEEN 1 AND 128),
    result jsonb CHECK (result IS NULL OR octet_length(result::text) <= 1048576),
    completed_at timestamptz NOT NULL,
    available_until timestamptz NOT NULL,
    CHECK (available_until > completed_at),
    CHECK (status NOT IN ('approved','cancelled','superseded') OR (outcome IS NULL AND result IS NULL)),
    CHECK (status NOT IN ('rejected','changes_requested','answered') OR outcome IS NOT NULL),
    UNIQUE (result_id, request_id)
);

CREATE TABLE casework_review_terminal_events (
    event_id uuid PRIMARY KEY,
    feed_position bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    request_id uuid NOT NULL UNIQUE,
    result_id uuid NOT NULL UNIQUE,
    producer_id text NOT NULL,
    completed_at timestamptz NOT NULL,
    retained_until timestamptz NOT NULL,
    UNIQUE (event_id, request_id),
    CHECK (retained_until > completed_at),
    FOREIGN KEY (result_id, request_id)
        REFERENCES casework_review_results(result_id, request_id) ON DELETE CASCADE,
    FOREIGN KEY (request_id, producer_id)
        REFERENCES casework_review_requests(request_id, producer_id) ON DELETE CASCADE
);
CREATE INDEX casework_review_terminal_feed_idx
    ON casework_review_terminal_events(producer_id, feed_position);

CREATE TABLE casework_review_completion_outbox (
    event_id uuid PRIMARY KEY,
    request_id uuid NOT NULL,
    destination_id text NOT NULL CHECK (octet_length(destination_id) BETWEEN 1 AND 128),
    recipient_binding text NOT NULL CHECK (octet_length(recipient_binding) BETWEEN 1 AND 256),
    state text NOT NULL CHECK (state IN ('pending','leased','delivered','exhausted')),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at timestamptz NOT NULL,
    lease_until timestamptz,
    last_failure_class text CHECK (last_failure_class IS NULL OR octet_length(last_failure_class) BETWEEN 1 AND 128),
    retained_until timestamptz NOT NULL,
    delivered_at timestamptz,
    CHECK ((state = 'delivered') = (delivered_at IS NOT NULL)),
    CHECK ((state = 'leased') = (lease_until IS NOT NULL)),
    CHECK (retained_until > next_attempt_at),
    FOREIGN KEY (event_id, request_id)
        REFERENCES casework_review_terminal_events(event_id, request_id) ON DELETE CASCADE,
    FOREIGN KEY (request_id, destination_id, recipient_binding)
        REFERENCES casework_review_requests(request_id, completion_destination, completion_recipient_binding)
);
CREATE INDEX casework_review_completion_due_idx
    ON casework_review_completion_outbox(next_attempt_at, event_id)
    WHERE state IN ('pending','leased');
CREATE INDEX casework_review_completion_retention_idx
    ON casework_review_completion_outbox(retained_until, event_id);

CREATE TABLE casework_review_history (
    event_id uuid PRIMARY KEY,
    request_id uuid NOT NULL REFERENCES casework_review_requests(request_id) ON DELETE CASCADE,
    task_id uuid,
    kind text NOT NULL CHECK (octet_length(kind) BETWEEN 1 AND 128),
    actor_ref text CHECK (actor_ref IS NULL OR octet_length(actor_ref) BETWEEN 1 AND 256),
    detail jsonb NOT NULL CHECK (octet_length(detail::text) <= 16384),
    occurred_at timestamptz NOT NULL,
    FOREIGN KEY (task_id, request_id)
        REFERENCES casework_review_tasks(task_id, request_id) ON DELETE SET NULL (task_id)
);
CREATE INDEX casework_review_history_request_idx
    ON casework_review_history(request_id, occurred_at, event_id);

CREATE TABLE casework_review_accountability (
    event_id uuid PRIMARY KEY,
    request_id uuid NOT NULL,
    task_id uuid NOT NULL,
    queue_id text NOT NULL CHECK (octet_length(queue_id) BETWEEN 1 AND 128),
    actor_ref text NOT NULL CHECK (octet_length(actor_ref) BETWEEN 1 AND 256),
    actor_issuer text NOT NULL CHECK (octet_length(actor_issuer) BETWEEN 1 AND 2048),
    actor_subject text NOT NULL CHECK (octet_length(actor_subject) BETWEEN 1 AND 2048),
    profile_id text NOT NULL CHECK (octet_length(profile_id) BETWEEN 1 AND 128),
    decision text NOT NULL CHECK (octet_length(decision) BETWEEN 1 AND 128),
    private_reason text CHECK (private_reason IS NULL OR octet_length(private_reason) <= 2000),
    result_digest text CHECK (result_digest IS NULL OR result_digest ~ '^sha256:[0-9a-f]{64}$'),
    occurred_at timestamptz NOT NULL,
    retained_until timestamptz NOT NULL,
    CHECK (retained_until > occurred_at),
    FOREIGN KEY (request_id) REFERENCES casework_review_requests(request_id) ON DELETE CASCADE
);
CREATE INDEX casework_review_accountability_retention_idx
    ON casework_review_accountability(retained_until, event_id);

-- Review-native institutional task grants. These deliberately bind the exact
-- active reviewer task rather than treating a terminal approval as authority.
CREATE TABLE casework_review_task_grants (
    grant_id uuid PRIMARY KEY,
    task_id uuid NOT NULL,
    request_id uuid NOT NULL,
    task_revision bigint NOT NULL CHECK (task_revision > 0),
    holder_issuer text NOT NULL CHECK (octet_length(holder_issuer) BETWEEN 1 AND 2048),
    holder_subject text NOT NULL CHECK (octet_length(holder_subject) BETWEEN 1 AND 2048),
    approver_profile text NOT NULL CHECK (octet_length(approver_profile) BETWEEN 1 AND 128),
    approver_role text NOT NULL CHECK (approver_role IN ('staff','supervisor')),
    idempotency_key text NOT NULL CHECK (octet_length(idempotency_key) BETWEEN 1 AND 256),
    request_hash text NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    -- Application admission remains capped at 65,536 compact JSON bytes. JSONB
    -- text rendering inserts separator whitespace, so retain a bounded 2x
    -- storage envelope for every application-admitted review grant.
    record jsonb NOT NULL CHECK (octet_length(record::text) <= 131072),
    approved_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (
        expires_at > approved_at AND expires_at <= approved_at + interval '900 seconds'
    ),
    invalidated_at timestamptz,
    invalidation_reason text CHECK (
        invalidation_reason IN ('revoked','eligibility','template','source')
    ),
    FOREIGN KEY (task_id,request_id)
        REFERENCES casework_review_tasks(task_id,request_id) ON DELETE CASCADE,
    UNIQUE(task_id,holder_issuer,holder_subject,approver_profile,idempotency_key)
);
CREATE INDEX casework_review_task_grants_active_idx
    ON casework_review_task_grants(expires_at,task_id)
    WHERE invalidated_at IS NULL;
CREATE INDEX casework_review_task_grants_task_idx
    ON casework_review_task_grants(task_id,approved_at,grant_id);

CREATE TABLE casework_review_clock_occurrences (
    clock_occurrence_id uuid PRIMARY KEY,
    clock_id text NOT NULL CHECK (octet_length(clock_id) BETWEEN 1 AND 128),
    scope text NOT NULL CHECK (scope IN ('subject','activity')),
    correlation_key text NOT NULL CHECK (octet_length(correlation_key) BETWEEN 1 AND 256),
    subject_source text NOT NULL CHECK (octet_length(subject_source) BETWEEN 1 AND 128),
    subject_type text NOT NULL CHECK (octet_length(subject_type) BETWEEN 1 AND 128),
    subject_id text NOT NULL CHECK (octet_length(subject_id) BETWEEN 1 AND 128),
    request_id uuid REFERENCES casework_review_requests(request_id) ON DELETE SET NULL,
    task_id uuid REFERENCES casework_review_tasks(task_id) ON DELETE SET NULL,
    policy_digest text NOT NULL CHECK (policy_digest ~ '^sha256:[0-9a-f]{64}$'),
    policy jsonb NOT NULL CHECK (octet_length(policy::text) <= 65536),
    state text NOT NULL CHECK (state IN ('running','paused','completed','cancelled','source_facts_missing')),
    anchor_at timestamptz NOT NULL,
    due_at timestamptz,
    at_risk_at timestamptz,
    paused_at timestamptz,
    paused_seconds bigint NOT NULL DEFAULT 0 CHECK (paused_seconds >= 0),
    completed_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE(subject_source,subject_type,subject_id,clock_id,scope,correlation_key),
    CHECK ((state='paused') = (paused_at IS NOT NULL)),
    CHECK ((state='completed') = (completed_at IS NOT NULL))
);
CREATE INDEX casework_review_clock_request_idx
    ON casework_review_clock_occurrences(request_id,clock_id,clock_occurrence_id);
CREATE INDEX casework_review_clock_subject_idx
    ON casework_review_clock_occurrences(subject_source,subject_type,subject_id,clock_id);
