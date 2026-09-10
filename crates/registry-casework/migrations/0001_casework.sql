CREATE TABLE IF NOT EXISTS casework_meta (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    directory_revision bigint NOT NULL CHECK (directory_revision >= 0)
);
INSERT INTO casework_meta (singleton, directory_revision) VALUES (true, 0)
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS casework_teams (
    team_id text PRIMARY KEY,
    revision bigint NOT NULL CHECK (revision > 0)
);
CREATE TABLE IF NOT EXISTS casework_memberships (
    team_id text NOT NULL REFERENCES casework_teams(team_id) ON DELETE CASCADE,
    issuer text NOT NULL,
    subject text NOT NULL,
    membership_kind text NOT NULL CHECK (membership_kind IN ('staff', 'supervisor')),
    PRIMARY KEY (team_id, issuer, subject, membership_kind)
);
CREATE TABLE IF NOT EXISTS casework_queue_service (
    queue_id text PRIMARY KEY,
    team_id text NOT NULL REFERENCES casework_teams(team_id),
    revision bigint NOT NULL CHECK (revision > 0)
);
CREATE TABLE IF NOT EXISTS casework_directory_events (
    event_id uuid PRIMARY KEY,
    directory_revision bigint NOT NULL,
    event_kind text NOT NULL,
    occurred_at timestamptz NOT NULL,
    actor_issuer text NOT NULL,
    actor_subject text NOT NULL,
    profile_id text NOT NULL,
    detail jsonb NOT NULL
);

CREATE TABLE IF NOT EXISTS casework_subjects (
    source_id text NOT NULL,
    subject_kind text NOT NULL,
    subject_id text NOT NULL,
    binding_generation text NOT NULL,
    wanted_revision bigint NOT NULL DEFAULT 0 CHECK (wanted_revision >= 0),
    applied_revision bigint NOT NULL DEFAULT 0 CHECK (applied_revision >= 0),
    representation_etag text,
    active boolean NOT NULL DEFAULT true,
    sync_pending boolean NOT NULL DEFAULT true,
    sync_lease_until timestamptz,
    last_sweep_at timestamptz,
    PRIMARY KEY (source_id, subject_kind, subject_id)
);

ALTER TABLE casework_subjects
    ADD COLUMN IF NOT EXISTS representation_etag text;

CREATE TABLE IF NOT EXISTS casework_items (
    item_id uuid PRIMARY KEY,
    source_id text NOT NULL,
    subject_kind text NOT NULL,
    subject_id text NOT NULL,
    occurrence_kind text NOT NULL CHECK (occurrence_kind IN ('review', 'application')),
    occurrence_key text NOT NULL,
    stage text,
    binding jsonb NOT NULL,
    state text NOT NULL CHECK (state IN ('open','claimed','waiting_applicant','waiting_application','synchronizing','completed','superseded','cancelled')),
    queue_id text NOT NULL,
    holder_issuer text,
    holder_subject text,
    revision bigint NOT NULL CHECK (revision > 0),
    first_observed_at timestamptz NOT NULL,
    passive_due_at timestamptz,
    updated_at timestamptz NOT NULL
);
ALTER TABLE casework_items
    ADD COLUMN IF NOT EXISTS occurrence_key text;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM casework_items WHERE occurrence_key IS NULL) THEN
        RAISE EXCEPTION 'legacy Casework items require an explicit adapter occurrence key migration';
    END IF;
END $$;
ALTER TABLE casework_items ALTER COLUMN occurrence_key SET NOT NULL;
ALTER TABLE casework_items
    DROP CONSTRAINT IF EXISTS casework_items_source_id_subject_kind_subject_id_fkey;
DROP INDEX IF EXISTS casework_items_occurrence_idx;
CREATE UNIQUE INDEX IF NOT EXISTS casework_items_occurrence_idx
    ON casework_items(source_id, subject_kind, subject_id, occurrence_key);
CREATE INDEX IF NOT EXISTS casework_items_queue_active_idx
    ON casework_items(queue_id, passive_due_at, item_id)
    WHERE state NOT IN ('completed','superseded','cancelled');

CREATE TABLE IF NOT EXISTS casework_history (
    event_id uuid PRIMARY KEY,
    item_id uuid NOT NULL REFERENCES casework_items(item_id),
    item_revision bigint NOT NULL,
    kind text NOT NULL,
    occurred_at timestamptz NOT NULL,
    actor_issuer text,
    actor_subject text,
    profile_id text NOT NULL,
    detail jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS casework_history_item_idx
    ON casework_history(item_id, occurred_at, event_id);

CREATE TABLE IF NOT EXISTS casework_events (
    event_id uuid PRIMARY KEY REFERENCES casework_history(event_id),
    item_id uuid NOT NULL REFERENCES casework_items(item_id),
    item_revision bigint NOT NULL,
    event_kind text NOT NULL,
    occurred_at timestamptz NOT NULL,
    actor_reference text,
    detail jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS casework_audit_outbox (
    event_id uuid PRIMARY KEY,
    audit_record jsonb NOT NULL,
    published_at timestamptz
);

CREATE TABLE IF NOT EXISTS casework_idempotency (
    issuer text NOT NULL,
    subject text NOT NULL,
    profile_id text NOT NULL,
    operation text NOT NULL,
    resource text NOT NULL,
    idempotency_key text NOT NULL,
    request_hash text NOT NULL,
    response jsonb,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (issuer, subject, profile_id, operation, resource, idempotency_key)
);

CREATE TABLE IF NOT EXISTS casework_drafts (
    item_id uuid NOT NULL REFERENCES casework_items(item_id),
    author_issuer text NOT NULL,
    author_subject text NOT NULL,
    binding jsonb NOT NULL,
    reason text NOT NULL CHECK (octet_length(reason) <= 16384),
    flagged_fields jsonb NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (item_id, author_issuer, author_subject)
);

CREATE TABLE IF NOT EXISTS casework_source_events (
    source_id text NOT NULL,
    deduplication_key text NOT NULL,
    subject_kind text NOT NULL,
    subject_id text NOT NULL,
    ordered_revision bigint NOT NULL CHECK (ordered_revision > 0),
    received_at timestamptz NOT NULL,
    PRIMARY KEY (source_id, deduplication_key)
);

CREATE TABLE IF NOT EXISTS casework_source_status (
    source_id text PRIMARY KEY,
    binding_generation text NOT NULL,
    remote_complete boolean NOT NULL,
    unavailable boolean NOT NULL,
    checked_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS casework_attempts (
    attempt_id uuid PRIMARY KEY,
    item_id uuid NOT NULL REFERENCES casework_items(item_id),
    actor_issuer text NOT NULL,
    actor_subject text NOT NULL,
    casework_profile_id text NOT NULL,
    source_profile_id text NOT NULL,
    item_revision bigint NOT NULL,
    request_hash text NOT NULL,
    operation text NOT NULL,
    decision_reason text CHECK (decision_reason IS NULL OR octet_length(decision_reason) <= 4096),
    flagged_fields jsonb NOT NULL,
    idempotency_key text NOT NULL,
    displayed_binding jsonb NOT NULL,
    recovery_evidence bytea NOT NULL CHECK (octet_length(recovery_evidence) BETWEEN 1 AND 65536),
    state text NOT NULL CHECK (state IN ('pending','uncertain','completed','refused')),
    execution_token uuid NOT NULL,
    execution_lease_until timestamptz NOT NULL,
    receipt jsonb,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (item_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS casework_correction_context (
    item_id uuid PRIMARY KEY REFERENCES casework_items(item_id),
    source_binding jsonb NOT NULL,
    reason text NOT NULL CHECK (octet_length(reason) <= 4096),
    flagged_fields jsonb NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS casework_attempts_one_live_idx
    ON casework_attempts(item_id)
    WHERE state IN ('pending','uncertain');

CREATE TABLE IF NOT EXISTS casework_cursors (
    cursor_id uuid PRIMARY KEY,
    issuer text NOT NULL,
    subject text NOT NULL,
    casework_profile_id text NOT NULL,
    source_profile_id text NOT NULL,
    context text NOT NULL,
    last_passive_due_at timestamptz,
    last_item_id uuid,
    expires_at timestamptz NOT NULL
);
