CREATE TABLE IF NOT EXISTS casework_hosted_items (
    item_id uuid PRIMARY KEY,
    requester_issuer text,
    requester_subject text,
    requester_profile_id text,
    requester_reference text CHECK (requester_reference IS NULL OR octet_length(requester_reference) <= 128),
    display jsonb,
    kind_id text NOT NULL,
    kind_version text NOT NULL,
    kind_policy_digest text NOT NULL,
    kind_policy jsonb NOT NULL,
    queue_id text NOT NULL,
    state text NOT NULL CHECK (state IN ('open','claimed','completed','cancelled')),
    holder_issuer text,
    holder_subject text,
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    terminal_at timestamptz,
    terminal_retained_until timestamptz,
    accountability_retained_until timestamptz,
    CHECK ((state IN ('completed','cancelled')) = (terminal_at IS NOT NULL)),
    CHECK ((requester_issuer IS NULL) = (requester_subject IS NULL)),
    CHECK ((requester_issuer IS NULL) = (requester_profile_id IS NULL)),
    CHECK ((requester_issuer IS NULL) = (requester_reference IS NULL)),
    CHECK ((requester_issuer IS NULL) = (display IS NULL))
);
CREATE INDEX IF NOT EXISTS casework_hosted_items_staff_inbox_idx
    ON casework_hosted_items(queue_id, created_at, item_id)
    WHERE state IN ('open','claimed');
CREATE INDEX IF NOT EXISTS casework_hosted_items_requester_idx
    ON casework_hosted_items(requester_issuer, requester_subject, requester_profile_id, item_id);
CREATE INDEX IF NOT EXISTS casework_hosted_items_retention_idx
    ON casework_hosted_items(terminal_retained_until, item_id)
    WHERE terminal_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS casework_hosted_notes (
    event_id uuid PRIMARY KEY,
    item_id uuid NOT NULL REFERENCES casework_hosted_items(item_id) ON DELETE CASCADE,
    item_revision bigint NOT NULL,
    author_issuer text NOT NULL,
    author_subject text NOT NULL,
    author_profile_id text NOT NULL,
    note text NOT NULL CHECK (octet_length(note) BETWEEN 1 AND 2000),
    created_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS casework_hosted_notes_item_idx
    ON casework_hosted_notes(item_id, created_at, event_id);

CREATE TABLE IF NOT EXISTS casework_hosted_history (
    event_id uuid PRIMARY KEY,
    item_id uuid NOT NULL REFERENCES casework_hosted_items(item_id) ON DELETE CASCADE,
    item_revision bigint NOT NULL,
    kind text NOT NULL,
    occurred_at timestamptz NOT NULL,
    actor_issuer text,
    actor_subject text,
    profile_id text NOT NULL,
    detail jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS casework_hosted_history_item_idx
    ON casework_hosted_history(item_id, occurred_at, event_id);
CREATE INDEX IF NOT EXISTS casework_hosted_history_actor_idx
    ON casework_hosted_history(actor_issuer, actor_subject)
    WHERE actor_issuer IS NOT NULL;

CREATE TABLE IF NOT EXISTS casework_hosted_actor_references (
    actor_ref text PRIMARY KEY,
    issuer text NOT NULL,
    subject text NOT NULL,
    UNIQUE (issuer, subject)
);

CREATE TABLE IF NOT EXISTS casework_hosted_terminal_events (
    event_id uuid PRIMARY KEY,
    item_id uuid NOT NULL UNIQUE REFERENCES casework_hosted_items(item_id) ON DELETE CASCADE,
    requester_issuer text NOT NULL,
    requester_subject text NOT NULL,
    requester_profile_id text NOT NULL,
    requester_reference text NOT NULL,
    state text NOT NULL CHECK (state IN ('completed','cancelled')),
    outcome text,
    cancellation_reason text CHECK (cancellation_reason IS NULL OR octet_length(cancellation_reason) <= 2000),
    actor_ref text REFERENCES casework_hosted_actor_references(actor_ref),
    kind_policy_digest text NOT NULL,
    terminal_at timestamptz NOT NULL,
    retained_until timestamptz NOT NULL,
    CHECK ((state = 'completed') = (outcome IS NOT NULL)),
    CHECK ((state = 'cancelled') = (outcome IS NULL))
);
CREATE INDEX IF NOT EXISTS casework_hosted_terminal_requester_idx
    ON casework_hosted_terminal_events(requester_issuer, requester_subject, requester_profile_id, terminal_at, event_id);
CREATE INDEX IF NOT EXISTS casework_hosted_terminal_retention_idx
    ON casework_hosted_terminal_events(retained_until, event_id);
CREATE INDEX IF NOT EXISTS casework_hosted_terminal_actor_idx
    ON casework_hosted_terminal_events(actor_ref)
    WHERE actor_ref IS NOT NULL;

CREATE TABLE IF NOT EXISTS casework_hosted_accountability (
    event_id uuid PRIMARY KEY,
    item_id uuid NOT NULL,
    actor_ref text NOT NULL REFERENCES casework_hosted_actor_references(actor_ref),
    actor_issuer text NOT NULL,
    actor_subject text NOT NULL,
    profile_id text NOT NULL,
    queue_id text NOT NULL,
    outcome text,
    reason text CHECK (reason IS NULL OR octet_length(reason) <= 2000),
    occurred_at timestamptz NOT NULL,
    retained_until timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS casework_hosted_accountability_retention_idx
    ON casework_hosted_accountability(retained_until, event_id);
CREATE INDEX IF NOT EXISTS casework_hosted_accountability_actor_idx
    ON casework_hosted_accountability(actor_ref);

CREATE TABLE IF NOT EXISTS casework_hosted_idempotency (
    issuer text NOT NULL,
    subject text NOT NULL,
    profile_id text NOT NULL,
    operation text NOT NULL,
    resource text NOT NULL,
    idempotency_key text NOT NULL,
    request_hash text NOT NULL,
    item_id uuid NOT NULL REFERENCES casework_hosted_items(item_id) ON DELETE CASCADE,
    response jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (issuer, subject, profile_id, operation, resource, idempotency_key)
);
CREATE INDEX IF NOT EXISTS casework_hosted_idempotency_item_retention_idx
    ON casework_hosted_idempotency(item_id, created_at, issuer, subject, profile_id, operation, resource, idempotency_key);

-- Payload-free digests remain through the pinned accountability-retention window
-- so a delayed retry cannot silently repeat an operation after its cached
-- response expires. The bounded retention sweep removes them afterward.
CREATE TABLE IF NOT EXISTS casework_hosted_idempotency_tombstones (
    binding_digest text PRIMARY KEY,
    request_hash text NOT NULL,
    expired_at timestamptz NOT NULL,
    retained_until timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS casework_hosted_idempotency_tombstone_retention_idx
    ON casework_hosted_idempotency_tombstones(retained_until, binding_digest);

CREATE TABLE IF NOT EXISTS casework_hosted_cursors (
    cursor_id uuid PRIMARY KEY,
    issuer text NOT NULL,
    subject text NOT NULL,
    profile_id text NOT NULL,
    context text NOT NULL,
    last_at timestamptz,
    last_id uuid,
    expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS casework_hosted_cursors_retention_idx
    ON casework_hosted_cursors(expires_at, cursor_id);
