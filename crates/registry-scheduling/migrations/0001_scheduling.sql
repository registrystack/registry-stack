CREATE TABLE IF NOT EXISTS scheduling_meta (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    scheduling_id text NOT NULL,
    policy_revision bigint NOT NULL CHECK (policy_revision > 0),
    policy_digest text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
-- The empty scheduling_id marks a database no deployment has adopted yet;
-- `scheduling migrate` claims it for the policy's scheduling id, and every
-- serve refuses both an empty and a mismatched one.
INSERT INTO scheduling_meta (singleton, scheduling_id, policy_revision, policy_digest)
VALUES (true, '', 1, '')
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS scheduling_policy_revisions (
    policy_revision bigint PRIMARY KEY CHECK (policy_revision > 0),
    policy_digest text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
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
    updated_at timestamptz NOT NULL DEFAULT now()
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
    kind text NOT NULL CHECK (kind IN ('booking','hold')),
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
    closed_at timestamptz
);
CREATE INDEX IF NOT EXISTS scheduling_claims_supply_active_idx
    ON scheduling_claims(supply_id, occupied_start, occupied_end)
    WHERE state = 'active';
CREATE INDEX IF NOT EXISTS scheduling_claims_duplicate_idx
    ON scheduling_claims(duplicate_key)
    WHERE state = 'active' AND duplicate_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS scheduling_claims_expiry_idx
    ON scheduling_claims(hold_expires_at)
    WHERE state = 'active' AND kind = 'hold';

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

CREATE TABLE IF NOT EXISTS scheduling_outbox (
    outbox_id uuid PRIMARY KEY,
    purpose text NOT NULL CHECK (purpose IN ('confirmation','change','cancellation','reminder')),
    claim_id uuid NOT NULL REFERENCES scheduling_claims(claim_id),
    appointment_revision bigint NOT NULL,
    due_at timestamptz NOT NULL,
    delivery_state text NOT NULL CHECK (delivery_state IN ('pending','delivered','failed','local')),
    attempts integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz
);
CREATE INDEX IF NOT EXISTS scheduling_outbox_due_idx
    ON scheduling_outbox(due_at, next_attempt_at)
    WHERE delivery_state = 'pending';
CREATE INDEX IF NOT EXISTS scheduling_outbox_claim_idx
    ON scheduling_outbox(claim_id, purpose);

CREATE TABLE IF NOT EXISTS scheduling_audit_outbox (
    event_id uuid PRIMARY KEY,
    audit_record jsonb NOT NULL,
    published_at timestamptz
);

CREATE TABLE IF NOT EXISTS scheduling_attempts (
    attempt_id uuid PRIMARY KEY,
    actor_issuer text NOT NULL,
    actor_subject text NOT NULL,
    scope text NOT NULL,
    idempotency_key text NOT NULL,
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
    CHECK (erased_at IS NOT NULL OR receipt IS NOT NULL),
    UNIQUE (actor_issuer, actor_subject, scope, idempotency_key)
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
