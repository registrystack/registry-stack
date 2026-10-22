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
    closed_at timestamptz,
    external_references jsonb NOT NULL DEFAULT '[]'::jsonb,
    owner_issuer text,
    owner_subject text,
    owner_reference text,
    owner_erased_at timestamptz,
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
