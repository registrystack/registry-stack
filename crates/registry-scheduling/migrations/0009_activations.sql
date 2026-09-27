-- The activation ledger: one row for every `schedulingctl apply`, the only
-- writer. A row is never updated or deleted, so the table is the history of
-- the packages this database has accepted, and the row with the greatest
-- apply_order names the active one. Startup reads it and refuses a package it
-- does not name; it never writes here. role_mode is the authority the
-- runtime_role actually held over this table once the apply's grants were
-- issued, not the mode the operator intended.
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
