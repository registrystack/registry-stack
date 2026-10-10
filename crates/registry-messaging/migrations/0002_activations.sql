-- Append-only governed package activation history.
CREATE TABLE IF NOT EXISTS messaging_activations (
    activation_id uuid PRIMARY KEY,
    apply_order bigint NOT NULL UNIQUE CHECK (apply_order > 0),
    package_digest text NOT NULL CHECK (package_digest ~ '^sha256:[0-9a-f]{64}$'),
    predecessor_package_digest text
        CHECK (predecessor_package_digest ~ '^sha256:[0-9a-f]{64}$'),
    database_id text NOT NULL CHECK (length(database_id) BETWEEN 1 AND 256),
    plan_kind text NOT NULL CHECK (plan_kind IN ('initial', 'successor')),
    applied_at timestamptz NOT NULL,
    operator_reference_hash text,
    backup_references text[] NOT NULL DEFAULT '{}'
        CHECK (cardinality(backup_references) <= 16),
    role_mode text NOT NULL CHECK (role_mode IN ('single', 'split')),
    CHECK ((plan_kind = 'initial') = (predecessor_package_digest IS NULL))
);
