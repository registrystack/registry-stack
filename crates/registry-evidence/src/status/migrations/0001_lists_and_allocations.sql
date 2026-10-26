-- Status lists and the entries allocated on them.
--
-- An allocation holds keyed values only: a selector pseudonym and, for a
-- holder-bound credential, a keyed digest of the holder key thumbprint, each
-- with the version of the key that produced it. There is no credential
-- identifier, raw selector or thumbprint column.

-- One row per status list. A list is open to allocation until it reaches half
-- its entries or its configured age; at most one list is open at a time.
-- `allocated_count` counts reserved entries, including those of issuance
-- transactions that later rolled back, so it never under-counts.
CREATE TABLE lists (
    list_id text PRIMARY KEY CHECK (list_id ~ '^[A-Za-z0-9_-]{22}$'),
    entry_count integer NOT NULL CHECK (entry_count BETWEEN 2 AND 1048576),
    bits smallint NOT NULL CHECK (bits = 2),
    created_at timestamptz NOT NULL,
    closed_at timestamptz,
    allocated_count integer NOT NULL
        CHECK (allocated_count >= 0 AND allocated_count <= entry_count / 2)
);

CREATE UNIQUE INDEX lists_one_open ON lists ((closed_at IS NULL))
    WHERE closed_at IS NULL;

-- One row per issued credential. The primary key is the uniqueness of
-- (list_id, idx): an index is allocated once and never reused.
-- Status codes are the Token Status List values: 0 VALID, 1 INVALID,
-- 2 SUSPENDED. `source_read_hour` is when the evaluation behind the
-- credential read its source, rounded down to the hour so an exact extract
-- `publishedAt` never persists here; an input older than it, less the
-- clock-skew allowance, is stale for the entry.
CREATE TABLE allocations (
    list_id text NOT NULL REFERENCES lists (list_id),
    idx integer NOT NULL CHECK (idx >= 0),
    holder_key_digest bytea CHECK (octet_length(holder_key_digest) = 32),
    holder_digest_key_version integer CHECK (holder_digest_key_version > 0),
    requirement_id text NOT NULL CHECK (octet_length(requirement_id) BETWEEN 1 AND 256),
    selector_pseudonym bytea NOT NULL CHECK (octet_length(selector_pseudonym) = 32),
    pseudonym_key_version integer NOT NULL CHECK (pseudonym_key_version > 0),
    issued_at timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    status smallint NOT NULL CHECK (status IN (0, 1, 2)),
    last_applied_source_revision bigint CHECK (last_applied_source_revision > 0),
    mapping_version integer CHECK (mapping_version > 0),
    source_read_hour timestamptz NOT NULL
        CHECK (mod(extract(epoch FROM source_read_hour), 3600) = 0),
    CONSTRAINT allocations_pkey PRIMARY KEY (list_id, idx),
    CONSTRAINT allocations_holder_digest_versioned
        CHECK ((holder_key_digest IS NULL) = (holder_digest_key_version IS NULL)),
    CONSTRAINT allocations_validity CHECK (not_after > issued_at),
    CONSTRAINT allocations_revision_mapped
        CHECK (last_applied_source_revision IS NULL OR mapping_version IS NOT NULL)
);

CREATE INDEX allocations_by_pseudonym ON allocations (selector_pseudonym);

CREATE INDEX allocations_by_holder_key_digest ON allocations (holder_key_digest)
    WHERE holder_key_digest IS NOT NULL;
