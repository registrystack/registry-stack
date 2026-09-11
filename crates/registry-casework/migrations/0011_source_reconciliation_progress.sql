CREATE TABLE IF NOT EXISTS casework_source_reconciliation_progress (
    source_id text NOT NULL,
    binding_generation text NOT NULL,
    remote_cursor text CHECK (
        remote_cursor IS NULL OR octet_length(remote_cursor) BETWEEN 1 AND 65536
    ),
    remote_cycle_complete boolean NOT NULL DEFAULT false,
    remote_lease_token uuid,
    remote_lease_until timestamptz,
    local_after_kind text,
    local_after_id text,
    local_cycle_complete boolean NOT NULL DEFAULT false,
    CHECK ((local_after_kind IS NULL) = (local_after_id IS NULL)),
    CHECK ((remote_lease_token IS NULL) = (remote_lease_until IS NULL)),
    PRIMARY KEY (source_id, binding_generation)
);
