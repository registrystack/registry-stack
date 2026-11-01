-- The governed-ingestion job host's tables (products/adapter/CONCEPT.md
-- section 17.2): one row per item the job has read, carrying identity and
-- progress and no payload, and one row per job carrying the source
-- position and the pass schedule. A dump of the item table identifies
-- items and answers; it exposes none of the source's data.

CREATE TABLE adapter_job_items (
    -- The job's own identifier; items of different jobs never share a row.
    job_id text NOT NULL CHECK (octet_length(job_id) BETWEEN 1 AND 256),
    -- The source's stable key for the item, under the job's namespace.
    item_key text NOT NULL CHECK (octet_length(item_key) BETWEEN 1 AND 512),
    -- The plain sha256 digest of the bytes the job's digestOf declaration
    -- covers: 'sha256:' and 64 lowercase hex digits. No keyed construction
    -- and no digest secret: the digest says only whether those bytes
    -- changed.
    last_digest text NOT NULL CHECK (last_digest ~ '^sha256:[0-9a-f]{64}$'),
    -- Counts changes to the item from 1, so a revert from B back to A is
    -- a change.
    sequence bigint NOT NULL CHECK (sequence >= 1),
    -- The last hand-off's outcome: pending (handed off, answer not yet
    -- recorded), acknowledged, or refused.
    status text NOT NULL CHECK (status IN ('pending', 'acknowledged', 'refused')),
    -- The destination's own item-scoped refusal code, for a refused row.
    code text CHECK (code IS NULL OR octet_length(code) BETWEEN 1 AND 256),
    -- The reference the destination returned for this digest's hand-off.
    run_id text CHECK (run_id IS NULL OR octet_length(run_id) BETWEEN 1 AND 256),
    -- The reference a previous, different-digest hand-off of this key
    -- returned.
    prior_run_id text CHECK (prior_run_id IS NULL OR octet_length(prior_run_id) BETWEEN 1 AND 256),
    -- Whether this key was handed off before under a digest whose receipt
    -- may have been lost. Set when a changed digest replaces a pending or
    -- acknowledged row's record, or when the destination acknowledges.
    admitted_before boolean NOT NULL DEFAULT false,
    -- From the runtime clock at the first write, never a database default.
    first_seen timestamptz NOT NULL,
    -- From the runtime clock at the last write.
    last_seen timestamptz NOT NULL,
    PRIMARY KEY (job_id, item_key)
);

CREATE INDEX adapter_job_items_status_idx
    ON adapter_job_items (job_id, status);

CREATE TABLE adapter_job_state (
    job_id text PRIMARY KEY CHECK (octet_length(job_id) BETWEEN 1 AND 256),
    -- The opaque page cursor the last settled pass saved; NULL at a
    -- finite end or before the first pass. Engine-owned resume state,
    -- never an item payload. The host bounds it by the engine's compact
    -- cursor bound before it saves; the jsonb text form is longer than
    -- the compact one, so the table carries no length check of its own.
    position jsonb,
    -- The projection digest the last pass ran under, so a projection edit
    -- is visible in status.
    projection_digest text CHECK (projection_digest IS NULL OR octet_length(projection_digest) BETWEEN 1 AND 128),
    -- The row lease: one pass at a time per job. NULL, or past, means the
    -- lease is free.
    lease_expires timestamptz,
    -- When the last pass ran, settled or stopped.
    last_pass_at timestamptz,
    -- Why the last pass stopped, value-free; NULL after a pass that
    -- settled its page.
    last_pass_stop text CHECK (last_pass_stop IS NULL OR octet_length(last_pass_stop) BETWEEN 1 AND 256),
    -- When the last rescan pass ran, for the source's declared
    -- rescanDelaySeconds gate.
    last_rescan_at timestamptz,
    -- Consecutive completed passes that read no items, for the interval
    -- trigger's backoffIdleThreshold.
    idle_streak bigint NOT NULL DEFAULT 0 CHECK (idle_streak >= 0),
    -- Consecutive passes that stopped before the page settled, for the
    -- interval trigger's backoffErrorThreshold.
    error_streak bigint NOT NULL DEFAULT 0 CHECK (error_streak >= 0)
);
