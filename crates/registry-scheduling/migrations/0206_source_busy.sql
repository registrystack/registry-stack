-- Source heads serialize one independently authorized reconciliation stream.
-- The source id is an operator binding, never selected from a request body.
CREATE TABLE scheduling_busy_source_heads (
    source_id text PRIMARY KEY
        CHECK (source_id <> '' AND octet_length(source_id) <= 128),
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    last_request_digest text
        CHECK (last_request_digest ~ '^sha256:[0-9a-f]{64}$'),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT scheduling_busy_source_heads_digest_check CHECK (
        (revision = 0 AND last_request_digest IS NULL)
        OR (revision > 0 AND last_request_digest IS NOT NULL)
    )
);

-- Coverage is per source and resource. Allocation admission treats absent,
-- expired, or unavailable coverage conservatively. A source outage updates
-- this row without erasing the last known busy facts.
CREATE TABLE scheduling_busy_source_coverage (
    source_id text NOT NULL
        REFERENCES scheduling_busy_source_heads(source_id),
    resource_id text NOT NULL
        CHECK (resource_id <> '' AND octet_length(resource_id) <= 128),
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    status text NOT NULL CHECK (status IN ('fresh', 'unavailable')),
    coverage_start timestamptz NOT NULL,
    coverage_end timestamptz NOT NULL,
    observed_at timestamptz NOT NULL,
    fresh_until timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (source_id, resource_id),
    CONSTRAINT scheduling_busy_source_coverage_interval_check
        CHECK (coverage_start < coverage_end),
    CONSTRAINT scheduling_busy_source_coverage_freshness_check CHECK (
        (status = 'fresh'
            AND fresh_until IS NOT NULL
            AND observed_at < fresh_until)
        OR (status = 'unavailable' AND fresh_until IS NULL)
    )
);
CREATE INDEX scheduling_busy_source_coverage_resource_idx
    ON scheduling_busy_source_coverage(resource_id, source_id);

-- One external occurrence is stable across retries and process restarts.
-- Rows deliberately contain only correlation, version, resource, and time;
-- event text, attendees, organizers, and absence reasons have no column.
CREATE TABLE scheduling_busy_intervals (
    source_id text NOT NULL
        REFERENCES scheduling_busy_source_heads(source_id),
    resource_id text NOT NULL
        CHECK (resource_id <> '' AND octet_length(resource_id) <= 128),
    external_uid text NOT NULL
        CHECK (external_uid <> '' AND octet_length(external_uid) <= 512),
    external_revision text NOT NULL
        CHECK (external_revision <> '' AND octet_length(external_revision) <= 256),
    busy_start timestamptz NOT NULL,
    busy_end timestamptz NOT NULL,
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    observed_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (source_id, resource_id, external_uid),
    CONSTRAINT scheduling_busy_intervals_interval_check
        CHECK (busy_start < busy_end)
);
CREATE INDEX scheduling_busy_intervals_resource_interval_idx
    ON scheduling_busy_intervals(resource_id, busy_start, busy_end, source_id);
