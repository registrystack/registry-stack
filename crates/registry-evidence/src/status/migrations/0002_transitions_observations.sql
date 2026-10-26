-- Transitions, the observation store, the staleness clock and the mapping
-- version registry.
--
-- Like allocations, these tables hold keyed values, statuses, revisions and
-- times only. The staleness clock is the one column that may hold an exact
-- extract `publishedAt`.

-- INVALID is terminal. The ledger already refuses to move an entry out of
-- it; this trigger refuses it for any writer of the table too.
CREATE FUNCTION allocations_invalid_is_terminal() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status = 1 AND NEW.status <> 1 THEN
        RAISE EXCEPTION 'an INVALID status entry is terminal'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER allocations_invalid_is_terminal
    BEFORE UPDATE OF status ON allocations
    FOR EACH ROW EXECUTE FUNCTION allocations_invalid_is_terminal();

-- One row per status change, written in the same transaction as the change.
-- It is history and provenance, not tamper evidence: it is not chained.
-- Each cause has a closed provenance shape: a hook names its mapping
-- version, event id, source revision, package revision and event source; an
-- operator names the approving principals and a case reference; a
-- reconciliation names its mapping version, run id, extract digest and, for
-- a matched row, its revision.
CREATE TABLE transitions (
    transition_id uuid PRIMARY KEY,
    list_id text NOT NULL,
    idx integer NOT NULL,
    from_status smallint NOT NULL CHECK (from_status IN (0, 2)),
    to_status smallint NOT NULL CHECK (to_status IN (0, 1, 2)),
    cause text NOT NULL CHECK (cause IN ('hook', 'operator', 'reconciliation')),
    mapping_version integer CHECK (mapping_version > 0),
    reason_category text NOT NULL CHECK (reason_category ~ '^[a-z][a-z0-9-]{0,63}$'),
    event_id text CHECK (octet_length(event_id) BETWEEN 1 AND 256),
    source_revision bigint CHECK (source_revision > 0),
    package_revision text CHECK (octet_length(package_revision) BETWEEN 1 AND 256),
    event_source text CHECK (octet_length(event_source) BETWEEN 1 AND 256),
    operator_principals text[],
    case_reference text CHECK (octet_length(case_reference) BETWEEN 1 AND 256),
    run_id uuid,
    extract_digest bytea CHECK (octet_length(extract_digest) = 32),
    occurred_at timestamptz NOT NULL,
    CONSTRAINT transitions_entry FOREIGN KEY (list_id, idx)
        REFERENCES allocations (list_id, idx),
    CONSTRAINT transitions_change CHECK (from_status <> to_status),
    CONSTRAINT transitions_reinstatement_by_operator
        CHECK (to_status <> 0 OR cause = 'operator'),
    CONSTRAINT transitions_hook_provenance CHECK (
        cause <> 'hook' OR (
            mapping_version IS NOT NULL AND event_id IS NOT NULL
            AND source_revision IS NOT NULL AND package_revision IS NOT NULL
            AND event_source IS NOT NULL
            AND operator_principals IS NULL AND case_reference IS NULL
            AND run_id IS NULL AND extract_digest IS NULL
        )
    ),
    CONSTRAINT transitions_operator_provenance CHECK (
        cause <> 'operator' OR (
            operator_principals IS NOT NULL
            AND cardinality(operator_principals) BETWEEN 1 AND 16
            AND array_position(operator_principals, NULL) IS NULL
            AND case_reference IS NOT NULL
            AND mapping_version IS NULL AND event_id IS NULL
            AND source_revision IS NULL AND package_revision IS NULL
            AND event_source IS NULL AND run_id IS NULL AND extract_digest IS NULL
        )
    ),
    CONSTRAINT transitions_reconciliation_provenance CHECK (
        cause <> 'reconciliation' OR (
            mapping_version IS NOT NULL AND run_id IS NOT NULL
            AND extract_digest IS NOT NULL
            AND event_id IS NULL AND package_revision IS NULL AND event_source IS NULL
            AND operator_principals IS NULL AND case_reference IS NULL
        )
    )
);

CREATE INDEX transitions_by_entry ON transitions (list_id, idx);

-- The latest observed mapped status per requirement and selector pseudonym,
-- kept so an allocation committed after a hook can inherit what the hook
-- observed. Source revisions are per record, so the observations of two
-- requirements that share a selector profile are kept apart and never
-- compared. `captured_at` is the source's capture time of the change; rows
-- are purged by it once the observation retention passes.
CREATE TABLE observations (
    requirement_id text NOT NULL CHECK (octet_length(requirement_id) BETWEEN 1 AND 256),
    selector_pseudonym bytea NOT NULL CHECK (octet_length(selector_pseudonym) = 32),
    pseudonym_key_version integer NOT NULL CHECK (pseudonym_key_version > 0),
    status smallint NOT NULL CHECK (status IN (0, 1, 2)),
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    captured_at timestamptz NOT NULL,
    mapping_version integer NOT NULL CHECK (mapping_version > 0),
    PRIMARY KEY (requirement_id, selector_pseudonym)
);

CREATE INDEX observations_by_capture_time ON observations (captured_at);

-- The last successful source observation: the `publishedAt` of the extract
-- behind the last complete reconciliation run, or the run instant if that is
-- earlier. One row.
CREATE TABLE staleness_clock (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    last_observed_at timestamptz NOT NULL
);

-- The highest mapping version any process sharing the ledger has
-- registered. One row.
CREATE TABLE mapping_versions (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    highest integer NOT NULL CHECK (highest > 0)
);
