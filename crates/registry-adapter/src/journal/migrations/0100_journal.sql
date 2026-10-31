-- The Adapter audit journal (products/adapter/CONCEPT.md section 11):
-- Camel's event notifier as a synchronous, value-free PostgreSQL journal
-- written before the response is sent. One row per event; it records no
-- bodies: no request payloads, no response payloads, no field values, no
-- filled query strings. Retention follows the shared audit.retentionDays
-- block and deletes by occurred_at through
-- adapter_journal_events_occurrence_idx.
CREATE TABLE adapter_journal_events (
    event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    event_kind text NOT NULL CHECK (event_kind IN (
        'exchangeCreated',
        'exchangeSending',
        'exchangeSent',
        'exchangeRedelivery',
        'exchangeFailureHandled',
        'exchangeCompleted',
        'exchangeFailed')),
    exchange_id text NOT NULL CHECK (octet_length(exchange_id) BETWEEN 1 AND 128),
    operation text NOT NULL CHECK (octet_length(operation) BETWEEN 1 AND 256),
    caller_ref text NOT NULL CHECK (octet_length(caller_ref) BETWEEN 1 AND 256),
    route_id text NOT NULL CHECK (octet_length(route_id) BETWEEN 1 AND 256),
    detail jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (octet_length(detail::text) <= 16384),
    -- From the runtime clock at the event, never a database default: the
    -- writer stamps the instant the event happened, and retention deletes
    -- by it.
    occurred_at timestamptz NOT NULL
);

-- Retention deletes scan this index on the leading occurred_at column;
-- event_id keeps batched deletes stable across rows that share an instant.
CREATE INDEX adapter_journal_events_occurrence_idx
    ON adapter_journal_events (occurred_at, event_id);

-- Rows are append-only: the journal's writers only insert, and retention
-- deletes whole rows. Like every such trigger this defends against this
-- ledger's own writers, not a hostile one: a table owner may drop the
-- trigger, and TRUNCATE bypasses it.
CREATE FUNCTION adapter_journal_events_are_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'journal events are append-only'
        USING ERRCODE = 'check_violation';
END;
$$;

CREATE TRIGGER adapter_journal_events_append_only
    BEFORE UPDATE ON adapter_journal_events
    FOR EACH ROW EXECUTE FUNCTION adapter_journal_events_are_append_only();
