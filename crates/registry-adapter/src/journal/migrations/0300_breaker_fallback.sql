-- Circuit breaker refusal and fallback are explicit, value-free lifecycle
-- events. Refusal carries only the closed breaker state; fallback carries
-- only the closed error class and fixed authentication metadata already
-- admitted by the exchange failure events.
ALTER TABLE adapter_journal_events
    DROP CONSTRAINT adapter_journal_events_event_kind_check;
ALTER TABLE adapter_journal_events
    ADD CONSTRAINT adapter_journal_events_event_kind_check CHECK (event_kind IN (
        'exchangeCreated',
        'exchangeSending',
        'exchangeSent',
        'exchangeRedelivery',
        'exchangeFailureHandled',
        'exchangeCompleted',
        'exchangeFailed',
        'callRefused',
        'breakerRefused',
        'breakerFallback'));
