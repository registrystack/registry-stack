-- Facade-owned asynchronous completion adds only value-free lifecycle facts.
-- Source identifiers, separate status credentials, request and response
-- bodies, and filled source paths remain outside the audit journal. The
-- response request ID remains the journal's ordinary exchange identifier.
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
        'breakerFallback',
        'exchangeAccepted',
        'recoveryChecked',
        'recoveryCheckFailed'));
