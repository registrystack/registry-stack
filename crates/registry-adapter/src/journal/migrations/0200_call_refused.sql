-- A verified caller's refused call (403, or a record type the operation does
-- not serve) is journaled as `callRefused`: identifiers, class and status
-- only, like every other event.
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
        'callRefused'));
