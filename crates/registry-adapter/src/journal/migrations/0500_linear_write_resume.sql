-- Linear write recovery adds value-free ordinal lifecycle facts. Binding
-- names and values, source identifiers, request or response bodies, filled
-- paths, headers and credentials remain outside the audit journal.
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
        'recoveryCheckFailed',
        'resumeStepStarted',
        'resumeStepCheckpointed'));
