-- SPDX-License-Identifier: Apache-2.0
--
-- The Messaging schema: the package ledger, accepted messages, their
-- dispatch jobs, their attempts and delivery receipts, the idempotency
-- records of their submissions, and the audit outbox.

-- The package ledger: one row for each package a deployment activated, in
-- activation order. The digest is the package identity the runtime verified;
-- the runtime version is the binary that activated it.
CREATE TABLE messaging_package_ledger (
    sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    package_digest text NOT NULL CHECK (package_digest ~ '^sha256:[0-9a-f]{64}$'),
    runtime_version text NOT NULL CHECK (length(runtime_version) BETWEEN 1 AND 64),
    activated_at timestamptz NOT NULL
);

-- A message row carries what the status route, the worker's policy, and
-- the audit may read: never the recipient, the rendered content, or the
-- template data. The recipient and the rendered parts live in the payload
-- row beside it, which the worker reads under its lease and which retention
-- erases after `retention.payloadDays` while the message row stays. Template
-- data is never stored: the parts rendered from it at acceptance are.
CREATE TABLE messaging_messages (
    message_id uuid PRIMARY KEY,
    submitter_issuer text NOT NULL CHECK (length(submitter_issuer) BETWEEN 1 AND 2048),
    submitter_subject text NOT NULL CHECK (length(submitter_subject) BETWEEN 1 AND 1024),
    access_profile text NOT NULL CHECK (length(access_profile) BETWEEN 1 AND 64),
    sender_profile text NOT NULL CHECK (length(sender_profile) BETWEEN 1 AND 64),
    channel text NOT NULL CHECK (channel IN ('email', 'sms')),
    provider text NOT NULL CHECK (length(provider) BETWEEN 1 AND 64),
    sender text NOT NULL CHECK (length(sender) BETWEEN 1 AND 320),
    recipient_kind text NOT NULL CHECK (recipient_kind IN ('email', 'phone')),
    content_source text NOT NULL CHECK (content_source IN ('template', 'direct')),
    template_id text CHECK (length(template_id) BETWEEN 1 AND 64),
    template_version text CHECK (length(template_version) BETWEEN 1 AND 64),
    template_locale text CHECK (length(template_locale) BETWEEN 1 AND 35),
    package_digest text NOT NULL CHECK (package_digest ~ '^sha256:[0-9a-f]{64}$'),
    correlation_id text CHECK (octet_length(correlation_id) BETWEEN 1 AND 128),
    sms_segments smallint CHECK (sms_segments > 0),
    maximum_attempts smallint NOT NULL CHECK (maximum_attempts BETWEEN 1 AND 20),
    initial_retry_delay_ms bigint NOT NULL CHECK (initial_retry_delay_ms > 0),
    maximum_retry_delay_ms bigint NOT NULL CHECK (maximum_retry_delay_ms >= initial_retry_delay_ms),
    on_uncertain text NOT NULL CHECK (on_uncertain IN ('hold', 'retry')),
    provider_idempotent_submit boolean NOT NULL,
    accepted_at timestamptz NOT NULL,
    not_before timestamptz,
    expires_at timestamptz NOT NULL,
    report text CHECK (report IN ('sent', 'delivered', 'undelivered')),
    report_at timestamptz,
    CONSTRAINT messaging_messages_recipient_channel CHECK (
        (channel = 'email' AND recipient_kind = 'email')
        OR (channel = 'sms' AND recipient_kind = 'phone')
    ),
    CONSTRAINT messaging_messages_content_source CHECK (
        (content_source = 'template'
            AND template_id IS NOT NULL
            AND template_version IS NOT NULL
            AND template_locale IS NOT NULL)
        OR (content_source = 'direct'
            AND template_id IS NULL
            AND template_version IS NULL
            AND template_locale IS NULL)
    ),
    CONSTRAINT messaging_messages_segments CHECK ((channel = 'sms') = (sms_segments IS NOT NULL)),
    CONSTRAINT messaging_messages_window CHECK (
        expires_at > accepted_at AND (not_before IS NULL OR not_before < expires_at)
    ),
    CONSTRAINT messaging_messages_report CHECK ((report IS NULL) = (report_at IS NULL))
);

CREATE INDEX messaging_messages_submitter_idx
    ON messaging_messages (submitter_issuer, submitter_subject, accepted_at);
CREATE INDEX messaging_messages_accepted_idx
    ON messaging_messages (accepted_at, message_id);

-- An access profile's `dailyLimit` is counted over the messages the profile
-- had accepted in the last 24 hours, in the acceptance transaction and under
-- the profile's advisory lock. The accepted messages are the count, so it
-- survives a restart without a counter table; this index keeps the count a
-- range scan of one profile.
CREATE INDEX messaging_messages_profile_accepted_idx
    ON messaging_messages (access_profile, accepted_at);

-- The recipient and the rendered parts. Retention erases them
-- `retention.payloadDays` after the message's dispatch job reached a
-- terminal state; an erased row keeps its key and its erasure time only.
CREATE TABLE messaging_message_payloads (
    message_id uuid PRIMARY KEY REFERENCES messaging_messages (message_id) ON DELETE CASCADE,
    recipient text CHECK (octet_length(recipient) BETWEEN 1 AND 320),
    subject text,
    text_body text,
    html_body text,
    erased_at timestamptz,
    CONSTRAINT messaging_message_payloads_erasure CHECK (
        (erased_at IS NULL AND recipient IS NOT NULL AND text_body IS NOT NULL)
        OR (erased_at IS NOT NULL
            AND recipient IS NULL
            AND subject IS NULL
            AND text_body IS NULL
            AND html_body IS NULL)
    )
);

-- The dispatch job table, exactly the shape `registry-platform-dispatch`
-- declares (`JobTable::create_statements`), keyed by the message and the one
-- part `message`. A unit test holds the two in parity.
CREATE TABLE IF NOT EXISTS messaging_dispatch_jobs (
    message_id uuid NOT NULL,
    part text NOT NULL
        CHECK (part <> '' AND octet_length(part) <= 256),
    generation bigint NOT NULL CHECK (generation > 0),
    state text NOT NULL
        CONSTRAINT messaging_dispatch_jobs_state_values CHECK (
            state IN ('pending', 'leased', 'delivered', 'dead_lettered',
                      'expired', 'unknown', 'cancelled')
        ),
    attempt smallint NOT NULL CHECK (attempt >= 0),
    next_attempt_at timestamptz,
    attempt_started_at timestamptz,
    lease_expires_at timestamptz,
    lease_token uuid,
    delivered_at timestamptz,
    dead_lettered_at timestamptz,
    expired_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (message_id, part),
    CONSTRAINT messaging_dispatch_jobs_shape CHECK (
        (state = 'pending'
            AND next_attempt_at IS NOT NULL
            AND attempt_started_at IS NULL
            AND lease_expires_at IS NULL
            AND lease_token IS NULL
            AND delivered_at IS NULL
            AND dead_lettered_at IS NULL
            AND expired_at IS NULL)
        OR (state = 'leased'
            AND attempt > 0
            AND next_attempt_at IS NULL
            AND attempt_started_at IS NOT NULL
            AND lease_expires_at > attempt_started_at
            AND lease_token IS NOT NULL
            AND delivered_at IS NULL
            AND dead_lettered_at IS NULL
            AND expired_at IS NULL)
        OR (state = 'delivered'
            AND attempt > 0
            AND next_attempt_at IS NULL
            AND attempt_started_at IS NULL
            AND lease_expires_at IS NULL
            AND lease_token IS NULL
            AND delivered_at IS NOT NULL
            AND dead_lettered_at IS NULL
            AND expired_at IS NULL)
        OR (state = 'dead_lettered'
            AND attempt > 0
            AND next_attempt_at IS NULL
            AND attempt_started_at IS NULL
            AND lease_expires_at IS NULL
            AND lease_token IS NULL
            AND delivered_at IS NULL
            AND dead_lettered_at IS NOT NULL)
        OR (state = 'expired'
            AND next_attempt_at IS NULL
            AND attempt_started_at IS NULL
            AND lease_expires_at IS NULL
            AND lease_token IS NULL
            AND delivered_at IS NULL
            AND dead_lettered_at IS NULL
            AND expired_at IS NOT NULL)
        OR (state = 'unknown'
            AND attempt > 0
            AND next_attempt_at IS NULL
            AND attempt_started_at IS NULL
            AND lease_expires_at IS NULL
            AND lease_token IS NULL
            AND delivered_at IS NULL
            AND dead_lettered_at IS NULL
            AND expired_at IS NULL)
        OR (state = 'cancelled'
            AND next_attempt_at IS NULL
            AND attempt_started_at IS NULL
            AND lease_expires_at IS NULL
            AND lease_token IS NULL
            AND delivered_at IS NULL
            AND dead_lettered_at IS NULL
            AND expired_at IS NULL)
    )
);
CREATE INDEX IF NOT EXISTS messaging_dispatch_jobs_due_idx
    ON messaging_dispatch_jobs (next_attempt_at, message_id, part)
    WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS messaging_dispatch_jobs_lease_idx
    ON messaging_dispatch_jobs (lease_expires_at, message_id, part)
    WHERE state = 'leased';

ALTER TABLE messaging_dispatch_jobs
    ADD CONSTRAINT messaging_dispatch_jobs_message
        FOREIGN KEY (message_id) REFERENCES messaging_messages (message_id) ON DELETE CASCADE,
    ADD CONSTRAINT messaging_dispatch_jobs_part CHECK (part = 'message');

-- Retention counts from the terminal state: a message's payload is erased
-- `retention.payloadDays` after its dispatch job reached `delivered`,
-- `dead_lettered`, `expired`, or `cancelled`, and its record is deleted
-- `retention.recordDays` after. The job's `updated_at` is when it entered
-- that state, since a terminal job changes again only when an operator
-- requeues it, which makes it pending.
CREATE INDEX messaging_dispatch_jobs_terminal_idx
    ON messaging_dispatch_jobs (updated_at, message_id)
    WHERE state IN ('delivered', 'dead_lettered', 'expired', 'cancelled');

-- The metrics listener counts the messages held unknown on every scrape;
-- pending and leased jobs already have their own partial indexes.
CREATE INDEX messaging_dispatch_jobs_unknown_idx
    ON messaging_dispatch_jobs (message_id)
    WHERE state = 'unknown';

-- One row per attempt the worker leased: its class once it finished, and
-- whether the provider answered a reference. The reference itself is kept
-- for receipts to match, never returned by the status route.
CREATE TABLE messaging_attempts (
    message_id uuid NOT NULL REFERENCES messaging_messages (message_id) ON DELETE CASCADE,
    generation bigint NOT NULL CHECK (generation > 0),
    attempt smallint NOT NULL CHECK (attempt > 0),
    started_at timestamptz NOT NULL,
    outcome text NOT NULL CHECK (
        outcome IN ('in-progress', 'accepted', 'transient', 'permanent', 'maybe-sent',
       'interrupted')
    ),
    finished_at timestamptz,
    provider_reference text CHECK (octet_length(provider_reference) BETWEEN 1 AND 128),
    failure_code text CHECK (octet_length(failure_code) BETWEEN 1 AND 64),
    PRIMARY KEY (message_id, generation, attempt),
    CONSTRAINT messaging_attempts_finished CHECK ((outcome = 'in-progress') = (finished_at IS NULL))
);

-- A receipt names the message by the reference its provider answered.
CREATE INDEX messaging_attempts_reference_idx
    ON messaging_attempts (provider_reference)
    WHERE provider_reference IS NOT NULL;

-- Delivery receipts: the report a provider's verified callbacks carried for
-- each message, and the bounded history of the receipts themselves.
--
-- `report` only moves forward (`sent`, then `delivered` or `undelivered`)
-- and never leaves a final report; the runtime decides that under the
-- message row's lock, in the transaction that records the receipt. A
-- receipt row names the report and the provider's code only: the callback's
-- body, form, and headers are never stored. A receipt row is one of the
-- distinct receipts of one message, in the order they arrived, at most
-- sixteen. A duplicate is not stored again, and a receipt past the bound is
-- not stored at all, so a provider repeating itself cannot grow the table.
CREATE TABLE messaging_receipts (
    message_id uuid NOT NULL REFERENCES messaging_messages (message_id) ON DELETE CASCADE,
    sequence smallint NOT NULL CHECK (sequence BETWEEN 1 AND 16),
    received_at timestamptz NOT NULL,
    report text NOT NULL CHECK (report IN ('sent', 'delivered', 'undelivered')),
    code text CHECK (octet_length(code) BETWEEN 1 AND 64),
    applied boolean NOT NULL,
    PRIMARY KEY (message_id, sequence)
);

CREATE UNIQUE INDEX messaging_receipts_distinct_idx
    ON messaging_receipts (message_id, report, coalesce(code, ''));

-- The idempotency record of one submission, keyed by the caller's keyed
-- audit pseudonym rather than its issuer and subject. The request hash binds
-- the key to one body; the stored receipt answers a retry until retention
-- erases it, and the row stays so the key stays spent. When retention
-- deletes the message, it nulls the message and the request hash too: the
-- row then holds the pseudonym, the key, and its times, and a retry under
-- the key is still refused as expired.
CREATE TABLE messaging_idempotency (
    principal text NOT NULL CHECK (principal ~ '^(hmac-sha256|sha256):[0-9a-f]{64}$'),
    operation text NOT NULL CHECK (operation IN ('submit-message')),
    idempotency_key text NOT NULL CHECK (octet_length(idempotency_key) BETWEEN 1 AND 128),
    request_hash text CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
    message_id uuid,
    status_code smallint,
    receipt jsonb,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    erased_at timestamptz,
    PRIMARY KEY (principal, operation, idempotency_key),
    CONSTRAINT messaging_idempotency_erasure CHECK (
        (erased_at IS NULL AND status_code IS NOT NULL AND receipt IS NOT NULL)
        OR (erased_at IS NOT NULL AND status_code IS NULL AND receipt IS NULL)
    ),
    CONSTRAINT messaging_idempotency_record CHECK (
        (message_id IS NOT NULL AND request_hash IS NOT NULL)
        OR (message_id IS NULL AND request_hash IS NULL AND erased_at IS NOT NULL)
    )
);

CREATE INDEX messaging_idempotency_expiry_idx
    ON messaging_idempotency (expires_at)
    WHERE erased_at IS NULL;

-- Retention finds the record of a deleted message by the message it names;
-- the key has no foreign key, since it outlives the message.
CREATE INDEX messaging_idempotency_message_idx
    ON messaging_idempotency (message_id)
    WHERE message_id IS NOT NULL;

-- Audit records written in the transaction whose change they record, and
-- appended to the keyed journal by the runtime's publisher. The sequence
-- orders one publication pass; the chain attests to publication order.
CREATE TABLE messaging_audit_outbox (
    event_id uuid PRIMARY KEY,
    recorded_seq bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    audit_record jsonb NOT NULL,
    published_at timestamptz
);

CREATE INDEX messaging_audit_outbox_pending_idx
    ON messaging_audit_outbox (recorded_seq)
    WHERE published_at IS NULL;
