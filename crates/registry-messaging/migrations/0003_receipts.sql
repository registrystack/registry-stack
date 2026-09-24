-- SPDX-License-Identifier: Apache-2.0
--
-- Delivery receipts: the report a provider's verified callbacks carried for
-- each message, and the bounded history of the receipts themselves.
--
-- `report` only moves forward (`sent`, then `delivered` or `undelivered`)
-- and never leaves a final report; the runtime decides that under the
-- message row's lock, in the transaction that records the receipt. A
-- receipt row names the report and the provider's code only: the callback's
-- body, form, and headers are never stored.

ALTER TABLE messaging_messages
    ADD COLUMN report text CHECK (report IN ('sent', 'delivered', 'undelivered')),
    ADD COLUMN report_at timestamptz,
    ADD CONSTRAINT messaging_messages_report CHECK ((report IS NULL) = (report_at IS NULL));

-- The distinct receipts of one message, in the order they arrived, at most
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

-- A receipt names the message by the reference its provider answered.
CREATE INDEX messaging_attempts_reference_idx
    ON messaging_attempts (provider_reference)
    WHERE provider_reference IS NOT NULL;
