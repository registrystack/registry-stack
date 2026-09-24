-- SPDX-License-Identifier: Apache-2.0
--
-- Retention counts from the terminal state, not from acceptance: a
-- message's payload is erased `retention.payloadDays` after its dispatch
-- job reached `delivered`, `dead_lettered`, `expired`, or `cancelled`, and
-- its record is deleted `retention.recordDays` after. The job's
-- `updated_at` is when it entered that state, since a terminal job changes
-- again only when an operator requeues it, which makes it pending. The
-- payload's own erasure time, fixed at acceptance, is therefore not a
-- retention time, and goes.

DROP INDEX messaging_message_payloads_erase_idx;
ALTER TABLE messaging_message_payloads DROP COLUMN erase_after;

CREATE INDEX messaging_dispatch_jobs_terminal_idx
    ON messaging_dispatch_jobs (updated_at, message_id)
    WHERE state IN ('delivered', 'dead_lettered', 'expired', 'cancelled');

-- A deleted record takes its idempotency record with it; the key has no
-- foreign key, so retention finds it by the message it names.
CREATE INDEX messaging_idempotency_message_idx
    ON messaging_idempotency (message_id);
