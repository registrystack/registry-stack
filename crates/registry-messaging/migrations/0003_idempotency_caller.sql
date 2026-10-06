-- SPDX-License-Identifier: Apache-2.0
--
-- Scope every spent idempotency key to the caller's issuer and subject, as
-- Scheduling and Casework scope theirs, rather than to the caller's keyed
-- audit pseudonym. Rotating `audit.hashKeyRef` then changes pseudonyms
-- only: a spent key stays spent across a rotation. The audit records keep
-- naming the caller by pseudonym; only the key's scope changes.
--
-- Records written under the pseudonym scope are discarded, not re-keyed,
-- so every key spent before this version can be used again. The table is
-- locked before the records are discarded, so a record an earlier runtime
-- still serving commits while this version waits is discarded with the
-- rest instead of failing the new NOT NULL columns.

LOCK TABLE messaging_idempotency IN ACCESS EXCLUSIVE MODE;
DELETE FROM messaging_idempotency;

ALTER TABLE messaging_idempotency DROP CONSTRAINT messaging_idempotency_pkey;
ALTER TABLE messaging_idempotency DROP COLUMN principal;
ALTER TABLE messaging_idempotency
    ADD COLUMN submitter_issuer text NOT NULL
        CHECK (length(submitter_issuer) BETWEEN 1 AND 2048),
    ADD COLUMN submitter_subject text NOT NULL
        CHECK (length(submitter_subject) BETWEEN 1 AND 1024),
    ADD PRIMARY KEY (submitter_issuer, submitter_subject, operation, idempotency_key);
