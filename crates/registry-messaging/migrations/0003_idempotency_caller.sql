-- SPDX-License-Identifier: Apache-2.0
--
-- Scope every spent idempotency key to the caller's issuer and subject, as
-- Scheduling and Casework scope theirs, rather than to the caller's keyed
-- audit pseudonym. Rotating `audit.hashKeyRef` then changes pseudonyms
-- only: a spent key stays spent across a rotation. The audit records keep
-- naming the caller by pseudonym; only the key's scope changes.
--
-- A record is identified and found by `key_reference`, a SHA-256 digest
-- over a fixed domain and the length-prefixed issuer, subject, operation,
-- and key. The raw issuer, subject, and key stay beside it only while the
-- submission receipt does: retention clears all three when it erases the
-- receipt, and the digest alone keeps the key spent for that caller.
--
-- Records written under the pseudonym scope are discarded, not re-keyed,
-- so every key spent before this version can be used again. The table is
-- locked before the records are discarded, so a record an earlier runtime
-- still serving commits while this version waits is discarded with the
-- rest instead of failing the new NOT NULL column.

LOCK TABLE messaging_idempotency IN ACCESS EXCLUSIVE MODE;
DELETE FROM messaging_idempotency;

ALTER TABLE messaging_idempotency DROP CONSTRAINT messaging_idempotency_pkey;
ALTER TABLE messaging_idempotency DROP COLUMN principal;
ALTER TABLE messaging_idempotency
    ALTER COLUMN idempotency_key DROP NOT NULL,
    ADD COLUMN key_reference text NOT NULL
        CHECK (key_reference ~ '^sha256:[0-9a-f]{64}$'),
    ADD COLUMN submitter_issuer text
        CHECK (length(submitter_issuer) BETWEEN 1 AND 2048),
    ADD COLUMN submitter_subject text
        CHECK (length(submitter_subject) BETWEEN 1 AND 1024),
    ADD PRIMARY KEY (key_reference),
    ADD CONSTRAINT messaging_idempotency_caller CHECK (
        (erased_at IS NULL AND submitter_issuer IS NOT NULL
            AND submitter_subject IS NOT NULL AND idempotency_key IS NOT NULL)
        OR (erased_at IS NOT NULL AND submitter_issuer IS NULL
            AND submitter_subject IS NULL AND idempotency_key IS NULL)
    );
