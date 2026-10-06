-- SPDX-License-Identifier: Apache-2.0
--
-- Scope every spent idempotency key to the caller's issuer and subject, as
-- Scheduling and Casework scope theirs, rather than to the caller's keyed
-- audit pseudonym. Rotating `audit.hashKeyRef` then changes pseudonyms
-- only: a key spent before the rotation is still spent after it. The audit
-- records keep naming the caller by pseudonym; only the key's scope changes.

ALTER TABLE messaging_idempotency
    ADD COLUMN submitter_issuer text
        CHECK (length(submitter_issuer) BETWEEN 1 AND 2048),
    ADD COLUMN submitter_subject text
        CHECK (length(submitter_subject) BETWEEN 1 AND 1024);

-- A key whose message is still held takes that message's submitter.
UPDATE messaging_idempotency AS key
   SET submitter_issuer = message.submitter_issuer,
       submitter_subject = message.submitter_subject
  FROM messaging_messages AS message
 WHERE message.message_id = key.message_id;

-- An earlier audit key rotation freed every spent key, so one caller can
-- hold the same key under two pseudonyms. The newest record keeps the key:
-- it is the one a retry after that rotation was answered with.
UPDATE messaging_idempotency AS key
   SET submitter_issuer = NULL,
       submitter_subject = NULL
  FROM messaging_idempotency AS newer
 WHERE newer.submitter_issuer = key.submitter_issuer
   AND newer.submitter_subject = key.submitter_subject
   AND newer.operation = key.operation
   AND newer.idempotency_key = key.idempotency_key
   AND (newer.created_at, newer.principal) > (key.created_at, key.principal);

-- A record no caller can be found for is preserved, unchanged, as inert
-- history outside the messaging_* runtime object namespace: a key whose
-- message retention deleted, a key that names no held message, and a key a
-- newer record of the same caller replaced. Nothing reads or erases it, and
-- its key is no longer spent.
CREATE TABLE legacy_messaging_idempotency (
    principal text NOT NULL,
    operation text NOT NULL,
    idempotency_key text NOT NULL,
    request_hash text,
    message_id uuid,
    status_code smallint,
    receipt jsonb,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    erased_at timestamptz,
    PRIMARY KEY (principal, operation, idempotency_key)
);

WITH moved AS (
    DELETE FROM messaging_idempotency
     WHERE submitter_issuer IS NULL
 RETURNING principal, operation, idempotency_key, request_hash, message_id,
           status_code, receipt, created_at, expires_at, erased_at
)
INSERT INTO legacy_messaging_idempotency
    (principal, operation, idempotency_key, request_hash, message_id,
     status_code, receipt, created_at, expires_at, erased_at)
SELECT principal, operation, idempotency_key, request_hash, message_id,
       status_code, receipt, created_at, expires_at, erased_at
  FROM moved;

ALTER TABLE messaging_idempotency
    ALTER COLUMN submitter_issuer SET NOT NULL,
    ALTER COLUMN submitter_subject SET NOT NULL;

ALTER TABLE messaging_idempotency DROP CONSTRAINT messaging_idempotency_pkey;
ALTER TABLE messaging_idempotency DROP COLUMN principal;
ALTER TABLE messaging_idempotency
    ADD PRIMARY KEY (submitter_issuer, submitter_subject, operation, idempotency_key);
