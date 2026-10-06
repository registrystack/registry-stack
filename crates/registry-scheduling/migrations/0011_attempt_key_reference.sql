-- An idempotency attempt is identified by a digest of its verified issuer,
-- subject, command scope, and key, so the retention sweep can clear the raw
-- caller and key with the receipt while the key stays spent for that caller.
-- The digest is SHA-256 over the domain and the four values, each prefixed by
-- its UTF-8 byte length as a big-endian 64-bit integer, rendered as sha256:
-- and lowercase hex: the same digest attempt_key_reference computes.
LOCK TABLE scheduling_attempts IN ACCESS EXCLUSIVE MODE;

ALTER TABLE scheduling_attempts ADD COLUMN key_reference text;

UPDATE scheduling_attempts
   SET key_reference = 'sha256:' || encode(sha256(
           int8send(octet_length(convert_to('scheduling-idempotency-key-v1', 'UTF8'))::bigint)
        || convert_to('scheduling-idempotency-key-v1', 'UTF8')
        || int8send(octet_length(convert_to(actor_issuer, 'UTF8'))::bigint)
        || convert_to(actor_issuer, 'UTF8')
        || int8send(octet_length(convert_to(actor_subject, 'UTF8'))::bigint)
        || convert_to(actor_subject, 'UTF8')
        || int8send(octet_length(convert_to(scope, 'UTF8'))::bigint)
        || convert_to(scope, 'UTF8')
        || int8send(octet_length(convert_to(idempotency_key, 'UTF8'))::bigint)
        || convert_to(idempotency_key, 'UTF8')
       ), 'hex');

ALTER TABLE scheduling_attempts
    DROP CONSTRAINT scheduling_attempts_actor_issuer_actor_subject_scope_idempo_key,
    ALTER COLUMN key_reference SET NOT NULL,
    ALTER COLUMN actor_issuer DROP NOT NULL,
    ALTER COLUMN actor_subject DROP NOT NULL,
    ALTER COLUMN idempotency_key DROP NOT NULL,
    ADD CONSTRAINT scheduling_attempts_key_reference_key UNIQUE (key_reference),
    ADD CONSTRAINT scheduling_attempts_key_reference_check
        CHECK (key_reference ~ '^sha256:[0-9a-f]{64}$');

-- A receipt already erased drops its raw caller and key now, as the sweep
-- does from here on.
UPDATE scheduling_attempts
   SET actor_issuer = NULL, actor_subject = NULL, idempotency_key = NULL
 WHERE erased_at IS NOT NULL;

-- The raw caller and key are present exactly while the receipt is: all three
-- non-empty on a row not yet erased, and all three cleared on an erased one.
ALTER TABLE scheduling_attempts
    ADD CONSTRAINT scheduling_attempts_raw_caller_check CHECK (
        (erased_at IS NULL
            AND actor_issuer IS NOT NULL AND actor_issuer <> ''
            AND actor_subject IS NOT NULL AND actor_subject <> ''
            AND idempotency_key IS NOT NULL AND idempotency_key <> '')
        OR (erased_at IS NOT NULL
            AND actor_issuer IS NULL AND actor_subject IS NULL AND idempotency_key IS NULL)
    );
