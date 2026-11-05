-- Pin the source origins a resumable write's sends reach, so a resend can
-- never reach another source after a runtime change. Rows written before
-- this column carry no pin and keep their artifact pin alone.
ALTER TABLE adapter_idempotency_resumes
    ADD COLUMN source_digest bytea CHECK (octet_length(source_digest) = 32);

-- A random generation drawn when a resumable claim is inserted. It joins the
-- derived source idempotency key, so every resend of one claim presents the
-- same source key while a caller key reused after the replay window reaches
-- the source under a new one. Rows written before this column carry none and
-- derive no source key.
ALTER TABLE adapter_idempotency_resumes
    ADD COLUMN key_generation bytea CHECK (octet_length(key_generation) = 16);
