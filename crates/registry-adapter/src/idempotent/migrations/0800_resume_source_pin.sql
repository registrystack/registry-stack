-- Pin the source origins a resumable write's sends reach, so a resend can
-- never reach another source after a runtime change. Rows written before
-- this column carry no pin and keep their artifact pin alone.
ALTER TABLE adapter_idempotency_resumes
    ADD COLUMN source_digest bytea CHECK (octet_length(source_digest) = 32);
