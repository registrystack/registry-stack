-- Pin the source origins an asynchronous write's write, status and
-- uncertainty routes reach, committed before the send. A status poll or an
-- uncertainty check runs only while the configured origins yield the same
-- pin, so a source-native identifier is only checked at the origin that
-- issued it. A row without a pin is never polled and stays held until it
-- expires.
ALTER TABLE adapter_idempotency_entries
    ADD COLUMN async_source_digest bytea
        CHECK (octet_length(async_source_digest) = 32),
    ADD CONSTRAINT adapter_idempotency_async_source_pin
        CHECK (async_source_digest IS NULL OR async_binding_digest IS NOT NULL);
