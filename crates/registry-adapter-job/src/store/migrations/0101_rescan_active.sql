-- A rescan traversal that spans pages: the marker stays set from the
-- pass that started at the first page until the page that ends it (a
-- finite scan's cleared cursor, or an ongoing scan's first empty page
-- at the tail), so every page of one scan retries refused rows and skips
-- settled ones, and the delay clock starts only when the scan finished.
ALTER TABLE adapter_job_state
    ADD COLUMN rescan_active boolean NOT NULL DEFAULT false;
-- The stable fence of one lease grant: every fenced write names the
-- epoch of the lease it holds, so a renewal extends the expiry without
-- invalidating the holder, and a newer grant invalidates the old one.
ALTER TABLE adapter_job_state
    ADD COLUMN lease_epoch bigint NOT NULL DEFAULT 0;
