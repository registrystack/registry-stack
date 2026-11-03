-- Held is an item-scoped settled state: the destination cannot safely
-- accept another automatic attempt, so an operator resolves it in the
-- owning product. The job exposes the code and reference but offers no
-- mutation that marks the row accepted.

ALTER TABLE adapter_job_items
    DROP CONSTRAINT adapter_job_items_status_check;

ALTER TABLE adapter_job_items
    ADD CONSTRAINT adapter_job_items_status_check
    CHECK (status IN ('pending', 'acknowledged', 'refused', 'held'));
