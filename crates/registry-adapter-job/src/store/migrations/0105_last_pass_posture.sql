ALTER TABLE adapter_job_state
    ADD COLUMN last_pass_posture text
        CHECK (last_pass_posture IN ('production', 'development'));
