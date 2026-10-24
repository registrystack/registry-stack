ALTER TABLE scheduling_pool_members
    ADD COLUMN availability jsonb,
    ADD CONSTRAINT scheduling_pool_members_availability_object CHECK (
        availability IS NULL OR jsonb_typeof(availability) = 'object'
    );
