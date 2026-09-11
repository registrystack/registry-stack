ALTER TABLE casework_memberships
    ADD COLUMN IF NOT EXISTS display_name text;
