-- Source-side setup for the PostgreSQL source example. Run it as the source
-- database's owner, not through the Adapter: the Adapter only reads.
--
-- `example_registry.households` stands in for your own table. The view is the
-- contract with the Adapter: a stable text key (`id`), the columns the job
-- projects, and nothing else. Change the table, keep the view's column names
-- and types, and the pack, query and job stay the same.
CREATE SCHEMA example_registry;

CREATE TABLE example_registry.households (
  household_id uuid PRIMARY KEY,
  head_name text NOT NULL,
  member_count integer NOT NULL CHECK (member_count > 0),
  registered_on date NOT NULL,
  status text NOT NULL
);

INSERT INTO example_registry.households
  (household_id, head_name, member_count, registered_on, status)
VALUES
  ('3f1c2a0e-6f0b-4a53-9a3e-0d3b5f8e0001', 'Amina Example', 4, '2026-10-01', 'registered'),
  ('3f1c2a0e-6f0b-4a53-9a3e-0d3b5f8e0002', 'Joseph Example', 6, '2026-10-02', 'registered'),
  ('3f1c2a0e-6f0b-4a53-9a3e-0d3b5f8e0003', 'Lena Example', 2, '2026-10-03', 'draft');

-- The view exposes only registered households. `id` is the item key: it must
-- be unique and never NULL, and it must not change when the household does.
CREATE VIEW example_registry.households_export AS
SELECT
  household_id::text AS id,
  head_name AS respondent_name,
  member_count AS household_size,
  registered_on
FROM example_registry.households
WHERE status = 'registered';

-- A dedicated login that can read the view and nothing else. Create its
-- password out of band and give the Adapter the secret reference, never the
-- value.
CREATE ROLE adapter_reader LOGIN;
GRANT USAGE ON SCHEMA example_registry TO adapter_reader;
GRANT SELECT ON example_registry.households_export TO adapter_reader;
