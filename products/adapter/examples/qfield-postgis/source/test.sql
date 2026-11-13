-- Run after schema.sql on a disposable PostGIS database. The assertions and
-- synthetic rows are scoped to this transaction.
BEGIN;
SET LOCAL client_min_messages = warning;

CREATE FUNCTION pg_temp.assert_true(condition boolean, message text)
RETURNS void
LANGUAGE plpgsql
AS $function$
BEGIN
  IF condition IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'assertion failed: %', message;
  END IF;
END
$function$;

-- Native QFieldSync can write both child layers before the root in its
-- transaction. The source accepts the batch while enforcing the references
-- at its end. Before the root arrives, neither child is visible to Adapter.
INSERT INTO field_collection.boundaries (id, site_id, boundary)
VALUES
  ('20000000-0000-0000-0000-000000000013',
   '10000000-0000-0000-0000-000000000013',
   ST_GeomFromText('POLYGON((29 9,31 9,31 11,29 11,29 9))', 4326));
INSERT INTO field_collection.contacts (id, site_id, name)
VALUES
  ('30000000-0000-4000-8000-000000000013',
   '10000000-0000-0000-0000-000000000013', 'First return'),
  ('30000000-0000-4000-8000-000000000014',
   '10000000-0000-0000-0000-000000000013', 'Second return');
SELECT pg_temp.assert_true(
  NOT EXISTS (SELECT 1 FROM field_collection.eligible_sites),
  'a return that has only written the child layers must remain invisible'
);
INSERT INTO field_collection.sites
  (id, site_name, position, ready, form_version,
   expected_boundary_id, expected_contact_ids)
VALUES
  ('10000000-0000-0000-0000-000000000013', 'Child layers written first',
   ST_SetSRID(ST_MakePoint(30, 10), 4326), true, 'field-site-v1',
   '20000000-0000-0000-0000-000000000013',
   '["30000000-0000-4000-8000-000000000013","30000000-0000-4000-8000-000000000014"]');
SET CONSTRAINTS ALL IMMEDIATE;
SELECT pg_temp.assert_true(
  (SELECT count(*) = 1 FROM field_collection.eligible_sites),
  'a complete return must pass both foreign keys and become eligible'
);
DELETE FROM field_collection.sites
WHERE id = '10000000-0000-0000-0000-000000000013';
SET CONSTRAINTS ALL DEFERRED;

-- Complete submission, with contacts inserted in reverse UUID order to prove
-- that the exported repeat array is deterministic.
INSERT INTO field_collection.sites
  (id, site_name, position, ready, form_version,
   expected_boundary_id, expected_contact_ids)
VALUES
  ('10000000-0000-0000-0000-000000000001', 'Clinic Alpha',
   ST_SetSRID(ST_MakePoint(30.12345678, 10.12345678), 4326),
   true, 'field-site-v1',
   '20000000-0000-0000-0000-000000000001',
   '["30000000-0000-4000-8000-000000000001","30000000-0000-4000-8000-000000000002"]');
INSERT INTO field_collection.boundaries (id, site_id, boundary)
VALUES
  ('20000000-0000-0000-0000-000000000001',
   '10000000-0000-0000-0000-000000000001',
   ST_GeomFromText('POLYGON((29 9,31 9,31 11,29 11,29 9))', 4326));
INSERT INTO field_collection.contacts (id, site_id, name)
VALUES
  ('30000000-0000-4000-8000-000000000002',
   '10000000-0000-0000-0000-000000000001', 'Second Contact'),
  ('30000000-0000-4000-8000-000000000001',
   '10000000-0000-0000-0000-000000000001', 'First Contact');

SELECT pg_temp.assert_true(
  (SELECT count(*) = 1 FROM field_collection.eligible_sites),
  'one complete submission must be eligible'
);
SELECT pg_temp.assert_true(
  (SELECT position =
          '{"type":"Point","coordinates":[30.1234568,10.1234568]}'::jsonb
     FROM field_collection.eligible_sites
    WHERE id = '10000000-0000-0000-0000-000000000001'),
  'the point must cross as typed GeoJSON at seven-decimal precision'
);
SELECT pg_temp.assert_true(
  (SELECT boundary->>'type' = 'Polygon'
     FROM field_collection.eligible_sites
    WHERE id = '10000000-0000-0000-0000-000000000001'),
  'the boundary must cross as typed GeoJSON'
);
SELECT pg_temp.assert_true(
  (SELECT contacts =
    '[{"id":"30000000-0000-4000-8000-000000000001","name":"First Contact"},
      {"id":"30000000-0000-4000-8000-000000000002","name":"Second Contact"}]'::jsonb
     FROM field_collection.eligible_sites
    WHERE id = '10000000-0000-0000-0000-000000000001'),
  'contacts must be a stable ID-ordered JSON array'
);

UPDATE field_collection.sites
SET site_name = repeat('s', 161)
WHERE id = '10000000-0000-0000-0000-000000000001';
SELECT pg_temp.assert_true(
  (SELECT status_code = 'site_name_invalid'
     FROM field_collection.site_intake_status
    WHERE site_id = '10000000-0000-0000-0000-000000000001'),
  'site names longer than the BReg 160-character bound must be refused'
);
UPDATE field_collection.sites
SET site_name = 'Clinic Alpha'
WHERE id = '10000000-0000-0000-0000-000000000001';

UPDATE field_collection.contacts
SET name = repeat('n', 81)
WHERE id = '30000000-0000-4000-8000-000000000001';
SELECT pg_temp.assert_true(
  (SELECT status_code = 'contact_name_invalid'
     FROM field_collection.site_intake_status
    WHERE site_id = '10000000-0000-0000-0000-000000000001'),
  'contact names longer than the BReg 80-character bound must be refused'
);
UPDATE field_collection.contacts
SET name = 'First Contact'
WHERE id = '30000000-0000-4000-8000-000000000001';

UPDATE field_collection.sites
SET expected_contact_ids =
  '["30000000-0000-4000-8000-000000000002", "30000000-0000-4000-8000-000000000001"]'
WHERE id = '10000000-0000-0000-0000-000000000001';
SELECT pg_temp.assert_true(
  (SELECT status_code = 'contact_ids_mismatch'
     FROM field_collection.site_intake_status
    WHERE site_id = '10000000-0000-0000-0000-000000000001'),
  'the declared contact IDs must use canonical sorted order'
);
UPDATE field_collection.sites
SET expected_contact_ids = 'not-json'
WHERE id = '10000000-0000-0000-0000-000000000001';
SELECT pg_temp.assert_true(
  (SELECT status_code = 'contact_ids_mismatch'
     FROM field_collection.site_intake_status
    WHERE site_id = '10000000-0000-0000-0000-000000000001'),
  'malformed declared contact JSON must be refused without failing the view'
);
UPDATE field_collection.sites
SET expected_contact_ids = $marker$["\u0000"]$marker$
WHERE id = '10000000-0000-0000-0000-000000000001';
SELECT pg_temp.assert_true(
  (SELECT status_code = 'contact_ids_mismatch'
     FROM field_collection.site_intake_status
    WHERE site_id = '10000000-0000-0000-0000-000000000001'),
  'a JSON array PostgreSQL cannot store as JSONB must stay ineligible'
);
UPDATE field_collection.sites
SET expected_contact_ids =
  '["30000000-0000-4000-8000-000000000001", "30000000-0000-4000-8000-000000000002"]'
WHERE id = '10000000-0000-0000-0000-000000000001';

-- Draft and unknown form versions never enter the governed feed.
INSERT INTO field_collection.sites
  (id, site_name, position, ready, form_version)
VALUES
  ('10000000-0000-0000-0000-000000000002', 'Draft',
   ST_SetSRID(ST_MakePoint(30, 10), 4326), false, 'field-site-v1'),
  ('10000000-0000-0000-0000-000000000003', 'Unknown version',
   ST_SetSRID(ST_MakePoint(30, 10), 4326), true, 'field-site-v2');
SELECT pg_temp.assert_true(
  (SELECT status_code = 'draft'
     FROM field_collection.site_intake_status
    WHERE site_id = '10000000-0000-0000-0000-000000000002'),
  'a draft must report draft without exposing answers'
);
SELECT pg_temp.assert_true(
  (SELECT status_code = 'unsupported_form_version'
     FROM field_collection.site_intake_status
    WHERE site_id = '10000000-0000-0000-0000-000000000003'),
  'an unknown form version must be refused'
);

-- A ready root with its declared contact but no boundary remains partial.
INSERT INTO field_collection.sites
  (id, site_name, position, ready, form_version,
   expected_boundary_id, expected_contact_ids)
VALUES
  ('10000000-0000-0000-0000-000000000008', 'Missing boundary',
   ST_SetSRID(ST_MakePoint(30, 10), 4326), true, 'field-site-v1',
   '20000000-0000-0000-0000-000000000008',
   '["30000000-0000-4000-8000-000000000011"]');
INSERT INTO field_collection.contacts (id, site_id, name)
VALUES
  ('30000000-0000-4000-8000-000000000011',
   '10000000-0000-0000-0000-000000000008', 'Boundary pending');
SELECT pg_temp.assert_true(
  (SELECT status_code = 'boundary_missing'
     FROM field_collection.site_intake_status
    WHERE site_id = '10000000-0000-0000-0000-000000000008'),
  'a missing declared boundary must be refused'
);

-- A ready root remains ineligible until the exact declared late child arrives.
INSERT INTO field_collection.sites
  (id, site_name, position, ready, form_version,
   expected_boundary_id, expected_contact_ids)
VALUES
  ('10000000-0000-0000-0000-000000000004', 'Late child',
   ST_SetSRID(ST_MakePoint(31, 11), 4326), true, 'field-site-v1',
   '20000000-0000-0000-0000-000000000004',
   '["30000000-0000-4000-8000-000000000004", "30000000-0000-4000-8000-000000000005"]');
INSERT INTO field_collection.boundaries (id, site_id, boundary)
VALUES
  ('20000000-0000-0000-0000-000000000004',
   '10000000-0000-0000-0000-000000000004',
   ST_GeomFromText('POLYGON((30 10,32 10,32 12,30 12,30 10))', 4326));
INSERT INTO field_collection.contacts (id, site_id, name)
VALUES
  ('30000000-0000-4000-8000-000000000004',
   '10000000-0000-0000-0000-000000000004', 'Arrived first');
UPDATE field_collection.sites
SET expected_contact_ids = '["30000000-0000-4000-8000-000000000004"]'
WHERE id = '10000000-0000-0000-0000-000000000004';
SELECT pg_temp.assert_true(
  (SELECT status_code = 'contact_count_out_of_bounds'
     FROM field_collection.site_intake_status
    WHERE site_id = '10000000-0000-0000-0000-000000000004'),
  'one exact contact cannot satisfy the form minimum'
);
UPDATE field_collection.sites
SET expected_contact_ids =
  '["30000000-0000-4000-8000-000000000004","30000000-0000-4000-8000-000000000005"]'
WHERE id = '10000000-0000-0000-0000-000000000004';
SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1 FROM field_collection.eligible_sites
    WHERE id = '10000000-0000-0000-0000-000000000004'
  ),
  'a partial child set must be refused'
);
INSERT INTO field_collection.contacts (id, site_id, name)
VALUES
  ('30000000-0000-4000-8000-000000000005',
   '10000000-0000-0000-0000-000000000004', 'Arrived later');
SELECT pg_temp.assert_true(
  EXISTS (
    SELECT 1 FROM field_collection.eligible_sites
    WHERE id = '10000000-0000-0000-0000-000000000004'
  ),
  'the exact late child must make the source row eligible'
);

-- An undeclared extra child changes the exact set and removes eligibility.
INSERT INTO field_collection.contacts (id, site_id, name)
VALUES
  ('30000000-0000-4000-8000-000000000006',
   '10000000-0000-0000-0000-000000000004', 'Unexpected extra');
SELECT pg_temp.assert_true(
  (SELECT status_code = 'contact_ids_mismatch'
     FROM field_collection.site_intake_status
    WHERE site_id = '10000000-0000-0000-0000-000000000004'),
  'an extra child must be refused by the exact declared ID set'
);

-- Even an exact declared repeat set is refused once it exceeds the bounded
-- eligibility cardinality.
INSERT INTO field_collection.sites
  (id, site_name, position, ready, form_version, expected_boundary_id)
VALUES
  ('10000000-0000-0000-0000-000000000009', 'Too many contacts',
   ST_SetSRID(ST_MakePoint(30, 10), 4326), true, 'field-site-v1',
   '20000000-0000-0000-0000-000000000009');
INSERT INTO field_collection.boundaries (id, site_id, boundary)
VALUES
  ('20000000-0000-0000-0000-000000000009',
   '10000000-0000-0000-0000-000000000009',
   ST_GeomFromText('POLYGON((29 9,31 9,31 11,29 11,29 9))', 4326));
INSERT INTO field_collection.contacts (id, site_id, name)
SELECT
  ('40000000-0000-4000-8000-' || lpad(n::text, 12, '0'))::uuid,
  '10000000-0000-0000-0000-000000000009'::uuid,
  'Contact ' || n::text
FROM generate_series(1, 9) AS generated(n);
UPDATE field_collection.sites AS s
SET expected_contact_ids = (
  SELECT jsonb_agg(lower(c.id::text) ORDER BY lower(c.id::text))::text
  FROM field_collection.contacts AS c
  WHERE c.site_id = s.id
)
WHERE s.id = '10000000-0000-0000-0000-000000000009';
SELECT pg_temp.assert_true(
  (SELECT status_code = 'contact_count_out_of_bounds'
     FROM field_collection.site_intake_status
    WHERE site_id = '10000000-0000-0000-0000-000000000009'),
  'nine exact contacts must exceed the eligibility bound'
);

-- A mismatched boundary UUID is structurally visible but never exported.
INSERT INTO field_collection.sites
  (id, site_name, position, ready, form_version,
   expected_boundary_id, expected_contact_ids)
VALUES
  ('10000000-0000-0000-0000-000000000005', 'Wrong boundary',
   ST_SetSRID(ST_MakePoint(30, 10), 4326), true, 'field-site-v1',
   '20000000-0000-0000-0000-000000000099',
   '["30000000-0000-4000-8000-000000000007"]');
INSERT INTO field_collection.boundaries (id, site_id, boundary)
VALUES
  ('20000000-0000-0000-0000-000000000005',
   '10000000-0000-0000-0000-000000000005',
   ST_GeomFromText('POLYGON((29 9,31 9,31 11,29 11,29 9))', 4326));
INSERT INTO field_collection.contacts (id, site_id, name)
VALUES
  ('30000000-0000-4000-8000-000000000007',
   '10000000-0000-0000-0000-000000000005', 'Expected contact');
SELECT pg_temp.assert_true(
  (SELECT status_code = 'boundary_id_mismatch'
     FROM field_collection.site_intake_status
    WHERE site_id = '10000000-0000-0000-0000-000000000005'),
  'a mismatched boundary ID must be refused'
);

-- Invalid and out-of-bounds geometries can remain source drafts, but cannot
-- become eligible even if the ready flag and child declarations say complete.
INSERT INTO field_collection.sites
  (id, site_name, position, ready, form_version,
   expected_boundary_id, expected_contact_ids)
VALUES
  ('10000000-0000-0000-0000-000000000006', 'Invalid polygon',
   ST_SetSRID(ST_MakePoint(30, 10), 4326), true, 'field-site-v1',
   '20000000-0000-0000-0000-000000000006',
   '["30000000-0000-4000-8000-000000000008"]'),
  ('10000000-0000-0000-0000-000000000007', 'Out of bounds',
   ST_SetSRID(ST_MakePoint(181, 10), 4326), true, 'field-site-v1',
   '20000000-0000-0000-0000-000000000007',
   '["30000000-0000-4000-8000-000000000009"]');
INSERT INTO field_collection.boundaries (id, site_id, boundary)
VALUES
  ('20000000-0000-0000-0000-000000000006',
   '10000000-0000-0000-0000-000000000006',
   ST_GeomFromText('POLYGON((29 9,31 11,31 9,29 11,29 9))', 4326)),
  ('20000000-0000-0000-0000-000000000007',
   '10000000-0000-0000-0000-000000000007',
   ST_GeomFromText('POLYGON((29 9,31 9,31 11,29 11,29 9))', 4326));
INSERT INTO field_collection.contacts (id, site_id, name)
VALUES
  ('30000000-0000-4000-8000-000000000008',
   '10000000-0000-0000-0000-000000000006', 'Invalid geometry contact'),
  ('30000000-0000-4000-8000-000000000009',
   '10000000-0000-0000-0000-000000000007', 'Out of bounds contact');
SELECT pg_temp.assert_true(
  (SELECT status_code = 'boundary_invalid'
     FROM field_collection.site_intake_status
    WHERE site_id = '10000000-0000-0000-0000-000000000006'),
  'an invalid polygon must be refused'
);
SELECT pg_temp.assert_true(
  (SELECT status_code = 'position_invalid'
     FROM field_collection.site_intake_status
    WHERE site_id = '10000000-0000-0000-0000-000000000007'),
  'an out-of-bounds point must be refused'
);

-- A valid polygon above the BReg 500-position bound is rejected before it can
-- consume a bounded Adapter field or row.
INSERT INTO field_collection.sites
  (id, site_name, position, ready, form_version,
   expected_boundary_id, expected_contact_ids)
VALUES
  ('10000000-0000-0000-0000-000000000012', 'Excessive polygon',
   ST_SetSRID(ST_MakePoint(30, 10), 4326), true, 'field-site-v1',
   '20000000-0000-0000-0000-000000000012',
   '["30000000-0000-4000-8000-000000000012"]');
INSERT INTO field_collection.boundaries (id, site_id, boundary)
VALUES
  ('20000000-0000-0000-0000-000000000012',
   '10000000-0000-0000-0000-000000000012',
   ST_Buffer(
     ST_SetSRID(ST_MakePoint(30, 10), 4326),
     0.5,
     'quad_segs=126'
   ));
INSERT INTO field_collection.contacts (id, site_id, name)
VALUES
  ('30000000-0000-4000-8000-000000000012',
   '10000000-0000-0000-0000-000000000012', 'Bounded contact');
SELECT pg_temp.assert_true(
  (SELECT ST_NPoints(boundary) > 500
     FROM field_collection.boundaries
    WHERE site_id = '10000000-0000-0000-0000-000000000012'),
  'the regression polygon must actually exceed 500 positions'
);
SELECT pg_temp.assert_true(
  (SELECT status_code = 'boundary_too_complex'
     FROM field_collection.site_intake_status
    WHERE site_id = '10000000-0000-0000-0000-000000000012'),
  'a valid polygon above 500 positions must be refused before projection'
);

-- The relational source refuses a second boundary and orphan children before
-- either can affect the eligible projection.
DO $negative$
BEGIN
  BEGIN
    INSERT INTO field_collection.boundaries (id, site_id, boundary)
    VALUES
      ('20000000-0000-0000-0000-000000000008',
       '10000000-0000-0000-0000-000000000001',
       ST_GeomFromText('POLYGON((28 8,32 8,32 12,28 12,28 8))', 4326));
    RAISE EXCEPTION 'a second boundary was accepted';
  EXCEPTION WHEN unique_violation THEN
    NULL;
  END;

  BEGIN
    INSERT INTO field_collection.contacts (id, site_id, name)
    VALUES
      ('30000000-0000-4000-8000-000000000010',
       '10000000-0000-0000-0000-000000000099', 'Orphan');
    SET CONSTRAINTS ALL IMMEDIATE;
    RAISE EXCEPTION 'an orphan child was accepted';
  EXCEPTION WHEN foreign_key_violation THEN
    NULL;
  END;

  BEGIN
    INSERT INTO field_collection.sites
      (id, site_name, position, ready, form_version)
    VALUES
      ('10000000-0000-0000-0000-000000000010', 'Wrong geometry type',
       ST_GeomFromText('LINESTRING(29 9,31 11)', 4326), false,
       'field-site-v1');
    RAISE EXCEPTION 'a non-Point position was accepted';
  EXCEPTION WHEN OTHERS THEN
    IF SQLSTATE <> '22023' THEN
      RAISE;
    END IF;
  END;
END
$negative$;

-- The public source boundary is exactly five columns, and its three compound
-- values retain JSONB types for the bounded Adapter decoder.
SELECT pg_temp.assert_true(
  (SELECT array_agg(column_name::text ORDER BY ordinal_position) =
          ARRAY['id', 'site_name', 'position', 'boundary', 'contacts']
     FROM information_schema.columns
    WHERE table_schema = 'field_collection'
      AND table_name = 'eligible_sites'),
  'eligible_sites must expose only the governed projection'
);
SELECT pg_temp.assert_true(
  (SELECT bool_and(data_type = 'jsonb')
     FROM information_schema.columns
    WHERE table_schema = 'field_collection'
      AND table_name = 'eligible_sites'
      AND column_name IN ('position', 'boundary', 'contacts')),
  'geometry and repeats must remain JSONB'
);
SELECT pg_temp.assert_true(
  (SELECT array_agg(column_name::text ORDER BY ordinal_position) =
          ARRAY['site_id', 'status_code']
     FROM information_schema.columns
    WHERE table_schema = 'field_collection'
      AND table_name = 'site_intake_status'),
  'operator status must not expose collected answers'
);

-- The Adapter role can read the eligible projection and nothing below it.
SELECT pg_temp.assert_true(
  has_table_privilege(
    'field_collection_adapter_reader',
    'field_collection.eligible_sites',
    'SELECT'
  ),
  'the Adapter role must read eligible_sites'
);
SELECT pg_temp.assert_true(
  (SELECT NOT rolcanlogin
          AND NOT rolinherit
          AND NOT rolsuper
          AND NOT rolcreatedb
          AND NOT rolcreaterole
          AND NOT rolreplication
          AND NOT rolbypassrls
     FROM pg_catalog.pg_roles
    WHERE rolname = 'field_collection_adapter_reader'),
  'the Adapter projection role must carry no login or database authority'
);
SELECT pg_temp.assert_true(
  NOT has_table_privilege(
    'field_collection_adapter_reader', 'field_collection.sites', 'SELECT'
  )
  AND NOT has_table_privilege(
    'field_collection_adapter_reader', 'field_collection.sites', 'INSERT'
  )
  AND NOT has_table_privilege(
    'field_collection_adapter_reader', 'field_collection.boundaries', 'SELECT'
  )
  AND NOT has_table_privilege(
    'field_collection_adapter_reader', 'field_collection.contacts', 'SELECT'
  )
  AND NOT has_table_privilege(
    'field_collection_adapter_reader',
    'field_collection.site_intake_status',
    'SELECT'
  ),
  'the Adapter role must have no source, status or write privilege'
);
SET LOCAL ROLE field_collection_adapter_reader;
SELECT count(*) FROM field_collection.eligible_sites;
RESET ROLE;

ROLLBACK;
SELECT 'qfield-postgis source regression: ok' AS result;
