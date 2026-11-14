-- Institution-owned QField/PostGIS source contract.
--
-- Run this file as the source database owner. QFieldSync writes only the three
-- source tables. Registry Adapter receives SELECT on eligible_sites only and
-- cannot write source data or inspect drafts and rejected answers.
-- A deployment login receives membership in this projection-only role.
-- Check any existing group before creating the collection schema.
DO $role$
DECLARE
  existing_role record;
BEGIN
  SELECT oid, rolcanlogin, rolinherit, rolsuper, rolcreatedb, rolcreaterole,
         rolreplication, rolbypassrls
  INTO existing_role
  FROM pg_catalog.pg_roles
  WHERE rolname = 'field_collection_adapter_reader';

  IF NOT FOUND THEN
    CREATE ROLE field_collection_adapter_reader
      NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
      NOREPLICATION NOBYPASSRLS;
  ELSIF existing_role.rolcanlogin OR existing_role.rolinherit
     OR existing_role.rolsuper OR existing_role.rolcreatedb
     OR existing_role.rolcreaterole OR existing_role.rolreplication
     OR existing_role.rolbypassrls
     OR EXISTS (
       SELECT 1 FROM pg_catalog.pg_auth_members
       WHERE member = existing_role.oid
     ) THEN
    RAISE EXCEPTION 'field_collection_adapter_reader must be a dedicated NOLOGIN projection role';
  END IF;
END
$role$;

CREATE EXTENSION IF NOT EXISTS postgis;

CREATE SCHEMA field_collection;
REVOKE ALL ON SCHEMA field_collection FROM PUBLIC;

CREATE TABLE field_collection.sites (
  id uuid PRIMARY KEY,
  site_name text NOT NULL,
  position geometry(Point, 4326),
  ready boolean NOT NULL DEFAULT false,
  form_version text NOT NULL DEFAULT 'field-site-v1',
  expected_boundary_id uuid,
  -- QField's offline GeoPackage round-trips text predictably, unlike a
  -- PostgreSQL array. The value is the sorted, lowercase JSON array of the
  -- contact UUID strings that the completed form declares.
  expected_contact_ids text,
  CONSTRAINT sites_name_present CHECK (btrim(site_name) <> ''),
  CONSTRAINT sites_expected_contact_ids_bounded CHECK (
    expected_contact_ids IS NULL OR octet_length(expected_contact_ids) <= 512
  )
);

-- The transactional QFieldSync return can write child layers before sites.
-- All three layers must use the same PostgreSQL connection service. Enforce
-- the references at commit, after the full return has had a chance to land.
CREATE TABLE field_collection.boundaries (
  id uuid PRIMARY KEY,
  site_id uuid NOT NULL UNIQUE
    REFERENCES field_collection.sites(id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
  boundary geometry(Polygon, 4326) NOT NULL
);

CREATE TABLE field_collection.contacts (
  id uuid PRIMARY KEY,
  site_id uuid NOT NULL
    REFERENCES field_collection.sites(id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
  name text NOT NULL,
  CONSTRAINT contacts_name_present CHECK (btrim(name) <> ''),
  CONSTRAINT contacts_name_bounded CHECK (octet_length(name) <= 512)
);

CREATE INDEX contacts_site_id_idx ON field_collection.contacts(site_id);

-- This private view evaluates one source-owned snapshot of every site's root
-- and complete child set. It deliberately retains the answers needed for the
-- eligible projection, but no privilege on it is granted to Registry Adapter.
-- Geometry is reduced to the BReg project's seven-decimal CRS84 precision
-- before export. The reduced geometry is validated again, so rounding cannot
-- turn a source-valid shape into an invalid registry input.
CREATE VIEW field_collection._site_intake
WITH (security_barrier = true)
AS
WITH contact_counts AS (
  SELECT c.site_id, count(*) AS contact_count
  FROM field_collection.contacts AS c
  GROUP BY c.site_id
), bounded_contact_sets AS (
  SELECT
    c.site_id,
    jsonb_agg(
      jsonb_build_object('id', lower(c.id::text), 'name', c.name)
      ORDER BY lower(c.id::text)
    ) AS contacts,
    jsonb_agg(lower(c.id::text) ORDER BY lower(c.id::text))
      AS canonical_contact_ids,
    bool_and(char_length(c.name) BETWEEN 1 AND 80)
      AS contact_names_are_eligible
  FROM field_collection.contacts AS c
  JOIN contact_counts AS cc
    ON cc.site_id = c.site_id
   AND cc.contact_count BETWEEN 2 AND 8
  GROUP BY c.site_id
), contact_sets AS (
  SELECT
    cc.site_id,
    cc.contact_count,
    bcs.contacts,
    bcs.canonical_contact_ids,
    bcs.contact_names_are_eligible
  FROM contact_counts AS cc
  LEFT JOIN bounded_contact_sets AS bcs ON bcs.site_id = cc.site_id
), source_rows AS (
  SELECT
    s.*,
    b.id AS boundary_id,
    b.boundary,
    coalesce(cs.contact_count, 0) AS contact_count,
    cs.contacts,
    cs.canonical_contact_ids,
    coalesce(cs.contact_names_are_eligible, false)
      AS contact_names_are_eligible
  FROM field_collection.sites AS s
  LEFT JOIN field_collection.boundaries AS b ON b.site_id = s.id
  LEFT JOIN contact_sets AS cs ON cs.site_id = s.id
), normalized AS (
  SELECT
    r.*,
    CASE
      WHEN pg_input_is_valid(r.expected_contact_ids, 'jsonb')
        THEN r.expected_contact_ids::jsonb
      ELSE NULL
    END AS declared_contact_ids,
    CASE
      WHEN r.position IS NULL THEN NULL
      WHEN NOT ST_IsValid(r.position, 0) THEN NULL
      WHEN ST_X(r.position) NOT BETWEEN -180.0 AND 180.0 THEN NULL
      WHEN ST_Y(r.position) NOT BETWEEN -90.0 AND 90.0 THEN NULL
      ELSE ST_ReducePrecision(r.position, 0.0000001)
    END AS projected_position,
    CASE
      WHEN r.boundary IS NULL THEN NULL
      -- BReg accepts at most 500 positions. Checking before validity and JSON
      -- projection also prevents one extreme geometry from consuming a page.
      WHEN ST_NPoints(r.boundary) > 500 THEN NULL
      -- The flags overload returns the validity result without emitting a
      -- coordinate-bearing NOTICE for rejected source geometry.
      WHEN NOT ST_IsValid(r.boundary, 0) THEN NULL
      WHEN ST_XMin(Box3D(r.boundary)) < -180.0 THEN NULL
      WHEN ST_XMax(Box3D(r.boundary)) > 180.0 THEN NULL
      WHEN ST_YMin(Box3D(r.boundary)) < -90.0 THEN NULL
      WHEN ST_YMax(Box3D(r.boundary)) > 90.0 THEN NULL
      ELSE ST_ReducePrecision(r.boundary, 0.0000001)
    END AS projected_boundary
  FROM source_rows AS r
)
SELECT
  n.*,
  n.projected_position IS NOT NULL
    AND GeometryType(n.projected_position) = 'POINT'
    AND ST_SRID(n.projected_position) = 4326
    AND NOT ST_IsEmpty(n.projected_position)
    AND ST_IsValid(n.projected_position, 0)
    AND ST_X(n.projected_position) BETWEEN -180.0 AND 180.0
    AND ST_Y(n.projected_position) BETWEEN -90.0 AND 90.0
      AS position_is_eligible,
  n.projected_boundary IS NOT NULL
    AND GeometryType(n.projected_boundary) = 'POLYGON'
    AND ST_SRID(n.projected_boundary) = 4326
    AND NOT ST_IsEmpty(n.projected_boundary)
    AND ST_IsValid(n.projected_boundary, 0)
    AND ST_NPoints(n.projected_boundary) <= 500
    AND ST_XMin(Box3D(n.projected_boundary)) >= -180.0
    AND ST_XMax(Box3D(n.projected_boundary)) <= 180.0
    AND ST_YMin(Box3D(n.projected_boundary)) >= -90.0
    AND ST_YMax(Box3D(n.projected_boundary)) <= 90.0
      AS boundary_is_eligible
FROM normalized AS n;

-- Only complete, exact field-site-v1 submissions cross the source boundary.
-- Geometry and repeats remain typed JSONB; the governed Adapter pack decides
-- how those reviewed values map to one BReg Action or Proposal input.
CREATE VIEW field_collection.eligible_sites
WITH (security_barrier = true)
AS
SELECT
  i.id,
  i.site_name,
  ST_AsGeoJSON(i.projected_position, 7, 0)::jsonb AS position,
  ST_AsGeoJSON(i.projected_boundary, 7, 0)::jsonb AS boundary,
  i.contacts
FROM field_collection._site_intake AS i
WHERE i.ready
  AND i.form_version = 'field-site-v1'
  AND char_length(i.site_name) BETWEEN 1 AND 160
  AND i.position_is_eligible
  AND i.boundary_is_eligible
  AND i.expected_boundary_id = i.boundary_id
  AND i.contact_count BETWEEN 2 AND 8
  AND i.contact_names_are_eligible
  AND octet_length(i.contacts::text) <= 8192
  AND i.declared_contact_ids = i.canonical_contact_ids;

-- QField operators can show one structural status without disclosing site,
-- geometry or contact answers. The order is intentional: it identifies the
-- first action that can make a row eligible without leaking rejected values.
CREATE VIEW field_collection.site_intake_status
WITH (security_barrier = true)
AS
SELECT
  i.id AS site_id,
  CASE
    WHEN NOT i.ready THEN 'draft'
    WHEN i.form_version <> 'field-site-v1' THEN 'unsupported_form_version'
    WHEN char_length(i.site_name) NOT BETWEEN 1 AND 160 THEN 'site_name_invalid'
    WHEN i.position IS NULL THEN 'position_missing'
    WHEN NOT i.position_is_eligible THEN 'position_invalid'
    WHEN i.boundary_id IS NULL THEN 'boundary_missing'
    WHEN i.expected_boundary_id IS DISTINCT FROM i.boundary_id
      THEN 'boundary_id_mismatch'
    WHEN ST_NPoints(i.boundary) > 500 THEN 'boundary_too_complex'
    WHEN NOT i.boundary_is_eligible THEN 'boundary_invalid'
    WHEN i.contact_count = 0 THEN 'contacts_missing'
    WHEN i.contact_count NOT BETWEEN 2 AND 8 THEN 'contact_count_out_of_bounds'
    WHEN NOT i.contact_names_are_eligible THEN 'contact_name_invalid'
    WHEN octet_length(i.contacts::text) > 8192 THEN 'contacts_too_large'
    WHEN i.declared_contact_ids IS DISTINCT FROM i.canonical_contact_ids
      THEN 'contact_ids_mismatch'
    ELSE 'eligible'
  END AS status_code
FROM field_collection._site_intake AS i;

REVOKE ALL ON ALL TABLES IN SCHEMA field_collection FROM PUBLIC;

REVOKE ALL ON ALL TABLES IN SCHEMA field_collection
  FROM field_collection_adapter_reader;
GRANT USAGE ON SCHEMA field_collection TO field_collection_adapter_reader;
GRANT SELECT ON field_collection.eligible_sites
  TO field_collection_adapter_reader;
