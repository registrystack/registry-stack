CREATE SCHEMA IF NOT EXISTS registry_data;
CREATE SCHEMA IF NOT EXISTS registry_source;
CREATE SCHEMA IF NOT EXISTS registry_derived;
CREATE SCHEMA IF NOT EXISTS registry_context;
CREATE OR REPLACE FUNCTION registry_context.evaluation_date()
              RETURNS date
              LANGUAGE sql
              STABLE
              SECURITY INVOKER
              AS $registry_server_function$
                  SELECT NULLIF(current_setting('registry.evaluation_date', true), '')::date
              $registry_server_function$;
CREATE TABLE registry_data."rs_e_group_membership_6b97f4204f141f28" (record_id uuid NOT NULL, record_revision bigint NOT NULL DEFAULT 1 CHECK (record_revision > 0), record_lifecycle text NOT NULL DEFAULT 'active' CHECK (record_lifecycle IN ('active', 'tombstoned')), created_at timestamptz NOT NULL DEFAULT transaction_timestamp(), updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(), active_package_revision text NOT NULL DEFAULT NULLIF(current_setting('registry.active_package_revision', true), '') CHECK (active_package_revision <> ''), PRIMARY KEY (record_id), "rs_f_group_membership_household_9ce011eef65483bd" uuid NOT NULL, "rs_f_group_membership_person_f16f370962050e27" uuid NOT NULL, "rs_f_group_membership_relationship_4da0b16845ccd25c" text NOT NULL CHECK ("rs_f_group_membership_relationship_4da0b16845ccd25c" IN ('head', 'spouse', 'child', 'dependent', 'other')), "rs_f_group_membership_valid_from_9982e6778a7c4410" date NOT NULL, "rs_f_group_membership_valid_to_6eb49ef9d6a65085" date);
CREATE TABLE registry_data."rs_e_household_45e8576d356a1f75" (record_id uuid NOT NULL, record_revision bigint NOT NULL DEFAULT 1 CHECK (record_revision > 0), record_lifecycle text NOT NULL DEFAULT 'active' CHECK (record_lifecycle IN ('active', 'tombstoned')), created_at timestamptz NOT NULL DEFAULT transaction_timestamp(), updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(), active_package_revision text NOT NULL DEFAULT NULLIF(current_setting('registry.active_package_revision', true), '') CHECK (active_package_revision <> ''), PRIMARY KEY (record_id), "rs_f_household_administrative_area_1946b433a9241a87" varchar(80) NOT NULL, "rs_f_household_household_code_44029c0143d71ab3" varchar(64) NOT NULL, "rs_f_household_household_name_aeac0ac6071a6b3d" varchar(160) NOT NULL, "rs_f_household_household_type_87fa3a1f7183bbe0" text NOT NULL CHECK ("rs_f_household_household_type_87fa3a1f7183bbe0" IN ('private', 'collective', 'institutional')), "rs_f_household_local_household_number_040305e8ef37727d" bigint NOT NULL);
CREATE TABLE registry_data."rs_e_person_a28225974420754a" (record_id uuid NOT NULL, record_revision bigint NOT NULL DEFAULT 1 CHECK (record_revision > 0), record_lifecycle text NOT NULL DEFAULT 'active' CHECK (record_lifecycle IN ('active', 'tombstoned')), created_at timestamptz NOT NULL DEFAULT transaction_timestamp(), updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(), active_package_revision text NOT NULL DEFAULT NULLIF(current_setting('registry.active_package_revision', true), '') CHECK (active_package_revision <> ''), PRIMARY KEY (record_id), "rs_f_person_date_of_birth_d4d8fa151f4a4285" date, "rs_f_person_family_name_1a6b1252713201d7" varchar(120), "rs_f_person_legal_name_142f648a19dcd2a4" varchar(160) NOT NULL, "rs_f_person_person_code_7514464caf72c5a7" varchar(64) NOT NULL, "rs_f_person_person_sex_01e02174128c75d2" text NOT NULL CHECK ("rs_f_person_person_sex_01e02174128c75d2" IN ('female', 'male', 'unknown')), "rs_f_person_preferred_language_d36dc5f1bd7bec3c" text CHECK ("rs_f_person_preferred_language_d36dc5f1bd7bec3c" IN ('en', 'es', 'fr')), "rs_f_person_residency_status_19ed35302430c5ac" text NOT NULL CHECK ("rs_f_person_residency_status_19ed35302430c5ac" IN ('usual-resident', 'temporary-resident', 'departed')));
ALTER TABLE registry_data."rs_e_group_membership_6b97f4204f141f28" ADD CONSTRAINT "registry_temporal_order_60d3dc851ed107ae8e3358d4" CHECK ("rs_f_group_membership_valid_to_6eb49ef9d6a65085" IS NULL OR "rs_f_group_membership_valid_from_9982e6778a7c4410" < "rs_f_group_membership_valid_to_6eb49ef9d6a65085");
ALTER TABLE registry_data."rs_e_group_membership_6b97f4204f141f28" ADD CONSTRAINT "rs_r_group_membership_household_b380b31f7172d457" FOREIGN KEY ("rs_f_group_membership_household_9ce011eef65483bd") REFERENCES registry_data."rs_e_household_45e8576d356a1f75" (record_id) ON DELETE RESTRICT;
ALTER TABLE registry_data."rs_e_group_membership_6b97f4204f141f28" ADD CONSTRAINT "rs_r_group_membership_person_a7a0a93318d692c5" FOREIGN KEY ("rs_f_group_membership_person_f16f370962050e27") REFERENCES registry_data."rs_e_person_a28225974420754a" (record_id) ON DELETE RESTRICT;
ALTER TABLE registry_data."rs_e_group_membership_6b97f4204f141f28" ADD CONSTRAINT "rs_c_group_membership_temporal_non_overlap_4a7_a431d790c9c7107c" EXCLUDE USING gist ("rs_f_group_membership_person_f16f370962050e27" WITH =, daterange("rs_f_group_membership_valid_from_9982e6778a7c4410", "rs_f_group_membership_valid_to_6eb49ef9d6a65085", '[)') WITH &&);
ALTER TABLE registry_data."rs_e_group_membership_6b97f4204f141f28" ADD CONSTRAINT "rs_c_group_membership_unique_29ca03124bd627de_1e94e199498d973c" UNIQUE ("rs_f_group_membership_person_f16f370962050e27", "rs_f_group_membership_household_9ce011eef65483bd", "rs_f_group_membership_valid_from_9982e6778a7c4410");
ALTER TABLE registry_data."rs_e_household_45e8576d356a1f75" ADD CONSTRAINT "rs_c_household_unique_35644d63b5c27a2d_29e5106744bb8f85" UNIQUE ("rs_f_household_administrative_area_1946b433a9241a87", "rs_f_household_local_household_number_040305e8ef37727d");
ALTER TABLE registry_data."rs_e_household_45e8576d356a1f75" ADD CONSTRAINT "rs_c_household_unique_5c243bbc691c96ec_a2783944072ade3e" UNIQUE ("rs_f_household_household_code_44029c0143d71ab3");
ALTER TABLE registry_data."rs_e_person_a28225974420754a" ADD CONSTRAINT "rs_c_person_unique_36996ff8fe2e1319_14d44b100fef1335" UNIQUE ("rs_f_person_person_code_7514464caf72c5a7");
ALTER TABLE registry_data."rs_e_group_membership_6b97f4204f141f28" ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry_data."rs_e_group_membership_6b97f4204f141f28" FORCE ROW LEVEL SECURITY;
CREATE POLICY "registry_rls_select_e4c68d24a3cc83c24851f3eb" ON registry_data."rs_e_group_membership_6b97f4204f141f28" FOR SELECT USING ((NULLIF(current_setting('registry.access_profile', true), '') = 'household-operator' AND NULLIF(current_setting('registry.principal', true), '') IS NOT NULL AND NULLIF(current_setting('registry.purpose', true), '') IN ('household-administration') AND jsonb_typeof(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 'array' AND jsonb_array_length(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 0) AND record_lifecycle = 'active');
CREATE POLICY "registry_rls_insert_95851ffed84c5ef8be616113" ON registry_data."rs_e_group_membership_6b97f4204f141f28" FOR INSERT WITH CHECK ((NULLIF(current_setting('registry.access_profile', true), '') = 'household-operator' AND NULLIF(current_setting('registry.principal', true), '') IS NOT NULL AND NULLIF(current_setting('registry.purpose', true), '') IN ('household-administration') AND jsonb_typeof(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 'array' AND jsonb_array_length(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 0) AND record_lifecycle = 'active');
CREATE POLICY "registry_rls_update_8ebb61cfa44b068b3de15a37" ON registry_data."rs_e_group_membership_6b97f4204f141f28" FOR UPDATE USING ((NULLIF(current_setting('registry.access_profile', true), '') = 'household-operator' AND NULLIF(current_setting('registry.principal', true), '') IS NOT NULL AND NULLIF(current_setting('registry.purpose', true), '') IN ('household-administration') AND jsonb_typeof(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 'array' AND jsonb_array_length(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 0) AND record_lifecycle = 'active') WITH CHECK ((NULLIF(current_setting('registry.access_profile', true), '') = 'household-operator' AND NULLIF(current_setting('registry.principal', true), '') IS NOT NULL AND NULLIF(current_setting('registry.purpose', true), '') IN ('household-administration') AND jsonb_typeof(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 'array' AND jsonb_array_length(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 0) AND record_lifecycle = 'active');
CREATE POLICY "registry_path_rls_select_d40194fdac27176f50e7bab9" ON registry_data."rs_e_group_membership_6b97f4204f141f28" FOR SELECT USING ((NULLIF(current_setting('registry.access_profile', true), '') = 'household-operator' AND NULLIF(current_setting('registry.principal', true), '') IS NOT NULL AND NULLIF(current_setting('registry.purpose', true), '') IN ('household-administration')) AND NULLIF(current_setting('registry.read_path_id', true), '') = 'people' AND record_lifecycle = 'active' AND "rs_f_group_membership_household_9ce011eef65483bd" = NULLIF(current_setting('registry.read_path_root_id', true), '')::uuid
             AND EXISTS (
                 SELECT 1
                   FROM registry_data."rs_e_household_45e8576d356a1f75" AS path_source
                  WHERE path_source.record_id = "rs_f_group_membership_household_9ce011eef65483bd"
                    AND path_source.record_lifecycle = 'active'
                    AND (NULLIF(current_setting('registry.access_profile', true), '') = 'household-operator' AND NULLIF(current_setting('registry.principal', true), '') IS NOT NULL AND NULLIF(current_setting('registry.purpose', true), '') IN ('household-administration') AND jsonb_typeof(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 'array' AND jsonb_array_length(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 0)
             ));
CREATE VIEW registry_source."group_membership"
                 WITH (security_invoker=true, security_barrier=true)
                 AS SELECT record_id AS id, "rs_f_group_membership_person_f16f370962050e27" AS "person", "rs_f_group_membership_household_9ce011eef65483bd" AS "household", "rs_f_group_membership_relationship_4da0b16845ccd25c" AS "relationship", "rs_f_group_membership_valid_from_9982e6778a7c4410" AS "valid_from", "rs_f_group_membership_valid_to_6eb49ef9d6a65085" AS "valid_to"
                    FROM registry_data."rs_e_group_membership_6b97f4204f141f28"
                   WHERE record_lifecycle = 'active';
ALTER TABLE registry_data."rs_e_household_45e8576d356a1f75" ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry_data."rs_e_household_45e8576d356a1f75" FORCE ROW LEVEL SECURITY;
CREATE POLICY "registry_rls_select_f2348f1ea686c085c254174f" ON registry_data."rs_e_household_45e8576d356a1f75" FOR SELECT USING ((NULLIF(current_setting('registry.access_profile', true), '') = 'household-operator' AND NULLIF(current_setting('registry.principal', true), '') IS NOT NULL AND NULLIF(current_setting('registry.purpose', true), '') IN ('household-administration') AND jsonb_typeof(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 'array' AND jsonb_array_length(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 0) AND record_lifecycle = 'active');
CREATE POLICY "registry_rls_insert_a49ea44589b3bfd7550c1880" ON registry_data."rs_e_household_45e8576d356a1f75" FOR INSERT WITH CHECK ((NULLIF(current_setting('registry.access_profile', true), '') = 'household-operator' AND NULLIF(current_setting('registry.principal', true), '') IS NOT NULL AND NULLIF(current_setting('registry.purpose', true), '') IN ('household-administration') AND jsonb_typeof(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 'array' AND jsonb_array_length(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 0) AND record_lifecycle = 'active');
CREATE POLICY "registry_rls_update_b573105c01cf4eb57ca69c80" ON registry_data."rs_e_household_45e8576d356a1f75" FOR UPDATE USING ((NULLIF(current_setting('registry.access_profile', true), '') = 'household-operator' AND NULLIF(current_setting('registry.principal', true), '') IS NOT NULL AND NULLIF(current_setting('registry.purpose', true), '') IN ('household-administration') AND jsonb_typeof(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 'array' AND jsonb_array_length(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 0) AND record_lifecycle = 'active') WITH CHECK ((NULLIF(current_setting('registry.access_profile', true), '') = 'household-operator' AND NULLIF(current_setting('registry.principal', true), '') IS NOT NULL AND NULLIF(current_setting('registry.purpose', true), '') IN ('household-administration') AND jsonb_typeof(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 'array' AND jsonb_array_length(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 0) AND record_lifecycle = 'active');
CREATE POLICY "registry_rls_select_bf0afc959f020c9105952b7d" ON registry_data."rs_e_household_45e8576d356a1f75" FOR SELECT USING ((NULLIF(current_setting('registry.access_profile', true), '') = 'household-viewer' AND NULLIF(current_setting('registry.principal', true), '') IS NOT NULL AND NULLIF(current_setting('registry.purpose', true), '') IN ('household-view') AND jsonb_typeof(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 'array' AND jsonb_array_length(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 1 AND jsonb_typeof((NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb -> 0)) = 'object' AND ((NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb -> 0) - 'field' - 'operator' - 'values') = '{}'::jsonb AND (NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb -> 0) ->> 'field' = 'id' AND (NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb -> 0) ->> 'operator' = 'equals' AND jsonb_typeof(((NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb -> 0) -> 'values')) = 'array' AND jsonb_array_length(((NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb -> 0) -> 'values')) = 1 AND record_id = (((NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb -> 0) -> 'values') ->> 0)::uuid) AND record_lifecycle = 'active');
CREATE POLICY "registry_path_rls_select_c8cb6ccd10712973c3e46aaf" ON registry_data."rs_e_household_45e8576d356a1f75" FOR SELECT USING ((NULLIF(current_setting('registry.access_profile', true), '') = 'household-operator' AND NULLIF(current_setting('registry.principal', true), '') IS NOT NULL AND NULLIF(current_setting('registry.purpose', true), '') IN ('household-administration') AND jsonb_typeof(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 'array' AND jsonb_array_length(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 0) AND NULLIF(current_setting('registry.read_path_id', true), '') = 'people' AND record_id = NULLIF(current_setting('registry.read_path_root_id', true), '')::uuid AND record_lifecycle = 'active');
CREATE VIEW registry_source."household"
                 WITH (security_invoker=true, security_barrier=true)
                 AS SELECT record_id AS id, "rs_f_household_household_code_44029c0143d71ab3" AS "household_code", "rs_f_household_local_household_number_040305e8ef37727d" AS "local_household_number", "rs_f_household_household_name_aeac0ac6071a6b3d" AS "household_name", "rs_f_household_administrative_area_1946b433a9241a87" AS "administrative_area", "rs_f_household_household_type_87fa3a1f7183bbe0" AS "household_type"
                    FROM registry_data."rs_e_household_45e8576d356a1f75"
                   WHERE record_lifecycle = 'active';
ALTER TABLE registry_data."rs_e_person_a28225974420754a" ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry_data."rs_e_person_a28225974420754a" FORCE ROW LEVEL SECURITY;
CREATE POLICY "registry_rls_select_799283181617a6fa58c49141" ON registry_data."rs_e_person_a28225974420754a" FOR SELECT USING ((NULLIF(current_setting('registry.access_profile', true), '') = 'household-operator' AND NULLIF(current_setting('registry.principal', true), '') IS NOT NULL AND NULLIF(current_setting('registry.purpose', true), '') IN ('household-administration') AND jsonb_typeof(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 'array' AND jsonb_array_length(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 0) AND record_lifecycle = 'active');
CREATE POLICY "registry_rls_insert_4439eb1ffa28a9c2175ef14d" ON registry_data."rs_e_person_a28225974420754a" FOR INSERT WITH CHECK ((NULLIF(current_setting('registry.access_profile', true), '') = 'household-operator' AND NULLIF(current_setting('registry.principal', true), '') IS NOT NULL AND NULLIF(current_setting('registry.purpose', true), '') IN ('household-administration') AND jsonb_typeof(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 'array' AND jsonb_array_length(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 0) AND record_lifecycle = 'active');
CREATE POLICY "registry_rls_update_1c8bc48adff601b70fae3086" ON registry_data."rs_e_person_a28225974420754a" FOR UPDATE USING ((NULLIF(current_setting('registry.access_profile', true), '') = 'household-operator' AND NULLIF(current_setting('registry.principal', true), '') IS NOT NULL AND NULLIF(current_setting('registry.purpose', true), '') IN ('household-administration') AND jsonb_typeof(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 'array' AND jsonb_array_length(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 0) AND record_lifecycle = 'active') WITH CHECK ((NULLIF(current_setting('registry.access_profile', true), '') = 'household-operator' AND NULLIF(current_setting('registry.principal', true), '') IS NOT NULL AND NULLIF(current_setting('registry.purpose', true), '') IN ('household-administration') AND jsonb_typeof(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 'array' AND jsonb_array_length(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 0) AND record_lifecycle = 'active');
CREATE POLICY "registry_path_rls_select_b32737d82dfcb2dfac05ef5c" ON registry_data."rs_e_person_a28225974420754a" FOR SELECT USING ((NULLIF(current_setting('registry.access_profile', true), '') = 'household-operator' AND NULLIF(current_setting('registry.principal', true), '') IS NOT NULL AND NULLIF(current_setting('registry.purpose', true), '') IN ('household-administration')) AND NULLIF(current_setting('registry.read_path_id', true), '') = 'people' AND record_lifecycle = 'active'
             AND EXISTS (
                 SELECT 1
                   FROM registry_data."rs_e_group_membership_6b97f4204f141f28" AS path_edge
                   JOIN registry_data."rs_e_household_45e8576d356a1f75" AS path_source
                     ON path_source.record_id = path_edge."rs_f_group_membership_household_9ce011eef65483bd"
                  WHERE path_edge."rs_f_group_membership_person_f16f370962050e27" = "rs_e_person_a28225974420754a".record_id
                    AND path_edge."rs_f_group_membership_household_9ce011eef65483bd" = NULLIF(current_setting('registry.read_path_root_id', true), '')::uuid
                    AND path_edge.record_lifecycle = 'active'
                    AND path_source.record_lifecycle = 'active'
                    AND (NULLIF(current_setting('registry.access_profile', true), '') = 'household-operator' AND NULLIF(current_setting('registry.principal', true), '') IS NOT NULL AND NULLIF(current_setting('registry.purpose', true), '') IN ('household-administration') AND jsonb_typeof(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 'array' AND jsonb_array_length(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 0)
             ));
CREATE VIEW registry_source."person"
                 WITH (security_invoker=true, security_barrier=true)
                 AS SELECT record_id AS id, "rs_f_person_person_code_7514464caf72c5a7" AS "person_code", "rs_f_person_legal_name_142f648a19dcd2a4" AS "legal_name", "rs_f_person_family_name_1a6b1252713201d7" AS "family_name", "rs_f_person_date_of_birth_d4d8fa151f4a4285" AS "date_of_birth", "rs_f_person_person_sex_01e02174128c75d2" AS "person_sex", "rs_f_person_residency_status_19ed35302430c5ac" AS "residency_status", "rs_f_person_preferred_language_d36dc5f1bd7bec3c" AS "preferred_language"
                    FROM registry_data."rs_e_person_a28225974420754a"
                   WHERE record_lifecycle = 'active';
CREATE VIEW registry_derived."household__household_demographics"
                     WITH (security_invoker=true, security_barrier=true)
                     AS SELECT "__registry$derived$key" AS "id", "head_count"::bigint AS "head_count", "child_count"::bigint AS "child_count", "child_under_5_count"::bigint AS "child_under_5_count", "elderly_count"::bigint AS "elderly_count", "single_headed"::boolean AS "single_headed", "woman_headed"::boolean AS "woman_headed"
                        FROM (
                            SELECT canonical_derived.*,
                                   count(*) OVER (PARTITION BY canonical_derived."__registry$derived$key") AS "__registry$derived$cardinality"
                              FROM (
                                  SELECT trusted_derived.*,
                                         trusted_derived."id"::uuid AS "__registry$derived$key"
                                    FROM (SELECT
  h.id AS id,
  count(*) FILTER (
    WHERE gm.relationship = 'head'
      AND gm.valid_from <= registry_context.evaluation_date()
      AND (gm.valid_to IS NULL OR registry_context.evaluation_date() < gm.valid_to)
  )::bigint AS head_count,
  count(*) FILTER (
    WHERE gm.relationship = 'child'
      AND gm.valid_from <= registry_context.evaluation_date()
      AND (gm.valid_to IS NULL OR registry_context.evaluation_date() < gm.valid_to)
  )::bigint AS child_count,
  count(*) FILTER (
    WHERE gm.relationship = 'child'
      AND p.date_of_birth > (registry_context.evaluation_date() - 5 * INTERVAL '1 year')::date
      AND gm.valid_from <= registry_context.evaluation_date()
      AND (gm.valid_to IS NULL OR registry_context.evaluation_date() < gm.valid_to)
  )::bigint AS child_under_5_count,
  count(*) FILTER (
    WHERE p.date_of_birth <= (registry_context.evaluation_date() - 65 * INTERVAL '1 year')::date
      AND gm.valid_from <= registry_context.evaluation_date()
      AND (gm.valid_to IS NULL OR registry_context.evaluation_date() < gm.valid_to)
  )::bigint AS elderly_count,
  (
    count(*) FILTER (
      WHERE gm.relationship = 'head'
        AND gm.valid_from <= registry_context.evaluation_date()
        AND (gm.valid_to IS NULL OR registry_context.evaluation_date() < gm.valid_to)
    ) = 1
    AND count(*) FILTER (
      WHERE gm.relationship = 'spouse'
        AND gm.valid_from <= registry_context.evaluation_date()
        AND (gm.valid_to IS NULL OR registry_context.evaluation_date() < gm.valid_to)
    ) = 0
  ) AS single_headed,
  (
    count(*) FILTER (
      WHERE gm.relationship = 'head'
        AND p.person_sex = 'female'
        AND gm.valid_from <= registry_context.evaluation_date()
        AND (gm.valid_to IS NULL OR registry_context.evaluation_date() < gm.valid_to)
    ) > 0
  ) AS woman_headed
FROM registry_source.household h
LEFT JOIN registry_source.group_membership gm
  ON gm.household = h.id
LEFT JOIN registry_source.person p
  ON p.id = gm.person
GROUP BY h.id) AS trusted_derived
                              ) AS canonical_derived
                        ) AS checked_derived
                       WHERE CASE
                           WHEN "__registry$derived$key" IS NOT NULL AND "__registry$derived$cardinality" = 1 THEN true
                           -- PostgreSQL has no scalar ASSERT. This row-dependent
                           -- expression raises one stable, value-free error for
                           -- a null or duplicate canonical key.
                           ELSE 1 / ("__registry$derived$cardinality" - "__registry$derived$cardinality") = 0
                       END;
