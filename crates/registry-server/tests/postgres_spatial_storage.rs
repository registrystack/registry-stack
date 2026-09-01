// SPDX-License-Identifier: Apache-2.0

use registry_server::compiler::{compile_project, compile_project_with_assets, CompileProfile};
use registry_server::contract::{parse_project_json, ModuleAssetSource};
use registry_server::generated_ddl::{
    DdlObjectOwner, DdlPolicyRole, DdlStatementKind, TablePrivilege,
};
use serde_json::json;

#[test]
fn bbox_grant_derives_postgis_projection_policy_and_inventory() {
    let registry = compiled_spatial_registry();

    assert!(registry.ddl().requires_postgis);
    let serialized = serde_json::to_value(registry.ddl()).expect("DDL inventory serializes");
    assert_eq!(serialized["requiresPostgis"], json!(true));

    let table_sql = registry
        .ddl()
        .statements
        .iter()
        .find(|statement| statement.id == "entity.site.table")
        .expect("table DDL is emitted")
        .sql
        .as_str();
    assert!(table_sql.contains("registry_spatial_ext.geometry(Point,4326)"));
    assert!(table_sql.contains("GENERATED ALWAYS AS"));
    assert!(table_sql.contains("registry_spatial_ext.ST_SetSRID"));
    assert!(table_sql.contains("registry_spatial_ext.ST_MakePoint"));

    assert!(registry.ddl().statements.iter().any(|statement| {
        statement.kind == DdlStatementKind::Function
            && statement
                .sql
                .contains("registry_context.spatial_bbox_geometry")
            && statement.sql.contains("SECURITY INVOKER")
            && statement
                .sql
                .contains("registry_spatial_ext.ST_MakeEnvelope")
    }));
    assert!(registry.ddl().statements.iter().any(|statement| {
        statement.kind == DdlStatementKind::Index
            && statement.sql.contains("USING gist")
            && statement.sql.contains("WHERE \"rs_spgeom_")
    }));

    let table = registry
        .ddl()
        .tables
        .iter()
        .find(|table| table.entity_id == "site")
        .expect("site table inventory exists");
    assert!(table
        .spatial_bbox_privileges
        .contains(&TablePrivilege::Select));
    assert!(table.policies.iter().any(|policy| {
        policy.applies_to == DdlPolicyRole::Runtime
            && policy.command.as_sql() == "SELECT"
            && policy
                .using_expression
                .as_deref()
                .is_some_and(|sql| !sql.contains("ST_Intersects"))
    }));
    let bbox_policy = table
        .policies
        .iter()
        .find(|policy| policy.applies_to == DdlPolicyRole::SpatialBbox)
        .expect("bbox role receives a separate policy");
    let bbox_sql = bbox_policy
        .using_expression
        .as_deref()
        .expect("bbox policy has a USING expression");
    assert!(bbox_sql.contains("registry.access_profile"));
    assert!(bbox_sql.contains("record_lifecycle = 'active'"));
    assert!(bbox_sql.contains("BETWEEN 0 AND 0.25"));
    assert!(bbox_sql.contains("BETWEEN 0 AND 1.5"));
    assert!(bbox_sql.contains("OPERATOR(registry_spatial_ext.&&)"));
    assert!(bbox_sql.contains("registry_spatial_ext.ST_Intersects"));
    assert!(bbox_sql.contains("registry_context.spatial_bbox_geometry()"));
    let postgis_position = bbox_sql
        .find("registry_spatial_ext.ST_Intersects")
        .expect("bbox policy contains exact PostGIS predicate");
    let residual_position = bbox_sql
        .find("-> 'coordinates' ->> 0)::numeric")
        .expect("bbox policy contains exact numeric JSONB residual");
    assert!(
        postgis_position < residual_position,
        "exact numeric residual must remain after the mandatory PostGIS predicate"
    );
    assert!(bbox_sql.contains(">= NULLIF(current_setting('registry.bbox_west'"));
    assert!(bbox_sql.contains("<= NULLIF(current_setting('registry.bbox_east'"));
    assert!(bbox_sql.contains(">= NULLIF(current_setting('registry.bbox_south'"));
    assert!(bbox_sql.contains("<= NULLIF(current_setting('registry.bbox_north'"));

    let source_view_sql = registry
        .ddl()
        .statements
        .iter()
        .find(|statement| statement.id == "entity.site.source-view")
        .expect("source view is emitted")
        .sql
        .as_str();
    assert!(!source_view_sql.contains("rs_spgeom_"));

    let candidate_view = registry
        .ddl()
        .views
        .iter()
        .find(|view| view.id == "entity.site.spatial-candidates")
        .expect("candidate ID view is inventoried");
    assert_eq!(candidate_view.schema, "registry_context");
    assert_eq!(candidate_view.owner, DdlObjectOwner::SpatialBbox);
    assert!(candidate_view
        .runtime_privileges
        .contains(&TablePrivilege::Select));
    let candidate_sql = registry
        .ddl()
        .statements
        .iter()
        .find(|statement| statement.id == "entity.site.spatial-candidates-view")
        .expect("candidate ID view statement is emitted")
        .sql
        .as_str();
    assert!(candidate_sql.contains("WITH (security_invoker=false, security_barrier=true)"));
    assert!(candidate_sql.contains("SELECT record_id AS id"));
    assert!(candidate_sql.contains("registry_spatial_ext.ST_Intersects"));
}

fn compiled_spatial_registry() -> registry_server::CompiledRegistry {
    compile_project(
        &parse_project_json(
            br#"{
              "apiVersion":"registry.registrystack.org/v1alpha1",
              "kind":"RegistryProject",
              "registry":{"id":"spatial-storage","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
              "entities":[{
                "id":"site","primaryDataset":"test-dataset","route":"sites","mutationMode":"mutable","tombstone":true,"classification":"internal",
                "fields":[
                  {"id":"code","type":"string","maxLength":32,"required":true,"classification":"internal"},
                  {"id":"location","type":"crs84-point","precision":6,"classification":"internal"}
                ],
                "geojson":{"geometryField":"location"}
              }],
              "accessProfiles":[{
                "id":"map-reader","default":true,"principalClaim":"principal","grants":[{
                  "entity":"site","operations":["create","get","list","patch","tombstone"],
                  "readableFields":["code","location"],"writableFields":["code","location"],
                  "spatialQueries":{"bbox":{"maximumLongitudeSpanDegrees":0.25,"maximumLatitudeSpanDegrees":1.5}}
                }]
              }]
            }"#,
        )
        .expect("project parses"),
        &[],
        CompileProfile::Authoring,
    )
    .expect("spatial project compiles")
}

fn compiled_spatial_derived_registry() -> registry_server::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"spatial-derived-storage","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"site","primaryDataset":"test-dataset","route":"sites","mutationMode":"mutable","classification":"internal",
            "fields":[
              {"id":"code","type":"string","maxLength":32,"required":true,"classification":"internal"},
              {"id":"location","type":"crs84-point","precision":6,"classification":"internal"}
            ],
            "geojson":{"geometryField":"location"},
            "derived":[{
              "id":"labels","sql":"sql/site-labels.sql","key":"id","execution":"live",
              "fields":[{"id":"map-label","type":"string","maxLength":64,"classification":"internal"}]
            }]
          }],
          "accessProfiles":[{
            "id":"map-reader","default":true,"principalClaim":"principal","grants":[{
              "entity":"site","operations":["create","get","list","patch"],
              "readableFields":["code","location","map-label"],
              "writableFields":["code","location"],
              "filterableFields":["map-label"],
              "sortableFields":["map-label"],
              "spatialQueries":{"bbox":{"maximumLongitudeSpanDegrees":0.25,"maximumLatitudeSpanDegrees":1.5}}
            }]
          }]
        }"#,
    )
    .expect("derived spatial project parses");
    compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "sql/site-labels.sql".to_owned(),
            bytes: b"SELECT s.id AS id, s.code AS map_label FROM registry_source.site s".to_vec(),
        }],
        CompileProfile::Authoring,
    )
    .expect("derived spatial project compiles")
}

fn compiled_spatial_cross_entity_derived_registry() -> registry_server::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"spatial-cross-derived-storage","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"zone","primaryDataset":"test-dataset","route":"zones","mutationMode":"mutable","classification":"internal",
            "fields":[
              {"id":"code","type":"string","maxLength":32,"required":true,"classification":"internal"},
              {"id":"label","type":"string","maxLength":64,"required":true,"classification":"internal"}
            ]
          },{
            "id":"site","primaryDataset":"test-dataset","route":"sites","mutationMode":"mutable","classification":"internal",
            "fields":[
              {"id":"code","type":"string","maxLength":32,"required":true,"classification":"internal"},
              {"id":"zone","type":"reference","target":"zone","required":true,"classification":"internal"},
              {"id":"location","type":"crs84-point","precision":6,"classification":"internal"}
            ],
            "geojson":{"geometryField":"location"},
            "derived":[{
              "id":"labels","sql":"sql/site-zone-labels.sql","key":"id","execution":"live",
              "fields":[{"id":"map-label","type":"string","maxLength":96,"classification":"internal"}]
            }]
          }],
          "accessProfiles":[{
            "id":"map-reader","default":true,"principalClaim":"principal","grants":[{
              "entity":"zone","operations":["create","get","list"],
              "readableFields":["code","label"],"writableFields":["code","label"]
            },{
              "entity":"site","operations":["create","get","list","patch"],
              "readableFields":["code","zone","location","map-label"],
              "writableFields":["code","zone","location"],
              "filterableFields":["map-label"],
              "sortableFields":["map-label"],
              "spatialQueries":{"bbox":{"maximumLongitudeSpanDegrees":0.25,"maximumLatitudeSpanDegrees":1.5}}
            }]
          }]
        }"#,
    )
    .expect("cross-entity derived spatial project parses");
    compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "sql/site-zone-labels.sql".to_owned(),
            bytes: b"SELECT s.id AS id, z.label AS map_label FROM registry_source.site s JOIN registry_source.zone z ON z.id = s.zone".to_vec(),
        }],
        CompileProfile::Authoring,
    )
    .expect("cross-entity derived spatial project compiles")
}

#[test]
fn bbox_derived_fields_grant_only_needed_view_inventory() {
    let registry = compiled_spatial_derived_registry();
    let source_views = registry
        .ddl()
        .views
        .iter()
        .filter(|view| view.schema == "registry_source")
        .collect::<Vec<_>>();
    assert!(!source_views.is_empty());
    assert!(source_views
        .iter()
        .all(|view| view.owner == DdlObjectOwner::Migration));

    let derived_view = registry
        .ddl()
        .views
        .iter()
        .find(|view| view.id == "entity.site.derived.labels")
        .expect("derived labels view is inventoried");
    assert_eq!(derived_view.owner, DdlObjectOwner::Migration);

    let serialized = serde_json::to_value(registry.ddl()).expect("DDL inventory serializes");
    assert_eq!(
        serialized["views"]
            .as_array()
            .expect("views serialize")
            .iter()
            .filter(|view| view.get("owner") == Some(&json!("spatial_bbox")))
            .count(),
        1,
        "only the candidate ID view is bbox-owned"
    );
}

#[test]
fn bbox_cross_entity_derived_dependency_keeps_ordinary_view_inventory() {
    let registry = compiled_spatial_cross_entity_derived_registry();
    let source_views = registry
        .ddl()
        .views
        .iter()
        .filter(|view| view.schema == "registry_source")
        .map(|view| (view.name.as_str(), view.owner))
        .collect::<Vec<_>>();
    assert_eq!(
        source_views,
        vec![
            ("site", DdlObjectOwner::Migration),
            ("zone", DdlObjectOwner::Migration)
        ]
    );

    let derived_views = registry
        .ddl()
        .views
        .iter()
        .filter(|view| view.schema == "registry_derived")
        .map(|view| (view.name.as_str(), view.owner))
        .collect::<Vec<_>>();
    assert_eq!(
        derived_views,
        vec![("site__labels", DdlObjectOwner::Migration)]
    );

    let zone_table = registry
        .ddl()
        .tables
        .iter()
        .find(|table| table.entity_id == "zone")
        .expect("zone table inventory exists");
    assert!(zone_table.spatial_bbox_privileges.is_empty());
    assert!(zone_table
        .policies
        .iter()
        .all(|policy| policy.applies_to != DdlPolicyRole::SpatialBbox));

    let site_table = registry
        .ddl()
        .tables
        .iter()
        .find(|table| table.entity_id == "site")
        .expect("site table inventory exists");
    assert_eq!(
        site_table
            .policies
            .iter()
            .filter(|policy| policy.applies_to == DdlPolicyRole::SpatialBbox)
            .count(),
        1,
        "root GIS table keeps only the exact spatial bbox role branch"
    );
    let candidate_view = registry
        .ddl()
        .views
        .iter()
        .find(|view| view.id == "entity.site.spatial-candidates")
        .expect("root GIS table has one bbox-owned candidate view");
    assert_eq!(candidate_view.owner, DdlObjectOwner::SpatialBbox);
}

#[test]
fn crs84_point_without_bbox_keeps_non_gis_ddl_and_inventory_stable() {
    let registry = compile_project(
        &parse_project_json(
            br#"{
              "apiVersion":"registry.registrystack.org/v1alpha1",
              "kind":"RegistryProject",
              "registry":{"id":"ordinary-point","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
              "entities":[{
                "id":"site","primaryDataset":"test-dataset","route":"sites","mutationMode":"mutable","classification":"internal",
                "fields":[
                  {"id":"code","type":"string","maxLength":32,"classification":"internal"},
                  {"id":"location","type":"crs84-point","precision":6,"classification":"internal"}
                ],
                "geojson":{"geometryField":"location"}
              }],
              "accessProfiles":[{
                "id":"reader","default":true,"principalClaim":"principal","grants":[{
                  "entity":"site","operations":["get","list"],"readableFields":["code","location"]
                }]
              }]
            }"#,
        )
        .expect("project parses"),
        &[],
        CompileProfile::Authoring,
    )
    .expect("ordinary point project compiles");

    assert!(!registry.ddl().requires_postgis);
    let serialized = serde_json::to_value(registry.ddl()).expect("DDL inventory serializes");
    assert!(serialized.get("requiresPostgis").is_none());
    let script = registry.ddl().script();
    assert!(!script.contains("registry_spatial_ext"));
    assert!(!script.contains("rs_spgeom_"));
    assert!(registry
        .ddl()
        .tables
        .iter()
        .flat_map(|table| table.policies.iter())
        .all(|policy| policy.applies_to == DdlPolicyRole::Public));
}

#[cfg(feature = "postgres-test")]
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

#[cfg(feature = "postgres-test")]
mod live_postgres {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::{
        compiled_spatial_cross_entity_derived_registry, compiled_spatial_derived_registry,
        compiled_spatial_registry, postgres_harness::TestDatabase,
    };
    use registry_server::postgres::{
        begin_record_transaction, initialize_registry_state_for_catalog_test,
        install_compiled_schema, provision_postgis_prerequisites,
        verify_catalog_identity_for_catalog, verify_postgis, ClaimContext, ExpectedManagedCatalog,
        RegistryLockKey, RegistryStateTestIdentity, SqlIdentifier,
    };
    use tokio_postgres::GenericClient;

    const PACKAGE_ID: &str = "spatial-storage-registry";
    const INSTANCE_ID: &str = "spatial-storage-instance";
    const DATABASE_ID: &str = "spatial-storage-database";
    const PACKAGE_REVISION: &str = "spatial-storage-package-1";

    struct InstalledSpatialDatabase {
        database: TestDatabase,
        registry: registry_server::CompiledRegistry,
        identity: registry_server::postgres::ExpectedRegistryIdentity,
        table: String,
        code: String,
        location: String,
        geometry: String,
        bbox_role: SqlIdentifier,
        lock_key: RegistryLockKey,
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_postgres_postgis_prerequisites_are_role_bound_and_shadow_resistant() {
        let registry = compiled_spatial_registry();
        let database = TestDatabase::create(2).await;
        let (migration, migration_task) = database.connect_migration().await;
        assert!(
            install_compiled_schema(&migration, &registry, &database.runtime_role)
                .await
                .is_err(),
            "spatial schema refuses before the administrator provisions PostGIS and bbox role"
        );

        database
            .admin
            .batch_execute(
                "CREATE SCHEMA registry_shadow;
                 CREATE DOMAIN registry_shadow.geometry AS text;",
            )
            .await
            .expect("test administrator creates search-path shadow objects");
        let bbox_role = provision_postgis_prerequisites(
            &database.admin,
            &database.migration_role,
            &database.runtime_role,
        )
        .await
        .expect("administrator provisions governed PostGIS prerequisites");
        migration
            .batch_execute("SET search_path = registry_shadow, public")
            .await
            .expect("test can install a hostile search path");
        verify_postgis(&migration, &database.migration_role, &database.runtime_role)
            .await
            .expect("qualified verifier ignores search-path shadow objects");

        assert_spatial_role_and_schema_bits(&database, &bbox_role).await;
        assert_postgis_extension_owner_is_outside_runtime_authority(&database, &bbox_role).await;
        assert_verify_postgis_rejects_role_and_schema_drift(&database, &migration, &bbox_role)
            .await;

        migration_task.abort();
        cleanup_spatial_role(&database, &bbox_role).await;
        database.cleanup().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_postgres_generated_projection_tracks_runtime_transactions_and_rollbacks() {
        let installed = install_spatial_database(2).await;
        let mut runtime = installed
            .database
            .runtime_config
            .build_pool()
            .expect("runtime pool builds")
            .get_for_test()
            .await
            .expect("runtime connection is available");
        let claims = claims(&installed.registry);

        let transaction = begin_record_transaction(
            &mut runtime,
            installed.lock_key,
            Duration::from_secs(2),
            &installed.identity,
            &claims,
        )
        .await
        .expect("runtime transaction starts with governed context");
        transaction
            .transaction_for_test()
            .execute(
                &format!(
                    "INSERT INTO registry_data.{} (record_id, {}, {})
                     VALUES ($1::text::uuid, $2, $3::text::jsonb)",
                    quote_identifier(&installed.table),
                    quote_identifier(&installed.code),
                    quote_identifier(&installed.location),
                ),
                &[
                    &"00000000-0000-4000-8000-000000000101",
                    &"alpha",
                    &point("100.100000", "13.100000"),
                ],
            )
            .await
            .expect("runtime insert computes generated geometry");
        transaction
            .commit()
            .await
            .expect("insert transaction commits");
        assert_eq!(
            geometry_text(
                &installed.database.admin,
                &installed,
                "00000000-0000-4000-8000-000000000101"
            )
            .await,
            Some("POINT(100.1 13.1)".to_owned())
        );

        let transaction = begin_record_transaction(
            &mut runtime,
            installed.lock_key,
            Duration::from_secs(2),
            &installed.identity,
            &claims,
        )
        .await
        .expect("runtime transaction starts for location update");
        transaction
            .transaction_for_test()
            .execute(
                &format!(
                    "UPDATE registry_data.{}
                        SET {} = $2::text::jsonb
                      WHERE record_id = $1::text::uuid",
                    quote_identifier(&installed.table),
                    quote_identifier(&installed.location),
                ),
                &[
                    &"00000000-0000-4000-8000-000000000101",
                    &point("100.200000", "13.250000"),
                ],
            )
            .await
            .expect("runtime update recomputes generated geometry");
        transaction
            .commit()
            .await
            .expect("update transaction commits");
        assert_eq!(
            geometry_text(
                &installed.database.admin,
                &installed,
                "00000000-0000-4000-8000-000000000101"
            )
            .await,
            Some("POINT(100.2 13.25)".to_owned())
        );

        let transaction = begin_record_transaction(
            &mut runtime,
            installed.lock_key,
            Duration::from_secs(2),
            &installed.identity,
            &claims,
        )
        .await
        .expect("runtime transaction starts for nullable update");
        transaction
            .transaction_for_test()
            .execute(
                &format!(
                    "UPDATE registry_data.{}
                        SET {} = NULL
                      WHERE record_id = $1::text::uuid",
                    quote_identifier(&installed.table),
                    quote_identifier(&installed.location),
                ),
                &[&"00000000-0000-4000-8000-000000000101"],
            )
            .await
            .expect("nullable source clears generated geometry");
        transaction.commit().await.expect("nullable update commits");
        assert_eq!(
            geometry_text(
                &installed.database.admin,
                &installed,
                "00000000-0000-4000-8000-000000000101"
            )
            .await,
            None
        );

        installed
            .database
            .admin
            .execute(
                &format!(
                    "DELETE FROM registry_data.{}
                      WHERE record_id = $1::text::uuid",
                    quote_identifier(&installed.table),
                ),
                &[&"00000000-0000-4000-8000-000000000101"],
            )
            .await
            .expect("administrator delete preserves generated-storage consistency");
        let deleted: i64 = installed
            .database
            .admin
            .query_one(
                &format!(
                    "SELECT count(*) FROM registry_data.{}
                      WHERE record_id = $1::text::uuid",
                    quote_identifier(&installed.table),
                ),
                &[&"00000000-0000-4000-8000-000000000101"],
            )
            .await
            .expect("administrator can inspect deleted storage row")
            .get(0);
        assert_eq!(deleted, 0);

        let transaction = begin_record_transaction(
            &mut runtime,
            installed.lock_key,
            Duration::from_secs(2),
            &installed.identity,
            &claims,
        )
        .await
        .expect("runtime transaction starts for generated-column negative");
        assert!(
            transaction
                .transaction_for_test()
                .execute(
                    &format!(
                        "INSERT INTO registry_data.{} (record_id, {}, {}, {})
                         VALUES ($1::text::uuid, $2, $3::text::jsonb, NULL)",
                        quote_identifier(&installed.table),
                        quote_identifier(&installed.code),
                        quote_identifier(&installed.location),
                        quote_identifier(&installed.geometry),
                    ),
                    &[
                        &"00000000-0000-4000-8000-000000000102",
                        &"generated-write",
                        &point("100.100000", "13.100000"),
                    ],
                )
                .await
                .is_err(),
            "generated spatial column is not caller-writable"
        );
        transaction
            .rollback()
            .await
            .expect("failed generated-column write rolls back");

        let transaction = begin_record_transaction(
            &mut runtime,
            installed.lock_key,
            Duration::from_secs(2),
            &installed.identity,
            &claims,
        )
        .await
        .expect("runtime transaction starts for failed batch");
        assert!(
            transaction
                .transaction_for_test()
                .batch_execute(&format!(
                    "INSERT INTO registry_data.{} (record_id, {}, {})
                         VALUES ('00000000-0000-4000-8000-000000000103'::uuid, 'before-failure', '{}'::jsonb);
                     INSERT INTO registry_data.{} (record_id, {}, {})
                         VALUES ('00000000-0000-4000-8000-000000000104'::uuid, 'bad-point', '{{\"type\":\"Point\",\"coordinates\":[\"bad\",13]}}'::jsonb);",
                    quote_identifier(&installed.table),
                    quote_identifier(&installed.code),
                    quote_identifier(&installed.location),
                    point("100.110000", "13.110000").replace('\'', "''"),
                    quote_identifier(&installed.table),
                    quote_identifier(&installed.code),
                    quote_identifier(&installed.location),
                ))
                .await
                .is_err(),
            "invalid generated projection aborts the whole SQL batch"
        );
        transaction
            .rollback()
            .await
            .expect("failed batch rolls back");

        let committed: i64 = installed
            .database
            .admin
            .query_one(
                &format!(
                    "SELECT count(*) FROM registry_data.{}
                      WHERE record_id IN (
                          '00000000-0000-4000-8000-000000000103'::uuid,
                          '00000000-0000-4000-8000-000000000104'::uuid
                      )",
                    quote_identifier(&installed.table),
                ),
                &[],
            )
            .await
            .expect("administrator can inspect rollback outcome")
            .get(0);
        assert_eq!(
            committed, 0,
            "failed batch leaves no generated-storage prefix"
        );

        cleanup_spatial_database(installed).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_postgres_exact_jsonb_residual_rejects_double_rounding_bbox_admission() {
        let installed = install_spatial_database(2).await;
        let mut runtime = installed
            .database
            .runtime_config
            .build_pool()
            .expect("runtime pool builds")
            .get_for_test()
            .await
            .expect("runtime connection is available");
        let claims = claims(&installed.registry);
        let transaction = begin_record_transaction(
            &mut runtime,
            installed.lock_key,
            Duration::from_secs(2),
            &installed.identity,
            &claims,
        )
        .await
        .expect("runtime transaction starts for exact residual seed");
        transaction
            .transaction_for_test()
            .execute(
                &format!(
                    "INSERT INTO registry_data.{} (record_id, {}, {})
                     VALUES ($1::text::uuid, $2, $3::text::jsonb)",
                    quote_identifier(&installed.table),
                    quote_identifier(&installed.code),
                    quote_identifier(&installed.location),
                ),
                &[
                    &"00000000-0000-4000-8000-000000000301",
                    &"rounding-boundary",
                    &point("100.3", "13.0"),
                ],
            )
            .await
            .expect("runtime inserts exact decimal boundary point");
        transaction
            .commit()
            .await
            .expect("exact residual seed commits");

        let transaction = begin_record_transaction(
            &mut runtime,
            installed.lock_key,
            Duration::from_secs(2),
            &installed.identity,
            &claims,
        )
        .await
        .expect("runtime transaction starts for exact residual read");
        install_bbox_context(
            transaction.transaction_for_test(),
            &installed.database.runtime_role,
            "100.30000000000000000001",
            "12",
            "100.31",
            "14",
        )
        .await;
        let matched: i64 = transaction
            .transaction_for_test()
            .query_one(&bbox_count_sql(&installed), &[])
            .await
            .expect("bbox query succeeds with exact residual comparisons")
            .get(0);
        assert_eq!(
            matched, 0,
            "the JSONB numeric residual rejects a point admitted only by double rounding"
        );
        let plan = explain_text(
            transaction.transaction_for_test(),
            &bbox_count_sql(&installed),
        )
        .await;
        assert!(
            plan.contains("Index Cond") && plan.contains("rs_spgeom_"),
            "exact residual must not remove the mandatory GiST index condition; plan was:\n{plan}"
        );
        transaction
            .rollback()
            .await
            .expect("exact residual read rolls back");

        cleanup_spatial_database(installed).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_postgres_forced_rls_bbox_policy_uses_gist_for_representative_volume() {
        let installed = install_spatial_database(2).await;
        let mut runtime = installed
            .database
            .runtime_config
            .build_pool()
            .expect("runtime pool builds")
            .get_for_test()
            .await
            .expect("runtime connection is available");
        let claims = claims(&installed.registry);
        let transaction = begin_record_transaction(
            &mut runtime,
            installed.lock_key,
            Duration::from_secs(2),
            &installed.identity,
            &claims,
        )
        .await
        .expect("runtime transaction starts for representative volume");
        transaction
            .transaction_for_test()
            .batch_execute(&format!(
                "INSERT INTO registry_data.{} (record_id, {}, {})
                 SELECT ('00000000-0000-4000-8000-' || lpad(gs::text, 12, '0'))::uuid,
                        'site-' || gs::text,
                        jsonb_build_object(
                            'type', 'Point',
                            'coordinates', jsonb_build_array(
                                CASE WHEN gs <= 8 THEN 100.0 + (gs::double precision / 100.0) ELSE 120.0 + (gs::double precision / 10000.0) END,
                                CASE WHEN gs <= 8 THEN 13.5 ELSE 30.0 END
                            )
                        )
                   FROM generate_series(1, 4096) AS gs",
                quote_identifier(&installed.table),
                quote_identifier(&installed.code),
                quote_identifier(&installed.location),
            ))
            .await
            .expect("runtime inserts representative spatial volume");
        transaction
            .commit()
            .await
            .expect("representative spatial volume commits");
        installed
            .database
            .admin
            .batch_execute(&format!(
                "ANALYZE registry_data.{}",
                quote_identifier(&installed.table)
            ))
            .await
            .expect("planner statistics are refreshed for representative volume");

        let transaction = begin_record_transaction(
            &mut runtime,
            installed.lock_key,
            Duration::from_secs(2),
            &installed.identity,
            &claims,
        )
        .await
        .expect("runtime transaction starts for bbox plan");
        install_bbox_context(
            transaction.transaction_for_test(),
            &installed.database.runtime_role,
            "100",
            "13",
            "100.25",
            "14.5",
        )
        .await;
        transaction
            .transaction_for_test()
            .batch_execute("SET LOCAL statement_timeout = '2s'")
            .await
            .expect("test installs bounded statement budget");
        let matched: i64 = transaction
            .transaction_for_test()
            .query_one(&bbox_count_sql(&installed), &[])
            .await
            .expect("bbox query succeeds through the candidate ID view")
            .get(0);
        assert_eq!(matched, 8);
        let plan = explain_text(
            transaction.transaction_for_test(),
            &bbox_count_sql(&installed),
        )
        .await;
        assert!(
            plan.contains("Index Cond") && plan.contains("rs_spgeom_") && plan.contains("gist"),
            "bbox query should expose a real GiST index condition under forced RLS; plan was:\n{plan}"
        );
        transaction
            .rollback()
            .await
            .expect("bbox plan transaction rolls back");

        cleanup_spatial_database(installed).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_postgres_bbox_role_can_read_authorized_derived_map_label_view() {
        let installed =
            install_spatial_database_with_registry(2, compiled_spatial_derived_registry()).await;
        let mut runtime = installed
            .database
            .runtime_config
            .build_pool()
            .expect("runtime pool builds")
            .get_for_test()
            .await
            .expect("runtime connection is available");
        let claims = claims(&installed.registry);
        let transaction = begin_record_transaction(
            &mut runtime,
            installed.lock_key,
            Duration::from_secs(2),
            &installed.identity,
            &claims,
        )
        .await
        .expect("runtime transaction starts for derived map-label seed");
        transaction
            .transaction_for_test()
            .execute(
                &format!(
                    "INSERT INTO registry_data.{} (record_id, {}, {})
                     VALUES ($1::text::uuid, $2, $3::text::jsonb)",
                    quote_identifier(&installed.table),
                    quote_identifier(&installed.code),
                    quote_identifier(&installed.location),
                ),
                &[
                    &"00000000-0000-4000-8000-000000000201",
                    &"alpha",
                    &point("100.100000", "13.100000"),
                ],
            )
            .await
            .expect("runtime inserts derived map-label source row");
        transaction
            .commit()
            .await
            .expect("derived map-label seed commits");

        let transaction = begin_record_transaction(
            &mut runtime,
            installed.lock_key,
            Duration::from_secs(2),
            &installed.identity,
            &claims,
        )
        .await
        .expect("runtime transaction starts for derived bbox read");
        install_bbox_context(
            transaction.transaction_for_test(),
            &installed.database.runtime_role,
            "100",
            "13",
            "100.25",
            "14.5",
        )
        .await;
        let derived_view = derived_view_name(&installed, "entity.site.derived.labels");
        let labels = transaction
            .transaction_for_test()
            .query(
                &format!(
                    "SELECT derived.map_label
                       FROM registry_context.{} AS candidate
                       JOIN registry_data.{} AS data
                         ON data.record_id = candidate.id
                       JOIN registry_derived.{} AS derived
                         ON derived.id = data.record_id
                      WHERE derived.map_label = 'alpha'
                      ORDER BY derived.map_label
                      LIMIT 1",
                    quote_identifier(&spatial_candidate_view_name(&installed)),
                    quote_identifier(&installed.table),
                    quote_identifier(&derived_view),
                ),
                &[],
            )
            .await
            .expect("runtime can read authorized derived field through candidate IDs");
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].get::<_, String>(0), "alpha");
        transaction
            .rollback()
            .await
            .expect("derived bbox read rolls back");

        cleanup_spatial_database(installed).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_postgres_bbox_role_can_read_cross_entity_derived_dependency_with_same_profile_rls(
    ) {
        let installed = install_spatial_database_with_registry(
            2,
            compiled_spatial_cross_entity_derived_registry(),
        )
        .await;
        let mut runtime = installed
            .database
            .runtime_config
            .build_pool()
            .expect("runtime pool builds")
            .get_for_test()
            .await
            .expect("runtime connection is available");

        let zone = &installed.registry.entities()["zone"];
        let zone_claims = claims_for(&installed.registry, "zone");
        let transaction = begin_record_transaction(
            &mut runtime,
            installed.lock_key,
            Duration::from_secs(2),
            &installed.identity,
            &zone_claims,
        )
        .await
        .expect("runtime transaction starts for zone dependency seed");
        transaction
            .transaction_for_test()
            .execute(
                &format!(
                    "INSERT INTO registry_data.{} (record_id, {}, {})
                     VALUES ($1::text::uuid, $2, $3)",
                    quote_identifier(&zone.physical_table),
                    quote_identifier(&zone.fields["code"].physical_name),
                    quote_identifier(&zone.fields["label"].physical_name),
                ),
                &[
                    &"00000000-0000-4000-8000-000000000401",
                    &"zone-a",
                    &"Zone One",
                ],
            )
            .await
            .expect("runtime inserts non-spatial derived dependency row");
        transaction
            .commit()
            .await
            .expect("zone dependency seed commits");

        let site_claims = claims_for(&installed.registry, "site");
        let transaction = begin_record_transaction(
            &mut runtime,
            installed.lock_key,
            Duration::from_secs(2),
            &installed.identity,
            &site_claims,
        )
        .await
        .expect("runtime transaction starts for cross-entity derived site seed");
        transaction
            .transaction_for_test()
            .execute(
                &format!(
                    "INSERT INTO registry_data.{} (record_id, {}, {}, {})
                     VALUES ($1::text::uuid, $2, $3::text::uuid, $4::text::jsonb)",
                    quote_identifier(&installed.table),
                    quote_identifier(&installed.code),
                    quote_identifier(
                        &installed.registry.entities()["site"].fields["zone"].physical_name
                    ),
                    quote_identifier(&installed.location),
                ),
                &[
                    &"00000000-0000-4000-8000-000000000402",
                    &"alpha",
                    &"00000000-0000-4000-8000-000000000401",
                    &point("100.100000", "13.100000"),
                ],
            )
            .await
            .expect("runtime inserts spatial root row linked to dependency");
        transaction
            .commit()
            .await
            .expect("cross-entity derived site seed commits");

        let transaction = begin_record_transaction(
            &mut runtime,
            installed.lock_key,
            Duration::from_secs(2),
            &installed.identity,
            &site_claims,
        )
        .await
        .expect("runtime transaction starts for cross-entity derived bbox read");
        install_bbox_context(
            transaction.transaction_for_test(),
            &installed.database.runtime_role,
            "100",
            "13",
            "100.25",
            "14.5",
        )
        .await;
        let derived_view = derived_view_name(&installed, "entity.site.derived.labels");
        let labels = transaction
            .transaction_for_test()
            .query(
                &format!(
                    "SELECT derived.map_label
                       FROM registry_context.{} AS candidate
                       JOIN registry_data.{} AS data
                         ON data.record_id = candidate.id
                       JOIN registry_derived.{} AS derived
                         ON derived.id = data.record_id
                      WHERE derived.map_label = 'Zone One'
                      ORDER BY derived.map_label
                      LIMIT 1",
                    quote_identifier(&spatial_candidate_view_name(&installed)),
                    quote_identifier(&installed.table),
                    quote_identifier(&derived_view),
                ),
                &[],
            )
            .await
            .expect("runtime can read cross-entity derived field through candidate IDs");
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].get::<_, String>(0), "Zone One");
        transaction
            .rollback()
            .await
            .expect("cross-entity derived bbox read rolls back");

        cleanup_spatial_database(installed).await;
    }

    async fn install_spatial_database(pool_size: usize) -> InstalledSpatialDatabase {
        install_spatial_database_with_registry(pool_size, compiled_spatial_registry()).await
    }

    async fn install_spatial_database_with_registry(
        pool_size: usize,
        registry: registry_server::CompiledRegistry,
    ) -> InstalledSpatialDatabase {
        let database = TestDatabase::create(pool_size).await;
        let bbox_role = provision_postgis_prerequisites(
            &database.admin,
            &database.migration_role,
            &database.runtime_role,
        )
        .await
        .expect("administrator provisions PostGIS prerequisites");
        let (migration, migration_task) = database.connect_migration().await;
        install_compiled_schema(&migration, &registry, &database.runtime_role)
            .await
            .expect("spatial compiled schema installs");
        let catalog = ExpectedManagedCatalog::compiled(&registry);
        let identity = initialize_registry_state_for_catalog_test(
            &migration,
            &database.runtime_role,
            &catalog,
            RegistryStateTestIdentity {
                package_id: PACKAGE_ID,
                environment: "local",
                instance_id: INSTANCE_ID,
                database_id: DATABASE_ID,
                package_revision: PACKAGE_REVISION,
                package_sequence: 1,
            },
        )
        .await
        .expect("spatial catalog binds active Registry identity");
        verify_catalog_identity_for_catalog(
            &migration,
            &identity,
            &catalog,
            &database.migration_role,
            &database.runtime_role,
        )
        .await
        .expect("spatial catalog passes exact verification");
        migration_task.abort();

        let entity = &registry.entities()["site"];
        let installed = InstalledSpatialDatabase {
            database,
            registry: registry.clone(),
            identity,
            table: entity.physical_table.clone(),
            code: entity.fields["code"].physical_name.clone(),
            location: entity.fields["location"].physical_name.clone(),
            geometry: spatial_geometry_column(&registry),
            bbox_role,
            lock_key: RegistryLockKey::derive(PACKAGE_ID).expect("lock key is bounded"),
        };
        assert_spatial_candidate_view_authority(&installed).await;
        installed
    }

    async fn assert_spatial_candidate_view_authority(installed: &InstalledSpatialDatabase) {
        let view_name = spatial_candidate_view_name(installed);
        let row = installed
            .database
            .admin
            .query_one(
                "SELECT owner.rolname,
                        pg_catalog.pg_has_role(runtime.oid, bbox.oid, 'MEMBER'),
                        pg_catalog.has_table_privilege($1, c.oid, 'SELECT'),
                        pg_catalog.has_table_privilege($1, c.oid, 'INSERT'),
                        pg_catalog.has_schema_privilege($1, 'registry_context', 'CREATE'),
                        pg_catalog.has_schema_privilege($2, 'registry_context', 'CREATE')
                   FROM pg_catalog.pg_class c
                   JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                   JOIN pg_catalog.pg_roles owner ON owner.oid = c.relowner
                   JOIN pg_catalog.pg_roles runtime ON runtime.rolname = $1
                   JOIN pg_catalog.pg_roles bbox ON bbox.rolname = $2
                  WHERE n.nspname = 'registry_context'
                    AND c.relname = $3",
                &[
                    &installed.database.runtime_role.as_str(),
                    &installed.bbox_role.as_str(),
                    &view_name.as_str(),
                ],
            )
            .await
            .expect("administrator can inspect candidate view authority");
        assert_eq!(
            row.get::<_, String>(0),
            installed.bbox_role.as_str(),
            "bbox owns only the candidate ID view"
        );
        assert!(
            !row.get::<_, bool>(1),
            "runtime must not be a bbox role member"
        );
        assert!(
            row.get::<_, bool>(2),
            "runtime receives narrow SELECT on the candidate ID view"
        );
        assert!(
            !row.get::<_, bool>(3),
            "runtime cannot write the candidate ID view"
        );
        assert!(
            !row.get::<_, bool>(4),
            "runtime cannot CREATE in registry_context"
        );
        assert!(
            !row.get::<_, bool>(5),
            "bbox keeps no CREATE privilege in registry_context after transfer"
        );

        let runtime = installed
            .database
            .runtime_config
            .build_pool()
            .expect("runtime pool builds")
            .get_for_test()
            .await
            .expect("runtime connection is available");
        assert!(
            runtime
                .batch_execute(&format!(
                    "SET ROLE {}",
                    quote_identifier(installed.bbox_role.as_str())
                ))
                .await
                .is_err(),
            "runtime cannot SET ROLE into the bbox candidate-view owner"
        );
        assert!(
            runtime
                .batch_execute(&format!(
                    "ALTER VIEW registry_context.{} OWNER TO {}",
                    quote_identifier(&view_name),
                    quote_identifier(installed.database.runtime_role.as_str())
                ))
                .await
                .is_err(),
            "runtime cannot retake ownership of the candidate ID view"
        );
        assert!(
            runtime
                .batch_execute(&format!(
                    "DROP VIEW registry_context.{}",
                    quote_identifier(&view_name),
                ))
                .await
                .is_err(),
            "runtime cannot drop the candidate ID view"
        );
    }

    async fn assert_postgis_extension_owner_is_outside_runtime_authority(
        database: &TestDatabase,
        bbox_role: &SqlIdentifier,
    ) {
        let row = database
            .admin
            .query_one(
                "SELECT extension_owner.rolname,
                        extension_owner.rolname = $1,
                        extension_owner.rolname = $2,
                        extension_owner.rolname = $3,
                        pg_catalog.pg_has_role($1, extension_owner.oid, 'MEMBER'),
                        pg_catalog.pg_has_role($2, extension_owner.oid, 'MEMBER'),
                        pg_catalog.pg_has_role($3, extension_owner.oid, 'MEMBER')
                   FROM pg_catalog.pg_extension extension
                   JOIN pg_catalog.pg_roles extension_owner
                     ON extension_owner.oid = extension.extowner
                  WHERE extension.extname = 'postgis'",
                &[
                    &database.migration_role.as_str(),
                    &database.runtime_role.as_str(),
                    &bbox_role.as_str(),
                ],
            )
            .await
            .expect("administrator can inspect PostGIS extension owner");
        assert_ne!(
            row.get::<_, String>(0),
            database.migration_role.as_str(),
            "migration must not own the PostGIS extension"
        );
        for index in 1..=6 {
            assert!(
                !row.get::<_, bool>(index),
                "PostGIS extension owner is inside runtime authority at column {index}"
            );
        }
    }

    async fn assert_spatial_role_and_schema_bits(
        database: &TestDatabase,
        bbox_role: &SqlIdentifier,
    ) {
        let row = database
            .admin
            .query_one(
                "SELECT bbox.rolcanlogin,
                        bbox.rolsuper,
                        bbox.rolbypassrls,
	                        bbox.rolcreatedb,
	                        bbox.rolcreaterole,
	                        bbox.rolinherit,
	                        m.inherit_option,
	                        m.set_option,
	                        m.admin_option,
	                        pg_catalog.pg_has_role(runtime.oid, bbox.oid, 'MEMBER'),
	                        pg_catalog.has_schema_privilege($1, 'registry_spatial_ext', 'CREATE'),
	                        pg_catalog.has_schema_privilege($2, 'registry_spatial_ext', 'CREATE'),
	                        pg_catalog.has_schema_privilege($3, 'registry_spatial_ext', 'CREATE'),
	                        pg_catalog.has_schema_privilege($2, 'registry_spatial_ext', 'USAGE'),
	                        pg_catalog.has_schema_privilege($1, 'registry_spatial_ext', 'USAGE'),
	                        pg_catalog.has_schema_privilege($3, 'registry_spatial_ext', 'USAGE')
	                   FROM pg_catalog.pg_roles migration
	                   JOIN pg_catalog.pg_roles runtime ON runtime.rolname = $1
	                   JOIN pg_catalog.pg_roles bbox ON bbox.rolname = $3
	                   JOIN pg_catalog.pg_auth_members m
	                     ON m.member = migration.oid AND m.roleid = bbox.oid
	                  WHERE migration.rolname = $2",
                &[
                    &database.runtime_role.as_str(),
                    &database.migration_role.as_str(),
                    &bbox_role.as_str(),
                ],
            )
            .await
            .expect("administrator can inspect spatial role bits");
        for index in 0..=6 {
            assert!(
                !row.get::<_, bool>(index),
                "forbidden bbox role bit {index} is set"
            );
        }
        assert!(row.get::<_, bool>(7), "migration may SET the bbox role");
        assert!(
            !row.get::<_, bool>(8),
            "migration must not administer the bbox role"
        );
        assert!(!row.get::<_, bool>(9), "runtime must not be a bbox member");
        for index in 10..=12 {
            assert!(
                !row.get::<_, bool>(index),
                "forbidden extension CREATE path {index} is set"
            );
        }
        assert!(
            row.get::<_, bool>(13),
            "migration has extension schema USAGE for DDL"
        );
        assert!(
            row.get::<_, bool>(14),
            "runtime has extension schema USAGE for startup verification"
        );
        assert!(
            row.get::<_, bool>(15),
            "bbox has extension schema USAGE for predicates"
        );
    }

    async fn assert_verify_postgis_rejects_role_and_schema_drift(
        database: &TestDatabase,
        migration: &impl GenericClient,
        bbox_role: &SqlIdentifier,
    ) {
        database
            .admin
            .batch_execute(&format!(
                "GRANT CREATE ON SCHEMA registry_spatial_ext TO {}",
                quote_identifier(bbox_role.as_str())
            ))
            .await
            .expect("administrator introduces bbox CREATE drift");
        assert!(
            verify_postgis(migration, &database.migration_role, &database.runtime_role)
                .await
                .is_err()
        );
        database
            .admin
            .batch_execute(&format!(
                "REVOKE CREATE ON SCHEMA registry_spatial_ext FROM {}",
                quote_identifier(bbox_role.as_str())
            ))
            .await
            .expect("administrator removes bbox CREATE drift");

        assert_inherited_extension_create_drift(
            database,
            migration,
            &database.migration_role,
            "rs_spatial_migration_parent",
        )
        .await;
        assert_inherited_extension_create_drift(
            database,
            migration,
            &database.runtime_role,
            "rs_spatial_runtime_parent",
        )
        .await;

        database
            .admin
            .batch_execute(&format!(
                "ALTER ROLE {} INHERIT",
                quote_identifier(bbox_role.as_str())
            ))
            .await
            .expect("administrator introduces bbox inherit drift");
        assert!(
            verify_postgis(migration, &database.migration_role, &database.runtime_role)
                .await
                .is_err()
        );
        database
            .admin
            .batch_execute(&format!(
                "ALTER ROLE {} NOINHERIT",
                quote_identifier(bbox_role.as_str())
            ))
            .await
            .expect("administrator removes bbox inherit drift");

        database
            .admin
            .batch_execute(&format!(
                "ALTER ROLE {} BYPASSRLS",
                quote_identifier(bbox_role.as_str())
            ))
            .await
            .expect("administrator introduces bbox BYPASSRLS drift");
        assert!(
            verify_postgis(migration, &database.migration_role, &database.runtime_role)
                .await
                .is_err()
        );
        database
            .admin
            .batch_execute(&format!(
                "ALTER ROLE {} NOBYPASSRLS",
                quote_identifier(bbox_role.as_str())
            ))
            .await
            .expect("administrator removes bbox BYPASSRLS drift");

        database
            .admin
            .batch_execute(&format!(
                "GRANT {} TO {} WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;",
                quote_identifier(bbox_role.as_str()),
                quote_identifier(database.runtime_role.as_str()),
            ))
            .await
            .expect("administrator introduces runtime bbox membership drift");
        assert!(
            verify_postgis(migration, &database.migration_role, &database.runtime_role)
                .await
                .is_err()
        );
        database
            .admin
            .batch_execute(&format!(
                "REVOKE {} FROM {};",
                quote_identifier(bbox_role.as_str()),
                quote_identifier(database.runtime_role.as_str()),
            ))
            .await
            .expect("administrator removes runtime bbox membership drift");

        let upstream = unique_role("rs_spatial_parent");
        database
            .admin
            .batch_execute(&format!(
                "CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
                 GRANT {} TO {} WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;",
                quote_identifier(upstream.as_str()),
                quote_identifier(upstream.as_str()),
                quote_identifier(bbox_role.as_str()),
            ))
            .await
            .expect("administrator introduces upstream bbox membership drift");
        assert!(
            verify_postgis(migration, &database.migration_role, &database.runtime_role)
                .await
                .is_err()
        );
        database
            .admin
            .batch_execute(&format!(
                "REVOKE {} FROM {};
                 DROP ROLE {};",
                quote_identifier(upstream.as_str()),
                quote_identifier(bbox_role.as_str()),
                quote_identifier(upstream.as_str()),
            ))
            .await
            .expect("administrator removes upstream bbox membership drift");

        verify_postgis(migration, &database.migration_role, &database.runtime_role)
            .await
            .expect("spatial prerequisites are healthy after drift cleanup");
    }

    async fn assert_inherited_extension_create_drift(
        database: &TestDatabase,
        migration: &impl GenericClient,
        target_role: &SqlIdentifier,
        prefix: &str,
    ) {
        let upstream = unique_role(prefix);
        database
            .admin
            .batch_execute(&format!(
                "CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
                 GRANT CREATE ON SCHEMA registry_spatial_ext TO {};
                 GRANT {} TO {} WITH INHERIT TRUE, SET TRUE, ADMIN FALSE;",
                quote_identifier(upstream.as_str()),
                quote_identifier(upstream.as_str()),
                quote_identifier(upstream.as_str()),
                quote_identifier(target_role.as_str()),
            ))
            .await
            .expect("administrator introduces inherited extension CREATE drift");
        assert!(
            verify_postgis(migration, &database.migration_role, &database.runtime_role)
                .await
                .is_err()
        );
        database
            .admin
            .batch_execute(&format!(
                "REVOKE {} FROM {};
                 REVOKE CREATE ON SCHEMA registry_spatial_ext FROM {};
                 DROP ROLE {};",
                quote_identifier(upstream.as_str()),
                quote_identifier(target_role.as_str()),
                quote_identifier(upstream.as_str()),
                quote_identifier(upstream.as_str()),
            ))
            .await
            .expect("administrator removes inherited extension CREATE drift");
    }

    async fn geometry_text(
        client: &impl GenericClient,
        installed: &InstalledSpatialDatabase,
        record_id: &str,
    ) -> Option<String> {
        client
            .query_one(
                &format!(
                    "SELECT registry_spatial_ext.ST_AsText({})
                       FROM registry_data.{}
                      WHERE record_id = $1::text::uuid",
                    quote_identifier(&installed.geometry),
                    quote_identifier(&installed.table),
                ),
                &[&record_id],
            )
            .await
            .expect("test can inspect generated spatial projection")
            .get(0)
    }

    async fn install_bbox_context(
        transaction: &tokio_postgres::Transaction<'_>,
        _runtime_role: &SqlIdentifier,
        west: &str,
        south: &str,
        east: &str,
        north: &str,
    ) {
        transaction
            .execute(
                "SELECT set_config('registry.bbox_west', $1, true),
                        set_config('registry.bbox_south', $2, true),
                        set_config('registry.bbox_east', $3, true),
                        set_config('registry.bbox_north', $4, true)",
                &[&west, &south, &east, &north],
            )
            .await
            .expect("test installs bbox context");
    }

    async fn explain_text(client: &impl GenericClient, sql: &str) -> String {
        client
            .query(&format!("EXPLAIN (FORMAT TEXT, COSTS OFF) {sql}"), &[])
            .await
            .expect("EXPLAIN succeeds")
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn bbox_count_sql(installed: &InstalledSpatialDatabase) -> String {
        format!(
            "SELECT count(*)
               FROM registry_context.{} AS candidate
               JOIN registry_data.{} AS data
                 ON data.record_id = candidate.id",
            quote_identifier(&spatial_candidate_view_name(installed)),
            quote_identifier(&installed.table),
        )
    }

    fn claims(registry: &registry_server::CompiledRegistry) -> ClaimContext {
        claims_for(registry, "site")
    }

    fn claims_for(registry: &registry_server::CompiledRegistry, entity_id: &str) -> ClaimContext {
        ClaimContext::for_compiled(
            registry,
            entity_id,
            Some("principal".to_owned()),
            "map-reader",
            None,
            Vec::new(),
        )
        .expect("fixture claims are valid")
    }

    fn derived_view_name(installed: &InstalledSpatialDatabase, id: &str) -> String {
        installed
            .registry
            .ddl()
            .views
            .iter()
            .find(|view| view.id == id)
            .expect("derived view is inventoried")
            .name
            .clone()
    }

    fn spatial_candidate_view_name(installed: &InstalledSpatialDatabase) -> String {
        installed
            .registry
            .ddl()
            .views
            .iter()
            .find(|view| view.id == "entity.site.spatial-candidates")
            .expect("spatial candidate view is inventoried")
            .name
            .clone()
    }

    fn spatial_geometry_column(registry: &registry_server::CompiledRegistry) -> String {
        let sql = registry
            .ddl()
            .statements
            .iter()
            .find(|statement| statement.sql.contains("\"rs_spgeom_"))
            .expect("spatial geometry column appears in DDL")
            .sql
            .as_str();
        let start = sql.find("\"rs_spgeom_").expect("spatial column starts") + 1;
        let rest = &sql[start..];
        let end = rest.find('"').expect("spatial column is quoted");
        rest[..end].to_owned()
    }

    fn point(lon: &str, lat: &str) -> String {
        format!(r#"{{"type":"Point","coordinates":[{lon},{lat}]}}"#)
    }

    fn quote_identifier(value: &str) -> String {
        format!("\"{}\"", value.replace('"', "\"\""))
    }

    fn unique_role(prefix: &str) -> SqlIdentifier {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after Unix epoch")
            .as_nanos();
        SqlIdentifier::parse(&format!("{prefix}_{:x}", nanos & 0xffff_ffff_ffff))
            .expect("generated role identifier is valid")
    }

    async fn cleanup_spatial_database(installed: InstalledSpatialDatabase) {
        cleanup_spatial_role(&installed.database, &installed.bbox_role).await;
        installed.database.cleanup().await;
    }

    async fn cleanup_spatial_role(database: &TestDatabase, bbox_role: &SqlIdentifier) {
        database
            .admin
            .batch_execute(&format!(
                "REVOKE {} FROM {};
                 DROP OWNED BY {};
                 DROP ROLE {};",
                quote_identifier(bbox_role.as_str()),
                quote_identifier(database.migration_role.as_str()),
                quote_identifier(bbox_role.as_str()),
                quote_identifier(bbox_role.as_str()),
            ))
            .await
            .expect("test administrator drops isolated bbox role");
    }
}
