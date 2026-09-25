// SPDX-License-Identifier: Apache-2.0

//! Compiler-owned reference indexes on real PostgreSQL: the catalog carries
//! them after activation, catalog verification refuses a database without
//! them, a successor package adds them to a database activated without them,
//! and a reference filter reaches them.

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use postgres_harness::TestDatabase;
use registry_breg::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedRequestClaims,
};
use registry_breg::compiler::{compile_project, module_digest, CompileProfile};
use registry_breg::contract::{parse_module_yaml, parse_project_yaml};
use registry_breg::cursor::CursorCodec;
use registry_breg::migration::{
    apply_verified_package, ApplyPrecondition, ApplyRoles, ApplyTimeouts,
    ApplyVerifiedPackageRequest,
};
use registry_breg::package::{
    compiled_registry_change_set_from_baseline, load_package, prepare_package,
    CompiledRegistryChangeClass, CompiledRegistryChangeCode, CompiledRegistryMigrationBaseline,
    PackageBuildRequest, PackageIntent, PackageLoadContext, PackageMigrationPlanInput,
    PackageModuleSource, PackageSourceFile, SignaturePolicy, VerifiedPackage,
};
use registry_breg::postgres::{
    install_compiled_schema, managed_schema_fingerprint, verify_catalog_identity_for_catalog,
    ExpectedManagedCatalog, ExpectedRegistryIdentity, PostgresKernelError,
    PostgresRecordReadService, RegistryLockKey,
};
use registry_breg::startup::{prepare_startup, StartupError};
use registry_breg::CompiledRegistry;
use registry_platform_audit::AuditProfile;
use serde_json::Value;
use tower::Service as _;
use zeroize::Zeroizing;

const INSTANCE: &str = "reference-index-instance";
const DATABASE: &str = "reference-index-database";
const SOURCE_REVISION: &str = "reference-index-source-revision";
const FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: registry.registrystack.org/breg-journeys/v1
journeys:
  - id: asset-list
    steps:
      - id: list-assets
        entity: asset
        accessProfile: reader
        claims: {principal: package-reader}
        request: {operation: list}
        expect: {outcome: success, status: 200, count: 0}
"#;
const RARE_SITE: &str = "00000000-0000-4000-8000-000000000999";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn activation_installs_reference_indexes_and_verification_refuses_their_absence() {
    let database = TestDatabase::create(2).await;
    let registry = compile_registry(1);
    let fingerprint = rehearsed_fingerprint(&database, &registry).await;
    let package = publish_and_load(
        prepare_package(build_request(
            1,
            None,
            &fingerprint,
            PackageMigrationPlanInput::InitialCompiledDdl,
        ))
        .expect("initial package prepares"),
        local_context(PackageIntent::InitialActivation),
    );
    let active = apply(
        &database,
        &package.verified,
        ApplyPrecondition::InitialActivation,
    )
    .await
    .expect("initial package activates");

    let site_index = reference_index_name(&registry, "site");
    assert_eq!(
        index_definitions(&database)
            .await
            .get(&site_index)
            .map(String::as_str),
        Some(
            format!(
                "CREATE INDEX {site_index} ON registry_data.{} USING btree ({})",
                registry.entities()["asset"].physical_table,
                registry.entities()["asset"].fields["site"].physical_name
            )
            .as_str()
        ),
        "the reference column carries a plain btree index after activation"
    );
    assert!(
        !registry.physical_names().entities["asset"]
            .indexes
            .contains_key("reference:owner"),
        "the authored index leading with owner replaces its reference index"
    );
    let authored = &registry.physical_names().entities["asset"].indexes["by-owner"];
    assert_eq!(
        index_definitions(&database)
            .await
            .keys()
            .filter(|name| name.starts_with("breg_ri_"))
            .collect::<Vec<_>>(),
        vec![&site_index],
        "only the uncovered reference column gains a compiler-owned index"
    );
    assert!(index_definitions(&database).await.contains_key(authored));

    let catalog = ExpectedManagedCatalog::compiled(&registry);
    let (migration, task) = database.connect_migration().await;
    verify_catalog_identity_for_catalog(
        &migration,
        &active,
        &catalog,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect("the activated catalog verifies");
    database
        .admin
        .batch_execute(&format!("DROP INDEX registry_data.\"{site_index}\""))
        .await
        .expect("test administrator drops the reference index");
    assert!(matches!(
        verify_catalog_identity_for_catalog(
            &migration,
            &active,
            &catalog,
            &database.migration_role,
            &database.runtime_role,
        )
        .await,
        Err(PostgresKernelError::RegistryUnavailable)
    ));
    assert_eq!(
        startup(&database, &package, &active, 1).await.err(),
        Some(StartupError::DatabaseUnready),
        "startup refuses a catalog missing a compiled reference index"
    );
    let recreate = registry
        .ddl()
        .statements
        .iter()
        .find(|statement| statement.id == "entity.asset.index.reference:site")
        .expect("the compiled index statement exists");
    migration
        .batch_execute(&recreate.sql)
        .await
        .expect("the compiled statement recreates the index");
    verify_catalog_identity_for_catalog(
        &migration,
        &active,
        &catalog,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect("recreating the exact compiled index restores the catalog");
    task.abort();
    startup(&database, &package, &active, 1)
        .await
        .expect("startup accepts the restored catalog");
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_successor_adds_reference_indexes_to_a_database_activated_without_them() {
    let database = TestDatabase::create(2).await;
    let registry = compile_registry(1);
    let fingerprint = rehearsed_fingerprint(&database, &registry).await;
    let initial = publish_and_load(
        prepare_package(build_request(
            1,
            None,
            &fingerprint,
            PackageMigrationPlanInput::InitialCompiledDdl,
        ))
        .expect("initial package prepares"),
        local_context(PackageIntent::InitialActivation),
    );
    let mut active = apply(
        &database,
        &initial.verified,
        ApplyPrecondition::InitialActivation,
    )
    .await
    .expect("initial package activates");

    // An engine that did not index reference columns activated this database:
    // the index is absent and the recorded fingerprint describes that catalog.
    let site_index = reference_index_name(&registry, "site");
    database
        .admin
        .batch_execute(&format!("DROP INDEX registry_data.\"{site_index}\""))
        .await
        .expect("test administrator removes the reference index");
    let (migration, task) = database.connect_migration().await;
    let prior_fingerprint = managed_schema_fingerprint(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(&registry),
    )
    .await
    .expect("the index-free catalog is fingerprinted");
    task.abort();
    assert_ne!(prior_fingerprint, fingerprint);
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_state SET schema_fingerprint = $1",
            &[&prior_fingerprint],
        )
        .await
        .expect("test administrator records the prior engine's fingerprint");
    active.schema_fingerprint = prior_fingerprint.clone();

    // The predecessor baseline an older package yields carries no reference
    // index members, so the successor plan adds them as ordinary indexes.
    let mut baseline =
        CompiledRegistryMigrationBaseline::from_compiled(&active.package_revision, &registry);
    for entity in baseline.entities.values_mut() {
        entity
            .indexes
            .retain(|member, _| !member.starts_with("reference:"));
    }
    for names in baseline.physical_names.entities.values_mut() {
        names
            .indexes
            .retain(|member, _| !member.starts_with("reference:"));
    }
    let successor_registry = compile_registry(2);
    let change_set = compiled_registry_change_set_from_baseline(
        &baseline,
        &successor_registry,
        &active.package_revision,
    );
    assert_eq!(
        change_set
            .changes
            .iter()
            .map(|change| (change.class, change.code))
            .collect::<Vec<_>>(),
        vec![(
            CompiledRegistryChangeClass::CompatibleAdditive,
            CompiledRegistryChangeCode::IndexAdded
        )]
    );
    let successor = publish_and_load(
        prepare_package(build_request(
            2,
            Some(&active.package_revision),
            &fingerprint,
            PackageMigrationPlanInput::SuccessorFromBaseline {
                prior_baseline: Box::new(baseline),
            },
        ))
        .expect("successor package prepares without reviewed SQL"),
        local_context(PackageIntent::Activation {
            active_revision: &active.package_revision,
            active_sequence: 1,
        }),
    );
    assert_eq!(
        successor
            .verified
            .manifest()
            .migration_plan
            .statements
            .iter()
            .map(|statement| statement.id.as_str())
            .collect::<Vec<_>>(),
        vec!["entity.asset.index.reference:site"]
    );
    let upgraded = apply(
        &database,
        &successor.verified,
        ApplyPrecondition::Successor { current: &active },
    )
    .await
    .expect("the successor activates on the index-free database");
    assert_eq!(upgraded.schema_fingerprint, fingerprint);
    assert!(index_definitions(&database).await.contains_key(&site_index));
    startup(&database, &successor, &upgraded, 2)
        .await
        .expect("startup accepts the upgraded catalog");
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_selective_reference_filter_uses_the_reference_index() {
    let database = TestDatabase::create(2).await;
    let registry = Arc::new(compile_registry(1));
    let fingerprint = rehearsed_fingerprint(&database, &registry).await;
    let package = publish_and_load(
        prepare_package(build_request(
            1,
            None,
            &fingerprint,
            PackageMigrationPlanInput::InitialCompiledDdl,
        ))
        .expect("initial package prepares"),
        local_context(PackageIntent::InitialActivation),
    );
    let active = apply(
        &database,
        &package.verified,
        ApplyPrecondition::InitialActivation,
    )
    .await
    .expect("initial package activates");
    seed_skewed_assets(&database, &registry, &active).await;

    let pool = database.runtime_config.build_pool().expect("bounded pool");
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x41; 32]), Duration::from_secs(300))
            .expect("test cursor key"),
    );
    let plans = Arc::new(Mutex::new(Vec::new()));
    let service = PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        active.clone(),
        RegistryLockKey::derive(&active.package_id).expect("bounded lock key"),
        Duration::from_secs(2),
        registry_breg::audit::test_support::capturing(
            AuditProfile::production_from_secret_bytes(vec![0x42; 32].into()).expect("keyed audit"),
        )
        .0,
        cursors.clone(),
    )
    .with_query_plan_for_test(plans.clone());
    let app = router(Arc::new(HttpService::new(
        registry.clone(),
        ReadRuntimeIdentity {
            package_revision: active.package_revision.clone(),
            schema_fingerprint: active.schema_fingerprint.clone(),
        },
        Arc::new(service),
        Arc::new(AlwaysReady),
        cursors,
    )));

    let (status, body) = send(
        &app,
        &format!("/v1/records/assets?accessProfile=reader&$filter=site%20eq%20'{RARE_SITE}'"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["items"].as_array().map(Vec::len), Some(5), "{body}");
    let site_index = reference_index_name(&registry, "site");
    let nodes = std::mem::take(&mut *plans.lock().expect("plan lock"));
    assert!(
        nodes
            .iter()
            .any(|node| node["indexName"].as_str() == Some(site_index.as_str())),
        "the generated list SQL reaches the reference index: {nodes:?}"
    );
    drop(app);
    drop(pool);
    database.cleanup().await;
}

struct PublishedPackage {
    _root: tempfile::TempDir,
    root: PathBuf,
    verified: VerifiedPackage,
}

fn publish_and_load(
    prepared: registry_breg::package::PreparedPackage,
    context: PackageLoadContext<'_>,
) -> PublishedPackage {
    let root = tempfile::Builder::new()
        .prefix("registry-reference-index-package-")
        .tempdir_in(
            std::env::temp_dir()
                .canonicalize()
                .expect("canonical temporary root"),
        )
        .expect("package temporary directory creates");
    let package = root.path().join("package");
    prepared
        .publish_to_directory(&package, Vec::new())
        .expect("package publishes");
    let verified = load_package(&package, &context).expect("published package loads");
    PublishedPackage {
        _root: root,
        root: package,
        verified,
    }
}

fn compile_registry(sequence: u64) -> CompiledRegistry {
    let module = parse_module_yaml(MODULE).expect("test module parses");
    let project = parse_project_yaml(&project_bytes(sequence, &module_digest(&module)))
        .expect("test project parses");
    compile_project(&project, &[module], CompileProfile::Production)
        .expect("test Registry compiles")
}

const MODULE: &[u8] = br#"{"id":"core","version":"1","entities":[
  {"id":"site","primaryDataset":"reference-index-registry","route":"sites","mutationMode":"mutable","classification":"internal",
   "fields":[{"id":"name","type":"string","maxLength":40,"required":true,"classification":"internal"}]},
  {"id":"asset","primaryDataset":"reference-index-registry","route":"assets","mutationMode":"mutable","classification":"internal",
   "fields":[{"id":"site","type":"reference","target":"site","required":true,"classification":"internal"},
             {"id":"owner","type":"reference","target":"site","classification":"internal"},
             {"id":"code","type":"string","maxLength":16,"required":true,"classification":"internal"}],
   "indexes":[{"id":"by-owner","fields":["owner","code"]}],
   "accessProfiles":[{"rowBoundaries":[],"id":"reader","principalClaim":"principal","operations":["get","list"],
     "readableFields":["site","owner","code"],"filterableFields":["site"]}]}]}"#;

fn project_bytes(sequence: u64, digest: &str) -> Vec<u8> {
    format!(
        r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"reference-index-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://reference-index.example.test"}},"package":{{"environment":"local","instanceId":"{INSTANCE}","sequence":{sequence},"sourceRevision":"{SOURCE_REVISION}"}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"internal","catalog":{{"baseUrl":"https://reference-index.example.test","title":"Reference Index Registry","publisher":{{"id":"reference-index-registry-authority","name":"Reference Index Publisher"}}}},"publicService":{{"id":"reference-index-registry-service","title":"Reference Index Registry"}},"datasets":[{{"id":"reference-index-registry","title":"Reference Index Dataset","owner":"Reference Index Publisher","status":"active"}}],"dataServices":[{{"id":"reference-index-registry-data-service","title":"Reference Index Registry","endpointUrl":"https://reference-index.example.test","servesDatasets":["reference-index-registry"]}}]}},"modules":[{{"id":"core","version":"1","digest":"{digest}"}}]}}"#
    )
    .into_bytes()
}

fn build_request(
    sequence: u64,
    prior_revision: Option<&str>,
    schema_fingerprint: &str,
    migration_plan: PackageMigrationPlanInput,
) -> PackageBuildRequest {
    let module = parse_module_yaml(MODULE).expect("package module parses");
    PackageBuildRequest {
        environment: "local".to_owned(),
        instance_id: INSTANCE.to_owned(),
        database_id: DATABASE.to_owned(),
        sequence,
        prior_revision: prior_revision.map(str::to_owned),
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint: schema_fingerprint.to_owned(),
        signature_policy: SignaturePolicy {
            threshold: 0,
            key_ids: Vec::new(),
        },
        project: PackageSourceFile {
            path: "source/registry.yaml".to_owned(),
            bytes: project_bytes(sequence, &module_digest(&module)),
        },
        modules: vec![PackageModuleSource {
            id: "core".to_owned(),
            path: "source/modules/core/module.yaml".to_owned(),
            bytes: MODULE.to_vec(),
            assets: Vec::new(),
        }],
        fixture_journeys: PackageSourceFile {
            path: "tests/journeys.yaml".to_owned(),
            bytes: FIXTURE_JOURNEYS.to_vec(),
        },
        migration_plan,
    }
}

fn local_context<'a>(intent: PackageIntent<'a>) -> PackageLoadContext<'a> {
    PackageLoadContext {
        environment: "local",
        instance_id: INSTANCE,
        database_id: DATABASE,
        database_initialization_environment: "local",
        compiler_source_revision: SOURCE_REVISION,
        trust_anchor: None,
        intent,
    }
}

async fn rehearsed_fingerprint(database: &TestDatabase, registry: &CompiledRegistry) -> String {
    let (mut migration, task) = database.connect_migration().await;
    let transaction = migration
        .transaction()
        .await
        .expect("fingerprint transaction starts");
    install_compiled_schema(&transaction, registry, &database.runtime_role)
        .await
        .expect("schema rehearses");
    let fingerprint = managed_schema_fingerprint(
        &transaction,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(registry),
    )
    .await
    .expect("fingerprint computes");
    transaction
        .rollback()
        .await
        .expect("fingerprint rehearsal rolls back");
    task.abort();
    fingerprint
}

async fn apply(
    database: &TestDatabase,
    package: &VerifiedPackage,
    precondition: ApplyPrecondition<'_>,
) -> registry_breg::migration::Result<ExpectedRegistryIdentity> {
    apply_verified_package(ApplyVerifiedPackageRequest::new(
        &database.migration_config,
        package,
        precondition,
        ApplyRoles::new(&database.migration_role, &database.runtime_role),
        ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
            .expect("test timeouts are bounded"),
    ))
    .await
}

async fn startup(
    database: &TestDatabase,
    package: &PublishedPackage,
    active: &ExpectedRegistryIdentity,
    sequence: u64,
) -> Result<(), StartupError> {
    let pool = database
        .runtime_config
        .build_pool()
        .expect("runtime pool builds");
    let mut runtime = pool.get_for_test().await.expect("runtime connects");
    prepare_startup(
        &package.root,
        &local_context(PackageIntent::Startup {
            active_revision: &active.package_revision,
            active_sequence: sequence,
        }),
        &mut runtime,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .map(|_| ())
}

fn reference_index_name(registry: &CompiledRegistry, field: &str) -> String {
    registry.physical_names().entities["asset"].indexes[&format!("reference:{field}")].clone()
}

async fn index_definitions(database: &TestDatabase) -> BTreeMap<String, String> {
    database
        .admin
        .query(
            "SELECT indexname::text, indexdef FROM pg_catalog.pg_indexes
             WHERE schemaname = 'registry_data'",
            &[],
        )
        .await
        .expect("index catalog reads")
        .into_iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect()
}

/// Twenty common sites share four thousand assets; one rare site owns five,
/// so an equality filter on the rare site is selective enough to prefer the
/// reference index over a sequential scan.
async fn seed_skewed_assets(
    database: &TestDatabase,
    registry: &CompiledRegistry,
    active: &ExpectedRegistryIdentity,
) {
    let site = &registry.entities()["site"];
    let asset = &registry.entities()["asset"];
    let site_table = &site.physical_table;
    let site_name = &site.fields["name"].physical_name;
    let asset_table = &asset.physical_table;
    let asset_site = &asset.fields["site"].physical_name;
    let asset_code = &asset.fields["code"].physical_name;
    let revision = &active.package_revision;
    // The superuser session bypasses row security for bulk synthetic rows.
    database
        .admin
        .batch_execute(&format!(
            "SET registry.active_package_revision = '{revision}';
             INSERT INTO registry_data.\"{site_table}\" (record_id, \"{site_name}\")
             SELECT ('00000000-0000-4000-8000-' || lpad(n::text, 12, '0'))::uuid, 'site-' || n
             FROM generate_series(1, 20) AS n;
             INSERT INTO registry_data.\"{site_table}\" (record_id, \"{site_name}\")
             VALUES ('{RARE_SITE}', 'rare');
             INSERT INTO registry_data.\"{asset_table}\" (record_id, \"{asset_site}\", \"{asset_code}\")
             SELECT gen_random_uuid(),
                    ('00000000-0000-4000-8000-' || lpad((1 + n % 20)::text, 12, '0'))::uuid,
                    'common-' || n
             FROM generate_series(1, 4000) AS n;
             INSERT INTO registry_data.\"{asset_table}\" (record_id, \"{asset_site}\", \"{asset_code}\")
             SELECT gen_random_uuid(), '{RARE_SITE}', 'rare-' || n FROM generate_series(1, 5) AS n;
             RESET registry.active_package_revision;
             ANALYZE registry_data.\"{site_table}\";
             ANALYZE registry_data.\"{asset_table}\";"
        ))
        .await
        .expect("skewed synthetic assets seed");
}

async fn send(app: &axum::Router, uri: &str) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .expect("bounded synthetic request");
    request.extensions_mut().insert(
        VerifiedRequestClaims::authenticated(
            "principal",
            "test-principal",
            BTreeSet::new(),
            None,
            BTreeMap::new(),
        )
        .expect("verified request claims"),
    );
    let response = app.clone().call(request).await.expect("router response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("bounded body");
    (
        status,
        serde_json::from_slice(&bytes).expect("JSON response"),
    )
}

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}
