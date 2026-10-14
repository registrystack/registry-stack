// SPDX-License-Identifier: Apache-2.0

//! List page plans on real PostgreSQL: a filtered page reaches the declared
//! index that leads with its filter and continues with its order, on the
//! first page and on a continuation deep into the filtered set. The assertions
//! are on plan shape, never on timing: the index the page seeks, the absence
//! of a sort, and how many rows each plan node reads to serve one page.

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode};
use postgres_harness::TestDatabase;
use registry_breg::CompiledRegistry;
use registry_breg::api::{
    HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedRequestClaims, router,
};
use registry_breg::compiler::{CompileProfile, compile_project, module_digest};
use registry_breg::contract::{parse_module_yaml, parse_project_yaml};
use registry_breg::cursor::CursorCodec;
use registry_breg::migration::{
    ActivationDeployment, ApplyPrecondition, ApplyRoles, ApplyTimeouts,
    ApplyVerifiedPackageRequest, apply_verified_package,
};
use registry_breg::package::{
    PackageBuildRequest, PackageLoadContext, PackageMigrationPlanInput, PackageModuleSource,
    PackageSourceFile, load_package, prepare_package,
};
use registry_breg::postgres::{
    ExpectedManagedCatalog, ExpectedRegistryIdentity, PostgresRecordReadService, RegistryLockKey,
    install_compiled_schema, managed_schema_fingerprint,
};
use registry_platform_audit::AuditProfile;
use serde_json::Value;
use tower::Service as _;
use zeroize::Zeroizing;

const INSTANCE: &str = "list-page-plan-instance";
const DATABASE: &str = "list-page-plan-database";
const SOURCE_REVISION: &str = "list-page-plan-source-revision";
const FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys:
  - id: asset-list
    steps:
      - id: list-assets
        entity: asset
        accessProfile: reader
        claims: {principal: package-reader}
        request: {type: list}
        expect: {outcome: success, status: 200, count: 0}
"#;

/// Rows seeded in total. Each of the three kinds holds a third of them, and
/// each status holds a third of a kind.
const ASSETS: usize = 45_000;
const PAGE: usize = 100;
/// Pages walked before the continuation whose plan is measured. Sixty pages
/// reach past the first status of a kind, so the measured page continues
/// inside a later run of equal sort values.
const DEEP_PAGES: usize = 60;
/// The most rows one plan node may read or discard to serve one page. A page
/// that seeks its index reads the page and the row that proves a next page;
/// a page that sorts or walks a prefix reads thousands.
const ROWS_PER_PAGE_BOUND: f64 = 4.0 * PAGE as f64;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_filtered_page_sorted_by_a_near_unique_field_seeks_its_declared_index() {
    let fixture = Fixture::activate().await;
    fixture
        .assert_first_and_deep_pages_seek(Some("code"), "by-kind-code")
        .await;
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_filtered_page_sorted_by_a_low_cardinality_field_seeks_its_declared_index() {
    let fixture = Fixture::activate().await;
    fixture
        .assert_first_and_deep_pages_seek(Some("status"), "by-kind-status")
        .await;
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_filtered_page_in_id_order_seeks_its_declared_index() {
    let fixture = Fixture::activate().await;
    fixture
        .assert_first_and_deep_pages_seek(None, "by-kind")
        .await;
    fixture.cleanup().await;
}

struct Fixture {
    database: TestDatabase,
    registry: Arc<CompiledRegistry>,
    app: axum::Router,
    plans: Arc<Mutex<Vec<Value>>>,
    pool: registry_breg::postgres::RuntimePool,
}

impl Fixture {
    async fn activate() -> Self {
        let database = TestDatabase::create(2).await;
        let registry = Arc::new(compile_registry());
        let fingerprint = rehearsed_fingerprint(&database, &registry).await;
        let prepared = prepare_package(build_request(&fingerprint)).expect("package prepares");
        let root = tempfile::Builder::new()
            .prefix("registry-list-page-plan-package-")
            .tempdir_in(
                std::env::temp_dir()
                    .canonicalize()
                    .expect("canonical temporary root"),
            )
            .expect("package temporary directory creates");
        let package: PathBuf = root.path().join("package");
        prepared
            .publish_to_directory(&package)
            .expect("package publishes");
        let verified = load_package(
            &package,
            &PackageLoadContext {
                database_initialization_environment: "local",
            },
        )
        .expect("published package loads");
        let active = apply_verified_package(ApplyVerifiedPackageRequest::new(
            &database.migration_config,
            &verified,
            ActivationDeployment::new("local", INSTANCE, DATABASE),
            ApplyPrecondition::InitialActivation,
            ApplyRoles::new(&database.migration_role, &database.runtime_role),
            ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
                .expect("test timeouts are bounded"),
            database.activation_audit(),
        ))
        .await
        .expect("package activates");
        seed_assets(&database, &registry, &active).await;

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
                AuditProfile::production_from_secret_bytes(vec![0x42; 32].into())
                    .expect("keyed audit"),
            )
            .0,
            cursors.clone(),
        )
        .with_query_plan_for_test(plans.clone());
        let app = router(Arc::new(HttpService::new(
            registry.clone(),
            ReadRuntimeIdentity {
                package_revision: active.activation_id.clone(),
                schema_fingerprint: active.schema_fingerprint.clone(),
            },
            Arc::new(service),
            Arc::new(AlwaysReady),
            cursors,
        )));
        Self {
            database,
            registry,
            app,
            plans,
            pool,
        }
    }

    /// Request the first page of one kind in the given order, then walk to a
    /// continuation deep in the filtered set, and hold both plans to the
    /// declared index. The walk then runs to the last page: a continuation
    /// that seeks must still return every asset of the kind once, in order.
    async fn assert_first_and_deep_pages_seek(&self, sort: Option<&str>, index_id: &str) {
        let order = sort
            .map(|field| format!("&$orderby={field}"))
            .unwrap_or_default();
        let index = self.registry.physical_names().entities["asset"].indexes[index_id].clone();
        let (status, mut body) = send(
            &self.app,
            &format!(
                "/v1/records/assets?accessProfile=reader&$filter=kind%20eq%20'kind-1'{order}&$top={PAGE}"
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["items"].as_array().map(Vec::len), Some(PAGE), "{body}");
        assert_page_seeks(&self.take_plan(), &index, "the first page");
        let mut keys = page_keys(&body, sort);

        for page in 1..=DEEP_PAGES {
            let cursor = body["pageInfo"]["nextCursor"]
                .as_str()
                .unwrap_or_else(|| panic!("page {page} continues: {body}"))
                .to_owned();
            self.take_plan();
            let (status, next) = send(
                &self.app,
                &format!("/v1/records/assets?accessProfile=reader&$skiptoken={cursor}"),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{next}");
            assert_eq!(next["items"].as_array().map(Vec::len), Some(PAGE), "{next}");
            keys.extend(page_keys(&next, sort));
            body = next;
        }
        assert_page_seeks(&self.take_plan(), &index, "the deep continuation page");

        while let Some(cursor) = body["pageInfo"]["nextCursor"].as_str().map(str::to_owned) {
            let (status, next) = send(
                &self.app,
                &format!("/v1/records/assets?accessProfile=reader&$skiptoken={cursor}"),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{next}");
            keys.extend(page_keys(&next, sort));
            body = next;
        }
        assert_eq!(keys.len(), ASSETS / 3, "the walk returns the whole kind");
        assert!(
            keys.windows(2).all(|pair| pair[0] < pair[1]),
            "the walk returns each asset once, ordered by the sort value and then the record id"
        );
    }

    fn take_plan(&self) -> Vec<Value> {
        std::mem::take(&mut *self.plans.lock().expect("plan lock"))
    }

    async fn cleanup(self) {
        drop(self.app);
        drop(self.pool);
        self.database.cleanup().await;
    }
}

/// The page order of each item: its sort value, when the list is sorted, and
/// its record id. The seeded sort values have one width, and a record id
/// orders as its text does, so the pairs compare as PostgreSQL orders them.
fn page_keys(body: &Value, sort: Option<&str>) -> Vec<(String, String)> {
    body["items"]
        .as_array()
        .expect("response carries items")
        .iter()
        .map(|item| {
            let value = sort.map_or_else(String::new, |field| {
                item["domainData"][field]
                    .as_str()
                    .expect("item sort value")
                    .to_owned()
            });
            let id = item["recordIdentifier"].as_str().expect("item id");
            (value, id.to_owned())
        })
        .collect()
}

/// A page that seeks its index is an ordered index scan that stops at the
/// page limit: no node sorts, and no node reads or discards more than a few
/// pages of rows.
fn assert_page_seeks(nodes: &[Value], index: &str, page: &str) {
    assert!(
        nodes.iter().any(|node| {
            node["indexName"].as_str() == Some(index)
                && matches!(
                    node["nodeType"].as_str(),
                    Some("Index Scan" | "Index Only Scan")
                )
        }),
        "{page} scans the declared index {index} in order: {nodes:?}"
    );
    assert!(
        !nodes.iter().any(|node| node["nodeType"]
            .as_str()
            .is_some_and(|node_type| node_type.contains("Sort"))),
        "{page} is served without a sort: {nodes:?}"
    );
    for node in nodes {
        let rows = node["actualRows"].as_f64().unwrap_or(0.0)
            * node["actualLoops"].as_f64().unwrap_or(1.0);
        let discarded = node["rowsRemovedByFilter"].as_f64().unwrap_or(0.0)
            * node["actualLoops"].as_f64().unwrap_or(1.0);
        assert!(
            rows <= ROWS_PER_PAGE_BOUND && discarded <= ROWS_PER_PAGE_BOUND,
            "{page} reads about one page of rows at every plan node: {nodes:?}"
        );
    }
}

fn compile_registry() -> CompiledRegistry {
    let module = parse_module_yaml(MODULE).expect("test module parses");
    let project =
        parse_project_yaml(&project_bytes(&module_digest(&module))).expect("test project parses");
    compile_project(&project, &[module], CompileProfile::Production)
        .expect("test Registry compiles")
}

const MODULE: &[u8] = br#"{"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule","id":"core","version":"1","recordTypes":[
  {"id":"asset","primaryDataset":"list-page-plan-registry","route":"assets","mutationMode":"mutable","classification":"internal",
   "fields":[{"id":"kind","type":"string","maximumLength":16,"required":true,"classification":"internal"},
             {"id":"code","type":"string","maximumLength":24,"required":true,"classification":"internal"},
             {"id":"status","type":"string","maximumLength":16,"required":true,"classification":"internal"}],
   "indexes":[{"id":"by-kind","fields":["kind"]},
              {"id":"by-kind-code","fields":["kind","code"]},
              {"id":"by-kind-status","fields":["kind","status"]}],
   "accessProfiles":[{"requiredScopes":"unrestricted","rowBoundaries":"unrestricted","id":"reader","principalClaim":"principal","operations":["get","list"],
     "readableFields":["kind","code","status"],"filterableFields":["kind"],"sortableFields":["code","status"]}]}]}"#;

fn project_bytes(digest: &str) -> Vec<u8> {
    format!(
        r#"{{"datasets":[{{"id": "list-page-plan-registry"}}],"apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject","project":{{"id":"list-page-plan-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://list-page-plan.example.test"}},"package":{{"sourceRevision":"{SOURCE_REVISION}"}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"internal","catalog":{{"baseUrl":"https://list-page-plan.example.test","title":"List Page Plan Registry","publisher":{{"id":"list-page-plan-registry-authority","name":"List Page Plan Publisher"}}}},"publicService":{{"id":"list-page-plan-registry-service","title":"List Page Plan Registry"}},"datasets":[{{"id":"list-page-plan-registry","title":"List Page Plan Dataset","owner":"List Page Plan Publisher","status":"active"}}],"dataServices":[{{"id":"list-page-plan-registry-data-service","title":"List Page Plan Registry","endpointUrl":"https://list-page-plan.example.test","servesDatasets":["list-page-plan-registry"]}}]}},"modules":[{{"id":"core","version":"1","digest":"{digest}"}}]}}"#
    )
    .into_bytes()
}

fn build_request(schema_fingerprint: &str) -> PackageBuildRequest {
    let module = parse_module_yaml(MODULE).expect("package module parses");
    PackageBuildRequest {
        from_package_digest: None,
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint: schema_fingerprint.to_owned(),
        project: PackageSourceFile {
            path: "source/registry.yaml".to_owned(),
            bytes: project_bytes(&module_digest(&module)),
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
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
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

/// Three kinds share the assets evenly, so the filter keeps a third of the
/// table. Inside one kind, pairs of assets share a code and thirds share a
/// status: the code order is near-unique and the status order runs through
/// long stretches of equal values, both tie-broken by the record id.
async fn seed_assets(
    database: &TestDatabase,
    registry: &CompiledRegistry,
    active: &ExpectedRegistryIdentity,
) {
    let asset = &registry.entities()["asset"];
    let table = &asset.physical_table;
    let kind = &asset.fields["kind"].physical_name;
    let code = &asset.fields["code"].physical_name;
    let status = &asset.fields["status"].physical_name;
    let revision = &active.activation_id;
    // The superuser session bypasses row security for bulk synthetic rows.
    database
        .admin
        .batch_execute(&format!(
            "SET registry.active_package_revision = '{revision}';
             INSERT INTO registry_data.\"{table}\" (record_id, \"{kind}\", \"{code}\", \"{status}\")
             SELECT gen_random_uuid(),
                    'kind-' || (n % 3),
                    'code-' || lpad((n / 6)::text, 8, '0'),
                    'status-' || ((n / 3) % 3)
             FROM generate_series(1, {ASSETS}) AS n;
             RESET registry.active_package_revision;
             ANALYZE registry_data.\"{table}\";"
        ))
        .await
        .expect("synthetic assets seed");
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
