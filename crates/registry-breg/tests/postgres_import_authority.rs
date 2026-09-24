// SPDX-License-Identifier: Apache-2.0
//! Proves an `import` grant loads records only inside an operator-opened
//! import authority: run creation and every chunk are admitted against an
//! open authority for the same entity and profile, under the active package,
//! before its expiry, within its volume, and for a pinned input when inputs
//! are pinned. Every authority transition leaves one chained audit record.

#![cfg(all(feature = "postgres-test", feature = "tooling"))]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use postgres_harness::TestDatabase;
use registry_breg::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedClaimValue,
    VerifiedRequestClaims,
};
use registry_breg::audit_tooling::AuditOperatorService;
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::cursor::CursorCodec;
use registry_breg::import_authority::{
    ImportAuthority, ImportAuthorityCloseRequest, ImportAuthorityError, ImportAuthorityOpenRequest,
    ImportAuthorityOperatorService, ImportAuthorityStatus, DEFAULT_IMPORT_AUTHORITY_WINDOW,
};
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema, ExpectedManagedCatalog,
    ExpectedRegistryIdentity, PostgresRecordMutationService, PostgresRecordReadService,
    RegistryLockKey, RegistryStateTestIdentity,
};
use registry_breg::CompiledRegistry;
use registry_platform_audit::AuditProfile;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::Service as _;
use uuid::Uuid;
use zeroize::Zeroizing;

const PRINCIPAL: &str = "import-authority-principal";
const PACKAGE_ID: &str = "import-authority-registry";
const PACKAGE_REVISION: &str = "package-import-1";
const SUCCESSOR_REVISION: &str = "package-import-2";

const FIXTURE: &str = r#"{
  "apiVersion":"registry.registrystack.org/v1alpha1",
  "kind":"RegistryProject",
  "registry":{"id":"import-authority-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
  "entities":[{
    "id":"widget","primaryDataset":"test-dataset","route":"widgets","mutationMode":"mutable","classification":"public",
    "batch":{"maximumItems":3,"maximumBytes":8192},
    "constraints":[{"kind":"unique","fields":["label"]}],
    "fields":[
      {"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"public"},
      {"id":"label","type":"string","maxLength":128,"required":true,"classification":"public"}
    ]
  },{
    "id":"gadget","primaryDataset":"test-dataset","route":"gadgets","mutationMode":"mutable","classification":"public",
    "batch":{"maximumItems":3,"maximumBytes":8192},
    "fields":[
      {"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"public"},
      {"id":"label","type":"string","maxLength":128,"required":true,"classification":"public"}
    ]
  },{
    "id":"ledger","primaryDataset":"test-dataset","route":"ledgers","mutationMode":"mutable","classification":"public",
    "batch":{"maximumItems":3,"maximumBytes":8192},
    "fields":[
      {"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"public"},
      {"id":"label","type":"string","maxLength":128,"required":true,"classification":"public"}
    ]
  }],
  "accessProfiles":[{
    "id":"loader","default":true,"principalClaim":"registry_principal",
    "permissions":[{
      "entity":"widget","operations":["import"],
      "readableFields":["jurisdiction","label"],"writableFields":["jurisdiction","label"],
      "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
    },{
      "entity":"gadget","operations":["import"],
      "readableFields":["jurisdiction","label"],"writableFields":["jurisdiction","label"],
      "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
    },{
      "entity":"ledger","operations":["create","batch"],
      "readableFields":["jurisdiction","label"],"writableFields":["jurisdiction","label"],
      "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
    }]
  },{
    "id":"second-loader","principalClaim":"registry_principal",
    "permissions":[{
      "entity":"widget","operations":["import"],
      "readableFields":["jurisdiction","label"],"writableFields":["jurisdiction","label"],
      "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
    }]
  }]
}"#;

fn compiled_registry() -> CompiledRegistry {
    let project = parse_project_json(FIXTURE.as_bytes()).expect("fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("fixture compiles")
}

struct Harness {
    database: TestDatabase,
    registry: Arc<CompiledRegistry>,
    identity: ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    audit_profile: AuditProfile,
    app: axum::Router,
}

impl Harness {
    async fn create() -> Self {
        let registry = Arc::new(compiled_registry());
        let database = TestDatabase::create(8).await;
        let (migration, migration_task) = database.connect_migration().await;
        install_compiled_schema(&migration, &registry, &database.runtime_role)
            .await
            .expect("migration installs the compiler-owned schema");
        let identity = initialize_compiled_registry_state_for_test(
            &migration,
            &database.runtime_role,
            &registry,
            RegistryStateTestIdentity {
                package_id: PACKAGE_ID,
                environment: "local",
                instance_id: "import-authority-instance",
                database_id: "import-authority-database",
                package_revision: PACKAGE_REVISION,
                package_sequence: 1,
            },
        )
        .await
        .expect("active package identity is initialized");
        migration_task.abort();
        let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives");
        let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x7c; 32].into())
            .expect("test owns a keyed audit profile");
        let app = build_router(
            &database,
            registry.clone(),
            identity.clone(),
            lock_key,
            audit_profile.clone(),
        );
        Self {
            database,
            registry,
            identity,
            lock_key,
            audit_profile,
            app,
        }
    }

    fn operator(&self) -> ImportAuthorityOperatorService {
        self.operator_under(&self.identity)
    }

    fn operator_under(
        &self,
        identity: &ExpectedRegistryIdentity,
    ) -> ImportAuthorityOperatorService {
        ImportAuthorityOperatorService::new_for_test(
            identity.clone(),
            ExpectedManagedCatalog::compiled(&self.registry),
            self.lock_key,
            self.database.migration_config.clone(),
            self.database.migration_role.clone(),
            self.database.runtime_role.clone(),
            self.audit_profile.clone(),
            self.registry.clone(),
        )
    }

    fn audit(&self) -> AuditOperatorService {
        AuditOperatorService::new_for_test(
            self.identity.clone(),
            ExpectedManagedCatalog::compiled(&self.registry),
            self.lock_key,
            self.database.migration_config.clone(),
            self.database.runtime_config.clone(),
            self.database.migration_role.clone(),
            self.database.runtime_role.clone(),
            self.audit_profile.clone(),
        )
    }

    async fn open(
        &self,
        entity_id: &str,
        profile_id: &str,
        max_items: i64,
        input_digests: &[String],
    ) -> ImportAuthority {
        self.operator()
            .open(open_request(
                entity_id,
                profile_id,
                max_items,
                input_digests,
            ))
            .await
            .expect("the operator opens an import authority")
    }

    async fn close(&self, authority_id: Uuid) -> ImportAuthority {
        self.operator()
            .close(ImportAuthorityCloseRequest {
                authority_id,
                operator_reference: "operator-b",
                reason: "load finished",
            })
            .await
            .expect("the operator closes the authority")
    }

    /// Activate a successor revision of the same package, as `bregctl apply`
    /// would, and answer the HTTP surface a restarted process serves under it.
    async fn activate_successor(&self) -> (axum::Router, ExpectedRegistryIdentity) {
        let successor = ExpectedRegistryIdentity {
            package_revision: SUCCESSOR_REVISION.to_owned(),
            package_sequence: 2,
            ..self.identity.clone()
        };
        let changed = self
            .database
            .admin
            .execute(
                "UPDATE registry_internal.registry_state
                    SET active_package_revision = $1, package_sequence = $2
                  WHERE singleton",
                &[&successor.package_revision, &successor.package_sequence],
            )
            .await
            .expect("successor revision activates");
        assert_eq!(changed, 1);
        let app = build_router(
            &self.database,
            self.registry.clone(),
            successor.clone(),
            self.lock_key,
            self.audit_profile.clone(),
        );
        (app, successor)
    }

    /// Move one authority's whole window into the past, as the passage of
    /// time would, without touching its status.
    async fn age_past_expiry(&self, authority_id: Uuid) {
        let changed = self
            .database
            .admin
            .execute(
                "UPDATE registry_internal.registry_import_authorities
                    SET opened_at = now() - interval '2 days',
                        expires_at = now() - interval '1 day'
                  WHERE authority_id = $1",
                &[&authority_id],
            )
            .await
            .expect("administrator ages the authority");
        assert_eq!(changed, 1);
    }

    async fn authority(&self, authority_id: Uuid) -> (String, i64) {
        let row = self
            .database
            .admin
            .query_one(
                "SELECT status, committed_items
                   FROM registry_internal.registry_import_authorities
                  WHERE authority_id = $1",
                &[&authority_id],
            )
            .await
            .expect("administrator reads the authority");
        (row.get(0), row.get(1))
    }

    async fn run_authority(&self, run_id: &str) -> Option<Uuid> {
        self.database
            .admin
            .query_one(
                "SELECT import_authority_id FROM registry_internal.registry_ingestion_runs
                  WHERE run_id = $1",
                &[&Uuid::parse_str(run_id).expect("run id")],
            )
            .await
            .expect("administrator reads the run")
            .get(0)
    }

    async fn run_count(&self) -> i64 {
        self.database
            .admin
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_ingestion_runs",
                &[],
            )
            .await
            .expect("administrator counts runs")
            .get(0)
    }

    /// The authority audit records, oldest first.
    async fn authority_records(&self, authority_id: Uuid) -> Vec<Value> {
        let rows = self
            .database
            .admin
            .query(
                "SELECT convert_from(envelope, 'UTF8')
                   FROM registry_internal.registry_audit
                  ORDER BY created_at",
                &[],
            )
            .await
            .expect("administrator reads the audit journal");
        rows.iter()
            .map(|row| {
                let envelope: Value =
                    serde_json::from_str(&row.get::<_, String>(0)).expect("envelope is JSON");
                envelope["record"].clone()
            })
            .filter(|record| {
                record["schema"] == "breg-import-authority-audit/v1"
                    && record["authorityId"] == authority_id.to_string()
            })
            .collect()
    }

    async fn create_run(
        &self,
        app: &axum::Router,
        entity_route: &str,
        profile_id: &str,
        plan: &Plan,
        package_revision: &str,
    ) -> axum::response::Response {
        send(
            app,
            Method::POST,
            &format!("/v1/records/{entity_route}/ingestion-runs?accessProfile={profile_id}"),
            json!({
                "operation": "create",
                "profileId": profile_id,
                "packageRevision": package_revision,
                "schemaFingerprint": self.identity.schema_fingerprint,
                "inputDigest": plan.input_digest,
                "inputLength": plan.input_length,
                "itemCount": plan.items.len(),
                "chunkCount": plan.chunks.len(),
                "chunkAlgorithmVersion": "greedy-canonical-http-batch-v1",
            }),
        )
        .await
    }

    async fn created_run(&self, entity_route: &str, profile_id: &str, plan: &Plan) -> String {
        let response = self
            .create_run(&self.app, entity_route, profile_id, plan, PACKAGE_REVISION)
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        body_json(response).await["run"]["runId"]
            .as_str()
            .expect("run id")
            .to_owned()
    }

    async fn submit(
        &self,
        entity_route: &str,
        profile_id: &str,
        run_id: &str,
        plan: &Plan,
        index: usize,
    ) -> axum::response::Response {
        send(
            &self.app,
            Method::POST,
            &format!(
                "/v1/records/{entity_route}/ingestion-runs/{run_id}/chunks?accessProfile={profile_id}"
            ),
            plan.chunk_body(index),
        )
        .await
    }

    async fn committed_chunk(&self, run_id: &str, plan: &Plan, index: usize) {
        let response = self.submit("widgets", "loader", run_id, plan, index).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Submit the chunk and prove the run blocked on its authority: the
    /// refusal is `ingestion.run_blocked`, the run reports
    /// `importAuthorityClosed`, and no widget was written by the chunk.
    async fn blocked_chunk(&self, run_id: &str, plan: &Plan, index: usize) {
        let before = self.widget_count().await;
        let response = self.submit("widgets", "loader", run_id, plan, index).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(body_json(response).await["code"], "ingestion.run_blocked");
        assert_eq!(self.widget_count().await, before);
        let run = send(
            &self.app,
            Method::GET,
            &format!("/v1/records/widgets/ingestion-runs/{run_id}?accessProfile=loader"),
            Value::Null,
        )
        .await;
        assert_eq!(run.status(), StatusCode::OK);
        let run = body_json(run).await;
        let run = if run.get("run").is_some() {
            run["run"].clone()
        } else {
            run
        };
        assert_eq!(run["status"], "blocked", "{run}");
        assert_eq!(run["blockedReason"], "importAuthorityClosed");
    }

    async fn widget_count(&self) -> i64 {
        let table = &self.registry.entities()["widget"].physical_table;
        self.database
            .admin
            .query_one(
                &format!("SELECT count(*) FROM registry_data.\"{table}\""),
                &[],
            )
            .await
            .expect("administrator counts widgets")
            .get(0)
    }

    /// The run audit records of one run, oldest first.
    async fn run_records(&self, run_id: &str) -> Vec<Value> {
        let rows = self
            .database
            .admin
            .query(
                "SELECT convert_from(envelope, 'UTF8')
                   FROM registry_internal.registry_audit
                  ORDER BY created_at",
                &[],
            )
            .await
            .expect("administrator reads the audit journal");
        rows.iter()
            .map(|row| {
                let envelope: Value =
                    serde_json::from_str(&row.get::<_, String>(0)).expect("envelope is JSON");
                envelope["record"].clone()
            })
            .filter(|record| record["kind"] == "ingestionRun" && record["runId"] == run_id)
            .collect()
    }

    async fn refused_run(&self, entity_route: &str, profile_id: &str, plan: &Plan) {
        let before = self.run_count().await;
        let response = self
            .create_run(&self.app, entity_route, profile_id, plan, PACKAGE_REVISION)
            .await;
        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
        assert_eq!(body_json(response).await["code"], "precondition.failed");
        assert_eq!(self.run_count().await, before, "a refused run never exists");
    }
}

fn open_request<'a>(
    entity_id: &'a str,
    profile_id: &'a str,
    max_items: i64,
    input_digests: &'a [String],
) -> ImportAuthorityOpenRequest<'a> {
    ImportAuthorityOpenRequest {
        entity_id,
        profile_id,
        max_items,
        expires_in: DEFAULT_IMPORT_AUTHORITY_WINDOW,
        input_digests,
        operator_reference: "operator-a",
        reason: "initial load of reviewed records",
    }
}

fn build_router(
    database: &TestDatabase,
    registry: Arc<CompiledRegistry>,
    identity: ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    profile: AuditProfile,
) -> axum::Router {
    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool builds");
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x53; 32]), Duration::from_secs(300))
            .expect("cursor key is valid"),
    );
    let records = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        profile.clone(),
        cursors.clone(),
    ));
    let mutations = PostgresRecordMutationService::new(
        pool,
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        profile,
    );
    router(Arc::new(
        HttpService::new(
            registry,
            ReadRuntimeIdentity {
                package_revision: identity.package_revision,
                schema_fingerprint: identity.schema_fingerprint,
            },
            records,
            Arc::new(AlwaysReady),
            cursors,
        )
        .with_postgres_mutations(Arc::new(mutations)),
    ))
}

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

fn claims() -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        PRINCIPAL,
        BTreeSet::new(),
        None,
        BTreeMap::from([(
            "jurisdiction".to_owned(),
            VerifiedClaimValue::direct_string("zone-a").expect("direct claim"),
        )]),
    )
    .expect("verified claims are bounded")
}

async fn send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    body: Value,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).expect("request JSON")))
        .expect("request");
    request.extensions_mut().insert(claims());
    let mut app = app.clone();
    app.call(request).await.expect("response")
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("JSON response")
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// One import input: its items, the greedy chunks the run announces, and the
/// digests the run and every chunk bind.
struct Plan {
    items: Vec<Value>,
    chunks: Vec<(usize, usize)>,
    input_digest: String,
    input_length: i64,
    chunk_digests: Vec<String>,
    prefix_digests: Vec<String>,
}

impl Plan {
    fn chunk_body(&self, index: usize) -> Value {
        let (start, end) = self.chunks[index];
        json!({
            "chunkIndex": index,
            "items": self.items[start..end],
            "digest": self.chunk_digests[index],
            "prefixDigest": self.prefix_digests[index],
        })
    }
}

fn plan(label_prefix: &str, count: usize) -> Plan {
    let items: Vec<Value> = (0..count)
        .map(|index| {
            json!({"operation":"create","data":{
                "jurisdiction":"zone-a","label":format!("{label_prefix}-{index}")
            }})
        })
        .collect();
    let lines: Vec<Vec<u8>> = items
        .iter()
        .map(|item| {
            let mut line =
                registry_platform_canonical_json::canonicalize_json(item).expect("canonical JSON");
            line.push(b'\n');
            line
        })
        .collect();
    let mut chunks = Vec::new();
    let mut start = 0;
    while start < items.len() {
        let end = (start + 3).min(items.len());
        chunks.push((start, end));
        start = end;
    }
    let chunk_digests = chunks
        .iter()
        .map(|&(start, end)| {
            hex_digest(
                &registry_platform_canonical_json::canonicalize_json(
                    &json!({"items": items[start..end]}),
                )
                .expect("canonical JSON"),
            )
        })
        .collect();
    let prefix_digests = chunks
        .iter()
        .map(|&(_, end)| hex_digest(&lines[..end].concat()))
        .collect();
    let input = lines.concat();
    Plan {
        items,
        chunks,
        input_digest: hex_digest(&input),
        input_length: input.len() as i64,
        chunk_digests,
        prefix_digests,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_import_run_is_refused_without_an_open_authority() {
    let harness = Harness::create().await;
    harness
        .refused_run("widgets", "loader", &plan("none", 2))
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_open_authority_admits_a_run_that_names_it() {
    let harness = Harness::create().await;
    let authority = harness.open("widget", "loader", 10, &[]).await;
    assert_eq!(authority.status, ImportAuthorityStatus::Open);
    assert_eq!(authority.activation_revision, PACKAGE_REVISION);
    let run_id = harness
        .created_run("widgets", "loader", &plan("admitted", 4))
        .await;
    assert_eq!(
        harness.run_authority(&run_id).await,
        Some(authority.authority_id)
    );
    let opened = harness.authority_records(authority.authority_id).await;
    assert_eq!(opened.len(), 1, "{opened:?}");
    assert_eq!(opened[0]["transition"], "opened");
    assert_eq!(opened[0]["operationId"], "breg.import_authority");
    assert_eq!(opened[0]["maxItems"], 10);
    for clear in ["operator-a", "initial load of reviewed records"] {
        assert!(
            !opened[0].to_string().contains(clear),
            "the operator reference and reason appear only as keyed hashes"
        );
    }
    assert!(opened[0]["operatorReference"].is_string());
    assert!(opened[0]["reasonReference"].is_string());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_batch_run_needs_no_authority() {
    let harness = Harness::create().await;
    let run_id = harness
        .created_run("ledgers", "loader", &plan("ledger", 2))
        .await;
    assert_eq!(harness.run_authority(&run_id).await, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_authority_for_another_profile_does_not_admit_the_run() {
    let harness = Harness::create().await;
    harness.open("widget", "second-loader", 10, &[]).await;
    harness
        .refused_run("widgets", "loader", &plan("wrong-profile", 2))
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_authority_for_another_entity_does_not_admit_the_run() {
    let harness = Harness::create().await;
    harness.open("gadget", "loader", 10, &[]).await;
    harness
        .refused_run("widgets", "loader", &plan("wrong-entity", 2))
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_run_larger_than_the_remaining_volume_never_starts() {
    let harness = Harness::create().await;
    harness.open("widget", "loader", 3, &[]).await;
    harness
        .refused_run("widgets", "loader", &plan("too-many", 4))
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pinned_authority_admits_only_the_pinned_input() {
    let harness = Harness::create().await;
    let reviewed = plan("reviewed", 2);
    let unreviewed = plan("unreviewed", 2);
    harness
        .open(
            "widget",
            "loader",
            10,
            std::slice::from_ref(&reviewed.input_digest),
        )
        .await;
    harness.refused_run("widgets", "loader", &unreviewed).await;
    harness.created_run("widgets", "loader", &reviewed).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closed_authority_admits_no_run_and_records_its_close() {
    let harness = Harness::create().await;
    let authority = harness.open("widget", "loader", 10, &[]).await;
    let closed = harness.close(authority.authority_id).await;
    assert_eq!(closed.status, ImportAuthorityStatus::Closed);
    assert!(closed.closed_at.is_some());
    harness
        .refused_run("widgets", "loader", &plan("revoked", 2))
        .await;
    let again = harness.close(authority.authority_id).await;
    assert_eq!(again, closed, "closing a closed authority changes nothing");
    let records = harness.authority_records(authority.authority_id).await;
    let transitions: Vec<&str> = records
        .iter()
        .map(|record| record["transition"].as_str().expect("transition"))
        .collect();
    assert_eq!(transitions, ["opened", "closed"]);
    assert!(records[1]["operatorReference"].is_string());
    assert_ne!(
        records[1]["operatorReference"], records[0]["operatorReference"],
        "the close names its own operator"
    );
    harness.audit().verify().await.expect("the chain verifies");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_expired_authority_admits_no_run_and_records_one_expiry() {
    let harness = Harness::create().await;
    let authority = harness.open("widget", "loader", 10, &[]).await;
    harness.age_past_expiry(authority.authority_id).await;
    harness
        .refused_run("widgets", "loader", &plan("expired", 2))
        .await;
    harness
        .refused_run("widgets", "loader", &plan("expired-again", 2))
        .await;
    assert_eq!(harness.authority(authority.authority_id).await.0, "expired");
    let records = harness.authority_records(authority.authority_id).await;
    let transitions: Vec<&str> = records
        .iter()
        .map(|record| record["transition"].as_str().expect("transition"))
        .collect();
    assert_eq!(transitions, ["opened", "expired"]);
    assert!(
        records[1].get("operatorReference").is_none(),
        "an observed expiry names no operator"
    );
    harness.audit().verify().await.expect("the chain verifies");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_successor_package_supersedes_an_open_authority() {
    let harness = Harness::create().await;
    let authority = harness.open("widget", "loader", 10, &[]).await;
    let (successor_app, successor) = harness.activate_successor().await;
    let before = harness.run_count().await;
    let response = harness
        .create_run(
            &successor_app,
            "widgets",
            "loader",
            &plan("superseded", 2),
            SUCCESSOR_REVISION,
        )
        .await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(harness.run_count().await, before);
    assert_eq!(
        harness.authority(authority.authority_id).await.0,
        "superseded"
    );
    let records = harness.authority_records(authority.authority_id).await;
    assert_eq!(records.len(), 2, "{records:?}");
    assert_eq!(records[1]["transition"], "superseded");
    assert_eq!(records[1]["packageRevision"], SUCCESSOR_REVISION);

    // The operator re-opens deliberately under the successor.
    let reopened = harness
        .operator_under(&successor)
        .open(open_request("widget", "loader", 10, &[]))
        .await
        .expect("a new authority opens under the successor");
    assert_eq!(reopened.activation_revision, SUCCESSOR_REVISION);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_entity_holds_at_most_one_open_authority() {
    let harness = Harness::create().await;
    harness.open("widget", "loader", 10, &[]).await;
    assert_eq!(
        harness
            .operator()
            .open(open_request("widget", "second-loader", 10, &[]))
            .await
            .err(),
        Some(ImportAuthorityError::AlreadyOpen)
    );
    harness.open("gadget", "loader", 10, &[]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_authority_opens_only_over_an_import_grant() {
    let harness = Harness::create().await;
    for (entity, profile) in [
        ("ledger", "loader"),
        ("gadget", "second-loader"),
        ("missing", "loader"),
    ] {
        assert_eq!(
            harness
                .operator()
                .open(open_request(entity, profile, 10, &[]))
                .await
                .err(),
            Some(ImportAuthorityError::NotImportable),
            "{entity}/{profile}"
        );
    }
    assert_eq!(
        harness
            .operator()
            .close(ImportAuthorityCloseRequest {
                authority_id: Uuid::new_v4(),
                operator_reference: "operator-b",
                reason: "no such authority",
            })
            .await
            .err(),
        Some(ImportAuthorityError::NotFound)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn close_expired_and_list_record_every_due_transition_once() {
    let harness = Harness::create().await;
    let widget = harness.open("widget", "loader", 10, &[]).await;
    let gadget = harness.open("gadget", "loader", 10, &[]).await;
    harness.age_past_expiry(widget.authority_id).await;
    let moved = harness
        .operator()
        .close_expired()
        .await
        .expect("close-expired settles due transitions");
    assert_eq!(moved.len(), 1);
    assert_eq!(moved[0].authority_id, widget.authority_id);
    assert_eq!(moved[0].status, ImportAuthorityStatus::Expired);
    assert!(harness
        .operator()
        .close_expired()
        .await
        .expect("a second sweep")
        .is_empty());
    let listed = harness.operator().list().await.expect("list answers");
    assert_eq!(listed.len(), 2);
    let status = |id: Uuid| {
        listed
            .iter()
            .find(|authority| authority.authority_id == id)
            .expect("listed")
            .status
    };
    assert_eq!(status(widget.authority_id), ImportAuthorityStatus::Expired);
    assert_eq!(status(gadget.authority_id), ImportAuthorityStatus::Open);
    assert_eq!(
        harness.authority_records(widget.authority_id).await.len(),
        2
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_runtime_role_cannot_open_close_or_reopen_an_authority() {
    let harness = Harness::create().await;
    let authority = harness.open("widget", "loader", 10, &[]).await;
    let (runtime, runtime_task) = harness.database.connect_admin().await;
    runtime
        .batch_execute(&format!(
            "SET ROLE \"{}\"",
            harness.database.runtime_role.as_str()
        ))
        .await
        .expect("the session takes the runtime role");
    let insert = runtime
        .execute(
            "INSERT INTO registry_internal.registry_import_authorities
                 (authority_id, entity_id, profile_id, operation, max_items,
                  activation_revision, expires_at, operator_reference, reason_reference)
             VALUES ($1, 'gadget', 'loader', 'create', 5, 'package-import-1',
                     now() + interval '1 day', 'r', 'r')",
            &[&Uuid::new_v4()],
        )
        .await;
    assert!(insert.is_err(), "the runtime role cannot open an authority");
    let widen = runtime
        .execute(
            "UPDATE registry_internal.registry_import_authorities
                SET max_items = 1000 WHERE authority_id = $1",
            &[&authority.authority_id],
        )
        .await;
    assert!(widen.is_err(), "the runtime role cannot widen the volume");
    let close = runtime
        .execute(
            "UPDATE registry_internal.registry_import_authorities
                SET status = 'closed', closed_at = now() WHERE authority_id = $1",
            &[&authority.authority_id],
        )
        .await;
    assert!(close.is_err(), "only the operator closes an authority");

    harness.close(authority.authority_id).await;
    let reopened = runtime
        .execute(
            "UPDATE registry_internal.registry_import_authorities
                SET status = 'open', closed_at = NULL WHERE authority_id = $1",
            &[&authority.authority_id],
        )
        .await
        .expect("row security hides the terminal row from the runtime update");
    assert_eq!(reopened, 0, "the runtime role cannot reopen an authority");
    assert_eq!(harness.authority(authority.authority_id).await.0, "closed");
    runtime_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_open_authority_opens_no_direct_write_route() {
    let harness = Harness::create().await;
    harness.open("widget", "loader", 10, &[]).await;
    let item = json!({"jurisdiction":"zone-a","label":"direct"});
    for (method, uri, body) in [
        (
            Method::POST,
            "/v1/records/widgets?accessProfile=loader",
            item.clone(),
        ),
        (
            Method::POST,
            "/v1/records/widgets:batch?accessProfile=loader",
            json!({"items":[{"operation":"create","data":item}]}),
        ),
    ] {
        let response = send(&harness.app, method, uri, body).await;
        assert!(
            response.status() == StatusCode::NOT_FOUND
                || response.status() == StatusCode::METHOD_NOT_ALLOWED,
            "{uri} answered {}",
            response.status()
        );
    }
    assert_eq!(
        harness.widget_count().await,
        0,
        "no route but the ingestion run writes a widget"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_chunk_counts_against_the_authority_until_it_is_exhausted() {
    let harness = Harness::create().await;
    let authority = harness.open("widget", "loader", 5, &[]).await;
    let load = plan("counted", 5);
    let run_id = harness.created_run("widgets", "loader", &load).await;
    harness.committed_chunk(&run_id, &load, 0).await;
    assert_eq!(
        harness.authority(authority.authority_id).await,
        ("open".to_owned(), 3)
    );
    harness.committed_chunk(&run_id, &load, 1).await;
    assert_eq!(
        harness.authority(authority.authority_id).await,
        ("exhausted".to_owned(), 5)
    );
    assert_eq!(harness.widget_count().await, 5);

    let transitions: Vec<Value> = harness
        .authority_records(authority.authority_id)
        .await
        .iter()
        .map(|record| record["transition"].clone())
        .collect();
    assert_eq!(transitions, [json!("opened"), json!("exhausted")]);
    let runs = harness.run_records(&run_id).await;
    let committed = runs
        .iter()
        .filter(|record| record["outcome"] == "committed")
        .collect::<Vec<_>>();
    assert_eq!(committed.len(), 2);
    assert!(committed
        .iter()
        .all(|record| record["importAuthorityId"] == authority.authority_id.to_string()));
    harness
        .refused_run("widgets", "loader", &plan("after-exhaustion", 1))
        .await;
    harness.audit().verify().await.expect("the chain verifies");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closing_the_authority_blocks_the_next_chunk_and_keeps_committed_ones() {
    let harness = Harness::create().await;
    let authority = harness.open("widget", "loader", 10, &[]).await;
    let load = plan("revoked-mid-run", 6);
    let run_id = harness.created_run("widgets", "loader", &load).await;
    harness.committed_chunk(&run_id, &load, 0).await;
    harness.close(authority.authority_id).await;
    harness.blocked_chunk(&run_id, &load, 1).await;
    assert_eq!(
        harness.widget_count().await,
        3,
        "revoking never undoes data"
    );
    let blocked: Vec<Value> = harness
        .run_records(&run_id)
        .await
        .into_iter()
        .filter(|record| record["outcome"] == "blocked")
        .collect();
    assert_eq!(blocked.len(), 1, "{blocked:?}");
    assert_eq!(blocked[0]["blockedReason"], "import_authority_closed");
    assert_eq!(
        blocked[0]["importAuthorityId"],
        authority.authority_id.to_string()
    );
    // A blocked run stays blocked; a later chunk is refused without a second
    // blocked record.
    let again = harness.submit("widgets", "loader", &run_id, &load, 1).await;
    assert_eq!(again.status(), StatusCode::CONFLICT);
    assert_eq!(
        harness
            .run_records(&run_id)
            .await
            .iter()
            .filter(|record| record["outcome"] == "blocked")
            .count(),
        1
    );
    harness.audit().verify().await.expect("the chain verifies");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expiry_between_two_chunks_blocks_the_run_and_records_the_expiry() {
    let harness = Harness::create().await;
    let authority = harness.open("widget", "loader", 10, &[]).await;
    let load = plan("expires-mid-run", 6);
    let run_id = harness.created_run("widgets", "loader", &load).await;
    harness.committed_chunk(&run_id, &load, 0).await;
    harness.age_past_expiry(authority.authority_id).await;
    harness.blocked_chunk(&run_id, &load, 1).await;
    assert_eq!(
        harness.authority(authority.authority_id).await,
        ("expired".to_owned(), 3)
    );
    let transitions: Vec<Value> = harness
        .authority_records(authority.authority_id)
        .await
        .iter()
        .map(|record| record["transition"].clone())
        .collect();
    assert_eq!(transitions, [json!("opened"), json!("expired")]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_run_cannot_spend_volume_the_first_already_committed() {
    let harness = Harness::create().await;
    let authority = harness.open("widget", "loader", 6, &[]).await;
    let first = plan("first", 3);
    let second = plan("second", 6);
    let first_run = harness.created_run("widgets", "loader", &first).await;
    // Both runs are admitted while the whole volume is still free.
    let second_run = harness.created_run("widgets", "loader", &second).await;
    harness.committed_chunk(&first_run, &first, 0).await;
    harness.committed_chunk(&second_run, &second, 0).await;
    assert_eq!(
        harness.authority(authority.authority_id).await,
        ("exhausted".to_owned(), 6)
    );
    harness.blocked_chunk(&second_run, &second, 1).await;
    assert_eq!(harness.widget_count().await, 6);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_close_racing_a_chunk_waits_for_it_and_stops_the_next() {
    let harness = Harness::create().await;
    let authority = harness.open("widget", "loader", 10, &[]).await;
    let load = plan("raced", 6);
    let run_id = harness.created_run("widgets", "loader", &load).await;

    // Hold the authority row lock from a second session, as an in-flight
    // chunk transaction would, and start the close behind it.
    let (holder, holder_task) = harness.database.connect_admin().await;
    holder
        .batch_execute("BEGIN")
        .await
        .expect("the holder opens a transaction");
    holder
        .execute(
            "SELECT 1 FROM registry_internal.registry_import_authorities
              WHERE authority_id = $1 FOR UPDATE",
            &[&authority.authority_id],
        )
        .await
        .expect("the holder locks the authority");
    let operator = harness.operator();
    let close = tokio::spawn(async move {
        operator
            .close(ImportAuthorityCloseRequest {
                authority_id: authority.authority_id,
                operator_reference: "operator-b",
                reason: "stop the load",
            })
            .await
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!close.is_finished(), "the close waits for the row lock");
    assert_eq!(harness.authority(authority.authority_id).await.0, "open");
    holder
        .batch_execute("COMMIT")
        .await
        .expect("the holder releases the lock");
    holder_task.abort();
    let closed = close
        .await
        .expect("the close task joins")
        .expect("the close commits");
    assert_eq!(closed.status, ImportAuthorityStatus::Closed);
    harness.blocked_chunk(&run_id, &load, 0).await;
}
