// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{HeaderName, HeaderValue, Method, Request, StatusCode};
use postgres_harness::TestDatabase;
use registry_breg::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedClaimValue,
    VerifiedRequestClaims,
};
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::cursor::CursorCodec;
use registry_breg::mutation::MutationFaultPoint;
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    PostgresRecordMutationService, PostgresRecordReadService, RegistryLockKey,
    RegistryStateTestIdentity,
};
use registry_platform_audit::AuditProfile;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::Service as _;
use uuid::Uuid;
use zeroize::Zeroizing;

const PACKAGE_ID: &str = "generated-identifier-batch-import";
const PACKAGE_REVISION: &str = "generated-identifier-batch-import-package";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn batch_and_import_allocate_identifiers_and_failed_chunks_roll_back_every_allocation() {
    let database = TestDatabase::create(8).await;
    let (migration, migration_task) = database.connect_migration().await;
    let registry = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("generated identifier batch/import schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: "generated-identifier-batch-import-database",
            label: PACKAGE_REVISION,
        },
    )
    .await
    .expect("generated identifier batch/import registry initializes");
    drop(migration);
    migration_task.abort();

    let normal = build_router(&database, Arc::clone(&registry), identity.clone(), None);
    let faulted = build_router(
        &database,
        Arc::clone(&registry),
        identity.clone(),
        Some(MutationFaultPoint::AfterFirstBatchItem),
    );
    let claims = writer_claims();

    let batch = post_json(
        &normal,
        "/v1/records/entries:batch",
        &claims,
        Some("generated-identifier-batch"),
        json!({"items": [
            {"operation":"create", "data":{"jurisdiction":"zone-a", "label":"batch-one"}},
            {"operation":"create", "data":{"jurisdiction":"zone-a", "label":"batch-two"}}
        ]}),
    )
    .await;
    assert_eq!(batch.status(), StatusCode::OK);
    let batch = body_json(batch).await;
    assert_eq!(
        generated_numbers(&batch["results"]),
        ["REG-0001", "REG-0002"]
    );
    assert_eq!(allocation_state(&database, &registry).await, (2, 1, 2, 3));

    let import_items = vec![
        json!({"operation":"create", "data":{"jurisdiction":"zone-a", "label":"import-one"}}),
        json!({"operation":"create", "data":{"jurisdiction":"zone-a", "label":"import-two"}}),
    ];
    let plan = import_plan(import_items);
    let created = post_json(
        &normal,
        "/v1/records/entries/ingestion-runs",
        &claims,
        None,
        run_body(&identity.schema_fingerprint, &plan),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let run_id = body_json(created).await["run"]["runId"]
        .as_str()
        .expect("run id")
        .to_owned();

    let failed = post_json(
        &faulted,
        &format!("/v1/records/entries/ingestion-runs/{run_id}/chunks"),
        &claims,
        None,
        chunk_body(&plan),
    )
    .await;
    assert_eq!(failed.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(allocation_state(&database, &registry).await, (2, 1, 2, 3));
    assert_eq!(run_checkpoint(&database, &run_id).await, (0, 0, 0));

    let retried = post_json(
        &normal,
        &format!("/v1/records/entries/ingestion-runs/{run_id}/chunks"),
        &claims,
        None,
        chunk_body(&plan),
    )
    .await;
    assert_eq!(retried.status(), StatusCode::OK);
    let retried = body_json(retried).await;
    assert_eq!(
        generated_numbers(&retried["receipt"]["batch"]["results"]),
        ["REG-0003", "REG-0004"]
    );
    assert_eq!(retried["run"]["status"], "complete");
    assert_eq!(allocation_state(&database, &registry).await, (4, 1, 4, 5));
    assert_eq!(run_checkpoint(&database, &run_id).await, (2, 1, 1));

    database.cleanup().await;
}

fn compiled_registry() -> registry_breg::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"generated-identifier-batch-import","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://identifiers.example.test"},
          "datasets":[{"id":"records"}],
          "recordTypes":[{
            "id":"entry","primaryDataset":"records","route":"entries","mutationMode":"mutable","classification":"internal",
            "batch":{"maximumItems":3,"maximumBytes":8192},
            "constraints":[{"type":"unique","fields":["label"]}],
            "fields":[
              {"id":"jurisdiction","type":"string","minimumLength":1,"maximumLength":16,"required":true,"classification":"internal"},
              {"id":"label","type":"string","minimumLength":1,"maximumLength":64,"required":true,"classification":"internal"},
              {"id":"number","type":"string","minimumLength":1,"maximumLength":32,"required":true,"classification":"internal",
               "generate":{"type":"sequence","prefix":"REG-","minimumDigits":4,"scope":["jurisdiction"]}}
            ]
          }],
          "accessProfiles":[{
            "id":"writer","default":true,"principalClaim":"registry_principal","requiredScopes":"unrestricted",
            "requiredPurposes":["case-management"],
            "permissions":{"records":[{
              "recordType":"entry","operations":["create","get","batch"],
              "readableFields":["jurisdiction","label","number"],
              "writableFields":["jurisdiction","label"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }]}
          }]
        }"#,
    )
    .expect("generated identifier batch/import project parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("generated identifier batch/import project compiles")
}

fn build_router(
    database: &TestDatabase,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    fault: Option<MutationFaultPoint>,
) -> axum::Router {
    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool builds");
    let audit = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x47; 32].into())
            .expect("test owns a keyed audit profile"),
    );
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives");
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x63; 32]), Duration::from_secs(300))
            .expect("cursor key is valid"),
    );
    let records = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        Arc::clone(&registry),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit.clone(),
        Arc::clone(&cursors),
    ));
    let mutations = PostgresRecordMutationService::new(
        pool,
        Arc::clone(&registry),
        identity.clone(),
        "generated-identifier-batch-import-instance",
        lock_key,
        Duration::from_secs(2),
        audit,
    );
    let mutations = match fault {
        Some(fault) => mutations.with_fault_for_test(fault),
        None => mutations,
    };
    router(Arc::new(
        HttpService::new(
            registry,
            ReadRuntimeIdentity {
                package_revision: identity.activation_id,
                schema_fingerprint: identity.schema_fingerprint,
            },
            records,
            Arc::new(AlwaysReady),
            cursors,
        )
        .with_postgres_mutations(Arc::new(mutations)),
    ))
}

fn writer_claims() -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        "generated-identifier-writer",
        BTreeSet::new(),
        Some("case-management".to_owned()),
        BTreeMap::from([(
            "jurisdiction".to_owned(),
            VerifiedClaimValue::direct_string("zone-a").expect("direct claim is valid"),
        )]),
    )
    .expect("authenticated writer claims are valid")
}

async fn allocation_state(
    database: &TestDatabase,
    registry: &registry_breg::CompiledRegistry,
) -> (i64, i64, i64, i64) {
    let table = &registry.entities()["entry"].physical_table;
    let row = database
        .admin
        .query_one(
            &format!(
                "SELECT
                 (SELECT count(*) FROM registry_data.\"{table}\"),
                 (SELECT count(*) FROM registry_internal.registry_generated_identifier_counters),
                 (SELECT count(*) FROM registry_internal.registry_generated_identifier_reservations),
                 (SELECT next_value::bigint FROM registry_internal.registry_generated_identifier_counters)"
            ),
            &[],
        )
        .await
        .expect("generated identifier state is inspectable");
    (row.get(0), row.get(1), row.get(2), row.get(3))
}

async fn run_checkpoint(database: &TestDatabase, run_id: &str) -> (i64, i64, i64) {
    let run_id = Uuid::parse_str(run_id).expect("run id parses");
    let row = database
        .admin
        .query_one(
            "SELECT committed_items, next_chunk_index,
                    (SELECT count(*) FROM registry_internal.registry_ingestion_run_chunks
                      WHERE run_id = $1)
               FROM registry_internal.registry_ingestion_runs
              WHERE run_id = $1",
            &[&run_id],
        )
        .await
        .expect("ingestion checkpoint is inspectable");
    (row.get(0), row.get(1), row.get(2))
}

fn generated_numbers(results: &Value) -> Vec<&str> {
    results
        .as_array()
        .expect("ordered mutation results")
        .iter()
        .map(|result| result["data"]["number"].as_str().expect("generated number"))
        .collect()
}

struct ImportPlan {
    items: Vec<Value>,
    digest: String,
    prefix_digest: String,
    input_digest: String,
    input_length: i64,
}

fn import_plan(items: Vec<Value>) -> ImportPlan {
    let mut input = Vec::new();
    for item in &items {
        let mut line = registry_platform_canonical_json::canonicalize_json(item)
            .expect("canonical import item");
        line.push(b'\n');
        input.extend_from_slice(&line);
    }
    let chunk = registry_platform_canonical_json::canonicalize_json(&json!({"items": items}))
        .expect("canonical import chunk");
    ImportPlan {
        items,
        digest: hex_digest(&chunk),
        prefix_digest: hex_digest(&input),
        input_digest: hex_digest(&input),
        input_length: i64::try_from(input.len()).expect("input length is bounded"),
    }
}

fn run_body(schema_fingerprint: &str, plan: &ImportPlan) -> Value {
    json!({
        "operation": "create",
        "profileId": "writer",
        "packageRevision": registry_breg::postgres::test_package_digest(PACKAGE_REVISION),
        "schemaFingerprint": schema_fingerprint,
        "inputDigest": plan.input_digest,
        "inputLength": plan.input_length,
        "itemCount": plan.items.len(),
        "chunkCount": 1,
        "chunkAlgorithmVersion": "greedy-canonical-http-batch-v1"
    })
}

fn chunk_body(plan: &ImportPlan) -> Value {
    json!({
        "chunkIndex": 0,
        "items": plan.items,
        "digest": plan.digest,
        "prefixDigest": plan.prefix_digest
    })
}

fn hex_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

async fn post_json(
    app: &axum::Router,
    uri: &str,
    claims: &VerifiedRequestClaims,
    idempotency_key: Option<&str>,
    body: Value,
) -> axum::response::Response {
    let mut headers = vec![("content-type", "application/json")];
    if let Some(idempotency_key) = idempotency_key {
        headers.push(("idempotency-key", idempotency_key));
    }
    send(
        app,
        Method::POST,
        uri,
        Some(claims.clone()),
        &headers,
        serde_json::to_vec(&body).expect("request JSON serializes"),
    )
    .await
}

async fn send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    claims: Option<VerifiedRequestClaims>,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::from(body))
        .expect("request builds");
    for (name, value) in headers {
        request.headers_mut().append(
            HeaderName::from_bytes(name.as_bytes()).expect("header name is valid"),
            HeaderValue::from_str(value).expect("header value is valid"),
        );
    }
    if let Some(claims) = claims {
        request.extensions_mut().insert(claims);
    }
    let mut app = app.clone();
    app.call(request).await.expect("router responds")
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("response body reads");
    serde_json::from_slice(&bytes).expect("response is JSON")
}

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}
