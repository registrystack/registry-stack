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
use tower::Service as _;
use uuid::Uuid;
use zeroize::Zeroizing;

const PRINCIPAL: &str = "batch-principal-must-not-enter-audit";
const RECORD_CANARY: &str = "batch-record-value-must-not-enter-audit";
const REASON_CANARY: &str = "effective-date-corrected-batch-canary";
const SOURCE_CANARY: &str = "case-document:batch-source-canary";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_batch_is_bounded_authorized_atomic_and_exactly_replayable() {
    let database = TestDatabase::create(8).await;
    let (migration, migration_task) = database.connect_migration().await;
    let registry = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("migration installs the compiler-owned schema");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: "batch-registry",
            environment: "local",
            instance_id: "batch-instance",
            database_id: "batch-database",
            package_revision: "package-batch-1",
            package_sequence: 1,
        },
    )
    .await
    .expect("active package identity is initialized");
    migration_task.abort();

    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool builds");
    let lock_key = RegistryLockKey::derive("batch-registry").expect("lock key is valid");
    let profile = AuditProfile::production_from_secret_bytes(vec![0x6b; 32].into())
        .expect("test audit profile is keyed");
    let app = mutation_router(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        profile.clone(),
        None,
    );
    let authorized_claims = claims(PRINCIPAL, "case-management", "zone-a");
    let table = &registry.entities()["widget"].physical_table;

    let openapi = send(
        &app,
        Method::GET,
        "/openapi.json",
        Some(authorized_claims.clone()),
        &[],
        vec![],
    )
    .await;
    assert_eq!(openapi.status(), StatusCode::OK);
    let openapi = body_json(openapi).await;
    assert_eq!(
        openapi["paths"]["/v1/records/widgets:batch"]["post"]["x-registry-maximumItems"],
        3
    );
    assert!(openapi["paths"]["/v1/records/widgets:batch"]["post"]["requestBody"].is_object());

    let seed = send_json(
        &app,
        "/v1/records/widgets",
        Some(authorized_claims.clone()),
        "seed-key",
        json!({"data": {
            "jurisdiction": "zone-a", "label": RECORD_CANARY, "secret": "hidden", "quantity": 1
        }}),
    )
    .await;
    assert_eq!(seed.status(), StatusCode::CREATED);
    let seed_etag = header(&seed, "etag");
    let seed_body = body_json(seed).await;
    let seed_id = seed_body["data"]["recordIdentifier"]
        .as_str()
        .expect("seed id")
        .to_owned();

    let batch_body = json!({
        "changeContext": {
            "kind": "correction",
            "reasonCode": REASON_CANARY,
            "sourceReferences": [SOURCE_CANARY]
        },
        "items": [
            {"operation":"create", "data": {
                "jurisdiction":"zone-a", "label":"batch-created", "secret":"not-disclosed", "quantity":2
            }},
            {"operation":"patch", "recordId":seed_id, "ifMatch":seed_etag, "patch":[
                {"op":"replace", "path":"/data/label", "value":"batch-patched"}
            ]}
        ]
    });
    let before = effect_counts(&database, table).await;
    let first = send_json(
        &app,
        "/v1/records/widgets:batch",
        Some(authorized_claims.clone()),
        "batch-key",
        batch_body.clone(),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    let first_bytes = response_bytes(first).await;
    let first_json: Value = serde_json::from_slice(&first_bytes).expect("batch response JSON");
    assert_snapshot_reference(&first_json["snapshot"]);
    assert!(first_json.get("changeContext").is_none());
    let items = first_json["results"]
        .as_array()
        .expect("ordered batch results");
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["operation"], "create");
    assert_eq!(items[0]["data"]["label"], "batch-created");
    assert_eq!(items[0]["revision"], 1);
    assert_eq!(items[1]["id"], seed_id);
    assert_eq!(items[1]["operation"], "patch");
    assert_eq!(items[1]["data"]["label"], "batch-patched");
    assert_eq!(items[1]["revision"], 2);
    assert!(items
        .iter()
        .all(|item| item["data"].get("secret").is_none()));
    let after = effect_counts(&database, table).await;
    assert_eq!(after.current, before.current + 1);
    assert_eq!(after.revisions, before.revisions + 2);
    assert_eq!(after.outbox, before.outbox + 2);
    assert_eq!(after.idempotency, before.idempotency + 1);
    assert_eq!(after.commits, before.commits + 1);
    assert_eq!(after.commit_members, before.commit_members + 2);
    let context = database
        .admin
        .query_one(
            "SELECT convert_from(change_context, 'UTF8')
               FROM registry_internal.registry_revision_commits
              WHERE commit_position = 2",
            &[],
        )
        .await
        .expect("administrator inspects stored restricted change context")
        .get::<_, String>(0);
    assert!(context.contains(REASON_CANARY));
    assert!(context.contains(SOURCE_CANARY));

    let replay = send_json(
        &app,
        "/v1/records/widgets:batch",
        Some(authorized_claims.clone()),
        "batch-key",
        batch_body.clone(),
    )
    .await;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(replay).await, first_bytes);
    assert_eq!(
        effect_counts(&database, table).await.without_audit(),
        after.without_audit()
    );

    let concurrent_before = effect_counts(&database, table).await;
    let left = send_json(
        &app,
        "/v1/records/widgets:batch",
        Some(authorized_claims.clone()),
        "batch-key",
        batch_body.clone(),
    );
    let right = send_json(
        &app,
        "/v1/records/widgets:batch",
        Some(authorized_claims.clone()),
        "batch-key",
        batch_body.clone(),
    );
    let (left, right) = tokio::join!(left, right);
    assert_eq!(left.status(), StatusCode::OK);
    assert_eq!(right.status(), StatusCode::OK);
    assert_eq!(response_bytes(left).await, first_bytes);
    assert_eq!(response_bytes(right).await, first_bytes);
    assert_eq!(
        effect_counts(&database, table).await.without_audit(),
        concurrent_before.without_audit(),
        "concurrent exact replay cannot repeat any mutation effect"
    );

    let changed_order = json!({
        "changeContext": batch_body["changeContext"].clone(),
        "items": [batch_body["items"][1].clone(), batch_body["items"][0].clone()]
    });
    let conflict = send_json(
        &app,
        "/v1/records/widgets:batch",
        Some(authorized_claims.clone()),
        "batch-key",
        changed_order,
    )
    .await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(conflict).await["code"], "idempotency.conflict");

    let changed_context = json!({
        "changeContext": {
            "kind": "correction",
            "reasonCode": "different-reason"
        },
        "items": batch_body["items"].clone()
    });
    let conflict = send_json(
        &app,
        "/v1/records/widgets:batch",
        Some(authorized_claims.clone()),
        "batch-key",
        changed_context,
    )
    .await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(conflict).await["code"], "idempotency.conflict");

    for (label, uri, changed_claims, changed_body) in [
        (
            "etag",
            "/v1/records/widgets:batch",
            authorized_claims.clone(),
            json!({"items":[
                batch_body["items"][0].clone(),
                {"operation":"patch", "recordId":seed_id, "ifMatch":"\"breg-different\"", "patch":[
                    {"op":"replace", "path":"/data/label", "value":"batch-patched"}
                ]}
            ]}),
        ),
        (
            "principal",
            "/v1/records/widgets:batch",
            claims("different-principal", "case-management", "zone-a"),
            batch_body.clone(),
        ),
        (
            "purpose",
            "/v1/records/widgets:batch",
            claims(PRINCIPAL, "case-review", "zone-a"),
            batch_body.clone(),
        ),
        (
            "boundary",
            "/v1/records/widgets:batch",
            claims(PRINCIPAL, "case-management", "zone-b"),
            batch_body.clone(),
        ),
        (
            "profile-and-projection",
            "/v1/records/widgets:batch?accessProfile=operator-minimal",
            authorized_claims.clone(),
            batch_body.clone(),
        ),
    ] {
        let response = send_json(&app, uri, Some(changed_claims), "batch-key", changed_body).await;
        assert_eq!(response.status(), StatusCode::CONFLICT, "{label}");
        assert_eq!(body_json(response).await["code"], "idempotency.conflict");
    }

    let mut changed_identity = identity.clone();
    changed_identity.package_revision = "package-batch-2".to_owned();
    let changed_package_app = mutation_router(
        pool.clone(),
        registry.clone(),
        changed_identity,
        lock_key,
        profile.clone(),
        None,
    );
    let changed_package = send_json(
        &changed_package_app,
        "/v1/records/widgets:batch",
        Some(authorized_claims.clone()),
        "batch-key",
        batch_body.clone(),
    )
    .await;
    assert_eq!(changed_package.status(), StatusCode::SERVICE_UNAVAILABLE);

    let before_atomic = effect_counts(&database, table).await;
    let invalid_later = json!({"items": [
        {"operation":"create", "data": {
            "jurisdiction":"zone-a", "label":"must-roll-back", "secret":"x", "quantity":4
        }},
        {"operation":"patch", "recordId":seed_id, "ifMatch":"\"breg-stale\"", "patch":[
            {"op":"replace", "path":"/data/label", "value":"never"}
        ]}
    ]});
    let failed = send_json(
        &app,
        "/v1/records/widgets:batch",
        Some(authorized_claims.clone()),
        "rollback-key",
        invalid_later,
    )
    .await;
    assert_eq!(failed.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        effect_counts(&database, table).await.without_audit(),
        before_atomic.without_audit(),
        "a later invalid item cannot commit a valid prefix"
    );

    for (key, body) in [
        ("empty", json!({"items":[]})),
        (
            "too-many",
            json!({"items":[
                {"operation":"create","data":{}}, {"operation":"create","data":{}},
                {"operation":"create","data":{}}, {"operation":"create","data":{}}
            ]}),
        ),
        (
            "extra-root",
            json!({"items":[{"operation":"create","data":{}}],"extra":true}),
        ),
        (
            "client-id",
            json!({"items":[{"operation":"create","recordId":seed_id,"data":{}}]}),
        ),
        (
            "tombstone",
            json!({"items":[{"operation":"tombstone","recordId":seed_id}]}),
        ),
        (
            "invalid-uuid",
            json!({"items":[{"operation":"patch","recordId":"NOT-A-UUID","ifMatch":"\"breg-etag\"","patch":[
                {"op":"replace","path":"/data/label","value":"never"}
            ]}]}),
        ),
        (
            "unwritable-field",
            json!({"items":[{"operation":"create","data":{
                "jurisdiction":"zone-a","label":"never-locked","locked":"forbidden","quantity":1
            }}]}),
        ),
    ] {
        let refused = send_json(
            &app,
            "/v1/records/widgets:batch",
            Some(authorized_claims.clone()),
            key,
            body,
        )
        .await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "{key}");
    }
    let oversized = json!({"items":[{"operation":"create","data":{
        "jurisdiction":"zone-a","label":"x","secret":"z".repeat(9000),"quantity":1
    }}]});
    let refused = send_json(
        &app,
        "/v1/records/widgets:batch",
        Some(authorized_claims.clone()),
        "oversized",
        oversized,
    )
    .await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);

    let top_level_match = send(
        &app,
        Method::POST,
        "/v1/records/widgets:batch",
        Some(authorized_claims.clone()),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", "top-level-match"),
            ("if-match", "\"breg-forbidden\""),
        ],
        serde_json::to_vec(&json!({"items":[{"operation":"create","data":{}}]}))
            .expect("request JSON"),
    )
    .await;
    assert_eq!(top_level_match.status(), StatusCode::BAD_REQUEST);
    let wrong_media = send(
        &app,
        Method::POST,
        "/v1/records/widgets:batch",
        Some(authorized_claims.clone()),
        &[
            ("content-type", "application/json-patch+json"),
            ("idempotency-key", "wrong-media"),
        ],
        br#"{"items":[]}"#.to_vec(),
    )
    .await;
    assert_eq!(wrong_media.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let before_hidden_unique = effect_counts(&database, table).await;
    let hidden_unique = send_json(
        &app,
        "/v1/records/widgets:batch",
        Some(authorized_claims.clone()),
        "hidden-unique",
        json!({"items":[{"operation":"create","data":{
            "jurisdiction":"zone-a","label":"batch-created","secret":"different","quantity":7
        }}]}),
    )
    .await;
    assert_eq!(hidden_unique.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(hidden_unique).await["code"], "mutation.conflict");
    assert_eq!(
        effect_counts(&database, table).await.without_audit(),
        before_hidden_unique.without_audit()
    );

    let patch_without_grant = send_json(
        &app,
        "/v1/records/widgets:batch?accessProfile=batch-creator",
        Some(authorized_claims.clone()),
        "create-only-profile",
        json!({"items":[{"operation":"patch","recordId":seed_id,"ifMatch":"\"breg-stale\"","patch":[
            {"op":"replace","path":"/data/label","value":"never"}
        ]}]}),
    )
    .await;
    assert_eq!(patch_without_grant.status(), StatusCode::BAD_REQUEST);
    let wrong_purpose = send_json(
        &app,
        "/v1/records/widgets:batch",
        Some(claims(PRINCIPAL, "wrong-purpose", "zone-a")),
        "purpose",
        json!({"items":[{"operation":"create","data":{
            "jurisdiction":"zone-a","label":"never","secret":"x","quantity":1
        }}]}),
    )
    .await;
    assert_eq!(wrong_purpose.status(), StatusCode::NOT_FOUND);
    let wrong_boundary = send_json(
        &app,
        "/v1/records/widgets:batch",
        Some(claims(PRINCIPAL, "case-management", "zone-b")),
        "boundary",
        json!({"items":[{"operation":"create","data":{
            "jurisdiction":"zone-a","label":"never-boundary","secret":"x","quantity":1
        }}]}),
    )
    .await;
    assert_eq!(wrong_boundary.status(), StatusCode::SERVICE_UNAVAILABLE);
    let extra_query = send_json(
        &app,
        "/v1/records/widgets:batch?pageSize=1",
        Some(authorized_claims.clone()),
        "query",
        json!({"items":[{"operation":"create","data":{}}]}),
    )
    .await;
    assert_eq!(extra_query.status(), StatusCode::NOT_FOUND);

    let fault_body = json!({"items":[
        {"operation":"create","data":{
            "jurisdiction":"zone-a","label":"fault-prefix","secret":"x","quantity":9
        }},
        {"operation":"create","data":{
            "jurisdiction":"zone-a","label":"fault-second","secret":"x","quantity":10
        }}
    ]});
    for (index, fault) in [
        MutationFaultPoint::BeforeCurrentRow,
        MutationFaultPoint::BeforeRevision,
        MutationFaultPoint::BeforeOutbox,
        MutationFaultPoint::AfterFirstBatchItem,
        MutationFaultPoint::BeforeTerminalAudit,
        MutationFaultPoint::BeforeIdempotency,
        MutationFaultPoint::BeforeCommit,
    ]
    .into_iter()
    .enumerate()
    {
        let fault_app = mutation_router(
            pool.clone(),
            registry.clone(),
            identity.clone(),
            lock_key,
            profile.clone(),
            Some(fault),
        );
        let before_fault = effect_counts(&database, table).await;
        let response = send_json(
            &fault_app,
            "/v1/records/widgets:batch",
            Some(authorized_claims.clone()),
            &format!("fault-{index}"),
            fault_body.clone(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            effect_counts(&database, table).await.without_audit(),
            before_fault.without_audit(),
            "fault {fault:?} rolls back every batch effect"
        );
    }

    let audit_rows = database
        .admin
        .query(
            "SELECT convert_from(envelope, 'UTF8') FROM registry_internal.registry_audit",
            &[],
        )
        .await
        .expect("administrator inspects minimized audit");
    let audit_text = audit_rows
        .iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(audit_text.contains("\"resultCount\":2"));
    assert!(!audit_text.contains(PRINCIPAL));
    assert!(!audit_text.contains(RECORD_CANARY));
    assert!(!audit_text.contains(REASON_CANARY));
    assert!(!audit_text.contains(SOURCE_CANARY));
    assert!(!audit_text.contains(&seed_id));
    assert!(!audit_text.contains("batch-created"));
    assert!(!audit_text.contains("registry_data"));
    let committed_terminals: i64 = database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_audit
             WHERE convert_from(envelope, 'UTF8') LIKE '%\"operationId\":\"records.widget.batch\"%'
               AND convert_from(envelope, 'UTF8') LIKE '%\"phase\":\"terminal\"%'
               AND convert_from(envelope, 'UTF8') LIKE '%\"outcome\":\"committed\"%'",
            &[],
        )
        .await
        .expect("administrator inspects batch terminal audit count")
        .get(0);
    assert_eq!(committed_terminals, 1);

    database.cleanup().await;
}

fn compiled_registry() -> registry_breg::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"batch-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"widget","primaryDataset":"test-dataset","route":"widgets","mutationMode":"mutable","classification":"public",
            "batch":{"maximumItems":3,"maximumBytes":8192},
            "constraints":[{"kind":"unique","fields":["label"]}],
            "fields":[
              {"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"public"},
              {"id":"label","type":"string","maxLength":128,"required":true,"classification":"public"},
              {"id":"locked","type":"string","maxLength":128,"classification":"internal"},
              {"id":"secret","type":"string","maxLength":128,"classification":"restricted"},
              {"id":"quantity","type":"int64","required":true,"classification":"public"}
            ],
            "events":[
              {"id":"widget-created","trigger":"created","projection":["label"]},
              {"id":"widget-patched","trigger":"patched","projection":["label","quantity"]}
            ]
          }],
          "accessProfiles":[{
            "id":"operator","default":true,"principalClaim":"registry_principal",
            "requiredPurposes":["case-management","case-review"],
            "grants":[{
              "entity":"widget","operations":["create","get","patch","batch"],
              "readableFields":["jurisdiction","label","locked","quantity"],
              "writableFields":["jurisdiction","label","secret","quantity"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }]
          },{
            "id":"batch-creator","principalClaim":"registry_principal",
            "requiredPurposes":["case-management"],
            "grants":[{
              "entity":"widget","operations":["create","batch"],
              "readableFields":["jurisdiction","label","locked","quantity"],
              "writableFields":["jurisdiction","label","secret","quantity"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }]
          },{
            "id":"operator-minimal","principalClaim":"registry_principal",
            "requiredPurposes":["case-management"],
            "grants":[{
              "entity":"widget","operations":["create","patch","batch"],
              "readableFields":["label"],
              "writableFields":["jurisdiction","label","secret","quantity"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }]
          }]
        }"#,
    )
    .expect("batch fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("batch fixture compiles to trusted inventories")
}

fn mutation_router(
    pool: registry_breg::postgres::RuntimePool,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    profile: AuditProfile,
    fault: Option<MutationFaultPoint>,
) -> axum::Router {
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x4f; 32]), Duration::from_secs(300))
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
    let mutations = match fault {
        Some(fault) => mutations.with_fault_for_test(fault),
        None => mutations,
    };
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

fn claims(principal: &str, purpose: &str, jurisdiction: &str) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        principal,
        BTreeSet::new(),
        Some(purpose.to_owned()),
        BTreeMap::from([(
            "jurisdiction".to_owned(),
            VerifiedClaimValue::direct_string(jurisdiction).expect("direct claim"),
        )]),
    )
    .expect("verified claims are bounded")
}

async fn send_json(
    app: &axum::Router,
    uri: &str,
    claims: Option<VerifiedRequestClaims>,
    key: &str,
    body: Value,
) -> axum::response::Response {
    send(
        app,
        Method::POST,
        uri,
        claims,
        &[
            ("content-type", "application/json"),
            ("idempotency-key", key),
        ],
        serde_json::to_vec(&body).expect("request JSON"),
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
        .expect("request");
    for (name, value) in headers {
        request.headers_mut().append(
            HeaderName::from_bytes(name.as_bytes()).expect("header name"),
            HeaderValue::from_str(value).expect("header value"),
        );
    }
    if let Some(claims) = claims {
        request.extensions_mut().insert(claims);
    }
    let mut app = app.clone();
    app.call(request).await.expect("response")
}

fn header(response: &axum::response::Response, name: &str) -> String {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .expect("response header")
        .to_owned()
}

async fn body_json(response: axum::response::Response) -> Value {
    serde_json::from_slice(&response_bytes(response).await).expect("JSON response")
}

async fn response_bytes(response: axum::response::Response) -> Vec<u8> {
    to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("response body")
        .to_vec()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EffectCounts {
    current: i64,
    revisions: i64,
    outbox: i64,
    audit: i64,
    idempotency: i64,
    commits: i64,
    commit_members: i64,
}

impl EffectCounts {
    fn without_audit(self) -> (i64, i64, i64, i64, i64, i64) {
        (
            self.current,
            self.revisions,
            self.outbox,
            self.idempotency,
            self.commits,
            self.commit_members,
        )
    }
}

async fn effect_counts(database: &TestDatabase, table: &str) -> EffectCounts {
    let row = database
        .admin
        .query_one(
            &format!(
                "SELECT
                   (SELECT count(*) FROM registry_data.\"{table}\"),
                   (SELECT count(*) FROM registry_internal.registry_revisions),
                   (SELECT count(*) FROM registry_internal.registry_outbox),
                   (SELECT count(*) FROM registry_internal.registry_audit),
                   (SELECT count(*) FROM registry_internal.registry_idempotency),
                   (SELECT count(*) FROM registry_internal.registry_revision_commits),
                   (SELECT count(*) FROM registry_internal.registry_revision_commit_members)"
            ),
            &[],
        )
        .await
        .expect("administrator inspects batch effects");
    EffectCounts {
        current: row.get(0),
        revisions: row.get(1),
        outbox: row.get(2),
        audit: row.get(3),
        idempotency: row.get(4),
        commits: row.get(5),
        commit_members: row.get(6),
    }
}

fn assert_snapshot_reference(value: &Value) {
    let snapshot = value.as_str().expect("response carries snapshot reference");
    assert_eq!(snapshot.len(), 40);
    assert!(snapshot.starts_with("breg1_"));
    Uuid::parse_str(&snapshot[4..]).expect("snapshot suffix is a UUID");
}
