// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, Response, StatusCode};
use postgres_harness::TestDatabase;
use registry_platform_audit::{AuditEnvelope, AuditProfile};
use registry_platform_canonical_json::canonicalize_json;
use registry_server::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedClaimValue,
    VerifiedRequestClaims,
};
use registry_server::compiler::{compile_project, CompileProfile};
use registry_server::contract::parse_project_json;
use registry_server::cursor::CursorCodec;
use registry_server::postgres::{
    initialize_registry_state_for_catalog_test, install_compiled_schema, ExpectedManagedCatalog,
    PostgresRecordReadService, PostgresRevisionReadService, RegistryLockKey,
    RegistryStateTestIdentity, RevisionReadFaultPoint,
};
use serde_json::{json, Value};
use tower::Service as _;
use uuid::Uuid;
use zeroize::Zeroizing;

const PACKAGE_ID: &str = "revision-http-registry";
const INSTANCE_ID: &str = "revision-http-instance";
const DATABASE_ID: &str = "revision-http-database";
const PACKAGE_REVISION: &str = "package-revision-http-1";
const PRINCIPAL_CANARY: &str = "principal-raw-must-not-enter-revision-audit";
const SECRET_CANARY: &str = "snapshot-secret-must-not-leave-projection";
const ACTOR_REFERENCE: &str =
    "hmac-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const REQUEST_REFERENCE: &str =
    "hmac-sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const RECORD_ID: &str = "00000000-0000-4000-8000-000000000001";
const HIDDEN_RECORD_ID: &str = "00000000-0000-4000-8000-000000000002";
const BOUNDED_RECORD_ID: &str = "00000000-0000-4000-8000-000000000003";
const MALFORMED_RECORD_ID: &str = "00000000-0000-4000-8000-000000000004";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_revision_http_is_bounded_authorized_atomic_and_audit_gated() {
    let database = TestDatabase::create(8).await;
    let (migration, migration_task) = database.connect_migration().await;
    let registry = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("migration installs the complete compiled PostgreSQL schema");
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
    .expect("migration initializes durable Registry identity");
    seed_revision_history(&migration).await;
    migration_task.abort();

    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool builds");
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock identity is bounded");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x5d; 32].into())
        .expect("test owns a strongly keyed audit profile");
    let app = revision_router(
        pool.clone(),
        Arc::clone(&registry),
        identity.clone(),
        lock_key,
        audit_profile.clone(),
        None,
    );

    let list = send(
        &app,
        &format!("/v1/records/widgets/{RECORD_ID}/revisions"),
        Some(history_claims("case-review", ["zone-a"])),
    )
    .await;
    assert_eq!(list.status(), StatusCode::OK);
    assert_eq!(list.headers()["cache-control"], "no-store");
    let list_bytes = body_bytes(list).await;
    let list = json_from_bytes(&list_bytes);
    let items = list["items"].as_array().expect("list returns items");
    assert_eq!(items.len(), 3);
    assert_eq!(
        items
            .iter()
            .map(|item| item["revision"].as_u64().expect("revision"))
            .collect::<Vec<_>>(),
        [3, 2, 1]
    );
    assert_eq!(items[0]["lifecycle"], "tombstoned");
    assert_eq!(items[0]["mutationKind"], "tombstone");
    assert_eq!(items[1]["mutationKind"], "patch");
    assert_eq!(items[2]["mutationKind"], "create");
    assert_eq!(items[0]["predecessorRevision"], 2);
    assert_eq!(items[2]["predecessorRevision"], Value::Null);
    assert_eq!(items[0]["actorReference"], ACTOR_REFERENCE);
    assert_eq!(items[0]["requestReference"], REQUEST_REFERENCE);
    assert_eq!(items[0]["data"], json!({"label": "tombstoned"}));
    assert!(!String::from_utf8(list_bytes)
        .expect("response is UTF-8")
        .contains(SECRET_CANARY));

    let tombstoned_detail = send(
        &app,
        &format!("/v1/records/widgets/{RECORD_ID}/revisions/3"),
        Some(history_claims("case-review", ["zone-a"])),
    )
    .await;
    assert_eq!(tombstoned_detail.status(), StatusCode::OK);
    let detail = body_json(tombstoned_detail).await;
    assert_eq!(detail["revision"], 3);
    assert_eq!(detail["lifecycle"], "tombstoned");

    let bounded = send(
        &app,
        &format!("/v1/records/widgets/{BOUNDED_RECORD_ID}/revisions"),
        Some(history_claims("case-review", ["zone-a"])),
    )
    .await;
    assert_eq!(bounded.status(), StatusCode::OK);
    let bounded = body_json(bounded).await;
    let bounded = bounded["items"].as_array().expect("bounded items");
    assert_eq!(bounded.len(), 100);
    assert_eq!(bounded.first().expect("newest")["revision"], 101);
    assert_eq!(bounded.last().expect("oldest retained")["revision"], 2);

    for uri in [
        format!("/v1/records/widgets/{HIDDEN_RECORD_ID}/revisions"),
        "/v1/records/widgets/00000000-0000-4000-8000-000000000099/revisions".to_owned(),
        format!("/v1/records/widgets/{RECORD_ID}/revisions/99"),
        "/v1/records/widgets/not-a-uuid/revisions".to_owned(),
        format!("/v1/records/widgets/{RECORD_ID}/revisions/01"),
        format!("/v1/records/widgets/{RECORD_ID}/revisions/0"),
    ] {
        let response = send(&app, &uri, Some(history_claims("case-review", ["zone-a"]))).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        assert_eq!(body_json(response).await["code"], "resource.not_found");
    }

    let anonymous = send(
        &app,
        &format!("/v1/records/widgets/{RECORD_ID}/revisions"),
        None,
    )
    .await;
    assert_eq!(anonymous.status(), StatusCode::NOT_FOUND);
    let wrong_purpose = send(
        &app,
        &format!("/v1/records/widgets/{RECORD_ID}/revisions?accessProfile=operator"),
        Some(history_claims("other-purpose", ["zone-a"])),
    )
    .await;
    assert_eq!(wrong_purpose.status(), StatusCode::NOT_FOUND);
    let unknown_profile = send(
        &app,
        &format!("/v1/records/widgets/{RECORD_ID}/revisions?accessProfile=unknown"),
        Some(history_claims("case-review", ["zone-a"])),
    )
    .await;
    assert_eq!(unknown_profile.status(), StatusCode::NOT_FOUND);
    let extra_query = send(
        &app,
        &format!("/v1/records/widgets/{RECORD_ID}/revisions?pageSize=1"),
        Some(history_claims("case-review", ["zone-a"])),
    )
    .await;
    assert_eq!(extra_query.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(extra_query).await["code"], "query.invalid");

    let malformed = send(
        &app,
        &format!("/v1/records/widgets/{MALFORMED_RECORD_ID}/revisions"),
        Some(history_claims("case-review", ["zone-a"])),
    )
    .await;
    assert_eq!(malformed.status(), StatusCode::SERVICE_UNAVAILABLE);
    let malformed = body_json(malformed).await;
    assert_eq!(malformed["code"], "source.unavailable");
    assert!(!malformed.to_string().contains("wrong-type"));
    assert!(!malformed
        .to_string()
        .contains("valid-row-must-not-be-released"));

    let before_fault = audit_count(&database).await;
    let faulting = revision_router(
        pool.clone(),
        Arc::clone(&registry),
        identity.clone(),
        lock_key,
        audit_profile.clone(),
        Some(RevisionReadFaultPoint::BeforeTerminalAudit),
    );
    let faulted = send(
        &faulting,
        &format!("/v1/records/widgets/{RECORD_ID}/revisions/2"),
        Some(history_claims("case-review", ["zone-a"])),
    )
    .await;
    assert_eq!(faulted.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_json(faulted).await["code"], "source.unavailable");
    assert_eq!(
        audit_count(&database).await,
        before_fault + 1,
        "terminal audit gate failure releases no held revision and leaves only the attempt"
    );

    let unkeyed = revision_router(
        pool,
        Arc::clone(&registry),
        identity,
        lock_key,
        AuditProfile::unkeyed_dev_only(),
        None,
    );
    let before_unkeyed = audit_count(&database).await;
    let refused_audit = send(
        &unkeyed,
        &format!("/v1/records/widgets/{RECORD_ID}/revisions/2"),
        Some(history_claims("case-review", ["zone-a"])),
    )
    .await;
    assert_eq!(refused_audit.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(audit_count(&database).await, before_unkeyed);

    assert_revision_audit_is_ordered_and_minimized(&database, &registry).await;
    database.cleanup().await;
}

#[allow(clippy::too_many_arguments)]
fn revision_router(
    pool: registry_server::postgres::RuntimePool,
    registry: Arc<registry_server::CompiledRegistry>,
    identity: registry_server::postgres::ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    audit_profile: AuditProfile,
    fault: Option<RevisionReadFaultPoint>,
) -> axum::Router {
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x3a; 32]), Duration::from_secs(300))
            .expect("cursor key is valid"),
    );
    let records = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        Arc::clone(&registry),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit_profile.clone(),
        Arc::clone(&cursors),
    ));
    let revisions = PostgresRevisionReadService::new(
        pool,
        Arc::clone(&registry),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit_profile,
    );
    let revisions = match fault {
        Some(fault) => revisions.with_fault_for_test(fault),
        None => revisions,
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
        .with_postgres_revisions(Arc::new(revisions)),
    ))
}

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

async fn send(
    app: &axum::Router,
    uri: &str,
    claims: Option<VerifiedRequestClaims>,
) -> Response<Body> {
    let mut request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .expect("request builds");
    if let Some(claims) = claims {
        request.extensions_mut().insert(claims);
    }
    let mut app = app.clone();
    app.call(request).await.expect("router returns a response")
}

fn history_claims<const N: usize>(
    purpose: &str,
    jurisdictions: [&str; N],
) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        PRINCIPAL_CANARY,
        BTreeSet::from(["history.read".to_owned()]),
        Some(purpose.to_owned()),
        BTreeMap::from([(
            "jurisdictions".to_owned(),
            VerifiedClaimValue::direct_string_set(jurisdictions)
                .expect("row authority is a verified direct string set"),
        )]),
    )
    .expect("claims are verified")
}

async fn seed_revision_history(migration: &tokio_postgres::Client) {
    for (revision, predecessor, lifecycle, mutation, label) in [
        (1_i64, None, "active", "create", "created"),
        (2, Some(1), "active", "patch", "patched"),
        (3, Some(2), "tombstoned", "tombstone", "tombstoned"),
    ] {
        insert_revision(
            migration,
            RECORD_ID,
            revision,
            predecessor,
            lifecycle,
            mutation,
            json!({
                "jurisdiction": "zone-a",
                "label": label,
                "secret": SECRET_CANARY,
            }),
        )
        .await;
    }
    insert_revision(
        migration,
        HIDDEN_RECORD_ID,
        1,
        None,
        "tombstoned",
        "tombstone",
        json!({
            "jurisdiction": "zone-b",
            "label": "hidden-row",
            "secret": SECRET_CANARY,
        }),
    )
    .await;
    for revision in 1_i64..=101 {
        insert_revision(
            migration,
            BOUNDED_RECORD_ID,
            revision,
            (revision > 1).then_some(revision - 1),
            "active",
            if revision == 1 { "create" } else { "patch" },
            json!({
                "jurisdiction": "zone-a",
                "label": format!("bounded-{revision}"),
                "secret": SECRET_CANARY,
            }),
        )
        .await;
    }
    insert_revision(
        migration,
        MALFORMED_RECORD_ID,
        1,
        None,
        "active",
        "create",
        json!({
            "jurisdiction": "zone-a",
            "label": "valid-row-must-not-be-released",
            "secret": SECRET_CANARY,
        }),
    )
    .await;
    insert_revision(
        migration,
        MALFORMED_RECORD_ID,
        2,
        Some(1),
        "active",
        "patch",
        json!({
            "jurisdiction": "zone-a",
            "label": 42,
            "secret": "wrong-type",
        }),
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn insert_revision(
    migration: &tokio_postgres::Client,
    record_id: &str,
    revision: i64,
    predecessor: Option<i64>,
    lifecycle: &str,
    mutation: &str,
    snapshot: Value,
) {
    let snapshot = canonicalize_json(&snapshot).expect("fixture snapshot canonicalizes");
    let record_id = Uuid::parse_str(record_id).expect("fixture UUID is valid");
    migration
        .execute(
            "INSERT INTO registry_internal.registry_revisions
                 (entity_id, record_id, record_reference, record_revision,
                  predecessor_revision, record_lifecycle, package_revision, operation_id,
                  mutation_kind, principal_reference, request_reference, snapshot)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            &[
                &"widget",
                &record_id,
                &"hmac-sha256:record-reference",
                &revision,
                &predecessor,
                &lifecycle,
                &PACKAGE_REVISION,
                &format!("records.widget.{mutation}"),
                &mutation,
                &ACTOR_REFERENCE,
                &REQUEST_REFERENCE,
                &snapshot,
            ],
        )
        .await
        .expect("migration seeds one canonical revision row");
}

async fn audit_count(database: &TestDatabase) -> i64 {
    database
        .admin
        .query_one("SELECT count(*) FROM registry_internal.registry_audit", &[])
        .await
        .expect("administrator inspects audit count")
        .get(0)
}

async fn assert_revision_audit_is_ordered_and_minimized(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
) {
    let rows = database
        .admin
        .query("SELECT envelope FROM registry_internal.registry_audit", &[])
        .await
        .expect("administrator inspects audit envelopes");
    let mut envelopes = rows
        .iter()
        .map(|row| {
            serde_json::from_slice::<AuditEnvelope>(&row.get::<_, Vec<u8>>(0))
                .expect("audit envelope is canonical platform JSON")
        })
        .collect::<Vec<_>>();
    let mut records = Vec::with_capacity(envelopes.len());
    let mut predecessor = None;
    while !envelopes.is_empty() {
        let index = envelopes
            .iter()
            .position(|envelope| envelope.prev_hash == predecessor)
            .expect("audit chain has one next record");
        let envelope = envelopes.remove(index);
        predecessor = Some(envelope.record_hash);
        records.push(envelope.record);
    }
    assert!(records.windows(2).any(|window| {
        window[0]["phase"] == "attempt"
            && window[1]["phase"] == "terminal"
            && window[1]["outcome"] == "returned"
    }));
    assert_eq!(records.last().expect("fault attempt")["phase"], "attempt");
    assert!(records.iter().any(|record| record["phase"] == "refusal"));
    assert!(records.iter().any(|record| {
        record["phase"] == "terminal"
            && record["outcome"] == "returned"
            && record["resultCount"] == 100
    }));
    for record in &records {
        assert!(record.get("recordRevision").is_none());
    }
    let audit_text = records
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        PRINCIPAL_CANARY,
        SECRET_CANARY,
        ACTOR_REFERENCE,
        REQUEST_REFERENCE,
        RECORD_ID,
        HIDDEN_RECORD_ID,
        BOUNDED_RECORD_ID,
        MALFORMED_RECORD_ID,
        "zone-a",
        "zone-b",
        "tombstoned",
        "wrong-type",
        "SELECT",
        "registry_revisions",
        &registry.entities()["widget"].physical_table,
    ] {
        assert!(!audit_text.contains(forbidden), "audit leaked {forbidden}");
    }
    assert!(audit_text.contains("principalReference"));
    assert!(audit_text.contains("recordReference"));
    assert!(audit_text.contains("fieldSetReference"));
    assert!(audit_text.contains("rowBoundaryReference"));
}

async fn body_json(response: Response<Body>) -> Value {
    json_from_bytes(&body_bytes(response).await)
}

async fn body_bytes(response: Response<Body>) -> Vec<u8> {
    to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("response body is bounded")
        .to_vec()
}

fn json_from_bytes(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("response is JSON")
}

fn compiled_registry() -> registry_server::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"revision-http-registry","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"widget","route":"widgets","mutationMode":"mutable","tombstone":true,
            "classification":"restricted",
            "fields":[
              {"id":"jurisdiction","type":"string","required":true,"maxLength":32,"classification":"internal"},
              {"id":"label","type":"string","required":true,"maxLength":100,"classification":"internal"},
              {"id":"secret","type":"string","required":true,"maxLength":100,"classification":"restricted"}
            ]
          }],
          "accessProfiles":[{
            "id":"operator","default":true,"principalClaim":"registry_principal",
            "requiredScopes":["history.read"],"requiredPurposes":["case-review"],
            "grants":[{
              "entity":"widget",
              "operations":["revisions"],"revisionAccess":true,
              "readableFields":["label"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdictions","operator":"in"}]
            }]
          }]
        }"#,
    )
    .expect("revision HTTP fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("revision HTTP fixture compiles")
}
