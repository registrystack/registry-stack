// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;
#[path = "support/action_requirements.rs"]
mod support;

use axum::{
    body::{to_bytes, Body},
    http::{Method, Request, StatusCode},
};
use postgres_harness::TestDatabase;
use registry_breg::{
    api::{
        router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture,
        VerifiedClaimValue, VerifiedRequestClaims,
    },
    compiler::{compile_project, CompileProfile},
    contract::parse_project_json,
    cursor::CursorCodec,
    mutation::MutationFaultPoint,
    postgres::{
        initialize_compiled_registry_state_for_test, install_compiled_schema,
        ExpectedRegistryIdentity, PostgresRecordMutationService, PostgresRecordReadService,
        RegistryLockKey, RegistryStateTestIdentity,
    },
};
use registry_platform_audit::AuditProfile;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;
use tower::Service as _;
use uuid::Uuid;
use zeroize::Zeroizing;

const ID: &str = "00000000-0000-4000-8000-000000000101";
const FOREIGN_ID: &str = "00000000-0000-4000-8000-000000000202";
const TOMBSTONED_ID: &str = "00000000-0000-4000-8000-000000000303";
const OTHER_ID: &str = "00000000-0000-4000-8000-000000000404";
const PACKAGE: &str = "action-requirements";

async fn setup() -> (
    TestDatabase,
    Arc<registry_breg::CompiledRegistry>,
    ExpectedRegistryIdentity,
) {
    setup_with_project(support::project()).await
}

async fn setup_with_project(
    source: Value,
) -> (
    TestDatabase,
    Arc<registry_breg::CompiledRegistry>,
    ExpectedRegistryIdentity,
) {
    setup_in(TestDatabase::create(8).await, source).await
}

async fn setup_in(
    database: TestDatabase,
    source: Value,
) -> (
    TestDatabase,
    Arc<registry_breg::CompiledRegistry>,
    ExpectedRegistryIdentity,
) {
    let registry = Arc::new(
        compile_project(
            &parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap(),
            &[],
            CompileProfile::Authoring,
        )
        .unwrap(),
    );
    let (migration, task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .unwrap();
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE,
            database_id: "requirements-database",
            label: "requirements-1",
        },
    )
    .await
    .unwrap();
    drop(migration);
    task.abort();
    let parent = &registry.entities()["parent"];
    database.admin.execute(&format!("INSERT INTO registry_data.{} (record_id, record_revision, record_lifecycle, active_package_revision, {}, {}) VALUES ($1, 1, 'active', $2, 'active', 'zone-a')", q(&parent.physical_table), q(&parent.fields["status"].physical_name), q(&parent.fields["zone"].physical_name)), &[&Uuid::parse_str(ID).unwrap(), &identity.activation_id]).await.unwrap();
    (database, registry, identity)
}

struct Ready;
impl ReadinessProbe for Ready {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

fn app(
    database: &TestDatabase,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: ExpectedRegistryIdentity,
    fault: Option<MutationFaultPoint>,
) -> axum::Router {
    app_with_audit(database, registry, identity, fault).0
}

fn app_with_audit(
    database: &TestDatabase,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: ExpectedRegistryIdentity,
    fault: Option<MutationFaultPoint>,
) -> (
    axum::Router,
    registry_breg::audit::test_support::AuditCapture,
) {
    let pool = database.runtime_config.build_pool().unwrap();
    let (audit, capture) = registry_breg::audit::test_support::capturing(
        AuditProfile::production_from_secret_bytes(vec![0x42; 32].into()).unwrap(),
    );
    let lock = RegistryLockKey::derive(PACKAGE).unwrap();
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x63; 32]), Duration::from_secs(300)).unwrap(),
    );
    let reads = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock,
        Duration::from_secs(5),
        audit.clone(),
        cursors.clone(),
    ));
    let read_identity = ReadRuntimeIdentity {
        package_revision: identity.activation_id.clone(),
        schema_fingerprint: identity.schema_fingerprint.clone(),
    };
    let mutations = PostgresRecordMutationService::new(
        pool,
        registry.clone(),
        identity,
        "requirements-instance",
        lock,
        Duration::from_secs(5),
        audit,
    );
    let mutations = match fault {
        Some(fault) => mutations.with_fault_for_test(fault),
        None => mutations,
    };
    let app = router(Arc::new(
        HttpService::new(registry, read_identity, reads, Arc::new(Ready), cursors)
            .with_postgres_mutations(Arc::new(mutations)),
    ));
    (app, capture)
}

async fn invoke(app: axum::Router, key: &str, parent: &str) -> (StatusCode, Value) {
    invoke_with_input(app, key, json!({"parentId": parent, "label": "synthetic"})).await
}

async fn invoke_with_input(mut app: axum::Router, key: &str, input: Value) -> (StatusCode, Value) {
    let claims = registrar_claims();
    let mut request = Request::builder()
        .method("POST")
        .uri("/v1/actions/register-child")
        .header("content-type", "application/json")
        .header("idempotency-key", key)
        .body(Body::from(
            serde_json::to_vec(&json!({"input": input})).unwrap(),
        ))
        .unwrap();
    request.extensions_mut().insert(claims);
    let response = app.call(request).await.unwrap();
    let status = response.status();
    let body =
        serde_json::from_slice(&to_bytes(response.into_body(), 128 * 1024).await.unwrap()).unwrap();
    (status, body)
}

fn registrar_claims() -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        "registrar",
        BTreeSet::from([
            "registry:register".to_owned(),
            "registry:parent:process".to_owned(),
        ]),
        None,
        BTreeMap::from([(
            "zone".to_owned(),
            VerifiedClaimValue::direct_string("zone-a").unwrap(),
        )]),
    )
    .unwrap()
}

async fn post_action(
    mut app: axum::Router,
    path: &str,
    body: Value,
    idempotency_key: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    if let Some(key) = idempotency_key {
        request
            .headers_mut()
            .insert("idempotency-key", key.parse().unwrap());
    }
    request.extensions_mut().insert(registrar_claims());
    let response = app.call(request).await.unwrap();
    let status = response.status();
    let body =
        serde_json::from_slice(&to_bytes(response.into_body(), 128 * 1024).await.unwrap()).unwrap();
    (status, body)
}

async fn availability(app: axum::Router, input: Value) -> (StatusCode, Value) {
    post_action(
        app,
        "/v1/actions/register-child/availability",
        json!({"targetInput":"parentId", "input":input}),
        None,
    )
    .await
}

async fn get_parent(mut app: axum::Router, id: &str) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(Method::GET)
        .uri(format!("/v1/records/parents/{id}?accessProfile=registrar"))
        .body(Body::empty())
        .unwrap();
    request.extensions_mut().insert(registrar_claims());
    let response = app.call(request).await.unwrap();
    let status = response.status();
    let body =
        serde_json::from_slice(&to_bytes(response.into_body(), 128 * 1024).await.unwrap()).unwrap();
    (status, body)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn action_input_equality_is_authorized_atomic_and_replayed_from_the_receipt() {
    let mut source = support::project();
    source["actions"][0]["inputs"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"expected-status", "apiName":"expectedStatus", "type":"vocabulary-code",
            "vocabulary":"status", "values":["active","inactive"], "required":true,
            "classification":"restricted"
        }));
    source["actions"][0]["commitGuards"]["targets"][0]
        .as_object_mut()
        .unwrap()
        .remove("equals");
    source["actions"][0]["commitGuards"]["targets"][0]["equalsFromInput"] =
        json!("expected-status");
    let (database, registry, identity) = setup_with_project(source).await;
    let app = app(&database, registry.clone(), identity, None);
    let accepted = invoke_with_input(
        app.clone(),
        "input-equality",
        json!({"parentId":ID, "label":"synthetic", "expectedStatus":"active"}),
    )
    .await;
    assert_eq!(accepted.0, StatusCode::OK, "{}", accepted.1);
    let after = counts(&database, &registry).await;
    let replay = invoke_with_input(
        app.clone(),
        "input-equality",
        json!({"parentId":ID, "label":"synthetic", "expectedStatus":"active"}),
    )
    .await;
    assert_eq!(accepted, replay);
    assert_eq!(after, counts(&database, &registry).await);
    let refused = invoke_with_input(
        app,
        "input-mismatch",
        json!({"parentId":ID, "label":"synthetic", "expectedStatus":"inactive"}),
    )
    .await;
    assert_eq!(refused.0, StatusCode::PRECONDITION_FAILED, "{}", refused.1);
    assert_eq!(after, counts(&database, &registry).await);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ordered_input_guards_compare_dates_and_instants_against_stored_fields() {
    let mut source = with_parent_get(
        support::project(),
        &["status", "zone", "opened-on", "opened-at", "expires-on"],
    );
    let fields = source["recordTypes"][0]["fields"].as_array_mut().unwrap();
    for (id, kind) in [
        ("opened-on", "date"),
        ("opened-at", "timestamp"),
        ("expires-on", "date"),
    ] {
        fields.push(json!({"id": id, "type": kind, "classification": "restricted"}));
    }
    let inputs = source["actions"][0]["inputs"].as_array_mut().unwrap();
    for (id, api_name, kind) in [
        ("assigned-on", "assignedOn", "date"),
        ("assigned-at", "assignedAt", "timestamp"),
    ] {
        inputs.push(json!({
            "id": id, "apiName": api_name, "type": kind, "required": true,
            "classification": "restricted"
        }));
    }
    source["actions"][0]["commitGuards"]["targets"] = json!([
        {"input": "parent", "field": "opened-on", "atMostFromInput": "assigned-on"},
        {"input": "parent", "field": "opened-at", "atMostFromInput": "assigned-at"},
        {"input": "parent", "field": "expires-on", "atLeastFromInput": "assigned-on"}
    ]);
    let (database, registry, identity) = setup_with_project(source).await;
    let parent = &registry.entities()["parent"];
    database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.{} SET {} = DATE '2026-10-30', {} = TIMESTAMPTZ '2026-10-30 10:00:00+00', {} = DATE '2026-11-30' WHERE record_id = $1",
                q(&parent.physical_table),
                q(&parent.fields["opened-on"].physical_name),
                q(&parent.fields["opened-at"].physical_name),
                q(&parent.fields["expires-on"].physical_name),
            ),
            &[&Uuid::parse_str(ID).unwrap()],
        )
        .await
        .unwrap();
    let app = app(&database, registry.clone(), identity, None);
    let body = |assigned_on: &str, assigned_at: &str| {
        json!({
            "parentId": ID, "label": "synthetic",
            "assignedOn": assigned_on, "assignedAt": assigned_at
        })
    };

    // The stored instant is 10:00:00 UTC. The same instant written with a
    // different offset is not later than it, so both spellings are accepted.
    let zulu = invoke_with_input(
        app.clone(),
        "ordered-zulu",
        body("2026-10-30", "2026-10-30T10:00:00Z"),
    )
    .await;
    assert_eq!(zulu.0, StatusCode::OK, "{}", zulu.1);
    let offset = invoke_with_input(
        app.clone(),
        "ordered-offset",
        body("2026-10-30", "2026-10-30T10:00:00+00:00"),
    )
    .await;
    assert_eq!(offset.0, StatusCode::OK, "{}", offset.1);
    let shifted = invoke_with_input(
        app.clone(),
        "ordered-shifted",
        body("2026-11-30", "2026-10-30T12:00:00+02:00"),
    )
    .await;
    assert_eq!(shifted.0, StatusCode::OK, "{}", shifted.1);
    let accepted = counts(&database, &registry).await;
    assert_eq!(accepted[0], 3);

    // Each refusal breaks exactly one guard and leaves no trace. The offset
    // case would pass a text comparison (`10:59:59` sorts after `10:00:00`)
    // but is 09:59:59 UTC.
    for (key, assigned_on, assigned_at) in [
        ("instant-earlier", "2026-10-30", "2026-10-30T09:59:59Z"),
        (
            "instant-earlier-with-offset",
            "2026-10-30",
            "2026-10-30T10:59:59+01:00",
        ),
        ("date-earlier", "2026-10-29", "2026-10-30T10:00:00Z"),
        ("date-later", "2026-12-01", "2026-10-30T10:00:00Z"),
    ] {
        let refused = invoke_with_input(app.clone(), key, body(assigned_on, assigned_at)).await;
        assert_eq!(
            refused.0,
            StatusCode::PRECONDITION_FAILED,
            "{key}: {}",
            refused.1
        );
        assert_eq!(refused.1["code"], "action.guard_failed", "{key}");
        assert_eq!(accepted, counts(&database, &registry).await, "{key}");
    }

    let available = availability(
        app.clone(),
        json!({"parentId": ID, "assignedOn": "2026-10-30", "assignedAt": "2026-10-30T10:00:00+00:00"}),
    )
    .await;
    assert_eq!(
        available.1,
        json!({"availability":{"available":true,"observedRevision":1}})
    );
    let unavailable = availability(
        app.clone(),
        json!({"parentId": ID, "assignedOn": "2026-10-30", "assignedAt": "2026-10-30T09:00:00Z"}),
    )
    .await;
    assert_eq!(unavailable.0, StatusCode::OK, "{}", unavailable.1);
    assert_eq!(unavailable.1["availability"]["available"], false);
    let missing = availability(app, json!({"parentId": ID, "assignedOn": "2026-10-30"})).await;
    assert_eq!(missing.0, StatusCode::OK, "{}", missing.1);
    assert_eq!(
        missing.1["availability"]["reason"], "input-required",
        "{}",
        missing.1
    );
    assert_eq!(
        missing.1["availability"]["missingInputs"],
        json!(["assignedAt"])
    );
    database.cleanup().await;
}

fn with_parent_get(source: Value, readable_fields: &[&str]) -> Value {
    with_parent_get_boundaries(
        source,
        readable_fields,
        json!([{"field":"zone", "claim":"zone", "operator":"equals"}]),
    )
}

fn with_parent_get_boundaries(
    mut source: Value,
    readable_fields: &[&str],
    row_boundaries: Value,
) -> Value {
    source["accessProfiles"][0]["permissions"]["records"] = json!([{
        "recordType": "parent",
        "operations": ["get"],
        "readableFields": readable_fields,
        "rowBoundaries": row_boundaries
    }]);
    source
}

async fn insert_parent(
    database: &TestDatabase,
    registry: &registry_breg::CompiledRegistry,
    activation_id: &str,
    id: &str,
    lifecycle: &str,
    zone: &str,
) {
    let parent = &registry.entities()["parent"];
    database
        .admin
        .execute(
            &format!(
                "INSERT INTO registry_data.{} (record_id, record_revision, record_lifecycle, active_package_revision, {}, {}) VALUES ($1, 1, $2, $3, 'active', $4)",
                q(&parent.physical_table),
                q(&parent.fields["status"].physical_name),
                q(&parent.fields["zone"].physical_name),
            ),
            &[
                &Uuid::parse_str(id).unwrap(),
                &lifecycle,
                &activation_id,
                &zone,
            ],
        )
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn immediate_action_availability_preserves_disclosure_and_commit_boundaries() {
    let source = with_parent_get(support::project(), &["status", "zone"]);
    let (database, registry, identity) = setup_with_project(source).await;
    insert_parent(
        &database,
        &registry,
        &identity.activation_id,
        FOREIGN_ID,
        "active",
        "zone-b",
    )
    .await;
    insert_parent(
        &database,
        &registry,
        &identity.activation_id,
        TOMBSTONED_ID,
        "tombstoned",
        "zone-a",
    )
    .await;
    let visible_app = app(&database, registry.clone(), identity, None);
    let before = counts(&database, &registry).await;

    let available = availability(visible_app.clone(), json!({"parentId":ID})).await;
    assert_eq!(available.0, StatusCode::OK, "{}", available.1);
    assert_eq!(
        available.1,
        json!({"availability":{"available":true,"observedRevision":1}}),
        "an unrelated required form input may remain unfilled"
    );
    assert_eq!(before, counts(&database, &registry).await);

    let missing = availability(
        visible_app.clone(),
        json!({"parentId":"00000000-0000-4000-8000-000000000999"}),
    )
    .await;
    let get_foreign = get_parent(visible_app.clone(), FOREIGN_ID).await;
    let foreign = availability(visible_app.clone(), json!({"parentId":FOREIGN_ID})).await;
    let tombstoned = availability(visible_app.clone(), json!({"parentId":TOMBSTONED_ID})).await;
    assert_eq!(missing.0, StatusCode::NOT_FOUND, "{}", missing.1);
    assert_eq!(get_foreign.0, StatusCode::NOT_FOUND, "{}", get_foreign.1);
    assert_eq!(foreign.0, missing.0, "{}", foreign.1);
    assert_eq!(foreign.1["code"], missing.1["code"]);
    assert_eq!(tombstoned.0, missing.0, "{}", tombstoned.1);
    assert_eq!(tombstoned.1["code"], missing.1["code"]);

    database
        .admin
        .execute(
            &status_sql(&registry),
            &[&"inactive", &Uuid::parse_str(ID).unwrap()],
        )
        .await
        .unwrap();
    let unavailable = availability(visible_app.clone(), json!({"parentId":ID})).await;
    assert_eq!(unavailable.0, StatusCode::OK, "{}", unavailable.1);
    assert_eq!(
        unavailable.1,
        json!({"availability":{
            "available":false,
            "observedRevision":2,
            "reason":"guard-not-satisfied",
            "recovery":"none"
        }})
    );
    let visible_guard_failure = invoke(visible_app, "visible-guard", ID).await;
    assert_eq!(
        visible_guard_failure.0,
        StatusCode::PRECONDITION_FAILED,
        "{}",
        visible_guard_failure.1
    );
    assert_eq!(visible_guard_failure.1["code"], "action.guard_failed");
    assert_eq!(before, counts(&database, &registry).await);
    database.cleanup().await;

    let source = with_parent_get_boundaries(
        support::project(),
        &["status", "zone"],
        json!("unrestricted"),
    );
    let (database, registry, identity) = setup_with_project(source).await;
    insert_parent(
        &database,
        &registry,
        &identity.activation_id,
        FOREIGN_ID,
        "active",
        "zone-b",
    )
    .await;
    let boundary_app = app(&database, registry.clone(), identity, None);
    let get_foreign = get_parent(boundary_app.clone(), FOREIGN_ID).await;
    assert_eq!(get_foreign.0, StatusCode::OK, "{}", get_foreign.1);
    let action_foreign = availability(boundary_app, json!({"parentId":FOREIGN_ID})).await;
    assert_eq!(
        action_foreign.0,
        StatusCode::NOT_FOUND,
        "{}",
        action_foreign.1
    );
    assert!(counts(&database, &registry)
        .await
        .iter()
        .all(|count| *count == 0));
    database.cleanup().await;

    for readable_fields in [None, Some(&["zone"][..])] {
        let source = readable_fields.map_or_else(support::project, |fields| {
            with_parent_get(support::project(), fields)
        });
        let (database, registry, identity) = setup_with_project(source).await;
        let app = app(&database, registry.clone(), identity, None);
        let concealed = availability(app.clone(), json!({"parentId":ID})).await;
        assert_eq!(concealed.0, StatusCode::OK, "{}", concealed.1);
        assert_eq!(
            concealed.1,
            json!({"availability":{
                "available":null,
                "observedRevision":null,
                "reason":"not-disclosed",
                "recovery":"none"
            }})
        );
        database
            .admin
            .execute(
                &status_sql(&registry),
                &[&"inactive", &Uuid::parse_str(ID).unwrap()],
            )
            .await
            .unwrap();
        let hidden_guard_failure = invoke(app, "hidden-guard", ID).await;
        assert_eq!(
            hidden_guard_failure.0,
            StatusCode::PRECONDITION_FAILED,
            "{}",
            hidden_guard_failure.1
        );
        assert_eq!(hidden_guard_failure.1["code"], "precondition.failed");
        assert!(counts(&database, &registry)
            .await
            .iter()
            .all(|count| *count == 0));
        database.cleanup().await;
    }

    let mut source = with_parent_get(support::project(), &["status", "zone"]);
    source["actions"][0]["inputs"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"expected-status", "apiName":"expectedStatus", "type":"vocabulary-code",
            "vocabulary":"status", "values":["active","inactive"], "required":true,
            "classification":"restricted"
        }));
    source["actions"][0]["commitGuards"]["targets"][0]
        .as_object_mut()
        .unwrap()
        .remove("equals");
    source["actions"][0]["commitGuards"]["targets"][0]["equalsFromInput"] =
        json!("expected-status");
    let (database, registry, identity) = setup_with_project(source).await;
    let equality_app = app(&database, registry.clone(), identity, None);
    let missing_input = availability(equality_app.clone(), json!({"parentId":ID})).await;
    assert_eq!(missing_input.0, StatusCode::OK, "{}", missing_input.1);
    assert_eq!(
        missing_input.1,
        json!({"availability":{
            "available":null,
            "observedRevision":1,
            "reason":"input-required",
            "recovery":"correct-input",
            "missingInputs":["expectedStatus"]
        }})
    );
    let matching = availability(
        equality_app.clone(),
        json!({"parentId":ID, "expectedStatus":"active"}),
    )
    .await;
    assert_eq!(
        matching.1,
        json!({"availability":{"available":true,"observedRevision":1}})
    );
    let mismatching = availability(
        equality_app.clone(),
        json!({"parentId":ID, "expectedStatus":"inactive"}),
    )
    .await;
    assert_eq!(mismatching.0, StatusCode::OK, "{}", mismatching.1);
    assert_eq!(mismatching.1["availability"]["available"], false);
    let input_guard_failure = invoke_with_input(
        equality_app,
        "input-guard",
        json!({"parentId":ID, "label":"synthetic", "expectedStatus":"inactive"}),
    )
    .await;
    assert_eq!(
        input_guard_failure.0,
        StatusCode::PRECONDITION_FAILED,
        "{}",
        input_guard_failure.1
    );
    assert_eq!(input_guard_failure.1["code"], "action.guard_failed");
    assert!(counts(&database, &registry)
        .await
        .iter()
        .all(|count| *count == 0));
    database.cleanup().await;

    let mut source = with_parent_get(support::project(), &["status", "zone"]);
    source["actions"][0]["commitGuards"]["targets"] =
        json!([{"input":"parent", "revision":"unchanged"}]);
    let (database, registry, identity) = setup_with_project(source).await;
    let revision_app = app(&database, registry.clone(), identity, None);
    let revision_availability = availability(revision_app.clone(), json!({"parentId":ID})).await;
    assert_eq!(
        revision_availability.1,
        json!({"availability":{"available":true,"observedRevision":1}}),
        "revision guards are checked by the condition exchange, not as failed field guards"
    );
    let conditions = post_action(
        revision_app.clone(),
        "/v1/actions/register-child/target-conditions",
        json!({"input":{"parentId":ID}}),
        None,
    )
    .await;
    assert_eq!(conditions.0, StatusCode::OK, "{}", conditions.1);
    database
        .admin
        .execute(
            &status_sql(&registry),
            &[&"active", &Uuid::parse_str(ID).unwrap()],
        )
        .await
        .unwrap();
    let stale = post_action(
        revision_app,
        "/v1/actions/register-child",
        json!({
            "input":{"parentId":ID, "label":"synthetic"},
            "preconditions":conditions.1["preconditions"].clone()
        }),
        Some("stale-revision"),
    )
    .await;
    assert_eq!(stale.0, StatusCode::PRECONDITION_FAILED, "{}", stale.1);
    assert_eq!(stale.1["code"], "precondition.failed");
    assert!(counts(&database, &registry)
        .await
        .iter()
        .all(|count| *count == 0));
    database.cleanup().await;

    // A second reference input sorts after the guarded one. A failed field
    // guard is answered as `action.guard_failed` only when every other check
    // passed: a missing, foreign, or tombstoned second reference, or a stale
    // condition on it, still answers the generic refusal.
    let mut source = with_other_parent(with_parent_get(support::project(), &["status", "zone"]));
    let (database, registry, identity) = setup_with_project(source.clone()).await;
    insert_parent(
        &database,
        &registry,
        &identity.activation_id,
        FOREIGN_ID,
        "active",
        "zone-b",
    )
    .await;
    insert_parent(
        &database,
        &registry,
        &identity.activation_id,
        TOMBSTONED_ID,
        "tombstoned",
        "zone-a",
    )
    .await;
    insert_parent(
        &database,
        &registry,
        &identity.activation_id,
        OTHER_ID,
        "active",
        "zone-a",
    )
    .await;
    database
        .admin
        .execute(
            &status_sql(&registry),
            &[&"inactive", &Uuid::parse_str(ID).unwrap()],
        )
        .await
        .unwrap();
    let two_reference_app = app(&database, registry.clone(), identity, None);
    for (key, other) in [
        ("other-missing", "00000000-0000-4000-8000-000000000999"),
        ("other-foreign", FOREIGN_ID),
        ("other-tombstoned", TOMBSTONED_ID),
    ] {
        let refused = invoke_with_input(
            two_reference_app.clone(),
            key,
            json!({"parentId":ID, "otherParentId":other, "label":"synthetic"}),
        )
        .await;
        assert_eq!(refused.0, StatusCode::PRECONDITION_FAILED, "{}", refused.1);
        assert_eq!(
            refused.1["code"], "precondition.failed",
            "{key}: {}",
            refused.1
        );
    }
    let guard_failed = invoke_with_input(
        two_reference_app,
        "other-visible",
        json!({"parentId":ID, "otherParentId":OTHER_ID, "label":"synthetic"}),
    )
    .await;
    assert_eq!(
        guard_failed.0,
        StatusCode::PRECONDITION_FAILED,
        "{}",
        guard_failed.1
    );
    assert_eq!(guard_failed.1["code"], "action.guard_failed");
    assert!(counts(&database, &registry)
        .await
        .iter()
        .all(|count| *count == 0));
    database.cleanup().await;

    source["actions"][0]["commitGuards"]["targets"]
        .as_array_mut()
        .unwrap()
        .push(json!({"input":"other-parent", "revision":"unchanged"}));
    let (database, registry, identity) = setup_with_project(source).await;
    insert_parent(
        &database,
        &registry,
        &identity.activation_id,
        OTHER_ID,
        "active",
        "zone-a",
    )
    .await;
    let stale_app = app(&database, registry.clone(), identity, None);
    let conditions = post_action(
        stale_app.clone(),
        "/v1/actions/register-child/target-conditions",
        json!({"input":{"otherParentId":OTHER_ID}}),
        None,
    )
    .await;
    assert_eq!(conditions.0, StatusCode::OK, "{}", conditions.1);
    for (status, id) in [("active", OTHER_ID), ("inactive", ID)] {
        database
            .admin
            .execute(
                &status_sql(&registry),
                &[&status, &Uuid::parse_str(id).unwrap()],
            )
            .await
            .unwrap();
    }
    let stale = post_action(
        stale_app,
        "/v1/actions/register-child",
        json!({
            "input":{"parentId":ID, "otherParentId":OTHER_ID, "label":"synthetic"},
            "preconditions":conditions.1["preconditions"].clone()
        }),
        Some("stale-other"),
    )
    .await;
    assert_eq!(stale.0, StatusCode::PRECONDITION_FAILED, "{}", stale.1);
    assert_eq!(stale.1["code"], "precondition.failed");
    assert!(counts(&database, &registry)
        .await
        .iter()
        .all(|count| *count == 0));
    database.cleanup().await;
}

#[tokio::test]
async fn authored_guard_reason_requires_all_guard_and_boundary_facts_to_be_readable() {
    for readable in [
        &["status", "zone", "secondary"][..],
        &["zone", "secondary"][..],
        &["status", "zone"][..],
    ] {
        let mut source = with_parent_get(support::project(), readable);
        source["recordTypes"][0]["fields"].as_array_mut().unwrap().push(json!({"id":"secondary","type":"string","maximumLength":32,"classification":"restricted"}));
        source["actions"][0]["commitGuards"]["targets"][0]["reason"] = json!("parent-inactive");
        // A second unreadable guard must conceal even a readable failed guard.
        source["actions"][0]["commitGuards"]["targets"].as_array_mut().unwrap().push(
            json!({"input":"parent","field":"secondary","equals":"ready","reason":"secondary-unready"})
        );
        let (database, registry, identity) = setup_with_project(source).await;
        let entity = &registry.entities()["parent"];
        database
            .admin
            .execute(
                &format!(
                    "UPDATE registry_data.\"{}\" SET \"{}\"='ready' WHERE record_id=$1",
                    entity.physical_table, entity.fields["secondary"].physical_name
                ),
                &[&Uuid::parse_str(ID).unwrap()],
            )
            .await
            .unwrap();
        let app = app(&database, registry.clone(), identity, None);
        let observed = availability(app.clone(), json!({"parentId":ID})).await;
        let disclosed = readable.contains(&"status") && readable.contains(&"secondary");
        if disclosed {
            assert_eq!(observed.1["availability"]["available"], true);
        }
        database
            .admin
            .execute(
                &status_sql(&registry),
                &[&"inactive", &Uuid::parse_str(ID).unwrap()],
            )
            .await
            .unwrap();
        let before = counts(&database, &registry).await;
        let current = availability(app.clone(), json!({"parentId":ID})).await;
        let hidden = availability(app.clone(), json!({"parentId":FOREIGN_ID})).await;
        assert!(hidden.1["availability"].get("guardReason").is_none());
        let refused_hidden = invoke(app.clone(), "authored-hidden-reason", FOREIGN_ID).await;
        assert_eq!(refused_hidden.1["code"], "precondition.failed");
        assert!(refused_hidden.1.get("guardReason").is_none());
        let refused = invoke(app, "authored-reason", ID).await;
        assert_eq!(refused.0, StatusCode::PRECONDITION_FAILED);
        if disclosed {
            assert_eq!(current.1["availability"]["guardReason"], "parent-inactive");
            assert_eq!(refused.1["code"], "action.guard_failed");
            assert_eq!(refused.1["guardReason"], "parent-inactive");
        } else {
            assert_eq!(current.1["availability"]["reason"], "not-disclosed");
            assert!(current.1["availability"].get("guardReason").is_none());
            assert_eq!(refused.1["code"], "precondition.failed");
            assert!(refused.1.get("guardReason").is_none());
        }
        assert_eq!(before, counts(&database, &registry).await);
        database.cleanup().await;
    }
}

/// Adds a second required reference to `parent`. It carries no field guard,
/// so its own checks are reference visibility and any revision condition.
fn with_other_parent(mut source: Value) -> Value {
    source["actions"][0]["inputs"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"other-parent", "apiName":"otherParentId", "type":"reference",
            "target":"parent", "required":true, "classification":"restricted"
        }));
    source
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn action_effect_fields_are_authorized_under_a_locale_collation() {
    // A locale collation such as glibc en_US ignores the hyphen at the first
    // comparison level and orders "awarded-by" before "award-number"; byte
    // order puts it after. The row-level policy must accept the written-field
    // set whatever the database collation is.
    let mut source = support::project();
    for (field, api_name) in [("award-number", "awardNumber"), ("awarded-by", "awardedBy")] {
        source["recordTypes"][1]["fields"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id": field, "type": "string", "maximumLength": 32, "required": true,
                "classification": "restricted"
            }));
        source["actions"][0]["inputs"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id": field, "apiName": api_name, "type": "string", "maximumLength": 32,
                "required": true, "classification": "restricted"
            }));
        source["actions"][0]["plan"]["effects"][0]["set"][field] = json!({"fromInput": field});
    }
    let database = TestDatabase::create_with_locale(8, "en_US.utf8").await;
    let locale_ordered = database
        .admin
        .query_one("SELECT 'awarded-by'::text < 'award-number'::text", &[])
        .await
        .unwrap()
        .get::<_, bool>(0);
    assert!(
        locale_ordered,
        "the test database must order text by locale, not by byte"
    );
    let (database, registry, identity) = setup_in(database, source).await;
    let app = app(&database, registry.clone(), identity, None);
    let accepted = invoke_with_input(
        app,
        "locale-collation",
        json!({
            "parentId": ID, "label": "synthetic", "awardNumber": "award-1",
            "awardedBy": "registrar"
        }),
    )
    .await;
    assert_eq!(accepted.0, StatusCode::OK, "{}", accepted.1);
    let child = &registry.entities()["child"];
    let row = database
        .admin
        .query_one(
            &format!(
                "SELECT {}, {} FROM registry_data.{}",
                q(&child.fields["award-number"].physical_name),
                q(&child.fields["awarded-by"].physical_name),
                q(&child.physical_table)
            ),
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        (row.get::<_, String>(0), row.get::<_, String>(1)),
        ("award-1".to_owned(), "registrar".to_owned())
    );
    database.cleanup().await;
}

fn status_sql(registry: &registry_breg::CompiledRegistry) -> String {
    let parent = &registry.entities()["parent"];
    format!(
        "UPDATE registry_data.{} SET {} = $1, record_revision = record_revision + 1 WHERE record_id = $2",
        q(&parent.physical_table),
        q(&parent.fields["status"].physical_name)
    )
}

async fn counts(database: &TestDatabase, registry: &registry_breg::CompiledRegistry) -> Vec<i64> {
    let row = database.admin.query_one(&format!("SELECT (SELECT count(*) FROM registry_data.{}), (SELECT count(*) FROM registry_internal.registry_revisions), (SELECT count(*) FROM registry_internal.registry_outbox), (SELECT count(*) FROM registry_internal.registry_idempotency), (SELECT count(*) FROM registry_internal.registry_immediate_action_applications), (SELECT count(*) FROM registry_internal.registry_immediate_action_results)", q(&registry.entities()["child"].physical_table)), &[]).await.unwrap();
    (0..6).map(|index| row.get(index)).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn action_requirements_are_acceptance_only_atomic_and_replayable() {
    let (database, registry, identity) = setup().await;
    let app = app(&database, registry.clone(), identity, None);
    let accepted = invoke(app.clone(), "accepted", ID).await;
    assert_eq!(accepted.0, StatusCode::OK, "{}", accepted.1);
    assert!(accepted.1.get("status").is_none());
    let after = counts(&database, &registry).await;
    assert!(after.iter().all(|count| *count == 1), "{after:?}");
    database
        .admin
        .execute(
            &status_sql(&registry),
            &[&"inactive", &Uuid::parse_str(ID).unwrap()],
        )
        .await
        .unwrap();
    let replay = invoke(app.clone(), "accepted", ID).await;
    assert_eq!(
        accepted, replay,
        "replay recovers the accepted result without requiring a still-active parent"
    );
    let inactive = invoke(app.clone(), "inactive", ID).await;
    assert_eq!(
        inactive.0,
        StatusCode::PRECONDITION_FAILED,
        "{}",
        inactive.1
    );
    assert!(!inactive.1.to_string().contains("inactive"));
    let missing = invoke(
        app.clone(),
        "missing",
        "00000000-0000-4000-8000-000000000999",
    )
    .await;
    assert_eq!(missing.0, inactive.0);
    assert_eq!(missing.1["code"], inactive.1["code"]);
    assert_eq!(after, counts(&database, &registry).await);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn action_requirements_hold_reference_lock_against_concurrent_inactivation() {
    let (mut database, registry, identity) = setup().await;
    let app = app(&database, registry.clone(), identity, None);
    // Inactivation takes the row first. Invocation must wait and inspect its committed value.
    let transaction = database.admin.transaction().await.unwrap();
    transaction
        .execute(
            &status_sql(&registry),
            &[&"inactive", &Uuid::parse_str(ID).unwrap()],
        )
        .await
        .unwrap();
    let pending = tokio::spawn(invoke(app.clone(), "inactivation-first", ID));
    wait_for_lock(
        &transaction,
        database.runtime_role.as_str(),
        "transactionid",
    )
    .await;
    transaction.commit().await.unwrap();
    let refused = pending.await.unwrap();
    assert_eq!(refused.0, StatusCode::PRECONDITION_FAILED, "{}", refused.1);
    assert!(counts(&database, &registry)
        .await
        .iter()
        .all(|count| *count == 0));
    database
        .admin
        .execute(
            &status_sql(&registry),
            &[&"active", &Uuid::parse_str(ID).unwrap()],
        )
        .await
        .unwrap();
    // Invocation takes the row first. Pause before INSERT, after the requirement was checked.
    let child = &registry.entities()["child"];
    database.admin.batch_execute(&format!("CREATE FUNCTION registry_internal.pause_required_action() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(819274); RETURN NEW; END; $$; CREATE TRIGGER pause_required_action BEFORE INSERT ON registry_data.{} FOR EACH ROW EXECUTE FUNCTION registry_internal.pause_required_action();", q(&child.physical_table))).await.unwrap();
    database
        .admin
        .query_one("SELECT pg_advisory_lock(819274)", &[])
        .await
        .unwrap();
    let pending = tokio::spawn(invoke(app, "invocation-first", ID));
    wait_for_lock(&database.admin, database.runtime_role.as_str(), "advisory").await;
    let database_name: String = database
        .admin
        .query_one("SELECT current_database()", &[])
        .await
        .unwrap()
        .get(0);
    let mut writer_config: tokio_postgres::Config = std::env::var("BREG_TEST_DATABASE_URL")
        .unwrap()
        .parse()
        .unwrap();
    writer_config
        .dbname(&database_name)
        .application_name("required-action-competing-writer");
    let (writer, connection) = writer_config.connect(tokio_postgres::NoTls).await.unwrap();
    let writer_task = tokio::spawn(async move { connection.await.unwrap() });
    let sql = status_sql(&registry);
    let write = tokio::spawn(async move {
        writer
            .execute(&sql, &[&"inactive", &Uuid::parse_str(ID).unwrap()])
            .await
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let waiting: bool = database.admin.query_one("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name = 'required-action-competing-writer' AND wait_event_type = 'Lock')", &[]).await.unwrap().get(0);
            if waiting { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("inactivation waits for the invocation's reference lock");
    database
        .admin
        .query_one("SELECT pg_advisory_unlock(819274)", &[])
        .await
        .unwrap();
    let accepted = pending.await.unwrap();
    assert_eq!(accepted.0, StatusCode::OK, "{}", accepted.1);
    assert_eq!(write.await.unwrap().unwrap(), 1);
    writer_task.abort();
    assert!(counts(&database, &registry)
        .await
        .iter()
        .all(|count| *count == 1));
    database.cleanup().await;
}

async fn wait_for_lock(
    client: &(impl tokio_postgres::GenericClient + Sync),
    role: &str,
    event: &str,
) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            client.query_one("SELECT pg_stat_clear_snapshot()", &[]).await.unwrap();
            let waiting: bool = client.query_one("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE usename = $1 AND wait_event_type = 'Lock' AND lower(wait_event) = $2)", &[&role, &event]).await.unwrap().get(0);
            if waiting { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("competing transaction reached expected lock before proceeding");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn action_requirements_preserve_fault_rollback() {
    let (database, registry, identity) = setup().await;
    let app = app(
        &database,
        registry.clone(),
        identity,
        Some(MutationFaultPoint::BeforeOutbox),
    );
    let refused = invoke(app, "fault", ID).await;
    assert!(!refused.0.is_success());
    assert!(counts(&database, &registry)
        .await
        .iter()
        .all(|count| *count == 0));
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn committed_action_audit_precedes_lost_response_fault() {
    let (database, registry, identity) = setup().await;
    let (app, audit) = app_with_audit(
        &database,
        registry.clone(),
        identity,
        Some(MutationFaultPoint::AfterCommitBeforeResponseRelease),
    );

    let lost = invoke(app, "lost-after-commit", ID).await;
    assert!(
        !lost.0.is_success(),
        "the injected fault withholds the answer"
    );
    let committed = counts(&database, &registry).await;
    assert!(
        committed.iter().all(|count| *count == 1),
        "the Action effects, revision, outbox, receipt, application, and result commit together: {committed:?}"
    );

    let terminal = audit
        .entries()
        .into_iter()
        .filter(|entry| {
            entry["phase"] == "response"
                && entry["record"]["operationId"] == "actions.register-child.invoke"
                && entry["record"]["phase"] == "terminal"
        })
        .collect::<Vec<_>>();
    assert_eq!(
        terminal.len(),
        1,
        "the committed Action has one terminal audit"
    );
    assert_eq!(terminal[0]["record"]["outcome"], "committed");
    database.cleanup().await;
}

fn q(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}
