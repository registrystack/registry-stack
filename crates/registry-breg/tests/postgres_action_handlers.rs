// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "postgres-test", feature = "tooling"))]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use postgres_harness::TestDatabase;
use registry_breg::{
    api::{
        router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture,
        VerifiedClaimValue, VerifiedRequestClaims,
    },
    compiler::{compile_project_with_assets, CompileProfile},
    contract::{parse_project_yaml, ModuleAssetSource},
    cursor::CursorCodec,
    mutation::MutationFaultPoint,
    postgres::{
        initialize_registry_state_for_catalog_test, install_compiled_schema,
        ExpectedManagedCatalog, ExpectedRegistryIdentity, PostgresRecordMutationService,
        PostgresRecordReadService, RegistryLockKey, RegistryStateTestIdentity,
    },
};
use registry_platform_audit::AuditProfile;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tower::Service as _;
use uuid::Uuid;
use zeroize::Zeroizing;

const ID: &str = "00000000-0000-4000-8000-000000000101";
const PACKAGE: &str = "person-registration-rhai";
static HANDLER_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn setup() -> (
    TestDatabase,
    Arc<registry_breg::CompiledRegistry>,
    ExpectedRegistryIdentity,
) {
    setup_with_handler_source(None).await
}

async fn setup_with_handler_source(
    handler_source: Option<&str>,
) -> (
    TestDatabase,
    Arc<registry_breg::CompiledRegistry>,
    ExpectedRegistryIdentity,
) {
    let database = TestDatabase::create(8).await;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/acceptance/person-registration-rhai");
    let mut project =
        parse_project_yaml(&std::fs::read(root.join("registry.yaml")).unwrap()).unwrap();
    project
        .entities
        .iter_mut()
        .find(|entity| entity.id == "person")
        .unwrap()
        .batch =
        Some(serde_json::from_value(json!({"maximumItems": 4,"maximumBytes":8192})).unwrap());
    project
        .access_profiles
        .iter_mut()
        .find(|profile| profile.id == "person-administrator")
        .unwrap()
        .grants
        .iter_mut()
        .find(|grant| grant.entity == "person")
        .unwrap()
        .operations
        .insert(registry_breg::contract::Operation::Batch);
    // The regression variant adds a field ceiling wider than the selected
    // mutation and a row boundary on the declared, optionally omitted target.
    project
        .actions
        .iter_mut()
        .find(|action| action.id == "register-person-with-registration")
        .unwrap()
        .handler
        .as_mut()
        .unwrap()
        .writes
        .iter_mut()
        .find(|slot| slot.id == "register")
        .unwrap()
        .fields
        .push("active".to_owned());
    project
        .actions
        .iter_mut()
        .find(|action| action.id == "register-person-with-registration")
        .unwrap()
        .inputs
        .push(
            serde_json::from_value(json!({
                "id":"clear-register-contact", "type":"boolean", "classification":"internal"
            }))
            .unwrap(),
        );
    project
        .access_profiles
        .iter_mut()
        .find(|profile| profile.id == "person-registrar")
        .unwrap()
        .grants
        .iter_mut()
        .find(|grant| grant.action.as_deref() == Some("register-person-with-registration"))
        .unwrap()
        .targets
        .iter_mut()
        .find(|target| target.entity == "register")
        .unwrap()
        .row_boundaries
        .push(
            serde_json::from_value(
                json!({"field":"register-code","claim":"register_code","operator":"equals"}),
            )
            .unwrap(),
        );
    let assets = [
        "scripts/register-person.rhai",
        "scripts/register-person-with-registration.rhai",
    ]
    .map(|path| {
        let source = std::fs::read_to_string(root.join(path)).unwrap();
        let source = if path == "scripts/register-person.rhai" {
            handler_source.map_or(source, str::to_owned)
        } else {
            // A test-only optional patch branch exercises clear through the
            // ordinary HTTP handler, compiled field ceiling, and SQL writer.
            source.replace(
                "if ctx.inputs[\"update-register\"] {",
                "if \"clear-register-contact\" in ctx.inputs && ctx.inputs[\"clear-register-contact\"] != () && ctx.inputs[\"clear-register-contact\"] {\n\
                     effects.push(#{id: \"register\", clear: [\"last-person\"]});\n\
                 } else if ctx.inputs[\"update-register\"] {",
            )
        };
        ModuleAssetSource {
            module: None,
            path: path.to_owned(),
            bytes: source.into_bytes(),
        }
    });
    let registry = Arc::new(
        compile_project_with_assets(&project, &[], &assets, CompileProfile::Authoring).unwrap(),
    );
    let (migration, task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .unwrap();
    let identity = initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(&registry),
        RegistryStateTestIdentity {
            package_id: PACKAGE,
            environment: "local",
            instance_id: "requirements-instance",
            database_id: "requirements-database",
            package_revision: "requirements-1",
            package_sequence: 1,
        },
    )
    .await
    .unwrap();
    drop(migration);
    task.abort();
    let register = &registry.entities()["register"];
    database.admin.execute(&format!("INSERT INTO registry_data.{} (record_id, record_revision, record_lifecycle, active_package_revision, {}, {}) VALUES ($1, 1, 'active', $2, 'R-1', true)", q(&register.physical_table), q(&register.fields["register-code"].physical_name), q(&register.fields["active"].physical_name)), &[&Uuid::parse_str(ID).unwrap(), &identity.package_revision]).await.unwrap();
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
    configured_app(database, registry, identity, fault, None)
}

fn configured_app(
    database: &TestDatabase,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: ExpectedRegistryIdentity,
    fault: Option<MutationFaultPoint>,
    timeout: Option<Duration>,
) -> axum::Router {
    let pool = database.runtime_config.build_pool().unwrap();
    let audit = AuditProfile::production_from_secret_bytes(vec![0x42; 32].into()).unwrap();
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
        package_revision: identity.package_revision.clone(),
        schema_fingerprint: identity.schema_fingerprint.clone(),
    };
    let mutations = PostgresRecordMutationService::new_with_event_destinations(
        pool,
        registry.clone(),
        identity,
        lock,
        Duration::from_secs(5),
        audit,
        Some(Arc::new(event_destinations(&registry))),
    );
    let mutations = match timeout {
        Some(timeout) => mutations.with_action_timeout_for_test(timeout),
        None => mutations,
    };
    let mutations = match fault {
        Some(fault) => mutations.with_fault_for_test(fault),
        None => mutations,
    };
    router(Arc::new(
        HttpService::new(registry, read_identity, reads, Arc::new(Ready), cursors)
            .with_postgres_mutations(Arc::new(mutations)),
    ))
}

fn claims(role: &str) -> VerifiedRequestClaims {
    let (scope, purpose) = match role {
        "person-reader" => ("registry:person:read", "person-registration-audit"),
        "person-administrator" => ("registry:person:manage", "person-maintenance"),
        "revoked" => ("registry:unrelated", "person-registration"),
        _ => ("registry:person:register", "person-registration"),
    };
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        "synthetic-registrar",
        BTreeSet::from([scope.to_owned()]),
        Some(purpose.to_owned()),
        BTreeMap::from([(
            "register_code".to_owned(),
            VerifiedClaimValue::direct_string(if role == "wrong-register" {
                "R-2"
            } else {
                "R-1"
            })
            .unwrap(),
        )]),
    )
    .unwrap()
}

async fn send(
    mut app: axum::Router,
    method: &str,
    path: &str,
    key: &str,
    body: Value,
    role: &str,
) -> (StatusCode, Value) {
    let claims = claims(role);
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("idempotency-key", key)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    request.extensions_mut().insert(claims);
    let response = app.call(request).await.unwrap();
    let status = response.status();
    let body =
        serde_json::from_slice(&to_bytes(response.into_body(), 128 * 1024).await.unwrap()).unwrap();
    (status, body)
}

async fn assert_direct_patch_pattern_diagnostic(mut app: axum::Router, record_id: &str) {
    let path = format!("/v1/records/people/{record_id}?accessProfile=person-administrator");
    let mut get = Request::builder().uri(&path).body(Body::empty()).unwrap();
    get.extensions_mut().insert(claims("person-administrator"));
    let response = app.call(get).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let etag = response.headers()["etag"].clone();
    let mut patch = Request::builder()
        .method("PATCH")
        .uri(&path)
        .header("content-type", "application/json-patch+json")
        .header("if-match", etag)
        .header("idempotency-key", "direct-invalid-pattern")
        .body(Body::from(
            serde_json::to_vec(
                &json!([{"op":"replace","path":"/data/identifier","value":"112345678901x"}]),
            )
            .unwrap(),
        ))
        .unwrap();
    patch
        .extensions_mut()
        .insert(claims("person-administrator"));
    let response = app.call(patch).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 128 * 1024).await.unwrap()).unwrap();
    assert_eq!(body["entityId"], "person");
    assert_eq!(body["fieldId"], "identifier");
    assert!(!body.to_string().contains("112345678901x"));
}

fn input(identifier: &str) -> Value {
    json!({"input":{"identifier":identifier,"givenName":"  Mina  ","familyName":"  Example "}})
}

async fn counts(database: &TestDatabase, registry: &registry_breg::CompiledRegistry) -> Vec<i64> {
    let row = database.admin.query_one(&format!("SELECT (SELECT count(*) FROM registry_data.{}), (SELECT count(*) FROM registry_data.{}), (SELECT count(*) FROM registry_internal.registry_revisions), (SELECT count(*) FROM registry_internal.registry_outbox), (SELECT count(*) FROM registry_internal.registry_idempotency), (SELECT count(*) FROM registry_internal.registry_immediate_action_applications), (SELECT count(*) FROM registry_internal.registry_immediate_action_results)", q(&registry.entities()["person"].physical_table), q(&registry.entities()["registration"].physical_table)), &[]).await.unwrap();
    (0..7).map(|index| row.get(index)).collect()
}

fn q(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

#[tokio::test(flavor = "current_thread")]
async fn action_handlers_compute_refuse_retry_recover_and_preserve_compiled_authority() {
    let _test_guard = HANDLER_TEST_LOCK.lock().await;
    let (database, registry, identity) = setup().await;
    let app = app(&database, registry.clone(), identity.clone(), None);
    let simple = "/v1/actions/register-person";
    let coordinated = "/v1/actions/register-person-with-registration";
    let openapi = send(
        app.clone(),
        "GET",
        "/openapi.json?accessProfile=person-registrar",
        "openapi",
        Value::Null,
        "person-registrar",
    )
    .await;
    assert_eq!(openapi.0, StatusCode::OK, "{}", openapi.1);
    let problem_validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&openapi.1["components"]["schemas"]["Problem"])
        .expect("caller-filtered problem schema compiles");
    let coordinated_input_validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(
            &openapi.1["components"]["schemas"]
                ["action-register-person-with-registration-invoke-input"],
        )
        .expect("caller-filtered handler input schema compiles");
    let coordinated_response_validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(
            &openapi.1["components"]["schemas"]
                ["action-register-person-with-registration-invoke-response"],
        )
        .expect("caller-filtered handler response schema compiles");
    for status in ["409", "422", "500", "503"] {
        assert!(
            openapi.1["paths"][simple]["post"]["responses"][status].is_object(),
            "handler invoke documents HTTP {status}"
        );
    }
    let call = |path: &str, key: &str, body| {
        let app = app.clone();
        let path = path.to_owned();
        let key = key.to_owned();
        async move { send(app, "POST", &path, &key, body, "person-registrar").await }
    };
    let before = counts(&database, &registry).await;
    let mut missing_identifier = input("0123456789012");
    missing_identifier["input"]["identifier"] = Value::Null;
    let invalid_input = call(simple, "required-null", missing_identifier).await;
    assert_eq!(
        invalid_input.0,
        StatusCode::BAD_REQUEST,
        "{}",
        invalid_input.1
    );
    assert_eq!(invalid_input.1["code"], "request.invalid");
    assert_eq!(invalid_input.1["fieldPath"], "/input/identifier");
    let mut blank = input("0123456789012");
    blank["input"]["givenName"] = json!("   ");
    blank["input"]["familyName"] = json!("  ");
    let refused = call(simple, "refused-retry", blank.clone()).await;
    assert_eq!(refused.0, StatusCode::UNPROCESSABLE_ENTITY, "{}", refused.1);
    assert_eq!(refused.1["code"], "action.refused");
    assert_eq!(
        refused.1["type"],
        "https://id.registrystack.org/problems/registry-breg/action/refused"
    );
    assert_eq!(refused.1["refusalCode"], "blank-name");
    assert_eq!(refused.1["fieldPath"], "/input/givenName");
    assert_eq!(refused.1["detail"], "At least one name part is required.");
    assert!(refused.1["traceId"].is_string());
    assert!(problem_validator.is_valid(&refused.1), "{}", refused.1);
    assert_eq!(before, counts(&database, &registry).await);
    let audit_phases = database.admin.query_one(
        "SELECT count(*) FILTER (WHERE convert_from(envelope, 'UTF8') LIKE '%\"phase\":\"attempt\"%'), count(*) FILTER (WHERE convert_from(envelope, 'UTF8') LIKE '%\"phase\":\"refusal\"%'), count(*) FILTER (WHERE convert_from(envelope, 'UTF8') LIKE '%\"phase\":\"terminal\"%') FROM registry_internal.registry_audit", &[]).await.unwrap();
    assert!(audit_phases.get::<_, i64>(0) >= 1);
    assert!(audit_phases.get::<_, i64>(1) >= 1);
    assert_eq!(audit_phases.get::<_, i64>(2), 0);
    // A refused invocation did not durably consume the key.
    let accepted = call(simple, "refused-retry", input("0123456789012")).await;
    assert_eq!(accepted.0, StatusCode::OK, "{}", accepted.1);
    let read = send(
        app.clone(),
        "GET",
        &format!(
            "/v1/records/people/{}?accessProfile=person-reader",
            accepted.1["results"]["person"]["recordId"]
                .as_str()
                .unwrap()
        ),
        "read",
        Value::Null,
        "person-reader",
    )
    .await;
    assert_eq!(read.0, StatusCode::OK, "{}", read.1);
    assert_eq!(
        read.1["data"]["domainData"]["identifier"], "0123456789012",
        "{}",
        read.1
    );
    assert_eq!(read.1["data"]["domainData"]["displayName"], "Mina Example");
    assert_direct_patch_pattern_diagnostic(
        app.clone(),
        accepted.1["results"]["person"]["recordId"]
            .as_str()
            .unwrap(),
    )
    .await;
    let after = counts(&database, &registry).await;
    assert_eq!(after, vec![1, 0, 1, 1, 1, 1, 1]);
    use registry_breg::action_handler::{
        fail_next_test_action_handler_invocation, reset_test_action_handler_invocation_count,
        test_action_handler_invocation_count,
    };
    reset_test_action_handler_invocation_count("register-person");
    fail_next_test_action_handler_invocation("register-person");
    assert_eq!(
        accepted,
        call(simple, "refused-retry", input("0123456789012")).await
    );
    assert_eq!(
        test_action_handler_invocation_count("register-person"),
        0,
        "receipt recovery bypasses evaluator despite pending controlled failure"
    );
    let failed = call(simple, "handler-failure-retry", input("1123456789012")).await;
    assert_eq!(failed.0, StatusCode::INTERNAL_SERVER_ERROR, "{}", failed.1);
    assert_eq!(failed.1["code"], "action.handler_failed");
    assert_eq!(
        failed.1["type"],
        "https://id.registrystack.org/problems/registry-breg/action/handler_failed"
    );
    assert!(problem_validator.is_valid(&failed.1), "{}", failed.1);
    assert_eq!(test_action_handler_invocation_count("register-person"), 1);
    assert_eq!(after, counts(&database, &registry).await);
    assert_eq!(
        call(simple, "refused-retry", input("1123456789012"))
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        send(
            app.clone(),
            "POST",
            simple,
            "refused-retry",
            input("0123456789012"),
            "revoked"
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let invalid = call(simple, "invalid-pattern", input("112345678901x")).await;
    assert_eq!(invalid.0, StatusCode::CONFLICT, "{}", invalid.1);
    assert_eq!(invalid.1["entityId"], "person");
    assert_eq!(invalid.1["fieldId"], "identifier");
    assert!(!invalid.1.to_string().contains("112345678901x"));
    assert!(problem_validator.is_valid(&invalid.1), "{}", invalid.1);
    assert_eq!(after, counts(&database, &registry).await);
    let direct_invalid = send(
        app.clone(),
        "POST",
        "/v1/records/people?accessProfile=person-administrator",
        "direct-invalid",
        json!({"data":{"identifier":"112345678901x","displayName":"Synthetic"}}),
        "person-administrator",
    )
    .await;
    assert_eq!(
        direct_invalid.0,
        StatusCode::CONFLICT,
        "{}",
        direct_invalid.1
    );
    assert_eq!(direct_invalid.1["entityId"], "person");
    assert_eq!(direct_invalid.1["fieldId"], "identifier");
    let batch_invalid = send(app.clone(), "POST", "/v1/records/people:batch?accessProfile=person-administrator", "batch-invalid", json!({"items":[
        {"operation":"create","data":{"identifier":"8123456789012","displayName":"Staged first"}},
        {"operation":"create","data":{"identifier":"912345678901x","displayName":"Invalid later"}}
    ]}), "person-administrator").await;
    assert_eq!(batch_invalid.0, StatusCode::CONFLICT, "{}", batch_invalid.1);
    assert_eq!(batch_invalid.1["entityId"], "person");
    assert_eq!(batch_invalid.1["fieldId"], "identifier");
    assert_eq!(
        after,
        counts(&database, &registry).await,
        "later pattern failure rolls back the atomic batch's valid prefix and evidence"
    );
    let condition = call(
        &format!("{coordinated}/target-conditions"),
        "conditions",
        json!({"input":{"registerId":ID}}),
    )
    .await;
    assert_eq!(condition.0, StatusCode::OK, "{}", condition.1);
    let coordinated_input = |identifier: &str, code: &str, include: bool| {
        let mut body = input(identifier);
        body["input"]["registerId"] = json!(ID);
        body["input"]["registrationCode"] = json!(code);
        body["input"]["recordRegistration"] = json!(include);
        body["input"]["updateRegister"] = json!(include);
        body["input"]["clearRegisterContact"] = Value::Null;
        body["preconditions"] = condition.1["preconditions"].clone();
        assert!(
            coordinated_input_validator.is_valid(&body),
            "an explicit null optional input follows the compiled invoke contract"
        );
        body
    };
    let outside = send(
        app.clone(),
        "POST",
        coordinated,
        "outside-omitted",
        coordinated_input("2123456789012", "reg-1", false),
        "wrong-register",
    )
    .await;
    assert_eq!(
        outside.0,
        StatusCode::PRECONDITION_FAILED,
        "omitted patch still requires target authority: {}",
        outside.1
    );
    assert_eq!(after, counts(&database, &registry).await);
    let omitted = call(
        coordinated,
        "omit",
        coordinated_input("2123456789012", "reg-1", false),
    )
    .await;
    assert_eq!(omitted.0, StatusCode::OK, "{}", omitted.1);
    assert!(
        coordinated_response_validator.is_valid(&omitted.1),
        "the served response schema accepts omitted handler slots: {}",
        omitted.1
    );
    assert_eq!(
        omitted.1["results"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        vec!["person"]
    );
    let mut missing = coordinated_input("3123456789012", "reg-1", false);
    missing.as_object_mut().unwrap().remove("preconditions");
    assert_eq!(
        call(coordinated, "missing-condition", missing).await.0,
        StatusCode::BAD_REQUEST
    );
    let complete = call(
        coordinated,
        "complete",
        coordinated_input("3123456789012", "reg-1", true),
    )
    .await;
    assert_eq!(complete.0, StatusCode::OK, "{}", complete.1);
    assert!(
        coordinated_response_validator.is_valid(&complete.1),
        "the served response schema accepts all selected handler results: {}",
        complete.1
    );
    assert_eq!(complete.1["results"].as_object().unwrap().len(), 3);
    let after_complete = counts(&database, &registry).await;
    assert_eq!(after_complete, vec![3, 1, 5, 4, 3, 3, 5]);
    assert_eq!(
        call(
            coordinated,
            "stale-omitted",
            coordinated_input("4123456789012", "reg-2", false)
        )
        .await
        .0,
        StatusCode::PRECONDITION_FAILED
    );
    let register = &registry.entities()["register"];
    let change_register_code = format!(
        "UPDATE registry_data.{} SET {} = $1 WHERE record_id = $2",
        q(&register.physical_table),
        q(&register.fields["register-code"].physical_name)
    );
    database
        .admin
        .execute(
            &change_register_code,
            &[&"R-2", &Uuid::parse_str(ID).unwrap()],
        )
        .await
        .unwrap();
    reset_test_action_handler_invocation_count("register-person-with-registration");
    assert_eq!(
        call(
            coordinated,
            "complete",
            coordinated_input("3123456789012", "reg-1", true)
        )
        .await
        .0,
        StatusCode::PRECONDITION_FAILED,
        "receipt release rechecks current row authority even for a committed handler action"
    );
    assert_eq!(
        test_action_handler_invocation_count("register-person-with-registration"),
        0,
        "revoked receipt authority never re-runs the handler"
    );
    assert_eq!(after_complete, counts(&database, &registry).await);
    database
        .admin
        .execute(
            &change_register_code,
            &[&"R-1", &Uuid::parse_str(ID).unwrap()],
        )
        .await
        .unwrap();
    database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.{} SET {} = false WHERE record_id = $1",
                q(&register.physical_table),
                q(&register.fields["active"].physical_name)
            ),
            &[&Uuid::parse_str(ID).unwrap()],
        )
        .await
        .unwrap();
    assert_eq!(
        complete,
        call(
            coordinated,
            "complete",
            coordinated_input("3123456789012", "reg-1", true)
        )
        .await
    );
    let current_condition = call(
        &format!("{coordinated}/target-conditions"),
        "conditions-2",
        json!({"input":{"registerId":ID}}),
    )
    .await;
    let mut ineligible = coordinated_input("4123456789012", "reg-2", false);
    ineligible["preconditions"] = current_condition.1["preconditions"].clone();
    assert_eq!(
        call(coordinated, "requires-omitted", ineligible.clone())
            .await
            .0,
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(after_complete, counts(&database, &registry).await);
    database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.{} SET {} = true WHERE record_id = $1",
                q(&register.physical_table),
                q(&register.fields["active"].physical_name)
            ),
            &[&Uuid::parse_str(ID).unwrap()],
        )
        .await
        .unwrap();
    let mut late_conflict = ineligible;
    late_conflict["input"]["recordRegistration"] = json!(true);
    late_conflict["input"]["registrationCode"] = json!("reg-1");
    assert_eq!(
        call(coordinated, "late-conflict", late_conflict).await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        after_complete,
        counts(&database, &registry).await,
        "later duplicate registration rolls back staged person, revision and event"
    );
    let fault_app = app_with_fault(
        &database,
        registry.clone(),
        identity.clone(),
        MutationFaultPoint::BeforeTerminalAudit,
    );
    assert_eq!(
        send(
            fault_app,
            "POST",
            simple,
            "evidence-failure",
            input("5123456789012"),
            "person-registrar"
        )
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(after_complete, counts(&database, &registry).await);
    // A real PostgreSQL serialization failure rolls back the first transaction.
    // Sequence values survive rollback and remember the reserved UUID's digest;
    // the retry trigger refuses if the coordinator invents a different identity.
    let person = &registry.entities()["person"];
    database.admin.batch_execute(&format!(
        "CREATE SEQUENCE registry_internal.handler_retry_attempt;
         CREATE SEQUENCE registry_internal.handler_retry_identity MINVALUE 0;
         GRANT USAGE, SELECT, UPDATE ON SEQUENCE registry_internal.handler_retry_attempt, registry_internal.handler_retry_identity TO {};
         CREATE FUNCTION registry_internal.handler_retry_probe() RETURNS trigger LANGUAGE plpgsql AS $body$
         DECLARE attempt bigint; identity_digest bigint; BEGIN
           attempt := nextval('registry_internal.handler_retry_attempt');
           identity_digest := ('x' || substr(md5(NEW.record_id::text), 1, 15))::bit(60)::bigint;
           IF attempt = 1 THEN
             PERFORM setval('registry_internal.handler_retry_identity', identity_digest, true);
             RAISE EXCEPTION 'synthetic confirmed abort' USING ERRCODE = '40001';
           END IF;
           IF identity_digest <> (SELECT last_value FROM registry_internal.handler_retry_identity) THEN
             RAISE EXCEPTION 'reserved identity changed';
           END IF;
           RETURN NEW; END $body$;
         CREATE TRIGGER handler_retry_probe BEFORE INSERT ON registry_data.{} FOR EACH ROW EXECUTE FUNCTION registry_internal.handler_retry_probe()",
        q(database.runtime_role.as_str()), q(&person.physical_table)
    )).await.unwrap();
    reset_test_action_handler_invocation_count("register-person");
    let retried = call(simple, "handler-failure-retry", input("1123456789012")).await;
    assert_eq!(retried.0, StatusCode::OK, "{}", retried.1);
    assert_eq!(
        test_action_handler_invocation_count("register-person"),
        1,
        "verified candidate reused after confirmed abort"
    );
    let attempts: i64 = database
        .admin
        .query_one(
            "SELECT last_value FROM registry_internal.handler_retry_attempt",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(attempts, 2);
    let retried_counts = counts(&database, &registry).await;
    assert_eq!(retried_counts, vec![4, 1, 6, 5, 4, 4, 6]);
    // Leave time for connection checkout and handler evaluation before the deadline;
    // the longer SQL sleep still forces cancellation after the candidate is evaluated.
    database.admin.batch_execute(&format!(
        "DROP TRIGGER handler_retry_probe ON registry_data.{}; CREATE FUNCTION registry_internal.handler_sleep_probe() RETURNS trigger LANGUAGE plpgsql AS $body$ BEGIN PERFORM pg_sleep(2); RETURN NEW; END $body$; CREATE TRIGGER handler_sleep_probe BEFORE INSERT ON registry_data.{} FOR EACH ROW EXECUTE FUNCTION registry_internal.handler_sleep_probe()",
        q(&person.physical_table), q(&person.physical_table)
    )).await.unwrap();
    reset_test_action_handler_invocation_count("register-person");
    let timeout_app = configured_app(
        &database,
        registry.clone(),
        identity.clone(),
        None,
        Some(Duration::from_secs(1)),
    );
    let timed_out = send(
        timeout_app,
        "POST",
        simple,
        "absolute-deadline",
        input("6123456789012"),
        "person-registrar",
    )
    .await;
    assert_eq!(
        timed_out.0,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        timed_out.1
    );
    assert_eq!(timed_out.1["code"], "service.unavailable");
    assert_eq!(
        test_action_handler_invocation_count("register-person"),
        1,
        "one request deadline extends from evaluated candidate into blocked SQL"
    );
    tokio::time::sleep(Duration::from_millis(2200)).await;
    assert_eq!(
        retried_counts,
        counts(&database, &registry).await,
        "cancelled SQL cannot commit later"
    );
    database
        .admin
        .batch_execute(&format!(
            "DROP TRIGGER handler_sleep_probe ON registry_data.{}",
            q(&person.physical_table)
        ))
        .await
        .unwrap();
    assert_eq!(
        call(simple, "absolute-deadline", input("6123456789012"))
            .await
            .0,
        StatusCode::OK,
        "timed out key and locks remain recoverable"
    );
    let before_evaluator_timeout = counts(&database, &registry).await;
    reset_test_action_handler_invocation_count("register-person");
    registry_breg::action_handler::expire_next_test_action_handler_during_evaluation(
        "register-person",
    );
    let evaluator_timeout_app = configured_app(
        &database,
        registry.clone(),
        identity,
        None,
        Some(Duration::from_millis(400)),
    );
    let evaluator_started = tokio::time::Instant::now();
    let evaluator = send(
        evaluator_timeout_app,
        "POST",
        simple,
        "evaluator-deadline",
        input("7123456789012"),
        "person-registrar",
    );
    let reactor_progress = async {
        while test_action_handler_invocation_count("register-person") == 0 {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(
            evaluator_started.elapsed() < Duration::from_millis(300),
            "a paused bounded evaluator must leave the single-thread reactor responsive"
        );
    };
    let (evaluator_timeout, ()) = tokio::join!(evaluator, reactor_progress);
    assert_eq!(
        evaluator_timeout.0,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        evaluator_timeout.1
    );
    assert_eq!(evaluator_timeout.1["code"], "service.unavailable");
    assert!(
        problem_validator.is_valid(&evaluator_timeout.1),
        "{}",
        evaluator_timeout.1
    );
    assert_eq!(test_action_handler_invocation_count("register-person"), 1);
    assert_eq!(before_evaluator_timeout, counts(&database, &registry).await);
    assert_eq!(call(simple, "evaluator-deadline", input("7123456789012")).await.0, StatusCode::OK, "active evaluator deadline rolls back the receipt lock and permits a healthy subsequent invocation");
    let clear_conditions = call(
        &format!("{coordinated}/target-conditions"),
        "clear-conditions",
        json!({"input":{"registerId":ID}}),
    )
    .await;
    assert_eq!(clear_conditions.0, StatusCode::OK, "{}", clear_conditions.1);
    let mut clear = coordinated_input("8123456789012", "reg-clear", false);
    clear["input"]["clearRegisterContact"] = json!(true);
    clear["preconditions"] = clear_conditions.1["preconditions"].clone();
    let cleared = call(coordinated, "clear-register-contact", clear).await;
    assert_eq!(cleared.0, StatusCode::OK, "{}", cleared.1);
    assert!(
        coordinated_response_validator.is_valid(&cleared.1),
        "{}",
        cleared.1
    );
    assert_eq!(cleared.1["results"].as_object().unwrap().len(), 2);
    assert_eq!(cleared.1["results"]["register"]["revision"], 3);
    let cleared_register = send(
        app.clone(),
        "GET",
        &format!("/v1/records/registers/{ID}?accessProfile=person-reader"),
        "read-cleared-register",
        Value::Null,
        "person-reader",
    )
    .await;
    assert_eq!(cleared_register.0, StatusCode::OK, "{}", cleared_register.1);
    assert!(cleared_register.1["data"]["domainData"]["lastPerson"].is_null());
    database.cleanup().await;
}

#[derive(Clone, Default)]
struct CapturedHandlerLogs(Arc<Mutex<Vec<u8>>>);

impl io::Write for CapturedHandlerLogs {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for CapturedHandlerLogs {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

fn captured_handler_logs() -> &'static CapturedHandlerLogs {
    static LOGS: OnceLock<CapturedHandlerLogs> = OnceLock::new();
    LOGS.get_or_init(|| {
        let logs = CapturedHandlerLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_target(false)
            .with_current_span(false)
            .with_span_list(false)
            .with_writer(logs.clone())
            .finish();
        tracing::subscriber::set_global_default(subscriber).unwrap();
        logs
    })
}

#[tokio::test(flavor = "current_thread")]
async fn action_handler_faults_log_only_compiled_locations_and_static_causes() {
    let _test_guard = HANDLER_TEST_LOCK.lock().await;
    let logs = captured_handler_logs();
    let (database, registry, identity) = setup_with_handler_source(Some(
        r#"fn handle(ctx) {
            if ctx.inputs.identifier == "0123456789012" {
                return #{effects: [#{id: "person", set: #{
                    identifier: ctx.inputs.identifier, "display-name": false
                }}]};
            }
            throw ctx.inputs;
        }"#,
    ))
    .await;
    let app = app(&database, registry.clone(), identity, None);
    logs.0.lock().unwrap().clear();
    let before = counts(&database, &registry).await;
    for identifier in ["0123456789012", "1123456789012"] {
        let mut body = input(identifier);
        body["input"]["givenName"] = json!("private-input-canary");
        let failed = send(
            app.clone(),
            "POST",
            "/v1/actions/register-person",
            identifier,
            body,
            "person-registrar",
        )
        .await;
        assert_eq!(failed.0, StatusCode::INTERNAL_SERVER_ERROR, "{}", failed.1);
        assert_eq!(failed.1["code"], "action.handler_failed");
        assert_eq!(
            failed.1["detail"],
            "The action handler could not produce an accepted result."
        );
        assert!(!failed.1.to_string().contains("private-input-canary"));
    }
    assert_eq!(before, counts(&database, &registry).await);
    let captured = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    for forbidden in [
        "private-input-canary",
        "0123456789012",
        "1123456789012",
        "throw ctx.inputs",
    ] {
        assert!(!captured.contains(forbidden));
    }
    let handler_logs = captured
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|entry| entry["fields"]["message"] == "action handler produced no effects")
        .collect::<Vec<_>>();
    assert_eq!(handler_logs.len(), 2);
    let field_failure = &handler_logs[0]["fields"];
    assert_eq!(field_failure["action_id"], "register-person");
    assert_eq!(field_failure["slot_id"], "person");
    assert_eq!(field_failure["field_id"], "display-name");
    assert_eq!(
        field_failure["cause"],
        "Use a value matching the declared field type and bounds."
    );
    assert_eq!(
        handler_logs[1]["fields"]["handler_failure"],
        "action.handler.execution"
    );
    database.cleanup().await;
}

fn app_with_fault(
    database: &TestDatabase,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: ExpectedRegistryIdentity,
    fault: MutationFaultPoint,
) -> axum::Router {
    app(database, registry, identity, Some(fault))
}

fn event_destinations(
    registry: &registry_breg::CompiledRegistry,
) -> registry_breg::event_destination::ActivatedEventDestinationRegistry {
    let scratch = tempfile::tempdir().expect("private destination fixture");
    let root = scratch
        .path()
        .canonicalize()
        .expect("canonical temporary directory");
    let key = root.join("event-key");
    std::fs::write(&key, [0x65; 32]).expect("synthetic event key writes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))
            .expect("key is private");
    }
    let anchor = root.join("trust-anchor.json");
    std::fs::write(&anchor, "{}").expect("unread anchor placeholder");
    let config = json!({
        "apiVersion":"registry.registrystack.org/breg-runtime/v1alpha1",
        "kind":"BRegRuntimeConfig",
        "listener":{"bind":"127.0.0.1:8080"},
        "identity":{"environment":"local", "instanceId":"facility-test", "databaseId":"facility-test", "databaseInitializationEnvironment":"local"},
        "secretProviders":{"file":{"root":root}},
        "database":{
            "runtimeUrlRef":"secret:file/database-url", "migrationUrlRef":"secret:file/migration-url",
            "pool":{"maxSize":4,"waitTimeoutMilliseconds":1000,"createTimeoutMilliseconds":1000,"recycleTimeoutMilliseconds":1000},
            "roles":{"migration":"registry_migration","runtime":"registry_runtime"}
        },
        "package":{"root":root,"trustAnchorPath":anchor,"compilerSourceRevision":"fixture-1", "activeRevision":format!("sha256:{}", "a".repeat(64)),"activeSequence":1},
        "authentication":{
            "oidc":{
                "issuer":"https://issuer.example", "audience":"urn:breg:handler-test", "allowedAlgorithm":"EdDSA", "accessTokenType":"JWT",
                "scopeClaim":"scope", "scopeSeparator":" ", "maxTokenLifetimeSeconds":300, "leewayMilliseconds":60000,
                "jwksCache":{"cacheTtlSeconds":600,"negativeCacheTtlSeconds":60,"refreshCooldownSeconds":30,"maxDocumentBytes":65536,"requestTimeoutMilliseconds":5000,"outageToleranceSeconds":900}
            },
            "authorityClaims":{"principal":"registry_principal", "purpose":"purpose"}
        },
        "audit":{"hashKeyRef":"secret:file/audit-key"},
        "cursor":{"secretRef":"secret:file/cursor-key", "maxAgeSeconds":300},
        "eventDestinations":{"person-events":{
            "origin":"https://consumer.example/", "path":"/events", "networkProfile":"productionHttps", "dnsFamily":"dualStackStrict",
            "allowedPrivateCidrs":[], "hmacSha256KeyRef":"secret:file/event-key", "classificationCeiling":"internal",
            "deliveryCeilings":{"attemptTimeoutMilliseconds":5000,"maximumAttempts":5}
        }},
        "operationalTimeouts":{"httpRequestMilliseconds":10000,"shutdownGraceMilliseconds":30000,"recordLockMilliseconds":5000,"migrationLockMilliseconds":30000,"migrationStatementMilliseconds":60000}
    });
    registry_breg::runtime_config::parse_runtime_config(&config.to_string())
        .expect("normal destination configuration parses")
        .activate_event_destinations(registry)
        .expect("exact logical destination activates")
}
