// SPDX-License-Identifier: Apache-2.0

//! Full-path acceptance for WASM v1 action handlers on real PostgreSQL: the
//! person-registration acceptance project with its handlers switched to
//! wat-built modules carrying fixed outcome documents, driven through the
//! real BREG API. Authorization, write ceilings, receipt semantics, redaction,
//! and audit content ride the same mutation machinery the Rhai journeys use,
//! so these journeys prove the execution wiring, not a parallel product.

#![cfg(all(feature = "postgres-test", feature = "tooling", feature = "wasm"))]

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
use registry_platform_hooks::HookHandlerSource;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;
use tower::Service as _;
use uuid::Uuid;
use zeroize::Zeroizing;

const ID: &str = "00000000-0000-4000-8000-000000000101";
const PACKAGE: &str = "person-registration-wasm";

/// The fixed outcome documents the guests return: the journey asserts these
/// exact values land in PostgreSQL, proving the guest's bytes (not any Rhai
/// path) produced the effects.
const PERSON_OUTCOME: &str = r#"{"effects":[{"id":"person","set":{"identifier":"9000000000001","display-name":"Mina Wasm"}}]}"#;
const REGISTERED_OUTCOME: &str = r#"{"effects":[{"id":"person","set":{"identifier":"9000000000002","display-name":"Mina Registered"}},{"id":"registration","set":{"registration-code":"W-100","person":{"fromEffect":"person"},"register":{"fromField":"register"}}},{"id":"register","set":{"last-person":{"fromEffect":"person"}}}]}"#;
const REFUSAL_OUTCOME: &str = r#"{"refusal":{"code":"blank-name","field":"given-name"}}"#;

fn hex_escape(bytes: &[u8]) -> String {
    let mut escaped = String::with_capacity(bytes.len() * 4);
    for byte in bytes {
        escaped.push_str(&format!("\\{byte:02x}"));
    }
    escaped
}

/// A wat guest whose outcome window holds `document` verbatim; the same
/// construction the parity corpus uses.
fn outcome_guest(document: &str) -> Vec<u8> {
    let document = document.as_bytes();
    let wat = format!(
        r#"(module
  (memory (export "memory") 1)
  (data (i32.const 1024) "{escaped}")
  (func (export "alloc") (param $len i32) (result i32) (i32.const 4096))
  (func (export "handle") (param $ptr i32) (param $len i32) (result i32) (i32.const 0))
  (func (export "result_ptr") (result i32) (i32.const 1024))
  (func (export "result_len") (result i32) (i32.const {len}))
)"#,
        escaped = hex_escape(document),
        len = document.len(),
    );
    wat::parse_str(&wat).expect("guest wat compiles to a binary module")
}

/// The person-registration acceptance project with its two Rhai handlers
/// switched to fixed-outcome WASM modules, plus a cloned always-refusing
/// action so the journey exercises a declared refusal through a real module.
async fn setup() -> (
    TestDatabase,
    Arc<registry_breg::CompiledRegistry>,
    ExpectedRegistryIdentity,
) {
    let database = TestDatabase::create(8).await;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/acceptance/person-registration-rhai");
    let mut project =
        parse_project_yaml(&std::fs::read(root.join("registry.yaml")).unwrap()).unwrap();
    for (action_id, module_path) in [
        ("register-person", "handlers/register-person.wasm"),
        (
            "register-person-with-registration",
            "handlers/register-person-with-registration.wasm",
        ),
    ] {
        let handler = project
            .actions
            .iter_mut()
            .find(|action| action.id == action_id)
            .unwrap()
            .handler
            .as_mut()
            .unwrap();
        handler.handler = HookHandlerSource::Wasm {
            module: module_path.to_owned(),
            abi: handler.abi().map(str::to_owned),
        };
    }
    // A third action with its own module that always returns the declared
    // refusal, granted to the registrar beside the other invokes.
    let mut refuse = project
        .actions
        .iter()
        .find(|action| action.id == "register-person")
        .unwrap()
        .clone();
    refuse.id = "refuse-person".to_owned();
    let refuse_handler = refuse.handler.as_mut().unwrap();
    refuse_handler.handler = HookHandlerSource::Wasm {
        module: "handlers/refuse-person.wasm".to_owned(),
        abi: refuse_handler.abi().map(str::to_owned),
    };
    project.actions.push(refuse);
    let registrar = project
        .access_profiles
        .iter_mut()
        .find(|profile| profile.id == "person-registrar")
        .unwrap();
    let mut grant = registrar
        .permissions
        .iter()
        .find(|grant| grant.action.as_deref() == Some("register-person"))
        .unwrap()
        .clone();
    grant.action = Some("refuse-person".to_owned());
    registrar.permissions.push(grant);

    let assets = [
        ("handlers/register-person.wasm", PERSON_OUTCOME),
        (
            "handlers/register-person-with-registration.wasm",
            REGISTERED_OUTCOME,
        ),
        ("handlers/refuse-person.wasm", REFUSAL_OUTCOME),
    ]
    .map(|(path, document)| ModuleAssetSource {
        module: None,
        path: path.to_owned(),
        bytes: outcome_guest(document),
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
            instance_id: "wasm-journey-instance",
            database_id: "wasm-journey-database",
            package_revision: "wasm-journey-1",
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

fn configured_app(
    database: &TestDatabase,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: ExpectedRegistryIdentity,
    fault: Option<MutationFaultPoint>,
) -> axum::Router {
    // Assembling the app directly bypasses the server startup path, so this
    // embedder installs the process WASM runtime itself; evaluation without
    // an install is refused.
    registry_breg::wasm_runtime::install_default().expect("the wasm runtime installs");
    let pool = database.runtime_config.build_pool().unwrap();
    let audit =
        database.audit(AuditProfile::production_from_secret_bytes(vec![0x42; 32].into()).unwrap());
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
            VerifiedClaimValue::direct_string("R-1").unwrap(),
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

fn input(identifier: &str) -> Value {
    json!({"input":{"identifier":identifier,"givenName":"  Mina  ","familyName":"  Wasm "}})
}

async fn counts(database: &TestDatabase, registry: &registry_breg::CompiledRegistry) -> Vec<i64> {
    let row = database.admin.query_one(&format!("SELECT (SELECT count(*) FROM registry_data.{}), (SELECT count(*) FROM registry_data.{}), (SELECT count(*) FROM registry_internal.registry_revisions), (SELECT count(*) FROM registry_internal.registry_outbox), (SELECT count(*) FROM registry_internal.registry_idempotency), (SELECT count(*) FROM registry_internal.registry_immediate_action_applications), (SELECT count(*) FROM registry_internal.registry_immediate_action_results)", q(&registry.entities()["person"].physical_table), q(&registry.entities()["registration"].physical_table)), &[]).await.unwrap();
    (0..7).map(|index| row.get(index)).collect()
}

async fn audit_phases(database: &TestDatabase) -> (i64, i64, i64) {
    let records = database.audit_records();
    let count = |phase: &str| {
        i64::try_from(
            records
                .iter()
                .filter(|record| record["phase"] == phase)
                .count(),
        )
        .expect("audit count fits i64")
    };
    (count("attempt"), count("refusal"), count("terminal"))
}

fn q(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wasm_handlers_execute_refuse_replay_and_apply_multi_effect_effects() {
    let (database, registry, identity) = setup().await;
    let app = configured_app(&database, registry.clone(), identity, None);
    let simple = "/v1/actions/register-person";
    let coordinated = "/v1/actions/register-person-with-registration";
    let refusing = "/v1/actions/refuse-person";
    let call = |path: &str, key: &str, body| {
        let app = app.clone();
        let path = path.to_owned();
        let key = key.to_owned();
        async move { send(app, "POST", &path, &key, body, "person-registrar").await }
    };

    // The served contract documents the same failure statuses for a WASM
    // handler action as for a Rhai one.
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
    for status in ["409", "422", "500", "503"] {
        assert!(
            openapi.1["paths"][simple]["post"]["responses"][status].is_object(),
            "wasm handler invoke documents HTTP {status}"
        );
    }

    // A declared refusal from a real module: same problem contract, same
    // label resolution, same statelessness, same unconsumed idempotency key.
    let before = counts(&database, &registry).await;
    let refused = call(refusing, "wasm-refused", input("0123456789012")).await;
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
    let phases = audit_phases(&database).await;
    assert!(phases.0 >= 1, "attempt audit row exists");
    assert!(phases.1 >= 1, "refusal audit row exists");
    assert_eq!(phases.2, 0, "no terminal audit row for a refusal");

    // Authorization is unchanged: an unauthorized scope never reaches a module.
    assert_eq!(
        send(
            app.clone(),
            "POST",
            simple,
            "wasm-refused",
            input("0123456789012"),
            "revoked"
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );

    // The refused key was not consumed: the same key now commits.
    let accepted = call(simple, "wasm-refused", input("0123456789012")).await;
    assert_eq!(accepted.0, StatusCode::OK, "{}", accepted.1);
    let person_id = accepted.1["results"]["person"]["recordId"]
        .as_str()
        .unwrap()
        .to_owned();
    // The guest's fixed outcome landed, not any computed Rhai value.
    let read = send(
        app.clone(),
        "GET",
        &format!("/v1/records/people/{person_id}?accessProfile=person-reader"),
        "read-person",
        Value::Null,
        "person-reader",
    )
    .await;
    assert_eq!(read.0, StatusCode::OK, "{}", read.1);
    assert_eq!(read.1["data"]["domainData"]["identifier"], "9000000000001");
    assert_eq!(read.1["data"]["domainData"]["displayName"], "Mina Wasm");
    let after_accept = counts(&database, &registry).await;
    assert_eq!(after_accept, vec![1, 0, 1, 1, 1, 1, 1]);

    // Receipt replay is byte-identical and writes nothing; the key stays
    // bound to its request digest, so a different body under the same key
    // conflicts exactly as it would for a Rhai handler.
    let replay = call(simple, "wasm-refused", input("0123456789012")).await;
    assert_eq!(accepted.1, replay.1);
    assert_eq!(after_accept, counts(&database, &registry).await);
    let rebound = call(simple, "wasm-refused", input("9999999999999")).await;
    assert_eq!(rebound.0, StatusCode::CONFLICT, "{}", rebound.1);
    assert_eq!(rebound.1["code"], "idempotency.conflict");
    assert_eq!(after_accept, counts(&database, &registry).await);

    // A second commit with a fresh key collides with the guest's fixed
    // identifier exactly as a duplicate Rhai effect would.
    assert_eq!(
        call(simple, "wasm-duplicate", input("1123456789012"))
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(after_accept, counts(&database, &registry).await);

    // The multi-effect guest wires fromEffect and fromField references and
    // the server applies all three writes atomically.
    let conditions = call(
        &format!("{coordinated}/target-conditions"),
        "wasm-conditions",
        json!({"input":{"registerId":ID}}),
    )
    .await;
    assert_eq!(conditions.0, StatusCode::OK, "{}", conditions.1);
    let mut coordinated_input = input("2123456789012");
    coordinated_input["input"]["registerId"] = json!(ID);
    coordinated_input["input"]["registrationCode"] = json!("W-input");
    coordinated_input["input"]["recordRegistration"] = json!(true);
    coordinated_input["input"]["updateRegister"] = json!(true);
    coordinated_input["preconditions"] = conditions.1["preconditions"].clone();
    let complete = call(coordinated, "wasm-complete", coordinated_input).await;
    assert_eq!(complete.0, StatusCode::OK, "{}", complete.1);
    assert_eq!(complete.1["results"].as_object().unwrap().len(), 3);
    let created_person = complete.1["results"]["person"]["recordId"]
        .as_str()
        .unwrap()
        .to_owned();
    let registration_id = complete.1["results"]["registration"]["recordId"]
        .as_str()
        .unwrap()
        .to_owned();
    // The created person is the one the fixed outcome named.
    let registered = send(
        app.clone(),
        "GET",
        &format!("/v1/records/people/{created_person}?accessProfile=person-reader"),
        "read-registered",
        Value::Null,
        "person-reader",
    )
    .await;
    assert_eq!(registered.0, StatusCode::OK, "{}", registered.1);
    assert_eq!(
        registered.1["data"]["domainData"]["identifier"],
        "9000000000002"
    );
    let registration = send(
        app.clone(),
        "GET",
        &format!("/v1/records/registrations/{registration_id}?accessProfile=person-reader"),
        "read-registration",
        Value::Null,
        "person-reader",
    )
    .await;
    assert_eq!(registration.0, StatusCode::OK, "{}", registration.1);
    // The registration code is the guest's fixed value; its person and
    // register references point at the emitted create and the fromField row.
    assert_eq!(
        registration.1["data"]["domainData"]["registrationCode"],
        "W-100"
    );
    let register = send(
        app.clone(),
        "GET",
        &format!("/v1/records/registers/{ID}?accessProfile=person-reader"),
        "read-register",
        Value::Null,
        "person-reader",
    )
    .await;
    assert_eq!(register.0, StatusCode::OK, "{}", register.1);
    assert_eq!(
        registration.1["data"]["domainData"]["person"],
        register.1["data"]["domainData"]["lastPerson"],
        "fromEffect wired the same emitted person into both writes"
    );
    assert_eq!(
        registration.1["data"]["domainData"]["register"],
        json!(ID),
        "fromField resolved the register reference input"
    );
    let after_complete = counts(&database, &registry).await;
    assert_eq!(after_complete[0], 2, "second person created");
    assert_eq!(after_complete[1], 1, "registration created");
    assert_eq!(after_complete[6] - after_accept[6], 3, "three result rows");
    let phases = audit_phases(&database).await;
    assert!(
        phases.2 >= 2,
        "terminal audit rows exist for committed invokes"
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wasm_multi_effect_application_rolls_back_completely_on_a_late_failure() {
    let (database, registry, identity) = setup().await;
    let coordinated = "/v1/actions/register-person-with-registration";
    let before = counts(&database, &registry).await;
    let conditions = send(
        configured_app(&database, registry.clone(), identity.clone(), None),
        "POST",
        &format!("{coordinated}/target-conditions"),
        "wasm-fault-conditions",
        json!({"input":{"registerId":ID}}),
        "person-registrar",
    )
    .await;
    assert_eq!(conditions.0, StatusCode::OK, "{}", conditions.1);
    let mut body = input("3123456789012");
    body["input"]["registerId"] = json!(ID);
    body["input"]["registrationCode"] = json!("W-fault");
    body["input"]["recordRegistration"] = json!(true);
    body["input"]["updateRegister"] = json!(true);
    body["preconditions"] = conditions.1["preconditions"].clone();
    // A late commit-path failure after the guest returned its multi-effect
    // outcome leaves no partial person, registration, register patch, event,
    // or receipt artifact.
    let fault_app = configured_app(
        &database,
        registry.clone(),
        identity.clone(),
        Some(MutationFaultPoint::BeforeTerminalAudit),
    );
    let failed = send(
        fault_app,
        "POST",
        coordinated,
        "wasm-faulted",
        body.clone(),
        "person-registrar",
    )
    .await;
    assert_eq!(failed.0, StatusCode::SERVICE_UNAVAILABLE, "{}", failed.1);
    assert_eq!(before, counts(&database, &registry).await);
    let phases = audit_phases(&database).await;
    assert!(phases.0 >= 1);
    // The fault point sits after the terminal audit row is written but before
    // the data transaction commits, exactly as in the Rhai journey: no data,
    // event, or receipt surface survives.
    // The rollback left the world consistent: the same invocation commits
    // cleanly once the fault is gone, including the register patch.
    let clean = send(
        configured_app(&database, registry.clone(), identity, None),
        "POST",
        coordinated,
        "wasm-faulted-retry",
        body,
        "person-registrar",
    )
    .await;
    assert_eq!(clean.0, StatusCode::OK, "{}", clean.1);
    let after = counts(&database, &registry).await;
    assert_eq!(after[0], before[0] + 1);
    assert_eq!(after[1], before[1] + 1);
    database.cleanup().await;
}

/// The activated webhook destination the acceptance project's declared events
/// expect, the same construction the Rhai handler journey activates.
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
        "audit":{"hashKeyRef":"secret:file/audit-key","path":root.join("audit").join("audit.jsonl")},
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
