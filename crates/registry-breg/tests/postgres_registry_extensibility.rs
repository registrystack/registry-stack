// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "postgres-test", feature = "tooling"))]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use postgres_harness::TestDatabase;
use registry_breg::api::{
    authenticated_router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture,
};
use registry_breg::auth::{AuthorityClaimConfig, RegistryAuthenticator};
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::{parse_module_yaml, parse_project_yaml};
use registry_breg::cursor::CursorCodec;
use registry_breg::event_destination::ActivatedEventDestinationRegistry;
use registry_breg::mutation::MutationFaultPoint;
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    PostgresRecordMutationService, PostgresRecordReadService, RegistryLockKey,
    RegistryStateTestIdentity,
};
use registry_breg::runtime_config::parse_runtime_config;
use registry_platform_audit::AuditProfile;
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
use registry_platform_testing::{oidc_verifier_config, MockIdp};
use serde_json::{json, Value};
use tower::ServiceExt as _;
use zeroize::Zeroizing;

const AUDIENCE: &str = "urn:breg:facility-registry-actions";
const REGISTRY_ID: &str = "facility-registry-actions";
const PROJECT: &[u8] =
    include_bytes!("../../../products/breg/fixtures/facility-registry-actions/registry.yaml");
const MODULE: &[u8] = include_bytes!(
    "../../../products/breg/fixtures/facility-registry-actions/modules/facility-registry-actions-core/module.yaml"
);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn facility_registration_transfer_and_events_use_governed_actions() {
    let project = parse_project_yaml(PROJECT).expect("authored project parses");
    let module = parse_module_yaml(MODULE).expect("authored module parses");
    let registry = Arc::new(
        compile_project(&project, &[module], CompileProfile::Production)
            .expect("exact locked fixture compiles without source repair"),
    );
    registry_breg::fixtures::validate_fixture_journeys(
        include_bytes!(
            "../../../products/breg/fixtures/facility-registry-actions/tests/journeys.yaml"
        ),
        &registry,
    )
    .expect("authored journey preflights against the exact compiled contract");
    let database = TestDatabase::create(8).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("fixture schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: REGISTRY_ID,
            environment: "acceptance",
            instance_id: "facility-registry-actions-fixture",
            database_id: "facility-registry-actions-test",
            package_revision: "facility-actions-1",
            package_sequence: 1,
        },
    )
    .await
    .expect("fixture identity initializes");
    drop(migration);
    migration_task.abort();
    let idp = MockIdp::start().await;
    let app = build_app(&database, registry.clone(), identity.clone(), &idp, None);
    let administrator = token(&idp, "administrator", "registry:operator:manage", json!({}));
    let operator = send(
        &app,
        Method::POST,
        "/v1/records/operators?accessProfile=operator-administrator",
        &administrator,
        Some("operator-create"),
        json!({"data":{"operatorCode":"OP-001", "status":"active"}}),
    )
    .await;
    assert_eq!(operator.0, StatusCode::CREATED, "{}", operator.1);
    let operator_id = operator.1["data"]["recordIdentifier"]
        .as_str()
        .expect("operator id");
    let inactive = send(
        &app,
        Method::POST,
        "/v1/records/operators?accessProfile=operator-administrator",
        &administrator,
        Some("operator-inactive"),
        json!({"data":{"operatorCode":"OP-002", "status":"inactive"}}),
    )
    .await;
    assert_eq!(inactive.0, StatusCode::CREATED, "{}", inactive.1);
    let registrar = token(&idp, "owner-a", "registry:facility:register", json!({}));
    let registration = json!({"input": {
        "facilityCode":"FAC-001", "label":"Synthetic facility", "owner":"owner-a",
        "operatorId":operator_id
    }});
    let before = counts(&database, &registry).await;
    let mut inactive_registration = registration.clone();
    inactive_registration["input"]["operatorId"] = inactive.1["data"]["recordIdentifier"].clone();
    let refused = send(
        &app,
        Method::POST,
        "/v1/actions/register-facility",
        &registrar,
        Some("inactive-registration"),
        inactive_registration,
    )
    .await;
    assert_eq!(refused.0, StatusCode::PRECONDITION_FAILED, "{}", refused.1);
    assert_eq!(counts(&database, &registry).await, before);

    // A late transaction failure cannot leave either record or its outbox event.
    let fault_app = build_app(
        &database,
        registry.clone(),
        identity,
        &idp,
        Some(MutationFaultPoint::BeforeCommit),
    );
    let failed = send(
        &fault_app,
        Method::POST,
        "/v1/actions/register-facility",
        &registrar,
        Some("registration-rollback"),
        registration.clone(),
    )
    .await;
    assert_eq!(failed.0, StatusCode::SERVICE_UNAVAILABLE, "{}", failed.1);
    assert_eq!(counts(&database, &registry).await, before);

    let registered = send(
        &app,
        Method::POST,
        "/v1/actions/register-facility",
        &registrar,
        Some("registration"),
        registration.clone(),
    )
    .await;
    assert_eq!(registered.0, StatusCode::OK, "{}", registered.1);
    let facility_id = registered.1["results"]["facility"]["recordId"]
        .as_str()
        .expect("facility result");
    let assignment_id = registered.1["results"]["initial-assignment"]["recordId"]
        .as_str()
        .expect("assignment result");
    let after_registration = counts(&database, &registry).await;
    assert_eq!(after_registration, [1, 1, before[2] + 2, 2, 1]);
    let assignment = &registry.entities()["initial-operator-assignment"];
    let links = database
        .admin
        .query_one(
            &format!(
                "SELECT {}::text, {}::text FROM registry_data.{} WHERE record_id = $1::uuid",
                q(&assignment.fields["facility"].physical_name),
                q(&assignment.fields["operator"].physical_name),
                q(&assignment.physical_table),
            ),
            &[&uuid::Uuid::parse_str(assignment_id).expect("assignment UUID")],
        )
        .await
        .expect("administrator inspects only synthetic reference links");
    assert_eq!(links.get::<_, String>(0), facility_id);
    assert_eq!(links.get::<_, String>(1), operator_id);
    let replay = send(
        &app,
        Method::POST,
        "/v1/actions/register-facility",
        &registrar,
        Some("registration"),
        registration,
    )
    .await;
    assert_eq!(
        replay, registered,
        "same operation recovers the captured receipt"
    );
    assert_eq!(counts(&database, &registry).await, after_registration);

    // This exact JWT is reused before and after transfer, with no token refresh.
    let old_owner = token(&idp, "owner-a", "registry:facility:read", json!({}));
    let new_owner = token(&idp, "owner-b", "registry:facility:read", json!({}));
    let facility_uri = format!("/v1/records/facilities/{facility_id}?accessProfile=facility-owner");
    assert_eq!(
        send(
            &app,
            Method::GET,
            &facility_uri,
            &old_owner,
            None,
            Value::Null
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        send(
            &app,
            Method::GET,
            &facility_uri,
            &new_owner,
            None,
            Value::Null
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let direct_patch = send(
        &app,
        Method::PATCH,
        &facility_uri,
        &old_owner,
        None,
        json!({"changes":[{"field":"owner","value":"owner-b"}]}),
    )
    .await;
    assert_eq!(
        direct_patch.0,
        StatusCode::NOT_FOUND,
        "owner read grant is not write authority"
    );

    let transfer_uri = "/v1/actions/transfer-facility?accessProfile=facility-transfer";
    let condition_uri =
        "/v1/actions/transfer-facility/target-conditions?accessProfile=facility-transfer";
    let unbound_broker = token(&idp, "broker", "registry:facility:transfer", json!({}));
    let missing_claim = send(
        &app,
        Method::POST,
        condition_uri,
        &unbound_broker,
        None,
        json!({"input":{"facilityId":facility_id}}),
    )
    .await;
    assert_eq!(missing_claim.0, StatusCode::NOT_FOUND);
    let restricted_broker = token(
        &idp,
        "broker",
        "registry:facility:transfer",
        json!({"allowed_owners":["owner-a"]}),
    );
    let broker = token(
        &idp,
        "broker",
        "registry:facility:transfer",
        json!({"allowed_owners":["owner-a", "owner-b"]}),
    );
    let condition = send(
        &app,
        Method::POST,
        condition_uri,
        &broker,
        None,
        json!({"input":{"facilityId":facility_id}}),
    )
    .await;
    assert_eq!(condition.0, StatusCode::OK, "{}", condition.1);
    let transfer = json!({"input":{"facilityId":facility_id,"owner":"owner-b"}, "preconditions":condition.1["preconditions"]});
    let restricted_condition = send(
        &app,
        Method::POST,
        condition_uri,
        &restricted_broker,
        None,
        json!({"input":{"facilityId":facility_id}}),
    )
    .await;
    assert_eq!(restricted_condition.0, StatusCode::OK);
    let mut restricted_transfer = transfer.clone();
    restricted_transfer["preconditions"] = restricted_condition.1["preconditions"].clone();
    let refused_transfer = send(
        &app,
        Method::POST,
        transfer_uri,
        &restricted_broker,
        Some("refused-transfer"),
        restricted_transfer,
    )
    .await;
    assert_eq!(
        refused_transfer.0,
        StatusCode::PRECONDITION_FAILED,
        "{}",
        refused_transfer.1
    );
    assert_eq!(counts(&database, &registry).await, after_registration);
    let transferred = send(
        &app,
        Method::POST,
        transfer_uri,
        &broker,
        Some("transfer"),
        transfer,
    )
    .await;
    assert_eq!(transferred.0, StatusCode::OK, "{}", transferred.1);
    assert_eq!(
        send(
            &app,
            Method::GET,
            &facility_uri,
            &old_owner,
            None,
            Value::Null
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(
            &app,
            Method::GET,
            &facility_uri,
            &new_owner,
            None,
            Value::Null
        )
        .await
        .0,
        StatusCode::OK
    );
    let old_list = send(
        &app,
        Method::GET,
        "/v1/records/facilities?accessProfile=facility-owner",
        &old_owner,
        None,
        Value::Null,
    )
    .await;
    assert_eq!(old_list.0, StatusCode::OK, "{}", old_list.1);
    assert_eq!(old_list.1["items"].as_array().expect("list items").len(), 0);
    assert_eq!(
        counts(&database, &registry).await,
        [1, 1, before[2] + 3, 3, 2]
    );
    let events = database.admin.query(
        "SELECT event_type, application_reference IS NOT NULL FROM registry_internal.registry_outbox ORDER BY event_type",
        &[],
    ).await.expect("administrator inspects committed declared event provenance");
    assert_eq!(
        events
            .iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<Vec<_>>(),
        [
            "facility-owner-changed-v1",
            "facility-registered-v1",
            "initial-operator-assigned-v1",
        ]
    );
    assert!(events.iter().all(|row| row.get::<_, bool>(1)));
    drop(app);
    drop(fault_app);
    database.cleanup().await;
}

fn token(idp: &MockIdp, principal: &str, scope: &str, extra: Value) -> String {
    let mut claims = json!({
        "aud":AUDIENCE, "registry_principal":principal, "scope":scope,
        "purpose":"facility-administration"
    });
    for (key, value) in extra.as_object().expect("extra claims object") {
        claims[key] = value.clone();
    }
    idp.mint_token(claims)
}

async fn send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    token: &str,
    key: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json");
    if let Some(key) = key {
        request = request.header("idempotency-key", key);
    }
    let response = app
        .clone()
        .oneshot(
            request
                .body(Body::from(if body.is_null() {
                    Vec::new()
                } else {
                    serde_json::to_vec(&body).expect("request serializes")
                }))
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("bounded body");
    (
        status,
        serde_json::from_slice(&bytes).expect("response JSON"),
    )
}

fn q(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

async fn counts(database: &TestDatabase, registry: &registry_breg::CompiledRegistry) -> [i64; 5] {
    let row = database
        .admin
        .query_one(
            &format!(
                "SELECT (SELECT count(*) FROM registry_data.{}),
                (SELECT count(*) FROM registry_data.{}),
                (SELECT count(*) FROM registry_internal.registry_revisions),
                (SELECT count(*) FROM registry_internal.registry_outbox),
                (SELECT count(*) FROM registry_internal.registry_immediate_action_applications)",
                q(&registry.entities()["facility"].physical_table),
                q(&registry.entities()["initial-operator-assignment"].physical_table),
            ),
            &[],
        )
        .await
        .expect("administrator inspects synthetic committed effects");
    [row.get(0), row.get(1), row.get(2), row.get(3), row.get(4)]
}

fn build_app(
    database: &TestDatabase,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    idp: &MockIdp,
    fault: Option<MutationFaultPoint>,
) -> axum::Router {
    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool");
    let lock_key = RegistryLockKey::derive(REGISTRY_ID).expect("registry lock key");
    let audit = AuditProfile::production_from_secret_bytes(vec![0x61; 32].into())
        .expect("keyed test audit");
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x43; 32]), Duration::from_secs(300))
            .expect("test cursor codec"),
    );
    let reads = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit.clone(),
        cursors.clone(),
    ));
    let mutations = PostgresRecordMutationService::new_with_event_destinations(
        pool,
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit,
        Some(Arc::new(event_destinations(&registry))),
    );
    let mutations = if let Some(fault) = fault {
        mutations.with_fault_for_test(fault)
    } else {
        mutations
    };
    let service = Arc::new(
        HttpService::new(
            registry.clone(),
            ReadRuntimeIdentity {
                package_revision: identity.package_revision,
                schema_fingerprint: identity.schema_fingerprint,
            },
            reads,
            Arc::new(AlwaysReady),
            cursors,
        )
        .with_postgres_mutations(Arc::new(mutations)),
    );
    let key_source = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        idp.jwks_uri(),
        JwksFetcherConfig::defaults(),
        FetchUrlPolicy::dev(),
    ));
    let authenticator = Arc::new(
        RegistryAuthenticator::new(
            &registry,
            oidc_verifier_config(idp.issuer(), vec![AUDIENCE.to_owned()]),
            key_source,
            AuthorityClaimConfig::new("registry_principal", Some("purpose".to_owned())),
        )
        .expect("OIDC profile matches compiled registry"),
    );
    authenticated_router(service, authenticator)
}

struct AlwaysReady;
impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

// Bind the fixture's logical destination through the normal runtime parser.
// This test captures events only; it never sends a network request.
fn event_destinations(
    registry: &registry_breg::CompiledRegistry,
) -> ActivatedEventDestinationRegistry {
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
                "issuer":"https://issuer.example", "audience":AUDIENCE, "allowedAlgorithm":"EdDSA", "accessTokenType":"JWT",
                "scopeClaim":"scope", "scopeSeparator":" ", "maxTokenLifetimeSeconds":300, "leewayMilliseconds":60000,
                "jwksCache":{"cacheTtlSeconds":600,"negativeCacheTtlSeconds":60,"refreshCooldownSeconds":30,"maxDocumentBytes":65536,"requestTimeoutMilliseconds":5000,"outageToleranceSeconds":900}
            },
            "authorityClaims":{"principal":"registry_principal", "purpose":"purpose"}
        },
        "audit":{"hashKeyRef":"secret:file/audit-key"},
        "cursor":{"secretRef":"secret:file/cursor-key", "maxAgeSeconds":300},
        "eventDestinations":{"facility-events":{
            "origin":"https://consumer.example/", "path":"/events", "networkProfile":"productionHttps", "dnsFamily":"dualStackStrict",
            "allowedPrivateCidrs":[], "hmacSha256KeyRef":"secret:file/event-key", "classificationCeiling":"internal",
            "deliveryCeilings":{"attemptTimeoutMilliseconds":5000,"maximumAttempts":5}
        }},
        "operationalTimeouts":{"httpRequestMilliseconds":10000,"shutdownGraceMilliseconds":30000,"recordLockMilliseconds":5000,"migrationLockMilliseconds":30000,"migrationStatementMilliseconds":60000}
    });
    parse_runtime_config(&config.to_string())
        .expect("normal destination configuration parses")
        .activate_event_destinations(registry)
        .expect("exact logical destination activates")
}
