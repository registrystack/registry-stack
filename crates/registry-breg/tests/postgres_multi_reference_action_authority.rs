// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "postgres-test", feature = "tooling"))]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{header::AUTHORIZATION, HeaderName, HeaderValue, Method, Request, StatusCode};
use postgres_harness::TestDatabase;
use registry_breg::api::{
    authenticated_router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture,
};
use registry_breg::auth::{AuthorityClaimConfig, RegistryAuthenticator};
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_yaml;
use registry_breg::cursor::CursorCodec;
use registry_breg::fixtures::validate_fixture_journeys;
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    PostgresRecordMutationService, PostgresRecordReadService, RegistryLockKey,
    RegistryStateTestIdentity,
};
use registry_platform_audit::AuditProfile;
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
use registry_platform_testing::{oidc_verifier_config, MockIdp};
use serde_json::{json, Value};
use tower::Service as _;
use zeroize::Zeroizing;

const AUDIENCE: &str = "urn:example:permit-authority-transfer";
const PACKAGE_ID: &str = "permit-authority-transfer";
const INSTANCE_ID: &str = "permit-authority-transfer-test";
const DATABASE_ID: &str = "permit-authority-transfer-test";
const PROJECT: &[u8] =
    include_bytes!("../../../products/breg/fixtures/multi-reference-array-claim/registry.yaml");
const JOURNEYS: &[u8] = include_bytes!(
    "../../../products/breg/fixtures/multi-reference-array-claim/tests/journeys.yaml"
);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_same_type_reference_target_must_match_the_array_claim() {
    let project = parse_project_yaml(PROJECT).expect("multi-reference fixture parses");
    let registry = Arc::new(
        compile_project(&project, &[], CompileProfile::Production)
            .expect("multi-reference fixture compiles for production"),
    );
    validate_fixture_journeys(JOURNEYS, &registry)
        .expect("multi-reference journeys preflight against the exact fixture");

    let action = registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "register-authority-transfer")
        .expect("fixture action compiles");
    assert!(
        action.condition_route.is_none(),
        "link-only reference targets require authority but no concurrency condition"
    );

    let database = TestDatabase::create(6).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("fixture schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "permit-authority-transfer-1",
        },
    )
    .await
    .expect("fixture identity initializes");
    drop(migration);
    migration_task.abort();

    let idp = MockIdp::start().await;
    let authenticator = authenticator(&registry, &idp);
    let app = action_router(&database, registry.clone(), identity, authenticator);
    let loader = token(&idp, None, "registry:authority:load");
    let north = create_authority(
        &app,
        &loader,
        "authority-north",
        "AUTH-NORTH",
        "north-district",
    )
    .await;
    let south = create_authority(
        &app,
        &loader,
        "authority-south",
        "AUTH-SOUTH",
        "south-district",
    )
    .await;
    let input = json!({
        "input": {
            "sourceAuthorityId": north,
            "destinationAuthorityId": south,
            "transferReference": "TRANSFER-001"
        }
    });

    let both = token(
        &idp,
        Some(json!(["north-district", "south-district"])),
        "registry:permit:transfer",
    );
    let succeeded = send(
        &app,
        Method::POST,
        "/v1/actions/register-authority-transfer?accessProfile=transfer-clerk",
        &both,
        Some("both-authorities-allowed"),
        input.clone(),
    )
    .await;
    assert_eq!(succeeded.0, StatusCode::OK, "{}", succeeded.1);
    let receipt = succeeded.1;
    assert_eq!(transfer_count(&database, &registry).await, 1);

    let mut replay_input = input.clone();
    replay_input["preconditions"] = json!({});
    let replay = send(
        &app,
        Method::POST,
        "/v1/actions/register-authority-transfer?accessProfile=transfer-clerk",
        &both,
        Some("both-authorities-allowed"),
        replay_input,
    )
    .await;
    assert_eq!(replay.0, StatusCode::OK, "{}", replay.1);
    assert_eq!(
        replay.1, receipt,
        "omitted and empty preconditions replay the same receipt"
    );
    assert_eq!(
        transfer_count(&database, &registry).await,
        1,
        "the idempotent replay creates no second transfer"
    );

    let north_only = token(
        &idp,
        Some(json!(["north-district"])),
        "registry:permit:transfer",
    );
    let one_refused = send(
        &app,
        Method::POST,
        "/v1/actions/register-authority-transfer?accessProfile=transfer-clerk",
        &north_only,
        Some("one-authority-outside-claim"),
        input.clone(),
    )
    .await;
    assert_eq!(
        one_refused.0,
        StatusCode::PRECONDITION_FAILED,
        "{}",
        one_refused.1
    );
    assert_eq!(transfer_count(&database, &registry).await, 1);

    let south_only = token(
        &idp,
        Some(json!(["south-district"])),
        "registry:permit:transfer",
    );
    let source_refused = send(
        &app,
        Method::POST,
        "/v1/actions/register-authority-transfer?accessProfile=transfer-clerk",
        &south_only,
        Some("source-authority-outside-claim"),
        input.clone(),
    )
    .await;
    assert_eq!(
        source_refused.0,
        StatusCode::PRECONDITION_FAILED,
        "{}",
        source_refused.1
    );
    assert_eq!(transfer_count(&database, &registry).await, 1);

    let missing = token(&idp, None, "registry:permit:transfer");
    let missing_refused = send(
        &app,
        Method::POST,
        "/v1/actions/register-authority-transfer?accessProfile=transfer-clerk",
        &missing,
        Some("missing-array-claim"),
        input.clone(),
    )
    .await;
    assert_eq!(
        missing_refused.0,
        StatusCode::NOT_FOUND,
        "{}",
        missing_refused.1
    );
    assert_eq!(
        missing_refused.1["code"], "resource.not_found",
        "{}",
        missing_refused.1
    );
    assert_eq!(transfer_count(&database, &registry).await, 1);

    let scalar = token(
        &idp,
        Some(json!("north-district")),
        "registry:permit:transfer",
    );
    let wrong_shape_refused = send(
        &app,
        Method::POST,
        "/v1/actions/register-authority-transfer?accessProfile=transfer-clerk",
        &scalar,
        Some("scalar-array-claim"),
        input,
    )
    .await;
    assert_eq!(
        wrong_shape_refused.0,
        StatusCode::UNAUTHORIZED,
        "{}",
        wrong_shape_refused.1
    );
    assert_eq!(
        wrong_shape_refused.1["code"], "authentication.refused",
        "{}",
        wrong_shape_refused.1
    );
    assert_eq!(transfer_count(&database, &registry).await, 1);

    database.cleanup().await;
}

async fn create_authority(
    app: &axum::Router,
    token: &str,
    key: &str,
    code: &str,
    jurisdiction: &str,
) -> String {
    let response = send(
        app,
        Method::POST,
        "/v1/records/public-authorities?accessProfile=reference-loader",
        token,
        Some(key),
        json!({"data":{"code":code,"jurisdiction":jurisdiction}}),
    )
    .await;
    assert_eq!(response.0, StatusCode::CREATED, "{}", response.1);
    response.1["data"]["recordIdentifier"]
        .as_str()
        .expect("created authority has an identifier")
        .to_owned()
}

fn token(idp: &MockIdp, jurisdictions: Option<Value>, scope: &str) -> String {
    let mut claims = json!({
        "aud": AUDIENCE,
        "azp": "fixture-client",
        "registry_actor_kind": "service",
        "registry_principal": "synthetic-permit-operator",
        "registry_purpose": "permit-administration",
        "scope": scope,
    });
    if let Some(jurisdictions) = jurisdictions {
        claims["allowed_jurisdictions"] = jurisdictions;
    }
    idp.mint_token(claims)
}

fn authenticator(
    registry: &registry_breg::CompiledRegistry,
    idp: &MockIdp,
) -> Arc<RegistryAuthenticator> {
    let mut verifier = oidc_verifier_config(idp.issuer(), vec![AUDIENCE.to_owned()]);
    verifier.allowed_clients = vec!["fixture-client".to_owned()];
    Arc::new(
        RegistryAuthenticator::new(
            registry,
            verifier,
            Arc::new(JwksFetcher::new_with_fetch_url_policy(
                idp.jwks_uri(),
                JwksFetcherConfig::defaults(),
                FetchUrlPolicy::dev(),
            )),
            AuthorityClaimConfig::new("registry_principal", Some("registry_purpose".to_owned())),
        )
        .expect("fixture authority claims bind to the compiled registry"),
    )
}

fn action_router(
    database: &TestDatabase,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    authenticator: Arc<RegistryAuthenticator>,
) -> axum::Router {
    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool builds");
    let audit = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x42; 32].into())
            .expect("test owns a keyed audit profile"),
    );
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives");
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x63; 32]), Duration::from_secs(300))
            .expect("test cursor key is valid"),
    );
    let records = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit.clone(),
        cursors.clone(),
    ));
    let read_identity = ReadRuntimeIdentity {
        package_revision: identity.activation_id.clone(),
        schema_fingerprint: identity.schema_fingerprint.clone(),
    };
    let mutations = Arc::new(PostgresRecordMutationService::new(
        pool,
        registry.clone(),
        identity,
        INSTANCE_ID,
        lock_key,
        Duration::from_secs(2),
        audit,
    ));
    authenticated_router(
        Arc::new(
            HttpService::new(
                registry,
                read_identity,
                records,
                Arc::new(AlwaysReady),
                cursors,
            )
            .with_postgres_mutations(mutations),
        ),
        authenticator,
    )
}

async fn send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    token: &str,
    idempotency_key: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::from(body.to_string()))
        .expect("request builds");
    request
        .headers_mut()
        .insert("content-type", HeaderValue::from_static("application/json"));
    request.headers_mut().insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).expect("MockIdp bearer value is valid"),
    );
    if let Some(key) = idempotency_key {
        request.headers_mut().insert(
            HeaderName::from_static("idempotency-key"),
            HeaderValue::from_str(key).expect("test idempotency key is valid"),
        );
    }
    let mut service = app.clone();
    let response = service.call(request).await.expect("router responds");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body is bounded");
    let body = serde_json::from_slice(&bytes).expect("response is JSON");
    (status, body)
}

async fn transfer_count(
    database: &TestDatabase,
    registry: &registry_breg::CompiledRegistry,
) -> i64 {
    let table = &registry.entities()["permit-transfer"].physical_table;
    database
        .admin
        .query_one(
            &format!("SELECT count(*) FROM registry_data.{}", quote(table)),
            &[],
        )
        .await
        .expect("administrator counts synthetic transfers")
        .get(0)
}

fn quote(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

#[derive(Clone)]
struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}
