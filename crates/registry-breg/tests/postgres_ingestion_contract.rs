// SPDX-License-Identifier: Apache-2.0

//! Structural contracts of the published ingestion-run surface.
//!
//! The OpenAPI catalogue each ingestion operation publishes is held to the
//! single maintained mapping the builder consumes
//! (`IngestionApiOperation::problem_codes`), so a producible refusal outside
//! the published contract, or a published entry no route can answer with,
//! fails here instead of reaching generated clients.

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
use registry_breg::compiler::{compile_project, CompileProfile, IngestionApiOperation};
use registry_breg::contract::parse_project_json;
use registry_breg::cursor::CursorCodec;
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    PostgresRecordMutationService, PostgresRecordReadService, RegistryLockKey,
    RegistryStateTestIdentity,
};
use registry_platform_audit::AuditProfile;
use serde_json::{json, Value};
use tower::Service as _;
use zeroize::Zeroizing;

const PRINCIPAL: &str = "ingestion-contract-principal";
const PACKAGE_ID: &str = "ingestion-contract-registry";
const PACKAGE_REVISION: &str = "package-ingestion-contract-1";

/// Every ingestion operation publishes exactly the problem responses the
/// maintained mapping names, each example under the status the problem
/// catalogue registers the code under, and the published operations are
/// exactly the mapping's six: a producible refusal outside the published
/// contract is invisible to generated clients and contract validators, and a
/// published entry no route can answer with is a contract lie.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ingestion_operations_publish_exactly_their_producible_problem_codes() {
    let harness = ContractHarness::create(compiled_registry()).await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let response = harness.get_json("/openapi.json", &claims).await;
    assert_eq!(response.status(), StatusCode::OK);
    let document = body_json(response).await;
    let paths = document["paths"].as_object().expect("paths are objects");

    // marker -> (problem code -> the status its example is published under)
    let mut published: BTreeMap<String, BTreeMap<String, u16>> = BTreeMap::new();
    for (_, methods) in paths {
        for (_, operation) in methods.as_object().expect("path entries are objects") {
            let Some(marker) = operation["x-registry-operation"].as_str() else {
                continue;
            };
            if !marker.starts_with("ingestion") {
                continue;
            }
            let entry = published.entry(marker.to_owned()).or_default();
            for (status, answer) in operation["responses"]
                .as_object()
                .expect("responses are objects")
            {
                let Some(examples) =
                    answer["content"]["application/problem+json"]["examples"].as_object()
                else {
                    // The success answer, which carries no problem examples.
                    continue;
                };
                let status: u16 = status.parse().expect("a response status is a number");
                for (code, example) in examples {
                    assert_eq!(
                        example["value"]["status"], status,
                        "{marker} publishes {code} under the status the example itself carries"
                    );
                    entry.insert(code.clone(), status);
                }
            }
        }
    }

    let expected_markers: BTreeSet<&str> = IngestionApiOperation::ALL
        .iter()
        .map(|operation| operation.openapi_marker())
        .collect();
    assert_eq!(
        published
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        expected_markers,
        "the published ingestion operations are exactly the maintained mapping's"
    );

    for operation in IngestionApiOperation::ALL {
        let expected: BTreeMap<&str, u16> = operation
            .problem_codes()
            .iter()
            .map(|code| (code.code(), code.status()))
            .collect();
        let published_codes = &published[operation.openapi_marker()];
        assert_eq!(
            published_codes
                .iter()
                .map(|(code, status)| (code.as_str(), *status))
                .collect::<BTreeMap<_, _>>(),
            expected,
            "{} publishes exactly its producible problem codes",
            operation.openapi_marker()
        );
    }
}

/// The catalogue's concealed-404 entries are producible on the operations
/// without a run-scoped path: an authenticated caller the compiled batch
/// route does not authorize, here one missing the row-boundary claim, is
/// concealed on run creation and run listing exactly as it is on the
/// run-scoped operations.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unauthorized_callers_are_concealed_on_run_creation_and_listing() {
    let harness = ContractHarness::create(compiled_registry()).await;
    let unbounded = unbounded_operator_claims(PRINCIPAL);

    let created = harness
        .post_json(
            "/v1/records/widgets/ingestion-runs",
            &unbounded,
            json!({"announce": "never-read"}),
        )
        .await;
    assert_eq!(created.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body_json(created).await["code"],
        "resource.not_found",
        "run creation conceals a caller the batch route does not authorize"
    );

    let listed = harness
        .get_json("/v1/records/widgets/ingestion-runs", &unbounded)
        .await;
    assert_eq!(listed.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body_json(listed).await["code"],
        "resource.not_found",
        "run listing conceals a caller the batch route does not authorize"
    );
}

struct ContractHarness {
    app: axum::Router,
}

impl ContractHarness {
    async fn create(registry: Arc<registry_breg::CompiledRegistry>) -> Self {
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
                instance_id: "ingestion-contract-instance",
                database_id: "ingestion-contract-database",
                package_revision: PACKAGE_REVISION,
                package_sequence: 1,
            },
        )
        .await
        .expect("active package identity is initialized");
        migration_task.abort();
        let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives");
        let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x2d; 32].into())
            .expect("test owns a keyed audit profile");
        let pool = database
            .runtime_config
            .build_pool()
            .expect("bounded runtime pool builds");
        let app = build_router(pool, registry, identity, lock_key, audit_profile);
        Self { app }
    }

    async fn post_json(
        &self,
        uri: &str,
        claims: &VerifiedRequestClaims,
        body: Value,
    ) -> axum::response::Response {
        send(
            &self.app,
            Method::POST,
            uri,
            Some(claims.clone()),
            &[("content-type", "application/json")],
            serde_json::to_vec(&body).expect("request JSON"),
        )
        .await
    }

    async fn get_json(
        &self,
        uri: &str,
        claims: &VerifiedRequestClaims,
    ) -> axum::response::Response {
        send(
            &self.app,
            Method::GET,
            uri,
            Some(claims.clone()),
            &[],
            Vec::new(),
        )
        .await
    }
}

fn build_router(
    pool: registry_breg::postgres::RuntimePool,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    profile: AuditProfile,
) -> axum::Router {
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x21; 32]), Duration::from_secs(300))
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

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("JSON response")
}

fn operator_claims(principal: &str, jurisdiction: &str) -> VerifiedRequestClaims {
    claims_with(
        principal,
        BTreeMap::from([(
            "jurisdiction".to_owned(),
            VerifiedClaimValue::direct_string(jurisdiction).expect("direct claim"),
        )]),
    )
}

/// An authenticated operator carrying no row-boundary claim, so the compiled
/// batch route refuses admission and the handlers answer concealed.
fn unbounded_operator_claims(principal: &str) -> VerifiedRequestClaims {
    claims_with(principal, BTreeMap::new())
}

fn claims_with(
    principal: &str,
    claims: BTreeMap<String, VerifiedClaimValue>,
) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        principal,
        BTreeSet::new(),
        Some("case-management".to_owned()),
        claims,
    )
    .expect("verified claims are bounded")
}

/// The compact batch-driven fixture the contract tests build their surface
/// from: one entity whose batch route the operator profile drives, with the
/// anonymous reader the concealment proofs stay outside.
const FIXTURE: &str = r#"{
  "apiVersion":"registry.registrystack.org/v1alpha1",
  "kind":"RegistryProject",
  "registry":{"id":"ingestion-contract-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://contract.example.test"},
  "entities":[{
    "id":"widget","primaryDataset":"test-dataset","route":"widgets","mutationMode":"mutable","classification":"public",
    "batch":{"maximumItems":3,"maximumBytes":8192},
    "constraints":[{"kind":"unique","fields":["label"]}],
    "fields":[
      {"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"public"},
      {"id":"label","type":"string","maxLength":128,"required":true,"classification":"public"},
      {"id":"quantity","type":"int64","required":true,"classification":"public"}
    ]
  }],
  "accessProfiles":[{
    "id":"operator","default":true,"principalClaim":"registry_principal",
    "requiredPurposes":["case-management"],
    "permissions":[{
      "entity":"widget","operations":["create","get","patch","batch"],
      "readableFields":["jurisdiction","label","quantity"],
      "writableFields":["jurisdiction","label","quantity"],
      "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
    }]
  },{
    "id":"anonymous-reader","anonymous":true,
    "permissions":[{
      "entity":"widget","operations":["get","list"],
      "readableFields":["label"],
      "rowBoundaries":[]
    }]
  }]
}"#;

fn compiled_registry() -> Arc<registry_breg::CompiledRegistry> {
    let project = parse_project_json(FIXTURE.as_bytes()).expect("contract fixture parses");
    Arc::new(
        compile_project(&project, &[], CompileProfile::Authoring)
            .expect("contract fixture compiles to trusted inventories"),
    )
}
