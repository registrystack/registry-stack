// SPDX-License-Identifier: Apache-2.0

//! Opt-in proof using tokens issued by the stock local issuer and Keycloak.
//! Run products/breg/scripts/test-issuer-portability.py. The recording backend
//! proves authorization before record I/O; PostgreSQL enforcement has its own gate.

#![cfg(feature = "runtime")]

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use jsonwebtoken::Algorithm;
use registry_breg::api::{
    authenticated_router, HeldReadResponse, HttpService, ReadRuntimeIdentity, ReadServiceError,
    ReadinessProbe, RecordReadRequest, RecordReadService, ServiceFuture,
};
use registry_breg::auth::{AuthorityClaimConfig, RegistryAuthenticator};
use registry_breg::cursor::CursorCodec;
use registry_breg::{compile_project, parse_project_yaml, CompileProfile, CompiledRegistry};
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifierConfig};
use serde::Deserialize;
use serde_json::json;
use tower::ServiceExt as _;
use zeroize::Zeroizing;

const PRINCIPAL: &str = "urn:institution:service-clerk";
const HUMAN_PRINCIPAL: &str = "urn:institution:human-clerk";
const PURPOSE: &str = "registry-administration";

#[derive(Deserialize)]
struct Issuer {
    issuer: String,
    algorithm: Algorithm,
    token_type: String,
    jwks_file: String,
}

#[derive(Deserialize)]
struct Journey {
    audience: String,
    stock: Issuer,
    keycloak: Issuer,
}

#[derive(Default)]
struct Records(Mutex<Vec<RecordReadRequest>>);

impl RecordReadService for Records {
    fn get(
        &self,
        request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        self.0.lock().expect("record requests").push(request);
        Box::pin(async { Ok(None) })
    }

    fn list(
        &self,
        _request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<HeldReadResponse, ReadServiceError>> {
        panic!("the journey has no list grant")
    }

    fn lookup(
        &self,
        _request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        panic!("the journey has no lookup grant")
    }
}

struct Ready;

impl ReadinessProbe for Ready {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

fn authenticator(
    registry: &CompiledRegistry,
    root: &Path,
    issuer: &Issuer,
    audience: &str,
) -> Arc<RegistryAuthenticator> {
    let jwks =
        serde_json::from_slice(&std::fs::read(root.join(&issuer.jwks_file)).expect("JWKS file"))
            .expect("public JWKS");
    let keys = Arc::new(JwksFetcher::new_static(jwks, JwksFetcherConfig::defaults()));
    let mut verifier = TokenVerifierConfig::access_token_profile(
        &issuer.issuer,
        vec![audience.to_owned()],
        vec![issuer.algorithm],
        vec![issuer.token_type.clone()],
    );
    verifier.max_token_lifetime = Some(Duration::from_secs(300));
    Arc::new(
        RegistryAuthenticator::new(
            registry,
            verifier,
            keys,
            AuthorityClaimConfig::new("registry_principal", Some("registry_purpose".to_owned())),
        )
        .expect("explicit issuer configuration"),
    )
}

async fn request(app: &axum::Router, token: &str, method: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri("/v1/records/records/00000000-0000-4000-8000-000000000001?accessProfile=clerk")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("router response")
        .status()
}

#[tokio::test]
#[ignore = "requires disposable issuers; run products/breg/scripts/test-issuer-portability.py"]
async fn stock_and_keycloak_preserve_authority_and_cutover_rejects_the_old_issuer() {
    let root = std::env::var_os("BREG_ISSUER_JOURNEY_DIR").expect("runner material directory");
    let root = Path::new(&root);
    let journey: Journey =
        serde_json::from_slice(&std::fs::read(root.join("journey.json")).expect("runner manifest"))
            .expect("manifest JSON");
    let project = parse_project_yaml(include_bytes!(
        "../../../products/breg/acceptance/issuer-portability/registry.yaml"
    ))
    .expect("portable project parses");
    let registry = Arc::new(
        compile_project(&project, &[], CompileProfile::Authoring)
            .expect("portable project compiles"),
    );
    let stock = authenticator(&registry, root, &journey.stock, &journey.audience);
    let keycloak = authenticator(&registry, root, &journey.keycloak, &journey.audience);
    let tokens: Vec<Zeroizing<String>> = [
        "stock.token",
        "service.token",
        "human.token",
        "no-scope.token",
    ]
    .iter()
    .map(|name| Zeroizing::new(std::fs::read_to_string(root.join(name)).expect("issued token")))
    .collect();
    for (index, issuer) in [(0, &stock), (1, &keycloak), (2, &keycloak)] {
        println!("Checking issuer token case {index}");
        issuer
            .authenticate(&tokens[index])
            .await
            .expect("real issued token verifies");
        let principal = if index == 2 {
            HUMAN_PRINCIPAL
        } else {
            PRINCIPAL
        };
        let records = Arc::new(Records::default());
        let service = Arc::new(HttpService::new(
            Arc::clone(&registry),
            ReadRuntimeIdentity {
                package_revision: "issuer-journey".into(),
                schema_fingerprint: "issuer-journey".into(),
            },
            records.clone(),
            Arc::new(Ready),
            Arc::new(
                CursorCodec::new(Zeroizing::new(vec![0x43; 32]), Duration::from_secs(300))
                    .expect("cursor key"),
            ),
        ));
        let app = authenticated_router(service, Arc::clone(issuer));
        assert_eq!(
            request(&app, &tokens[index], "GET").await,
            StatusCode::NOT_FOUND
        );
        {
            let requests = records.0.lock().expect("record requests");
            assert_eq!(
                requests.len(),
                1,
                "authorized GET reaches the recording backend"
            );
            let context = &requests[0].context;
            assert_eq!(context.principal(), Some(principal));
            assert_eq!(context.purpose(), Some(PURPOSE));
            assert_eq!(context.row_boundaries().len(), 1);
            assert_eq!(
                context.row_boundaries()[0].values(),
                &BTreeSet::from(["district-a".to_owned()])
            );
        }
        assert_eq!(
            request(&app, &tokens[index], "DELETE").await,
            StatusCode::NOT_FOUND
        );
        if index > 0 {
            assert_eq!(
                request(&app, &tokens[0], "GET").await,
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                request(&app, &tokens[3], "GET").await,
                StatusCode::NOT_FOUND
            );
        }
        assert_eq!(
            records.0.lock().expect("record requests").len(),
            1,
            "refused requests never reach records"
        );
    }
    assert!(
        stock.authenticate(&tokens[1]).await.is_err(),
        "new issuer needs explicit trust"
    );
    assert!(
        authenticator(
            &registry,
            root,
            &journey.keycloak,
            "urn:breg:another-resource"
        )
        .authenticate(&tokens[2])
        .await
        .is_err(),
        "another resource never accepts the token"
    );
    println!(
        "{}",
        json!({"stockIssuer": "passed", "keycloakService": "passed", "keycloakAuthorizationCodePkce": "passed", "issuerCutover": "passed", "databaseEnforcement": "separate-gate"})
    );
}

#[cfg(feature = "postgres-test")]
#[path = "support/client_http.rs"]
#[allow(dead_code)]
mod client_http;
#[cfg(feature = "postgres-test")]
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

#[cfg(feature = "postgres-test")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires disposable issuers and PostgreSQL; run test-issuer-portability.py --with-postgres"]
async fn stock_to_keycloak_preserves_native_proposal_issuer_isolation() {
    use registry_breg::contract::parse_project_json;
    use registry_breg_client::{
        BRegActionInvocationRequest, BRegCreateRequest, BRegDirectWrite, BRegIdempotencyKey,
        BRegProposalState, BRegRecordFormat,
    };
    let root = std::env::var_os("BREG_ISSUER_JOURNEY_DIR").expect("runner material directory");
    let root = Path::new(&root);
    let journey: Journey =
        serde_json::from_slice(&std::fs::read(root.join("journey.json")).unwrap()).unwrap();
    // A native governed Action replaces the retired Request-as-Record approval fixture.
    let source = json!({"apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
        "project":{"id":"issuer-proposal","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://issuer-proposal.example.test"},
        "datasets":[{"id":"records"}],"recordTypes":[{"id":"record","primaryDataset":"records","route":"records","mutationMode":"mutable",
        "fields":[{"id":"label","type":"string","required":true,"maximumLength":100,"classification":"internal"},
        {"id":"district","type":"string","required":true,"maximumLength":100,"classification":"internal"}]}],
        "actions":[{"id":"correct-label","execution":{"mode":"proposal","proposal":{"review":{"type":"none"},"application":{"mode":"manual"},"retention":{"mode":"operator-erase"}}},
        "inputs":[{"id":"target","type":"reference","target":"record","required":true,"classification":"internal"},
        {"id":"value","type":"string","required":true,"maximumLength":100,"classification":"internal"}],
        "commitGuards":{"targets":[{"input":"target","revision":"unchanged"}]},
        "plan":{"type":"fixed","effects":[{"id":"label","target":{"fromInput":"target"},"operation":"patch","set":{"label":{"fromInput":"value"}}}]}}],
        "accessProfiles":[{"id":"clerk","default":true,"principalClaim":"registry_principal","requiredScopes":["registry:read"],"requiredPurposes":["registry-administration"],
        "permissions":{"records":[{"recordType":"record","operations":["create","get"],"readableFields":["label","district"],"writableFields":["label","district"],
        "rowBoundaries":[{"field":"district","claim":"districts","operator":"equals"}]}],
        "actions":[{"action":"correct-label","operations":["start"],"targets":[{"recordType":"record","rowBoundaries":[{"field":"district","claim":"districts","operator":"equals"}]}]}],
        "proposals":[{"action":"correct-label","operations":["get","submit","apply"],"ownership":"caller","targets":[{"recordType":"record","rowBoundaries":[{"field":"district","claim":"districts","operator":"equals"}]}]}]}}]});
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    let registry = compile_project(&project, &[], CompileProfile::Authoring).unwrap();
    let stock = authenticator(&registry, root, &journey.stock, &journey.audience);
    let cutover = authenticator(&registry, root, &journey.keycloak, &journey.audience);
    let stock_token = Zeroizing::new(std::fs::read_to_string(root.join("stock.token")).unwrap());
    let service_token =
        Zeroizing::new(std::fs::read_to_string(root.join("service.token")).unwrap());
    let human_token = Zeroizing::new(std::fs::read_to_string(root.join("human.token")).unwrap());
    let before = stock.authenticate(&stock_token).await.unwrap();
    let after = cutover.authenticate(&service_token).await.unwrap();
    assert!(
        cutover.authenticate(&stock_token).await.is_err(),
        "cutover rejects the old issuer before Proposal access"
    );
    let stock_policy =
        registry_breg::idempotency::IdempotencyPolicy::new(journey.stock.issuer.clone(), 7)
            .unwrap();
    let fixture =
        client_http::ClientFixture::start_with_mutations(registry, before, move |mutations| {
            mutations.with_idempotency_policy(stock_policy)
        })
        .await;
    let old = &fixture.http.client;
    let metadata = old.registry_contract(Some("clerk")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.record.create", "clerk")
        .unwrap()
    else {
        panic!("create")
    };
    let key = |value| BRegIdempotencyKey::parse(value).unwrap();
    let record = old
        .create_record(
            &create,
            &BRegCreateRequest::new(
                json!({"label":"Before","district":"district-a"})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .unwrap(),
            &key("issuer-record"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let action = metadata
        .value
        .select_action("correct-label", "clerk")
        .unwrap();
    let input = BRegActionInvocationRequest::new(
        &action,
        json!({"target":record.value.data.record_identifier,"value":"After"})
            .as_object()
            .unwrap()
            .clone(),
        None,
    )
    .unwrap();
    let draft = old
        .start_proposal(&action, &input, &key("issuer-proposal"))
        .await
        .unwrap()
        .value;
    let submitted = old
        .execute_proposal(
            &old.prepare_proposal(&draft, "submit", json!({}), &key("issuer-submit"))
                .unwrap(),
        )
        .await
        .unwrap()
        .value;
    let apply = old.prepare_proposal(&submitted,"apply",json!({"submissionVersion":1,"effectDigest":submitted.effect_digest().unwrap(),"reason":"synthetic issuer cutover"}),&key("issuer-apply")).unwrap();
    let applied = old.execute_proposal(&apply).await.unwrap().value;
    assert_eq!(applied.state(), BRegProposalState::Applied);
    let pending = old
        .start_proposal(&action, &input, &key("issuer-pending"))
        .await
        .unwrap()
        .value;
    let mutations_for = |issuer: &str| {
        registry_breg::postgres::PostgresRecordMutationService::new(
            fixture.pool.clone(),
            fixture.registry.clone(),
            fixture.identity.clone(),
            "client-capability-test",
            registry_breg::postgres::RegistryLockKey::derive(fixture.registry.registry_id())
                .unwrap(),
            Duration::from_secs(2),
            fixture.audit_capture.audit(
                registry_platform_audit::AuditProfile::production_from_secret_bytes(
                    vec![0x61; 32].into(),
                )
                .unwrap(),
            ),
        )
        .with_idempotency_policy(
            registry_breg::idempotency::IdempotencyPolicy::new(issuer, 7).unwrap(),
        )
    };
    let same_issuer = fixture
        .client_with_mutations(
            stock.authenticate(&stock_token).await.unwrap(),
            mutations_for(&journey.stock.issuer),
        )
        .await;
    let replay = same_issuer
        .client
        .execute_proposal(&apply)
        .await
        .unwrap()
        .value;
    assert_eq!(
        serde_json::to_value(replay).unwrap(),
        serde_json::to_value(&applied).unwrap(),
        "a reconstructed runtime under the same issuer recovers the exact receipt"
    );
    let new = fixture
        .client_with_mutations(after, mutations_for(&journey.keycloak.issuer))
        .await;
    assert!(
        new.client.read_proposal(&applied).await.is_err(),
        "the same textual principal from another issuer cannot inherit Proposal ownership"
    );
    assert!(
        new.client.execute_proposal(&apply).await.is_err(),
        "another issuer cannot replay a committed Proposal receipt"
    );
    let continue_pending = new
        .client
        .prepare_proposal(&pending, "submit", json!({}), &key("issuer-continued"))
        .unwrap();
    assert!(
        new.client
            .execute_proposal(&continue_pending)
            .await
            .is_err(),
        "another issuer cannot continue an old pending Proposal"
    );
    let human = fixture
        .client_with_mutations(
            cutover.authenticate(&human_token).await.unwrap(),
            mutations_for(&journey.keycloak.issuer),
        )
        .await;
    assert!(
        human.client.read_proposal(&applied).await.is_err(),
        "another institutional principal cannot inherit Proposal ownership"
    );
    assert!(
        human.client.execute_proposal(&apply).await.is_err(),
        "another principal cannot replay the committed receipt"
    );
    let revisions: i64 = fixture
        .database
        .admin
        .query_one(
            "SELECT count(*)::bigint FROM registry_internal.registry_revisions",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        revisions, 2,
        "receipt replay did not apply the effect again"
    );
    drop(same_issuer);
    drop(human);
    drop(new);
    fixture.finish().await;
}
