// SPDX-License-Identifier: Apache-2.0

//! Opt-in proof using tokens issued by actual local Mint and Keycloak services.
//! Run products/breg/scripts/test-issuer-portability.py. The recording backend
//! proves authorization before record I/O; PostgreSQL enforcement has its own gate.

#![cfg(feature = "runtime")]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use jsonwebtoken::Algorithm;
use registry_breg::api::{
    authenticated_router, HeldReadResponse, HttpService, ReadRuntimeIdentity, ReadServiceError,
    ReadinessProbe, RecordReadRequest, RecordReadService, ServiceFuture, VerifiedClaimValue,
    VerifiedRequestClaims,
};
use registry_breg::auth::{AuthorityClaimConfig, RegistryAuthenticator};
use registry_breg::cursor::CursorCodec;
use registry_breg::{compile_project, parse_project_yaml, CompileProfile, CompiledRegistry};
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifierConfig};
use serde::Deserialize;
use serde_json::json;
use tower::ServiceExt as _;
use zeroize::Zeroizing;

const AUDIENCE: &str = "urn:breg:issuer-portability";
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
    mint: Issuer,
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
            AuthorityClaimConfig::new("registry_principal", Some("purpose".to_owned())),
        )
        .expect("explicit issuer configuration"),
    )
}

fn expected_claims(principal: &str, scopes: &[&str]) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        principal,
        scopes.iter().map(|scope| (*scope).to_owned()).collect(),
        Some(PURPOSE.to_owned()),
        BTreeMap::from([(
            "districts".to_owned(),
            VerifiedClaimValue::direct_string_set(["district-a"]).expect("district assignment"),
        )]),
    )
    .expect("expected authority")
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
async fn mint_and_keycloak_preserve_authority_and_cutover_rejects_the_old_issuer() {
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
    let mint = authenticator(&registry, root, &journey.mint, AUDIENCE);
    let keycloak = authenticator(&registry, root, &journey.keycloak, AUDIENCE);
    let tokens: Vec<Zeroizing<String>> = [
        "mint.token",
        "service.token",
        "human.token",
        "no-scope.token",
    ]
    .iter()
    .map(|name| Zeroizing::new(std::fs::read_to_string(root.join(name)).expect("issued token")))
    .collect();
    for (index, issuer, scopes) in [
        (0, &mint, vec!["registry.read"]),
        (1, &keycloak, vec!["registry.read"]),
        (2, &keycloak, vec!["openid", "registry.read"]),
    ] {
        println!("Checking issuer token case {index}");
        let claims = issuer
            .authenticate(&tokens[index])
            .await
            .expect("real issued token verifies");
        let principal = if index == 2 {
            HUMAN_PRINCIPAL
        } else {
            PRINCIPAL
        };
        assert!(
            claims == expected_claims(principal, &scopes),
            "issuer must preserve exact institutional authority"
        );
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
        mint.authenticate(&tokens[1]).await.is_err(),
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
        json!({"mintService": "passed", "keycloakService": "passed", "keycloakAuthorizationCodePkce": "passed", "issuerCutover": "passed", "databaseEnforcement": "separate-gate"})
    );
}
