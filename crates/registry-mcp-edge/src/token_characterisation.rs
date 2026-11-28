// SPDX-License-Identifier: Apache-2.0

//! Characterises which identity-provider tokens the MCP edge's real caller
//! authentication admits, against the token fixture corpus in
//! `products/platform/conformance/tokens`.
//!
//! Each row builds a resource server from the public options and verifier
//! constructor the product hosts use, mounts the `require_caller` layer the
//! edge router applies, and sends the fixture as a bearer credential. The
//! layer answers a refusal with a status that names no check, so the check is
//! read from a second verifier built by the same public `token_verifier`
//! constructor over the same key set.

use std::{sync::Arc, time::Duration};

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    routing::post,
    Router,
};
use registry_platform_audit::AuditProfile;
use registry_platform_oidc::{parse_static_jwks, JwksFetcher, JwksFetcherConfig, TokenVerifier};
use registry_platform_testing::{
    ClaimValue, FixtureCase, Outcome, TokenCorpus, TokenFixture, TokenSigner,
};
use serde_json::Value;
use tower::ServiceExt;
use zeroize::Zeroizing;

use crate::{
    inbound::require_caller, token_verifier, AccessTokenAlgorithm, RateLimitOptions,
    ResourceServer, ResourceServerError, ResourceServerOptions, TokenBucketOptions,
};

const ISSUER: &str = "https://issuer.example.test";
const RESOURCE: &str = "https://gateway.example.test/mcp";
const PLACEHOLDER_CLIENT: &str = "journey-app";
const PLACEHOLDER_SCOPE: &str = "records:get";

fn literal(fixture: &TokenFixture, claim: &str) -> Option<String> {
    match fixture.claims.get(claim) {
        Some(ClaimValue::Literal(Value::String(text))) => Some(text.clone()),
        _ => None,
    }
}

/// The client the token names, read the way the verifier reads it.
fn client_of(fixture: &TokenFixture) -> Option<String> {
    literal(fixture, "azp").or_else(|| literal(fixture, "client_id"))
}

fn first_scope(fixture: &TokenFixture) -> Option<String> {
    fixture.read_scope("scope")
}

/// The algorithm the fixture declares, when the edge can be configured with
/// it. A symmetric or absent algorithm leaves the edge on RS256, which then
/// refuses the token at the algorithm check.
fn algorithm_of(fixture: &TokenFixture) -> AccessTokenAlgorithm {
    match fixture.header.as_ref().map(|header| header.alg.as_str()) {
        Some("ES256") => AccessTokenAlgorithm::ES256,
        Some("EdDSA") => AccessTokenAlgorithm::EdDSA,
        _ => AccessTokenAlgorithm::RS256,
    }
}

fn options_for(case: &FixtureCase) -> ResourceServerOptions {
    ResourceServerOptions {
        resource: case.audience.clone(),
        issuer: case.issuer.clone(),
        allow_insecure_http: false,
        algorithms: vec![algorithm_of(&case.fixture)],
        allowed_clients: vec![client_of(&case.fixture).unwrap_or_else(|| PLACEHOLDER_CLIENT.into())],
        required_scopes: vec![
            first_scope(&case.fixture).unwrap_or_else(|| PLACEHOLDER_SCOPE.into())
        ],
        scope_claim: "scope".to_owned(),
        maximum_token_lifetime: Duration::from_secs(3600),
        resource_name: "Token characterisation".to_owned(),
        principal_audit_namespace: "principal-v1".to_owned(),
        client_audit_namespace: "client-v1".to_owned(),
    }
}

/// A static key document admits RSA and EC keys only, so the corpus's EdDSA
/// key is left out.
fn fetcher_for(case: &FixtureCase) -> Arc<JwksFetcher> {
    let mut keys = case.jwks.clone();
    keys["keys"]
        .as_array_mut()
        .expect("a key set lists keys")
        .retain(|key| key["kty"] != "OKP");
    Arc::new(JwksFetcher::new_static(
        parse_static_jwks(keys.to_string().as_bytes()).expect("the corpus key set parses"),
        JwksFetcherConfig::defaults(),
    ))
}

async fn observe(case: &FixtureCase) -> Outcome {
    let options = options_for(case);
    let hasher = AuditProfile::production_from_secret_bytes(Zeroizing::new(vec![5; 32]))
        .expect("audit profile")
        .key_hasher();
    let server = match ResourceServer::new(
        &options,
        token_verifier(&options, fetcher_for(case)),
        hasher,
        RateLimitOptions {
            per_principal: TokenBucketOptions {
                requests_per_minute: 60,
                burst: 1000,
            },
            per_client: TokenBucketOptions {
                requests_per_minute: 60,
                burst: 1000,
            },
        },
    ) {
        Ok(server) => Arc::new(server),
        // The edge serves one MCP path, so an audience that is not an `/mcp`
        // URL cannot be configured.
        Err(ResourceServerError::Resource) => return Outcome::None,
        Err(error) => panic!("the resource server builds: {error:?}"),
    };
    let router = Router::new()
        .route("/mcp", post(|| async { "ok" }))
        .layer(axum::middleware::from_fn_with_state(server, require_caller));
    let token = case.token.expose();
    let response = router
        .oneshot(
            Request::post("/mcp")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let probe: TokenVerifier = token_verifier(&options, fetcher_for(case));
    let verdict = probe.verify(token).await;
    match (response.status(), verdict) {
        (StatusCode::OK, Ok(_)) => Outcome::Admitted(None),
        (StatusCode::OK, Err(_)) => panic!("the edge admitted a token its verifier refused"),
        (_, Err(error)) => Outcome::refused_by(&error),
        (StatusCode::FORBIDDEN, Ok(_)) => "refused/scope".parse().expect("result value"),
        (StatusCode::UNAUTHORIZED, Ok(_)) => "refused/claims".parse().expect("result value"),
        (StatusCode::SERVICE_UNAVAILABLE, Ok(_)) => {
            "refused/unavailable".parse().expect("result value")
        }
        (status, Ok(_)) => panic!("the edge answered the unexpected status {status}"),
    }
}

#[tokio::test]
async fn caller_authentication_matches_the_token_corpus() {
    let corpus = TokenCorpus::load().expect("the token corpus loads");
    let signer = TokenSigner::new();
    let report = corpus
        .run_product_async("mcp-edge", &signer, ISSUER, RESOURCE, |case| async move {
            observe(&case).await
        })
        .await
        .expect("the corpus runs");
    assert!(
        report.rows.iter().any(|row| row.observed.is_some()),
        "no row ran"
    );
    report.assert_matches();
}
