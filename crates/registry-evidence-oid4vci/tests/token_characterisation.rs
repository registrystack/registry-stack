//! Characterises the Evidence OID4VCI offer endpoint's access-token
//! authentication against the shared token fixture corpus in
//! `products/platform/conformance/tokens`.
//!
//! Every row of `expected.yaml` with an `evidence-oid4vci` cell runs through
//! `MintResourceServer::from_config`, the constructor the server calls, with
//! the issuer key set served over HTTP from a loopback listener.
//!
//! `OfferAuthorizer::authorize` collapses every verifier refusal into one
//! error, so the refusal stage is named by a second verifier built from the
//! exported `verifier_profile` over the same configuration. It is consulted
//! only after the real resource server has refused.

use std::sync::Arc;

use axum::{routing::get, Json, Router};
use jsonwebtoken::jwk::JwkSet;
use registry_evidence_oid4vci::{
    authorizer::{verifier_profile, AuthorizationError, MintResourceServer, OfferAuthorizer},
    config::{AccessTokenAlgorithm, OfferAuthorizationConfig, Restriction, ValidationMode},
};
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifier};
use registry_platform_testing::{
    ClaimValue, Configuration, FixtureCase, Outcome, Stage, TokenCorpus, TokenSigner,
};
use serde_json::Value;

/// The audience the product under test is configured with.
const PRODUCT_AUDIENCE: &str = "evidence-oid4vci-fixture";

/// The client the `default` configuration admits when a fixture names none,
/// and the scope the `recipe` configuration requires when a fixture carries
/// none.
const FALLBACK_CLIENT: &str = "journey-app";
const FALLBACK_SCOPE: &str = "oid4vci:offer";

fn literal_string(case: &FixtureCase, claim: &str) -> Option<String> {
    match case.fixture.claims.get(claim) {
        Some(ClaimValue::Literal(Value::String(text))) => Some(text.clone()),
        _ => None,
    }
}

fn fixture_client(case: &FixtureCase) -> Option<String> {
    literal_string(case, "client_id").or_else(|| literal_string(case, "azp"))
}

/// The first scope the fixture carries, read from `scope` or `scp`.
fn first_scope(case: &FixtureCase) -> Option<String> {
    case.fixture
        .read_scope("scope")
        .or_else(|| case.fixture.read_scope("scp"))
}

/// The algorithm the offer boundary is configured with for the row: the
/// fixture's own where the product admits it, and ES256 otherwise.
fn configured_algorithm(case: &FixtureCase) -> AccessTokenAlgorithm {
    match case
        .fixture
        .header
        .as_ref()
        .map(|header| header.alg.as_str())
    {
        Some("RS256") => AccessTokenAlgorithm::RS256,
        Some("EdDSA") => AccessTokenAlgorithm::EdDSA,
        _ => AccessTokenAlgorithm::ES256,
    }
}

fn row_config(case: &FixtureCase, jwks_uri: &str) -> OfferAuthorizationConfig {
    let allowed_clients = match (case.configuration, fixture_client(case)) {
        (Configuration::Default, client) => {
            Restriction::Listed(vec![client.unwrap_or_else(|| FALLBACK_CLIENT.to_owned())])
        }
        (_, Some(client)) => Restriction::Listed(vec![client]),
        (_, None) => Restriction::Unrestricted,
    };
    let required_scopes = match case.configuration {
        Configuration::Default => Restriction::Unrestricted,
        _ => Restriction::Listed(vec![
            first_scope(case).unwrap_or_else(|| FALLBACK_SCOPE.to_owned())
        ]),
    };
    OfferAuthorizationConfig {
        claims: Default::default(),
        issuer: case.issuer.clone(),
        jwks_uri: jwks_uri.to_owned(),
        allow_insecure_http: true,
        audiences: vec![case.audience.clone()],
        algorithms: vec![configured_algorithm(case)],
        allowed_clients,
        required_scopes,
        maximum_token_lifetime_seconds: 86_400,
    }
}

/// Serve the signer's public key set from a loopback listener and return the
/// origin, which doubles as the issuer.
async fn serve_key_set(key_set: Value) -> String {
    let app = Router::new().route(
        "/jwks.json",
        get(move || {
            let key_set = key_set.clone();
            async move { Json(key_set) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port is free");
    let port = listener
        .local_addr()
        .expect("the listener has an address")
        .port();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("the key set server runs for the test");
    });
    format!("http://127.0.0.1:{port}")
}

/// The stage at which the shared verifier, under the product's own profile,
/// refuses the token. A token it admits is refused by the product's scope gate
/// or by its own claim rules.
async fn refusal_stage(config: &OfferAuthorizationConfig, case: &FixtureCase) -> Stage {
    let jwks: JwkSet = serde_json::from_value(case.jwks.clone()).expect("the key set parses");
    let verifier = TokenVerifier::new(
        verifier_profile(config),
        Arc::new(JwksFetcher::new_static(jwks, JwksFetcherConfig::defaults())),
    );
    match verifier.verify(case.token.expose()).await {
        Err(error) => {
            let label = error.authentication_stage().label();
            match format!("refused/{label}").parse::<Outcome>() {
                Ok(Outcome::Refused(stage)) => stage,
                other => panic!("the verifier stage `{label}` is not a corpus stage: {other:?}"),
            }
        }
        Ok(verified) => {
            let present: Vec<&str> = verified.scopes.iter().map(String::as_str).collect();
            let scope_missing = config
                .required_scopes
                .items()
                .iter()
                .any(|scope| !present.contains(&scope.as_str()));
            if scope_missing {
                Stage::Scope
            } else {
                Stage::Claims
            }
        }
    }
}

async fn authorize(case: FixtureCase, key_set_uri: String) -> Outcome {
    let config = row_config(&case, &key_set_uri);
    let server =
        MintResourceServer::from_config(&config, ValidationMode::SupervisedLocalDevelopment);
    match server.authorize(case.token.expose()).await {
        Ok(_) => Outcome::Admitted(None),
        Err(AuthorizationError::Missing) => Outcome::Refused(Stage::Header),
        Err(AuthorizationError::KeySource) => Outcome::Refused(Stage::Unavailable),
        Err(AuthorizationError::Refused) => Outcome::Refused(refusal_stage(&config, &case).await),
    }
}

#[tokio::test]
async fn evidence_oid4vci_authentication_matches_the_token_corpus() {
    let corpus = TokenCorpus::load().expect("the token corpus loads");
    let signer = TokenSigner::new();
    let origin = serve_key_set(signer.public_key_set()).await;
    let key_set_uri = format!("{origin}/jwks.json");
    let report = corpus
        .run_product_async(
            "evidence-oid4vci",
            &signer,
            &origin,
            PRODUCT_AUDIENCE,
            |case| authorize(case, key_set_uri.clone()),
        )
        .await
        .expect("the corpus runs for evidence-oid4vci");
    assert!(
        report.rows.iter().any(|row| row.observed.is_some()),
        "no row ran through the offer boundary"
    );
    report.assert_matches();
}
