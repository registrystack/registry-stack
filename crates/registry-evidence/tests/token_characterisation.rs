//! Characterises Evidence's access-token authentication against the shared
//! token fixture corpus in `products/platform/conformance/tokens`.
//!
//! Every row of `expected.yaml` with an `evidence` cell runs through
//! `Authenticator::from_config`, the constructor the server calls, with the
//! issuer key set served over HTTP from a loopback listener. The row's
//! configuration is expressed through the bundle's own authentication members.
//!
//! `Authenticator::authenticate` collapses every verifier refusal into one
//! error, so the refusal stage is named by a second verifier built from the
//! same bundle members. It is consulted only after the real authenticator has
//! refused, and a disagreement between the two fails the test.

use std::{collections::HashSet, sync::Arc, time::Duration};

use axum::{routing::get, Json, Router};
use jsonwebtoken::{jwk::JwkSet, Algorithm};
use registry_evidence::{
    auth::{AuthenticationError, Authenticator},
    config::{
        AccessTokenAlgorithm, AccessTokenType, AdmissionGate, AuthenticationConfig, EvidenceConfig,
        OidcAuthenticationConfig,
    },
};
use registry_platform_authcommon::FailedCheck;
use registry_platform_config::JwksSource;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifier, TokenVerifierConfig};
use registry_platform_testing::{
    ClaimValue, Configuration, FixtureCase, Outcome, Stage, TokenCorpus, TokenSigner,
};
use registry_platform_yaml::{BoundedU64, UniqueList, Url};
use serde_json::Value;

/// The audience the product under test is configured with.
const PRODUCT_AUDIENCE: &str = "evidence-fixture";

/// The client the `default` configuration admits when a fixture names none,
/// and the scope the `recipe` configuration requires when a fixture carries
/// none.
const FALLBACK_CLIENT: &str = "journey-app";
const FALLBACK_SCOPE: &str = "records:get";

/// The bundle Evidence's own acceptance tests start from.
const STARTER_BUNDLE: &str =
    "../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml";

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

fn unique(values: Vec<String>) -> UniqueList<String> {
    UniqueList::new(values).expect("the values are distinct")
}

/// The algorithm Evidence is configured with for the row: the fixture's own
/// where Evidence admits it, and the starter's otherwise.
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

fn row_config(case: &FixtureCase, jwks_uri: &str) -> OidcAuthenticationConfig {
    let bundle = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(STARTER_BUNDLE);
    let bytes = std::fs::read(&bundle).expect("the starter bundle is readable");
    let mut config = EvidenceConfig::parse_yaml(&bytes)
        .expect("the starter bundle parses")
        .authentication
        .oidc;
    config.provider.issuer = Url::new(&case.issuer).expect("the issuer is a URL");
    config.provider.audience = case.audience.clone();
    config.provider.jwks_source = JwksSource::Uri {
        uri: Url::new(jwks_uri).expect("the key set location is a URL"),
    };
    config.provider.allow_insecure_http = true;
    config.token_types = vec![AccessTokenType::AtJwt];
    config.algorithms = vec![configured_algorithm(case)];
    config.maximum_token_lifetime_seconds =
        BoundedU64::new(86_400).expect("the day is within the lifetime bounds");
    let client = fixture_client(case);
    config.allowed_clients = match (case.configuration, client) {
        (Configuration::Default, client) => AdmissionGate::listed(unique(vec![
            client.unwrap_or_else(|| FALLBACK_CLIENT.to_owned())
        ])),
        (_, Some(client)) => AdmissionGate::listed(unique(vec![client])),
        (_, None) => AdmissionGate::unrestricted(),
    };
    config.required_scopes = match case.configuration {
        Configuration::Default => AdmissionGate::unrestricted(),
        _ => AdmissionGate::listed(unique(vec![
            first_scope(case).unwrap_or_else(|| FALLBACK_SCOPE.to_owned())
        ])),
    };
    config
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

/// The stage at which the shared verifier refuses the token under the row's
/// bundle members, or `None` when it admits it.
async fn verifier_refusal(config: &OidcAuthenticationConfig, case: &FixtureCase) -> Option<Stage> {
    let jwks: JwkSet = serde_json::from_value(case.jwks.clone()).expect("the key set parses");
    let algorithms: Vec<Algorithm> = config
        .algorithms
        .iter()
        .map(|algorithm| algorithm.to_jsonwebtoken())
        .collect();
    let verifier = TokenVerifier::new(
        TokenVerifierConfig::access_token_profile(
            config.issuer().to_owned(),
            vec![config.audience().to_owned()],
            algorithms,
            vec!["at+jwt".to_owned()],
        )
        .with_denied_kids(HashSet::new())
        .with_max_token_lifetime(Some(Duration::from_secs(
            config.maximum_token_lifetime_seconds.get(),
        )))
        .with_allowed_clients(config.allowed_clients.admitted()),
        Arc::new(JwksFetcher::new_static(jwks, JwksFetcherConfig::defaults())),
    );
    let error = verifier.verify(case.token.expose()).await.err()?;
    match Outcome::refused_by(&error) {
        Outcome::Refused(stage) => Some(stage),
        other => panic!("the verifier error {error:?} is not a refusal: {other:?}"),
    }
}

async fn authenticate(case: FixtureCase, key_set_uri: String) -> Outcome {
    let config = row_config(&case, &key_set_uri);
    let authenticator = Authenticator::from_config(
        &AuthenticationConfig {
            oidc: config.clone(),
        },
        Vec::new(),
    );
    match authenticator.authenticate(case.token.expose()).await {
        Ok(context) => Outcome::Admitted(Some(context.actor_kind().as_str().to_owned())),
        Err(AuthenticationError::Malformed) => Outcome::Refused(Stage::Header),
        Err(AuthenticationError::Context(_) | AuthenticationError::SenderConstrained) => {
            Outcome::Refused(Stage::Claims)
        }
        Err(AuthenticationError::Verification(check)) => {
            match verifier_refusal(&config, &case).await {
                Some(stage) => Outcome::Refused(stage),
                None => {
                    assert!(
                    !config.required_scopes.admitted().is_empty(),
                    "the authenticator refused a token the verifier admits and no scope gate is set"
                );
                    assert_eq!(
                        check,
                        FailedCheck::Scope,
                        "a token the verifier admits is refused by the scope gate"
                    );
                    Outcome::Refused(Stage::Scope)
                }
            }
        }
    }
}

#[tokio::test]
async fn evidence_authentication_matches_the_token_corpus() {
    let corpus = TokenCorpus::load().expect("the token corpus loads");
    let signer = TokenSigner::new();
    let origin = serve_key_set(signer.public_key_set()).await;
    let key_set_uri = format!("{origin}/jwks.json");
    let report = corpus
        .run_product_async("evidence", &signer, &origin, PRODUCT_AUDIENCE, |case| {
            authenticate(case, key_set_uri.clone())
        })
        .await
        .expect("the corpus runs for evidence");
    assert!(
        report.rows.iter().any(|row| row.observed.is_some()),
        "no row ran through Evidence"
    );
    report.assert_matches();
}
