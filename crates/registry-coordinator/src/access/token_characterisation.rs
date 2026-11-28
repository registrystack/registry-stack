// SPDX-License-Identifier: Apache-2.0
//! Characterises which identity-provider tokens the Coordinator's real caller
//! authentication admits, against the token fixture corpus in
//! `products/platform/conformance/tokens`.
//!
//! Each row builds the authenticator the server builds, through
//! `AccessConfig::authenticator`, over a static key set holding the corpus
//! signer's public keys, and presents the fixture to `Authenticator::authenticate`.
//! The module sits under `access` so it can also ask the authenticator's own
//! verifier for the check that refused a token and compare it with the check
//! the refusal carries.
use super::*;
use registry_platform_oidc::OidcError;
use registry_platform_testing::{
    ClaimValue, Configuration, FixtureCase, Outcome, TokenCorpus, TokenFixture, TokenSigner,
};
use registry_platform_yaml::Url;
use serde_json::Value;

const ISSUER: &str = "https://issuer.example.test";
const AUDIENCE: &str = "urn:coordinator:test";
const KEY_FILE: &str = "issuer-keys.json";
const PLACEHOLDER_CLIENT: &str = "journey-app";
const PLACEHOLDER_SUBJECT: &str = "placeholder-subject";
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

fn stage_of(error: &OidcError) -> Outcome {
    format!("refused/{}", error.authentication_stage().label())
        .parse()
        .expect("every authentication stage label is a result value")
}

async fn authenticator_for(case: &FixtureCase, secrets: &SecretProvidersConfig) -> Authenticator {
    let scope_claim = match case.configuration {
        Configuration::Recipe => "scope",
        _ => "registry_scopes",
    };
    let policy = ClientPolicy {
        subjects: vec![literal(&case.fixture, "sub").unwrap_or_else(|| PLACEHOLDER_SUBJECT.into())],
        required_scopes: vec![
            first_scope(&case.fixture).unwrap_or_else(|| PLACEHOLDER_SCOPE.into())
        ],
        workflows: vec!["follow-up".into()],
        actions: vec![Action::Start, Action::Status],
        operator: false,
    };
    let client = client_of(&case.fixture).unwrap_or_else(|| PLACEHOLDER_CLIENT.into());
    let access = AccessConfig {
        issuer: OidcIssuerConfig {
            issuer: Url::new(case.issuer.clone()).expect("issuer URL"),
            audience: case.audience.clone(),
            jwks_source: JwksSource::Static {
                document_ref: format!("secret:file/{KEY_FILE}"),
            },
            allow_insecure_http: false,
        },
        assertion_issuers: BTreeMap::new(),
        scope_claim: scope_claim.into(),
        policies: BTreeMap::from([(client, policy)]),
    };
    access
        .authenticator(secrets, false)
        .await
        .expect("the authenticator builds over the static key set")
}

async fn observe(authenticator: &Authenticator, token: &str) -> Outcome {
    let verdict = authenticator.verifier.verify(token).await;
    let admission = authenticator.authenticate(token).await;
    match (admission, verdict) {
        (Ok(_), Ok(_)) => Outcome::Admitted(None),
        (Ok(_), Err(_)) => panic!("authenticate admitted a token its own verifier refused"),
        (Err(refusal), Err(error)) => {
            assert_eq!(
                refusal.check,
                Some(error.failed_check()),
                "the refusal names the verifier's check"
            );
            stage_of(&error)
        }
        (Err(error), Ok(_)) => {
            let (outcome, checks): (_, &[FailedCheck]) = match error.code.as_str() {
                "access.denied" => (
                    "refused/scope",
                    &[
                        FailedCheck::Delegation,
                        FailedCheck::AccessProfile,
                        FailedCheck::Scope,
                    ],
                ),
                "access.unauthenticated" => (
                    "refused/claims",
                    &[
                        FailedCheck::TokenAssertionIssuer,
                        FailedCheck::TokenClient,
                        FailedCheck::TokenClaims,
                    ],
                ),
                "access.unavailable" => {
                    ("refused/unavailable", &[FailedCheck::KeySourceUnavailable])
                }
                other => panic!("authenticate refused with the unexpected code {other}"),
            };
            assert!(
                error.check.is_some_and(|check| checks.contains(&check)),
                "{} carries a check from {checks:?}, not {:?}",
                error.code,
                error.check
            );
            outcome.parse().expect("result value")
        }
    }
}

/// The corpus public keys a static key document may hold: it admits RSA and
/// EC keys only, so the corpus's EdDSA key is left out.
fn static_key_document(signer: &TokenSigner) -> String {
    let mut keys = signer.public_key_set();
    keys["keys"]
        .as_array_mut()
        .expect("a key set lists keys")
        .retain(|key| key["kty"] != "OKP");
    keys.to_string()
}

#[tokio::test]
async fn caller_authentication_matches_the_token_corpus() {
    let corpus = TokenCorpus::load().expect("the token corpus loads");
    let signer = TokenSigner::new();
    let root = tempfile::tempdir().expect("key directory");
    let root_path = root.path().canonicalize().expect("physical key directory");
    let key_file = root_path.join(KEY_FILE);
    std::fs::write(&key_file, static_key_document(&signer)).expect("write the key set");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only key file");
    }
    let secrets = SecretProvidersConfig {
        file: Some(registry_platform_config::FileSecretProviderConfig { root: root_path }),
        environment: None,
    };
    let secrets = &secrets;
    let report = corpus
        .run_product_async(
            "coordinator",
            &signer,
            ISSUER,
            AUDIENCE,
            |case| async move {
                let authenticator = authenticator_for(&case, secrets).await;
                observe(&authenticator, case.token.expose()).await
            },
        )
        .await
        .expect("the corpus runs");
    assert!(
        report.rows.iter().any(|row| row.observed.is_some()),
        "no row ran"
    );
    report.assert_matches();
}
