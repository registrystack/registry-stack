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
use registry_platform_testing::{
    Binding, ClaimValue, Configuration, FixtureCase, FixtureClass, Outcome, TokenCorpus,
    TokenFixture, TokenSigner,
};
use serde_json::json;
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

async fn authenticator_for(case: &FixtureCase, secrets: &SecretProvidersConfig) -> Authenticator {
    let recipe = case.configuration == Configuration::Recipe;
    let jwt_typed = case
        .fixture
        .header
        .as_ref()
        .and_then(|header| header.typ.as_deref())
        == Some("JWT");
    let scope_claim = if recipe && case.fixture.claims.contains_key("scp") {
        "scp"
    } else {
        "scope"
    };
    let policy = ClientPolicy {
        subjects: vec![literal(&case.fixture, "sub").unwrap_or_else(|| PLACEHOLDER_SUBJECT.into())],
        required_scopes: vec![case
            .fixture
            .read_scope(scope_claim)
            .filter(|scope| {
                ![
                    "openid",
                    "profile",
                    "email",
                    "address",
                    "phone",
                    "offline_access",
                ]
                .contains(&scope.as_str())
            })
            .unwrap_or_else(|| PLACEHOLDER_SCOPE.into())],
        workflows: vec!["follow-up".into()],
        actions: vec![Action::Start, Action::Status],
        operator: false,
    };
    let client = client_of(&case.fixture).unwrap_or_else(|| PLACEHOLDER_CLIENT.into());
    let mut entry = json!({
        "issuer": case.issuer,
        "audience": case.audience,
        "jwksSource": {"type": "static", "documentRef": format!("secret:file/{KEY_FILE}")},
        "scopeClaim": scope_claim,
        "allowedClients": "from-policies",
    });
    if case.configuration == Configuration::JwtAccepted || (recipe && jwt_typed) {
        entry["accessTokenType"] = json!("JWT");
    }
    if let Some(kind) = case.declared_kind {
        if let Some(client) = client_of(&case.fixture) {
            entry["clientActorKinds"] = json!({(client): kind});
        } else {
            entry["actorKind"] = json!(kind);
        }
    }
    let envelope = registry_platform_config::RuntimeEnvelope {
        api_version: crate::runtime::API_VERSION,
        kind: crate::runtime::KIND,
    };
    let document = json!({
        "apiVersion": envelope.api_version, "kind": envelope.kind,
        "issuers": {"main": entry}, "policies": {(client): policy},
    });
    let access = registry_platform_config::RuntimeConfigLoader::new_without_posture(envelope)
        .parse_str::<AccessConfig>(&document.to_string(), |_| None)
        .expect("the issuer entry decodes")
        .config;
    access
        .authenticator(secrets)
        .await
        .expect("the authenticator builds over the static key set")
}

async fn observe(authenticator: &Authenticator, token: &str) -> Outcome {
    let verdict = authenticator.issuers.verify(token).await;
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
            Outcome::refused_by(&error.error)
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

fn static_secrets(root: &std::path::Path, signer: &TokenSigner) -> SecretProvidersConfig {
    let root_path = root.canonicalize().expect("physical key directory");
    let key_file = root_path.join(KEY_FILE);
    std::fs::write(&key_file, static_key_document(signer)).expect("write the key set");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only key file");
    }
    SecretProvidersConfig {
        file: Some(registry_platform_config::FileSecretProviderConfig { root: root_path }),
        environment: None,
    }
}

#[tokio::test]
async fn a_jwt_typed_token_is_refused_by_default_and_the_log_names_the_setting() {
    use crate::http::refusal_recording_tests::refused_in;
    use registry_platform_config::Posture;

    let corpus = TokenCorpus::load().unwrap();
    let fixture = corpus.fixture("keycloak-client-credentials").unwrap();
    let signer = TokenSigner::new();
    let root = tempfile::tempdir().unwrap();
    let secrets = static_secrets(root.path(), &signer);
    let binding = Binding {
        issuer: ISSUER.into(),
        audience: AUDIENCE.into(),
    };
    let case = FixtureCase {
        fixture: fixture.clone(),
        against: registry_platform_testing::Against::PlainRead,
        configuration: Configuration::Default,
        declared_kind: None,
        issuer: binding.issuer.clone(),
        audience: binding.audience.clone(),
        token: signer.sign(fixture, &binding).unwrap(),
        jwks: signer.public_key_set(),
    };
    let authenticator = authenticator_for(&case, &secrets).await;
    for posture in [Posture::Production, Posture::Development] {
        let Err(error) = authenticator.authenticate(case.token.expose()).await else {
            panic!("the default entry admitted a JWT access token");
        };
        assert_eq!(error.check, Some(FailedCheck::TokenType));
        let (status, body, _, log) = refused_in(error, posture).await;
        assert_eq!(status.as_u16(), 401);
        assert!(log.contains("set accessTokenType on the entry"), "{log}");
        assert!(!body.to_string().contains("accessTokenType"));
    }
}

#[tokio::test]
async fn caller_authentication_matches_the_token_corpus() {
    let corpus = TokenCorpus::load().expect("the token corpus loads");
    let signer = TokenSigner::new();
    let root = tempfile::tempdir().expect("key directory");
    let secrets = static_secrets(root.path(), &signer);
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
    // Exercise proposed rows whose current cell has no runnable expectation.
    for row in &corpus.expectations().rows {
        let cell = &row.products["coordinator"];
        if !matches!(cell.expected(), Outcome::None)
            || matches!(cell.target, Outcome::None | Outcome::NotApplicable)
        {
            continue;
        }
        let fixture = corpus
            .fixture(&row.fixture)
            .expect("the row names a fixture");
        let configuration = row.configuration.block();
        let audience = match (fixture.class, configuration, literal(fixture, "aud")) {
            (FixtureClass::Positive, Configuration::Recipe, Some(audience)) => audience,
            _ => AUDIENCE.to_owned(),
        };
        let binding = Binding {
            issuer: ISSUER.into(),
            audience,
        };
        let case = FixtureCase {
            fixture: fixture.clone(),
            against: row.against,
            configuration,
            declared_kind: row.configuration.declared_kind(fixture),
            issuer: binding.issuer.clone(),
            audience: binding.audience.clone(),
            token: signer.sign(fixture, &binding).expect("the fixture signs"),
            jwks: signer.public_key_set(),
        };
        let authenticator = authenticator_for(&case, secrets).await;
        let observed = observe(&authenticator, case.token.expose()).await;
        eprintln!(
            "{} / {:?} / {:?}: target {}, observed {observed}",
            row.fixture, row.against, row.configuration, cell.target
        );
    }
    report.assert_matches();
}

#[tokio::test]
async fn verifier_errors_outside_the_original_key_source_set_answer_401() {
    use registry_platform_oidc::{CallerRefusal, OidcEndpoint, StaticJwksError};

    let mut statuses = Vec::new();
    for error in [
        OidcError::StaticKeySet(StaticJwksError::Empty),
        OidcError::InsecureHttpRequiresOptIn,
        OidcError::EndpointRefused {
            endpoint: OidcEndpoint::DeclaredJwks,
            remedy: "synthetic endpoint refusal",
        },
    ] {
        let variant = format!("{error:?}");
        let error = verification_error(CallerRefusal {
            error,
            remedy: None,
        });
        let (status, _, _, _) = crate::http::refusal_recording_tests::refused_in(
            error,
            registry_platform_config::Posture::Production,
        )
        .await;
        statuses.push((variant, status.as_u16()));
    }
    assert!(
        statuses.iter().all(|(_, status)| *status == 401),
        "{statuses:?}"
    );
}

async fn caller_refusal_test(
    configuration: Configuration,
    declared_kind: Option<registry_platform_oidc::ActorKind>,
    token_issuer: &str,
    modify: impl FnOnce(&mut TokenFixture),
    check: FailedCheck,
    remedy: &str,
) {
    let corpus = TokenCorpus::load().unwrap();
    let mut fixture = corpus
        .fixture("keycloak-client-credentials")
        .unwrap()
        .clone();
    fixture.header.as_mut().unwrap().typ = Some("at+jwt".into());
    modify(&mut fixture);
    let signer = TokenSigner::new();
    let root = tempfile::tempdir().unwrap();
    let secrets = static_secrets(root.path(), &signer);
    let binding = Binding {
        issuer: token_issuer.into(),
        audience: AUDIENCE.into(),
    };
    let case = FixtureCase {
        token: signer.sign(&fixture, &binding).unwrap(),
        fixture,
        against: registry_platform_testing::Against::PlainRead,
        configuration,
        declared_kind,
        issuer: ISSUER.into(),
        audience: binding.audience,
        jwks: signer.public_key_set(),
    };
    let authenticator = authenticator_for(&case, &secrets).await;
    let Err(error) = authenticator.authenticate(case.token.expose()).await else {
        panic!("the caller was admitted");
    };
    let (status, body, _, log) = crate::http::refusal_recording_tests::refused_in(
        error,
        registry_platform_config::Posture::Development,
    )
    .await;
    assert_eq!(status.as_u16(), 401);
    assert_eq!(body["failedCheck"], check.as_str(), "{body}");
    assert!(log.contains(remedy), "{log}");
    assert!(!body.to_string().contains(remedy));
}

#[tokio::test]
async fn an_id_token_is_refused_whether_or_not_jwt_is_admitted() {
    for (configuration, remedy) in [
        (Configuration::Default, "set accessTokenType on the entry"),
        (
            Configuration::JwtAccepted,
            "The token carries an ID token claim.",
        ),
    ] {
        caller_refusal_test(
            configuration,
            None,
            ISSUER,
            |fixture| {
                fixture.header.as_mut().unwrap().typ = Some("JWT".into());
                fixture
                    .claims
                    .insert("typ".into(), ClaimValue::Literal(json!("ID")));
            },
            FailedCheck::TokenType,
            remedy,
        )
        .await;
    }
}

#[tokio::test]
async fn a_token_kind_that_contradicts_the_declared_kind_is_refused() {
    caller_refusal_test(
        Configuration::Default,
        Some(registry_platform_oidc::ActorKind::Service),
        ISSUER,
        |fixture| {
            fixture.claims.insert(
                "registry_actor_kind".into(),
                ClaimValue::Literal(json!("human")),
            );
        },
        FailedCheck::ActorKind,
        "The token's actor kind claim differs from the kind declared",
    )
    .await;
}

#[tokio::test]
async fn an_identity_only_token_is_refused_without_a_declared_kind() {
    caller_refusal_test(
        Configuration::Default,
        None,
        ISSUER,
        |fixture| {
            fixture.claims.insert(
                "scope".into(),
                ClaimValue::Literal(json!("openid profile email address phone offline_access")),
            );
        },
        FailedCheck::ActorKind,
        "The token grants no scope and its kind is not declared.",
    )
    .await;
}

#[tokio::test]
async fn an_unknown_issuer_refusal_logs_the_issuer_entry_remedy() {
    caller_refusal_test(
        Configuration::Default,
        None,
        "https://other.example.test",
        |_| {},
        FailedCheck::TokenIssuer,
        "No issuer entry names the token's issuer. Add an entry under issuers",
    )
    .await;
}
