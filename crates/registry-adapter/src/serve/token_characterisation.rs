// SPDX-License-Identifier: Apache-2.0
//! Characterises which identity-provider tokens the facade's real caller
//! authentication admits, against the token fixture corpus in
//! `products/platform/conformance/tokens`.
//!
//! Each row builds the authenticator the server builds, through
//! `serve::authenticator`, over a static key set holding the corpus signer's
//! public keys, and presents the fixture to `Authenticator::authenticate`. The
//! payment host builds its authenticator through the same function and
//! authenticates a bearer through the same method. The module sits under
//! `serve` so it can also ask the authenticator's own verifier for the check
//! that refused a token and compare it with the check `CallerRefusal` carries.
use super::*;
use registry_platform_config::SecretProvider;
use registry_platform_testing::{
    ClaimValue, Configuration, FixtureCase, Outcome, TokenCorpus, TokenFixture, TokenSigner,
};
use serde_json::{json, Value};

const ISSUER: &str = "https://issuer.example.test";
const AUDIENCE: &str = "registry-adapter-test";
const KEY_FILE: &str = "issuer-keys.json";
const PLACEHOLDER_CLIENT: &str = "journey-app";

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

fn runtime_for(case: &FixtureCase) -> AdapterRuntimeConfig {
    let client = client_of(&case.fixture);
    let mut issuer = json!({
        "issuer": case.issuer,
        "audience": case.audience,
        "jwksSource": {"type": "static", "documentRef": format!("secret:file/{KEY_FILE}")},
        "allowedClients": [client.as_deref().unwrap_or(PLACEHOLDER_CLIENT)]
    });
    let recipe = case.configuration == Configuration::Recipe;
    if case.configuration == Configuration::JwtAccepted
        || (recipe
            && case
                .fixture
                .header
                .as_ref()
                .and_then(|header| header.typ.as_deref())
                == Some("JWT"))
    {
        issuer["accessTokenType"] = json!("JWT");
    }
    if recipe && case.fixture.claims.contains_key("scp") {
        issuer["scopeClaim"] = json!("scp");
    }
    if let Some(kind) = case.declared_kind {
        let kind = match kind {
            registry_platform_oidc::ActorKind::Human => "human",
            registry_platform_oidc::ActorKind::Agent => "agent",
            registry_platform_oidc::ActorKind::Service => "service",
        };
        if let Some(client) = client {
            issuer["clientActorKinds"] = json!({(client): kind});
        } else {
            issuer["actorKind"] = json!(kind);
        }
    }
    test_runtime(json!({
        "id": "token-characterisation",
        "endpoints": [{"endpoint": "tracker", "baseUrl": "https://tracker.example.invalid"}],
        "listener": {"bind": "127.0.0.1:8080"},
        "database": {
            "runtimeUrlRef": "secret:file/database-runtime",
            "migrationUrlRef": "secret:file/database-migration"
        },
        "oidc": {"issuers": {"primary": issuer}},
        "allowedPrivateCidrs": ["10.0.0.0/8"],
        "audit": {"retentionDays": 90}
    }))
}

async fn observe(authenticator: &Authenticator, token: &str) -> Outcome {
    let verdict = authenticator.issuers.verify(token).await;
    let admission = authenticator.authenticate(token).await;
    match (admission, verdict) {
        (Ok(_), Ok(_)) => Outcome::Admitted(None),
        (Ok(_), Err(_)) => panic!("authenticate admitted a token its own verifier refused"),
        (Err(refusal), Err(error)) => {
            assert_eq!(
                refusal.failed_check(),
                error.failed_check(),
                "the refusal carries the check the verifier named"
            );
            Outcome::refused_by(&error.error)
        }
        (Err(CallerRefusal::Unauthenticated(_)), Ok(_)) => {
            "refused/claims".parse().expect("result value")
        }
        (Err(CallerRefusal::Unavailable), Ok(_)) => {
            "refused/unavailable".parse().expect("result value")
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
    let resolver = SecretResolver::new([SecretProvider::File], root_path).expect("resolver");
    let resolver = &resolver;
    let report = corpus
        .run_product_async("adapter", &signer, ISSUER, AUDIENCE, |case| async move {
            let runtime = runtime_for(&case);
            let authenticator = authenticator(&runtime, resolver)
                .await
                .expect("the authenticator builds over the static key set");
            observe(&authenticator, case.token.expose()).await
        })
        .await
        .expect("the corpus runs");
    assert!(
        report.rows.iter().any(|row| row.observed.is_some()),
        "no row ran"
    );
    report.assert_matches();
}
