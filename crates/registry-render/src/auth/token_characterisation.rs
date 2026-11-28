//! Characterises which identity-provider tokens Render's real caller
//! authentication admits, against the token fixture corpus in
//! `products/platform/conformance/tokens`.
//!
//! Each row loads a runtime file the way `serve` does, builds the verifier
//! through `verifier`, and presents the fixture to `authenticate` for the
//! render scope, the call every render and document route makes. The module
//! sits under `auth` so it can also ask the verifier for the check that
//! refused a token, which `AuthenticationError` does not carry.
use super::*;
use registry_platform_oidc::OidcError;
use registry_platform_testing::{
    ClaimValue, Configuration, FixtureCase, Outcome, TokenCorpus, TokenFixture, TokenSigner,
};
use serde_json::Value;
use std::path::Path;

const ISSUER: &str = "https://issuer.example.test";
const AUDIENCE: &str = "urn:render:test";
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

fn stage_of(error: &OidcError) -> Outcome {
    format!("refused/{}", error.authentication_stage().label())
        .parse()
        .expect("every authentication stage label is a result value")
}

/// A runtime file for one row. The recipe for a token that names no client
/// writes `unrestricted`, as the runtime allows; every other row lists
/// the fixture's client, or a placeholder when the token names none.
fn write_runtime(home: &Path, case: &FixtureCase) -> std::path::PathBuf {
    let clients = match (client_of(&case.fixture), case.configuration) {
        (Some(client), _) => format!("[{client}]"),
        (None, Configuration::Recipe) => "unrestricted".to_owned(),
        (None, _) => format!("[{PLACEHOLDER_CLIENT}]"),
    };
    let runtime = format!(
        "apiVersion: {}\nkind: {}\nlistener:\n  bind: 127.0.0.1:18080\npackage:\n  root: {}\nsecretProviders:\n  file:\n    root: {}\nauthentication:\n  oidc:\n    issuer: {}\n    audience: {}\n    allowedClients: {}\n    jwksSource:\n      type: static\n      documentRef: secret:file/{KEY_FILE}\naudit:\n  path: {}\n",
        crate::runtime::RUNTIME_API_VERSION,
        crate::runtime::RUNTIME_KIND,
        home.join("bundle").display(),
        home.display(),
        case.issuer,
        case.audience,
        clients,
        home.join("audit").join("render.jsonl").display(),
    );
    let path = home.join("runtime.yaml");
    std::fs::write(&path, runtime).expect("write the runtime file");
    path
}

async fn observe(verifier: &TokenVerifier, token: &str) -> Outcome {
    let verdict = verifier.verify(token).await;
    let admission = authenticate(verifier, token, RENDER_SCOPE).await;
    match (admission, verdict) {
        (Ok(_), Ok(_)) => Outcome::Admitted(None),
        (Ok(_), Err(_)) => panic!("authenticate admitted a token its own verifier refused"),
        (Err(refused), Err(error)) => {
            assert_eq!(
                refused.failed_check(),
                error.failed_check(),
                "the recorded check is the verifier's"
            );
            stage_of(&error)
        }
        (Err(AuthenticationError::Forbidden { .. }), Ok(_)) => {
            "refused/scope".parse().expect("result value")
        }
        (Err(AuthenticationError::Refused(_)), Ok(_)) => {
            "refused/claims".parse().expect("result value")
        }
        (Err(AuthenticationError::Unavailable), Ok(_)) => {
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
    let scratch = tempfile::tempdir().expect("home directory");
    let home = scratch
        .path()
        .canonicalize()
        .expect("physical home directory");
    std::fs::create_dir(home.join("bundle")).expect("package directory");
    std::fs::create_dir(home.join("audit")).expect("audit directory");
    let key_file = home.join(KEY_FILE);
    std::fs::write(&key_file, static_key_document(&signer)).expect("write the key set");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only key file");
    }
    let home = &home;
    let report = corpus
        .run_product_async("render", &signer, ISSUER, AUDIENCE, |case| async move {
            let path = write_runtime(home, &case);
            let (runtime, _) =
                crate::runtime::load(&path).expect("the runtime file loads and validates");
            let verifier = verifier(&runtime)
                .await
                .expect("the verifier builds over the static key set")
                .expect("the runtime declares oidc authentication");
            observe(&verifier, case.token.expose()).await
        })
        .await
        .expect("the corpus runs");
    assert!(
        report.rows.iter().any(|row| row.observed.is_some()),
        "no row ran"
    );
    report.assert_matches();
}
