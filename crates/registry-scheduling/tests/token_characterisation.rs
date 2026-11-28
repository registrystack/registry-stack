// SPDX-License-Identifier: Apache-2.0

//! Characterisation of Scheduling's bearer authentication against the token
//! fixture corpus (`products/platform/conformance/tokens`).
//!
//! Every row of `expected.yaml` with a `scheduling` cell is run through the
//! authenticator the server builds: the verifier profile and the authenticator
//! settings come from a `RuntimeConfig` loaded from a runtime file, the keys
//! from that file's static key source, and the credential goes through
//! `SchedulingAuthenticator::authenticate_read`, the plain read. No database is
//! involved.
//!
//! The authenticator reports a verifier refusal as one error. The stage of that
//! refusal is read by running the same token through a second verifier built
//! from the same configuration and keys, so the stage is the shared verifier's
//! own label.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use registry_platform_authcommon::FailedCheck;
use registry_platform_config::write_package;
use registry_platform_oidc::TokenVerifier;
use registry_platform_testing::{
    ClaimValue, Configuration, FixtureCase, Outcome, TokenCorpus, TokenSigner,
};
use registry_scheduling::auth::{AuthenticationError, SchedulingAuthenticator};
use registry_scheduling::config::{package_limits, RuntimeConfig, PACKAGE_COMMAND};
use registry_scheduling::runtime::secret_resolver;
use registry_scheduling_core::{
    AUTHORED_POLICY_FILE, SCHEDULING_RUNTIME_API_VERSION, SCHEDULING_RUNTIME_KIND,
};
use serde_json::{json, Value};

const ISSUER: &str = "https://identity.example.test";
const AUDIENCE: &str = "urn:example:scheduling";
/// The client a fixture without a client claim is configured against: the
/// allowed list always holds one client, as the runtime requires.
const PLACEHOLDER_CLIENT: &str = "journey-app";
const PLACEHOLDER_SCOPE: &str = "records:get";
/// A scope no fixture carries, so the explain scope never equals the read scope.
const EXPLAIN_SCOPE: &str = "corpus:explain";

fn literal_string(case: &FixtureCase, claim: &str) -> Option<String> {
    match case.fixture.claims.get(claim) {
        Some(ClaimValue::Literal(Value::String(text))) => Some(text.clone()),
        _ => None,
    }
}

/// The client the fixture names, from `client_id` or `azp`.
fn fixture_client(case: &FixtureCase) -> String {
    literal_string(case, "client_id")
        .or_else(|| literal_string(case, "azp"))
        .unwrap_or_else(|| PLACEHOLDER_CLIENT.to_owned())
}

/// The claim the configuration reads scopes from.
fn scope_claim(case: &FixtureCase) -> &'static str {
    if case.configuration == Configuration::Recipe
        && case.fixture.claims.contains_key("scp")
        && !case.fixture.claims.contains_key("scope")
    {
        "scp"
    } else {
        "scope"
    }
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write a private file");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("restrict the file");
}

/// The key set a static key source accepts: it refuses a set holding any key
/// that is not RSA or EC, so the corpus's EdDSA key stays out of the file. No
/// admitted algorithm uses it.
fn static_key_set(jwks: &Value) -> Value {
    let keys: Vec<Value> = jwks["keys"]
        .as_array()
        .expect("a key set with a keys array")
        .iter()
        .filter(|key| matches!(key["kty"].as_str(), Some("RSA" | "EC")))
        .cloned()
        .collect();
    json!({ "keys": keys })
}

fn refusal(stage_label: &str) -> Outcome {
    format!("refused/{stage_label}")
        .parse()
        .expect("a stage the corpus knows")
}

async fn observe(package_root: PathBuf, case: FixtureCase) -> Outcome {
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().expect("a temp dir"))
        .expect("a runtime directory");
    let secrets = root.path().join("secrets");
    fs::create_dir(&secrets).expect("a secrets directory");
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700)).expect("restrict secrets");
    write_private(
        &secrets.join("issuer-jwks"),
        &serde_json::to_vec(&static_key_set(&case.jwks)).expect("a key set"),
    );
    let claim = scope_claim(&case);
    let scope = case
        .fixture
        .read_scope(claim)
        .unwrap_or_else(|| PLACEHOLDER_SCOPE.to_owned());
    let runtime_path = root.path().join("runtime.json");
    fs::write(
        &runtime_path,
        serde_json::to_vec(&json!({
            "apiVersion": SCHEDULING_RUNTIME_API_VERSION,
            "kind": SCHEDULING_RUNTIME_KIND,
            "identity": {"databaseId": "token-characterisation"},
            "package": {"root": package_root},
            "listener": {"bind": "127.0.0.1:0", "tlsTermination": "development-loopback", "networkExposure": "private-address"},
            "secretProviders": {"file": {"root": secrets}, "environment": {}},
            "database": {
                "runtimeUrlRef": "secret:env/SCHEDULING_RUNTIME_URL",
                "migrationUrlRef": "secret:env/SCHEDULING_MIGRATION_URL"
            },
            "authentication": {"oidc": {
                "issuer": case.issuer,
                "audience": case.audience,
                "jwksSource": {"type": "static", "documentRef": "secret:file/issuer-jwks"},
                "allowedClients": [fixture_client(&case)],
                "scopeClaim": claim,
                "readsScope": scope,
                "explainScope": EXPLAIN_SCOPE
            }},
            "taskGrantStatus": "unchecked-final-fifteen-minutes",
            "audit": {"path": root.path().join("audit.jsonl"), "hashKeyRef": "secret:file/audit-key"},
            "destinations": {},
            "retention": {"receiptRetentionDays": 7}
        }))
        .expect("a runtime document"),
    )
    .expect("write the runtime file");
    let config = RuntimeConfig::load(&runtime_path, registry_scheduling::config::DEFAULT_POSTURE)
        .expect("the runtime configuration loads");
    let resolver = secret_resolver(&config).expect("the secret resolver");
    let (verifier, keys) = config
        .oidc_verifier(&resolver)
        .await
        .expect("the static key source");

    let authenticator =
        SchedulingAuthenticator::new(&config.authentication.oidc, verifier.clone(), keys.clone());
    let token = case.token.expose();
    match authenticator.authenticate_read(token).await {
        Ok(caller) => Outcome::Admitted(Some(caller.actor_kind)),
        Err(AuthenticationError::Claims(_)) => refusal("claims"),
        Err(AuthenticationError::Unavailable) => refusal("unavailable"),
        Err(error @ (AuthenticationError::Refused(_) | AuthenticationError::Profile(_))) => {
            let reference = TokenVerifier::new(verifier, keys);
            match reference.verify(token).await {
                Err(failure) => {
                    // The refusal records the shared verifier's own check, or
                    // the malformed credential the compact-token admission
                    // refuses before the verifier runs.
                    assert!(
                        matches!(
                            error,
                            AuthenticationError::Refused(check)
                                if check == failure.failed_check()
                                    || check == FailedCheck::CredentialMalformed
                        ),
                        "{error:?} does not carry the verifier check"
                    );
                    Outcome::refused_by(&failure)
                }
                Ok(verified) if matches!(error, AuthenticationError::Profile(_)) => {
                    if verified.scopes.iter().any(|held| held == &scope) {
                        refusal("profile")
                    } else {
                        assert_eq!(error, AuthenticationError::Profile(FailedCheck::Scope));
                        refusal("scope")
                    }
                }
                // The credential is not a compact access token, so the
                // verifier is never reached.
                Ok(_) => {
                    assert_eq!(
                        error,
                        AuthenticationError::Refused(FailedCheck::CredentialMalformed)
                    );
                    refusal("header")
                }
            }
        }
    }
}

/// The standalone example policy, installed as a package the runtime file can name.
fn installed_example_package() -> tempfile::TempDir {
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().expect("a temp dir"))
        .expect("a package directory");
    write_package(
        &root.path().join("package"),
        &BTreeMap::from([(
            AUTHORED_POLICY_FILE.to_owned(),
            include_bytes!(
                "../../../products/scheduling/examples/standalone-exact-time/scheduling.yaml"
            )
            .to_vec(),
        )]),
        None,
        &package_limits(),
        PACKAGE_COMMAND,
    )
    .expect("the installed example package");
    root
}

#[tokio::test]
async fn scheduling_authentication_matches_the_token_corpus() {
    let corpus = TokenCorpus::load().expect("the token corpus loads");
    let installed = installed_example_package();
    let signer = TokenSigner::new();
    let report = corpus
        .run_product_async("scheduling", &signer, ISSUER, AUDIENCE, |case| {
            observe(installed.path().join("package"), case)
        })
        .await
        .expect("every scheduling row is planned and signed");
    let run = report
        .rows
        .iter()
        .filter(|row| row.observed.is_some())
        .count();
    assert!(run > 0, "no scheduling row ran");
    eprintln!(
        "scheduling: {run} rows ran, {} differ",
        report.mismatches().len()
    );
    report.assert_matches();
}
