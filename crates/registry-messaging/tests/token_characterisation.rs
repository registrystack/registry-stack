// SPDX-License-Identifier: Apache-2.0

//! Characterisation of Messaging's bearer authentication against the token
//! fixture corpus (`products/platform/conformance/tokens`).
//!
//! Every row of `expected.yaml` with a `messaging` cell is run through the
//! authenticator the server builds: the verifier profile comes from a
//! `RuntimeConfig` loaded from a runtime file, the keys from that file's static
//! key source, and the credential goes through
//! `MessagingAuthenticator::authenticate`. No database is involved.
//!
//! The authenticator reports a verifier refusal as one error. The stage of that
//! refusal is read by running the same token through a second verifier built
//! from the same configuration and keys, so the stage is the shared verifier's
//! own label.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use registry_messaging::auth::{AuthenticationError, MessagingAuthenticator};
use registry_messaging::config::RuntimeConfig;
use registry_messaging::package::{package_inputs, write_package_inputs};
use registry_messaging_core::{
    AccessProfile, AccessProfiles, ActorKind, ActsAs, MESSAGING_RUNTIME_API_VERSION,
    MESSAGING_RUNTIME_KIND,
};
use registry_platform_oidc::TokenVerifier;
use registry_platform_testing::{
    Against, ClaimValue, Configuration, FixtureCase, Outcome, TokenCorpus, TokenSigner,
};
use serde_json::{json, Value};

const ISSUER: &str = "https://identity.example.test";
const AUDIENCE: &str = "urn:example:messaging";
/// The client a fixture without a client claim is configured against: the
/// allowed list always holds one client, as the runtime requires.
const PLACEHOLDER_CLIENT: &str = "journey-app";
/// Clients the installed starter package names. The runtime refuses a
/// configuration whose allowed list omits a client of a package profile.
const PACKAGE_CLIENTS: [&str; 2] = ["case-system", "operations-console"];
const PLACEHOLDER_SCOPE: &str = "records:get";

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

fn profiles(case: &FixtureCase, scope: &str) -> AccessProfiles {
    AccessProfiles::new(vec![AccessProfile {
        id: "corpus".to_owned(),
        label: None,
        description: None,
        principal_claim: "sub".to_owned(),
        required_scopes: vec![scope.to_owned()],
        requester_clients: vec![fixture_client(case)],
        actor_kind: (case.against == Against::HumanOnlyProfile).then_some(ActorKind::Human),
        acts_as: ActsAs::Operator,
        sender_profiles: Vec::new(),
        templates: Vec::new(),
        allow_direct_content: false,
        requests_per_minute: 60,
        burst: 10,
        maximum_messages_per_day: None,
    }])
    .expect("a valid access profile")
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
            "apiVersion": MESSAGING_RUNTIME_API_VERSION,
            "kind": MESSAGING_RUNTIME_KIND,
            "identity": {"databaseId": "token-characterisation"},
            "package": {"root": package_root},
            "listener": {"bind": "127.0.0.1:0", "tlsTermination": "development-loopback"},
            "secretProviders": {"file": {"root": secrets}, "environment": {}},
            "database": {
                "runtimeUrlRef": "secret:env/MESSAGING_RUNTIME_URL",
                "migrationUrlRef": "secret:env/MESSAGING_MIGRATION_URL"
            },
            "authentication": {"oidc": {
                "issuer": case.issuer,
                "audience": case.audience,
                "jwksSource": {"type": "static", "documentRef": "secret:file/issuer-jwks"},
                "allowedClients": [fixture_client(&case), PACKAGE_CLIENTS[0], PACKAGE_CLIENTS[1]],
                "scopeClaim": claim
            }},
            "audit": {"path": root.path().join("audit"), "hashKeyRef": "secret:file/audit-hash-key"}
        }))
        .expect("a runtime document"),
    )
    .expect("write the runtime file");
    let config = RuntimeConfig::load(&runtime_path).expect("the runtime configuration loads");
    let resolver = config.secret_resolver().expect("the secret resolver");
    let keys = config
        .jwks_fetcher(&resolver)
        .await
        .expect("the static key source");

    let profiles = profiles(&case, &scope);
    let admitted = config
        .admitted_clients(&profiles)
        .expect("the listed clients cover the profile");
    let authenticator = MessagingAuthenticator::new(
        config.verifier_profile(&admitted),
        Arc::clone(&keys),
        profiles,
        config.binds_assertion_issuers(),
    );
    let token = case.token.expose();
    match authenticator.authenticate(token).await {
        Ok(caller) => Outcome::Admitted(Some(
            caller
                .actor_kind
                .map_or("unspecified", ActorKind::as_str)
                .to_owned(),
        )),
        Err(AuthenticationError::Claims(_)) => refusal("claims"),
        Err(AuthenticationError::Unavailable) => refusal("unavailable"),
        Err(error @ (AuthenticationError::Refused(_) | AuthenticationError::Profile(_))) => {
            let reference = TokenVerifier::new(config.verifier_profile(&admitted), keys);
            match reference.verify(token).await {
                Err(failure) => refusal(failure.authentication_stage().label()),
                Ok(verified) if matches!(error, AuthenticationError::Profile(_)) => {
                    if verified.scopes.iter().any(|held| held == &scope) {
                        refusal("profile")
                    } else {
                        refusal("scope")
                    }
                }
                // The credential is not a compact access token, so the
                // verifier is never reached.
                Ok(_) => refusal("header"),
            }
        }
    }
}

/// The published starter, installed as a package the runtime file can name.
fn installed_starter_package() -> tempfile::TempDir {
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().expect("a temp dir"))
        .expect("a package directory");
    let starter =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/messaging/examples/starter");
    let project = root.path().join("project");
    fs::create_dir_all(&project).expect("a project directory");
    fs::copy(
        starter.join("messaging.yaml"),
        project.join("messaging.yaml"),
    )
    .expect("the starter manifest");
    copy_tree(&starter.join("templates"), &project.join("templates"));
    copy_tree(&starter.join("providers"), &project.join("providers"));
    let inputs = package_inputs(&project).expect("the starter package inputs");
    write_package_inputs(&root.path().join("package"), &inputs, None)
        .expect("the installed starter package");
    root
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("a directory");
    for entry in fs::read_dir(from).expect("a directory to copy") {
        let entry = entry.expect("a directory entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("an entry type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("a copied file");
        }
    }
}

#[tokio::test]
async fn messaging_authentication_matches_the_token_corpus() {
    let corpus = TokenCorpus::load().expect("the token corpus loads");
    let installed = installed_starter_package();
    let signer = TokenSigner::new();
    let report = corpus
        .run_product_async("messaging", &signer, ISSUER, AUDIENCE, |case| {
            observe(installed.path().join("package"), case)
        })
        .await
        .expect("every messaging row is planned and signed");
    let run = report
        .rows
        .iter()
        .filter(|row| row.observed.is_some())
        .count();
    assert!(run > 0, "no messaging row ran");
    eprintln!(
        "messaging: {run} rows ran, {} differ",
        report.mismatches().len()
    );
    report.assert_matches();
}
