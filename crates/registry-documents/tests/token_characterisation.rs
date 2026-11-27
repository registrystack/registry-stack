#![allow(
    clippy::disallowed_methods,
    reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
)]
// SPDX-License-Identifier: Apache-2.0

//! Characterisation of the Document Store's bearer authentication against the
//! token fixture corpus (`products/platform/conformance/tokens`).
//!
//! Every row of `expected.yaml` with a `documents` cell is run through the
//! authenticator the server builds: the verifier profile comes from a
//! `RuntimeConfig` loaded from a runtime file, the keys from that file's static
//! key source, the access profiles from a project package, and the credential
//! goes through `DocumentsAuthenticator::authenticate`. No database is involved.
//!
//! The project package is the published starter with its `staff` access profile
//! rewritten for the row: the fixture's client, the first scope the fixture
//! carries, and the actor kind the fixture declares (`human` when it declares
//! none, or when the row selects the human-only profile).
//!
//! The authenticator reports a verifier refusal as one error. The stage of that
//! refusal is read by running the same token through a second verifier built
//! from the same configuration and keys, so the stage is the shared verifier's
//! own label.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use registry_documents::auth::{AuthenticationError, DocumentsAuthenticator};
use registry_documents::config::RuntimeConfig;
use registry_documents::package::{package_limits, PACKAGE_COMMAND, PROJECT_FILE};
use registry_documents_core::{AccessProfiles, DocumentsProject};
use registry_platform_config::write_package;
use registry_platform_oidc::TokenVerifier;
use registry_platform_testing::{
    Against, ClaimValue, Configuration, FixtureCase, Outcome, TokenCorpus, TokenSigner,
};
use serde_json::{json, Value};

const ISSUER: &str = "https://identity.example.test";
const AUDIENCE: &str = "urn:example:documents";
/// The client a fixture without a client claim is configured against: the
/// allowed list always holds one client, as the runtime requires.
const PLACEHOLDER_CLIENT: &str = "journey-app";
const PLACEHOLDER_SCOPE: &str = "records:get";
/// The clients the starter's other access profiles name. The allowed list
/// keeps them so every profile of the package resolves a client.
const STARTER_CLIENTS: [&str; 4] = [
    "civil-registry-app",
    "citizen-portal",
    "partner-portal",
    "partner-service",
];
const STARTER_PROJECT: &str =
    include_str!("../../../products/documents/examples/starter/documents.yaml");

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

/// The actor kind the profile admits: the one the fixture declares when it is
/// a kind the Document Store has, and `human` otherwise or when the row
/// selects the human-only profile.
fn profile_actor_kind(case: &FixtureCase) -> &'static str {
    if case.against == Against::HumanOnlyProfile {
        return "human";
    }
    match literal_string(case, "registry_actor_kind").as_deref() {
        Some("service") => "service",
        _ => "human",
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

/// The starter project with its `staff` profile rewritten for the row.
fn project_text(client: &str, scope: &str, kind: &str) -> String {
    let mut project: Value = serde_norway::from_str(STARTER_PROJECT).expect("the starter parses");
    let staff = project
        .pointer_mut("/accessProfiles/staff")
        .expect("the starter has a staff access profile");
    staff["requesterClients"] = json!([client]);
    staff["requiredScopes"] = json!([scope]);
    staff["actorKind"] = json!(kind);
    serde_norway::to_string(&project).expect("the project serialises")
}

fn refusal(stage_label: &str) -> Outcome {
    format!("refused/{stage_label}")
        .parse()
        .expect("a stage the corpus knows")
}

async fn observe(case: FixtureCase) -> Outcome {
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().expect("a temp dir"))
        .expect("a runtime directory");
    let secrets = root.path().join("secrets");
    fs::create_dir(&secrets).expect("a secrets directory");
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700)).expect("restrict secrets");
    write_private(
        &secrets.join("jwks.json"),
        &serde_json::to_vec(&static_key_set(&case.jwks)).expect("a key set"),
    );
    // The database is never contacted: only the key source and the verifier
    // profile are built from this runtime file.
    write_private(
        &secrets.join("database-url"),
        b"postgresql://corpus@127.0.0.1:1/corpus",
    );
    write_private(
        &secrets.join("audit-key"),
        b"documents-corpus-audit-key-0123456789",
    );
    write_private(
        &secrets.join("hook-key"),
        b"documents-corpus-hook-key-0123456789",
    );

    let claim = scope_claim(&case);
    let scope = case
        .fixture
        .read_scope(claim)
        .unwrap_or_else(|| PLACEHOLDER_SCOPE.to_owned());
    let client = fixture_client(&case);
    let project = project_text(&client, &scope, profile_actor_kind(&case));
    let package = root.path().join("package");
    write_package(
        &package,
        &BTreeMap::from([(PROJECT_FILE.to_owned(), project.clone().into_bytes())]),
        None,
        &package_limits(),
        PACKAGE_COMMAND,
    )
    .expect("the package for the row");

    let mut allowed = vec![client];
    allowed.extend(STARTER_CLIENTS.map(str::to_owned));
    let runtime_path = root.path().join("runtime.yaml");
    fs::write(
        &runtime_path,
        format!(
            "\
apiVersion: id.registrystack.org/formats/documents/runtime/v1alpha1
kind: DocumentsRuntimeConfig
identity:
  databaseId: token-characterisation
package:
  root: {package}
listener:
  bind: 127.0.0.1:0
  tlsTermination: development-loopback
  networkExposure: private-address
secretProviders:
  file:
    root: {secrets}
database:
  runtimeUrlRef: secret:file/database-url
  migrationUrlRef: secret:file/database-url
authentication:
  oidc:
    issuer: {issuer}
    audience: {audience}
    scopeClaim: {claim}
    allowedClients: {allowed}
    jwksSource:
      type: static
      documentRef: secret:file/jwks.json
audit:
  destination: file
  path: {audit}
  hashKeyRef: secret:file/audit-key
storage:
  type: database
contentVerification:
  type: disabled
cleanup:
  erasure: active
destinations:
  hooks:
    owning-system-events:
      url: http://127.0.0.1:9/document-events
      hmacSha256KeyRef: secret:file/hook-key
      attemptTimeoutMilliseconds: 1000
      maximumAttempts: 2
",
            package = package.display(),
            secrets = secrets.display(),
            issuer = case.issuer,
            audience = case.audience,
            allowed = serde_json::to_string(&allowed).expect("a client list"),
            audit = root.path().join("audit.ndjson").display(),
        ),
    )
    .expect("write the runtime file");
    let config = RuntimeConfig::load(&runtime_path).expect("the runtime configuration loads");
    let resolver = config.secret_resolver().expect("the secret resolver");
    let keys = config
        .jwks_fetcher(&resolver)
        .await
        .expect("the static key source");
    let decoded = DocumentsProject::decode(PROJECT_FILE, project.as_bytes())
        .expect("the rewritten project decodes")
        .value;

    let admitted = config
        .admitted_clients(&decoded)
        .expect("the listed clients cover the project");
    let authenticator = DocumentsAuthenticator::new(
        config.verifier_profile(&admitted),
        keys.clone(),
        AccessProfiles::new(&decoded),
        config.binds_assertion_issuers(),
    );
    let token = case.token.expose();
    match authenticator.authenticate(token).await {
        Ok(caller) => Outcome::Admitted(Some(caller.kind.as_str().to_owned())),
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

#[tokio::test]
async fn documents_authentication_matches_the_token_corpus() {
    let corpus = TokenCorpus::load().expect("the token corpus loads");
    let signer = TokenSigner::new();
    let report = corpus
        .run_product_async("documents", &signer, ISSUER, AUDIENCE, observe)
        .await
        .expect("every documents row is planned and signed");
    let run = report
        .rows
        .iter()
        .filter(|row| row.observed.is_some())
        .count();
    assert!(run > 0, "no documents row ran");
    eprintln!(
        "documents: {run} rows ran, {} differ",
        report.mismatches().len()
    );
    report.assert_matches();
}
