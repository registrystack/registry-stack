// SPDX-License-Identifier: Apache-2.0
//! Runs the token fixture corpus through Casework's real authentication path
//! and asserts each result against the `casework` column of `expected.yaml`.
//!
//! The access-token verifier profile and the key source come from a runtime
//! file parsed by `RuntimeConfig::loader` and built by
//! `RuntimeConfig::oidc_verifier`, as at startup, with the signer's public
//! keys served as a static key set. Casework verifies RS256 and ES256 only, so
//! the key set the file points at holds those two keys.

use std::path::Path;
use std::sync::Arc;

use registry_casework::{
    secret_resolver, AuthenticationError, CaseworkAuthenticator, RuntimeConfig,
};
use registry_casework_core::{
    AccessProfile, CaseworkActsAs, CaseworkProject, InboxPolicy, ProjectIdentity, QueuePolicy,
    CASEWORK_API_VERSION, CASEWORK_KIND,
};
use registry_platform_oidc::JwksFetcher;
use registry_platform_testing::{
    Against, CapturedDiagnosticLogs, ClaimValue, Configuration, FixtureCase, Outcome, Stage,
    TokenCorpus, TokenFixture, TokenSigner,
};
use serde_json::{json, Value};
use tracing::instrument::WithSubscriber;

const ISSUER: &str = "https://issuer.example.test";
const AUDIENCE: &str = "urn:casework:test";
/// The client a default configuration lists when the fixture names none, so a
/// token without a client claim meets a list that does not include it.
const LISTED_CLIENT: &str = "journey-app";
/// The scope a profile requires when the fixture carries none.
const FALLBACK_SCOPE: &str = "records:get";
const JWKS_FILE: &str = "oidc-jwks";

#[tokio::test]
async fn casework_token_characterisation() {
    let corpus = TokenCorpus::load().expect("the corpus loads");
    let signer = TokenSigner::new();
    let root = tempfile::tempdir().expect("temporary directory");
    let secrets = Secrets::write(root.path(), &signer.public_key_set());
    let report = corpus
        .run_product_async("casework", &signer, ISSUER, AUDIENCE, |case| {
            observe(case, &secrets)
        })
        .await
        .expect("the corpus runs");
    assert!(
        report.rows.iter().any(|row| row.observed.is_some()),
        "no row ran, so the test proves nothing"
    );
    report.assert_matches();
}

/// The directory the runtime file's `file` secret provider reads, holding the
/// static key set.
struct Secrets {
    root: std::path::PathBuf,
}

impl Secrets {
    fn write(root: &Path, public_keys: &Value) -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let root = std::fs::canonicalize(root).expect("canonical root");
        let directory = root.join("secrets");
        std::fs::create_dir(&directory).expect("secrets directory");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("private secrets directory");
        // The runtime refuses a static key set that holds an OKP key, and it
        // verifies RS256 and ES256 only.
        let keys: Vec<&Value> = public_keys["keys"]
            .as_array()
            .expect("the key set lists keys")
            .iter()
            .filter(|key| matches!(key["kty"].as_str(), Some("RSA" | "EC")))
            .collect();
        let file = directory.join(JWKS_FILE);
        std::fs::write(&file, json!({ "keys": keys }).to_string()).expect("key set file");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))
            .expect("private key set file");
        Self { root }
    }
}

/// What a configuration changes in the runtime file's `authentication.oidc`
/// block, derived from the fixture the way `expected.yaml` describes.
struct Shape {
    /// `None` leaves `scopeClaim` out, as the runner's own file does.
    scope_claim: Option<&'static str>,
    /// Empty writes `allowedClients: unrestricted`.
    clients: Vec<String>,
    /// The scope the access profile requires.
    scope: String,
}

impl Shape {
    fn of(case: &FixtureCase) -> Self {
        let fixture = &case.fixture;
        let recipe = case.configuration == Configuration::Recipe;
        let scope_claim = match (recipe, fixture.claims.contains_key("scp")) {
            (true, true) => Some("scp"),
            (true, false) => Some("scope"),
            (false, _) => None,
        };
        let client = literal_text(fixture, "client_id").or_else(|| literal_text(fixture, "azp"));
        let clients = match (client, recipe) {
            (Some(client), _) => vec![client],
            (None, true) => Vec::new(),
            (None, false) => vec![LISTED_CLIENT.to_owned()],
        };
        let scope = first_scope(fixture, scope_claim.unwrap_or("registry_scopes"))
            .unwrap_or_else(|| FALLBACK_SCOPE.to_owned());
        Self {
            scope_claim,
            clients,
            scope,
        }
    }

    fn runtime_yaml(&self, case: &FixtureCase, root: &Path) -> String {
        let clients = if self.clients.is_empty() {
            "unrestricted".to_owned()
        } else {
            json!(self.clients).to_string()
        };
        let scope_claim = self
            .scope_claim
            .map(|claim| format!("    scopeClaim: {claim}\n"))
            .unwrap_or_default();
        format!(
            "apiVersion: id.registrystack.org/formats/casework/runtime/v1alpha1
kind: CaseworkRuntimeConfig
identity: {{databaseId: casework-token-test}}
package: {{root: {root}/package}}
listener: {{bind: \"127.0.0.1:8100\", tlsTermination: development-loopback}}
secretProviders: {{file: {{root: {root}/secrets}}, environment: {{}}}}
database: {{runtimeUrlRef: secret:env/RUNTIME, migrationUrlRef: secret:env/MIGRATION}}
authentication:
  oidc:
    issuer: {issuer}
    audience: {audience}
    allowedClients: {clients}
{scope_claim}    jwksSource: {{type: static, documentRef: secret:file/{JWKS_FILE}}}
audit: {{path: {root}/audit.ndjson, hashKeyRef: secret:file/audit}}
contextProviders: {{}}
",
            root = root.display(),
            issuer = case.issuer,
            audience = case.audience,
        )
    }

    /// A project with a Requester profile, which a service identity may use,
    /// and a Staff profile, which only a person may use. Each requires the
    /// fixture's first scope.
    fn project(&self) -> CaseworkProject {
        let starter = CaseworkProject::from_slice(include_bytes!(
            "../../../products/casework/examples/standalone-decision/casework.yaml"
        ))
        .expect("canonical review fixture");
        let profile = |id: &str, acts_as| AccessProfile {
            id: id.to_owned(),
            label: None,
            description: None,
            principal_claim: "sub".to_owned(),
            required_scopes: vec![self.scope.clone()],
            acts_as,
        };
        CaseworkProject {
            task_templates: Vec::new(),
            api_version: CASEWORK_API_VERSION.to_owned(),
            kind: CASEWORK_KIND.to_owned(),
            project: ProjectIdentity::new(
                "token-characterisation".parse().expect("project id"),
                "1".to_owned(),
            ),
            access_profiles: vec![
                profile("requester", CaseworkActsAs::Requester),
                profile("staff", CaseworkActsAs::Staff),
            ],
            queues: vec![QueuePolicy {
                id: "decisions".to_owned(),
                label: "Decisions".to_owned(),
            }],
            teams: starter.teams,
            context_providers: Vec::new(),
            review_policies: starter.review_policies,
            trusted_producers: starter.trusted_producers,
            calendars: Vec::new(),
            clocks: Vec::new(),
            inbox: InboxPolicy::default(),
        }
    }
}

fn literal_text(fixture: &TokenFixture, claim: &str) -> Option<String> {
    match fixture.claims.get(claim) {
        Some(ClaimValue::Literal(Value::String(text))) => Some(text.clone()),
        _ => None,
    }
}

/// The first scope the fixture carries in `claim`, a space-separated string or
/// a list.
fn first_scope(fixture: &TokenFixture, claim: &str) -> Option<String> {
    match fixture.claims.get(claim) {
        Some(ClaimValue::Literal(Value::String(text))) => text.split(' ').next().map(str::to_owned),
        Some(ClaimValue::Literal(Value::Array(items))) => {
            items.first().and_then(Value::as_str).map(str::to_owned)
        }
        _ => None,
    }
}

async fn observe(case: FixtureCase, secrets: &Secrets) -> Outcome {
    let shape = Shape::of(&case);
    let config = RuntimeConfig::loader()
        .parse_str::<RuntimeConfig>(&shape.runtime_yaml(&case, &secrets.root), |_| None)
        .expect("the runtime file for this row parses")
        .config;
    let resolver = secret_resolver(&config).expect("the secret providers resolve");
    let (verifier, keys): (_, Arc<JwksFetcher>) = config
        .oidc_verifier(&resolver)
        .await
        .expect("the verifier profile builds");
    let authenticator = CaseworkAuthenticator::new(
        &shape.project(),
        verifier,
        keys,
        config.authentication.oidc.human_identity.clone(),
    );

    let profile = match case.against {
        Against::PlainRead => "requester",
        Against::HumanOnlyProfile => "staff",
    };
    let logs = CapturedDiagnosticLogs::default();
    let result = authenticator
        .authenticate(case.token.expose(), profile)
        .with_subscriber(logs.subscriber())
        .await;
    match result {
        Ok(_) => Outcome::Admitted(None),
        Err(AuthenticationError::Claims) => Outcome::Refused(Stage::Claims),
        Err(
            AuthenticationError::Refused
            | AuthenticationError::Profile
            | AuthenticationError::NotHuman,
        ) => logged_stage(&logs).map_or(Outcome::Unknown, Outcome::Refused),
    }
}

/// The stage of the one value-free diagnostic a refusal logged, when there is
/// exactly one.
fn logged_stage(logs: &CapturedDiagnosticLogs) -> Option<Stage> {
    let text = logs.text();
    let stages: Vec<String> = text
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|line| line["fields"]["stage"].as_str().map(str::to_owned))
        .collect();
    match stages.as_slice() {
        [stage] => match format!("refused/{stage}").parse::<Outcome>() {
            Ok(Outcome::Refused(stage)) => Some(stage),
            other => panic!("the logged stage is not a known stage: {other:?}"),
        },
        _ => None,
    }
}
