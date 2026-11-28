// SPDX-License-Identifier: Apache-2.0
//! Runs the token fixture corpus through Casework's real authentication path
//! and asserts each result against the `casework` column of `expected.yaml`.
//!
//! The issuer entry and its key source come from a runtime file parsed by
//! `RuntimeConfig::loader` and built by `RuntimeConfig::issuer_verifiers`, as
//! at startup, with the signer's public keys served as a static key set.
//! Casework verifies RS256 and ES256 only, so the key set the file points at
//! holds those two keys.

use std::path::Path;

use registry_casework::{
    secret_resolver, AuthenticationError, CaseworkAuthenticator, RuntimeConfig,
};
use registry_casework_core::{
    AccessProfile, CaseworkActsAs, CaseworkProject, InboxPolicy, ProjectIdentity, QueuePolicy,
    CASEWORK_API_VERSION, CASEWORK_KIND,
};
use registry_platform_authcommon::FailedCheck;
use registry_platform_oidc::ActorKind;
use registry_platform_testing::{
    Against, ClaimValue, Configuration, FixtureCase, Outcome, Stage, TokenCorpus, TokenFixture,
    TokenSigner,
};
use serde_json::{json, Value};

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

/// What a configuration changes in the runtime file's issuer entry, derived
/// from the fixture the way `expected.yaml` describes.
struct Shape {
    /// `None` leaves `scopeClaim` out, so the entry reads `scope`.
    scope_claim: Option<&'static str>,
    /// `true` writes `accessTokenType: JWT`. Otherwise the member is left
    /// out and the entry admits `at+jwt` only.
    jwt_access_token: bool,
    /// Empty writes `allowedClients: unrestricted`.
    clients: Vec<String>,
    /// The client the fixture names, if any.
    client: Option<String>,
    /// The actor kind the operator declares under `recipe-declared-kind`.
    declared_kind: Option<ActorKind>,
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
        // The recipe states the type the provider writes. An entry admits
        // `at+jwt` unless it says `JWT`.
        let jwt_access_token = match case.configuration {
            Configuration::Recipe => {
                fixture
                    .header
                    .as_ref()
                    .and_then(|header| header.typ.as_deref())
                    == Some("JWT")
            }
            Configuration::JwtAccepted => true,
            Configuration::Default => false,
        };
        let client = literal_text(fixture, "client_id").or_else(|| literal_text(fixture, "azp"));
        let clients = match (&client, recipe) {
            (Some(client), _) => vec![client.clone()],
            (None, true) => Vec::new(),
            (None, false) => vec![LISTED_CLIENT.to_owned()],
        };
        let scope = fixture
            .read_scope(scope_claim.unwrap_or("scope"))
            .unwrap_or_else(|| FALLBACK_SCOPE.to_owned());
        Self {
            scope_claim,
            jwt_access_token,
            clients,
            client,
            declared_kind: case.declared_kind,
            scope,
        }
    }

    /// The entry's `accessTokenType`, `scopeClaim` and declared-kind members,
    /// each on its own line, or nothing where the row leaves them out.
    fn optional_members(&self) -> String {
        let mut members = String::new();
        if self.jwt_access_token {
            members.push_str("        accessTokenType: JWT\n");
        }
        if let Some(claim) = self.scope_claim {
            members.push_str(&format!("        scopeClaim: {claim}\n"));
        }
        if let Some(kind) = self.declared_kind {
            let kind = kind.as_str();
            // A kind is declared for the fixture's client, or for the whole
            // issuer where the token names no client.
            match &self.client {
                Some(client) => {
                    // JSON is YAML flow syntax, so any client id stays one key.
                    let declared = json!({ client.as_str(): kind });
                    members.push_str(&format!("        clientActorKinds: {declared}\n"));
                }
                None => members.push_str(&format!("        actorKind: {kind}\n")),
            }
        }
        members
    }

    fn runtime_yaml(&self, case: &FixtureCase, root: &Path) -> String {
        let clients = if self.clients.is_empty() {
            "unrestricted".to_owned()
        } else {
            json!(self.clients).to_string()
        };
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
    issuers:
      main:
        issuer: {issuer}
        audience: {audience}
        allowedClients: {clients}
{members}        jwksSource: {{type: static, documentRef: secret:file/{JWKS_FILE}}}
audit: {{path: {root}/audit.ndjson, hashKeyRef: secret:file/audit}}
contextProviders: {{}}
",
            root = root.display(),
            issuer = case.issuer,
            audience = case.audience,
            members = self.optional_members(),
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

async fn observe(case: FixtureCase, secrets: &Secrets) -> Outcome {
    let shape = Shape::of(&case);
    let loaded = RuntimeConfig::loader(registry_platform_config::DeclaredPosture {
        posture: registry_platform_config::Posture::Development,
        source: registry_platform_config::PostureSource::Flag,
    })
    .parse_str::<RuntimeConfig>(&shape.runtime_yaml(&case, &secrets.root), |_| None)
    .expect("the runtime file for this row parses");
    let config = loaded.config;
    let resolver = secret_resolver(&config).expect("the secret providers resolve");
    let verifiers = config
        .issuer_verifiers(&resolver, loaded.development.as_ref())
        .await
        .expect("the issuer verifiers build");
    let authenticator =
        CaseworkAuthenticator::new(&shape.project(), verifiers).expect("the issuer set builds");

    let profile = match case.against {
        Against::PlainRead => "requester",
        Against::HumanOnlyProfile => "staff",
    };
    match authenticator
        .authenticate(case.token.expose(), profile)
        .await
    {
        Ok(_) => Outcome::Admitted(None),
        // The person-only rule of the selected profile is a profile refusal.
        // The verifier's own actor-kind refusals are the actor-kind stage.
        Err(AuthenticationError::NotHuman(_)) => Outcome::Refused(Stage::Profile),
        Err(error) => Outcome::Refused(stage_of(error.failed_check())),
    }
}

/// The refusal stage the corpus names for the check a refusal failed.
fn stage_of(check: FailedCheck) -> Stage {
    match check {
        FailedCheck::CredentialMissing | FailedCheck::CredentialMalformed => Stage::Header,
        FailedCheck::TokenAlgorithm => Stage::Algorithm,
        FailedCheck::TokenType => Stage::TokenType,
        FailedCheck::TokenKey => Stage::Key,
        FailedCheck::TokenSignature => Stage::Signature,
        FailedCheck::TokenIssuer => Stage::Issuer,
        FailedCheck::TokenAudience => Stage::Audience,
        FailedCheck::TokenTime => Stage::Time,
        FailedCheck::TokenClient | FailedCheck::TokenAssertionIssuer => Stage::Client,
        FailedCheck::Scope => Stage::Scope,
        FailedCheck::AccessProfile => Stage::Profile,
        FailedCheck::ActorKind => Stage::ActorKind,
        FailedCheck::KeySourceUnavailable => Stage::Unavailable,
        FailedCheck::TokenClaims => Stage::Claims,
        other => panic!("the corpus has no stage for the check {}", other.as_str()),
    }
}
