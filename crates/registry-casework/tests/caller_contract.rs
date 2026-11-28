// SPDX-License-Identifier: Apache-2.0

//! The caller contract on Casework's authentication path: several issuers,
//! the access-token type, the caller kind, and the refusal detail a
//! development process adds.
//!
//! Each authenticator is built as startup builds it: a runtime file read by
//! `RuntimeConfig::loader`, checked, and turned into one verifier per issuer
//! entry by `RuntimeConfig::issuer_verifiers`. Each entry reads its signing
//! keys from its own static key set, so a token that names one issuer and is
//! signed with another's key meets the named issuer's keys.

use std::path::Path;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use registry_casework::{
    router_with_recorder, secret_resolver, AuthenticationError, CaseworkAuthenticator,
    CaseworkService, DatabaseConfig, HttpState, PostgresStore, RuntimeConfig,
};
use registry_casework_core::{CaseworkActsAs, CaseworkProject};
use registry_platform_authcommon::{FailedCheck, RefusalRecorder};
use registry_platform_config::{
    DeclaredPosture, LoadedRuntimeConfig, Posture, PostureReport, PostureSource, SecretProvider,
    SecretResolver,
};
use registry_platform_crypto::PrivateJwk;
use registry_platform_testing::{
    access_token_test_key, jwks_from_private_jwk, sign_compact_jwt_with_key, CapturedDiagnosticLogs,
};
use serde_json::{json, Value};
use tower::ServiceExt as _;
use tracing::instrument::WithSubscriber as _;

const AUDIENCE: &str = "urn:casework:caller-contract";
const PROFILE_HEADER: &str = "registry-casework-profile";
const STAFF_SCOPE: &str = "casework:staff";
const REQUEST_SCOPE: &str = "casework:request";
const PORTAL: &str = "casework-portal";
const PARTNER_CLIENT: &str = "partner-batch";

/// One issuer the tests sign for, with its own key.
struct Issuer {
    id: &'static str,
    iss: &'static str,
    key: PrivateJwk,
}

impl Issuer {
    fn new(id: &'static str, iss: &'static str) -> Self {
        Self {
            id,
            iss,
            key: access_token_test_key(jsonwebtoken::Algorithm::ES256),
        }
    }

    fn main() -> Self {
        Self::new("main", "https://people.example.test")
    }

    fn partners() -> Self {
        Self::new("partners", "https://partners.example.test")
    }

    /// The entry `authentication.oidc.issuers.<id>` reads, before `extra`
    /// adds or replaces members.
    fn entry(&self, extra: Value) -> Value {
        let mut entry = json!({
            "issuer": self.iss,
            "audience": AUDIENCE,
            "allowedClients": "unrestricted",
            "jwksSource": {"type": "static", "documentRef": format!("secret:file/jwks-{}", self.id)},
        });
        entry
            .as_object_mut()
            .expect("an entry is an object")
            .extend(extra.as_object().expect("extra is an object").clone());
        entry
    }

    /// A token signed with this issuer's key. `claims` adds to or replaces
    /// the issuer, audience, subject and lifetime.
    fn sign(&self, typ: &str, claims: Value) -> String {
        sign_with(&self.key, typ, self.claims(claims))
    }

    fn claims(&self, claims: Value) -> Value {
        let now = chrono::Utc::now().timestamp();
        let mut all = json!({
            "iss": self.iss,
            "aud": AUDIENCE,
            "sub": "person-1",
            "iat": now,
            "exp": now + 300,
        });
        all.as_object_mut()
            .expect("claims are an object")
            .extend(claims.as_object().expect("claims are an object").clone());
        all
    }
}

fn sign_with(key: &PrivateJwk, typ: &str, claims: Value) -> String {
    let kid = key.kid.clone().expect("the test key has a key id");
    sign_compact_jwt_with_key(key, typ, &kid, claims)
}

/// The runtime file's directory: its secrets hold one static key set per
/// issuer.
struct Deployment {
    root: tempfile::TempDir,
}

impl Deployment {
    fn new(issuers: &[&Issuer]) -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap())
            .expect("temporary directory");
        let secrets = root.path().join("secrets");
        std::fs::create_dir(&secrets).expect("secrets directory");
        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700))
            .expect("private secrets directory");
        for issuer in issuers {
            let file = secrets.join(format!("jwks-{}", issuer.id));
            std::fs::write(&file, jwks_from_private_jwk(&issuer.key).to_string())
                .expect("key set file");
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))
                .expect("private key set file");
        }
        Self { root }
    }

    fn path(&self) -> &Path {
        self.root.path()
    }

    /// Read `entries` as `authentication.oidc.issuers` the way startup reads
    /// a runtime file that declares the development posture, so an entry may
    /// state a development-only setting.
    fn config(&self, entries: Value) -> LoadedRuntimeConfig<RuntimeConfig> {
        let root = self.path();
        let document = json!({
            "apiVersion": "id.registrystack.org/formats/casework/runtime/v1alpha1",
            "kind": "CaseworkRuntimeConfig",
            "identity": {"databaseId": "caller-contract"},
            "package": {"root": root.join("package")},
            "listener": {"bind": "127.0.0.1:8100", "tlsTermination": "development-loopback"},
            "secretProviders": {"file": {"root": root.join("secrets")}, "environment": {}},
            "database": {"runtimeUrlRef": "secret:env/RUNTIME", "migrationUrlRef": "secret:env/MIGRATION"},
            "authentication": {"oidc": {"issuers": entries}},
            "audit": {"path": root.join("audit.ndjson"), "hashKeyRef": "secret:file/audit"},
        });
        let loaded = RuntimeConfig::loader(declared(Posture::Development))
            .parse_str::<RuntimeConfig>(&document.to_string(), |_| None)
            .expect("the runtime file parses");
        let findings = loaded.config.findings(None);
        assert!(findings.is_empty(), "{findings:?}");
        loaded
    }

    async fn authenticator(&self, entries: Value) -> CaseworkAuthenticator {
        let loaded = self.config(entries);
        let resolver = secret_resolver(&loaded.config).expect("the secret providers resolve");
        let verifiers = loaded
            .config
            .issuer_verifiers(&resolver, loaded.development.as_ref())
            .await
            .expect("each issuer entry builds a verifier");
        CaseworkAuthenticator::new(&project(), verifiers).expect("the issuer set builds")
    }

    async fn router(
        &self,
        entries: Value,
        posture: Posture,
        recorder: Arc<RefusalRecorder>,
    ) -> axum::Router {
        let project = project();
        let service = CaseworkService::new(unconnected_store(self.path()), project.clone(), [])
            .expect("a service with no providers");
        router_with_recorder(
            HttpState {
                posture: PostureReport::new(declared(posture)),
                service,
                authenticator: Arc::new(self.authenticator(entries).await),
                project: Arc::new(project),
            },
            recorder,
        )
    }
}

/// `posture`, declared by flag.
fn declared(posture: Posture) -> DeclaredPosture {
    DeclaredPosture {
        posture,
        source: PostureSource::Flag,
    }
}

/// A store whose pool has no server behind it. It connects only when used,
/// and every request here is answered before a handler reaches it.
fn unconnected_store(root: &Path) -> PostgresStore {
    use std::os::unix::fs::PermissionsExt as _;
    let directory = root.join("store-secrets");
    std::fs::create_dir_all(&directory).expect("store secret directory");
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
        .expect("private store secret directory");
    let file = directory.join("database-url");
    std::fs::write(&file, "postgresql://casework@127.0.0.1:9/casework").expect("database url");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))
        .expect("private database url");
    let secrets = SecretResolver::new([SecretProvider::File], &directory).expect("secret resolver");
    PostgresStore::connect_runtime(
        &DatabaseConfig {
            runtime_url_ref: "secret:file/database-url".to_owned(),
            migration_url_ref: "secret:file/database-url".to_owned(),
            ca_bundle_ref: None,
            test_only_plaintext: false,
            transport: None,
        },
        &secrets,
        None,
    )
    .expect("an unconnected runtime store")
}

/// The standalone decision project. Its Staff profile is one only a person
/// may use, and its Requester profile pins no kind. Both read `sub`.
fn project() -> CaseworkProject {
    CaseworkProject::from_slice(include_bytes!(
        "../../../products/casework/examples/standalone-decision/casework.yaml"
    ))
    .expect("canonical review fixture")
}

fn person(scope: &str) -> Value {
    json!({"scope": scope, "registry_actor_kind": "human"})
}

fn refused(check: FailedCheck) -> AuthenticationError {
    AuthenticationError::Refused(check)
}

async fn get(app: &axum::Router, path: &str, token: &str, profile: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header(PROFILE_HEADER, profile)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    let mut body: Value = serde_json::from_slice(&bytes).expect("a JSON body");
    if let Some(problem) = body.as_object_mut() {
        problem.remove("traceId");
    }
    (status, body)
}

#[tokio::test]
async fn a_jwt_typed_token_is_refused_by_default_and_the_log_names_the_setting() {
    let main = Issuer::main();
    let deployment = Deployment::new(&[&main]);
    let entries = json!({"main": main.entry(json!({}))});
    let authenticator = deployment.authenticator(entries.clone()).await;
    authenticator
        .authenticate(&main.sign("at+jwt", person(STAFF_SCOPE)), "staff")
        .await
        .expect("an RFC 9068 access token is admitted by default");

    let token = main.sign("JWT", person(STAFF_SCOPE));
    assert_eq!(
        authenticator.authenticate(&token, "staff").await,
        Err(refused(FailedCheck::TokenType))
    );

    let recorder = Arc::new(RefusalRecorder::new("casework").expect("the casework recorder"));
    let app = deployment
        .router(entries, Posture::Production, Arc::clone(&recorder))
        .await;
    let logs = CapturedDiagnosticLogs::default();
    let (status, body) = get(&app, "/v1/review-tasks", &token, "staff")
        .with_subscriber(logs.subscriber())
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "authentication.refused");
    assert!(body.get("failedCheck").is_none(), "{body}");
    let text = logs.text();
    let line: Value = serde_json::from_str(text.lines().next().expect("a refusal line"))
        .expect("a JSON log line");
    assert_eq!(line["fields"]["failed_check"], "token-type", "{text}");
    let remedy = line["fields"]["remedy"]
        .as_str()
        .expect("the line names a remedy");
    assert!(remedy.contains("accessTokenType"), "{remedy}");
    assert!(!text.contains(&token), "{text}");
}

#[tokio::test]
async fn a_jwt_typed_token_is_admitted_when_the_issuer_states_it() {
    let main = Issuer::main();
    let deployment = Deployment::new(&[&main]);
    let authenticator = deployment
        .authenticator(json!({"main": main.entry(json!({"accessTokenType": "JWT"}))}))
        .await;
    let actor = authenticator
        .authenticate(&main.sign("JWT", person(STAFF_SCOPE)), "staff")
        .await
        .expect("the entry admits a JWT-typed access token");
    assert_eq!(actor.profile_id, "staff");
}

#[tokio::test]
async fn an_id_token_is_refused_whether_or_not_jwt_is_admitted() {
    let main = Issuer::main();
    let deployment = Deployment::new(&[&main]);
    let mut id_token_claims = person(STAFF_SCOPE);
    id_token_claims["nonce"] = json!("n-0S6_WzA2Mj");
    let id_token = main.sign("JWT", id_token_claims);
    for entry in [json!({}), json!({"accessTokenType": "JWT"})] {
        let authenticator = deployment
            .authenticator(json!({"main": main.entry(entry.clone())}))
            .await;
        assert_eq!(
            authenticator.authenticate(&id_token, "staff").await,
            Err(refused(FailedCheck::TokenType)),
            "{entry}"
        );
    }
}

#[tokio::test]
async fn a_token_without_a_kind_authenticates_as_unspecified() {
    let main = Issuer::main();
    let deployment = Deployment::new(&[&main]);
    let authenticator = deployment
        .authenticator(json!({"main": main.entry(json!({}))}))
        .await;
    let actor = authenticator
        .authenticate(
            &main.sign("at+jwt", json!({"scope": REQUEST_SCOPE})),
            "requester",
        )
        .await
        .expect("a profile that pins no kind admits a token that names none");
    assert_eq!(actor.role, CaseworkActsAs::Requester);
    assert_eq!(actor.principal.subject, "person-1");
}

#[tokio::test]
async fn a_human_only_profile_refuses_an_unspecified_kind() {
    let main = Issuer::main();
    let deployment = Deployment::new(&[&main]);
    let authenticator = deployment
        .authenticator(json!({"main": main.entry(json!({}))}))
        .await;
    assert_eq!(
        authenticator
            .authenticate(&main.sign("at+jwt", json!({"scope": STAFF_SCOPE})), "staff")
            .await,
        Err(AuthenticationError::NotHuman(FailedCheck::ActorKind))
    );
}

#[tokio::test]
async fn a_declared_client_kind_admits_a_token_without_a_kind() {
    let main = Issuer::main();
    let deployment = Deployment::new(&[&main]);
    let authenticator = deployment
        .authenticator(json!({"main": main.entry(json!({
            "allowedClients": [PORTAL],
            "clientActorKinds": {PORTAL: "human"},
        }))}))
        .await;
    let actor = authenticator
        .authenticate(
            &main.sign("at+jwt", json!({"scope": STAFF_SCOPE, "azp": PORTAL})),
            "staff",
        )
        .await
        .expect("the declared kind makes the caller a person");
    assert_eq!(actor.role, CaseworkActsAs::Staff);
}

#[tokio::test]
async fn a_token_kind_that_contradicts_the_declared_kind_is_refused() {
    let main = Issuer::main();
    let deployment = Deployment::new(&[&main]);
    let authenticator = deployment
        .authenticator(json!({"main": main.entry(json!({
            "allowedClients": [PORTAL],
            "clientActorKinds": {PORTAL: "human"},
        }))}))
        .await;
    let token = main.sign(
        "at+jwt",
        json!({"scope": REQUEST_SCOPE, "azp": PORTAL, "registry_actor_kind": "service"}),
    );
    assert_eq!(
        authenticator.authenticate(&token, "requester").await,
        Err(refused(FailedCheck::ActorKind))
    );
}

#[tokio::test]
async fn an_unlisted_client_is_refused() {
    let main = Issuer::main();
    let deployment = Deployment::new(&[&main]);
    let authenticator = deployment
        .authenticator(json!({"main": main.entry(json!({"allowedClients": [PORTAL]}))}))
        .await;
    let mut claims = person(STAFF_SCOPE);
    claims["azp"] = json!("another-app");
    assert_eq!(
        authenticator
            .authenticate(&main.sign("at+jwt", claims), "staff")
            .await,
        Err(refused(FailedCheck::TokenClient))
    );
}

#[tokio::test]
async fn an_identity_only_token_is_refused_without_a_declared_kind() {
    let main = Issuer::main();
    let deployment = Deployment::new(&[&main]);
    // A kind the token claims is token content, not the operator's
    // declaration, so it does not admit an identity-only token.
    let token = main.sign("at+jwt", person("openid profile email"));
    let authenticator = deployment
        .authenticator(json!({"main": main.entry(json!({}))}))
        .await;
    assert_eq!(
        authenticator.authenticate(&token, "staff").await,
        Err(refused(FailedCheck::ActorKind))
    );
    // A declared kind admits it to authentication, where the profile's
    // required scope then refuses it.
    let declared = deployment
        .authenticator(json!({"main": main.entry(json!({"actorKind": "human"}))}))
        .await;
    assert_eq!(
        declared.authenticate(&token, "staff").await,
        Err(AuthenticationError::Profile(FailedCheck::Scope))
    );
}

/// `main` reads the default type and scope claim and admits every client.
/// `partners` admits plain JWTs, reads `scp`, and lists one client.
fn two_entries(main: &Issuer, partners: &Issuer) -> Value {
    json!({
        "main": main.entry(json!({})),
        "partners": partners.entry(json!({
            "accessTokenType": "JWT",
            "scopeClaim": "scp",
            "allowedClients": [PARTNER_CLIENT],
        })),
    })
}

#[tokio::test]
async fn a_token_from_each_configured_issuer_is_verified_under_its_own_rules() {
    let main = Issuer::main();
    let partners = Issuer::partners();
    let deployment = Deployment::new(&[&main, &partners]);
    let authenticator = deployment
        .authenticator(two_entries(&main, &partners))
        .await;

    let actor = authenticator
        .authenticate(&main.sign("at+jwt", person(STAFF_SCOPE)), "staff")
        .await
        .expect("main admits its own token");
    assert_eq!(actor.principal.issuer, main.iss);
    let actor = authenticator
        .authenticate(
            &partners.sign(
                "JWT",
                json!({"scp": REQUEST_SCOPE, "azp": PARTNER_CLIENT, "registry_actor_kind": "service"}),
            ),
            "requester",
        )
        .await
        .expect("partners admits its own token");
    assert_eq!(actor.principal.issuer, partners.iss);
    assert_eq!(actor.principal.subject, "person-1");

    // Each entry's rules stay its own.
    assert_eq!(
        authenticator
            .authenticate(&main.sign("JWT", person(STAFF_SCOPE)), "staff")
            .await,
        Err(refused(FailedCheck::TokenType)),
        "main does not admit a plain JWT because partners does"
    );
    assert_eq!(
        authenticator
            .authenticate(
                &partners.sign(
                    "JWT",
                    json!({"scp": STAFF_SCOPE, "scope": REQUEST_SCOPE, "azp": PARTNER_CLIENT, "registry_actor_kind": "service"}),
                ),
                "requester",
            )
            .await,
        Err(AuthenticationError::Profile(FailedCheck::Scope)),
        "partners reads scopes from scp only"
    );
    assert_eq!(
        authenticator
            .authenticate(
                &partners.sign(
                    "JWT",
                    json!({"scp": REQUEST_SCOPE, "azp": "another-app", "registry_actor_kind": "service"}),
                ),
                "requester",
            )
            .await,
        Err(refused(FailedCheck::TokenClient)),
        "partners lists its clients although main admits every client"
    );
}

#[tokio::test]
async fn a_token_naming_one_issuer_signed_by_the_other_is_refused() {
    let main = Issuer::main();
    let partners = Issuer::partners();
    let deployment = Deployment::new(&[&main, &partners]);
    let authenticator = deployment
        .authenticator(two_entries(&main, &partners))
        .await;
    // Both keys carry the same key id, so the named issuer finds a key and
    // the signature fails.
    let forged = sign_with(&partners.key, "at+jwt", main.claims(person(STAFF_SCOPE)));
    assert_eq!(
        authenticator.authenticate(&forged, "staff").await,
        Err(refused(FailedCheck::TokenSignature))
    );
}

#[tokio::test]
async fn a_token_from_an_unconfigured_issuer_is_refused() {
    let main = Issuer::main();
    let partners = Issuer::partners();
    let deployment = Deployment::new(&[&main, &partners]);
    let authenticator = deployment
        .authenticator(two_entries(&main, &partners))
        .await;
    let mut claims = person(STAFF_SCOPE);
    claims["iss"] = json!("https://elsewhere.example.test");
    assert_eq!(
        authenticator
            .authenticate(&main.sign("at+jwt", claims), "staff")
            .await,
        Err(refused(FailedCheck::TokenIssuer))
    );
}

#[tokio::test]
async fn the_development_body_names_the_failed_check_and_production_does_not() {
    let main = Issuer::main();
    let deployment = Deployment::new(&[&main]);
    let entries = json!({"main": main.entry(json!({}))});
    let token = main.sign("JWT", person(STAFF_SCOPE));
    let mut bodies = Vec::new();
    for posture in [Posture::Production, Posture::Development] {
        let recorder = Arc::new(RefusalRecorder::new("casework").expect("the casework recorder"));
        let app = deployment
            .router(entries.clone(), posture, Arc::clone(&recorder))
            .await;
        let (status, body) = get(&app, "/v1/review-tasks", &token, "staff").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{posture:?}");
        assert_eq!(
            recorder.counter().get(&["token-type"]),
            Some(1),
            "{posture:?}"
        );
        bodies.push(body);
    }
    let [production, mut development] = <[Value; 2]>::try_from(bodies).unwrap();
    assert!(production.get("failedCheck").is_none(), "{production}");
    assert_eq!(development["failedCheck"], "token-type", "{development}");
    development
        .as_object_mut()
        .expect("a problem object")
        .remove("failedCheck");
    assert_eq!(development, production, "only failedCheck differs");
}

#[tokio::test]
async fn the_same_token_reaches_the_same_profile_in_both_postures() {
    let main = Issuer::main();
    let deployment = Deployment::new(&[&main]);
    let entries = json!({"main": main.entry(json!({}))});
    let token = main.sign("at+jwt", person(STAFF_SCOPE));
    let mut answers = Vec::new();
    for posture in [Posture::Production, Posture::Development] {
        let recorder = Arc::new(RefusalRecorder::new("casework").expect("the casework recorder"));
        let app = deployment.router(entries.clone(), posture, recorder).await;
        answers.push(get(&app, "/v1/review-policies", &token, "staff").await);
    }
    assert_eq!(answers[0].0, StatusCode::OK, "{:?}", answers[0].1);
    assert_eq!(answers[0], answers[1]);
}
