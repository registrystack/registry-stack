// SPDX-License-Identifier: Apache-2.0
//! The review page against a real Base Registry Engine: the citizen address
//! correction acceptance project, compiled, signed, installed on a disposable
//! PostgreSQL database, and served over loopback HTTP. The page signs people
//! in through an in-process authorization server whose tokens the registry
//! accepts, so every read and submit it makes carries the person's own
//! authority.
//!
//! Requires `BREG_TEST_DATABASE_URL`; the test fails rather than skips
//! without it.

#![cfg(all(feature = "postgres-test", unix))]

#[path = "../../registry-breg/tests/support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;
mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use postgres_harness::TestDatabase;
use registry_breg::compiler::{compile_project_with_assets, CompileProfile};
use registry_breg::contract::{parse_project_yaml, RegistryProject};
use registry_breg::package::{
    load_package, prepare_package, PackageBuildRequest, PackageIntent, PackageLoadContext,
    PackageMigrationPlanInput, PackageSignature, PackageSourceFile, PackageTrustAnchor,
    SignaturePolicy, TrustAnchorKey, VerifiedPackage, FIXTURE_JOURNEYS_PATH,
    TRUST_ANCHOR_API_VERSION,
};
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    managed_schema_fingerprint, ExpectedManagedCatalog, RegistryStateTestIdentity,
};
use registry_breg::startup::prepare_with_connection_config_for_test;
use registry_breg::CompiledRegistry;
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_crypto::{generate_private_jwk, sign, GeneratedKeyAlgorithm, PrivateJwk};
use registry_platform_testing::{
    fixtures, jwks_from_private_jwk, sign_ed25519_compact_jwt, TestAuthorizationServer, TestClient,
};
use serde_json::{json, Value};
use support::{browser, cookie_pair, page, sign_in_to, write_secret, Page};
use tempfile::TempDir;
use tokio::task::JoinHandle;

const PROJECT: &str = "citizen-address-correction";
/// The audience the registry accepts and the resource the page requests.
const RESOURCE: &str = "https://registry.example/citizen-address-correction";
const REVIEW_PAGE_CLIENT: &str = "citizen-review-page";
const GATEWAY_CLIENT: &str = "citizen-gateway";
const STAFF_CLIENT: &str = "registry-staff-console";
/// The synthetic actor identity the registry pins to the gateway client.
const GATEWAY_ACTOR: &str = "6f1c2d8e-3b4a-4e59-9c7d-2a8b5e0f1d34";
const SELF_SCOPE: &str = "address-correction:self";
const STEWARD_SCOPE: &str = "registry:steward";
const CITIZEN_A: &str = "synthetic-citizen-a";
const CITIZEN_B: &str = "synthetic-citizen-b";
const ACCESS_TOKEN_TYP: &str = "at+jwt";
// Each fixture owns the process-global configured WASM runtime until it ends.
static RUNTIME_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The draft the page is offered by B names A's address. The registry
/// accepts that draft, the page reads its target under B's own token, the
/// read is refused, and the page renders the neutral not-found page with no
/// form. A crafted POST carrying B's valid CSRF token is refused the same way
/// and never reaches the registry's submit: the draft still offers the same
/// submit precondition afterwards, and the journal holds no submit attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_draft_naming_another_persons_address_offers_no_form_and_a_crafted_post_never_submits() {
    let fixture = Fixture::start().await;
    let a = fixture
        .seed_citizen("P-0001", CITIZEN_A, "1 Harbour Road")
        .await;
    let b = fixture
        .seed_citizen("P-0002", CITIZEN_B, "4 Mill Street")
        .await;
    let own = fixture
        .create_draft(CITIZEN_B, &b.address, "b-own", "5 Mill Street")
        .await;
    let foreign = fixture
        .create_draft(CITIZEN_B, &a.address, "b-foreign", "8 Mismatch Road")
        .await;
    let before = fixture.submit_precondition(CITIZEN_B, &foreign).await;

    let session = cookie_pair(
        &sign_in_to(&fixture.http, &fixture.page_origin, CITIZEN_B, &own)
            .await
            .set_cookie("breg-review-session")
            .expect("the callback sets a session cookie"),
    );
    // B's own draft renders a form, which hands B a valid CSRF token and a
    // view identifier to craft a POST with.
    let own_page = fixture.get(&format!("/requests/{own}"), &session).await;
    assert_eq!(own_page.status, StatusCode::OK, "{}", own_page.body);
    let csrf = own_page.input("csrf").expect("the own draft offers a form");
    let view = own_page.input("view").expect("the own draft offers a form");

    let foreign_page = fixture.get(&format!("/requests/{foreign}"), &session).await;
    assert_eq!(
        foreign_page.status,
        StatusCode::NOT_FOUND,
        "{}",
        foreign_page.body
    );
    assert_eq!(foreign_page.error_code(), Some("not-found"));
    assert!(
        foreign_page.input("view").is_none(),
        "{}",
        foreign_page.body
    );
    assert!(!foreign_page
        .body
        .contains("<form method=\"post\" action=\"/requests/"));
    assert!(!foreign_page.body.contains("1 Harbour Road"));
    assert!(!foreign_page.body.contains("8 Mismatch Road"));

    let crafted = fixture
        .post(
            &format!("/requests/{foreign}/submit"),
            &session,
            &[("csrf", &csrf), ("view", &view)],
        )
        .await;
    assert_eq!(crafted.status, StatusCode::NOT_FOUND, "{}", crafted.body);
    assert_eq!(crafted.error_code(), Some("not-found"));

    let after = fixture.submit_precondition(CITIZEN_B, &foreign).await;
    assert_eq!(
        after, before,
        "the foreign draft is still unsubmitted, with the same submit precondition"
    );
    let journal = fixture.journal();
    assert!(
        !journal.contains("\"attempted\""),
        "no submit was attempted: {journal}"
    );
    assert!(journal.contains("\"refused\""), "{journal}");
    fixture.finish().await;
}

/// The positive control for the test above: the page reads a person's own
/// draft and the address it changes from the real registry, shows both, and
/// submits exactly once however often the form is posted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_person_reviews_and_submits_their_own_draft_against_the_real_registry() {
    let fixture = Fixture::start().await;
    let a = fixture
        .seed_citizen("P-0001", CITIZEN_A, "1 Harbour Road")
        .await;
    let draft = fixture
        .create_draft(CITIZEN_A, &a.address, "a-own", "2 Quarry Lane")
        .await;
    let before = fixture.submit_precondition(CITIZEN_A, &draft).await;
    assert!(before.is_some(), "a fresh draft offers submission");

    let session = cookie_pair(
        &sign_in_to(&fixture.http, &fixture.page_origin, CITIZEN_A, &draft)
            .await
            .set_cookie("breg-review-session")
            .expect("the callback sets a session cookie"),
    );
    let review = fixture.get(&format!("/requests/{draft}"), &session).await;
    assert_eq!(review.status, StatusCode::OK, "{}", review.body);
    assert!(review.body.contains("1 Harbour Road"), "{}", review.body);
    assert!(review.body.contains("2 Quarry Lane"), "{}", review.body);
    let csrf = review.input("csrf").expect("a form");
    let view = review.input("view").expect("a form");

    let submitted = fixture
        .post(
            &format!("/requests/{draft}/submit"),
            &session,
            &[("csrf", &csrf), ("view", &view)],
        )
        .await;
    assert_eq!(submitted.status, StatusCode::OK, "{}", submitted.body);
    let after = fixture.submit_precondition(CITIZEN_A, &draft).await;
    assert!(
        after.is_none(),
        "a submitted draft no longer offers submission"
    );
    // A resubmitted form reuses its view's idempotency key, so the registry
    // answers with the first receipt instead of submitting again.
    let replayed = fixture
        .post(
            &format!("/requests/{draft}/submit"),
            &session,
            &[("csrf", &csrf), ("view", &view)],
        )
        .await;
    assert_eq!(replayed.status, StatusCode::OK, "{}", replayed.body);
    let journal = fixture.journal();
    assert_eq!(journal.matches("\"attempted\"").count(), 2, "{journal}");
    assert_eq!(journal.matches("\"succeeded\"").count(), 4, "{journal}");
    fixture.finish().await;
}

/// The submit re-reads the draft's target under the person's token before it
/// calls the registry. A form rendered while the person could read their
/// address is refused once the steward withdraws their link, and the draft is
/// left unsubmitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_submit_after_the_link_is_withdrawn_is_refused_before_the_registry_submits() {
    let fixture = Fixture::start().await;
    let a = fixture
        .seed_citizen("P-0001", CITIZEN_A, "1 Harbour Road")
        .await;
    let draft = fixture
        .create_draft(CITIZEN_A, &a.address, "a-own", "2 Quarry Lane")
        .await;
    let before = fixture.submit_precondition(CITIZEN_A, &draft).await;
    assert!(before.is_some(), "a fresh draft offers submission");

    let session = cookie_pair(
        &sign_in_to(&fixture.http, &fixture.page_origin, CITIZEN_A, &draft)
            .await
            .set_cookie("breg-review-session")
            .expect("the callback sets a session cookie"),
    );
    let review = fixture.get(&format!("/requests/{draft}"), &session).await;
    assert_eq!(review.status, StatusCode::OK, "{}", review.body);
    let csrf = review.input("csrf").expect("a form");
    let view = review.input("view").expect("a form");

    fixture.withdraw_link(&a.link).await;
    let submitted = fixture
        .post(
            &format!("/requests/{draft}/submit"),
            &session,
            &[("csrf", &csrf), ("view", &view)],
        )
        .await;
    assert_eq!(
        submitted.status,
        StatusCode::NOT_FOUND,
        "{}",
        submitted.body
    );
    assert_eq!(submitted.error_code(), Some("not-found"));
    assert_eq!(
        fixture.submit_precondition(CITIZEN_A, &draft).await,
        before,
        "the draft is still unsubmitted, with the same submit precondition"
    );
    let journal = fixture.journal();
    assert!(!journal.contains("\"attempted\""), "{journal}");
    fixture.finish().await;
}

struct Citizen {
    address: String,
    link: String,
}

struct Fixture {
    _guard: tokio::sync::MutexGuard<'static, ()>,
    database: TestDatabase,
    registry_url: String,
    registry_task: JoinHandle<()>,
    page_task: JoinHandle<()>,
    page_origin: String,
    authorization_server: TestAuthorizationServer,
    http: reqwest::Client,
    directory: TempDir,
}

impl Fixture {
    async fn start() -> Self {
        let guard = RUNTIME_LOCK.lock().await;
        let directory = tempfile::tempdir().expect("scratch directory");
        let root = directory
            .path()
            .canonicalize()
            .expect("scratch directory canonicalizes");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

        let page_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let page_address = page_listener.local_addr().unwrap();
        let page_origin = format!("http://{page_address}");
        let (_, client_public_key) = fixtures::ed25519_pair();
        let authorization_server = TestAuthorizationServer::builder()
            .client(
                TestClient::new(REVIEW_PAGE_CLIENT)
                    .with_public_jwk(client_public_key)
                    .with_redirect_uri(format!("{page_origin}/signin/callback"))
                    .with_resource(RESOURCE),
            )
            .client(TestClient::new(STAFF_CLIENT).with_resource(RESOURCE))
            .start()
            .await;

        let database = TestDatabase::create(8).await;
        let sources = ProjectSources::load();
        let (migration, migration_task) = database.connect_migration().await;
        install_compiled_schema(&migration, &sources.compiled, &database.runtime_role)
            .await
            .expect("the compiler-owned schema installs");
        let schema_fingerprint = managed_schema_fingerprint(
            &migration,
            &database.runtime_role,
            &ExpectedManagedCatalog::compiled(&sources.compiled),
        )
        .await
        .expect("the managed schema fingerprint computes");
        let package = Package::build(&root, &sources, &schema_fingerprint);
        let manifest = package.verified.manifest();
        initialize_compiled_registry_state_for_test(
            &migration,
            &database.runtime_role,
            &sources.compiled,
            RegistryStateTestIdentity {
                package_id: &manifest.package_id,
                environment: &manifest.environment,
                instance_id: &manifest.instance_id,
                database_id: &manifest.database_id,
                package_revision: &manifest.package_revision,
                package_sequence: 1,
            },
        )
        .await
        .expect("the database initializes from the signed package identity");
        drop(migration);
        migration_task.abort();

        let registry_config =
            package.write_runtime_config(&root, &database, &authorization_server.issuer());
        let prepared = prepare_with_connection_config_for_test(
            &registry_config,
            database.runtime_config.clone(),
        )
        .await
        .expect("the registry starts from the signed package");
        let registry_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let registry_url = format!("http://{}", registry_listener.local_addr().unwrap());
        let registry_app = prepared.app();
        let registry_task = tokio::spawn(async move {
            // The prepared server stays alive as long as its router serves.
            let _prepared = prepared;
            axum::serve(registry_listener, registry_app)
                .await
                .expect("the registry serves");
        });

        let page_config = write_page_config(
            &root,
            page_address,
            &page_origin,
            &authorization_server.issuer(),
            &registry_url,
        );
        let config =
            registry_breg_review::RuntimeConfig::load(&page_config).expect("page config loads");
        let router = registry_breg_review::router(config)
            .await
            .expect("the review page starts");
        let page_task = tokio::spawn(async move {
            registry_breg_review::serve(page_listener, router)
                .await
                .expect("the review page serves");
        });

        Self {
            _guard: guard,
            database,
            registry_url,
            registry_task,
            page_task,
            page_origin,
            authorization_server,
            http: browser(),
            directory,
        }
    }

    fn steward_token(&self) -> String {
        self.authorization_server.issue_access_token(
            STAFF_CLIENT,
            "synthetic-steward",
            RESOURCE,
            STEWARD_SCOPE,
            now() + 300,
        )
    }

    /// The standing agent's delegated token for `citizen`, signed with the
    /// authorization server's key: the in-process server does not run the
    /// exchange that would add the actor.
    fn agent_token(&self, citizen: &str) -> String {
        let issued_at = now();
        sign_ed25519_compact_jwt(
            fixtures::ED25519_PRIVATE_JWK,
            ACCESS_TOKEN_TYP,
            "registry-platform-testing-ed25519-1",
            json!({
                "iss": self.authorization_server.issuer(),
                "sub": citizen,
                "aud": RESOURCE,
                "azp": GATEWAY_CLIENT,
                "client_id": GATEWAY_CLIENT,
                "registry_actor_kind": "agent",
                "act": {"sub": GATEWAY_ACTOR},
                "scope": SELF_SCOPE,
                "iat": issued_at,
                "exp": issued_at + 300,
                "jti": uuid::Uuid::new_v4().to_string(),
            }),
        )
    }

    /// The review page profile's token for `citizen`, as the page itself
    /// would hold it.
    fn review_token(&self, citizen: &str) -> String {
        self.authorization_server.issue_access_token(
            REVIEW_PAGE_CLIENT,
            citizen,
            RESOURCE,
            SELF_SCOPE,
            now() + 300,
        )
    }

    async fn registry(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
        idempotency_key: Option<&str>,
        token: &str,
    ) -> (StatusCode, Value) {
        let mut request = self
            .http
            .request(method, format!("{}{path}", self.registry_url))
            .bearer_auth(token);
        if let Some(key) = idempotency_key {
            request = request.header("idempotency-key", key);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.expect("the registry answers");
        let status = StatusCode::from_u16(response.status().as_u16()).unwrap();
        let bytes = response.bytes().await.expect("the registry body reads");
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("the registry answers JSON")
        };
        (status, body)
    }

    async fn create(&self, route: &str, key: &str, data: Value) -> String {
        let (status, body) = self
            .registry(
                reqwest::Method::POST,
                &format!("/v1/records/{route}?accessProfile=steward"),
                Some(json!({"data": data})),
                Some(key),
                &self.steward_token(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{route}: {body}");
        body["data"]["recordIdentifier"]
            .as_str()
            .expect("a created record has an identifier")
            .to_owned()
    }

    /// The steward registers a person with an address and links `principal`
    /// to that person.
    async fn seed_citizen(&self, code: &str, principal: &str, line: &str) -> Citizen {
        let person = self
            .create(
                "persons",
                &format!("person-{code}"),
                json!({"personCode": code, "familyName": "Okafor", "givenName": "Ada"}),
            )
            .await;
        let address = self
            .create(
                "person-addresses",
                &format!("address-{code}"),
                json!({"subject": person, "addressLine": line, "locality": "Port Selene", "postalCode": "PS-100"}),
            )
            .await;
        let link = self
            .create(
                "self-service-links",
                &format!("link-{code}"),
                json!({"subject": person, "principal": principal, "active": true}),
            )
            .await;
        Citizen { address, link }
    }

    /// The steward deactivates a self-service link.
    async fn withdraw_link(&self, link: &str) {
        let token = self.steward_token();
        let path = format!(
            "{}/v1/records/self-service-links/{link}?accessProfile=steward",
            self.registry_url
        );
        let read = self
            .http
            .get(&path)
            .bearer_auth(&token)
            .send()
            .await
            .expect("the registry answers");
        assert_eq!(read.status().as_u16(), 200);
        let etag = read
            .headers()
            .get("etag")
            .expect("a record read carries its ETag")
            .to_str()
            .unwrap()
            .to_owned();
        let patched = self
            .http
            .patch(&path)
            .bearer_auth(&token)
            .header("content-type", "application/json-patch+json")
            .header("if-match", etag)
            .header("idempotency-key", format!("withdraw-{link}"))
            .body(r#"[{"op":"replace","path":"/data/active","value":false}]"#)
            .send()
            .await
            .expect("the registry answers");
        let status = patched.status().as_u16();
        assert_eq!(status, 200, "{}", patched.text().await.unwrap_or_default());
    }

    /// The standing agent drafts, for `owner`, a correction of `address`.
    async fn create_draft(&self, owner: &str, address: &str, key: &str, line: &str) -> String {
        let (status, body) = self
            .registry(
                reqwest::Method::POST,
                "/v1/records/address-correction-requests?accessProfile=citizen-agent",
                Some(json!({"data": {
                    "address": address,
                    "newAddressLine": line,
                    "newLocality": "Port Selene",
                    "newPostalCode": "PS-100",
                    "owner": owner,
                }})),
                Some(key),
                &self.agent_token(owner),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body["data"]["recordIdentifier"]
            .as_str()
            .expect("a draft has an identifier")
            .to_owned()
    }

    /// The submit precondition the registry offers `citizen`'s review
    /// profile for `draft`, or `None` once the draft no longer offers
    /// submission.
    async fn submit_precondition(&self, citizen: &str, draft: &str) -> Option<String> {
        let (status, body) = self
            .registry(
                reqwest::Method::GET,
                &format!(
                    "/v1/records/address-correction-requests/{draft}?accessProfile=citizen-review"
                ),
                None,
                None,
                &self.review_token(citizen),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["data"]["request"]["actions"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|action| action["operation"] == "submit_request")
            .map(|action| {
                action["ifMatch"]
                    .as_str()
                    .expect("an action carries its precondition")
                    .to_owned()
            })
    }

    async fn get(&self, path: &str, session: &str) -> Page {
        page(
            self.http
                .get(format!("{}{path}", self.page_origin))
                .header("cookie", session)
                .send()
                .await
                .unwrap(),
        )
        .await
    }

    async fn post(&self, path: &str, session: &str, form: &[(&str, &str)]) -> Page {
        let body = form
            .iter()
            .map(|(name, value)| format!("{name}={}", support::encode(value)))
            .collect::<Vec<_>>()
            .join("&");
        page(
            self.http
                .post(format!("{}{path}", self.page_origin))
                .header("cookie", session)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(body)
                .send()
                .await
                .unwrap(),
        )
        .await
    }

    /// Every audit segment the page wrote, in order.
    fn journal(&self) -> String {
        let directory = self.directory.path().join("audit");
        let mut paths: Vec<PathBuf> = fs::read_dir(&directory)
            .expect("the audit directory exists")
            .map(|entry| entry.expect("an audit entry").path())
            .filter(|path| path.is_file())
            .collect();
        paths.sort();
        paths
            .iter()
            .map(|path| fs::read_to_string(path).expect("an audit segment reads"))
            .collect()
    }

    async fn finish(self) {
        self.page_task.abort();
        self.registry_task.abort();
        let _ = self.page_task.await;
        let _ = self.registry_task.await;
        self.authorization_server.stop().await;
        self.database.cleanup().await;
    }
}

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the clock is after the epoch")
            .as_secs(),
    )
    .expect("seconds fit")
}

fn write_page_config(
    root: &Path,
    address: std::net::SocketAddr,
    origin: &str,
    issuer: &str,
    registry_url: &str,
) -> PathBuf {
    let secrets = root.join("page-secrets");
    fs::create_dir(&secrets).unwrap();
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700)).unwrap();
    write_secret(
        &secrets,
        "client-key.jwk",
        fixtures::ED25519_PRIVATE_JWK.as_bytes(),
    );
    write_secret(&secrets, "audit-key", &[0x5a; 32]);
    let audit = root.join("audit");
    fs::create_dir(&audit).unwrap();
    fs::set_permissions(&audit, fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.join("page.yaml");
    fs::write(
        &path,
        format!(
            "apiVersion: registry.registrystack.org/breg-review-runtime/v1alpha1\n\
             kind: BRegReviewRuntimeConfig\n\
             listener:\n  bind: \"{address}\"\n  tlsTermination: development-loopback\n\
             publicOrigin: {origin}\n\
             secretProviders:\n  file:\n    root: {secrets}\n\
             signIn:\n  issuer: {issuer}\n  clientId: {REVIEW_PAGE_CLIENT}\n  clientKeyRef: secret:file/client-key.jwk\n  scopes: [\"{SELF_SCOPE}\"]\n\
             registry:\n  baseUrl: {registry_url}\n  resource: {RESOURCE}\n  entity: address-correction-request\n  targetField: address\n  accessProfile: citizen-review\n\
             audit:\n  path: {audit}\n  hashKeyRef: secret:file/audit-key\n",
            secrets = secrets.display(),
            audit = audit.join("audit.jsonl").display(),
        ),
    )
    .unwrap();
    path
}

struct ProjectSources {
    project: RegistryProject,
    project_bytes: Vec<u8>,
    journeys: Vec<u8>,
    compiled: CompiledRegistry,
}

impl ProjectSources {
    fn load() -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/acceptance")
            .join(PROJECT);
        let project_bytes =
            fs::read(root.join("registry.yaml")).expect("the acceptance registry reads");
        let project = parse_project_yaml(&project_bytes)
            .expect("the acceptance registry follows the authoring contract");
        let compiled = compile_project_with_assets(&project, &[], &[], CompileProfile::Production)
            .expect("the acceptance project compiles for production");
        let journeys =
            fs::read(root.join("tests/journeys.yaml")).expect("the acceptance journeys read");
        Self {
            project,
            project_bytes,
            journeys,
            compiled,
        }
    }
}

struct Package {
    root: PathBuf,
    anchor: PathBuf,
    revision: String,
    verified: VerifiedPackage,
}

impl Package {
    fn build(root: &Path, sources: &ProjectSources, schema_fingerprint: &str) -> Self {
        let identity = sources
            .project
            .package
            .as_ref()
            .expect("the acceptance project declares its package identity");
        let database_id = format!("{}-database", sources.project.registry.id);
        let signing =
            generate_private_jwk(GeneratedKeyAlgorithm::Es384).expect("a signing key generates");
        let key_id = signing.public().kid.expect("a generated key has a kid");
        let prepared = prepare_package(PackageBuildRequest {
            environment: identity.environment.clone(),
            instance_id: identity.instance_id.clone(),
            database_id: database_id.clone(),
            sequence: identity.sequence,
            prior_revision: None,
            compiler_source_revision: identity.source_revision.clone(),
            schema_fingerprint: schema_fingerprint.to_owned(),
            signature_policy: SignaturePolicy {
                threshold: 1,
                key_ids: vec![key_id.clone()],
            },
            project: PackageSourceFile {
                path: "registry.yaml".to_owned(),
                bytes: sources.project_bytes.clone(),
            },
            modules: Vec::new(),
            fixture_journeys: PackageSourceFile {
                path: FIXTURE_JOURNEYS_PATH.to_owned(),
                bytes: sources.journeys.clone(),
            },
            migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
        })
        .expect("the package prepares from its sources");
        let package_root = root.join("package");
        let revision = prepared.package_revision().to_owned();
        let signature =
            sign(prepared.canonical_signed_bytes(), &signing).expect("the package signs");
        prepared
            .publish_to_directory(
                &package_root,
                vec![PackageSignature {
                    key_id: key_id.clone(),
                    signature_hex: hex(&signature),
                }],
            )
            .expect("the signed package publishes");
        let anchor = root.join("trust-anchor.json");
        let anchor_document = serde_json::to_value(PackageTrustAnchor {
            api_version: TRUST_ANCHOR_API_VERSION.to_owned(),
            environment: identity.environment.clone(),
            instance_id: identity.instance_id.clone(),
            database_id: database_id.clone(),
            threshold: 1,
            keys: vec![TrustAnchorKey {
                key_id,
                jwk: serde_json::to_value(signing.public()).expect("the public key serializes"),
            }],
        })
        .expect("the trust anchor serializes");
        write_private(
            &anchor,
            &canonicalize_json(&anchor_document).expect("the trust anchor canonicalizes"),
        );
        let verified = load_package(
            &package_root,
            &PackageLoadContext {
                environment: &identity.environment,
                instance_id: &identity.instance_id,
                database_id: &database_id,
                database_initialization_environment: &identity.environment,
                compiler_source_revision: &identity.source_revision,
                trust_anchor: Some(&anchor),
                intent: PackageIntent::InitialActivation,
            },
        )
        .expect("the published package verifies");
        Self {
            root: package_root,
            anchor,
            revision,
            verified,
        }
    }

    fn write_runtime_config(&self, root: &Path, database: &TestDatabase, issuer: &str) -> PathBuf {
        let secrets = root.join("registry-secrets");
        fs::create_dir(&secrets).unwrap();
        fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700)).unwrap();
        write_private(&secrets.join("database-url"), b"unused-by-test-startup");
        write_private(&secrets.join("audit-key"), &[0x71; 32]);
        write_private(&secrets.join("cursor-key"), &[0x52; 32]);
        write_private(
            &secrets.join("review-authority-token"),
            b"synthetic-review-token",
        );
        write_private(
            &secrets.join("oidc-jwks"),
            &serde_json::to_vec(&jwks_from_private_jwk(
                &PrivateJwk::parse(fixtures::ED25519_PRIVATE_JWK).expect("the fixture key parses"),
            ))
            .expect("the JWKS serializes"),
        );
        let identity = self.verified.manifest();
        let path = root.join("registry.yaml");
        fs::write(
            &path,
            format!(
                r#"apiVersion: registry.registrystack.org/breg-runtime/v1alpha1
kind: BRegRuntimeConfig
listener:
  bind: 127.0.0.1:9
identity:
  environment: {environment}
  instanceId: {instance}
  databaseId: {database_id}
  databaseInitializationEnvironment: {environment}
secretProviders:
  file:
    root: {secrets}
database:
  runtimeUrlRef: secret:file/database-url
  migrationUrlRef: secret:file/migration-database-url
  pool:
    maxSize: 8
    waitTimeoutMilliseconds: 2000
    createTimeoutMilliseconds: 2000
    recycleTimeoutMilliseconds: 2000
  roles:
    migration: {migration_role}
    runtime: {runtime_role}
package:
  root: {package_root}
  trustAnchorPath: {anchor}
  compilerSourceRevision: {source_revision}
  activeRevision: {revision}
  activeSequence: {sequence}
authentication:
  oidc:
    issuer: {issuer}
    audience: {RESOURCE}
    allowedAlgorithm: EdDSA
    accessTokenType: {ACCESS_TOKEN_TYP}
    scopeClaim: scope
    scopeSeparator: " "
    allowedClients: [{GATEWAY_CLIENT}, {REVIEW_PAGE_CLIENT}, {STAFF_CLIENT}]
    maxTokenLifetimeSeconds: 3600
    leewayMilliseconds: 60000
    jwksSource:
      kind: static
      documentRef: secret:file/oidc-jwks
    jwksCache:
      cacheTtlSeconds: 60
      negativeCacheTtlSeconds: 1
      refreshCooldownSeconds: 1
      maxDocumentBytes: 65536
      requestTimeoutMilliseconds: 5000
      outageToleranceSeconds: 0
  authorityClaims:
    principal: sub
    trustedActors:
      {GATEWAY_CLIENT}: {GATEWAY_ACTOR}
reviewAuthorities:
  casework:
    endpoint: http://127.0.0.1:9/
    profile: registry-producer
    producerId: citizen-address-registry
    recoveryDays: 7
    tokenRef: secret:file/review-authority-token
audit:
  hashKeyRef: secret:file/audit-key
cursor:
  secretRef: secret:file/cursor-key
  maxAgeSeconds: 300
operationalTimeouts:
  httpRequestMilliseconds: 5000
  shutdownGraceMilliseconds: 1000
  recordLockMilliseconds: 2000
  migrationLockMilliseconds: 2000
  migrationStatementMilliseconds: 5000
"#,
                environment = identity.environment,
                instance = identity.instance_id,
                database_id = identity.database_id,
                secrets = secrets.display(),
                migration_role = database.migration_role.as_str(),
                runtime_role = database.runtime_role.as_str(),
                package_root = self.root.display(),
                anchor = self.anchor.display(),
                source_revision = identity.compiler.source_revision,
                revision = self.revision,
                sequence = identity.sequence,
            ),
        )
        .expect("the registry runtime configuration writes");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("a private file writes");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("owner-only permissions");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
