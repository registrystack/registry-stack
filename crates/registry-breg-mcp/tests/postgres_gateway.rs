// SPDX-License-Identifier: Apache-2.0

//! The citizen gateway against a real Base Registry Engine on PostgreSQL.

#![cfg(all(feature = "postgres-test", unix))]

#[path = "support/gateway.rs"]
mod gateway;
#[path = "support/mock_registry.rs"]
mod mock_registry;
#[path = "../../registry-breg/tests/support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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
use registry_platform_httputil::client::{
    ExchangeAuthorization, ExchangeContext, PrivateKeyJwt, PrivateKeyJwtConfig, SubjectTokenType,
    TokenProvider as _, UpstreamSubjectToken,
};
use registry_platform_testing::{
    fixtures as testing_fixtures, jwks_from_private_jwk, ExchangeProfile, TestActorKind,
    TestAuthorizationServer, TestClient,
};
use serde::Serialize;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::task::JoinHandle;

const PROJECT: &str = "citizen-address-correction";
const AUDIENCE: &str = "urn:breg:citizen-address-correction";
const CHAT_HOST: &str = "chat-host";
const GATEWAY_CLIENT: &str = "citizen-gateway";
const REVIEW_PAGE_CLIENT: &str = "citizen-review-page";
const STAFF_CLIENT: &str = "registry-staff-console";
const GATEWAY_ACTOR: &str = "6f1c2d8e-3b4a-4e59-9c7d-2a8b5e0f1d34";
const SELF_SCOPE: &str = "address-correction:self";
const STEWARD_SCOPE: &str = "registry:steward";
const REVIEW_SCOPE: &str = "address-correction:review";
const CITIZEN_A: &str = "synthetic-citizen-a";
const CITIZEN_B: &str = "synthetic-citizen-b";
const REVIEW_AUTHORITY: &str = "casework";

static WASM_RUNTIME_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A gateway served on its own loopback port, configured against `fixture`.
struct RunningGateway {
    resource: String,
    _directory: TempDir,
}

impl RunningGateway {
    async fn start(listener: tokio::net::TcpListener, fixture: &RealRegistry) -> Self {
        let origin = format!("http://{}", listener.local_addr().expect("gateway address"));
        let directory = tempfile::tempdir().expect("temporary directory");
        let secrets = gateway::write_secrets(directory.path(), &fixture.gateway_key);
        let document = gateway::document(&gateway::Document {
            listen: &origin["http://".len()..],
            resource: &fixture.gateway_resource,
            issuer: &fixture.server.issuer(),
            jwks: &fixture.server.jwks_uri(),
            registry: &format!("{}/", fixture.base_url),
            token_endpoint: &fixture.server.token_endpoint(),
            secrets: &secrets,
            audit: &directory.path().join("audit").join("audit.jsonl"),
            limits: gateway::Limits::default(),
        });
        let config_path = directory.path().join("runtime.yaml");
        fs::write(&config_path, document).expect("runtime configuration writes");
        gateway::serve(listener, &config_path).await;
        Self {
            resource: fixture.gateway_resource.clone(),
            _directory: directory,
        }
    }
}

async fn gateway_listener() -> (tokio::net::TcpListener, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("gateway listens");
    let resource = format!(
        "http://{}/mcp",
        listener.local_addr().expect("gateway address")
    );
    (listener, resource)
}

/// The metadata the stand-in registry serves is the registry's own answer
/// for the citizen agent profile, so the unit and protocol suites exercise
/// the contract a real engine publishes.
#[tokio::test(flavor = "multi_thread")]
async fn the_captured_agent_metadata_is_the_registrys_own() {
    let (_listener, resource) = gateway_listener().await;
    let fixture = RealRegistry::start(&resource).await;
    fixture.seed_citizen("A-1", CITIZEN_A).await;
    let token = fixture.agent_token(CITIZEN_A, true).await;
    let response = reqwest::Client::new()
        .get(format!(
            "{}/v1/registry?accessProfile=citizen-agent",
            fixture.base_url
        ))
        .header("authorization", token)
        .send()
        .await
        .expect("registry answers");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let live: Value = response.json().await.expect("metadata is JSON");
    let captured: Value =
        serde_json::from_slice(mock_registry::METADATA).expect("captured metadata is JSON");
    assert_eq!(live, captured);
    fixture.finish().await;
}

/// A token exchanged without the gateway's actor assertion names the citizen
/// but no agent, and the agent profile refuses it.
#[tokio::test(flavor = "multi_thread")]
async fn a_token_exchanged_without_the_actor_is_refused_by_the_registry() {
    let (_listener, resource) = gateway_listener().await;
    let fixture = RealRegistry::start(&resource).await;
    fixture.seed_citizen("A-1", CITIZEN_A).await;
    let token = fixture.agent_token(CITIZEN_A, false).await;
    let response = reqwest::Client::new()
        .get(format!(
            "{}/v1/records/person-addresses?accessProfile=citizen-agent",
            fixture.base_url
        ))
        .header("authorization", token)
        .send()
        .await
        .expect("registry answers");
    let status = response.status();
    let body = response.text().await.expect("refusal body");
    assert!(status.is_client_error(), "{status}");
    assert!(!body.contains("1 Harbour Road"));
    fixture.finish().await;
}

/// Citizen B's chat host tries every way the tool surface offers to name
/// citizen A's address. Nothing lands; the one draft B creates names B's
/// own address, resolved by the gateway through B's delegated lookup.
#[tokio::test(flavor = "multi_thread")]
async fn the_gateway_writes_only_the_citizens_own_address() {
    let (listener, resource) = gateway_listener().await;
    let fixture = RealRegistry::start(&resource).await;
    let address_a = fixture.seed_citizen("A-1", CITIZEN_A).await;
    let address_b = fixture.seed_citizen("B-1", CITIZEN_B).await;
    let running = RunningGateway::start(listener, &fixture).await;
    let client = gateway::connect(&running.resource, &fixture.chat_host_token(CITIZEN_B)).await;

    let details = gateway::call(&client, "get_my_details", json!({})).await;
    assert_eq!(details.is_error, Some(false), "{details:?}");
    let details = serde_json::to_string(&gateway::structured(&details)).expect("details");
    assert!(details.contains("4 Mill Street"), "{details}");
    assert!(!details.contains("1 Harbour Road"), "{details}");

    let fields = json!({"newAddressLine": "2 Quay", "newLocality": "Port Selene", "newPostalCode": "PS-200"});
    for (field, value) in [("address", address_a.as_str()), ("owner", CITIZEN_A)] {
        let mut smuggled = fields.clone();
        smuggled[field] = json!(value);
        let result = gateway::call(&client, "start_application", smuggled).await;
        assert_eq!(gateway::error_code(&result), "invalid_arguments", "{field}");
    }
    assert!(fixture.listed_requests().await.is_empty());

    let started = gateway::call(&client, "start_application", fields).await;
    assert_eq!(started.is_error, Some(false), "{started:?}");
    let application = gateway::structured(&started)["application"].clone();
    assert_eq!(application["status"], "prepared");
    let identifier = application["applicationId"].clone();
    for path in ["/address", "/owner", "/data/address"] {
        let result = gateway::call(
            &client,
            "update_application",
            json!({"applicationId": identifier, "expectedRevision": application["revision"],
                "patch": [{"op": "replace", "path": path, "value": address_a}]}),
        )
        .await;
        assert_eq!(gateway::error_code(&result), "invalid_arguments", "{path}");
    }
    let updated = gateway::call(
        &client,
        "update_application",
        json!({"applicationId": identifier, "expectedRevision": application["revision"],
            "patch": [{"op": "replace", "path": "/newLocality", "value": "Old Town"}]}),
    )
    .await;
    assert_eq!(updated.is_error, Some(false), "{updated:?}");
    let status = gateway::call(
        &client,
        "get_application_status",
        json!({"applicationId": identifier}),
    )
    .await;
    assert_eq!(
        gateway::structured(&status)["application"]["status"],
        "prepared"
    );
    let review = gateway::call(
        &client,
        "prepare_review",
        json!({"applicationId": identifier}),
    )
    .await;
    assert_eq!(review.is_error, Some(false), "{review:?}");
    client.cancel().await.expect("client closes");

    let listed = fixture.listed_requests().await;
    assert_eq!(listed.len(), 1, "{listed:?}");
    assert_eq!(
        listed[0]["domainData"]["address"],
        address_b.as_str(),
        "{listed:?}"
    );
    assert_eq!(listed[0]["domainData"]["newLocality"], "Old Town");
    assert!(!serde_json::to_string(&listed)
        .expect("listed")
        .contains(&address_a));
    fixture.finish().await;
}

/// A retried start returns the draft it already created, and once the
/// citizen cancels that draft on the review page the same values start a
/// new application instead of replaying the closed one.
#[tokio::test(flavor = "multi_thread")]
async fn a_citizen_starts_again_after_cancelling_and_a_retry_reuses_the_draft() {
    let (listener, resource) = gateway_listener().await;
    let fixture = RealRegistry::start(&resource).await;
    fixture.seed_citizen("B-1", CITIZEN_B).await;
    let running = RunningGateway::start(listener, &fixture).await;
    let client = gateway::connect(&running.resource, &fixture.chat_host_token(CITIZEN_B)).await;
    let fields = json!({"newAddressLine": "2 Quay", "newLocality": "Port Selene", "newPostalCode": "PS-200"});

    let start = || gateway::call(&client, "start_application", fields.clone());
    let first = start().await;
    assert_eq!(first.is_error, Some(false), "{first:?}");
    let first = gateway::structured(&first)["application"].clone();
    let retried = start().await;
    assert_eq!(retried.is_error, Some(false), "{retried:?}");
    assert_eq!(
        gateway::structured(&retried)["application"]["applicationId"],
        first["applicationId"]
    );

    fixture
        .cancel_as_citizen(
            CITIZEN_B,
            first["applicationId"].as_str().expect("identifier"),
        )
        .await;
    let status = gateway::call(
        &client,
        "get_application_status",
        json!({"applicationId": first["applicationId"]}),
    )
    .await;
    assert_eq!(
        gateway::structured(&status)["application"]["status"],
        "cancelled"
    );

    let second = start().await;
    assert_eq!(second.is_error, Some(false), "{second:?}");
    let second = gateway::structured(&second)["application"].clone();
    assert_ne!(second["applicationId"], first["applicationId"]);
    assert_eq!(second["status"], "prepared");
    let retried = start().await;
    assert_eq!(retried.is_error, Some(false), "{retried:?}");
    assert_eq!(
        gateway::structured(&retried)["application"]["applicationId"],
        second["applicationId"]
    );
    client.cancel().await.expect("client closes");

    let listed = fixture.listed_requests().await;
    let mut states: Vec<&str> = listed
        .iter()
        .map(|item| item["request"]["bregState"].as_str().expect("state"))
        .collect();
    states.sort_unstable();
    assert_eq!(states, ["cancelled", "draft"], "{listed:?}");
    fixture.finish().await;
}

struct RealRegistry {
    runtime_guard: tokio::sync::MutexGuard<'static, ()>,
    database: TestDatabase,
    server: TestAuthorizationServer,
    gateway_key: PrivateJwk,
    /// The gateway's resource identifier, which the chat host's tokens name.
    gateway_resource: String,
    base_url: String,
    serve_task: JoinHandle<()>,
    authority_task: JoinHandle<()>,
    _package: TestPackage,
}

impl RealRegistry {
    async fn start(gateway_resource: &str) -> Self {
        let runtime_guard = WASM_RUNTIME_TEST_LOCK.lock().await;
        let sources = ProjectSources::load();
        let registry = Arc::new(sources.compiled.clone());
        let database = TestDatabase::create(8).await;
        let (migration, migration_task) = database.connect_migration().await;
        let expected_catalog = ExpectedManagedCatalog::compiled(&registry);
        install_compiled_schema(&migration, &registry, &database.runtime_role)
            .await
            .expect("administrator installs the compiler-owned schema");
        let schema_fingerprint =
            managed_schema_fingerprint(&migration, &database.runtime_role, &expected_catalog)
                .await
                .expect("managed schema fingerprint computes");
        let package = TestPackage::build(&sources, &schema_fingerprint);
        let manifest = package.package.manifest();
        initialize_compiled_registry_state_for_test(
            &migration,
            &database.runtime_role,
            &registry,
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
        .expect("database initializes from the exact signed package identity");
        drop(migration);
        migration_task.abort();

        let gateway_key =
            generate_private_jwk(GeneratedKeyAlgorithm::Es384).expect("gateway key generates");
        let server = TestAuthorizationServer::builder()
            .client(
                TestClient::new(GATEWAY_CLIENT)
                    .with_public_jwk(gateway_key.public())
                    .with_resource(AUDIENCE)
                    .with_actor_kind(TestActorKind::Agent)
                    .with_service_subject(GATEWAY_ACTOR),
            )
            .client(TestClient::new(CHAT_HOST).with_resource(gateway_resource))
            .client(TestClient::new(STAFF_CLIENT).with_actor_kind(TestActorKind::Human))
            .client(TestClient::new(REVIEW_PAGE_CLIENT).with_actor_kind(TestActorKind::Human))
            .exchange_profile(ExchangeProfile::Conformant)
            .start()
            .await;

        let (authority_endpoint, authority_task) = unavailable_review_authority().await;
        let config_path = package.write_runtime_config(&database, &server, &authority_endpoint);
        let prepared =
            prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
                .await
                .expect("verified startup constructs the authenticated runtime");
        let app = prepared.app();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("registry listens");
        let base_url = format!(
            "http://{}",
            listener.local_addr().expect("registry address")
        );
        let serve_task = tokio::spawn(async move {
            let _prepared = prepared;
            axum::serve(listener, app).await.expect("registry serves");
        });
        Self {
            runtime_guard,
            database,
            server,
            gateway_key,
            gateway_resource: gateway_resource.to_owned(),
            base_url,
            serve_task,
            authority_task,
            _package: package,
        }
    }

    fn steward_token(&self) -> String {
        format!(
            "Bearer {}",
            self.server.issue_access_token(
                STAFF_CLIENT,
                "synthetic-steward",
                AUDIENCE,
                STEWARD_SCOPE,
                now() + 600,
            )
        )
    }

    /// The citizen's chat-host token for the gateway resource.
    fn chat_host_token(&self, citizen: &str) -> String {
        self.server.issue_access_token(
            CHAT_HOST,
            citizen,
            &self.gateway_resource,
            SELF_SCOPE,
            now() + 600,
        )
    }

    /// Exchange the chat-host token the way the gateway does and return the
    /// authorization header value for the registry. Without `with_actor`
    /// the exchange carries no actor assertion.
    async fn agent_token(&self, citizen: &str, with_actor: bool) -> String {
        let subject = self.chat_host_token(citizen);
        let expires_at = now() + 600;
        let provider = |resource: Option<&str>, scopes: &[&str]| {
            let mut config = PrivateKeyJwtConfig::new(
                self.server
                    .token_endpoint()
                    .parse()
                    .expect("token endpoint"),
                GATEWAY_CLIENT,
                self.gateway_key.clone(),
            );
            if let Some(resource) = resource {
                config = config.with_resource(resource);
            }
            if !scopes.is_empty() {
                config = config.with_scopes(scopes.iter().copied());
            }
            PrivateKeyJwt::new(config).expect("provider builds")
        };
        let exchange = ExchangeAuthorization::upstream(
            provider(Some(AUDIENCE), &[SELF_SCOPE]),
            ExchangeContext::first_party(
                self.server.issuer(),
                citizen,
                &self.gateway_resource,
                "postgres-gateway",
                expires_at,
            )
            .expect("context"),
            UpstreamSubjectToken::new(subject, SubjectTokenType::AccessToken, expires_at)
                .expect("subject"),
            with_actor.then(|| Arc::new(provider(None, &[]))),
        )
        .expect("exchange configures");
        exchange
            .bearer_token()
            .await
            .expect("exchange succeeds")
            .authorization_header_value()
            .to_str()
            .expect("header is text")
            .to_owned()
    }

    /// Every address correction request the registry holds, drafts
    /// included, as the reviewer lists them.
    async fn listed_requests(&self) -> Vec<Value> {
        let token = self.server.issue_access_token(
            STAFF_CLIENT,
            "synthetic-reviewer",
            AUDIENCE,
            REVIEW_SCOPE,
            now() + 600,
        );
        let response = reqwest::Client::new()
            .get(format!(
                "{}/v1/records/address-correction-requests?accessProfile=reviewer",
                self.base_url
            ))
            .header("authorization", format!("Bearer {token}"))
            .send()
            .await
            .expect("registry answers");
        let status = response.status();
        let body: Value = response.json().await.expect("listing is JSON");
        assert_eq!(status, reqwest::StatusCode::OK, "{body}");
        body["items"]
            .as_array()
            .cloned()
            .expect("listing has items")
    }

    /// The citizen cancels a draft on the review page, following the cancel
    /// action the registry advertises to that profile.
    async fn cancel_as_citizen(&self, citizen: &str, request: &str) {
        let token = format!(
            "Bearer {}",
            self.server.issue_access_token(
                REVIEW_PAGE_CLIENT,
                citizen,
                AUDIENCE,
                SELF_SCOPE,
                now() + 600,
            )
        );
        let http = reqwest::Client::new();
        let view = http
            .get(format!(
                "{}/v1/records/address-correction-requests/{request}?accessProfile=citizen-review",
                self.base_url
            ))
            .header("authorization", &token)
            .send()
            .await
            .expect("registry answers");
        let status = view.status();
        let view: Value = view.json().await.expect("request view is JSON");
        assert_eq!(status, reqwest::StatusCode::OK, "{view}");
        let cancel = view["data"]["request"]["actions"]
            .as_array()
            .and_then(|actions| {
                actions
                    .iter()
                    .find(|action| action["operation"] == "cancel_request")
            })
            .unwrap_or_else(|| panic!("the review profile is offered a cancel: {view}"));
        let response = http
            .post(format!(
                "{}{}",
                self.base_url,
                cancel["href"].as_str().expect("cancel has an href")
            ))
            .header("authorization", &token)
            .header("idempotency-key", format!("cancel-{request}"))
            .header(
                "if-match",
                cancel["ifMatch"]
                    .as_str()
                    .expect("cancel has a precondition"),
            )
            .json(&json!({}))
            .send()
            .await
            .expect("registry answers");
        let status = response.status();
        let body = response.text().await.expect("cancel body");
        assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    }

    async fn create(&self, route: &str, key: &str, data: Value) -> String {
        let response = reqwest::Client::new()
            .post(format!(
                "{}/v1/records/{route}?accessProfile=steward",
                self.base_url
            ))
            .header("authorization", self.steward_token())
            .header("idempotency-key", key)
            .json(&json!({"data": data}))
            .send()
            .await
            .expect("registry answers");
        let status = response.status();
        let body: Value = response.json().await.expect("created body is JSON");
        assert_eq!(status, reqwest::StatusCode::CREATED, "{route}: {body}");
        body["data"]["recordIdentifier"]
            .as_str()
            .expect("created record has an identifier")
            .to_owned()
    }

    /// The steward registers a person with an address and links the
    /// citizen's principal to that person; returns the address identifier.
    async fn seed_citizen(&self, code: &str, principal: &str) -> String {
        let person = self
            .create(
                "persons",
                &format!("person-{code}"),
                json!({"personCode": code, "familyName": "Okafor", "givenName": "Ada"}),
            )
            .await;
        let (line, postal) = if principal == CITIZEN_A {
            ("1 Harbour Road", "PS-100")
        } else {
            ("4 Mill Street", "PS-400")
        };
        let address = self
            .create(
                "person-addresses",
                &format!("address-{code}"),
                json!({"subject": person, "addressLine": line, "locality": "Port Selene", "postalCode": postal}),
            )
            .await;
        self.create(
            "self-service-links",
            &format!("link-{code}"),
            json!({"subject": person, "principal": principal, "active": true}),
        )
        .await;
        address
    }

    async fn finish(self) {
        let Self {
            runtime_guard,
            database,
            server,
            serve_task,
            authority_task,
            ..
        } = self;
        serve_task.abort();
        authority_task.abort();
        server.stop().await;
        database.cleanup().await;
        drop(runtime_guard);
    }
}

/// The review authority is never reached by these tests: submission belongs
/// to the citizen's review page, not the gateway.
async fn unavailable_review_authority() -> (String, JoinHandle<()>) {
    let app = axum::Router::new().fallback(|| async { http::StatusCode::SERVICE_UNAVAILABLE });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("review authority stub listens");
    let endpoint = format!("http://{}/", listener.local_addr().expect("stub address"));
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("review authority stub serves");
    });
    (endpoint, task)
}

struct ProjectSources {
    project: RegistryProject,
    project_bytes: Vec<u8>,
    journeys: Vec<u8>,
    compiled: CompiledRegistry,
}

impl ProjectSources {
    /// Load the acceptance project exactly as it is on disk.
    fn load() -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/acceptance")
            .join(PROJECT);
        let project_bytes =
            fs::read(root.join("registry.yaml")).expect("acceptance registry reads");
        let project = parse_project_yaml(&project_bytes)
            .expect("acceptance registry follows the strict authoring contract");
        let compiled = compile_project_with_assets(&project, &[], &[], CompileProfile::Production)
            .expect("acceptance project closes under the Production compiler");
        let journeys =
            fs::read(root.join("tests/journeys.yaml")).expect("acceptance journeys are readable");
        Self {
            project,
            project_bytes,
            journeys,
            compiled,
        }
    }
}

struct TestPackage {
    _root: TempDir,
    directory: PathBuf,
    package_root: PathBuf,
    anchor: PathBuf,
    revision: String,
    package: VerifiedPackage,
}

impl TestPackage {
    fn build(sources: &ProjectSources, schema_fingerprint: &str) -> Self {
        let identity = sources
            .project
            .package
            .as_ref()
            .expect("acceptance project declares package identity");
        let database_id = format!("{}-database", sources.project.registry.id);
        let signing = generate_private_jwk(GeneratedKeyAlgorithm::Es384)
            .expect("package signing key generates");
        let key_id = signing.public().kid.expect("generated signing key has kid");
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
        .expect("package prepares from exact sources");
        let root = tempfile::tempdir().expect("temporary package root creates");
        let directory = root
            .path()
            .canonicalize()
            .expect("temporary package root canonicalizes");
        let package_root = directory.join("package");
        let revision = prepared.package_revision().to_owned();
        let signature =
            sign(prepared.canonical_signed_bytes(), &signing).expect("package bytes sign");
        prepared
            .publish_to_directory(
                &package_root,
                vec![PackageSignature {
                    key_id: key_id.clone(),
                    signature_hex: hex(&signature),
                }],
            )
            .expect("signed package publishes");
        let anchor = directory.join("trust-anchor.json");
        write_json(
            &anchor,
            &PackageTrustAnchor {
                api_version: TRUST_ANCHOR_API_VERSION.to_owned(),
                environment: identity.environment.clone(),
                instance_id: identity.instance_id.clone(),
                database_id: database_id.clone(),
                threshold: 1,
                keys: vec![TrustAnchorKey {
                    key_id,
                    jwk: serde_json::to_value(signing.public())
                        .expect("public signing JWK serializes"),
                }],
            },
        );
        let package = load_package(
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
        .expect("published package rederives and verifies");
        assert_eq!(package.registry(), &sources.compiled);
        Self {
            _root: root,
            directory,
            package_root,
            anchor,
            revision,
            package,
        }
    }

    fn write_runtime_config(
        &self,
        database: &TestDatabase,
        server: &TestAuthorizationServer,
        review_endpoint: &str,
    ) -> PathBuf {
        let secrets = self.directory.join("secrets");
        fs::create_dir_all(&secrets).expect("secret root creates");
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
                &PrivateJwk::parse(testing_fixtures::ED25519_PRIVATE_JWK)
                    .expect("test authorization server key parses"),
            ))
            .expect("static JWKS serializes"),
        );
        let identity = self.package.manifest();
        let path = self.directory.join("runtime.yaml");
        fs::write(
            &path,
            format!(
                r#"apiVersion: registry.registrystack.org/breg-runtime/v1alpha1
kind: BRegRuntimeConfig
listener:
  bind: 127.0.0.1:9
identity:
  environment: {}
  instanceId: {}
  databaseId: {}
  databaseInitializationEnvironment: {}
secretProviders:
  file:
    root: {}
database:
  runtimeUrlRef: secret:file/database-url
  migrationUrlRef: secret:file/migration-database-url
  pool:
    maxSize: 8
    waitTimeoutMilliseconds: 2000
    createTimeoutMilliseconds: 2000
    recycleTimeoutMilliseconds: 2000
  roles:
    migration: {}
    runtime: {}
package:
  root: {}
  trustAnchorPath: {}
  compilerSourceRevision: {}
  activeRevision: {}
  activeSequence: {}
authentication:
  oidc:
    issuer: {}
    audience: {AUDIENCE}
    allowedAlgorithm: EdDSA
    accessTokenType: at+jwt
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
  {REVIEW_AUTHORITY}:
    endpoint: {review_endpoint}
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
                identity.environment,
                identity.instance_id,
                identity.database_id,
                identity.environment,
                secrets.display(),
                database.migration_role.as_str(),
                database.runtime_role.as_str(),
                self.package_root.display(),
                self.anchor.display(),
                identity.compiler.source_revision,
                self.revision,
                identity.sequence,
                server.issuer(),
            ),
        )
        .expect("strict runtime configuration writes");
        set_private_permissions(&path);
        path
    }
}

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after the epoch")
            .as_secs(),
    )
    .expect("seconds fit")
}

fn write_json(path: &Path, value: &impl Serialize) {
    let bytes = canonicalize_json(&serde_json::to_value(value).expect("value serializes"))
        .expect("value canonicalizes");
    write_private(path, &bytes);
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("private file writes");
    set_private_permissions(path);
}

fn set_private_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("private file permissions set");
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    encoded
}
