// SPDX-License-Identifier: Apache-2.0

//! A real Base Registry Engine on PostgreSQL for the citizen gateway.
//!
//! The acceptance project `citizen-address-correction` is compiled, signed
//! as a package, installed into a fresh database, and served by the
//! engine's verified startup behind the test authorization server. The
//! review authority the engine submits to is a loopback stub that stands in
//! for Casework. The PostgreSQL suite and the scripted local run share this
//! fixture and the citizen journey it drives.

#![allow(dead_code)]

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as UrlPath, State};
use axum::response::IntoResponse as _;
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
use uuid::Uuid;

use crate::gateway;
use crate::postgres_harness::TestDatabase;
pub const PROJECT: &str = "citizen-address-correction";
pub const AUDIENCE: &str = "urn:breg:citizen-address-correction";
pub const CHAT_HOST: &str = "chat-host";
pub const GATEWAY_CLIENT: &str = "citizen-gateway";
pub const REVIEW_PAGE_CLIENT: &str = "citizen-review-page";
pub const STAFF_CLIENT: &str = "registry-staff-console";
pub const GATEWAY_ACTOR: &str = "6f1c2d8e-3b4a-4e59-9c7d-2a8b5e0f1d34";
pub const SELF_SCOPE: &str = "address-correction:self";
pub const STEWARD_SCOPE: &str = "registry:steward";
pub const REVIEW_SCOPE: &str = "address-correction:review";
pub const APPLY_SCOPE: &str = "address-correction:apply";
pub const REQUEST_ENTITY: &str = "address-correction-request";
pub const CITIZEN_A: &str = "synthetic-citizen-a";
pub const CITIZEN_B: &str = "synthetic-citizen-b";
pub const REVIEW_AUTHORITY: &str = "casework";

pub static WASM_RUNTIME_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The acceptance project served by a real engine on a fresh database, with
/// the authorization server every party signs in through.
pub struct RealRegistry {
    runtime_guard: tokio::sync::MutexGuard<'static, ()>,
    database: TestDatabase,
    pub server: TestAuthorizationServer,
    pub gateway_key: PrivateJwk,
    /// The gateway's resource identifier, which the chat host's tokens name.
    pub gateway_resource: String,
    pub base_url: String,
    serve_task: JoinHandle<()>,
    authority: ReviewAuthorityStub,
    _package: TestPackage,
}

impl RealRegistry {
    /// Start the registry and its authorization server. With `review_page`,
    /// the review page client may sign people in back to that origin.
    pub async fn start(gateway_resource: &str, review_page: Option<&str>) -> Self {
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
        let mut review_page_client =
            TestClient::new(REVIEW_PAGE_CLIENT).with_actor_kind(TestActorKind::Human);
        if let Some(origin) = review_page {
            let (_, page_key) = testing_fixtures::ed25519_pair();
            review_page_client = review_page_client
                .with_public_jwk(page_key)
                .with_redirect_uri(format!("{origin}/signin/callback"))
                .with_resource(AUDIENCE);
        }
        let server = TestAuthorizationServer::builder()
            .client(
                TestClient::new(GATEWAY_CLIENT)
                    .with_public_jwk(gateway_key.public())
                    .with_resource(AUDIENCE)
                    // The gateway's actor token is requested for its own resource.
                    .with_resource(gateway_resource)
                    .with_actor_kind(TestActorKind::Agent)
                    .with_service_subject(GATEWAY_ACTOR),
            )
            .client(TestClient::new(CHAT_HOST).with_resource(gateway_resource))
            .client(TestClient::new(STAFF_CLIENT).with_actor_kind(TestActorKind::Human))
            .client(review_page_client)
            .exchange_profile(ExchangeProfile::Conformant)
            .start()
            .await;

        let authority = ReviewAuthorityStub::start().await;
        let config_path = package.write_runtime_config(&database, &server, &authority.endpoint);
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
            authority,
            _package: package,
        }
    }

    pub fn steward_token(&self) -> String {
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
    pub fn chat_host_token(&self, citizen: &str) -> String {
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
    /// the exchange carries no actor assertion. The test writes the header
    /// itself, which `clippy.toml` refuses the gateway, to present tokens the
    /// gateway would never send.
    #[allow(clippy::disallowed_methods)]
    pub async fn agent_token(&self, citizen: &str, with_actor: bool) -> String {
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
            with_actor.then(|| Arc::new(provider(Some(&self.gateway_resource), &[]))),
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
    pub async fn listed_requests(&self) -> Vec<Value> {
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
    pub async fn cancel_as_citizen(&self, citizen: &str, request: &str) {
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

    /// The person-address record as the steward reads it.
    pub async fn steward_address(&self, address: &str) -> Value {
        let response = reqwest::Client::new()
            .get(format!(
                "{}/v1/records/person-addresses/{address}?accessProfile=steward",
                self.base_url
            ))
            .header("authorization", self.steward_token())
            .send()
            .await
            .expect("registry answers");
        let status = response.status();
        let body: Value = response.json().await.expect("address is JSON");
        assert_eq!(status, reqwest::StatusCode::OK, "{body}");
        body["data"]["domainData"].clone()
    }

    /// Record the review authority's approval the way reconciliation does,
    /// and serve the same result from the authority for the fresh check the
    /// registry makes before it applies. This stands in for Casework.
    pub async fn approve(&self, request_id: &str) {
        let request_id = Uuid::parse_str(request_id).expect("request id is a UUID");
        let row = self
            .database
            .admin
            .query_one(
                "SELECT create_request,expected_submission_digest
                   FROM registry_internal.registry_request_review_submissions
                  WHERE request_entity_id=$1 AND request_id=$2",
                &[&REQUEST_ENTITY, &request_id],
            )
            .await
            .expect("queued review submission");
        let create: Value = row.get(0);
        let submission_digest: String = row.get(1);
        let review_request_id = Uuid::new_v4();
        let result_id = Uuid::new_v4();
        let accepted = json!({
            "requestId": review_request_id,
            "subject": create["subject"].clone(),
            "policy": {
                "id": create["kind"].clone(),
                "version": "1",
                "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            },
            "submissionDigest": submission_digest,
        });
        let result = json!({
            "resultId": result_id,
            "requestId": review_request_id,
            "subject": accepted["subject"].clone(),
            "policy": accepted["policy"].clone(),
            "submissionDigest": accepted["submissionDigest"].clone(),
            "status": "approved",
            "completedAt": "2026-09-01T00:00:00Z",
            "availableUntil": "2099-09-02T00:00:00Z"
        });
        self.database
            .admin
            .execute(
                "UPDATE registry_internal.registry_request_review_submissions
                    SET state='accepted',accepted_binding=$3
                  WHERE request_entity_id=$1 AND request_id=$2",
                &[&REQUEST_ENTITY, &request_id, &accepted],
            )
            .await
            .expect("review submission accepted");
        self.database
            .admin
            .execute(
                "INSERT INTO registry_internal.registry_request_review_results
                 (request_entity_id,request_id,proposal_version,authority,result_id,result,status,
                  completed_at,available_until)
                 VALUES ($1,$2,1,$3,$4,$5,'approved',
                         '2026-09-01T00:00:00Z','2099-09-02T00:00:00Z')",
                &[
                    &REQUEST_ENTITY,
                    &request_id,
                    &REVIEW_AUTHORITY,
                    &result_id,
                    &result,
                ],
            )
            .await
            .expect("reconciled review result");
        *self.authority.result.lock().expect("stub result") = Some(result);
    }

    /// The applier applies the approved proposal through the action the
    /// registry offers the `applier` profile.
    pub async fn apply(&self, request: &str) {
        let token = format!(
            "Bearer {}",
            self.server.issue_access_token(
                STAFF_CLIENT,
                "synthetic-applier",
                AUDIENCE,
                APPLY_SCOPE,
                now() + 600,
            )
        );
        let http = reqwest::Client::new();
        let view = http
            .get(format!(
                "{}/v1/records/address-correction-requests/{request}?accessProfile=applier",
                self.base_url
            ))
            .header("authorization", &token)
            .send()
            .await
            .expect("registry answers");
        let status = view.status();
        let view: Value = view.json().await.expect("request view is JSON");
        assert_eq!(status, reqwest::StatusCode::OK, "{view}");
        let digest = view["data"]["request"]["effectDigest"]
            .as_str()
            .unwrap_or_else(|| panic!("the applier sees the frozen effect digest: {view}"))
            .to_owned();
        let apply = view["data"]["request"]["actions"]
            .as_array()
            .and_then(|actions| {
                actions
                    .iter()
                    .find(|action| action["operation"] == "apply_request")
            })
            .unwrap_or_else(|| panic!("the applier is offered an apply: {view}"));
        let response = http
            .post(format!(
                "{}{}",
                self.base_url,
                apply["href"].as_str().expect("apply has an href")
            ))
            .header("authorization", &token)
            .header("idempotency-key", format!("apply-{request}"))
            .header(
                "if-match",
                apply["ifMatch"].as_str().expect("apply has a precondition"),
            )
            .json(&json!({"proposalVersion": 1, "effectDigest": digest}))
            .send()
            .await
            .expect("registry answers");
        let status = response.status();
        let body = response.text().await.expect("apply body");
        assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    }

    pub async fn create(&self, route: &str, key: &str, data: Value) -> String {
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
    pub async fn seed_citizen(&self, code: &str, principal: &str) -> String {
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

    pub async fn finish(self) {
        let Self {
            runtime_guard,
            database,
            server,
            serve_task,
            authority,
            ..
        } = self;
        serve_task.abort();
        authority.task.abort();
        server.stop().await;
        database.cleanup().await;
        drop(runtime_guard);
    }
}

/// Write a gateway runtime configuration under `directory` for a gateway
/// bound to `listen`, serving the fixture's gateway resource over its
/// registry, with review links under `review`, and return its path. The
/// gateway's key and audit hash key are owner-only files beside it.
pub fn write_gateway_config(
    directory: &Path,
    listen: &str,
    fixture: &RealRegistry,
    review: &str,
) -> PathBuf {
    let secrets = gateway::write_secrets(directory, &fixture.gateway_key);
    let document = gateway::document(&gateway::Document {
        listen,
        resource: &fixture.gateway_resource,
        issuer: &fixture.server.issuer(),
        jwks: &fixture.server.jwks_uri(),
        registry: &format!("{}/", fixture.base_url),
        token_endpoint: &fixture.server.token_endpoint(),
        review,
        secrets: &secrets,
        audit: &directory.join("audit").join("audit.jsonl"),
        limits: gateway::Limits::default(),
    });
    let path = directory.join("runtime.yaml");
    fs::write(&path, document).expect("runtime configuration writes");
    path
}

/// The whole citizen journey across the three services on one registry. The
/// chat host drives the gateway at `resource` to a prepared draft; the
/// citizen signs in to `page` and submits it through the page's own form;
/// the review authority's approval is recorded and the applier applies the
/// change. The gateway reports each state as the registry holds it, and the
/// citizen's address carries the new values only once the change is applied.
/// Each step is printed as it passes; nothing printed is a credential.
pub async fn citizen_journey(fixture: &RealRegistry, resource: &str, page: &ReviewPage) {
    let address = fixture.seed_citizen("B-1", CITIZEN_B).await;
    println!("registry: seeded a person, their address, and their self-service link");
    let client = gateway::connect(resource, &fixture.chat_host_token(CITIZEN_B)).await;
    println!("gateway: the chat host connected over MCP at {resource}");

    let described = gateway::call(&client, "describe_service", json!({})).await;
    assert_eq!(described.is_error, Some(false), "{described:?}");
    println!("tool describe_service: answered");
    let details = gateway::call(&client, "get_my_details", json!({})).await;
    assert_eq!(details.is_error, Some(false), "{details:?}");
    let details = serde_json::to_string(&gateway::structured(&details)).expect("details");
    assert!(details.contains("4 Mill Street"), "{details}");
    println!("tool get_my_details: the current address is 4 Mill Street");

    let started = gateway::call(
        &client,
        "start_application",
        json!({"newAddressLine": "2 Quay", "newLocality": "Port Selene", "newPostalCode": "PS-200"}),
    )
    .await;
    assert_eq!(started.is_error, Some(false), "{started:?}");
    let application = gateway::structured(&started)["application"].clone();
    assert_eq!(application["status"], "prepared");
    let identifier = application["applicationId"]
        .as_str()
        .expect("identifier")
        .to_owned();
    println!("tool start_application: application {identifier} is prepared");
    let updated = gateway::call(
        &client,
        "update_application",
        json!({"applicationId": identifier, "expectedRevision": application["revision"],
            "patch": [{"op": "replace", "path": "/newLocality", "value": "Old Town"}]}),
    )
    .await;
    assert_eq!(updated.is_error, Some(false), "{updated:?}");
    println!("tool update_application: the locality is now Old Town");
    let prepared = gateway::call(
        &client,
        "prepare_review",
        json!({"applicationId": identifier}),
    )
    .await;
    assert_eq!(prepared.is_error, Some(false), "{prepared:?}");
    let review_url = gateway::structured(&prepared)["reviewUrl"]
        .as_str()
        .expect("a review link")
        .to_owned();
    assert_eq!(review_url, format!("{}/requests/{identifier}", page.origin));
    println!("tool prepare_review: the review link is {review_url}");

    // The citizen follows the link: the page signs them in, shows the
    // address the draft changes beside the correction, and submits once.
    let session = page.sign_in(CITIZEN_B, &identifier).await;
    println!("review page: the citizen signed in through the authorization server");
    let (status, review) = page.get(&review_url, &session).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{review}");
    assert!(review.contains("4 Mill Street"), "{review}");
    assert!(review.contains("Old Town"), "{review}");
    println!("review page: GET {review_url} {status}, showing 4 Mill Street beside Old Town");
    let csrf = form_input(&review, "csrf").expect("the page offers a form");
    let view = form_input(&review, "view").expect("the page offers a form");
    let submit = format!("{}/requests/{identifier}/submit", page.origin);
    let (status, receipt) = page
        .post(&submit, &session, &[("csrf", &csrf), ("view", &view)])
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{receipt}");
    println!("review page: POST {submit} {status}");
    let status_of = || {
        gateway::call(
            &client,
            "get_application_status",
            json!({"applicationId": identifier}),
        )
    };
    let reported = status_of().await;
    assert_eq!(
        gateway::structured(&reported)["application"]["status"],
        "submitted",
        "{reported:?}"
    );
    println!("tool get_application_status: submitted");
    assert_eq!(
        fixture.steward_address(&address).await["addressLine"],
        "4 Mill Street",
        "submission leaves the address alone"
    );
    println!("registry: the stored address is still 4 Mill Street");

    fixture.approve(&identifier).await;
    println!("review authority (stub standing in for Casework): approved");
    // The citizen-agent profile's grant does not name review_state, so the
    // registry shows the agent no review outcome and the gateway still
    // reports an approved application as submitted.
    let reported = status_of().await;
    assert_eq!(
        gateway::structured(&reported)["application"]["status"],
        "submitted",
        "{reported:?}"
    );
    println!("tool get_application_status: submitted (the agent profile reads no review outcome)");
    fixture.apply(&identifier).await;
    println!("registry: the applier applied the approved proposal");
    let reported = status_of().await;
    assert_eq!(
        gateway::structured(&reported)["application"]["status"],
        "applied",
        "{reported:?}"
    );
    println!("tool get_application_status: applied");

    let details = gateway::call(&client, "get_my_details", json!({})).await;
    assert_eq!(details.is_error, Some(false), "{details:?}");
    let details = serde_json::to_string(&gateway::structured(&details)).expect("details");
    assert!(details.contains("2 Quay"), "{details}");
    assert!(details.contains("Old Town"), "{details}");
    assert!(!details.contains("4 Mill Street"), "{details}");
    println!("tool get_my_details: the current address is 2 Quay, Old Town");
    client.cancel().await.expect("client closes");
    let stored = fixture.steward_address(&address).await;
    assert_eq!(
        (
            &stored["addressLine"],
            &stored["locality"],
            &stored["postalCode"]
        ),
        (&json!("2 Quay"), &json!("Old Town"), &json!("PS-200")),
        "{stored}"
    );
    println!("registry: the stored address is 2 Quay, Old Town, PS-200");
}

/// The citizen review page served on its own loopback port. It signs people
/// in through the fixture's authorization server and reads and submits under
/// each person's own token, as it does in production.
pub struct ReviewPage {
    http: reqwest::Client,
    pub origin: String,
    task: Option<JoinHandle<()>>,
    _directory: Option<TempDir>,
}

impl ReviewPage {
    pub async fn start(
        listener: tokio::net::TcpListener,
        origin: &str,
        fixture: &RealRegistry,
    ) -> Self {
        let directory = tempfile::tempdir().expect("review page directory");
        let address = listener.local_addr().expect("review page address");
        let path = Self::write_config(directory.path(), address, origin, fixture);
        let config = registry_breg_review::RuntimeConfig::load(&path)
            .expect("review page configuration loads");
        let router = registry_breg_review::router(config)
            .await
            .expect("review page starts");
        let task = tokio::spawn(async move {
            // Stopped by aborting the task, so the test process keeps its
            // own signal handling.
            registry_breg_review::serve_until(listener, router, std::future::pending())
                .await
                .expect("review page serves");
        });
        Self {
            task: Some(task),
            _directory: Some(directory),
            ..Self::served_at(origin)
        }
    }

    /// A browser for a review page some other process serves at `origin`.
    pub fn served_at(origin: &str) -> Self {
        Self {
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("browser builds"),
            origin: origin.to_owned(),
            task: None,
            _directory: None,
        }
    }

    /// Write the page's runtime configuration, its owner-only secrets, and
    /// its audit directory under `directory` for a page bound to `address`
    /// and published at `origin`, and return the configuration's path.
    pub fn write_config(
        directory: &Path,
        address: SocketAddr,
        origin: &str,
        fixture: &RealRegistry,
    ) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let root = directory
            .canonicalize()
            .expect("review page directory canonicalizes");
        let secrets = root.join("secrets");
        let audit = root.join("audit");
        for private in [&secrets, &audit] {
            fs::create_dir(private).expect("private directory creates");
            fs::set_permissions(private, fs::Permissions::from_mode(0o700))
                .expect("owner-only directory");
        }
        write_private(
            &secrets.join("client-key.jwk"),
            testing_fixtures::ED25519_PRIVATE_JWK.as_bytes(),
        );
        write_private(&secrets.join("audit-key"), &[0x5a; 32]);
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
                 registry:\n  baseUrl: {registry}\n  resource: {AUDIENCE}\n  entity: {REQUEST_ENTITY}\n  targetField: address\n  accessProfile: citizen-review\n\
                 audit:\n  path: {audit}\n  hashKeyRef: secret:file/audit-key\n",
                secrets = secrets.display(),
                issuer = fixture.server.issuer(),
                registry = fixture.base_url,
                audit = audit.join("audit.jsonl").display(),
            ),
        )
        .expect("review page configuration writes");
        path
    }

    /// Sign `citizen` in through the page's redirect to the authorization
    /// server and back, returning to `request`, and return the session cookie
    /// a browser would send.
    pub async fn sign_in(&self, citizen: &str, request: &str) -> String {
        let start = self
            .http
            .get(format!(
                "{}/signin?return=%2Frequests%2F{request}",
                self.origin
            ))
            .send()
            .await
            .expect("review page answers");
        assert_eq!(start.status(), reqwest::StatusCode::SEE_OTHER);
        let sign_in_cookie = cookie(&start, "breg-review-signin");
        let authorize = format!("{}&login_hint={citizen}", header(&start, "location"));
        let redirected = self
            .http
            .get(authorize)
            .send()
            .await
            .expect("authorization server answers");
        assert_eq!(redirected.status(), reqwest::StatusCode::FOUND);
        let callback = header(&redirected, "location");
        assert!(callback.starts_with(&format!("{}/signin/callback?", self.origin)));
        let signed_in = self
            .http
            .get(callback)
            .header("cookie", sign_in_cookie)
            .send()
            .await
            .expect("review page answers");
        cookie(&signed_in, "breg-review-session")
    }

    pub async fn get(&self, url: &str, session: &str) -> (reqwest::StatusCode, String) {
        let response = self
            .http
            .get(url)
            .header("cookie", session)
            .send()
            .await
            .expect("review page answers");
        (response.status(), response.text().await.expect("page body"))
    }

    pub async fn post(
        &self,
        url: &str,
        session: &str,
        form: &[(&str, &str)],
    ) -> (reqwest::StatusCode, String) {
        let body = form
            .iter()
            .map(|(name, value)| {
                let value: String =
                    url::form_urlencoded::byte_serialize(value.as_bytes()).collect();
                format!("{name}={value}")
            })
            .collect::<Vec<_>>()
            .join("&");
        let response = self
            .http
            .post(url)
            .header("cookie", session)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .expect("review page answers");
        (response.status(), response.text().await.expect("page body"))
    }

    pub async fn finish(self) {
        if let Some(task) = self.task {
            task.abort();
            let _ = task.await;
        }
    }
}

/// The `name=value` pair of the cookie `response` sets under `name`.
pub fn cookie(response: &reqwest::Response, name: &str) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with(&format!("{name}=")))
        .and_then(|value| value.split(';').next())
        .unwrap_or_else(|| panic!("the response sets {name}"))
        .to_owned()
}

pub fn header(response: &reqwest::Response, name: &str) -> String {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| panic!("the response carries {name}"))
        .to_owned()
}

/// The value of the hidden form input `name`, if the page renders one.
pub fn form_input(body: &str, name: &str) -> Option<String> {
    let marker = format!("name=\"{name}\" value=\"");
    let start = body.find(&marker)? + marker.len();
    let end = body[start..].find('"')? + start;
    Some(body[start..end].to_owned())
}

/// The review authority the registry submits to. It answers nothing until a
/// test records an approval, and then serves that one result from the route
/// the registry reads before it applies.
pub struct ReviewAuthorityStub {
    endpoint: String,
    result: Arc<Mutex<Option<Value>>>,
    task: JoinHandle<()>,
}

impl ReviewAuthorityStub {
    pub async fn start() -> Self {
        let result = Arc::new(Mutex::new(None::<Value>));
        let app = axum::Router::new()
            .route(
                "/v1/review-requests/{request_id}/result",
                axum::routing::get(
                    |State(result): State<Arc<Mutex<Option<Value>>>>,
                     UrlPath(request_id): UrlPath<Uuid>| async move {
                        match result.lock().expect("stub result").clone() {
                            Some(result) if result["requestId"] == request_id.to_string() => (
                                http::StatusCode::OK,
                                // The review client requires a W3C trace context on every answer.
                                [(
                                    "traceparent",
                                    "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
                                )],
                                axum::Json(result),
                            )
                                .into_response(),
                            _ => http::StatusCode::SERVICE_UNAVAILABLE.into_response(),
                        }
                    },
                ),
            )
            .fallback(|| async { http::StatusCode::SERVICE_UNAVAILABLE })
            .with_state(Arc::clone(&result));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("review authority stub listens");
        let endpoint = format!("http://{}/", listener.local_addr().expect("stub address"));
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("review authority stub serves");
        });
        Self {
            endpoint,
            result,
            task,
        }
    }
}

pub struct ProjectSources {
    project: RegistryProject,
    project_bytes: Vec<u8>,
    journeys: Vec<u8>,
    compiled: CompiledRegistry,
}

impl ProjectSources {
    /// Load the acceptance project exactly as it is on disk.
    pub fn load() -> Self {
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

pub struct TestPackage {
    _root: TempDir,
    directory: PathBuf,
    package_root: PathBuf,
    anchor: PathBuf,
    revision: String,
    package: VerifiedPackage,
}

impl TestPackage {
    pub fn build(sources: &ProjectSources, schema_fingerprint: &str) -> Self {
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

    pub fn write_runtime_config(
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

pub fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after the epoch")
            .as_secs(),
    )
    .expect("seconds fit")
}

pub fn write_json(path: &Path, value: &impl Serialize) {
    let bytes = canonicalize_json(&serde_json::to_value(value).expect("value serializes"))
        .expect("value canonicalizes");
    write_private(path, &bytes);
}

pub fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("private file writes");
    set_private_permissions(path);
}

pub fn set_private_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("private file permissions set");
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    encoded
}
