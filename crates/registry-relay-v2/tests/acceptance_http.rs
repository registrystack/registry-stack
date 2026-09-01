// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use futures::stream;
use http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, ETAG, LINK, VARY};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use jsonschema::{Draft, JSONSchema};
use oxjsonld::JsonLdParser;
use registry_mint::{
    config::MintConfig,
    server::{build_app as build_mint_app, MintService},
};
use registry_platform_audit::{
    AuditChainHasher, AuditEnvelope, AuditError, AuditSink, ChainState, JsonlFileSink,
};
use registry_platform_crypto::PublicJwk;
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifier};
use registry_platform_sqlite::{
    inspect_schema, materialize_fixture, CapturedSnapshot, DatabaseProfile, InspectionLimits,
    SchemaObjectKind,
};
use registry_platform_testing::{
    fixtures, oidc_verifier_config, sign_ed25519_compact_jwt, MockIdp,
};
use registry_relay_client::{
    BoundingBox, Conditional, ListRequest, LookupRequest, PrivateKeyJwt, PrivateKeyJwtConfig,
    RecordCollectionResponse, RecordFormat, RecordOptions, RecordResponse, RelayClient,
    RelayClientConfig, ResourceListRequest, SdmxDataFormat, SdmxDataRequest, SdmxStructureKind,
    SdmxStructureRequest, SearchRequest, StaticToken, TokenProvider,
};
use registry_relay_v2::artifacts::{
    generate_artifacts, REGISTRY_RECORD_CONTEXT_ID, REGISTRY_RECORD_PROFILE_ID, RELAY_PROFILE_ID,
};
use registry_relay_v2::audit::RelayAudit;
use registry_relay_v2::auth::RelayAuthenticator;
use registry_relay_v2::compiler::{
    classification_inventory_digest, compile_contract, compile_contract_with_governed_files,
    GovernedFileSet,
};
use registry_relay_v2::contract::{RegistryContract, RelayRuntime, Visibility};
use registry_relay_v2::fixture_contract::{
    parse_journey, FixtureAuthorization as AuthorizationFixture, FixtureFormatProfile,
    FixtureGeoJsonRoot, FixtureGeometryType, FixtureJourney as Journey, FixtureJsonScalarType,
    FixtureMethod, FixtureStep as JourneyStep,
};
use registry_relay_v2::format_capabilities::{
    CRS84_URI, JSON_FG_CORE_CONFORMANCE, JSON_FG_PROFILE_URI, JSON_FG_TYPES_CONFORMANCE,
    RFC7946_PROFILE_URI,
};
use registry_relay_v2::identification::{
    parse_classification_review_yaml, render_classification_review_yaml,
};
use registry_relay_v2::model::{
    CompileProfile, ObservedColumn, ObservedSourceSchema, ObservedView, OperationKind,
};
use registry_relay_v2::server::{
    router, AlignmentMetadata, InstitutionMetadata, QuotaConfig, RelayService, ServiceMetadata,
};
use registry_relay_v2::sqlite_runtime::{RuntimeSourceBinding, SqliteRuntime, SqliteRuntimeLimits};
use registry_relay_v2::startup::build_authenticator_for_supervised_local_development;
use serde_json::{json, Map, Value};
use tempfile::TempDir;
use tower::ServiceExt as _;

const ACCEPTANCE_ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../products/relay-v2/acceptance"
);
const PROJECTS: [&str; 4] = [
    "social-assistance",
    "business-registry",
    "civil-event",
    "labour-statistics",
];

#[derive(Default)]
struct ResponseContractCoverage {
    json_records: usize,
    json_ld_records: usize,
}

struct ProjectHarness {
    app: axum::Router,
    service: Arc<RelayService>,
    contract: RegistryContract,
    runtime: RelayRuntime,
    database: PathBuf,
    idp: Option<MockIdp>,
    _temp: TempDir,
}

struct ClientLoopback {
    client: RelayClient,
    shutdown: tokio::sync::oneshot::Sender<()>,
    server: tokio::task::JoinHandle<Result<(), std::io::Error>>,
}

impl ClientLoopback {
    async fn start(harness: &ProjectHarness, token: Option<String>) -> Self {
        let provider = token.map(|token| {
            Arc::new(StaticToken::new(token).expect("fixture bearer token is header-safe"))
                as Arc<dyn TokenProvider>
        });
        Self::start_with_provider(harness, provider).await
    }

    async fn start_with_provider(
        harness: &ProjectHarness,
        provider: Option<Arc<dyn TokenProvider>>,
    ) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("client acceptance listener binds");
        let address = listener
            .local_addr()
            .expect("client acceptance address resolves");
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let app = harness.app.clone();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
        });
        let mut config = RelayClientConfig::new(
            url::Url::parse(&format!("http://{address}"))
                .expect("client acceptance base URL parses"),
        );
        if let Some(provider) = provider {
            config = config.with_token_provider(provider);
        }
        Self {
            client: RelayClient::new(config).expect("client acceptance client builds"),
            shutdown,
            server,
        }
    }

    async fn stop(self) {
        self.shutdown
            .send(())
            .expect("client acceptance server is running");
        tokio::time::timeout(Duration::from_secs(5), self.server)
            .await
            .expect("client acceptance server shuts down before timeout")
            .expect("client acceptance server task completes")
            .expect("client acceptance server shuts down cleanly");
    }
}

struct MintLoopback {
    issuer: String,
    token_provider: Arc<dyn TokenProvider>,
    shutdown: tokio::sync::oneshot::Sender<()>,
    server: tokio::task::JoinHandle<Result<(), std::io::Error>>,
    _temp: TempDir,
}

impl MintLoopback {
    async fn start_social_assistance(audience: &str) -> Self {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
            .expect("Mint acceptance listener reserves");
        listener
            .set_nonblocking(true)
            .expect("Mint acceptance listener becomes nonblocking");
        let address = listener
            .local_addr()
            .expect("Mint acceptance address resolves");
        let issuer = format!("http://{address}");
        let token_endpoint = format!("{issuer}/token");

        let temp = tempfile::tempdir().expect("Mint acceptance deployment creates");
        let root = temp.path();
        fs::create_dir(root.join("clients")).expect("Mint client directory creates");
        fs::create_dir(root.join("public-keys")).expect("Mint public-key directory creates");
        fs::create_dir(root.join("secrets")).expect("Mint secret directory creates");

        let (service_public, service_private) = mint_service_key_pair(9);
        let public_file = format!(
            "{}.jwk.json",
            service_public["kid"]
                .as_str()
                .expect("Mint service key has an id")
        );
        fs::write(
            root.join("public-keys").join(&public_file),
            service_public.to_string(),
        )
        .expect("Mint governed public key writes");
        write_owner_only(
            &root.join("secrets/signing.jwk"),
            service_private.to_string().as_bytes(),
        );
        write_owner_only(
            &root.join("secrets/audit-hmac-key"),
            b"0123456789abcdef0123456789abcdef",
        );

        let (client_private, client_public) = fixtures::ed25519_pair();
        let client_public =
            serde_json::to_value(client_public).expect("Mint client public key serializes");
        fs::write(
            root.join("clients/relay-consumer.yaml"),
            format!(
                "clientId: relay-consumer\nprincipal: synthetic-social-caseworker\nauthorization:\n  scopes: [registry:social-assistance:caseworker]\n  claims:\n    purpose: benefit-delivery\n    service_area: AREA-A\nkeys: [{client_public}]\n"
            ),
        )
        .expect("Mint Relay registration writes");

        let config_path = root.join("mint.yaml");
        fs::write(
            &config_path,
            format!(
                r#"version: 1
validationMode: supervised-local-development
issuer: {issuer}
listener: {{address: 127.0.0.1, port: {}}}
signing:
  algorithm: ES256
  activePublicJwkFile: public-keys/{public_file}
  publishedPublicJwkFiles: []
  revokedKeyIds: []
signer:
  kind: local-jwk
  privateKeyRef: secret:file/signing.jwk
secretProviders:
  file: {{root: {}}}
audit:
  path: audit/mint.jsonl
  maximumFileBytes: 1073741824
  hashKeyRef: secret:file/audit-hmac-key
  hashKeyVersion: 1
accessTokens:
  audiences: [{audience}]
  lifetimeSeconds: 300
clientAssertion:
  audience: {token_endpoint}
  algorithms: [EdDSA]
clients:
  directory: clients
"#,
                address.port(),
                root.join("secrets").display(),
            ),
        )
        .expect("Mint Relay deployment writes");

        let config = MintConfig::load(&config_path).expect("Mint Relay configuration loads");
        let service = Arc::new(
            MintService::load(config)
                .await
                .expect("Mint Relay deployment loads"),
        );
        let app = build_mint_app(service);
        let listener = tokio::net::TcpListener::from_std(listener)
            .expect("Mint acceptance listener transfers to Tokio");
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(1))
            .build()
            .expect("Mint acceptance readiness client builds");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if http
                    .get(format!("{issuer}/ready"))
                    .send()
                    .await
                    .is_ok_and(|response| response.status().is_success())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("Mint becomes ready before the acceptance deadline");

        let provider: Arc<dyn TokenProvider> = Arc::new(
            PrivateKeyJwt::new(PrivateKeyJwtConfig::new(
                url::Url::parse(&token_endpoint).expect("Mint token endpoint parses"),
                "relay-consumer",
                client_private,
            ))
            .expect("Mint private-key-JWT provider builds"),
        );

        Self {
            issuer,
            token_provider: provider,
            shutdown,
            server,
            _temp: temp,
        }
    }

    async fn stop(self) {
        self.shutdown
            .send(())
            .expect("Mint acceptance server is running");
        tokio::time::timeout(Duration::from_secs(5), self.server)
            .await
            .expect("Mint acceptance server shuts down before timeout")
            .expect("Mint acceptance server task completes")
            .expect("Mint acceptance server shuts down cleanly");
    }
}

fn mint_service_key_pair(seed: u8) -> (Value, Value) {
    let scalar = [seed; 32];
    let signing =
        p256::ecdsa::SigningKey::from_slice(&scalar).expect("the Mint acceptance scalar is valid");
    let encoded = signing.verifying_key().to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(encoded.x().expect("an uncompressed point has x"));
    let y = URL_SAFE_NO_PAD.encode(encoded.y().expect("an uncompressed point has y"));
    let public = PublicJwk::parse(
        &json!({"kty":"EC", "crv":"P-256", "alg":"ES256", "x":x, "y":y}).to_string(),
    )
    .expect("the Mint acceptance public key parses");
    let kid = public.jkt().expect("the Mint service thumbprint computes");
    (
        json!({"kty":"EC", "crv":"P-256", "alg":"ES256", "kid":kid, "x":x, "y":y}),
        json!({"kty":"EC", "crv":"P-256", "alg":"ES256", "kid":kid, "x":x, "y":y,
               "d":URL_SAFE_NO_PAD.encode(scalar)}),
    )
}

fn write_owner_only(path: &Path, contents: &[u8]) {
    fs::write(path, contents).expect("Mint acceptance secret writes");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("Mint acceptance secret becomes owner-only");
}

fn complete<T>(outcome: Conditional<T>, operation: &str) -> registry_relay_client::Complete<T> {
    match outcome {
        Conditional::Complete(value) => value,
        Conditional::NotModified(_) => panic!("{operation} unexpectedly returned 304"),
    }
}

struct ControlledAuditSink {
    fail_on_write: usize,
    writes: AtomicUsize,
    records: Mutex<Vec<Value>>,
}

impl ControlledAuditSink {
    fn new(fail_on_write: usize) -> Self {
        Self {
            fail_on_write,
            writes: AtomicUsize::new(0),
            records: Mutex::new(Vec::new()),
        }
    }

    fn writes(&self) -> usize {
        self.writes.load(Ordering::SeqCst)
    }

    fn values(&self) -> Vec<Value> {
        self.records.lock().expect("audit records lock").clone()
    }
}

#[async_trait::async_trait]
impl AuditSink for ControlledAuditSink {
    async fn write(&self, envelope: &AuditEnvelope) -> Result<(), AuditError> {
        let write = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
        if write == self.fail_on_write {
            return Err(AuditError::Io(std::io::Error::other(
                "controlled audit failure",
            )));
        }
        self.records
            .lock()
            .expect("audit records lock")
            .push(envelope.record.clone());
        Ok(())
    }

    #[allow(deprecated)]
    async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
        Ok(None)
    }

    async fn tail_hash_with_hasher(
        &self,
        _hasher: &AuditChainHasher,
    ) -> Result<Option<[u8; 32]>, AuditError> {
        Ok(None)
    }
}

#[derive(Default)]
struct SourceAccessTripwireAuditSink {
    attempts: AtomicUsize,
    records: Mutex<Vec<Value>>,
}

impl SourceAccessTripwireAuditSink {
    fn attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }

    fn values(&self) -> Vec<Value> {
        self.records.lock().expect("audit records lock").clone()
    }
}

#[async_trait::async_trait]
impl AuditSink for SourceAccessTripwireAuditSink {
    async fn write(&self, envelope: &AuditEnvelope) -> Result<(), AuditError> {
        if envelope.record["phase"] == "attempt" {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            return Err(AuditError::Io(std::io::Error::other(
                "source access tripwire reached",
            )));
        }
        self.records
            .lock()
            .expect("audit records lock")
            .push(envelope.record.clone());
        Ok(())
    }

    #[allow(deprecated)]
    async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
        Ok(None)
    }

    async fn tail_hash_with_hasher(
        &self,
        _hasher: &AuditChainHasher,
    ) -> Result<Option<[u8; 32]>, AuditError> {
        Ok(None)
    }
}

#[tokio::test]
async fn all_four_registry_http_journeys_use_the_real_router() {
    let selected = std::env::var("RELAY_V2_ACCEPTANCE_PROJECT").ok();
    if let Some(selected) = &selected {
        assert!(
            PROJECTS.contains(&selected.as_str()),
            "selected acceptance project is unknown"
        );
    }
    for project in PROJECTS.into_iter().filter(|project| {
        selected
            .as_deref()
            .is_none_or(|selected| selected == *project)
    }) {
        let mut harness = ProjectHarness::open(project).await;
        let journey = project_journey(project);
        assert_eq!(
            journey.schema_version,
            "relay.registrystack.org/http-journey/v1alpha1"
        );
        assert_eq!(
            journey.registry,
            harness.contract.registry.registry_identifier
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener binds");
        let address = listener.local_addr().expect("loopback address resolves");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let app = harness.app.clone();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("loopback client builds");
        let mut equivalence_classes = BTreeMap::new();
        let mut response_documents = BTreeMap::new();
        let mut etags = BTreeMap::new();
        let mut contract_coverage = ResponseContractCoverage::default();
        for step in journey.steps {
            let request = harness.request_with_observations(
                &step,
                &journey.authorizations,
                &response_documents,
                &etags,
            );
            let response = send_loopback_request(&client, address, request)
                .await
                .unwrap_or_else(|error| panic!("{project}/{} request failed: {error}", step.id));
            let status = response.status();
            let headers = response.headers().clone();
            let body = response.bytes().await.expect("response body reads");
            assert_eq!(
                status,
                StatusCode::from_u16(step.expect.status).expect("expected status is valid"),
                "{project}/{} returned the wrong status; response body withheld",
                step.id
            );
            if let Some(reference) = &step.expect.etag_same_as {
                assert_eq!(
                    headers.get(ETAG).and_then(|value| value.to_str().ok()),
                    etags.get(reference).map(String::as_str),
                    "{project}/{} ETag must match {reference}",
                    step.id
                );
            }
            if let Some(etag) = headers.get(ETAG).and_then(|value| value.to_str().ok()) {
                etags.insert(step.id.clone(), etag.to_owned());
            }
            assert_expectations(project, &step, &headers, &body, &mut equivalence_classes);
            if !body.is_empty() {
                let document = decode_fixture_response(&headers, &body);
                validate_response_contracts(
                    &harness,
                    project,
                    &step,
                    &headers,
                    &document,
                    &mut contract_coverage,
                );
                if let Some(reference) = &step.expect.records_equivalent_to {
                    let expected = response_documents
                        .get(reference)
                        .unwrap_or_else(|| panic!("referenced response {reference} exists"));
                    assert_eq!(
                        normalized_fixture_response(&document),
                        normalized_fixture_response(expected),
                        "{project}/{} Record values must match {reference}",
                        step.id
                    );
                }
                response_documents.insert(step.id.clone(), document);
            }
        }
        if !harness.service.registry.resources.is_empty() {
            assert!(
                contract_coverage.json_records > 0,
                "{project} must validate an ordinary JSON Record against its generated schema"
            );
            assert!(
                contract_coverage.json_ld_records > 0,
                "{project} must validate a JSON-LD Record against its generated schema"
            );
        }
        shutdown_tx.send(()).expect("loopback server is running");
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("loopback server shuts down before timeout")
            .expect("loopback server task completes")
            .expect("loopback server shuts down cleanly");
        if let Some(idp) = harness.idp.take() {
            idp.stop().await;
        }
    }
}

#[tokio::test]
async fn provider_discovery_description_route_serves_compiled_exact_bytes_without_authentication() {
    for project in PROJECTS {
        let harness = ProjectHarness::open(project).await;
        let expected = harness
            .service
            .artifacts
            .get("artifacts/discovery.jsonld")
            .expect("maintained Registry publishes a description")
            .content
            .clone();
        let response = harness
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/v2/artifacts/discovery-description")
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::OK, "{project}");
        assert_eq!(
            response.headers().get(CONTENT_TYPE),
            Some(&HeaderValue::from_static(
                "application/ld+json;profile=\"https://registrystack.org/discovery/profile/v1alpha1\""
            )),
            "{project}"
        );
        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("response body reads");
        assert_eq!(body.as_ref(), expected.as_slice(), "{project}");
        if project == "labour-statistics" {
            let description = registry_discovery_profile::parse_description(&body)
                .expect("maintained labour-statistics publication satisfies the shared profile");
            let statistical = description
                .services()
                .iter()
                .filter(|service| {
                    service.operation_family_ids()
                        == ["https://registrystack.org/discovery/operation-family/relay-v2/statistical-dataflow"]
                })
                .collect::<Vec<_>>();
            assert_eq!(statistical.len(), 1);
            assert!(statistical[0].semantic_class_ids().is_empty());
        }

        // If the public-artifact branch performed optional bearer
        // authentication, this malformed credential would be rejected before
        // the compiled bytes were served.
        let response = harness
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/v2/artifacts/discovery-description")
                    .header(AUTHORIZATION, "Bearer malformed")
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::OK, "{project}");
        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("response body reads");
        assert_eq!(body.as_ref(), expected.as_slice(), "{project}");

        // The authentication bypass is deliberately scoped to the public
        // Discovery advertisement. Existing public artifact semantics still
        // authenticate a bearer when the caller supplies one.
        let response = harness
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/v2/artifacts/capability-inventory")
                    .header(AUTHORIZATION, "Bearer malformed")
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{project}");
    }
}

#[tokio::test]
async fn rust_client_drives_the_real_relay_router_across_the_public_surface() {
    let mut business = ProjectHarness::open("business-registry").await;
    let business_loopback = ClientLoopback::start(&business, None).await;
    let client = &business_loopback.client;

    assert_eq!(
        client.health().await.expect("health succeeds").value.status,
        "ok"
    );
    assert_eq!(
        client.ready().await.expect("ready succeeds").value.status,
        "ready"
    );
    let openapi = complete(
        client.openapi(None).await.expect("OpenAPI succeeds"),
        "OpenAPI",
    );
    assert_eq!(openapi.value.media_type(), "application/json");
    assert!(!openapi.value.as_bytes().is_empty());

    let service = complete(
        client
            .service_metadata(None)
            .await
            .expect("service metadata succeeds"),
        "service metadata",
    );
    assert_eq!(
        service.value.registry_identifier,
        "urn:example:registry:registered-businesses"
    );

    let first_resources = complete(
        client
            .resources(
                ResourceListRequest::default()
                    .page_size(1)
                    .expect("resource page size is valid"),
                None,
            )
            .await
            .expect("first resource page succeeds"),
        "first resource page",
    );
    assert_eq!(first_resources.value.value.items.len(), 1);
    let resource_continuation = first_resources
        .value
        .continuation
        .as_ref()
        .expect("first resource page has a continuation");
    let second_resources = complete(
        client
            .continue_resources(resource_continuation, None)
            .await
            .expect("second resource page succeeds"),
        "second resource page",
    );
    assert_eq!(second_resources.value.value.items.len(), 1);
    assert_ne!(
        first_resources.value.value.items[0].resource_identifier,
        second_resources.value.value.items[0].resource_identifier
    );
    let resource = complete(
        client
            .resource("registered-business", None)
            .await
            .expect("resource metadata succeeds"),
        "resource metadata",
    );
    assert_eq!(
        resource.value.data.resource_identifier,
        "registered-business"
    );

    let first_list_request = ListRequest::default()
        .page_size(1)
        .expect("record page size is valid")
        .filter("jurisdiction", "EX-A")
        .expect("declared filter is valid");
    let first_list = complete(
        client
            .list_records("registered-business", &first_list_request, None)
            .await
            .expect("first Record page succeeds"),
        "first Record page",
    );
    match &first_list.value.value {
        RecordCollectionResponse::Json(records) => assert_eq!(records.items.len(), 1),
        RecordCollectionResponse::GeoJson(_) => panic!("list unexpectedly returned GeoJSON"),
    }
    let list_continuation = first_list
        .value
        .continuation
        .as_ref()
        .expect("first Record page has a continuation");
    let second_list = complete(
        client
            .continue_collection(list_continuation, None)
            .await
            .expect("second Record page succeeds"),
        "second Record page",
    );
    match &second_list.value.value {
        RecordCollectionResponse::Json(records) => assert_eq!(records.items.len(), 1),
        RecordCollectionResponse::GeoJson(_) => {
            panic!("continuation unexpectedly returned GeoJSON")
        }
    }

    let read = complete(
        client
            .read_record(
                "registered-business",
                "BIZ-SYNTH-0001",
                &RecordOptions::default(),
                None,
            )
            .await
            .expect("Record read succeeds"),
        "Record read",
    );
    match &read.value {
        RecordResponse::Json(record) => {
            assert_eq!(record.data.record_identifier, "BIZ-SYNTH-0001")
        }
        RecordResponse::GeoJson(_) => panic!("ordinary read unexpectedly returned GeoJSON"),
    }
    let etag = read
        .metadata
        .etag()
        .cloned()
        .expect("public snapshot read returns an ETag");
    match client
        .read_record(
            "registered-business",
            "BIZ-SYNTH-0001",
            &RecordOptions::default(),
            Some(&etag),
        )
        .await
        .expect("Record revalidation succeeds")
    {
        Conditional::NotModified(not_modified) => assert_eq!(not_modified.etag, etag),
        Conditional::Complete(_) => panic!("Record revalidation did not return 304"),
    }
    let json_ld_read = complete(
        client
            .read_record(
                "registered-business",
                "BIZ-SYNTH-0001",
                &RecordOptions::default().format(RecordFormat::JsonLd),
                None,
            )
            .await
            .expect("JSON-LD Record read succeeds"),
        "JSON-LD Record read",
    );
    match json_ld_read.value {
        RecordResponse::Json(record) => {
            assert_eq!(record.data.record_identifier, "BIZ-SYNTH-0001");
            assert!(record.json_ld_context.is_some());
        }
        RecordResponse::GeoJson(_) => panic!("JSON-LD read unexpectedly returned GeoJSON"),
    }

    let feature_read = complete(
        client
            .read_record(
                "registered-premises",
                "PREM-SYNTH-0001",
                &RecordOptions::default().format(RecordFormat::GeoJsonRfc7946),
                None,
            )
            .await
            .expect("GeoJSON feature read succeeds"),
        "GeoJSON feature read",
    );
    match feature_read.value {
        RecordResponse::GeoJson(feature) => {
            assert_eq!(feature.kind, "Feature");
            assert_eq!(feature.properties.record_identifier, "PREM-SYNTH-0001");
        }
        RecordResponse::Json(_) => panic!("GeoJSON feature read returned ordinary JSON"),
    }

    let spatial_request = SearchRequest::new(
        BoundingBox::new(100.0, 13.0, 101.0, 14.0).expect("fixture bbox is valid"),
    )
    .options(RecordOptions::default().format(RecordFormat::GeoJsonRfc7946));
    let spatial = complete(
        client
            .search_records("registered-premises", "within-bbox", &spatial_request, None)
            .await
            .expect("GeoJSON search succeeds"),
        "GeoJSON search",
    );
    match &spatial.value.value {
        RecordCollectionResponse::GeoJson(features) => {
            assert_eq!(features.kind, "FeatureCollection");
            assert!(!features.features.is_empty());
        }
        RecordCollectionResponse::Json(_) => panic!("GeoJSON search returned ordinary JSON"),
    }
    let spatial_continuation = spatial
        .value
        .continuation
        .as_ref()
        .expect("first GeoJSON search page has a continuation");
    let next_spatial = complete(
        client
            .continue_collection(spatial_continuation, None)
            .await
            .expect("second GeoJSON search page succeeds"),
        "second GeoJSON search page",
    );
    match &next_spatial.value.value {
        RecordCollectionResponse::GeoJson(features) => {
            assert_eq!(features.kind, "FeatureCollection");
            assert_eq!(features.features.len(), 1);
        }
        RecordCollectionResponse::Json(_) => {
            panic!("GeoJSON search continuation returned ordinary JSON")
        }
    }
    let json_fg_request = SearchRequest::new(
        BoundingBox::new(100.0, 13.0, 101.0, 14.0).expect("fixture bbox is valid"),
    )
    .options(RecordOptions::default().format(RecordFormat::JsonFg));
    let json_fg = complete(
        client
            .search_records("registered-premises", "within-bbox", &json_fg_request, None)
            .await
            .expect("JSON-FG search succeeds"),
        "JSON-FG search",
    );
    match json_fg.value.value {
        RecordCollectionResponse::GeoJson(features) => {
            assert_eq!(features.kind, "FeatureCollection");
            assert!(features.conforms_to.is_some());
        }
        RecordCollectionResponse::Json(_) => panic!("JSON-FG search returned ordinary JSON"),
    }

    let artifact = complete(
        client
            .artifact("capability-inventory", None)
            .await
            .expect("public artifact succeeds"),
        "public artifact",
    );
    assert_eq!(artifact.value.media_type(), "application/json");
    assert!(!artifact.value.as_bytes().is_empty());

    business_loopback.stop().await;
    if let Some(idp) = business.idp.take() {
        idp.stop().await;
    }

    let mut civil = ProjectHarness::open("civil-event").await;
    let civil_journey = project_journey("civil-event");
    let lookup_authorization = civil_journey
        .authorizations
        .get("civil-verifier-ex-a")
        .expect("civil lookup authorization is declared");
    let lookup_token = civil.token("client-lookup", lookup_authorization);
    let civil_loopback = ClientLoopback::start(&civil, Some(lookup_token)).await;
    let lookup = LookupRequest::default()
        .options(
            RecordOptions::default()
                .fields([
                    "eventType",
                    "registrationStatus",
                    "registrationDate",
                    "certificateAvailable",
                ])
                .expect("lookup fields are valid"),
        )
        .selector("registrationNumber", json!("REG-SYNTH-000001"))
        .expect("registration number selector is valid")
        .selector("eventType", json!("BIRTH"))
        .expect("event type selector is valid");
    let lookup = complete(
        civil_loopback
            .client
            .lookup_record("civil-event", "verify-registration", &lookup, None)
            .await
            .expect("lookup succeeds"),
        "lookup",
    );
    match lookup.value {
        RecordResponse::Json(record) => {
            assert_eq!(record.data.record_identifier, "EVENT-SYNTH-0001")
        }
        RecordResponse::GeoJson(_) => panic!("lookup unexpectedly returned GeoJSON"),
    }
    civil_loopback.stop().await;
    if let Some(idp) = civil.idp.take() {
        idp.stop().await;
    }

    let mut labour = ProjectHarness::open("labour-statistics").await;
    let labour_loopback = ClientLoopback::start(&labour, None).await;
    let data_request =
        SdmxDataRequest::new("LABOUR_STATISTICS", "LABOUR_FORCE_PARTICIPATION", "1.0.0")
            .expect("SDMX data route is valid")
            .keyed("EX-A.F")
            .expect("SDMX key is valid")
            .constraint("TIME_PERIOD", "ge:2024-Q1+le:2024-Q2")
            .expect("SDMX time constraint is valid")
            .dimension_at_observation("AllDimensions")
            .expect("SDMX observation dimension is valid");
    let data = complete(
        labour_loopback
            .client
            .sdmx_data(&data_request, None)
            .await
            .expect("SDMX data succeeds"),
        "SDMX data",
    );
    assert_eq!(
        data.value.media_type(),
        "application/vnd.sdmx.data+json;version=2.1.0"
    );
    assert!(!data.value.as_bytes().is_empty());
    let csv_request =
        SdmxDataRequest::new("LABOUR_STATISTICS", "LABOUR_FORCE_PARTICIPATION", "1.0.0")
            .expect("SDMX CSV route is valid")
            .keyed("EX-A.F")
            .expect("SDMX CSV key is valid")
            .constraint("TIME_PERIOD", "ge:2024-Q1+le:2024-Q2")
            .expect("SDMX CSV time constraint is valid")
            .format(SdmxDataFormat::Csv);
    let csv = complete(
        labour_loopback
            .client
            .sdmx_data(&csv_request, None)
            .await
            .expect("SDMX CSV succeeds"),
        "SDMX CSV",
    );
    assert_eq!(
        csv.value.media_type(),
        "application/vnd.sdmx.data+csv;version=2.1.0"
    );
    assert!(!csv.value.as_bytes().is_empty());

    let structure_request = SdmxStructureRequest::new(
        SdmxStructureKind::Dataflow,
        "LABOUR_STATISTICS",
        "LABOUR_FORCE_PARTICIPATION",
        "1.0.0",
    )
    .expect("SDMX structure route is valid");
    let structure = complete(
        labour_loopback
            .client
            .sdmx_structure(&structure_request, None)
            .await
            .expect("SDMX structure succeeds"),
        "SDMX structure",
    );
    assert_eq!(
        structure.value.media_type(),
        "application/vnd.sdmx.structure+json;version=2.1.0"
    );
    assert!(!structure.value.as_bytes().is_empty());
    labour_loopback.stop().await;
    if let Some(idp) = labour.idp.take() {
        idp.stop().await;
    }
}

#[tokio::test]
async fn mint_registered_authority_drives_a_protected_relay_lookup() {
    let mut relay = ProjectHarness::open("social-assistance").await;
    let audience = relay
        .runtime
        .authentication
        .issuer
        .as_ref()
        .expect("social-assistance declares an issuer")
        .audience
        .clone();
    let mint = MintLoopback::start_social_assistance(&audience).await;

    if let Some(fixture_idp) = relay.idp.take() {
        fixture_idp.stop().await;
    }
    let mut issuer = relay
        .runtime
        .authentication
        .issuer
        .clone()
        .expect("social-assistance declares an issuer");
    issuer.discovery_url = Some(format!("{}/.well-known/openid-configuration", mint.issuer));
    issuer.algorithms = vec!["ES256".into()];
    let authenticator = build_authenticator_for_supervised_local_development(&issuer)
        .await
        .expect("Relay startup discovers Mint and loads its signing key");
    relay.replace_authenticator(authenticator);

    let loopback =
        ClientLoopback::start_with_provider(&relay, Some(Arc::clone(&mint.token_provider))).await;
    let request = LookupRequest::default()
        .options(
            RecordOptions::default()
                .access_profile("caseworker")
                .expect("caseworker is a valid access profile")
                .fields(["enrolmentReference", "programmeCode"])
                .expect("caseworker fields are valid"),
        )
        .selector("caseReference", json!("CASE-SYNTH-0001"))
        .expect("case reference selector is valid")
        .selector("personReference", json!("PERSON-SYNTH-0001"))
        .expect("person reference selector is valid");
    let result = complete(
        loopback
            .client
            .lookup_record("assistance-enrolment", "by-case-and-person", &request, None)
            .await
            .expect("Mint-authorized Relay lookup succeeds"),
        "Mint-authorized Relay lookup",
    );
    match result.value {
        RecordResponse::Json(record) => {
            assert_eq!(record.data.record_identifier, "ENROL-SYNTH-0001");
            assert_eq!(
                record.data.domain_data,
                BTreeMap::from([
                    ("enrolmentReference".into(), json!("ENROL-SYNTH-0001")),
                    ("programmeCode".into(), json!("PROGRAMME-A")),
                ])
            );
        }
        RecordResponse::GeoJson(_) => panic!("protected lookup unexpectedly returned GeoJSON"),
    }

    loopback.stop().await;
    mint.stop().await;
}

#[tokio::test]
async fn business_list_with_a_late_malformed_row_fails_atomically() {
    let sink = Arc::new(ControlledAuditSink::new(usize::MAX));
    let harness = ProjectHarness::open_with_audit(
        "business-registry",
        Some(Arc::clone(&sink) as Arc<dyn AuditSink>),
    )
    .await;
    let response = harness
        .app
        .oneshot(
            Request::builder()
                .uri("/v2/resources/registered-business/records?jurisdiction=EX-B&pageSize=4")
                .body(Body::empty())
                .expect("business list request builds"),
        )
        .await
        .expect("router responds");
    let body = response_body(response, StatusCode::SERVICE_UNAVAILABLE).await;
    assert_eq!(body["code"], "source.unavailable");

    let response_wire = serde_json::to_string(&body).expect("problem response serializes");
    for hidden in [
        "BIZ-SYNTH-0002",
        "BIZ-SYNTH-0004",
        "BIZ-SYNTH-BAD1",
        "Synthetic River Trading Ltd",
        "Fixture Market Cooperative",
        "Invalid Fixture Enterprise",
        "not-a-date-time",
    ] {
        assert!(
            !response_wire.contains(hidden),
            "source values must not escape the failed page"
        );
    }

    let records = sink.values();
    assert_eq!(records.len(), 2, "attempt and source-failed terminal audit");
    assert_eq!(records[0]["phase"], "attempt");
    assert!(records[0].get("outcome").is_none());
    assert_eq!(records[1]["phase"], "terminal");
    assert_eq!(records[1]["outcome"], "source-failed");
    assert_eq!(records[0]["operationId"], records[1]["operationId"]);
    let audit_wire = serde_json::to_string(&records).expect("audit records serialize");
    for hidden in [
        "BIZ-SYNTH-0002",
        "BIZ-SYNTH-0004",
        "BIZ-SYNTH-BAD1",
        "Synthetic River Trading Ltd",
        "Fixture Market Cooperative",
        "Invalid Fixture Enterprise",
        "not-a-date-time",
    ] {
        assert!(
            !audit_wire.contains(hidden),
            "source values must not escape through audit"
        );
    }
}

#[tokio::test]
async fn malformed_disclosed_property_type_and_requiredness_fail_closed() {
    let original = fs::read_to_string(project_root("business-registry").join("fixture.sql"))
        .expect("business fixture reads");
    let valid_recorded_at = original.replacen(
        "'not-a-date-time', 'Invalid Fixture Enterprise'",
        "'2026-06-05T08:00:00Z', 'Invalid Fixture Enterprise'",
        1,
    );
    assert_ne!(valid_recorded_at, original);

    let wrong_type = valid_recorded_at.replacen(") STRICT;", ");", 1).replacen(
        "'Invalid Fixture Enterprise', 'Invalid Fixture Enterprise'",
        "X'FF', X'FF'",
        1,
    );
    let missing_required = valid_recorded_at
        .replacen(
            "public_legal_name TEXT NOT NULL",
            "public_legal_name TEXT",
            1,
        )
        .replacen(
            "'Invalid Fixture Enterprise', 'Invalid Fixture Enterprise'",
            "'Invalid Fixture Enterprise', NULL",
            1,
        );

    for (case, fixture_sql) in [
        ("wrong property type", wrong_type),
        ("missing required property", missing_required),
    ] {
        let sink = Arc::new(ControlledAuditSink::new(usize::MAX));
        let harness = ProjectHarness::open_with_fixture_sql(
            "business-registry",
            fixture_sql,
            Some(Arc::clone(&sink) as Arc<dyn AuditSink>),
            true,
        )
        .await;
        let response = harness
            .app
            .oneshot(
                Request::builder()
                    .uri("/v2/resources/registered-business/records/BIZ-SYNTH-BAD1")
                    .body(Body::empty())
                    .expect("business read request builds"),
            )
            .await
            .expect("router responds");
        let body = response_body(response, StatusCode::SERVICE_UNAVAILABLE).await;
        assert_eq!(body["code"], "source.unavailable", "{case}");
        let response_wire = serde_json::to_string(&body).expect("problem response serializes");
        assert!(!response_wire.contains("BIZ-SYNTH-BAD1"), "{case}");
        assert!(
            !response_wire.contains("Invalid Fixture Enterprise"),
            "{case}"
        );

        let records = sink.values();
        assert_eq!(records.len(), 2, "{case}: attempt and terminal audit");
        assert_eq!(records[0]["phase"], "attempt", "{case}");
        assert_eq!(records[1]["phase"], "terminal", "{case}");
        assert_eq!(records[1]["outcome"], "source-failed", "{case}");
        let audit_wire = serde_json::to_string(&records).expect("audit records serialize");
        assert!(!audit_wire.contains("BIZ-SYNTH-BAD1"), "{case}");
        assert!(!audit_wire.contains("Invalid Fixture Enterprise"), "{case}");
    }
}

async fn send_loopback_request(
    client: &reqwest::Client,
    address: std::net::SocketAddr,
    request: Request<Body>,
) -> reqwest::Result<reqwest::Response> {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 1024 * 1024)
        .await
        .expect("journey request body reads");
    client
        .request(
            reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
                .expect("journey method converts"),
            format!("http://{address}{}", parts.uri),
        )
        .headers(parts.headers)
        .body(body)
        .send()
        .await
}

#[tokio::test]
async fn probe_responses_preserve_one_request_trace_context() {
    const HEALTH_TRACE_ID: &str = "11111111111111111111111111111111";
    const READY_TRACE_ID: &str = "22222222222222222222222222222222";
    const UNREADY_TRACE_ID: &str = "33333333333333333333333333333333";

    let harness = ProjectHarness::open("business-registry").await;
    for (path, trace_id, expected_body) in [
        ("/health", HEALTH_TRACE_ID, r#"{"status":"ok"}"#),
        ("/ready", READY_TRACE_ID, r#"{"status":"ready"}"#),
    ] {
        let traceparent = format!("00-{trace_id}-0123456789abcdef-01");
        let response = harness
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("traceparent", &traceparent)
                    .body(Body::empty())
                    .expect("probe request builds"),
            )
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("traceparent"),
            Some(&traceparent.parse().expect("traceparent is valid"))
        );
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let body = to_bytes(response.into_body(), 1024)
            .await
            .expect("probe response reads");
        assert_eq!(body.as_ref(), expected_body.as_bytes());
    }

    fs::remove_file(&harness.database).expect("source removes");
    let traceparent = format!("00-{UNREADY_TRACE_ID}-fedcba9876543210-00");
    let response = harness
        .app
        .oneshot(
            Request::builder()
                .uri("/ready")
                .header("traceparent", &traceparent)
                .body(Body::empty())
                .expect("readiness request builds"),
        )
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.headers().get("traceparent"),
        Some(&traceparent.parse().expect("traceparent is valid"))
    );
    assert_eq!(
        response.headers().get(CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
    let body = to_bytes(response.into_body(), 1024)
        .await
        .expect("readiness problem reads");
    let document: Value = serde_json::from_slice(&body).expect("readiness problem is JSON");
    assert_eq!(document["code"], "service.not_ready");
    assert_eq!(document["traceId"], UNREADY_TRACE_ID);
}

#[tokio::test]
async fn wrong_method_uses_the_traced_problem_boundary() {
    const TRACE_ID: &str = "44444444444444444444444444444444";

    let harness = ProjectHarness::open("business-registry").await;
    let traceparent = format!("00-{TRACE_ID}-0123456789abcdef-01");
    let response = harness
        .app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2")
                .header("traceparent", &traceparent)
                .body(Body::empty())
                .expect("wrong-method request builds"),
        )
        .await
        .expect("router responds");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.headers().get(CONTENT_TYPE),
        Some(&HeaderValue::from_static("application/problem+json"))
    );
    assert_eq!(
        response.headers().get(CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
    assert_eq!(
        response.headers().get("traceparent"),
        Some(&traceparent.parse().expect("traceparent is valid"))
    );

    let body = to_bytes(response.into_body(), 1024)
        .await
        .expect("method problem reads");
    let document: Value = serde_json::from_slice(&body).expect("method problem is JSON");
    assert_eq!(document["status"], 404);
    assert_eq!(document["code"], "resource.not_found");
    assert_eq!(document["traceId"], TRACE_ID);
}

#[tokio::test]
async fn readiness_fails_value_free_for_missing_replaced_and_drifted_sources() {
    for project in ["business-registry", "social-assistance"] {
        let harness = ProjectHarness::open(project).await;
        assert!(harness.service.is_ready().await, "{project} starts ready");
        fs::remove_file(&harness.database).expect("source removes");
        assert_unready(&harness, project, "missing").await;

        let harness = ProjectHarness::open(project).await;
        assert!(harness.service.is_ready().await, "{project} starts ready");
        let old = harness.database.with_extension("old.sqlite");
        fs::rename(&harness.database, &old).expect("bound source moves");
        materialize_fixture(
            &harness.database,
            &fs::read_to_string(project_root(project).join("fixture.sql"))
                .expect("fixture SQL reads"),
        )
        .expect("replacement materializes");
        assert_unready(&harness, project, "replaced").await;

        let harness = ProjectHarness::open(project).await;
        assert!(harness.service.is_ready().await, "{project} starts ready");
        let drift = harness.database.with_extension("drift.sqlite");
        let mut changed_sql = fs::read_to_string(project_root(project).join("fixture.sql"))
            .expect("fixture SQL reads");
        changed_sql.push_str("\nCREATE TABLE readiness_schema_drift (id TEXT);\n");
        materialize_fixture(&drift, &changed_sql).expect("drifted source materializes");
        make_writable(&harness.database);
        fs::copy(&drift, &harness.database).expect("source drifts in place");
        make_read_only(&harness.database);
        assert_unready(&harness, project, "drifted").await;
    }

    let harness = ProjectHarness::open("business-registry").await;
    fs::write(
        format!("{}-wal", harness.database.display()),
        b"synthetic uncheckpointed sidecar",
    )
    .expect("snapshot sidecar writes");
    assert_unready(&harness, "business-registry", "sidecar").await;
}

#[tokio::test]
async fn social_live_update_is_consistent_and_truthfully_unversioned() {
    let harness = ProjectHarness::open("social-assistance").await;
    let journey = project_journey("social-assistance");
    let step = journey
        .steps
        .iter()
        .find(|step| step.id == "lookup-default")
        .expect("default lookup exists");

    let before = harness
        .app
        .clone()
        .oneshot(harness.request(step, &journey.authorizations))
        .await
        .expect("router responds");
    assert_eq!(before.status(), StatusCode::OK);
    assert_eq!(
        before.headers().get(CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
    assert!(!before.headers().contains_key(ETAG));
    let before = to_bytes(before.into_body(), 1024 * 1024)
        .await
        .expect("response reads");
    let before: Value = serde_json::from_slice(&before).expect("response parses");
    assert_eq!(
        before.pointer("/data/revisionIdentifier"),
        Some(&json!("3"))
    );
    assert_eq!(
        before.pointer("/data/domainData/enrolmentStatus"),
        Some(&json!("ELIGIBLE"))
    );

    make_writable(&harness.database);
    materialize_fixture(
        &harness.database,
        "UPDATE source_assistance_enrolments \
         SET record_revision = '4', enrolment_status = 'SUSPENDED', valid_through = NULL \
         WHERE enrolment_reference = 'ENROL-SYNTH-0001';",
    )
    .expect("trusted publisher update commits");

    let after = harness
        .app
        .clone()
        .oneshot(harness.request(step, &journey.authorizations))
        .await
        .expect("router responds");
    assert_eq!(after.status(), StatusCode::OK);
    assert_eq!(
        after.headers().get(CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
    assert!(!after.headers().contains_key(ETAG));
    let after = to_bytes(after.into_body(), 1024 * 1024)
        .await
        .expect("response reads");
    let after: Value = serde_json::from_slice(&after).expect("response parses");
    assert_eq!(after.pointer("/data/revisionIdentifier"), Some(&json!("4")));
    assert_eq!(
        after.pointer("/data/domainData/enrolmentStatus"),
        Some(&json!("SUSPENDED"))
    );
    assert!(after.pointer("/data/domainData/validThrough").is_none());
    assert_eq!(
        after.pointer("/meta/sourceRevision"),
        Some(&json!({"profile": "live", "status": "unversioned", "value": null}))
    );
}

#[tokio::test]
async fn trusted_purpose_and_row_binding_refusals_use_only_verified_claims() {
    let harness = ProjectHarness::open("social-assistance").await;
    let journey = project_journey("social-assistance");
    for (step_id, status) in [
        ("missing-purpose", StatusCode::FORBIDDEN),
        ("wrong-purpose", StatusCode::FORBIDDEN),
        ("missing-binding", StatusCode::FORBIDDEN),
        ("wrong-binding", StatusCode::NOT_FOUND),
    ] {
        let step = journey
            .steps
            .iter()
            .find(|step| step.id == step_id)
            .unwrap_or_else(|| panic!("{step_id} journey exists"));
        let response = harness
            .app
            .clone()
            .oneshot(harness.request(step, &journey.authorizations))
            .await
            .expect("router responds");
        let expected_code = if status == StatusCode::FORBIDDEN {
            "consultation.denied"
        } else {
            "consultation.unresolved"
        };
        assert_problem_code(response, status, expected_code).await;
    }
}

#[tokio::test]
async fn audit_attempt_failure_prevents_source_access() {
    let sink = Arc::new(ControlledAuditSink::new(1));
    let harness = ProjectHarness::open_with_audit(
        "business-registry",
        Some(Arc::clone(&sink) as Arc<dyn AuditSink>),
    )
    .await;
    let response = harness
        .app
        .oneshot(
            Request::builder()
                .uri("/v2/resources/registered-business/records/BIZ-SYNTH-0001")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    let body = response_body(response, StatusCode::SERVICE_UNAVAILABLE).await;
    assert_eq!(
        body.get("code").and_then(Value::as_str),
        Some("audit.unavailable")
    );
    assert_eq!(
        sink.writes(),
        1,
        "source path must stop at failed attempt audit"
    );
}

#[tokio::test]
async fn audit_terminal_failure_discards_held_record_bytes() {
    let sink = Arc::new(ControlledAuditSink::new(2));
    let harness = ProjectHarness::open_with_audit(
        "business-registry",
        Some(Arc::clone(&sink) as Arc<dyn AuditSink>),
    )
    .await;
    let response = harness
        .app
        .oneshot(
            Request::builder()
                .uri("/v2/resources/registered-business/records/BIZ-SYNTH-0001")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    let body = response_body(response, StatusCode::SERVICE_UNAVAILABLE).await;
    assert_eq!(
        body.get("code").and_then(Value::as_str),
        Some("audit.unavailable")
    );
    let wire = serde_json::to_string(&body).expect("problem serializes");
    assert!(!wire.contains("BIZ-SYNTH-0001"));
    assert!(!wire.contains("Example Orchard Cooperative"));
    assert_eq!(
        sink.writes(),
        2,
        "release must stop at failed terminal audit"
    );
}

#[tokio::test]
async fn spatial_terminal_audit_failure_discards_held_feature_bytes() {
    let sink = Arc::new(ControlledAuditSink::new(2));
    let fixture_sql = fs::read_to_string(project_root("business-registry").join("fixture.sql"))
        .expect("business fixture reads");
    let harness = ProjectHarness::open_with_fixture_sql(
        "business-registry",
        fixture_sql,
        Some(Arc::clone(&sink) as Arc<dyn AuditSink>),
        true,
    )
    .await;
    let response = harness
        .app
        .oneshot(
            Request::builder()
                .uri(
                    "/v2/resources/registered-premises/records/PREM-SYNTH-0001?formatProfile=jsonfg",
                )
                .header("accept", "application/geo+json")
                .body(Body::empty())
                .expect("spatial request builds"),
        )
        .await
        .expect("router responds");
    let body = response_body(response, StatusCode::SERVICE_UNAVAILABLE).await;
    assert_eq!(body["code"], "audit.unavailable");

    let wire = serde_json::to_string(&body).expect("problem serializes");
    for held in [
        "PREM-SYNTH-0001",
        "Orchard cooperative market",
        "Feature",
        "Point",
        "coordinates",
        "100.0",
        "13.0",
    ] {
        assert!(
            !wire.contains(held),
            "held spatial response bytes must not escape after terminal audit failure"
        );
    }
    assert_eq!(sink.writes(), 2, "release stops at terminal audit failure");
    let records = sink.values();
    assert_eq!(records.len(), 1, "only the attempt audit is committed");
    assert_eq!(records[0]["phase"], "attempt");
    assert_eq!(records[0]["wireFormat"], "geojson");
    assert_eq!(records[0]["formatProfile"], "jsonfg");
}

#[tokio::test]
async fn bbox_shape_refusals_are_audited_before_any_search_attempt() {
    let sink = Arc::new(SourceAccessTripwireAuditSink::default());
    let fixture_sql = fs::read_to_string(project_root("business-registry").join("fixture.sql"))
        .expect("business fixture reads");
    let harness = ProjectHarness::open_with_fixture_sql(
        "business-registry",
        fixture_sql,
        Some(Arc::clone(&sink) as Arc<dyn AuditSink>),
        true,
    )
    .await;
    let response = harness
        .app
        .oneshot(
            Request::builder()
                .uri(
                    "/v2/resources/registered-premises/searches/within-bbox?bbox=privateLongitude,privateLatitude,canary",
                )
                .body(Body::empty())
                .expect("invalid bbox request builds"),
        )
        .await
        .expect("router responds");
    assert_problem_code(response, StatusCode::BAD_REQUEST, "filter.invalid_value").await;

    assert_eq!(
        sink.attempts(),
        0,
        "invalid bbox must not reach the attempt boundary before source execution"
    );
    let records = sink.values();
    assert_eq!(records.len(), 1, "the refusal is audited exactly once");
    assert_eq!(records[0]["phase"], "refusal");
    assert_eq!(records[0]["outcome"], "invalid-request");
    let audit_wire = serde_json::to_string(&records).expect("audit records serialize");
    for hidden in ["privateLongitude", "privateLatitude", "canary"] {
        assert!(
            !audit_wire.contains(hidden),
            "rejected bbox values must not enter audit"
        );
    }
}

#[tokio::test]
async fn spatial_formats_validate_and_keep_distinct_cache_identities() {
    let fixture_sql = fs::read_to_string(project_root("business-registry").join("fixture.sql"))
        .expect("business fixture reads");
    let harness =
        ProjectHarness::open_with_fixture_sql("business-registry", fixture_sql, None, true).await;
    let resource = harness
        .service
        .registry
        .resources
        .iter()
        .find(|resource| resource.id == "registered-premises")
        .expect("business Registry compiles the premises resource");
    let operation = resource
        .operations
        .iter()
        .find(|operation| {
            matches!(
                &operation.kind,
                OperationKind::Search { name } if name == "within-bbox"
            )
        })
        .expect("business Registry compiles the bbox search");
    let access_profile = operation
        .access_profiles
        .iter()
        .find(|access_profile| access_profile.id == "public-premises")
        .expect("bbox search carries the public premises access profile");
    let binding = harness
        .service
        .artifacts
        .operation_bindings
        .iter()
        .find(|binding| {
            binding.operation_identifier == operation.identifier
                && binding.access_profile_identifier == access_profile.id
        })
        .expect("bbox search has one exact public artifact binding");

    let record_schema_artifact = harness
        .service
        .artifacts
        .get(&binding.access_profile_schema_path)
        .expect("public Record schema exists");
    assert_eq!(record_schema_artifact.visibility, Visibility::Public);
    let record_schema: Value = serde_json::from_slice(&record_schema_artifact.content)
        .expect("public Record schema parses");
    let record_validator = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .compile(&record_schema)
        .expect("public Record schema compiles");

    let geojson_schema_id = access_profile
        .schema_reference
        .strip_suffix("-schema")
        .map(|base| format!("{base}-geojson-schema"))
        .unwrap_or_else(|| format!("{}-geojson", access_profile.schema_reference));
    let matching_geojson_schemas = harness
        .service
        .artifacts
        .artifacts
        .iter()
        .filter(|artifact| artifact.media_type == "application/schema+json")
        .filter_map(|artifact| {
            let schema: Value = serde_json::from_slice(&artifact.content).ok()?;
            (schema.get("$id").and_then(Value::as_str) == Some(geojson_schema_id.as_str()))
                .then_some((artifact, schema))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        matching_geojson_schemas.len(),
        1,
        "the exact public access profile owns one GeoJSON response schema"
    );
    let (geojson_schema_artifact, geojson_schema) = &matching_geojson_schemas[0];
    assert_eq!(geojson_schema_artifact.visibility, Visibility::Public);
    let geojson_validator = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .compile(geojson_schema)
        .expect("public GeoJSON response schema compiles");

    let context_artifact = harness
        .service
        .artifacts
        .get(&binding.context_path)
        .expect("public JSON-LD context exists");
    assert_eq!(context_artifact.visibility, Visibility::Public);
    let context_document: Value =
        serde_json::from_slice(&context_artifact.content).expect("public JSON-LD context parses");
    assert_eq!(
        context_document.pointer("/@context/location/@type"),
        Some(&Value::String("@json".into())),
        "the public Point property stays an RDF JSON literal"
    );

    let cases = [
        ("json", "application/json", None, "application/json", None),
        (
            "json-ld",
            "application/ld+json",
            None,
            "application/ld+json",
            None,
        ),
        (
            "geojson",
            "application/geo+json",
            Some("rfc7946"),
            "application/geo+json",
            Some(RFC7946_PROFILE_URI),
        ),
        (
            "json-fg",
            "application/geo+json",
            Some("jsonfg"),
            "application/geo+json",
            Some(JSON_FG_PROFILE_URI),
        ),
    ];
    let mut exact_bodies = BTreeSet::new();
    let mut exact_etags = BTreeSet::new();
    for (label, accept, format_profile, media_type, profile_uri) in cases {
        let mut uri = String::from(
            "/v2/resources/registered-premises/searches/within-bbox?bbox=100,13,101,14&pageSize=4",
        );
        if let Some(format_profile) = format_profile {
            uri.push_str("&formatProfile=");
            uri.push_str(format_profile);
        }
        let response = harness
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("accept", accept)
                    .body(Body::empty())
                    .expect("spatial format request builds"),
            )
            .await
            .expect("real router responds");
        assert_eq!(response.status(), StatusCode::OK, "{label} status");
        let headers = response.headers().clone();
        assert_eq!(
            headers
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some(media_type),
            "{label} negotiated media type"
        );
        assert_eq!(
            headers
                .get(CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("public, no-cache"),
            "{label} is publicly revalidatable"
        );
        assert_eq!(
            headers.get(VARY).and_then(|value| value.to_str().ok()),
            Some("Accept, Authorization"),
            "{label} varies across the negotiation and authorization boundaries"
        );
        let expected_link = profile_uri.map_or_else(
            || {
                Some(format!(
                    "<{REGISTRY_RECORD_PROFILE_ID}>; rel=\"profile\", <{RELAY_PROFILE_ID}>; rel=\"profile\""
                ))
            },
            |profile| Some(format!("<{profile}>; rel=\"profile\"")),
        );
        assert_eq!(
            headers.get(LINK).and_then(|value| value.to_str().ok()),
            expected_link.as_deref(),
            "{label} profile link"
        );

        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("spatial response body reads")
            .to_vec();
        let etag = headers
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .expect("public snapshot response has an ETag")
            .to_owned();
        assert!(etag.starts_with('"') && etag.ends_with('"'), "{label} ETag");
        let document: Value = serde_json::from_slice(&body).expect("spatial response is JSON");

        if label == "json" || label == "json-ld" {
            let records = response_records(&document);
            assert_eq!(records.len(), 3, "{label} returns the bounded journey page");
            for record in records {
                assert!(
                    record_validator.is_valid(record),
                    "{label} Record validates against the exact public access-profile schema"
                );
            }
        } else {
            assert!(
                geojson_validator.is_valid(&document),
                "{label} validates against the exact public GeoJSON response schema"
            );
            assert_eq!(document["type"], "FeatureCollection", "{label} root");
            let features = document["features"]
                .as_array()
                .expect("GeoJSON features are an array");
            assert_eq!(
                features.len(),
                3,
                "{label} returns the bounded journey page"
            );
            for feature in features {
                assert_eq!(feature["type"], "Feature");
                assert_eq!(feature["geometry"]["type"], "Point");
                assert_eq!(
                    feature["geometry"]["coordinates"].as_array().map(Vec::len),
                    Some(2)
                );
            }
        }

        if label == "json-ld" {
            assert_operation_context_is_disjoint_from_shared_terms(&context_document);
        } else if label == "geojson" {
            for member in ["conformsTo", "featureType", "coordRefSys"] {
                assert!(
                    document.get(member).is_none(),
                    "RFC 7946 response omits JSON-FG-only member {member}"
                );
            }
        } else if label == "json-fg" {
            assert_eq!(document["featureType"], "registered-premises");
            assert_eq!(document["coordRefSys"], CRS84_URI);
            let conforms_to = document["conformsTo"]
                .as_array()
                .expect("JSON-FG root carries conformsTo")
                .iter()
                .filter_map(Value::as_str)
                .collect::<BTreeSet<_>>();
            assert_eq!(
                conforms_to,
                BTreeSet::from([JSON_FG_CORE_CONFORMANCE, JSON_FG_TYPES_CONFORMANCE])
            );
            for feature in document["features"]
                .as_array()
                .expect("JSON-FG features are an array")
            {
                for member in ["conformsTo", "featureType", "coordRefSys"] {
                    assert!(
                        feature.get(member).is_none(),
                        "JSON-FG collection feature must not repeat root-only member {member}"
                    );
                }
            }
        }

        let wire = String::from_utf8_lossy(&body);
        for hidden in [
            "longitude",
            "latitude",
            "business_registration_number",
            "source_registered_premises",
            "relay_registered_premises",
            "BIZ-SYNTH-0001",
        ] {
            assert!(
                !wire.contains(hidden),
                "{label} leaked source term {hidden}"
            );
        }
        assert!(
            exact_bodies.insert(body),
            "{label} exact bytes are distinct"
        );
        assert!(exact_etags.insert(etag), "{label} ETag is distinct");
    }
    assert_eq!(exact_bodies.len(), 4);
    assert_eq!(exact_etags.len(), 4);
}

#[tokio::test]
async fn real_jwt_path_rejects_malformed_audience_time_and_expired_tokens() {
    let harness = ProjectHarness::open("social-assistance").await;
    let journey = project_journey("social-assistance");
    let step = journey
        .steps
        .iter()
        .find(|step| step.id == "lookup-success")
        .expect("protected lookup journey exists");
    let fixture_id = step
        .authorization_fixture
        .as_deref()
        .expect("lookup has authorization fixture");
    let fixture = journey
        .authorizations
        .get(fixture_id)
        .expect("authorization fixture resolves");

    let malformed = request_with_bearer(&harness, step, &journey.authorizations, "malformed");
    assert_problem_code(
        harness
            .app
            .clone()
            .oneshot(malformed)
            .await
            .expect("router responds"),
        StatusCode::UNAUTHORIZED,
        "auth.invalid_credential",
    )
    .await;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is valid")
        .as_secs();
    let expected_audience = &harness
        .runtime
        .authentication
        .issuer
        .as_ref()
        .expect("issuer exists")
        .audience;
    let multiple_audiences = harness.signed_token_with_audience(
        fixture_id,
        fixture,
        json!([expected_audience, "urn:example:secondary-audience"]),
        now,
        now,
        now.saturating_add(900),
    );
    assert_problem_code(
        harness
            .app
            .clone()
            .oneshot(request_with_bearer(
                &harness,
                step,
                &journey.authorizations,
                &multiple_audiences,
            ))
            .await
            .expect("router responds"),
        StatusCode::UNAUTHORIZED,
        "auth.invalid_credential",
    )
    .await;

    let future_issued_at = now.saturating_add(300);
    let future_issued = harness.signed_token(
        fixture_id,
        fixture,
        expected_audience,
        future_issued_at,
        now,
        future_issued_at.saturating_add(900),
    );
    assert_problem_code(
        harness
            .app
            .clone()
            .oneshot(request_with_bearer(
                &harness,
                step,
                &journey.authorizations,
                &future_issued,
            ))
            .await
            .expect("router responds"),
        StatusCode::UNAUTHORIZED,
        "auth.invalid_credential",
    )
    .await;

    let wrong_audience = harness.signed_token(
        fixture_id,
        fixture,
        "urn:example:wrong-audience",
        now,
        now,
        now.saturating_add(900),
    );
    assert_problem_code(
        harness
            .app
            .clone()
            .oneshot(request_with_bearer(
                &harness,
                step,
                &journey.authorizations,
                &wrong_audience,
            ))
            .await
            .expect("router responds"),
        StatusCode::UNAUTHORIZED,
        "auth.invalid_credential",
    )
    .await;

    let issued_at = now.saturating_sub(1_000);
    let expired = harness.signed_token(
        fixture_id,
        fixture,
        &harness
            .runtime
            .authentication
            .issuer
            .as_ref()
            .expect("issuer exists")
            .audience,
        issued_at,
        issued_at,
        now.saturating_sub(120),
    );
    assert_problem_code(
        harness
            .app
            .clone()
            .oneshot(request_with_bearer(
                &harness,
                step,
                &journey.authorizations,
                &expired,
            ))
            .await
            .expect("router responds"),
        StatusCode::UNAUTHORIZED,
        "auth.invalid_credential",
    )
    .await;
}

#[tokio::test]
async fn real_jwt_path_uses_trusted_issuer_not_the_jwks_transport_host() {
    const TRUSTED_ISSUER: &str = "https://trusted-issuer.example.invalid/tenant";

    let mut harness = ProjectHarness::open("social-assistance").await;
    let journey = project_journey("social-assistance");
    let step = journey
        .steps
        .iter()
        .find(|step| step.id == "lookup-success")
        .expect("protected lookup journey exists");
    let fixture_id = step
        .authorization_fixture
        .as_deref()
        .expect("lookup has authorization fixture");
    let fixture = journey
        .authorizations
        .get(fixture_id)
        .expect("authorization fixture resolves");

    let transport_issuer = harness
        .idp
        .as_ref()
        .expect("protected project has a JWKS host")
        .issuer();
    let jwks_url = harness
        .idp
        .as_ref()
        .expect("protected project has a JWKS host")
        .jwks_uri();
    assert_ne!(TRUSTED_ISSUER, transport_issuer);

    let mut issuer = harness
        .runtime
        .authentication
        .issuer
        .clone()
        .expect("social-assistance declares an issuer");
    issuer.trusted_issuer = Some(TRUSTED_ISSUER.into());
    issuer.discovery_url = None;
    issuer.jwks_url = Some(jwks_url);
    issuer.algorithms = vec!["EdDSA".into()];
    let audience = issuer.audience.clone();
    let authenticator = build_authenticator_for_supervised_local_development(&issuer)
        .await
        .expect("Relay loads the direct JWKS transport");
    harness.replace_authenticator(authenticator);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is valid")
        .as_secs();
    let trusted_token = harness.signed_token_with_issuer(
        TRUSTED_ISSUER,
        fixture_id,
        fixture,
        json!(audience),
        [now, now, now.saturating_add(900)],
    );
    let accepted = harness
        .app
        .clone()
        .oneshot(request_with_bearer(
            &harness,
            step,
            &journey.authorizations,
            &trusted_token,
        ))
        .await
        .expect("router responds to the trusted issuer");
    assert_eq!(accepted.status(), StatusCode::OK);

    let transport_host_token = harness.signed_token_with_issuer(
        &transport_issuer,
        fixture_id,
        fixture,
        json!(audience),
        [now, now, now.saturating_add(900)],
    );
    assert_problem_code(
        harness
            .app
            .clone()
            .oneshot(request_with_bearer(
                &harness,
                step,
                &journey.authorizations,
                &transport_host_token,
            ))
            .await
            .expect("router responds to the transport-host issuer"),
        StatusCode::UNAUTHORIZED,
        "auth.invalid_credential",
    )
    .await;
}

#[tokio::test]
async fn operation_bound_metadata_is_no_store_and_links_only_visible_artifacts() {
    let harness = ProjectHarness::open("social-assistance").await;
    let journey = project_journey("social-assistance");
    let step = journey
        .steps
        .iter()
        .find(|step| step.id == "lookup-success")
        .expect("protected lookup journey exists");
    let fixture_id = step
        .authorization_fixture
        .as_deref()
        .expect("lookup has authorization fixture");
    let fixture = journey
        .authorizations
        .get(fixture_id)
        .expect("authorization fixture resolves");
    let token = harness.token(fixture_id, fixture);

    for (uri, capability_pointer) in [
        ("/v2", "/capabilities/0"),
        ("/v2/resources", "/items/0/capabilities/0"),
        ("/v2/resources/assistance-enrolment", "/data/capabilities/0"),
    ] {
        let response = harness
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header(AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("metadata request builds"),
            )
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::OK, "{uri} status");
        assert_eq!(
            response
                .headers()
                .get(CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store"),
            "{uri} cache policy"
        );
        assert!(!response.headers().contains_key(ETAG), "{uri} omits ETag");
        let document: Value = serde_json::from_slice(
            &to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("metadata body reads"),
        )
        .expect("metadata is JSON");
        let capability = document
            .pointer(capability_pointer)
            .and_then(Value::as_object)
            .expect("visible capability is linked");
        for reference in [
            "schemaReference",
            "semanticModelReference",
            "contextReference",
            "processingReference",
        ] {
            assert!(
                capability.get(reference).and_then(Value::as_str).is_some(),
                "{uri} exposes {reference}"
            );
        }
        assert!(
            !capability.contains_key("classificationReference"),
            "operator-only classification metadata stays undiscoverable"
        );
        assert!(
            capability["processingReference"]
                .as_str()
                .is_some_and(|reference| reference.ends_with(
                    "/v2/artifacts/assistance-enrolment--lookup-by-case-and-person--access-profile-limited-processing"
                )),
            "processing metadata link resolves to the mounted artifact identifier"
        );
    }
}

#[tokio::test]
async fn invalid_bearer_on_unknown_data_routes_is_audited_fail_closed() {
    let sink = Arc::new(ControlledAuditSink::new(usize::MAX));
    let harness = ProjectHarness::open_with_audit(
        "civil-event",
        Some(Arc::clone(&sink) as Arc<dyn AuditSink>),
    )
    .await;
    for (method, uri) in [
        (Method::GET, "/v2/resources/unknown/records"),
        (Method::GET, "/v2/resources/civil-event/records"),
        (Method::GET, "/v2/resources/unknown/records/record"),
        (
            Method::GET,
            "/v2/resources/civil-event/records/EVENT-SYNTH-0001",
        ),
        (Method::POST, "/v2/resources/unknown/lookups/unknown"),
        (
            Method::POST,
            "/v2/resources/civil-event/lookups/verify-registration",
        ),
    ] {
        let response = harness
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header(AUTHORIZATION, "Bearer malformed")
                    .body(Body::empty())
                    .expect("unknown request builds"),
            )
            .await
            .expect("router responds");
        assert_problem_code(
            response,
            StatusCode::UNAUTHORIZED,
            "auth.invalid_credential",
        )
        .await;
    }
    assert_eq!(
        sink.writes(),
        6,
        "each invalid credential is refused in audit"
    );
    let records = sink.values();
    assert_eq!(records.len(), 6);
    for record in &records {
        assert_eq!(record["phase"], "refusal");
        assert_eq!(record["outcome"], "invalid-credential");
        assert_eq!(record["principalKind"], "unknown");
        assert!(record.get("resourceIdentifier").is_none());
        assert!(record.get("operationIdentifier").is_none());
        assert!(record.get("accessRuleRevision").is_none());
        assert_eq!(record["selectedProperties"], json!([]));
    }
    let audit_wire = serde_json::to_string(&records).expect("audit serializes");
    for hidden in ["EVENT-SYNTH-0001", "verify-registration", "malformed"] {
        assert!(!audit_wire.contains(hidden));
    }

    let failing_sink = Arc::new(ControlledAuditSink::new(1));
    let harness = ProjectHarness::open_with_audit(
        "civil-event",
        Some(Arc::clone(&failing_sink) as Arc<dyn AuditSink>),
    )
    .await;
    assert_problem_code(
        harness
            .app
            .oneshot(
                Request::builder()
                    .uri("/v2/resources/civil-event/records/EVENT-SYNTH-0001")
                    .header(AUTHORIZATION, "Bearer malformed")
                    .body(Body::empty())
                    .expect("unknown request builds"),
            )
            .await
            .expect("router responds"),
        StatusCode::SERVICE_UNAVAILABLE,
        "audit.unavailable",
    )
    .await;
    assert_eq!(failing_sink.writes(), 1);
}

#[tokio::test]
async fn insufficient_scope_and_unknown_data_surfaces_are_indistinguishable() {
    let sink = Arc::new(ControlledAuditSink::new(usize::MAX));
    let harness = ProjectHarness::open_with_audit(
        "civil-event",
        Some(Arc::clone(&sink) as Arc<dyn AuditSink>),
    )
    .await;
    let journey = project_journey("civil-event");
    let read_fixture = journey
        .authorizations
        .get("civil-registrar-ex-a")
        .expect("read fixture resolves");
    let lookup_fixture = journey
        .authorizations
        .get("civil-verifier-ex-a")
        .expect("lookup fixture resolves");
    let read_token = harness.token("civil-registrar-ex-a", read_fixture);
    let lookup_token = harness.token("civil-verifier-ex-a", lookup_fixture);

    for (token, method, known, unknown) in [
        (
            lookup_token.as_str(),
            Method::GET,
            "/v2/resources/civil-event/records/EVENT-SYNTH-0001",
            "/v2/resources/unknown/records/EVENT-SYNTH-0001",
        ),
        (
            read_token.as_str(),
            Method::POST,
            "/v2/resources/civil-event/lookups/verify-registration",
            "/v2/resources/civil-event/lookups/unknown",
        ),
        (
            lookup_token.as_str(),
            Method::GET,
            "/v2/resources/civil-event/records",
            "/v2/resources/unknown/records",
        ),
    ] {
        let mut normalized = None;
        for uri in [known, unknown] {
            let response = harness
                .app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method.clone())
                        .uri(uri)
                        .header(AUTHORIZATION, format!("Bearer {token}"))
                        .body(Body::empty())
                        .expect("data request builds"),
                )
                .await
                .expect("router responds");
            let mut body = response_body(response, StatusCode::NOT_FOUND).await;
            assert_eq!(body["code"], "resource.not_found");
            body.as_object_mut()
                .expect("problem object")
                .remove("traceId");
            if let Some(expected) = &normalized {
                assert_eq!(&body, expected);
            } else {
                normalized = Some(body);
            }
        }
    }

    let padding = "x".repeat(20_000);
    let oversized_known = format!("/v2/resources/civil-event/records?padding={padding}");
    let oversized_unknown = format!("/v2/resources/unknown/records?padding={padding}");
    let mut normalized = None;
    for uri in [&oversized_known, &oversized_unknown] {
        let response = harness
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header(AUTHORIZATION, format!("Bearer {lookup_token}"))
                    .body(Body::empty())
                    .expect("oversized list request builds"),
            )
            .await
            .expect("router responds");
        let mut body = response_body(response, StatusCode::NOT_FOUND).await;
        assert_eq!(body["code"], "resource.not_found");
        body.as_object_mut()
            .expect("problem object")
            .remove("traceId");
        if let Some(expected) = &normalized {
            assert_eq!(&body, expected);
        } else {
            normalized = Some(body);
        }
    }

    let records = sink.values();
    assert_eq!(records.len(), 8);
    for record in &records {
        assert_eq!(record["phase"], "refusal");
        assert_eq!(record["outcome"], "not-found");
        assert_eq!(record["principalKind"], "authenticated");
        assert!(record.get("resourceIdentifier").is_none());
        assert!(record.get("operationIdentifier").is_none());
        assert!(record.get("accessRuleRevision").is_none());
        assert_eq!(record["selectedProperties"], json!([]));
    }
    let audit_wire = serde_json::to_string(&records).expect("audit serializes");
    for hidden in ["EVENT-SYNTH-0001", "verify-registration"] {
        assert!(!audit_wire.contains(hidden));
    }
}

#[tokio::test]
async fn list_uri_refusal_uses_the_resolved_access_context() {
    let sink = Arc::new(ControlledAuditSink::new(usize::MAX));
    let harness = ProjectHarness::open_with_audit(
        "business-registry",
        Some(Arc::clone(&sink) as Arc<dyn AuditSink>),
    )
    .await;
    let padding = "x".repeat(20_000);
    let response = harness
        .app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v2/resources/registered-business/records?padding={padding}"
                ))
                .body(Body::empty())
                .expect("oversized business list request builds"),
        )
        .await
        .expect("router responds");
    assert_problem_code(response, StatusCode::URI_TOO_LONG, "internal.uri_too_long").await;

    let records = sink.values();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["phase"], "refusal");
    assert_eq!(records[0]["outcome"], "invalid-request");
    assert_eq!(records[0]["principalKind"], "anonymous");
    assert_eq!(records[0]["resourceIdentifier"], "registered-business");
    assert_eq!(
        records[0]["operationIdentifier"],
        "registered-business.list"
    );
    assert_eq!(records[0]["selectedProperties"], json!([]));
}

#[tokio::test]
async fn lookup_body_collection_obeys_the_request_deadline() {
    let harness = ProjectHarness::open("social-assistance").await;
    let journey = project_journey("social-assistance");
    let step = journey
        .steps
        .iter()
        .find(|step| step.id == "lookup-success")
        .expect("protected lookup journey exists");
    let fixture_id = step
        .authorization_fixture
        .as_deref()
        .expect("lookup has authorization fixture");
    let fixture = journey
        .authorizations
        .get(fixture_id)
        .expect("authorization fixture resolves");
    let token = harness.token(fixture_id, fixture);
    let pending = stream::pending::<Result<Bytes, Infallible>>();
    let request = Request::builder()
        .method(Method::POST)
        .uri(&step.request.path)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from_stream(pending))
        .expect("pending lookup request builds");

    let response = tokio::time::timeout(
        Duration::from_millis(
            harness
                .runtime
                .limits
                .request_timeout_milliseconds
                .saturating_add(1_000),
        ),
        harness.app.oneshot(request),
    )
    .await
    .expect("router enforces its shorter request deadline")
    .expect("router responds");
    assert_problem_code(response, StatusCode::GATEWAY_TIMEOUT, "internal.timeout").await;
}

fn request_with_bearer(
    harness: &ProjectHarness,
    step: &JourneyStep,
    authorizations: &BTreeMap<String, AuthorizationFixture>,
    token: &str,
) -> Request<Body> {
    let mut request = harness.request(step, authorizations);
    request.headers_mut().insert(
        AUTHORIZATION,
        format!("Bearer {token}").parse().expect("bearer header"),
    );
    request
}

async fn assert_problem_code(response: http::Response<Body>, status: StatusCode, code: &str) {
    let body = response_body(response, status).await;
    assert_eq!(body.get("code").and_then(Value::as_str), Some(code));
}

async fn response_body(response: http::Response<Body>, status: StatusCode) -> Value {
    assert_eq!(response.status(), status);
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body reads");
    serde_json::from_slice(&bytes).expect("response is JSON")
}

fn decode_fixture_response(headers: &HeaderMap, body: &[u8]) -> Value {
    let media_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if media_type.starts_with("application/vnd.sdmx.data+csv") {
        let mut reader = csv::ReaderBuilder::new().from_reader(body);
        let headers = reader
            .headers()
            .expect("SDMX CSV header parses")
            .iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let rows = reader
            .records()
            .map(|record| {
                let record = record.expect("SDMX CSV row parses");
                headers
                    .iter()
                    .zip(record.iter())
                    .skip(3)
                    .map(|(component, value)| (component.clone(), Value::String(value.to_owned())))
                    .collect::<serde_json::Map<_, _>>()
            })
            .collect::<Vec<_>>();
        return json!({"__fixtureSdmxRows": rows});
    }
    serde_json::from_slice(body).expect("fixture response is JSON")
}

fn sdmx_observation_rows(document: &Value) -> Option<Vec<BTreeMap<String, Value>>> {
    if let Some(rows) = document.get("__fixtureSdmxRows").and_then(Value::as_array) {
        return rows
            .iter()
            .map(|row| {
                row.as_object().map(|row| {
                    row.iter()
                        .map(|(component, value)| (component.clone(), value.clone()))
                        .collect()
                })
            })
            .collect();
    }

    let data_set = document.pointer("/data/dataSets/0")?;
    let structure = document.pointer("/data/structures/0")?;
    let series_dimensions = structure
        .pointer("/dimensions/series")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let observation_dimensions = structure
        .pointer("/dimensions/observation")
        .and_then(Value::as_array)?;
    let measures = structure
        .pointer("/measures/observation")
        .and_then(Value::as_array)?;
    let attributes = structure
        .pointer("/attributes/observation")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let mut rows = Vec::new();

    if let Some(observations) = data_set.get("observations").and_then(Value::as_object) {
        for (key, values) in observations {
            let mut row = decode_sdmx_dimensions(observation_dimensions, key)?;
            decode_sdmx_observation_values(&mut row, measures, attributes, values)?;
            rows.push(row);
        }
    } else {
        for (series_key, series) in data_set.get("series")?.as_object()? {
            let series_values = decode_sdmx_dimensions(series_dimensions, series_key)?;
            for (observation_key, values) in series.get("observations")?.as_object()? {
                let mut row = series_values.clone();
                row.extend(decode_sdmx_dimensions(
                    observation_dimensions,
                    observation_key,
                )?);
                decode_sdmx_observation_values(&mut row, measures, attributes, values)?;
                rows.push(row);
            }
        }
    }
    Some(rows)
}

fn decode_sdmx_dimensions(dimensions: &[Value], key: &str) -> Option<BTreeMap<String, Value>> {
    let indexes = if dimensions.is_empty() {
        Vec::new()
    } else {
        key.split(':')
            .map(str::parse::<usize>)
            .collect::<Result<Vec<_>, _>>()
            .ok()?
    };
    if indexes.len() != dimensions.len() {
        return None;
    }
    dimensions
        .iter()
        .zip(indexes)
        .map(|(dimension, index)| {
            let id = dimension.get("id")?.as_str()?.to_owned();
            let value = sdmx_indexed_value(dimension, index)?;
            Some((id, value))
        })
        .collect()
}

fn decode_sdmx_observation_values(
    row: &mut BTreeMap<String, Value>,
    measures: &[Value],
    attributes: &[Value],
    values: &Value,
) -> Option<()> {
    let values = values.as_array()?;
    if values.len() != measures.len().saturating_add(attributes.len()) {
        return None;
    }
    for (index, measure) in measures.iter().enumerate() {
        row.insert(
            measure.get("id")?.as_str()?.to_owned(),
            values[index].clone(),
        );
    }
    for (index, attribute) in attributes.iter().enumerate() {
        let value = &values[measures.len() + index];
        let value = if attribute.get("values").is_some() {
            let code_index = usize::try_from(value.as_u64()?).ok()?;
            sdmx_indexed_value(attribute, code_index)?
        } else {
            value.clone()
        };
        row.insert(attribute.get("id")?.as_str()?.to_owned(), value);
    }
    Some(())
}

fn sdmx_indexed_value(component: &Value, index: usize) -> Option<Value> {
    let value = component.get("values")?.as_array()?.get(index)?;
    value.get("id").or_else(|| value.get("value")).cloned()
}

fn normalized_fixture_response(document: &Value) -> Value {
    let Some(rows) = sdmx_observation_rows(document) else {
        return Value::Array(normalized_records(document));
    };
    let mut rows = rows
        .into_iter()
        .map(|row| {
            Value::Object(
                row.into_iter()
                    .map(|(component, value)| {
                        let value = match value {
                            Value::String(value) => value,
                            Value::Number(value) => value.to_string(),
                            Value::Bool(value) => value.to_string(),
                            Value::Null => String::new(),
                            Value::Array(_) | Value::Object(_) => {
                                serde_json::to_string(&value).expect("SDMX value serializes")
                            }
                        };
                        (component, Value::String(value))
                    })
                    .collect(),
            )
        })
        .collect::<Vec<_>>();
    rows.sort_by_key(|row| serde_json::to_string(row).expect("normalized SDMX row serializes"));
    Value::Array(rows)
}

fn assert_expectations(
    project: &str,
    step: &JourneyStep,
    headers: &HeaderMap,
    body: &[u8],
    equivalence_classes: &mut BTreeMap<String, Value>,
) {
    let label = format!("{project}/{}", step.id);
    if step.expect.body_empty.unwrap_or(false) {
        assert!(body.is_empty(), "{label} body must be empty");
        return;
    }
    let document = decode_fixture_response(headers, body);
    if let Some(expected) = &step.expect.media_type {
        assert_eq!(
            headers
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some(expected.as_str()),
            "{label} media type"
        );
    }
    if let Some(code) = &step.expect.code {
        assert_eq!(
            document.get("code").and_then(Value::as_str),
            Some(code.as_str()),
            "{label} code"
        );
    }
    if step.expect.route_absent.unwrap_or(false) {
        assert_eq!(
            document.get("code").and_then(Value::as_str),
            Some("resource.not_found"),
            "{label} absent route must not disclose operation state"
        );
    }
    if !step.expect.capability_patterns.is_empty()
        || !step.expect.absent_capability_patterns.is_empty()
    {
        let patterns = document
            .get("capabilities")
            .and_then(Value::as_array)
            .expect("capabilities array")
            .iter()
            .filter_map(|capability| {
                Some(format!(
                    "{}.{}",
                    capability.get("family")?.as_str()?,
                    capability.get("pattern")?.as_str()?
                ))
            })
            .collect::<BTreeSet<_>>();
        for expected in &step.expect.capability_patterns {
            assert!(
                patterns.contains(expected),
                "{label} missing capability {expected}"
            );
        }
        for absent in &step.expect.absent_capability_patterns {
            assert!(
                !patterns.contains(absent),
                "{label} exposed forbidden capability {absent}"
            );
        }
    }
    if let Some(count) = step.expect.item_count {
        assert_eq!(
            document
                .get("items")
                .or_else(|| document.get("features"))
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(count as usize),
            "{label} item count"
        );
    }
    if let Some(count) = step.expect.observation_count {
        assert_eq!(
            sdmx_observation_rows(&document).map(|rows| rows.len()),
            Some(count as usize),
            "{label} observation count"
        );
    }
    if let Some(expected) = &step.expect.sdmx_json_types {
        let rows = sdmx_observation_rows(&document)
            .unwrap_or_else(|| panic!("{label} must contain SDMX observations"));
        for (role, components) in [
            ("dimension", &expected.dimensions),
            ("measure", &expected.measures),
            ("attribute", &expected.attributes),
        ] {
            for (component, expected_type) in components {
                for row in &rows {
                    let value = row.get(component).unwrap_or_else(|| {
                        panic!(
                            "{label} {role} {component} must exist in every observation; decoded components: {:?}",
                            row.keys().collect::<Vec<_>>()
                        )
                    });
                    let matches = match expected_type {
                        FixtureJsonScalarType::String => value.is_string(),
                        FixtureJsonScalarType::Number => value.is_number(),
                        FixtureJsonScalarType::Boolean => value.is_boolean(),
                    };
                    assert!(
                        matches,
                        "{label} {role} {component} has the authored JSON scalar type"
                    );
                }
            }
        }
    }
    if let Some(expectation) = &step.expect.next_cursor {
        let cursor = document.pointer("/pageInfo/nextCursor");
        match expectation.as_str() {
            Some("non-null") => assert!(
                cursor.is_some_and(|value| !value.is_null()),
                "{label} cursor"
            ),
            Some("null") => assert!(cursor.is_some_and(Value::is_null), "{label} cursor"),
            Some(value) => panic!("{label} has unsupported nextCursor expectation {value}"),
            None => panic!("{label} nextCursor expectation must be a string"),
        }
    }
    let records = response_records(&document);
    if step.expect.registry_core_required.unwrap_or(false) {
        assert!(!records.is_empty(), "{label} must contain a Record");
        let registry_record_envelope = headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value.starts_with("application/json") || value.starts_with("application/ld+json")
            });
        if registry_record_envelope {
            for key in [
                "registryIdentifier",
                "datasetIdentifier",
                "entityTypeIdentifier",
            ] {
                assert!(
                    document["meta"].get(key).is_some(),
                    "{label} meta is missing {key}"
                );
            }
        }
        for record in &records {
            for key in [
                "recordIdentifier",
                "revisionIdentifier",
                "lifecycleState",
                "schemaReference",
                "semanticModelReference",
                "authorityIdentifier",
                "recordedAt",
                "domainData",
            ] {
                assert!(record.get(key).is_some(), "{label} Record is missing {key}");
            }
            if registry_record_envelope {
                for key in [
                    "registryIdentifier",
                    "datasetIdentifier",
                    "entityTypeIdentifier",
                ] {
                    assert!(
                        record.get(key).is_none(),
                        "{label} Record duplicates response context {key}"
                    );
                }
            } else {
                assert!(
                    record.get("registryIdentifier").is_some(),
                    "{label} GeoJSON Record keeps its separate Registry identity"
                );
            }
        }
    }
    if !step.expect.domain_data_keys.is_empty() {
        assert!(!records.is_empty(), "{label} must contain domain data");
        let expected = step
            .expect
            .domain_data_keys
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        for record in &records {
            let actual = record
                .get("domainData")
                .and_then(Value::as_object)
                .expect("domainData object")
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            assert_eq!(actual, expected, "{label} disclosed domain properties");
        }
    }
    if !step.expect.domain_data_values.is_empty() {
        assert!(
            step.expect.domain_data_values.len() <= 64,
            "{label} has too many exact domain-value expectations"
        );
        assert!(!records.is_empty(), "{label} must contain domain data");
        for (property, expected) in &step.expect.domain_data_values {
            assert!(
                property.len() <= 128,
                "{label} has an overlong domain-value expectation name"
            );
            assert!(
                matches!(
                    expected,
                    Value::Bool(_) | Value::Number(_) | Value::String(_)
                ),
                "{label} domain-value expectations must be non-null JSON scalars"
            );
            assert!(
                step.expect.domain_data_keys.contains(property),
                "{label} exact domain-value expectation must be closed by domainDataKeys"
            );
            for record in &records {
                let actual = record
                    .get("domainData")
                    .and_then(Value::as_object)
                    .and_then(|domain| domain.get(property));
                assert!(
                    actual == Some(expected),
                    "{label} returned the wrong governed value for {property}"
                );
            }
        }
    }
    if let Some(identifier) = &step.expect.record_identifier {
        assert_eq!(
            response_records(&document)
                .first()
                .and_then(|record| record.get("recordIdentifier"))
                .and_then(Value::as_str),
            Some(identifier.as_str()),
            "{label} record identifier"
        );
    }
    if let Some(root) = step.expect.geo_json_root {
        let expected = match root {
            FixtureGeoJsonRoot::Feature => "Feature",
            FixtureGeoJsonRoot::FeatureCollection => "FeatureCollection",
        };
        assert_eq!(
            document.get("type").and_then(Value::as_str),
            Some(expected),
            "{label} GeoJSON root"
        );
    }
    if let Some(expected) = step.expect.geometry_type {
        let features = geojson_features(&document);
        assert!(
            !features.is_empty(),
            "{label} must contain a GeoJSON Feature"
        );
        for feature in features {
            let geometry = feature.get("geometry").expect("Feature carries geometry");
            match expected {
                FixtureGeometryType::Point => {
                    assert_eq!(geometry.get("type").and_then(Value::as_str), Some("Point"));
                    assert_eq!(
                        geometry
                            .get("coordinates")
                            .and_then(Value::as_array)
                            .map(Vec::len),
                        Some(2),
                        "{label} Point has CRS84 longitude-latitude coordinates"
                    );
                }
                FixtureGeometryType::Null => {
                    assert!(geometry.is_null(), "{label} geometry must be null");
                }
            }
        }
    }
    if let Some(profile) = step.expect.format_profile {
        assert_eq!(
            headers
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/geo+json"),
            "{label} spatial profile media type"
        );
        let (profile_uri, json_fg) = match profile {
            FixtureFormatProfile::Rfc7946 => (RFC7946_PROFILE_URI, false),
            FixtureFormatProfile::Jsonfg => (JSON_FG_PROFILE_URI, true),
        };
        assert_eq!(
            headers.get(LINK).and_then(|value| value.to_str().ok()),
            Some(format!("<{profile_uri}>; rel=\"profile\"").as_str()),
            "{label} spatial profile link"
        );
        for member in ["conformsTo", "featureType", "coordRefSys"] {
            assert_eq!(
                document.get(member).is_some(),
                json_fg,
                "{label} JSON-FG root member {member}"
            );
        }
        if json_fg {
            assert_eq!(document["coordRefSys"], CRS84_URI, "{label} CRS");
            for feature in geojson_features(&document) {
                for member in ["conformsTo", "featureType", "coordRefSys"] {
                    assert!(
                        feature.get(member).is_none(),
                        "{label} collection Feature repeats root-only member {member}"
                    );
                }
            }
        }
    }
    if let Some(cache) = &step.expect.cache {
        match cache.as_str() {
            "public-snapshot-revalidation" => {
                assert_eq!(
                    headers
                        .get(CACHE_CONTROL)
                        .and_then(|value| value.to_str().ok()),
                    Some("public, no-cache"),
                    "{label} cache-control"
                );
                assert!(headers.contains_key(ETAG), "{label} requires an ETag");
                assert_eq!(
                    headers.get(VARY).and_then(|value| value.to_str().ok()),
                    Some("Accept, Authorization"),
                    "{label} vary"
                );
            }
            "no-store" => {
                assert_eq!(
                    headers
                        .get(CACHE_CONTROL)
                        .and_then(|value| value.to_str().ok()),
                    Some("no-store"),
                    "{label} cache-control"
                );
                assert!(!headers.contains_key(ETAG), "{label} omits an ETag");
            }
            unsupported => panic!("{label} has unsupported cache expectation {unsupported}"),
        }
    }
    let body_text = String::from_utf8_lossy(body);
    for absent in &step.expect.absent_everywhere {
        assert!(
            !body_text.contains(absent),
            "{label} disclosed forbidden term {absent}"
        );
    }
    if let Some(class) = &step.expect.equivalence_class {
        let mut normalized = document;
        normalized
            .as_object_mut()
            .expect("problem object")
            .remove("traceId");
        if let Some(existing) = equivalence_classes.get(class) {
            assert_eq!(
                &normalized, existing,
                "{label} changed equivalence-class problem"
            );
        } else {
            equivalence_classes.insert(class.clone(), normalized);
        }
    }
}

fn normalized_records(document: &Value) -> Vec<Value> {
    response_records(document)
        .into_iter()
        .map(|record| {
            let mut record = record.clone();
            if let Some(object) = record.as_object_mut() {
                object.remove("@id");
                object.remove("@type");
                object.remove("registryIdentifier");
                if let Some(domain) = object.get_mut("domainData").and_then(Value::as_object_mut) {
                    domain.retain(|_, value| {
                        value.get("type").and_then(Value::as_str) != Some("Point")
                            || value.get("coordinates").and_then(Value::as_array).is_none()
                    });
                }
            }
            record
        })
        .collect()
}

fn response_records(document: &Value) -> Vec<&Value> {
    if let Some(record) = document.get("data") {
        vec![record]
    } else if let Some(items) = document.get("items").and_then(Value::as_array) {
        items.iter().collect()
    } else {
        geojson_features(document)
            .into_iter()
            .filter_map(|feature| feature.get("properties"))
            .collect()
    }
}

fn geojson_features(document: &Value) -> Vec<&Value> {
    if document.get("type").and_then(Value::as_str) == Some("Feature") {
        vec![document]
    } else {
        document
            .get("features")
            .and_then(Value::as_array)
            .map_or_else(Vec::new, |items| items.iter().collect())
    }
}

fn validate_response_contracts(
    harness: &ProjectHarness,
    project: &str,
    step: &JourneyStep,
    headers: &HeaderMap,
    document: &Value,
    coverage: &mut ResponseContractCoverage,
) {
    let records = response_records(document);
    if records.is_empty() {
        return;
    }
    let media_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .expect("Record response has a content type");
    let json_ld = match media_type {
        "application/json" => false,
        "application/ld+json" => true,
        "application/geo+json" => return,
        "application/vnd.sdmx.structure+json" | "application/vnd.sdmx.data+json" => return,
        _ => panic!(
            "{project}/{} returned an unsupported Record media type",
            step.id
        ),
    };

    let operation_identifier = document
        .pointer("/meta/operationIdentifier")
        .and_then(Value::as_str)
        .expect("Record response names its compiled operation");
    let access_profile_identifier = document
        .pointer("/meta/accessProfile")
        .and_then(Value::as_str)
        .expect("Record response names its selected access profile");
    let matching_bindings = harness
        .service
        .artifacts
        .operation_bindings
        .iter()
        .filter(|binding| {
            binding.operation_identifier == operation_identifier
                && binding.access_profile_identifier == access_profile_identifier
        })
        .collect::<Vec<_>>();
    assert_eq!(
        matching_bindings.len(),
        1,
        "{project}/{} must resolve one exact operation and access profile binding",
        step.id
    );
    let binding = matching_bindings[0];
    let resource = harness
        .service
        .registry
        .resources
        .iter()
        .find(|resource| {
            resource
                .operations
                .iter()
                .any(|operation| operation.identifier == binding.operation_identifier)
        })
        .expect("compiled operation belongs to one resource");
    assert_eq!(
        document
            .pointer("/meta/registryIdentifier")
            .and_then(Value::as_str),
        Some(harness.service.registry.registry_identifier.as_str())
    );
    assert_eq!(
        document
            .pointer("/meta/datasetIdentifier")
            .and_then(Value::as_str),
        Some(resource.dataset_identifier.as_str())
    );
    assert_eq!(
        document
            .pointer("/meta/entityTypeIdentifier")
            .and_then(Value::as_str),
        Some(resource.entity_type_identifier.as_str())
    );
    let expected_link = format!(
        "<{REGISTRY_RECORD_PROFILE_ID}>; rel=\"profile\", <{RELAY_PROFILE_ID}>; rel=\"profile\""
    );
    assert_eq!(
        headers.get(LINK).and_then(|value| value.to_str().ok()),
        Some(expected_link.as_str())
    );

    for record in records {
        let schema_reference = record
            .get("schemaReference")
            .and_then(Value::as_str)
            .expect("Record carries its exact permitted-access profile schema reference");
        assert_eq!(
            document
                .pointer("/meta/links/schema")
                .and_then(Value::as_str),
            Some(schema_reference),
            "{project}/{} metadata and Record must name the same schema",
            step.id
        );

        let matching_schemas = harness
            .service
            .artifacts
            .artifacts
            .iter()
            .filter(|artifact| artifact.media_type == "application/schema+json")
            .filter_map(|artifact| {
                let schema: Value = serde_json::from_slice(&artifact.content).ok()?;
                (schema.get("$id").and_then(Value::as_str) == Some(schema_reference))
                    .then_some((artifact, schema))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            matching_schemas.len(),
            1,
            "{project}/{} must resolve exactly one generated permitted-access profile schema",
            step.id
        );
        let (schema_artifact, schema) = &matching_schemas[0];
        let validator = JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .should_validate_formats(true)
            .compile(schema)
            .unwrap_or_else(|_| {
                panic!(
                    "{project}/{} generated permitted-access profile schema must compile",
                    step.id
                )
            });
        assert!(
            validator.is_valid(record),
            "{project}/{} Record must validate against its exact generated permitted-access profile schema",
            step.id
        );

        assert_eq!(
            binding.access_profile_schema_path, schema_artifact.path,
            "{project}/{} schema must belong to the exact operation and access profile",
            step.id
        );
        let shacl_path = &binding.access_profile_shacl_path;
        let shacl_artifact = harness
            .service
            .artifacts
            .get(shacl_path)
            .expect("the exact response binding carries its generated SHACL artifact");
        assert_eq!(shacl_artifact.media_type, "text/turtle");
        assert!(
            !shacl_artifact.content.is_empty(),
            "{project}/{} exact generated SHACL artifact must not be empty",
            step.id
        );

        if json_ld {
            coverage.json_ld_records += 1;
        } else {
            coverage.json_records += 1;
        }
    }

    if json_ld {
        validate_json_ld_graph(harness, project, step, document, binding);
    }
}

fn validate_json_ld_graph(
    harness: &ProjectHarness,
    project: &str,
    step: &JourneyStep,
    document: &Value,
    binding: &registry_relay_v2::artifacts::OperationArtifactBindings,
) {
    let resource = harness
        .service
        .registry
        .resources
        .iter()
        .find(|resource| {
            resource
                .operations
                .iter()
                .any(|operation| operation.identifier == binding.operation_identifier)
        })
        .expect("compiled operation belongs to one resource");
    let access_profile = resource
        .operations
        .iter()
        .find(|operation| operation.identifier == binding.operation_identifier)
        .and_then(|operation| {
            operation
                .access_profiles
                .iter()
                .find(|access_profile| access_profile.id == binding.access_profile_identifier)
        })
        .expect("compiled operation carries the selected access profile");
    assert_eq!(
        document.get("@context"),
        Some(&json!([
            REGISTRY_RECORD_CONTEXT_ID,
            access_profile.context_reference
        ])),
        "{project}/{} JSON-LD response must name the selected access profile context",
        step.id
    );
    assert_eq!(
        document
            .pointer("/meta/links/context")
            .and_then(Value::as_str),
        Some(access_profile.context_reference.as_str()),
        "{project}/{} response metadata must name the selected access profile context",
        step.id
    );
    let context_artifact = harness
        .service
        .artifacts
        .get(&binding.context_path)
        .expect("the exact response binding carries its generated JSON-LD context");
    let context_document: Value = serde_json::from_slice(&context_artifact.content)
        .expect("generated JSON-LD context parses");
    assert_operation_context_is_disjoint_from_shared_terms(&context_document);
    let mut quads = Vec::new();
    for record in response_records(document) {
        let mut semantic_record = Map::new();
        semantic_record.insert("@context".into(), context_document["@context"].clone());
        for field in [
            "@id",
            "@type",
            "lifecycleState",
            "schemaReference",
            "semanticModelReference",
            "authorityIdentifier",
            "recordedAt",
        ] {
            semantic_record.insert(field.into(), record[field].clone());
        }
        for (field, value) in record["domainData"]
            .as_object()
            .expect("Record domainData is an object")
        {
            semantic_record.insert(field.clone(), value.clone());
        }
        let raw = serde_json::to_string(&semantic_record)
            .expect("operation semantic projection serializes");
        let parser = JsonLdParser::new()
            .with_base_iri(&harness.service.registry.base_uri)
            .expect("Registry base IRI is valid");
        quads.extend(parser.for_slice(&raw).map(|quad| {
            quad.unwrap_or_else(|error| {
                panic!(
                    "{project}/{} generated operation context must expand its owned terms: {error}",
                    step.id
                )
            })
            .to_string()
        }));
    }
    assert!(
        !quads.is_empty(),
        "{project}/{} JSON-LD response must produce an RDF graph",
        step.id
    );

    let shacl = std::str::from_utf8(
        &harness
            .service
            .artifacts
            .get(&binding.access_profile_shacl_path)
            .expect("bound SHACL artifact exists")
            .content,
    )
    .expect("generated SHACL is UTF-8");
    assert!(shacl.contains(&format!("sh:targetClass <{}>", resource.semantic_class)));
    assert!(shacl.contains("sh:ignoredProperties ( rdf:type )"));

    for record in response_records(document) {
        let subject = record
            .get("@id")
            .and_then(Value::as_str)
            .expect("JSON-LD Record carries @id");
        assert_quad(
            &quads,
            subject,
            "http://www.w3.org/1999/02/22-rdf-syntax-ns#type",
            &format!("<{}>", resource.semantic_class),
            project,
            &step.id,
        );
        for field in [
            "schemaReference",
            "semanticModelReference",
            "authorityIdentifier",
        ] {
            let object = record[field]
                .as_str()
                .expect("Registry Core IRI is a string");
            let predicate = format!("https://id.registrystack.org/vocab/core/{field}");
            assert_quad(
                &quads,
                subject,
                &predicate,
                &format!("<{object}>"),
                project,
                &step.id,
            );
            assert!(shacl.contains(&format!("sh:path <{predicate}> ; sh:nodeKind sh:IRI")));
        }
        for (field, namespace, datatype) in [
            (
                "lifecycleState",
                "https://id.registrystack.org/vocab/core/",
                "http://www.w3.org/2001/XMLSchema#string",
            ),
            (
                "recordedAt",
                "https://id.registrystack.org/vocab/core/",
                "http://www.w3.org/2001/XMLSchema#dateTime",
            ),
        ] {
            let predicate = format!("{namespace}{field}");
            assert_typed_quad(&quads, subject, &predicate, datatype, project, &step.id);
            assert!(shacl.contains(&format!("sh:path <{predicate}> ; sh:datatype <{datatype}>")));
        }
        for field in ["recordIdentifier", "revisionIdentifier"] {
            let predicate = format!("https://id.registrystack.org/vocab/registry-record/{field}");
            assert!(shacl.contains(&format!(
                "sh:path <{predicate}> ; sh:datatype <http://www.w3.org/2001/XMLSchema#string>"
            )));
        }
        let domain_data = record["domainData"]
            .as_object()
            .expect("Record domainData is an object");
        for property_name in domain_data.keys() {
            let property = resource
                .properties
                .iter()
                .find(|property| property.name == *property_name)
                .expect("disclosed property is compiled");
            assert!(access_profile.selectable_properties.contains(property_name));
            let datatype = property.scalar_binding().map_or(
                "http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON",
                |binding| registry_relay_v2::semantics::datatype_iri(binding.data_type),
            );
            if property.point_binding().is_some() {
                assert_eq!(
                    domain_data[property_name]["type"], "Point",
                    "{project}/{} JSON-LD Point has its governed shape",
                    step.id
                );
            }
            assert_typed_quad(
                &quads,
                subject,
                &property.semantic_iri,
                datatype,
                project,
                &step.id,
            );
            assert!(shacl.contains(&format!(
                "sh:path <{}> ; sh:datatype <{datatype}>",
                property.semantic_iri
            )));
        }
    }
}

fn assert_operation_context_is_disjoint_from_shared_terms(context_document: &Value) {
    let operation_terms = context_document["@context"]
        .as_object()
        .expect("generated operation context is an object");
    for term in registry_relay_v2::semantics::REGISTRY_RECORD_SHARED_CONTEXT_TERMS {
        assert!(
            !operation_terms.contains_key(*term),
            "generated operation context must not redefine shared term {term}"
        );
    }
}

fn assert_quad(
    quads: &[String],
    subject: &str,
    predicate: &str,
    object: &str,
    project: &str,
    step: &str,
) {
    let expected = format!("<{subject}> <{predicate}> {object}");
    assert!(
        quads.iter().any(|quad| quad.contains(&expected)),
        "{project}/{step} expanded graph is missing a required IRI statement"
    );
}

fn assert_typed_quad(
    quads: &[String],
    subject: &str,
    predicate: &str,
    datatype: &str,
    project: &str,
    step: &str,
) {
    let subject_predicate = format!("<{subject}> <{predicate}>");
    let datatype_marker = format!("^^<{datatype}>");
    let plain_string = datatype == "http://www.w3.org/2001/XMLSchema#string";
    assert!(
        quads.iter().any(|quad| {
            let Some((_, object)) = quad.split_once(&subject_predicate) else {
                return false;
            };
            if plain_string {
                object.trim_start().starts_with('"')
            } else {
                object.contains(&datatype_marker)
            }
        }),
        "{project}/{step} expanded graph is missing predicate {predicate} with datatype {datatype}"
    );
}

impl ProjectHarness {
    async fn open(project: &str) -> Self {
        Self::open_with_audit(project, None).await
    }

    async fn open_with_audit(project: &str, sink: Option<Arc<dyn AuditSink>>) -> Self {
        let root = project_root(project);
        let fixture_sql = fs::read_to_string(root.join("fixture.sql")).expect("fixture SQL reads");
        Self::open_with_fixture_sql(project, fixture_sql, sink, false).await
    }

    async fn open_with_fixture_sql(
        project: &str,
        fixture_sql: String,
        sink: Option<Arc<dyn AuditSink>>,
        accept_fixture_fingerprint: bool,
    ) -> Self {
        let root = project_root(project);
        let contract_yaml = fs::read_to_string(root.join("registry.yaml")).expect("contract reads");
        let mut contract = RegistryContract::parse_yaml(&contract_yaml).expect("contract parses");
        let runtime = RelayRuntime::parse_yaml(
            &fs::read_to_string(root.join("runtime.yaml")).expect("runtime reads"),
        )
        .expect("runtime parses");
        let temp = tempfile::tempdir().expect("temporary project creates");
        let database = temp.path().join("fixture.sqlite");
        materialize_fixture(&database, &fixture_sql).expect("fixture materializes");

        let captured = CapturedSnapshot::capture(&database).expect("fixture captures");
        let catalog = inspect_schema(
            &DatabaseProfile::Snapshot(captured),
            &InspectionLimits {
                maximum_objects: 10_000,
                maximum_sql_bytes: 8 * 1024 * 1024,
                maximum_statement_steps: 1_000_000,
                timeout: Duration::from_secs(5),
            },
        )
        .expect("schema inspects");
        let observed_fingerprint = catalog.fingerprint.clone();
        let source_id = contract
            .sources
            .keys()
            .next()
            .expect("one source")
            .to_owned();
        if accept_fixture_fingerprint {
            let governed_fingerprint = contract
                .sources
                .get(&source_id)
                .expect("fixture source resolves")
                .expected_schema_fingerprint
                .clone();
            if governed_fingerprint != observed_fingerprint {
                let governed_yaml =
                    contract_yaml.replacen(&governed_fingerprint, &observed_fingerprint, 1);
                assert_ne!(governed_yaml, contract_yaml, "source fingerprint rewrites");
                contract = RegistryContract::parse_yaml(&governed_yaml)
                    .expect("fixture-governed contract parses");
            }
        }
        let observed = vec![ObservedSourceSchema {
            source: source_id.clone(),
            fingerprint: catalog.fingerprint,
            views: catalog
                .objects
                .into_iter()
                .filter(|object| object.kind == SchemaObjectKind::View)
                .map(|object| ObservedView {
                    name: object.name,
                    columns: object
                        .columns
                        .into_iter()
                        .map(|column| ObservedColumn {
                            name: column.name,
                            declared_type: column.declared_type,
                            nullable: column.nullable,
                            primary_key: column.primary_key,
                        })
                        .collect(),
                })
                .collect(),
        }];
        let mut governed = governed_files(&root, &contract);
        let inventory = compile_contract(&contract, &observed, CompileProfile::Production)
            .expect("fixture classification inventory compiles");
        let current_inventory_digest = classification_inventory_digest(&inventory)
            .expect("fixture classification inventory digests");
        if accept_fixture_fingerprint {
            let review_path = contract.classifications.provenance_ref.clone();
            let mut review = parse_classification_review_yaml(
                governed
                    .get(&review_path)
                    .expect("classification review is governed"),
            )
            .expect("classification review parses");
            review.classification_inventory_digest = current_inventory_digest.clone();
            governed.insert(
                review_path,
                render_classification_review_yaml(&review)
                    .expect("synthetic fixture review renders"),
            );
        }
        let compiled = Arc::new(
            compile_contract_with_governed_files(
                &contract,
                &observed,
                CompileProfile::Production,
                &governed,
            )
            .unwrap_or_else(|report| {
                panic!(
                    "{project} compilation failed (observed schema {observed_fingerprint}, current classification inventory {current_inventory_digest}): {report:?}"
                )
            }),
        );
        let artifacts = Arc::new(generate_artifacts(&compiled).expect("artifacts generate"));
        let sqlite = Arc::new(
            SqliteRuntime::open(
                &compiled,
                &BTreeMap::from([(
                    source_id,
                    RuntimeSourceBinding {
                        path: database.clone(),
                    },
                )]),
                SqliteRuntimeLimits {
                    request_timeout: Duration::from_millis(
                        runtime.limits.request_timeout_milliseconds,
                    ),
                    concurrent_queries: usize::try_from(runtime.limits.concurrent_queries)
                        .expect("query limit fits"),
                },
            )
            .expect("SQLite runtime opens"),
        );
        let sink: Arc<dyn AuditSink> =
            sink.unwrap_or_else(|| Arc::new(JsonlFileSink::new(temp.path().join("audit.jsonl"))));
        let chain = Arc::new(
            ChainState::bootstrap_unkeyed_dev_only(sink.as_ref())
                .await
                .expect("test audit chain starts"),
        );
        let audit = RelayAudit::new(chain, sink);

        let (authenticator, idp) = if let Some(issuer) = runtime.authentication.issuer.as_ref() {
            let idp = MockIdp::start().await;
            let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
                idp.jwks_uri(),
                JwksFetcherConfig::defaults(),
                FetchUrlPolicy::dev(),
            ));
            fetcher.ensure_key_set().await.expect("fixture JWKS loads");
            let mut config = oidc_verifier_config(idp.issuer(), vec![issuer.audience.clone()]);
            config.allowed_typ = vec!["at+jwt".into()];
            config.max_token_lifetime = Some(Duration::from_secs(3600));
            (
                Some(RelayAuthenticator::new(
                    Arc::new(TokenVerifier::new(config, fetcher)),
                    issuer.audience.clone(),
                    Duration::from_secs(30),
                )),
                Some(idp),
            )
        } else {
            (None, None)
        };
        let metadata = ServiceMetadata {
            authority: InstitutionMetadata {
                identifier: contract.registry.authority.identifier.clone(),
                name: contract.registry.authority.name.clone(),
            },
            operator: contract
                .registry
                .operator
                .as_ref()
                .map(|operator| InstitutionMetadata {
                    identifier: operator.identifier.clone(),
                    name: operator.name.clone(),
                }),
            authoritative_scope: contract.registry.authoritative_scope.clone(),
            alignment_targets: contract
                .registry
                .alignment_targets
                .iter()
                .map(|target| AlignmentMetadata {
                    name: target.name.clone(),
                    version: target.version.clone(),
                    status: target.status.clone(),
                    cfr_target: target.cfr_target.clone(),
                })
                .collect(),
        };
        let service = Arc::new(RelayService::new(
            compiled,
            artifacts,
            sqlite,
            authenticator,
            audit,
            runtime.cursor.as_ref().map(|_| {
                Arc::new(
                    registry_relay_v2::cursor::CursorKey::new(vec![0x5a; 32])
                        .expect("cursor key is valid"),
                )
            }),
            Duration::from_secs(
                runtime
                    .cursor
                    .as_ref()
                    .map_or(300, |cursor| cursor.maximum_age_seconds),
            ),
            Duration::from_millis(runtime.limits.request_timeout_milliseconds),
            runtime.quotas.as_ref().map(|quota| QuotaConfig {
                requests_per_minute: quota.requests_per_minute,
                burst: quota.burst,
            }),
            metadata,
        ));
        Self {
            app: router(Arc::clone(&service)),
            service,
            contract,
            runtime,
            database,
            idp,
            _temp: temp,
        }
    }

    fn replace_authenticator(&mut self, authenticator: RelayAuthenticator) {
        let service = Arc::new(RelayService::new(
            Arc::clone(&self.service.registry),
            Arc::clone(&self.service.artifacts),
            Arc::clone(&self.service.sqlite),
            Some(authenticator),
            self.service.audit.clone(),
            self.service.cursor_key.clone(),
            self.service.cursor_maximum_age,
            self.service.request_timeout,
            self.runtime.quotas.as_ref().map(|quota| QuotaConfig {
                requests_per_minute: quota.requests_per_minute,
                burst: quota.burst,
            }),
            self.service.metadata.clone(),
        ));
        self.app = router(Arc::clone(&service));
        self.service = service;
    }

    fn request(
        &self,
        step: &JourneyStep,
        authorizations: &BTreeMap<String, AuthorizationFixture>,
    ) -> Request<Body> {
        self.request_with_observations(step, authorizations, &BTreeMap::new(), &BTreeMap::new())
    }

    fn request_with_observations(
        &self,
        step: &JourneyStep,
        authorizations: &BTreeMap<String, AuthorizationFixture>,
        response_documents: &BTreeMap<String, Value>,
        etags: &BTreeMap<String, String>,
    ) -> Request<Body> {
        let mut url = step.request.path.clone();
        if !step.request.query.is_empty() {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            for (name, value) in &step.request.query {
                let scalar = journey_query_value(value, response_documents).unwrap_or_else(|| {
                    panic!(
                        "journey {} query {name} must be scalar, got {value:?}",
                        step.id
                    )
                });
                serializer.append_pair(name, &scalar);
            }
            url.push('?');
            url.push_str(&serializer.finish());
        }
        let method = match step.request.method {
            FixtureMethod::Get => Method::GET,
            FixtureMethod::Post => Method::POST,
        };
        let body = if step.request.body.is_empty() {
            Vec::new()
        } else {
            serde_json::to_vec(&json!({"selectors": &step.request.body})).expect("body serializes")
        };
        let mut request = Request::builder()
            .method(method)
            .uri(url)
            .body(Body::from(body))
            .expect("request builds");
        if !step.request.body.is_empty() {
            request.headers_mut().insert(
                CONTENT_TYPE,
                "application/json".parse().expect("content type"),
            );
        }
        for (name, value) in &step.request.headers {
            let value = value
                .strip_prefix("$etag:")
                .map_or_else(
                    || value.as_str(),
                    |reference| {
                        etags
                            .get(reference)
                            .unwrap_or_else(|| panic!("referenced ETag {reference} exists"))
                    },
                )
                .parse::<HeaderValue>()
                .expect("journey header value");
            request.headers_mut().insert(
                name.parse::<HeaderName>().expect("journey header name"),
                value,
            );
        }
        if let Some(fixture) = step.authorization_fixture.as_deref() {
            let definition = authorizations
                .get(fixture)
                .unwrap_or_else(|| panic!("authorization fixture {fixture} is declared"));
            let token = self.token(fixture, definition);
            request.headers_mut().insert(
                AUTHORIZATION,
                format!("Bearer {token}")
                    .parse()
                    .expect("authorization header"),
            );
        }
        request
    }

    fn token(&self, fixture: &str, definition: &AuthorizationFixture) -> String {
        let audience = &self
            .runtime
            .authentication
            .issuer
            .as_ref()
            .expect("runtime has issuer")
            .audience;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is valid")
            .as_secs();
        self.signed_token(
            fixture,
            definition,
            audience,
            now,
            now,
            now.saturating_add(900),
        )
    }

    fn signed_token(
        &self,
        fixture: &str,
        definition: &AuthorizationFixture,
        audience: &str,
        issued_at: u64,
        not_before: u64,
        expires_at: u64,
    ) -> String {
        self.signed_token_with_audience(
            fixture,
            definition,
            json!(audience),
            issued_at,
            not_before,
            expires_at,
        )
    }

    fn signed_token_with_audience(
        &self,
        fixture: &str,
        definition: &AuthorizationFixture,
        audience: Value,
        issued_at: u64,
        not_before: u64,
        expires_at: u64,
    ) -> String {
        let issuer = self
            .idp
            .as_ref()
            .expect("protected project has an IdP")
            .issuer();
        self.signed_token_with_issuer(
            &issuer,
            fixture,
            definition,
            audience,
            [issued_at, not_before, expires_at],
        )
    }

    fn signed_token_with_issuer(
        &self,
        issuer: &str,
        fixture: &str,
        definition: &AuthorizationFixture,
        audience: Value,
        validity: [u64; 3],
    ) -> String {
        let [issued_at, not_before, expires_at] = validity;
        let mut claims = serde_json::Map::new();
        claims.insert("iss".into(), json!(issuer));
        claims.insert("aud".into(), audience);
        claims.insert("sub".into(), json!(definition.principal));
        claims.insert(
            "scope".into(),
            json!(definition
                .scopes
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(" ")),
        );
        claims.insert("iat".into(), json!(issued_at));
        claims.insert("nbf".into(), json!(not_before));
        claims.insert("exp".into(), json!(expires_at));
        claims.insert(
            "jti".into(),
            json!(format!("fixture-{fixture}-{issued_at}")),
        );
        for (name, value) in &definition.claims {
            claims.insert(name.clone(), json!(value));
        }
        sign_ed25519_compact_jwt(
            fixtures::ED25519_PRIVATE_JWK,
            "at+jwt",
            "registry-platform-testing-ed25519-1",
            Value::Object(claims),
        )
    }
}

async fn assert_unready(harness: &ProjectHarness, project: &str, condition: &str) {
    assert!(
        !harness.service.is_ready().await,
        "{project} must become unready when its source is {condition}"
    );
    let response = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    let document = response_body(response, StatusCode::SERVICE_UNAVAILABLE).await;
    assert_eq!(
        document.get("code").and_then(Value::as_str),
        Some("service.not_ready")
    );
    let wire = serde_json::to_string(&document).expect("problem serializes");
    for protected in [
        project,
        condition,
        "fixture.sqlite",
        "readiness_schema_drift",
        harness.database.to_string_lossy().as_ref(),
    ] {
        assert!(
            !wire.contains(protected),
            "readiness failure disclosed protected detail"
        );
    }
}

#[cfg(unix)]
fn make_writable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("source becomes writable");
}

#[cfg(not(unix))]
fn make_writable(path: &Path) {
    let mut permissions = fs::metadata(path).expect("source metadata").permissions();
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions).expect("source becomes writable");
}

fn make_read_only(path: &Path) {
    let mut permissions = fs::metadata(path).expect("source metadata").permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions).expect("source becomes read-only");
}

fn governed_files(root: &Path, contract: &RegistryContract) -> GovernedFileSet {
    let mut paths = BTreeSet::new();
    paths.insert(contract.registry.identifier_lifecycle_policy_ref.clone());
    paths.insert(contract.classifications.provenance_ref.clone());
    let review_bytes = fs::read(root.join(&contract.classifications.provenance_ref))
        .expect("classification review reads");
    let review = parse_classification_review_yaml(&review_bytes)
        .expect("classification review strictly parses");
    paths.insert(review.rationale_ref);
    if let Some(generated) = review.generated_identification {
        paths.insert(generated.report_ref);
    }
    for alignment in &contract.semantics.alignments {
        paths.insert(alignment.profile_ref.clone());
    }
    for resource in &contract.resources {
        paths.insert(resource.record_context.lifecycle_state.codelist.clone());
        for (_, property) in resource.properties.iter() {
            if let Some(path) = property
                .scalar_binding()
                .and_then(|binding| binding.codelist.as_ref())
            {
                paths.insert(path.to_owned());
            }
        }
        for lookup in &resource.operations.lookups {
            for (_, selector) in lookup.request_body.selectors.iter() {
                if let Some(path) = &selector.codelist {
                    paths.insert(path.clone());
                }
            }
        }
        for processing in &resource.processing_descriptions {
            paths.insert(processing.legal_basis_ref.clone());
            paths.insert(processing.dpv_profile_ref.clone());
        }
    }
    for dataset in &contract.statistical_datasets {
        for (_, dimension) in dataset.dimensions.iter() {
            if let Some(path) = &dimension.vocabulary {
                paths.insert(path.clone());
            }
        }
        for (_, attribute) in dataset.attributes.iter() {
            if let Some(path) = &attribute.vocabulary {
                paths.insert(path.clone());
            }
        }
        for processing in &dataset.processing_descriptions {
            paths.insert(processing.legal_basis_ref.clone());
            paths.insert(processing.dpv_profile_ref.clone());
        }
    }
    paths
        .into_iter()
        .map(|path| {
            let content = fs::read(root.join(&path))
                .unwrap_or_else(|error| panic!("governed file {path} reads: {error}"));
            (path, content)
        })
        .collect()
}

fn project_root(project: &str) -> PathBuf {
    Path::new(ACCEPTANCE_ROOT).join(project)
}

fn project_journey(project: &str) -> Journey {
    let bytes = fs::read(project_root(project).join("expected-http.yaml")).expect("journey reads");
    let yaml = std::str::from_utf8(&bytes).expect("journey is UTF-8 YAML");
    parse_journey(yaml).expect("journey parses through the production fixture contract")
}

fn yaml_scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn journey_query_value(
    value: &Value,
    response_documents: &BTreeMap<String, Value>,
) -> Option<String> {
    match value {
        Value::String(value) => value
            .strip_prefix("$nextCursor:")
            .map(|reference| {
                response_documents
                    .get(reference)?
                    .pointer("/pageInfo/nextCursor")?
                    .as_str()
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| Some(value.clone())),
        _ => yaml_scalar(value),
    }
}
