// SPDX-License-Identifier: Apache-2.0

//! A complete gateway on a loopback port, started from an operator document.
//!
//! The harness writes the same runtime configuration an operator would, with
//! owner-only secret files, and starts the public `runtime::build` router over
//! the test authorization server and the stand-in registry. The gateway's
//! token endpoint is a counting pass-through to the authorization server, so
//! a test can prove that a refused request never reached the exchange.

#![allow(dead_code)]

use std::{
    io::Write as _,
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
};

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use registry_breg_mcp::{config::RuntimeConfig, runtime};
use registry_platform_crypto::{generate_private_jwk, GeneratedKeyAlgorithm, PrivateJwk};
use registry_platform_testing::{
    ExchangeProfile, TestActorKind, TestAuthorizationServer, TestClient,
};
use rmcp::{
    model::{CallToolRequestParams, CallToolResult},
    service::RunningService,
    transport::{
        streamable_http_client::StreamableHttpClientTransportConfig, StreamableHttpClientTransport,
    },
    RoleClient, ServiceExt as _,
};
use serde_json::{json, Map, Value};
use tempfile::TempDir;

use crate::mock_registry::MockRegistry;

pub const AUDIENCE: &str = "urn:breg:citizen-address-correction";
pub const GATEWAY: &str = "citizen-gateway";
pub const CHAT_HOST: &str = "chat-host";
pub const OTHER_HOST: &str = "other-host";
pub const ACTOR: &str = "6f1c2d8e-3b4a-4e59-9c7d-2a8b5e0f1d34";
pub const SCOPE: &str = "address-correction:self";
/// The review page base of every gateway that serves no real page.
pub const REVIEW_BASE_URL: &str = "https://review.example.test/citizen/";
pub const CITIZEN_A: &str = "synthetic-citizen-a";
pub const CITIZEN_B: &str = "synthetic-citizen-b";
pub const ADDRESS_A: &str = "c7110c06-8938-4294-bd68-7390de8e752e";
pub const ADDRESS_B: &str = "5b0a3c1e-2d4f-4a6b-8c9d-0e1f2a3b4c5d";
/// The audit hash key the harness writes; a result, log, or audit record
/// that contains it has leaked a secret.
pub const AUDIT_KEY: &str = "harness-audit-hash-key-0123456789abcdef0123456789abcdef";

/// The per-citizen and per-client token buckets the gateway starts with.
#[derive(Clone, Copy)]
pub struct Limits {
    pub per_citizen_burst: u32,
    pub per_client_burst: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            per_citizen_burst: 100,
            per_client_burst: 100,
        }
    }
}

pub struct Harness {
    pub authorization: TestAuthorizationServer,
    pub registry: MockRegistry,
    /// `http://127.0.0.1:<port>`, the gateway's origin.
    pub origin: String,
    /// The gateway's resource identifier, `<origin>/mcp`.
    pub resource: String,
    pub directory: TempDir,
    pub gateway_key: PrivateJwk,
    exchanges: Arc<AtomicUsize>,
    config_path: PathBuf,
}

impl Harness {
    pub async fn start(limits: Limits) -> Self {
        capture_logs();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("gateway listens");
        let origin = format!("http://{}", listener.local_addr().expect("gateway address"));
        let resource = format!("{origin}/mcp");
        let gateway_key = generate_private_jwk(GeneratedKeyAlgorithm::Es384).expect("key");
        let authorization = TestAuthorizationServer::builder()
            .client(
                TestClient::new(GATEWAY)
                    .with_public_jwk(gateway_key.public())
                    .with_resource(AUDIENCE)
                    // The gateway's actor token is requested for its own resource.
                    .with_resource(resource.clone())
                    .with_actor_kind(TestActorKind::Agent)
                    .with_service_subject(ACTOR),
            )
            .client(TestClient::new(CHAT_HOST).with_resource(resource.clone()))
            .client(TestClient::new(OTHER_HOST).with_resource(resource.clone()))
            .exchange_profile(ExchangeProfile::Conformant)
            .start()
            .await;
        let registry = MockRegistry::start().await;
        registry.add_address(CITIZEN_A, ADDRESS_A, "1 Harbour Road");
        registry.add_address(CITIZEN_B, ADDRESS_B, "4 Mill Street");
        let exchanges = Arc::new(AtomicUsize::new(0));
        let token_endpoint =
            counting_token_endpoint(authorization.token_endpoint(), Arc::clone(&exchanges)).await;

        let directory = tempfile::tempdir().expect("temporary directory");
        let secrets = write_secrets(directory.path(), &gateway_key);
        let document = document(&Document {
            listen: &origin["http://".len()..],
            resource: &resource,
            issuer: &authorization.issuer(),
            jwks: &authorization.jwks_uri(),
            registry: &registry.base_url,
            token_endpoint: &token_endpoint,
            review: REVIEW_BASE_URL,
            secrets: &secrets,
            audit: &directory.path().join("audit").join("audit.jsonl"),
            limits,
        });
        let config_path = directory.path().join("runtime.yaml");
        std::fs::write(&config_path, &document).expect("runtime configuration writes");
        serve(listener, &config_path).await;
        Self {
            authorization,
            registry,
            origin,
            resource,
            directory,
            gateway_key,
            exchanges,
            config_path,
        }
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// An access token the chat host holds for `citizen`, for this gateway.
    pub fn token(&self, citizen: &str) -> String {
        self.token_for(CHAT_HOST, citizen, &self.resource.clone(), now() + 300)
    }

    pub fn token_for(
        &self,
        client: &str,
        citizen: &str,
        audience: &str,
        expires_at: i64,
    ) -> String {
        self.authorization
            .issue_access_token(client, citizen, audience, SCOPE, expires_at)
    }

    /// How many requests reached the gateway's token endpoint.
    pub fn exchanges(&self) -> usize {
        self.exchanges.load(Ordering::SeqCst)
    }

    pub fn audit_text(&self) -> String {
        let directory = self.directory.path().join("audit");
        let mut text = String::new();
        for entry in std::fs::read_dir(directory).expect("audit directory reads") {
            let path = entry.expect("audit entry").path();
            if path.is_file() {
                text.push_str(&std::fs::read_to_string(path).expect("audit file reads"));
            }
        }
        text
    }

    /// The private scalar of the gateway's key, which nothing may disclose.
    pub fn gateway_key_secret(&self) -> String {
        self.gateway_key.d.clone().expect("private scalar")
    }
}

/// Load the runtime configuration at `path` and serve the gateway it
/// describes on `listener`, exactly as `breg-mcp serve` would.
pub async fn serve(listener: tokio::net::TcpListener, path: &Path) {
    let config = RuntimeConfig::load(path).expect("runtime configuration loads");
    let app = runtime::build(&config).await.expect("gateway builds");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("gateway serves");
    });
}

/// Write the gateway's private key and audit hash key as owner-only files
/// under `directory/secrets`, and return that secret root.
pub fn write_secrets(directory: &Path, gateway_key: &PrivateJwk) -> PathBuf {
    let secrets = directory.join("secrets");
    std::fs::create_dir(&secrets).expect("secrets directory");
    write_secret(&secrets, "gateway-key", &private_jwk_json(gateway_key));
    write_secret(&secrets, "audit-key", AUDIT_KEY);
    secrets
}

pub async fn connect(resource: &str, token: &str) -> RunningService<RoleClient, ()> {
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(resource.to_owned())
            .auth_header(token.to_owned()),
    );
    ().serve(transport).await.expect("the MCP client connects")
}

pub fn arguments(value: Value) -> Map<String, Value> {
    value.as_object().cloned().expect("arguments are an object")
}

pub async fn call(
    client: &RunningService<RoleClient, ()>,
    tool: &str,
    value: Value,
) -> CallToolResult {
    client
        .call_tool(CallToolRequestParams::new(tool.to_owned()).with_arguments(arguments(value)))
        .await
        .expect("the tool call completes")
}

pub fn structured(result: &CallToolResult) -> Value {
    result
        .structured_content
        .clone()
        .expect("the result is structured")
}

pub fn error_code(result: &CallToolResult) -> String {
    assert_eq!(result.is_error, Some(true), "{result:?}");
    structured(result)["error"]["code"]
        .as_str()
        .expect("error code")
        .to_owned()
}

pub fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("time fits")
}

pub fn private_jwk_json(key: &PrivateJwk) -> String {
    json!({
        "kty": key.kty,
        "kid": key.kid,
        "alg": key.alg,
        "crv": key.crv,
        "x": key.x,
        "y": key.y,
        "d": key.d,
    })
    .to_string()
}

pub fn write_secret(directory: &Path, name: &str, value: &str) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join(name))
        .expect("secret file opens");
    file.write_all(value.as_bytes()).expect("secret writes");
}

pub struct Document<'a> {
    pub listen: &'a str,
    pub resource: &'a str,
    pub issuer: &'a str,
    pub jwks: &'a str,
    pub registry: &'a str,
    pub token_endpoint: &'a str,
    /// The review page base the gateway builds each review link under.
    pub review: &'a str,
    pub secrets: &'a Path,
    pub audit: &'a Path,
    pub limits: Limits,
}

pub fn document(values: &Document<'_>) -> String {
    format!(
        r#"apiVersion: registry.registrystack.org/breg-mcp-runtime/v1alpha1
kind: BRegMcpRuntimeConfig
listener:
  bind: {listen}
  tlsTermination: development-loopback
secretProviders:
  file:
    root: {secrets}
resourceServer:
  resource: {resource}
  issuer: {issuer}
  jwks:
    kind: uri
    uri: {jwks}
  algorithms: [EdDSA]
  allowedClients: [{CHAT_HOST}]
  requiredScopes: [{SCOPE}]
registry:
  baseUrl: {registry}
  accessProfile: citizen-agent
  audience: {AUDIENCE}
  scopes: [{SCOPE}]
  requestTimeoutMilliseconds: 5000
exchange:
  tokenEndpoint: {token_endpoint}
  clientId: {GATEWAY}
  privateKeyRef: secret:file/gateway-key
  assertionAudience: {issuer}
service:
  name: Address correction
  description: Correct the postal address the registry holds for you.
  disclosure: The assistant you use will see your current address and the correction you request.
  details:
    entity: person-address
  application:
    entity: address-correction-request
    targetField: address
    ownerField: owner
  reviewBaseUrl: {review}
audit:
  path: {audit}
  hashKeyRef: secret:file/audit-key
rateLimits:
  perCitizen:
    requestsPerMinute: 1
    burst: {citizen_burst}
  perClient:
    requestsPerMinute: 1
    burst: {client_burst}
"#,
        listen = values.listen,
        secrets = values.secrets.display(),
        resource = values.resource,
        issuer = values.issuer,
        jwks = values.jwks,
        registry = values.registry,
        token_endpoint = values.token_endpoint,
        review = values.review,
        audit = values.audit.display(),
        citizen_burst = values.limits.per_citizen_burst,
        client_burst = values.limits.per_client_burst,
    )
}

#[derive(Clone)]
struct Forward {
    target: String,
    count: Arc<AtomicUsize>,
    client: reqwest::Client,
}

/// A token endpoint that counts each request and forwards it unchanged.
async fn counting_token_endpoint(target: String, count: Arc<AtomicUsize>) -> String {
    let app = Router::new()
        .route("/token", post(forward))
        .with_state(Forward {
            target,
            count,
            client: reqwest::Client::new(),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("token pass-through listens");
    let url = format!(
        "http://{}/token",
        listener.local_addr().expect("token pass-through address")
    );
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("token pass-through serves");
    });
    url
}

async fn forward(State(forward): State<Forward>, headers: HeaderMap, body: Bytes) -> Response {
    forward.count.fetch_add(1, Ordering::SeqCst);
    let mut request = forward.client.post(&forward.target).body(body);
    if let Some(content_type) = headers.get(axum::http::header::CONTENT_TYPE) {
        request = request.header(axum::http::header::CONTENT_TYPE, content_type.clone());
    }
    let Ok(response) = request.send().await else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .cloned();
    let bytes = response.bytes().await.unwrap_or_default();
    let mut answer = (status, bytes).into_response();
    if let Some(content_type) = content_type {
        answer
            .headers_mut()
            .insert(axum::http::header::CONTENT_TYPE, content_type);
    }
    answer
}

/// Everything every gateway in this test process has logged, as JSON lines.
pub fn logs() -> String {
    String::from_utf8_lossy(
        &LOGS
            .get()
            .expect("logs are captured")
            .lock()
            .expect("log buffer"),
    )
    .into_owned()
}

static LOGS: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();

#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log buffer").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Install one process-wide JSON subscriber at debug level, the most an
/// operator would plausibly enable, so a test can search everything logged.
fn capture_logs() {
    let buffer = LOGS.get_or_init(|| {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let writer = Capture(Arc::clone(&buffer));
        let installed = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("debug"))
            .json()
            .with_writer(move || writer.clone())
            .try_init();
        assert!(installed.is_ok(), "the log capture is the only subscriber");
        buffer
    });
    let _ = buffer;
}
