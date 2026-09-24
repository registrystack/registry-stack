// SPDX-License-Identifier: Apache-2.0

//! The deployment both message suites run against: an isolated schema, a
//! copy of the published starter package applied to it, the runtime's
//! message store and keyed journal, and the public router behind an
//! authenticator that accepts symmetric test tokens.
//!
//! Every suite that includes this module uses a different part of it, so
//! an item one suite leaves unused is not dead code.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use axum::body::{to_bytes, Body};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use registry_messaging::audit::AuditJournal;
use registry_messaging::auth::MessagingAuthenticator;
use registry_messaging::config::RuntimeConfig;
use registry_messaging::dispatch::Transports;
use registry_messaging::http::{router, HttpState, Readiness};
use registry_messaging::messages::{MessageService, MessageStore};
use registry_messaging::metrics::Metrics;
use registry_messaging::outbox::Publisher;
use registry_messaging::package::load_package;
use registry_messaging::providers::activate_providers;
use registry_messaging::runtime::{apply_package, message_store, migrate_from_path};
use registry_messaging::store::PostgresStore;
use registry_messaging_core::{Package, IDEMPOTENCY_KEY_HEADER};
use registry_platform_audit::AuditProfile;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifierConfig};
use serde_json::{json, Value};
use tower::ServiceExt as _;
use uuid::Uuid;

pub const ISSUER: &str = "https://identity.example.test";
pub const AUDIENCE: &str = "urn:example:messaging";
const TOKEN_SECRET: &[u8] = b"01234567890123456789012345678901";
const AUDIT_SECRET: &str = "an-audit-master-secret-of-32-bytes!";

/// The recipient, template data, and principal every test submission
/// carries. None of them may reach a log line or an audit record.
pub const RECIPIENT: &str = "ada.lovelace@example.org";
pub const PHONE: &str = "+15551234567";
pub const NAME: &str = "Ada Lovelace";
pub const OFFICE: &str = "Central Registry Office";
pub const SENDER_PRINCIPAL: &str = "case-system-principal";
pub const OTHER_SENDER_PRINCIPAL: &str = "another-case-principal";
pub const OPERATOR_PRINCIPAL: &str = "operator-1";

/// Everything a log line or an audit record must never carry.
pub fn forbidden_values() -> Vec<String> {
    vec![
        RECIPIENT.to_owned(),
        PHONE.to_owned(),
        NAME.to_owned(),
        OFFICE.to_owned(),
        SENDER_PRINCIPAL.to_owned(),
        OTHER_SENDER_PRINCIPAL.to_owned(),
        OPERATOR_PRINCIPAL.to_owned(),
        String::from_utf8(TOKEN_SECRET.to_vec()).unwrap(),
        AUDIT_SECRET.to_owned(),
        "postgres://".to_owned(),
    ]
}

/// A global subscriber that writes every operational log line, as JSON,
/// into one buffer the suite reads back.
pub fn captured_logs() -> String {
    String::from_utf8(log_buffer().lock().unwrap().clone()).unwrap()
}

fn log_buffer() -> &'static Arc<Mutex<Vec<u8>>> {
    static BUFFER: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    BUFFER.get_or_init(|| Arc::new(Mutex::new(Vec::new())))
}

#[derive(Clone)]
struct BufferWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for BufferWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn capture_logs() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let buffer = Arc::clone(log_buffer());
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || BufferWriter(Arc::clone(&buffer)))
            .finish();
        tracing::subscriber::set_global_default(subscriber).expect("one global log subscriber");
    });
}

/// One isolated schema and the secret reference that reaches it.
pub struct Isolated {
    pub schema: String,
    reference: String,
    pub admin: tokio_postgres::Client,
}

pub async fn isolated_schema() -> Isolated {
    let base = std::env::var("MESSAGING_TEST_DATABASE_URL")
        .expect("MESSAGING_TEST_DATABASE_URL names a disposable PostgreSQL test server");
    let schema = format!("messaging_{}", Uuid::new_v4().simple());
    let separator = if base.contains('?') { '&' } else { '?' };
    let scoped = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let (admin, connection) = tokio_postgres::connect(&scoped, tokio_postgres::NoTls)
        .await
        .expect("connect the messaging test database");
    tokio::spawn(async move { connection.await.expect("the messaging admin connection") });
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("an isolated messaging schema");
    let secret_name = format!("MESSAGING_SCHEMA_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    std::env::set_var(&secret_name, &scoped);
    Isolated {
        schema,
        reference: format!("secret:env/{secret_name}"),
        admin,
    }
}

fn free_port() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    listener.local_addr().expect("the bound address")
}

/// A public P-256 key (RFC 7517, appendix A.1); nothing here signs a token
/// with it. The runtime configuration needs a key source; the router the
/// suites call verifies with the symmetric test key instead.
fn static_jwks() -> String {
    json!({"keys": [{
        "kty": "EC",
        "crv": "P-256",
        "kid": "test-1",
        "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
    }]})
    .to_string()
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// A migrated schema with the starter package applied, and the runtime
/// pieces the message routes and the worker run on.
pub struct Harness {
    root: tempfile::TempDir,
    pub isolated: Isolated,
    pub config: RuntimeConfig,
    pub package: Arc<Package>,
    pub store: PostgresStore,
    pub service: Arc<MessageService>,
    pub audit: Arc<AuditJournal>,
    pub metrics: Arc<Metrics>,
    /// The transports of the providers the runtime configuration connects.
    pub transports: Arc<Transports>,
    pub app: Router,
}

impl Harness {
    pub async fn start() -> Self {
        Self::start_with(Value::Null, |_| {}).await
    }

    /// Start with `providers` as the runtime configuration's providers
    /// block, activated as the runtime activates them, after
    /// `adjust_package` has changed the package copy.
    pub async fn start_with(providers: Value, adjust_package: impl FnOnce(&Path)) -> Self {
        capture_logs();
        let isolated = isolated_schema().await;
        let root = tempfile::tempdir().expect("a runtime directory");
        let starter =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/messaging/examples/starter");
        let package_root = root.path().join("package");
        std::fs::create_dir_all(&package_root).unwrap();
        std::fs::copy(
            starter.join("messaging.yaml"),
            package_root.join("messaging.yaml"),
        )
        .unwrap();
        copy_tree(&starter.join("templates"), &package_root.join("templates"));
        copy_tree(&starter.join("providers"), &package_root.join("providers"));
        adjust_package(&package_root);
        let runtime_path =
            write_runtime(root.path(), &package_root, &isolated.reference, providers);
        migrate_from_path(&runtime_path).await.expect("migrate");
        let config = RuntimeConfig::load(&runtime_path).expect("the runtime configuration");
        apply_package(&config, true)
            .await
            .expect("apply the starter");

        let package = Arc::new(load_package(&package_root).expect("the starter").package);
        let secrets = config.secret_resolver().expect("the secret resolver");
        let store = PostgresStore::connect_runtime(&config.database, &secrets).expect("the store");
        let messages: MessageStore = message_store(&config).await.expect("the message store");
        let profile = AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(
            AUDIT_SECRET.as_bytes().to_vec(),
        ))
        .expect("the audit profile");
        let audit = Arc::new(
            AuditJournal::open(&config.audit.path, &profile)
                .await
                .expect("the audit journal"),
        );
        let service = Arc::new(MessageService::new(
            messages,
            Arc::clone(&audit),
            config.retention,
        ));
        let mut transports = Transports::new();
        let callbacks = activate_providers(
            &config,
            &config.load_package().expect("the package"),
            &secrets,
            &mut transports,
        )
        .expect("activate the configured providers");
        let transports = Arc::new(transports);
        let metrics = Arc::new(Metrics::default());
        let authenticator = Arc::new(MessagingAuthenticator::new(
            verifier(),
            keys(),
            package.access_profiles().clone(),
            false,
        ));
        let app = router(HttpState {
            authenticator,
            readiness: Readiness::Store(store.clone()),
            metrics: Arc::clone(&metrics),
            package: Arc::clone(&package),
            audit: Arc::clone(&audit),
            messages: Some(Arc::clone(&service)),
            callbacks: Arc::new(callbacks),
        });
        Self {
            root,
            isolated,
            config,
            package,
            store,
            service,
            audit,
            metrics,
            transports,
            app,
        }
    }

    pub fn runtime_path(&self) -> PathBuf {
        self.root.path().join("runtime.yaml")
    }

    /// Append every pending outbox record to the journal.
    pub async fn publish(&self) {
        let mut publisher =
            Publisher::new(self.store.clone(), Arc::clone(&self.audit)).expect("a publisher");
        while publisher.publish_pass().await.expect("a publication pass") > 0 {}
    }

    /// Every record the journal holds, across its segments, oldest first
    /// within each segment.
    pub fn journal(&self) -> Vec<Value> {
        let directory = self.config.audit.path.parent().expect("an audit directory");
        let mut files: Vec<PathBuf> = std::fs::read_dir(directory)
            .expect("the audit directory")
            .map(|entry| entry.unwrap().path())
            .collect();
        files.sort();
        files
            .iter()
            .flat_map(|file| {
                std::fs::read_to_string(file)
                    .unwrap()
                    .lines()
                    .filter(|line| !line.is_empty())
                    .map(|line| serde_json::from_str::<Value>(line).unwrap())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// The outbox records, published or not, in the order they were written.
    pub async fn outbox(&self) -> Vec<Value> {
        self.isolated
            .admin
            .query(
                "SELECT audit_record FROM messaging_audit_outbox ORDER BY recorded_seq",
                &[],
            )
            .await
            .unwrap()
            .iter()
            .map(|row| row.get(0))
            .collect()
    }

    /// Run one statement against the isolated schema as the test's admin.
    pub async fn execute(
        &self,
        statement: &str,
        parameters: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> u64 {
        self.isolated
            .admin
            .execute(statement, parameters)
            .await
            .unwrap()
    }

    pub async fn count(&self, query: &str) -> i64 {
        self.isolated
            .admin
            .query_one(query, &[])
            .await
            .unwrap()
            .get(0)
    }

    /// The dispatch state of one message.
    pub async fn state(&self, message_id: Uuid) -> String {
        self.isolated
            .admin
            .query_one(
                "SELECT state FROM messaging_dispatch_jobs WHERE message_id = $1",
                &[&message_id],
            )
            .await
            .unwrap()
            .get(0)
    }

    pub async fn submit(&self, bearer: &str, key: &str, body: &Value) -> (StatusCode, Value) {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .header(AUTHORIZATION, format!("Bearer {bearer}"))
            .header(IDEMPOTENCY_KEY_HEADER, key)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap();
        send(self.app.clone(), request).await
    }

    /// Submit `body` as the starter's sender and return the accepted id.
    pub async fn accepted(&self, body: &Value) -> Uuid {
        let (status, receipt) = self
            .submit(&sender_token(), &Uuid::new_v4().to_string(), body)
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{receipt}");
        Uuid::parse_str(receipt["id"].as_str().unwrap()).unwrap()
    }

    /// Send one request through the public router.
    pub async fn send(&self, request: Request<Body>) -> (StatusCode, Value) {
        send(self.app.clone(), request).await
    }

    pub async fn call(&self, method: &str, uri: &str, bearer: Option<&str>) -> (StatusCode, Value) {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(bearer) = bearer {
            request = request.header(AUTHORIZATION, format!("Bearer {bearer}"));
        }
        send(self.app.clone(), request.body(Body::empty()).unwrap()).await
    }
}

async fn send(app: Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 256 * 1024).await.unwrap();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, body)
}

fn write_runtime(root: &Path, package: &Path, database: &str, providers: Value) -> PathBuf {
    let jwks_name = format!("MESSAGING_JWKS_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    let audit_name = format!("MESSAGING_AUDIT_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    std::env::set_var(&jwks_name, static_jwks());
    std::env::set_var(&audit_name, AUDIT_SECRET);
    let runtime = json!({
        "apiVersion": registry_messaging_core::MESSAGING_RUNTIME_API_VERSION,
        "kind": registry_messaging_core::MESSAGING_RUNTIME_KIND,
        "package": {"root": package},
        "listener": {"bind": free_port().to_string(), "tlsTermination": "development-loopback"},
        "secretProviders": {"environment": {}},
        "database": {
            "runtimeUrlRef": database,
            "migrationUrlRef": database,
            "testOnlyPlaintext": true
        },
        "authentication": {"oidc": {
            "issuer": ISSUER,
            "audience": AUDIENCE,
            "jwksSource": {"kind": "static", "documentRef": format!("secret:env/{jwks_name}")},
            "allowedClients": ["case-system", "operations-console"]
        }},
        "audit": {
            "path": root.join("audit").join("messaging.jsonl"),
            "hashKeyRef": format!("secret:env/{audit_name}")
        }
    });
    let mut runtime = runtime;
    if !providers.is_null() {
        runtime["providers"] = providers;
    }
    let path = root.join("runtime.yaml");
    std::fs::write(&path, serde_norway::to_string(&runtime).unwrap()).unwrap();
    path
}

/// The runtime's verifier profile, with the symmetric test algorithm in
/// place of the production asymmetric pair.
fn verifier() -> TokenVerifierConfig {
    TokenVerifierConfig::access_token_profile(
        ISSUER,
        vec![AUDIENCE.to_owned()],
        vec![Algorithm::HS256],
        registry_platform_oidc::access_token_typ_set("at+jwt"),
    )
    .with_scope_claim("registry_scopes")
    .with_allowed_clients(vec![
        "case-system".to_owned(),
        "operations-console".to_owned(),
    ])
}

fn keys() -> Arc<JwksFetcher> {
    Arc::new(JwksFetcher::new_static(
        serde_json::from_value(json!({"keys": [{
            "kty": "oct",
            "kid": "test",
            "alg": "HS256",
            "use": "sig",
            "k": URL_SAFE_NO_PAD.encode(TOKEN_SECRET),
        }]}))
        .unwrap(),
        JwksFetcherConfig::defaults(),
    ))
}

/// Sign an access token, filling in the claims a real token always carries.
pub fn token(mut claims: Value) -> String {
    let now = chrono::Utc::now().timestamp();
    let object = claims.as_object_mut().unwrap();
    object.entry("iss").or_insert(json!(ISSUER));
    object.entry("aud").or_insert(json!(AUDIENCE));
    object.entry("iat").or_insert(json!(now));
    object.entry("exp").or_insert(json!(now + 300));
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("test".to_owned());
    header.typ = Some("at+jwt".to_owned());
    jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(TOKEN_SECRET)).unwrap()
}

pub fn sender_token_for(principal: &str) -> String {
    token(json!({
        "sub": principal,
        "azp": "case-system",
        "registry_scopes": "messaging:send",
        "registry_actor_kind": "service",
    }))
}

pub fn sender_token() -> String {
    sender_token_for(SENDER_PRINCIPAL)
}

pub fn operator_token() -> String {
    token(json!({
        "sub": OPERATOR_PRINCIPAL,
        "azp": "operations-console",
        "registry_scopes": "messaging:operate",
        "registry_actor_kind": "human",
    }))
}

/// An email submission through the starter's transactional profile.
pub fn email_submission() -> Value {
    json!({
        "senderProfile": "transactional",
        "to": {"email": RECIPIENT},
        "template": {"id": "appointment-reminder", "version": "1"},
        "locale": "en",
        "data": {"name": NAME, "day": "2026-10-01", "office": OFFICE},
        "correlationId": "case-42"
    })
}

/// An SMS submission through the starter's reminders-sms profile.
pub fn sms_submission() -> Value {
    json!({
        "senderProfile": "reminders-sms",
        "to": {"phone": PHONE},
        "template": {"id": "appointment-reminder-sms", "version": "1"},
        "locale": "en",
        "data": {"name": NAME, "day": "2026-10-01", "office": OFFICE}
    })
}

/// Fail naming the first forbidden value `value` carries.
pub fn assert_absent(what: &str, value: &Value) {
    if let Err(leak) =
        registry_platform_testing::assert_json_absent_strings(value, forbidden_values())
    {
        panic!("{what} carries a forbidden value: {leak:?}");
    }
}

/// Fail when any captured log line carries a forbidden value.
pub fn assert_logs_clean() {
    let logs = captured_logs();
    let mut buffer = Vec::new();
    for line in logs.lines().filter(|line| !line.is_empty()) {
        buffer.push(serde_json::from_str::<Value>(line).expect("a JSON log line"));
    }
    assert_absent("the operational log", &Value::Array(buffer));
}
