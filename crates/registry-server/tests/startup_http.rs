// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "runtime")]

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{HeaderName, HeaderValue, Request, StatusCode};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::Algorithm;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifierConfig};
use registry_server::api::{
    authenticated_router, router, HeldReadResponse, HttpService, ReadRuntimeIdentity,
    ReadServiceError, ReadinessProbe, RecordReadRequest, RecordReadService, ServiceFuture,
};
use registry_server::auth::{AuthorityClaimConfig, RegistryAuthenticator};
use registry_server::cursor::CursorCodec;
use registry_server::runtime_config::{parse_runtime_config_with_env, RuntimeConfigError};
use registry_server::startup::{
    operational_log_level, with_request_timeout_for_test, OperationalEvent, OperationalLogLevel,
    StartupError, WebhookStateTransitionCode,
};
use registry_server::{compile_project, parse_project_yaml, CompileProfile, CompiledRegistry};
use serde_json::{json, Value};
use tower::ServiceExt as _;
use zeroize::Zeroizing;

const RAW_PRINCIPAL_CANARY: &str = "rs-v1-25-raw-principal-canary";
const RECORD_ID_CANARY: &str = "aaaaaaaa-aaaa-4aaa-8aaa-rsv125canary";
const QUERY_VALUE_CANARY: &str = "rs-v1-25-query-value-canary";
const REQUEST_VALUE_CANARY: &str = "rs-v1-25-request-value-canary";
const RESPONSE_VALUE_CANARY: &str = "rs-v1-25-response-value-canary";
const SQL_CANARY: &str = "SELECT rs_v1_25_sql_canary FROM private_records";
const TOKEN_CANARY: &str = "rs-v1-25-token-canary";
const FILESYSTEM_PATH_CANARY: &str = "rs-v1-25-filesystem-path-canary";
const WEBHOOK_URL_CANARY: &str = "https://rs-v1-25-webhook.invalid/private";
const WEBHOOK_SECRET_CANARY: &str = "rs-v1-25-webhook-secret-canary";
const WEBHOOK_PAYLOAD_CANARY: &str = "rs-v1-25-webhook-payload-canary";
const UPSTREAM_DETAIL_CANARY: &str = "rs-v1-25-upstream-detail-canary";
const TRACESTATE_CANARY: &str = "registry=rs-v1-25-tracestate-canary";

const PROJECT: &str = r#"
apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: startup-http
  version: 1
  defaultLanguage: en
entities:
  - id: public-record
    route: public-records
    mutationMode: create_only
    tombstone: false
    classification: public
    fields:
      - {id: label, type: string, required: true, maxLength: 80, classification: public}
    accessProfiles:
      - id: public
        default: true
        anonymous: true
        operations: [list]
        readableFields: [label]
"#;

struct NoopRecords;

impl RecordReadService for NoopRecords {
    fn get(
        &self,
        _request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        Box::pin(async { Ok(None) })
    }

    fn list(
        &self,
        _request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<HeldReadResponse, ReadServiceError>> {
        Box::pin(async {
            HeldReadResponse::from_json(&json!({"items": []}))
                .map_err(|_| ReadServiceError::Unavailable)
        })
    }
}

struct SlowReadiness;

impl ReadinessProbe for SlowReadiness {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            true
        })
    }
}

#[tokio::test]
async fn request_timeout_returns_value_free_problem() {
    let service = Arc::new(HttpService::new(
        compiled_registry(),
        ReadRuntimeIdentity {
            package_revision: "package-startup-http".to_owned(),
            schema_fingerprint: "schema-startup-http".to_owned(),
        },
        Arc::new(NoopRecords),
        Arc::new(SlowReadiness),
        Arc::new(
            CursorCodec::new(Zeroizing::new(vec![0x45; 32]), Duration::from_secs(300))
                .expect("test cursor key is valid"),
        ),
    ));
    let app = with_request_timeout_for_test(router(service), Duration::from_millis(10));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");

    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("timeout body reads");
    let text = std::str::from_utf8(&body).expect("timeout body is utf-8");
    assert!(text.contains("request.timeout"));
    assert!(!text.contains("startup-http"));
}

#[test]
fn operational_log_level_is_a_closed_vocabulary() {
    assert_eq!(
        operational_log_level(None).expect("default log level"),
        tracing_subscriber::filter::LevelFilter::INFO
    );
    assert!(operational_log_level(Some("info")).is_ok());
    assert!(operational_log_level(Some("warn")).is_ok());
    assert!(operational_log_level(Some("error")).is_ok());
    assert!(operational_log_level(Some("debug")).is_err());
    assert!(operational_log_level(Some("registry_server=trace")).is_err());
}

#[derive(Clone, Default)]
struct CapturedOperationalLogs(Arc<Mutex<Vec<u8>>>);

impl CapturedOperationalLogs {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("operational log buffer").clone())
            .expect("operational logs are UTF-8")
    }
}

impl io::Write for CapturedOperationalLogs {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("operational log buffer poisoned"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for CapturedOperationalLogs {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

fn startup_errors() -> [StartupError; 12] {
    [
        StartupError::RuntimeConfig,
        StartupError::PackageRefused,
        StartupError::DatabaseConnection,
        StartupError::DatabaseUnready,
        StartupError::Audit,
        StartupError::Cursor,
        StartupError::Oidc,
        StartupError::Authentication,
        StartupError::EventDestinations,
        StartupError::Listener,
        StartupError::Shutdown,
        StartupError::Logging,
    ]
}

fn expected_operational_event(
    event: OperationalEvent,
) -> (
    OperationalLogLevel,
    &'static str,
    &'static str,
    Option<&'static str>,
    Option<&'static str>,
) {
    match event {
        OperationalEvent::StartupBegan => (
            OperationalLogLevel::Info,
            "registry_server::startup",
            "Registry Server startup began",
            None,
            None,
        ),
        OperationalEvent::Listening => (
            OperationalLogLevel::Info,
            "registry_server::startup",
            "Registry Server is listening",
            None,
            None,
        ),
        OperationalEvent::Stopped => (
            OperationalLogLevel::Error,
            "registry_server::startup",
            "Registry Server stopped",
            None,
            None,
        ),
        OperationalEvent::StoppedWithError(error) => (
            OperationalLogLevel::Error,
            "registry_server::startup",
            "Registry Server stopped",
            Some(expected_startup_error(error)),
            None,
        ),
        OperationalEvent::WebhookWorkerIterationFailed => (
            OperationalLogLevel::Warn,
            "registry_server::webhook",
            "webhook worker iteration failed",
            None,
            Some("webhook.worker.iteration_failed"),
        ),
        OperationalEvent::WebhookStateTransitionFailed(code) => (
            OperationalLogLevel::Warn,
            "registry_server::webhook",
            "webhook state transition failed",
            None,
            Some(expected_webhook_state_transition_code(code)),
        ),
    }
}

fn expected_startup_error(error: StartupError) -> &'static str {
    match error {
        StartupError::RuntimeConfig => "the Registry runtime configuration was refused",
        StartupError::PackageRefused => "the Registry package was refused",
        StartupError::DatabaseConnection => "the Registry database connection was refused",
        StartupError::DatabaseUnready => "the Registry database is not ready for this package",
        StartupError::Audit => "the Registry audit profile was refused",
        StartupError::Cursor => "the Registry cursor profile was refused",
        StartupError::Oidc => "the Registry OIDC key source was refused",
        StartupError::Authentication => "the Registry authentication profile was refused",
        StartupError::EventDestinations => "the Registry event destination bindings were refused",
        StartupError::Listener => "the Registry listener could not be started",
        StartupError::Shutdown => "the Registry shutdown signal failed",
        StartupError::Logging => "the Registry operational log level was refused",
    }
}

fn expected_webhook_state_transition_code(code: WebhookStateTransitionCode) -> &'static str {
    match code {
        WebhookStateTransitionCode::ClaimIdentityRefused => "webhook.claim.identity_refused",
        WebhookStateTransitionCode::ClaimRecoveryFailed => "webhook.claim.recovery_failed",
        WebhookStateTransitionCode::ClaimSelectFailed => "webhook.claim.select_failed",
        WebhookStateTransitionCode::ClaimPolicyRefused => "webhook.claim.policy_refused",
        WebhookStateTransitionCode::ClaimUpdateFailed => "webhook.claim.update_failed",
        WebhookStateTransitionCode::ClaimAuditFailed => "webhook.claim.audit_failed",
        WebhookStateTransitionCode::ClaimCommitFailed => "webhook.claim.commit_failed",
    }
}

fn operational_level_name(level: OperationalLogLevel) -> &'static str {
    match level {
        OperationalLogLevel::Info => "INFO",
        OperationalLogLevel::Warn => "WARN",
        OperationalLogLevel::Error => "ERROR",
    }
}

#[test]
fn every_operational_event_renders_exact_closed_value_free_json_fields() {
    let mut events = vec![
        OperationalEvent::StartupBegan,
        OperationalEvent::Listening,
        OperationalEvent::Stopped,
    ];
    events.extend(
        startup_errors()
            .into_iter()
            .map(OperationalEvent::StoppedWithError),
    );
    events.push(OperationalEvent::WebhookWorkerIterationFailed);
    events.extend(
        WebhookStateTransitionCode::ALL
            .into_iter()
            .map(OperationalEvent::WebhookStateTransitionFailed),
    );

    let writer = CapturedOperationalLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_target(false)
        .with_current_span(false)
        .with_span_list(false)
        .with_writer(writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        for event in &events {
            event.emit();
        }
    });

    let output = writer.text();
    assert_forbidden_values_absent(&output);
    let rendered = output
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("operational log is JSON"))
        .collect::<Vec<_>>();
    assert_eq!(rendered.len(), events.len());
    for (event, rendered) in events.into_iter().zip(rendered) {
        let expected = event.record();
        let (level, target, message, error, code) = expected_operational_event(event);
        assert_eq!(expected.level(), level);
        assert_eq!(expected.target(), target);
        assert_eq!(expected.message(), message);
        assert_eq!(expected.error(), error);
        assert_eq!(expected.code(), code);
        let object = rendered
            .as_object()
            .expect("operational log record is an object");
        assert_eq!(
            object.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            BTreeSet::from(["fields", "level", "timestamp"])
        );
        assert_eq!(rendered["level"], operational_level_name(expected.level()));
        let fields = rendered["fields"]
            .as_object()
            .expect("operational fields are an object");
        let mut expected_field_names = BTreeSet::from(["message"]);
        if expected.error().is_some() {
            expected_field_names.insert("error");
        }
        if expected.code().is_some() {
            expected_field_names.insert("code");
        }
        assert_eq!(
            fields.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            expected_field_names
        );
        assert_eq!(fields["message"], expected.message());
        assert_eq!(
            fields.get("error").and_then(Value::as_str),
            expected.error()
        );
        assert_eq!(fields.get("code").and_then(Value::as_str), expected.code());
        assert!(matches!(
            expected.target(),
            "registry_server::startup" | "registry_server::webhook"
        ));
    }
}

#[tokio::test]
async fn provenance_operational_logs_metrics_and_traces_are_separate_closed_and_value_free() {
    let directory = TestDirectory::create();
    let registry = compiled_registry();
    let registry_revision = registry.revision().to_owned();
    let service = Arc::new(HttpService::new(
        Arc::clone(&registry),
        ReadRuntimeIdentity {
            package_revision: "package-startup-http".to_owned(),
            schema_fingerprint: "schema-startup-http".to_owned(),
        },
        Arc::new(NoopRecords),
        Arc::new(SlowReadiness),
        Arc::new(
            CursorCodec::new(Zeroizing::new(vec![0x45; 32]), Duration::from_secs(300))
                .expect("test cursor key is valid"),
        ),
    ));
    let authenticator = Arc::new(
        RegistryAuthenticator::new(
            &registry,
            TokenVerifierConfig::access_token_profile(
                "https://issuer.example",
                vec!["urn:registry-server:test".to_owned()],
                vec![Algorithm::EdDSA],
                vec!["at+jwt".to_owned()],
            ),
            Arc::new(JwksFetcher::new_static(
                JwkSet { keys: Vec::new() },
                JwksFetcherConfig::defaults(),
            )),
            AuthorityClaimConfig::new("registry_principal", None, Vec::new()),
        )
        .expect("anonymous Registry has a valid production authenticator"),
    );
    let app = with_request_timeout_for_test(
        authenticated_router(service, authenticator),
        Duration::from_secs(10),
    );

    let provenance = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/registry")
                .body(Body::empty())
                .expect("provenance request builds"),
        )
        .await
        .expect("provenance response");
    assert_eq!(provenance.status(), StatusCode::OK);
    let provenance: Value = serde_json::from_slice(
        &to_bytes(provenance.into_body(), 1024 * 1024)
            .await
            .expect("provenance body reads"),
    )
    .expect("provenance body is JSON");
    assert_eq!(provenance["id"], "startup-http");
    assert_eq!(provenance["version"], "1");
    assert_eq!(provenance["revision"], registry_revision);

    let mut request = Request::builder()
        .uri(format!(
            "/v1/records/public-records?filter=label:equals:{QUERY_VALUE_CANARY}&requestValue={REQUEST_VALUE_CANARY}"
        ))
        .body(Body::from(REQUEST_VALUE_CANARY))
        .expect("canary request builds");
    for (name, value) in [
        ("authorization", format!("Bearer {TOKEN_CANARY}")),
        ("tracestate", TRACESTATE_CANARY.to_owned()),
        (
            "traceparent",
            "00-11111111111111111111111111111111-2222222222222222-01".to_owned(),
        ),
        ("x-raw-principal", RAW_PRINCIPAL_CANARY.to_owned()),
        ("x-record-id", RECORD_ID_CANARY.to_owned()),
        ("x-response-value", RESPONSE_VALUE_CANARY.to_owned()),
        ("x-sql", SQL_CANARY.to_owned()),
        ("x-webhook-url", WEBHOOK_URL_CANARY.to_owned()),
        ("x-webhook-secret", WEBHOOK_SECRET_CANARY.to_owned()),
        ("x-webhook-payload", WEBHOOK_PAYLOAD_CANARY.to_owned()),
        ("x-upstream-detail", UPSTREAM_DETAIL_CANARY.to_owned()),
    ] {
        request.headers_mut().insert(
            HeaderName::from_bytes(name.as_bytes()).expect("header name is valid"),
            HeaderValue::from_str(&value).expect("header value is valid"),
        );
    }
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("canary request responds");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().get("traceparent").is_none());
    assert!(response.headers().get("tracestate").is_none());
    let mut rendered_response = response
        .headers()
        .iter()
        .map(|(name, value)| format!("{}:{}\n", name, value.to_str().unwrap_or("<binary>")))
        .collect::<String>();
    rendered_response.push_str(
        std::str::from_utf8(
            &to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("canary response reads"),
        )
        .expect("canary response is UTF-8"),
    );
    assert_forbidden_values_absent(&rendered_response);

    for uri in ["/metrics", "/v1/metrics"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .expect("metrics request builds"),
            )
            .await
            .expect("metrics request responds");
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("metrics refusal reads");
        let body = std::str::from_utf8(&body).expect("metrics refusal is UTF-8");
        assert_forbidden_values_absent(body);
    }

    let valid_runtime = runtime_without_telemetry(directory.path());
    parse_runtime_config_with_env(&valid_runtime, |_| None)
        .expect("runtime without telemetry parses");
    for (member, expected) in [
        (
            format!("metrics:\n  labels:\n    principal: {RAW_PRINCIPAL_CANARY}\n"),
            RuntimeConfigError::Document,
        ),
        (
            format!("telemetry:\n  tracestate: {TRACESTATE_CANARY}\n"),
            RuntimeConfigError::GovernedMember,
        ),
    ] {
        let error = parse_runtime_config_with_env(&(valid_runtime.clone() + &member), |_| None)
            .expect_err("runtime telemetry authority is absent");
        assert_eq!(error, expected);
        assert_forbidden_values_absent(&format!("{error:?} {error}"));
    }

    let config_path = directory.path().join(FILESYSTEM_PATH_CANARY);
    fs::write(&config_path, canary_runtime_document()).expect("canary runtime config writes");
    let output = Command::new(env!("CARGO_BIN_EXE_registry-server"))
        .args([
            "--config",
            config_path.to_str().expect("config path is UTF-8"),
        ])
        .env("REGISTRY_SERVER_LOG", "info")
        .output()
        .expect("registry-server process runs");
    assert_eq!(output.status.code(), Some(1));
    let stdout = std::str::from_utf8(&output.stdout).expect("operational stdout is UTF-8");
    let stderr = std::str::from_utf8(&output.stderr).expect("operational stderr is UTF-8");
    let logs = format!("{stdout}{stderr}");
    assert_forbidden_values_absent(&logs);
    assert!(!logs.contains("startup-http"));
    assert!(!logs.contains(&registry_revision));
    let records = logs
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("operational log is JSON"))
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 2);
    for record in &records {
        assert_eq!(
            record
                .as_object()
                .expect("log record is an object")
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["fields", "level", "timestamp"])
        );
        let fields = record["fields"].as_object().expect("log fields are closed");
        assert!(fields
            .keys()
            .all(|field| matches!(field.as_str(), "message" | "error")));
        assert!(matches!(
            fields["message"].as_str(),
            Some("Registry Server startup began" | "Registry Server stopped")
        ));
        if let Some(error) = fields.get("error") {
            assert_eq!(error, "the Registry runtime configuration was refused");
        }
    }

    let invalid_level = Command::new(env!("CARGO_BIN_EXE_registry-server"))
        .args([
            "--config",
            config_path.to_str().expect("config path is UTF-8"),
        ])
        .env("REGISTRY_SERVER_LOG", "debug")
        .output()
        .expect("invalid log level is rendered through the production logger");
    assert_eq!(invalid_level.status.code(), Some(2));
    let invalid_logs = format!(
        "{}{}",
        std::str::from_utf8(&invalid_level.stdout).expect("operational stdout is UTF-8"),
        std::str::from_utf8(&invalid_level.stderr).expect("operational stderr is UTF-8")
    );
    assert_forbidden_values_absent(&invalid_logs);
    let invalid_records = invalid_logs
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("operational log is JSON"))
        .collect::<Vec<_>>();
    assert_eq!(invalid_records.len(), 1);
    let invalid_record = &invalid_records[0];
    assert_eq!(invalid_record["level"], "ERROR");
    assert_eq!(
        invalid_record["fields"]["message"],
        "Registry Server stopped"
    );
    assert_eq!(
        invalid_record["fields"]["error"],
        "the Registry operational log level was refused"
    );
    assert_eq!(
        invalid_record["fields"]
            .as_object()
            .expect("invalid-level fields are closed")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["error", "message"])
    );
}

struct TestDirectory {
    directory: PathBuf,
}

impl TestDirectory {
    fn create() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "registry-server-startup-http-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&directory).expect("temporary directory is created");
        Self { directory }
    }

    fn path(&self) -> &Path {
        &self.directory
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).expect("temporary directory is removed");
    }
}

fn forbidden_values() -> [&'static str; 13] {
    [
        RAW_PRINCIPAL_CANARY,
        RECORD_ID_CANARY,
        QUERY_VALUE_CANARY,
        REQUEST_VALUE_CANARY,
        RESPONSE_VALUE_CANARY,
        SQL_CANARY,
        TOKEN_CANARY,
        FILESYSTEM_PATH_CANARY,
        WEBHOOK_URL_CANARY,
        WEBHOOK_SECRET_CANARY,
        WEBHOOK_PAYLOAD_CANARY,
        UPSTREAM_DETAIL_CANARY,
        TRACESTATE_CANARY,
    ]
}

fn assert_forbidden_values_absent(text: &str) {
    for forbidden in forbidden_values() {
        assert!(!text.contains(forbidden), "forbidden value was disclosed");
    }
}

fn canary_runtime_document() -> String {
    format!(
        r#"telemetry:
  rawPrincipal: {RAW_PRINCIPAL_CANARY}
  recordId: {RECORD_ID_CANARY}
  queryValue: {QUERY_VALUE_CANARY}
  requestValue: {REQUEST_VALUE_CANARY}
  responseValue: {RESPONSE_VALUE_CANARY}
  sql: "{SQL_CANARY}"
  token: {TOKEN_CANARY}
  webhookUrl: {WEBHOOK_URL_CANARY}
  webhookSecret: {WEBHOOK_SECRET_CANARY}
  webhookPayload: {WEBHOOK_PAYLOAD_CANARY}
  upstreamDetail: {UPSTREAM_DETAIL_CANARY}
  tracestate: {TRACESTATE_CANARY}
"#
    )
}

fn runtime_without_telemetry(root: &Path) -> String {
    format!(
        r#"listener:
  bind: 127.0.0.1:8080
  trustedProxy: direct
identity:
  environment: production
  instanceId: registry-primary
  databaseId: registry-db
  databaseInitializationEnvironment: production
secretProviders:
  environment: {{}}
  file:
    root: {}
database:
  runtimeUrlRef: secret:env/REGISTRY_SERVER_RUNTIME_CONFIG_DATABASE_URL
  migrationUrlRef: secret:env/REGISTRY_SERVER_RUNTIME_CONFIG_MIGRATION_DATABASE_URL
  pool:
    maxSize: 4
    waitTimeoutMilliseconds: 1000
    createTimeoutMilliseconds: 1000
    recycleTimeoutMilliseconds: 1000
  roles:
    migration: registry_migration
    runtime: registry_runtime
package:
  root: {}
  trustAnchorPath: {}
  compilerSourceRevision: source-revision-1
  activeRevision: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  activeSequence: 1
authentication:
  oidc:
    issuer: https://issuer.example
    audience: urn:registry-server:test
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: " "
    allowedClients: [registry-client]
    deniedKids: [denied-kid]
    maxTokenLifetimeSeconds: 300
    leewayMilliseconds: 60000
    jwksCache:
      cacheTtlSeconds: 600
      negativeCacheTtlSeconds: 60
      refreshCooldownSeconds: 30
      maxDocumentBytes: 65536
      requestTimeoutMilliseconds: 5000
      outageToleranceSeconds: 900
  authorityClaims:
    principal: registry_principal
    purpose: registry_purpose
    rowBoundaryClaims:
      - {{name: jurisdiction, type: directStringSet}}
      - {{name: tenant, type: directString}}
audit:
  hashKeyRef: secret:file/audit-key
cursor:
  secretRef: secret:file/cursor-key
  maxAgeSeconds: 300
eventDestinations: {{}}
operationalTimeouts:
  httpRequestMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
  recordLockMilliseconds: 5000
  migrationLockMilliseconds: 30000
  migrationStatementMilliseconds: 60000
"#,
        root.display(),
        root.display(),
        root.join("trust-anchor.json").display()
    )
}

#[cfg(feature = "postgres-test")]
#[tokio::test]
async fn serve_returns_after_graceful_shutdown_signal() {
    use axum::routing::get;
    use registry_server::startup::{serve_until_shutdown, PreparedServer};
    use registry_server::webhook::WebhookWorkerLifecycleProbe;

    let app = axum::Router::new().route("/healthz", get(|| async { "ok" }));
    let probe = WebhookWorkerLifecycleProbe::new(false);
    let prepared = PreparedServer::from_parts_with_webhook_worker_for_test(
        "127.0.0.1:0".parse().expect("ephemeral bind parses"),
        app,
        Duration::from_secs(2),
        probe.worker(),
    );

    let result = tokio::time::timeout(
        Duration::from_secs(2),
        serve_until_shutdown(prepared, async { Ok(()) }),
    )
    .await
    .expect("server exits within test timeout");
    assert_eq!(result, Ok(()));
    assert!(probe.started());
    assert!(probe.stopped());
    assert!(!probe.running());
}

#[cfg(feature = "postgres-test")]
#[tokio::test]
async fn shutdown_signal_failure_still_stops_and_joins_the_bound_server() {
    use axum::routing::get;
    use registry_server::startup::{serve_until_shutdown, PreparedServer, StartupError};
    use registry_server::webhook::WebhookWorkerLifecycleProbe;
    use tokio::net::TcpListener;

    let reservation = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ephemeral listener reservation binds");
    let bind = reservation
        .local_addr()
        .expect("ephemeral listener address reads");
    drop(reservation);
    let app = axum::Router::new().route("/healthz", get(|| async { "ok" }));
    let probe = WebhookWorkerLifecycleProbe::new(false);
    let prepared = PreparedServer::from_parts_with_webhook_worker_for_test(
        bind,
        app,
        Duration::from_secs(2),
        probe.worker(),
    );

    let result = tokio::time::timeout(
        Duration::from_secs(2),
        serve_until_shutdown(prepared, async { Err(StartupError::Shutdown) }),
    )
    .await
    .expect("signal failure still completes bounded cleanup");
    assert_eq!(result, Err(StartupError::Shutdown));
    assert!(probe.started());
    assert!(probe.stopped());
    assert!(!probe.running());
    let rebound = TcpListener::bind(bind)
        .await
        .expect("server task no longer owns the listener after error cleanup");
    drop(rebound);
}

#[cfg(feature = "postgres-test")]
#[tokio::test]
async fn listener_bind_failure_never_starts_or_detaches_the_webhook_worker() {
    use axum::routing::get;
    use registry_server::startup::{serve_until_shutdown, PreparedServer, StartupError};
    use registry_server::webhook::WebhookWorkerLifecycleProbe;
    use tokio::net::TcpListener;

    let occupied = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("occupied listener binds");
    let bind = occupied.local_addr().expect("occupied address reads");
    let app = axum::Router::new().route("/healthz", get(|| async { "ok" }));
    let probe = WebhookWorkerLifecycleProbe::new(false);
    let prepared = PreparedServer::from_parts_with_webhook_worker_for_test(
        bind,
        app,
        Duration::from_secs(1),
        probe.worker(),
    );

    assert_eq!(
        serve_until_shutdown(prepared, async { Ok(()) }).await,
        Err(StartupError::Listener)
    );
    assert!(!probe.started());
    assert!(!probe.running());
    drop(occupied);
}

#[cfg(feature = "postgres-test")]
#[tokio::test]
async fn shutdown_timeout_aborts_and_joins_the_webhook_worker_before_returning() {
    use axum::routing::get;
    use registry_server::startup::{serve_until_shutdown, PreparedServer, StartupError};
    use registry_server::webhook::WebhookWorkerLifecycleProbe;
    use tokio::net::TcpListener;

    let reservation = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ephemeral listener reservation binds");
    let bind = reservation
        .local_addr()
        .expect("ephemeral listener address reads");
    drop(reservation);
    let app = axum::Router::new().route("/healthz", get(|| async { "ok" }));
    let probe = WebhookWorkerLifecycleProbe::new(true);
    let prepared = PreparedServer::from_parts_with_webhook_worker_for_test(
        bind,
        app,
        Duration::from_millis(25),
        probe.worker(),
    );

    assert_eq!(
        serve_until_shutdown(prepared, async { Ok(()) }).await,
        Err(StartupError::Shutdown)
    );
    assert!(probe.started());
    assert!(probe.stopped());
    assert!(!probe.running());
    let rebound = TcpListener::bind(bind)
        .await
        .expect("timeout cleanup joined the server before returning");
    drop(rebound);
}

fn compiled_registry() -> Arc<CompiledRegistry> {
    let project = parse_project_yaml(PROJECT.as_bytes()).expect("project parses");
    Arc::new(compile_project(&project, &[], CompileProfile::Authoring).expect("project compiles"))
}
