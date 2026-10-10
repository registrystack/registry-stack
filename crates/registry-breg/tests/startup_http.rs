// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "runtime")]

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{HeaderName, HeaderValue, Request, StatusCode};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::Algorithm;
use registry_breg::api::{
    authenticated_router, router, HeldReadResponse, HttpService, ReadRuntimeIdentity,
    ReadServiceError, ReadinessProbe, RecordReadRequest, RecordReadService, ServiceFuture,
    VerifiedRequestClaims,
};
use registry_breg::auth::{AuthorityClaimConfig, RegistryAuthenticator};
use registry_breg::cursor::CursorCodec;
use registry_breg::metrics::{self, Metrics};
use registry_breg::package::PackageError;
use registry_breg::postgres::{
    advise, AdvisorySeverity, BaselineAdvisory, BaselineSettings, RoleMode,
};
use registry_breg::runtime_config::{parse_runtime_config_with_env, RuntimeConfigError};
use registry_breg::startup::{
    operational_log_level, with_request_timeout_and_metrics_for_test,
    with_request_timeout_for_test, BackgroundTask, BackgroundTaskStop, OperationalEvent,
    OperationalLogLevel, StartupError, WebhookStateTransitionCode,
};
use registry_breg::{compile_project, parse_project_yaml, CompileProfile, CompiledRegistry};
use registry_platform_crypto::PrivateJwk;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifierConfig};
use registry_platform_testing::{fixtures, jwks_from_private_jwk, sign_ed25519_compact_jwt};
use serde_json::{json, Value};
use tower::ServiceExt as _;
use zeroize::Zeroizing;

const RAW_PRINCIPAL_CANARY: &str = "breg-v1-25-raw-principal-canary";
const RECORD_ID_CANARY: &str = "aaaaaaaa-aaaa-4aaa-8aaa-rsv125canary";
const QUERY_VALUE_CANARY: &str = "breg-v1-25-query-value-canary";
const REQUEST_VALUE_CANARY: &str = "breg-v1-25-request-value-canary";
const RESPONSE_VALUE_CANARY: &str = "breg-v1-25-response-value-canary";
const SQL_CANARY: &str = "SELECT breg_v1_25_sql_canary FROM private_records";
const TOKEN_CANARY: &str = "breg-v1-25-token-canary";
const FILESYSTEM_PATH_CANARY: &str = "breg-v1-25-filesystem-path-canary";
const WEBHOOK_URL_CANARY: &str = "https://breg-v1-25-webhook.invalid/private";
const WEBHOOK_SECRET_CANARY: &str = "breg-v1-25-webhook-secret-canary";
const WEBHOOK_PAYLOAD_CANARY: &str = "breg-v1-25-webhook-payload-canary";
const UPSTREAM_DETAIL_CANARY: &str = "breg-v1-25-upstream-detail-canary";
const TRACESTATE_CANARY: &str = "registry=breg-v1-25-tracestate-canary";
static TRACING_CAPTURE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const PROJECT: &str = r#"
apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: startup-http
  version: "1"
  defaultLanguage: en
  canonicalBaseIri: https://authoring.example.test
entities:
  - id: public-record
    primaryDataset: test-dataset
    route: public-records
    mutationMode: create_only
    tombstone: false
    classification: public
    fields:
      - {id: label, type: string, required: true, maxLength: 80, classification: public}
accessProfiles:
  - id: public
    default: true
    principalClaim: registry_principal
    requiredScopes: unrestricted
    permissions:
      - entity: public-record
        rowBoundaries: unrestricted
        operations: [list]
        readableFields: [label]
"#;

#[derive(Default)]
struct NoopRecords {
    correlations: Mutex<Vec<(uuid::Uuid, String)>>,
}

impl RecordReadService for NoopRecords {
    fn get(
        &self,
        _request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        Box::pin(async { Ok(None) })
    }

    fn list(
        &self,
        request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<HeldReadResponse, ReadServiceError>> {
        self.correlations
            .lock()
            .expect("correlation capture")
            .push((
                request.correlation.request_id(),
                request.correlation.trace_id().as_str().to_owned(),
            ));
        Box::pin(async {
            HeldReadResponse::from_json(&json!({"items": []}))
                .map_err(|_| ReadServiceError::Unavailable)
        })
    }

    fn lookup(
        &self,
        _request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        Box::pin(async { Ok(None) })
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
    let _request_logs = captured_request_logs();
    let service = Arc::new(HttpService::new(
        compiled_registry(),
        ReadRuntimeIdentity {
            package_revision: "package-startup-http".to_owned(),
            schema_fingerprint: "schema-startup-http".to_owned(),
        },
        Arc::new(NoopRecords::default()),
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
                .header(
                    "traceparent",
                    "00-11111111111111111111111111111111-2222222222222222-01",
                )
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");

    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let traceparent = response
        .headers()
        .get("traceparent")
        .expect("timeout response carries traceparent")
        .to_str()
        .expect("traceparent is ASCII")
        .to_owned();
    assert_eq!(
        traceparent,
        "00-11111111111111111111111111111111-2222222222222222-01"
    );
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("timeout body reads");
    let text = std::str::from_utf8(&body).expect("timeout body is utf-8");
    assert!(text.contains("request.timeout"));
    assert!(!text.contains("startup-http"));
    let problem: Value = serde_json::from_slice(&body).expect("timeout problem is JSON");
    assert_eq!(problem["traceId"], trace_id(&traceparent));
}

#[tokio::test]
async fn trace_transport_health_aliases_and_request_ids_are_correlated() {
    let _request_logs = captured_request_logs();
    const INBOUND: &str = "00-11111111111111111111111111111111-2222222222222222-01";
    const SECOND: &str = "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01";

    let records = Arc::new(NoopRecords::default());
    let service = Arc::new(HttpService::new(
        compiled_registry(),
        ReadRuntimeIdentity {
            package_revision: "package-startup-http".to_owned(),
            schema_fingerprint: "schema-startup-http".to_owned(),
        },
        records.clone(),
        Arc::new(SlowReadiness),
        Arc::new(
            CursorCodec::new(Zeroizing::new(vec![0x45; 32]), Duration::from_secs(300))
                .expect("test cursor key is valid"),
        ),
    ));
    let app = router(service);

    let mut valid_request = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .expect("valid trace request builds");
    valid_request
        .headers_mut()
        .insert("traceparent", HeaderValue::from_static(INBOUND));
    valid_request.headers_mut().insert(
        "tracestate",
        HeaderValue::from_static("registry=caller-controlled"),
    );
    let valid = app
        .clone()
        .oneshot(valid_request)
        .await
        .expect("valid trace responds");
    assert_eq!(valid.status(), StatusCode::OK);
    assert_eq!(valid.headers()["traceparent"], INBOUND);
    assert!(valid.headers().get("tracestate").is_none());
    let health_body = to_bytes(valid.into_body(), 1024)
        .await
        .expect("health body reads");

    let healthz = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .expect("healthz request builds"),
        )
        .await
        .expect("healthz responds");
    assert_eq!(healthz.status(), StatusCode::OK);
    assert!(healthz.headers().get("traceparent").is_some());
    assert_eq!(
        to_bytes(healthz.into_body(), 1024)
            .await
            .expect("healthz body reads"),
        health_body
    );

    for inbound in [None, Some("invalid")] {
        let mut request = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .expect("replacement trace request builds");
        if let Some(inbound) = inbound {
            request.headers_mut().insert(
                "traceparent",
                HeaderValue::from_str(inbound).expect("test header is valid"),
            );
        }
        let response = app
            .clone()
            .oneshot(request)
            .await
            .expect("replacement trace responds");
        assert_canonical_server_trace(response.headers()["traceparent"].to_str().unwrap());
    }

    let mut duplicate = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .expect("duplicate trace request builds");
    duplicate
        .headers_mut()
        .append("traceparent", HeaderValue::from_static(INBOUND));
    duplicate
        .headers_mut()
        .append("traceparent", HeaderValue::from_static(SECOND));
    let duplicate = app
        .clone()
        .oneshot(duplicate)
        .await
        .expect("duplicate trace responds");
    let effective = duplicate.headers()["traceparent"].to_str().unwrap();
    assert_canonical_server_trace(effective);
    assert_ne!(effective, INBOUND);
    assert_ne!(effective, SECOND);

    let mut unmatched_request = Request::builder()
        .uri("/does-not-exist")
        .body(Body::empty())
        .expect("unmatched request builds");
    unmatched_request
        .headers_mut()
        .insert("traceparent", HeaderValue::from_static(INBOUND));
    let unmatched = app
        .clone()
        .oneshot(unmatched_request)
        .await
        .expect("unmatched request responds");
    assert_eq!(unmatched.status(), StatusCode::NOT_FOUND);
    assert_eq!(unmatched.headers()["traceparent"], INBOUND);
    let problem: Value = serde_json::from_slice(
        &to_bytes(unmatched.into_body(), 1024 * 1024)
            .await
            .expect("unmatched problem reads"),
    )
    .expect("unmatched problem is JSON");
    assert_eq!(problem["traceId"], trace_id(INBOUND));

    for _ in 0..2 {
        let mut request = Request::builder()
            .uri("/v1/records/public-records")
            .body(Body::empty())
            .expect("list request builds");
        request
            .headers_mut()
            .insert("traceparent", HeaderValue::from_static(INBOUND));
        request.extensions_mut().insert(reader_claims());
        let response = app
            .clone()
            .oneshot(request)
            .await
            .expect("list request responds");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["traceparent"], INBOUND);
    }
    let correlations = records.correlations.lock().expect("correlation capture");
    assert_eq!(correlations.len(), 2);
    assert_ne!(correlations[0].0, correlations[1].0);
    assert_eq!(correlations[0].1, trace_id(INBOUND));
    assert_eq!(correlations[1].1, trace_id(INBOUND));
}

fn trace_id(traceparent: &str) -> &str {
    traceparent
        .split('-')
        .nth(1)
        .expect("canonical traceparent carries trace ID")
}

fn assert_canonical_server_trace(traceparent: &str) {
    assert_eq!(traceparent.len(), 55);
    assert!(traceparent.starts_with("00-"));
    assert!(traceparent.is_ascii());
    assert_ne!(trace_id(traceparent), "00000000000000000000000000000000");
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
    assert!(operational_log_level(Some("breg=trace")).is_err());
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

fn captured_request_logs() -> &'static CapturedOperationalLogs {
    static WRITER: OnceLock<CapturedOperationalLogs> = OnceLock::new();
    WRITER.get_or_init(|| {
        let writer = CapturedOperationalLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_target(false)
            .with_current_span(false)
            .with_span_list(false)
            .with_writer(writer.clone())
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("request log subscriber installs once for this test binary");
        writer
    })
}

#[tokio::test(flavor = "current_thread")]
async fn request_operational_log_has_only_closed_value_free_fields() {
    let _capture_guard = TRACING_CAPTURE.lock().await;
    const INBOUND: &str = "00-99999999999999999999999999999999-8888888888888888-01";
    let writer = captured_request_logs();
    let service = Arc::new(HttpService::new(
        compiled_registry(),
        ReadRuntimeIdentity {
            package_revision: "package-startup-http".to_owned(),
            schema_fingerprint: "schema-startup-http".to_owned(),
        },
        Arc::new(NoopRecords::default()),
        Arc::new(SlowReadiness),
        Arc::new(
            CursorCodec::new(Zeroizing::new(vec![0x45; 32]), Duration::from_secs(300))
                .expect("test cursor key is valid"),
        ),
    ));
    let mut request = Request::builder()
        .uri(format!("/health?private={QUERY_VALUE_CANARY}"))
        .body(Body::empty())
        .expect("request builds");
    request
        .headers_mut()
        .insert("traceparent", HeaderValue::from_static(INBOUND));
    request.headers_mut().insert(
        "authorization",
        HeaderValue::from_static("Bearer operational-log-token-canary"),
    );
    let response = router(service)
        .oneshot(request)
        .await
        .expect("request responds");
    assert_eq!(response.status(), StatusCode::OK);

    let output = writer.text();
    assert!(!output.contains("pattern-private-entity"));
    assert!(!output.contains("pattern-private-field"));
    assert_forbidden_values_absent(&output);
    assert!(!output.contains("operational-log-token-canary"));
    assert!(!output.contains("/health"));
    let expected_trace_id = trace_id(INBOUND);
    let matching_records = output
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("request log is JSON"))
        .filter(|record| record["fields"]["trace_id"] == expected_trace_id)
        .collect::<Vec<_>>();
    assert_eq!(matching_records.len(), 1);
    let rendered = &matching_records[0];
    let fields = rendered["fields"]
        .as_object()
        .expect("request log fields are an object");
    assert_eq!(
        fields.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "duration_ms",
            "message",
            "method",
            "problem_code",
            "request_id",
            "status",
            "trace_id",
        ])
    );
    assert_eq!(fields["method"], "GET");
    assert_eq!(fields["status"], "success");
    assert_eq!(fields["problem_code"], "none");
    assert_eq!(fields["trace_id"], expected_trace_id);
    uuid::Uuid::parse_str(
        fields["request_id"]
            .as_str()
            .expect("request log carries request_id"),
    )
    .expect("request_id is a UUID");
}

/// A description the audit writer gives for a torn audit file.
const AUDIT_DESTINATION_REASON: &str = "the audit file could not be opened: audit file has an incomplete final entry; archive it and restart with a fresh path";

fn startup_errors() -> [StartupError; 28] {
    [
        // The wrapped cause never changes the rendered operational message: it
        // only lets `bregctl doctor` name it. Any `RuntimeConfigError` variant
        // exercises the same static text, so one representative is enough here.
        StartupError::RuntimeConfig(RuntimeConfigError::InvalidBinding),
        StartupError::PackageRefused(PackageError::Integrity),
        StartupError::DatabaseConnection,
        StartupError::DatabaseUnready,
        StartupError::DatabaseUninitialized,
        StartupError::UnrecognizedDatabase,
        StartupError::InstanceClaimMismatch,
        StartupError::RuntimeWriteAuthority,
        StartupError::RuntimeGrantsMissing,
        StartupError::RoleModeChanged,
        StartupError::FieldPatternSyntax {
            entity_id: "pattern-private-entity".to_owned(),
            field_id: "pattern-private-field".to_owned(),
        },
        StartupError::Audit,
        StartupError::AuditDestination(AUDIT_DESTINATION_REASON.to_owned()),
        StartupError::Cursor,
        StartupError::Oidc,
        StartupError::Authentication,
        StartupError::AuthenticationClientsUnlisted,
        StartupError::EventDestinations,
        StartupError::RetainedWebhookBindings {
            retained_deliveries: 2,
        },
        StartupError::InstanceIdChangedWithPendingDeliveries {
            stored_source: "instance-source-private-canary".to_owned(),
            configured_instance_id: "instance-id-private-canary".to_owned(),
            pending_deliveries: 2,
        },
        StartupError::ReviewAuthorityMissing {
            authority: "review-authority-private-canary".to_owned(),
            retained_submissions: 2,
        },
        StartupError::AttachmentStorage,
        StartupError::FieldEncryption,
        StartupError::FieldEncryptionCustody,
        StartupError::Listener,
        StartupError::Shutdown,
        StartupError::BackgroundTaskStopped,
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
            "registry_breg::startup",
            "Base Registry Engine startup began",
            None,
            None,
        ),
        OperationalEvent::Listening => (
            OperationalLogLevel::Info,
            "registry_breg::startup",
            "Base Registry Engine is listening",
            None,
            None,
        ),
        OperationalEvent::Stopped => (
            OperationalLogLevel::Error,
            "registry_breg::startup",
            "Base Registry Engine stopped",
            None,
            None,
        ),
        OperationalEvent::StoppedWithError(error) => (
            OperationalLogLevel::Error,
            "registry_breg::startup",
            "Base Registry Engine stopped",
            Some(expected_startup_error(error)),
            None,
        ),
        OperationalEvent::WebhookWorkerIterationFailed => (
            OperationalLogLevel::Warn,
            "registry_breg::webhook",
            "webhook worker iteration failed",
            None,
            Some("webhook.worker.iteration_failed"),
        ),
        OperationalEvent::AttachmentVerificationIterationFailed => (
            OperationalLogLevel::Warn,
            "registry_breg::attachment_verification",
            "attachment verification worker iteration failed",
            None,
            Some("attachment_verification.worker.iteration_failed"),
        ),
        OperationalEvent::AttachmentVerificationRetryPending => (
            OperationalLogLevel::Warn,
            "registry_breg::attachment_verification",
            "attachment verification retry is pending",
            None,
            Some("attachment_verification.retry_pending"),
        ),
        OperationalEvent::ReviewWorkerIterationFailed => (
            OperationalLogLevel::Warn,
            "registry_breg::review",
            "review worker iteration failed",
            None,
            Some("review.worker.iteration_failed"),
        ),
        OperationalEvent::ReviewResultLookupsUnavailable => (
            OperationalLogLevel::Warn,
            "registry_breg::review",
            "BReg review result lookups are temporarily unavailable",
            None,
            Some("review.result_lookups.unavailable"),
        ),
        OperationalEvent::MetricsQueueSampleFailed => (
            OperationalLogLevel::Warn,
            "registry_breg::metrics",
            "queue ages could not be sampled for this metrics scrape",
            None,
            Some("metrics.queue_sample.failed"),
        ),
        OperationalEvent::WebhookStateTransitionFailed(code) => (
            OperationalLogLevel::Warn,
            "registry_breg::webhook",
            "webhook state transition failed",
            None,
            Some(expected_webhook_state_transition_code(code)),
        ),
        OperationalEvent::BackgroundTaskStopped(task, stop) => (
            OperationalLogLevel::Error,
            "registry_breg::startup",
            match stop {
                BackgroundTaskStop::Panicked => "a Base Registry Engine background task panicked",
                BackgroundTaskStop::Returned => {
                    "a Base Registry Engine background task returned before shutdown was requested"
                }
            },
            None,
            Some(expected_background_task_stop_code(task, stop)),
        ),
        OperationalEvent::RoleMode(RoleMode::Single) => (
            OperationalLogLevel::Info,
            "registry_breg::startup",
            "Base Registry Engine serves with the migration role (roleMode single); the activation ledger check catches mistakes but not someone holding that credential",
            None,
            Some("startup.role_mode.single"),
        ),
        OperationalEvent::RoleMode(RoleMode::Split) => (
            OperationalLogLevel::Info,
            "registry_breg::startup",
            "Base Registry Engine serves with a separate runtime role (roleMode split)",
            None,
            Some("startup.role_mode.split"),
        ),
        OperationalEvent::ClientsUnrestricted => (
            OperationalLogLevel::Info,
            "registry_breg::startup",
            "authentication.oidc.allowedClients is unrestricted: a token from any client is accepted",
            None,
            Some("startup.authentication.clients_unrestricted"),
        ),
        OperationalEvent::PostgresBaselineAdvisory(advisory) => (
            match advisory.severity() {
                AdvisorySeverity::Warning => OperationalLogLevel::Warn,
                AdvisorySeverity::Information => OperationalLogLevel::Info,
            },
            "registry_breg::postgres",
            advisory.message(),
            None,
            Some(advisory.code()),
        ),
    }
}

/// Every baseline advisory code, from settings that warn on everything and
/// settings that could not be read at all.
fn baseline_advisories() -> Vec<BaselineAdvisory> {
    let warning = BaselineSettings {
        max_connections: Some("20".to_owned()),
        superuser_reserved_connections: Some("3".to_owned()),
        reserved_connections: Some("1".to_owned()),
        autovacuum: Some("off".to_owned()),
        track_counts: Some("off".to_owned()),
        pg_stat_statements_installed: Some(false),
        pg_stat_statements_loaded: Some(false),
        pg_stat_statements_tracking: None,
    };
    let within_budget = BaselineSettings {
        max_connections: Some("100".to_owned()),
        ..warning.clone()
    };
    let mut advisories = advise(&warning, 9);
    advisories.push(advise(&within_budget, 9).remove(0));
    advisories.extend(advise(&BaselineSettings::default(), 9));
    advisories
}

fn baseline_observed_field(advisory: &BaselineAdvisory) -> String {
    advisory
        .observed()
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn expected_startup_error(error: StartupError) -> &'static str {
    match error {
        StartupError::RuntimeConfig(_) => "the Registry runtime configuration was refused",
        StartupError::PackageRefused(_) => "the Registry package was refused",
        StartupError::PackageEnvelopeRefused(_) => "the Registry package was refused",
        StartupError::DatabaseConnection => "the Registry database connection was refused",
        StartupError::DatabaseUnready => "the Registry database is not ready for this package",
        StartupError::DatabaseUninitialized => {
            "the Registry database records no activated package; run `bregctl apply --package DIR --initial` to activate the first package"
        }
        StartupError::UnrecognizedDatabase => {
            "the Registry database holds registry state this release does not recognise; a release reads only the state its predecessor wrote, so upgrade the database one release at a time"
        }
        StartupError::DatabaseIdentityMismatch => {
            "the Registry database records a different database id than identity.databaseId; point the runtime file at the database it names or correct identity.databaseId"
        }
        StartupError::ActivePackageMismatch => {
            "the Registry database has not activated the package at package.root; run `bregctl plan --package DIR` then `bregctl apply --package DIR`"
        }
        StartupError::InstanceClaimMismatch => {
            "the Registry database is not the instance its claim names; adopt a restored copy with bregctl instance-claim adopt"
        }
        StartupError::RuntimeWriteAuthority => {
            "the Registry runtime role can write the activation ledger or the registry state; run `bregctl apply --package DIR` to name the fix"
        }
        StartupError::RuntimeGrantsMissing => {
            "the Registry runtime role is missing grants the active package gives it; run `bregctl apply --package DIR` to reissue them"
        }
        StartupError::RoleModeChanged => {
            "the Registry database was activated for a separate runtime role but the runtime file names one role; run `bregctl apply --package DIR` to activate it for one role"
        }
        StartupError::FieldPatternSyntax { .. } => {
            "a persisted field pattern has invalid PostgreSQL syntax"
        }
        StartupError::Audit => "the Registry audit profile or destination was refused",
        StartupError::AuditDestination(_) => "the Registry audit destination was refused",
        StartupError::Cursor => "the Registry cursor profile was refused",
        StartupError::Oidc => "the Registry OIDC key source was refused",
        StartupError::Authentication => "the Registry authentication profile was refused",
        StartupError::AuthenticationClientsUnlisted => {
            "the project names clients that authentication.oidc.allowedClients does not list; list each client named in requesterClients, trusted actors, or consent recipients there"
        }
        StartupError::EventDestinations => "the Registry event destination bindings were refused",
        StartupError::RetainedWebhookBindings { .. } => {
            "retained webhook deliveries require superseded bindings; run `bregctl doctor` to name the recovery"
        }
        StartupError::InstanceIdChangedWithPendingDeliveries { .. } => {
            "pending webhook deliveries were captured under a different identity.instanceId; restore the previous identity.instanceId until they drain, and run `bregctl doctor` to name it"
        }
        StartupError::ReviewBindings | StartupError::ReviewAuthorityMissing { .. } => {
            "the Registry retained review bindings were refused"
        }
        StartupError::AttachmentStorage => {
            "the Registry attachment storage or verification binding was refused"
        }
        StartupError::FieldEncryption => "the Registry field-encryption key state was refused",
        StartupError::FieldEncryptionCustody => {
            "the Registry field-encryption data-key custody was refused"
        }
        StartupError::Listener => "the Registry listener could not be started",
        StartupError::Shutdown => "the Registry shutdown signal failed",
        StartupError::BackgroundTaskStopped => {
            "a Registry background task stopped before shutdown was requested"
        }
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

fn expected_background_task_stop_code(
    task: BackgroundTask,
    stop: BackgroundTaskStop,
) -> &'static str {
    match (task, stop) {
        (BackgroundTask::WebhookWorker, BackgroundTaskStop::Panicked) => "webhook.worker.panicked",
        (BackgroundTask::WebhookWorker, BackgroundTaskStop::Returned) => "webhook.worker.returned",
        (BackgroundTask::AttachmentVerificationWorker, BackgroundTaskStop::Panicked) => {
            "attachment_verification.worker.panicked"
        }
        (BackgroundTask::AttachmentVerificationWorker, BackgroundTaskStop::Returned) => {
            "attachment_verification.worker.returned"
        }
        (BackgroundTask::ReviewWorker, BackgroundTaskStop::Panicked) => "review.worker.panicked",
        (BackgroundTask::ReviewWorker, BackgroundTaskStop::Returned) => "review.worker.returned",
        (BackgroundTask::SubjectAccessLogRetention, BackgroundTaskStop::Panicked) => {
            "subject_access_log.retention.panicked"
        }
        (BackgroundTask::SubjectAccessLogRetention, BackgroundTaskStop::Returned) => {
            "subject_access_log.retention.returned"
        }
        (BackgroundTask::MetricsListener, BackgroundTaskStop::Panicked) => {
            "metrics.listener.panicked"
        }
        (BackgroundTask::MetricsListener, BackgroundTaskStop::Returned) => {
            "metrics.listener.returned"
        }
    }
}

fn operational_level_name(level: OperationalLogLevel) -> &'static str {
    match level {
        OperationalLogLevel::Info => "INFO",
        OperationalLogLevel::Warn => "WARN",
        OperationalLogLevel::Error => "ERROR",
    }
}

#[tokio::test(flavor = "current_thread")]
async fn every_operational_event_renders_exact_closed_value_free_json_fields() {
    let _capture_guard = TRACING_CAPTURE.lock().await;
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
    events.push(OperationalEvent::RoleMode(RoleMode::Single));
    events.push(OperationalEvent::RoleMode(RoleMode::Split));
    events.push(OperationalEvent::ClientsUnrestricted);
    events.push(OperationalEvent::WebhookWorkerIterationFailed);
    events.push(OperationalEvent::AttachmentVerificationIterationFailed);
    events.push(OperationalEvent::AttachmentVerificationRetryPending);
    events.push(OperationalEvent::ReviewWorkerIterationFailed);
    events.push(OperationalEvent::ReviewResultLookupsUnavailable);
    events.push(OperationalEvent::MetricsQueueSampleFailed);
    for task in BackgroundTask::ALL {
        events.extend(
            BackgroundTaskStop::ALL
                .into_iter()
                .map(|stop| OperationalEvent::BackgroundTaskStopped(task, stop)),
        );
    }
    events.extend(
        WebhookStateTransitionCode::ALL
            .into_iter()
            .map(OperationalEvent::WebhookStateTransitionFailed),
    );
    events.extend(
        baseline_advisories()
            .into_iter()
            .map(OperationalEvent::PostgresBaselineAdvisory),
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
    assert!(!output.contains("pattern-private-entity"));
    assert!(!output.contains("pattern-private-field"));
    assert!(!output.contains("instance-source-private-canary"));
    assert!(!output.contains("instance-id-private-canary"));
    assert_forbidden_values_absent(&output);
    let rendered = output
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("operational log is JSON"))
        .collect::<Vec<_>>();
    assert_eq!(rendered.len(), events.len());
    for (event, rendered) in events.into_iter().zip(rendered) {
        let expected = event.record();
        let observed = match &event {
            OperationalEvent::PostgresBaselineAdvisory(advisory) => {
                Some(baseline_observed_field(advisory))
            }
            _ => None,
        };
        let reason = match &event {
            OperationalEvent::StoppedWithError(StartupError::AuditDestination(reason)) => {
                Some(reason.clone())
            }
            _ => None,
        };
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
        if observed.is_some() {
            expected_field_names.insert("observed");
        }
        if reason.is_some() {
            expected_field_names.insert("reason");
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
        assert_eq!(
            fields.get("observed").and_then(Value::as_str),
            observed.as_deref()
        );
        // The writer's refusal reaches the operator with its recovery step.
        assert_eq!(
            fields.get("reason").and_then(Value::as_str),
            reason.as_deref()
        );
        assert!(matches!(
            expected.target(),
            "registry_breg::startup"
                | "registry_breg::webhook"
                | "registry_breg::attachment_verification"
                | "registry_breg::review"
                | "registry_breg::metrics"
                | "registry_breg::postgres"
        ));
    }
}

#[tokio::test]
async fn provenance_operational_logs_metrics_and_traces_are_separate_closed_and_value_free() {
    let _request_logs = captured_request_logs();
    let directory = TestDirectory::create();
    let registry = compiled_registry();
    let registry_revision = registry.revision().to_owned();
    let service = Arc::new(HttpService::new(
        Arc::clone(&registry),
        ReadRuntimeIdentity {
            package_revision: "package-startup-http".to_owned(),
            schema_fingerprint: "schema-startup-http".to_owned(),
        },
        Arc::new(NoopRecords::default()),
        Arc::new(SlowReadiness),
        Arc::new(
            CursorCodec::new(Zeroizing::new(vec![0x45; 32]), Duration::from_secs(300))
                .expect("test cursor key is valid"),
        ),
    ));
    let authenticator = pinned_authenticator(&registry);
    let app = with_request_timeout_for_test(
        authenticated_router(service, authenticator),
        Duration::from_secs(10),
    );

    let provenance = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/registry")
                .header("authorization", reader_bearer())
                .body(Body::empty())
                .expect("provenance request builds"),
        )
        .await
        .expect("provenance response");
    assert_eq!(provenance.status(), StatusCode::OK);
    assert_eq!(
        provenance
            .headers()
            .get("registry-engine-version")
            .and_then(|value| value.to_str().ok()),
        Some(registry_platform_buildinfo::DISPLAY_VERSION),
        "the contract document names the engine release a peer must match"
    );
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
    assert_eq!(
        response.headers()["traceparent"],
        "00-11111111111111111111111111111111-2222222222222222-01"
    );
    assert!(response.headers().get("tracestate").is_none());
    let mut rendered_response = response
        .headers()
        .iter()
        .map(|(name, value)| format!("{}:{}\n", name, value.to_str().unwrap_or("<binary>")))
        .collect::<String>();
    let response_body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("canary response reads");
    let problem: Value = serde_json::from_slice(&response_body).expect("canary problem is JSON");
    assert_eq!(problem["traceId"], "11111111111111111111111111111111");
    rendered_response
        .push_str(std::str::from_utf8(&response_body).expect("canary response is UTF-8"));
    assert_forbidden_values_absent(&rendered_response);

    for uri in ["/metrics", "/v1/metrics"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("authorization", reader_bearer())
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
    for (member, expected_path) in [
        (
            format!("metrics:\n  labels:\n    principal: {RAW_PRINCIPAL_CANARY}\n"),
            "/metrics",
        ),
        (
            format!("telemetry:\n  tracestate: {TRACESTATE_CANARY}\n"),
            "/telemetry",
        ),
    ] {
        let error =
            parse_runtime_config_with_env(&(valid_runtime.clone() + member.as_str()), |_| None)
                .expect_err("runtime telemetry authority is absent");
        let diagnostics = error.diagnostics(None);
        assert_eq!(diagnostics[0].code, "config.unknown-key");
        assert_eq!(diagnostics[0].path, expected_path);
        assert_forbidden_values_absent(&format!("{error:?} {error} {}", error.render_human(None)));
    }

    // The loader refuses a path through a symbolic link, and the temporary
    // directory may sit under one (`/var` on macOS), so the refusal this test
    // reads is reached through the resolved directory.
    let config_path = fs::canonicalize(directory.path())
        .expect("temporary directory resolves")
        .join(FILESYSTEM_PATH_CANARY);
    fs::write(&config_path, canary_runtime_document()).expect("canary runtime config writes");
    let output = Command::new(env!("CARGO_BIN_EXE_breg"))
        .args([
            "--runtime-config",
            config_path.to_str().expect("config path is UTF-8"),
        ])
        .env("BREG_LOG", "info")
        .output()
        .expect("breg process runs");
    assert_eq!(output.status.code(), Some(1));
    let stdout = std::str::from_utf8(&output.stdout).expect("operational stdout is UTF-8");
    let stderr = std::str::from_utf8(&output.stderr).expect("operational stderr is UTF-8");
    // The operational log on stdout names no path and no value.
    assert_forbidden_values_absent(stdout);
    // The operator reads the reader's diagnostics on stderr: the refused key
    // with its position and fix, under the file the operator named, and no
    // configured value.
    let config_file = config_path.to_str().expect("config path is UTF-8");
    let human = stderr.replace(config_file, "<runtime.yaml>");
    assert_forbidden_values_absent(&human);
    assert!(
        human.starts_with("breg did not start: its runtime configuration was refused.\n"),
        "{human}"
    );
    assert!(
        human.contains("error[config.unknown-key] <runtime.yaml>:3:1 /telemetry\n"),
        "{human}"
    );
    assert!(human.contains("  next: "), "{human}");
    assert!(human.ends_with(" in 1 file\n"), "{human}");
    let logs = format!("{stdout}{human}");
    assert!(!logs.contains("startup-http"));
    assert!(!logs.contains(&registry_revision));
    let records = stdout
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
            Some("Base Registry Engine startup began" | "Base Registry Engine stopped")
        ));
        if let Some(error) = fields.get("error") {
            assert_eq!(error, "the Registry runtime configuration was refused");
        }
    }

    let unknown_flag = Command::new(env!("CARGO_BIN_EXE_breg"))
        .args([
            "--config",
            config_path.to_str().expect("config path is UTF-8"),
        ])
        .output()
        .expect("breg process runs");
    assert_eq!(unknown_flag.status.code(), Some(2));
    assert!(unknown_flag.stdout.is_empty());
    let unknown_stderr = std::str::from_utf8(&unknown_flag.stderr).expect("refusal is UTF-8");
    assert!(
        unknown_stderr.starts_with("error: unexpected argument '--config' found"),
        "{unknown_stderr}"
    );
    assert!(
        !unknown_stderr.contains(config_path.to_str().expect("config path is UTF-8")),
        "{unknown_stderr}"
    );

    let invalid_level = Command::new(env!("CARGO_BIN_EXE_breg"))
        .args([
            "--runtime-config",
            config_path.to_str().expect("config path is UTF-8"),
        ])
        .env("BREG_LOG", "debug")
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
        "Base Registry Engine stopped"
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

/// The production recording path: the timeout boundary records every served
/// request into the metrics registry, a scrape renders it, and no request
/// value reaches a label even when the request carried canary material.
#[tokio::test]
async fn configured_metrics_record_served_requests_with_closed_value_free_labels() {
    let _request_logs = captured_request_logs();
    let registry = compiled_registry();
    let service = Arc::new(HttpService::new(
        Arc::clone(&registry),
        ReadRuntimeIdentity {
            package_revision: "package-startup-http".to_owned(),
            schema_fingerprint: "schema-startup-http".to_owned(),
        },
        Arc::new(NoopRecords::default()),
        Arc::new(SlowReadiness),
        Arc::new(
            CursorCodec::new(Zeroizing::new(vec![0x45; 32]), Duration::from_secs(300))
                .expect("test cursor key is valid"),
        ),
    ));
    let authenticator = pinned_authenticator(&registry);
    let metrics = Arc::new(Metrics::without_pool_for_test());
    let app = with_request_timeout_and_metrics_for_test(
        authenticated_router(service, authenticator),
        Duration::from_secs(10),
        Some(Arc::clone(&metrics)),
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("health request builds"),
        )
        .await
        .expect("health request responds");
    assert_eq!(response.status(), StatusCode::OK);

    // An invalid presented credential on a registered record route: served
    // as a client error, recorded under the registered route template.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/records/public-records?filter=label:equals:{QUERY_VALUE_CANARY}"
                ))
                .header("authorization", format!("Bearer {TOKEN_CANARY}"))
                .body(Body::empty())
                .expect("canary request builds"),
        )
        .await
        .expect("canary request responds");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let scrape = metrics::metrics_app(Arc::clone(&metrics))
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .expect("scrape request builds"),
        )
        .await
        .expect("scrape request responds");
    assert_eq!(scrape.status(), StatusCode::OK);
    let body = to_bytes(scrape.into_body(), 1024 * 1024)
        .await
        .expect("scrape body reads");
    let body = std::str::from_utf8(&body).expect("scrape body is UTF-8");
    assert!(body.contains(
        "breg_http_requests_total{route=\"/health\",method=\"GET\",status=\"success\"} 1\n"
    ));
    assert!(
        body.contains(
            "breg_http_requests_total{route=\"/v1/records/public-records\",method=\"GET\",status=\"client_error\"} 1\n"
        ),
        "the refusal is recorded under its registered route template"
    );
    assert_forbidden_values_absent(body);
}

/// A request that presents no credential is refused before admission, before
/// any access profile or query is read, with one value-free problem. The
/// refusal is counted as a client error under the registered route template,
/// and no metric family is reserved for unauthenticated callers.
#[tokio::test]
async fn unauthenticated_requests_are_refused_before_any_profile_or_query_is_read() {
    let _request_logs = captured_request_logs();
    let registry = compiled_registry();
    let records = Arc::new(NoopRecords::default());
    let service = Arc::new(HttpService::new(
        Arc::clone(&registry),
        ReadRuntimeIdentity {
            package_revision: "package-startup-http".to_owned(),
            schema_fingerprint: "schema-startup-http".to_owned(),
        },
        records.clone(),
        Arc::new(SlowReadiness),
        Arc::new(
            CursorCodec::new(Zeroizing::new(vec![0x46; 32]), Duration::from_secs(300))
                .expect("test cursor key is valid"),
        ),
    ));
    let authenticator = pinned_authenticator(&registry);
    let metrics = Arc::new(Metrics::without_pool_for_test());
    let app = with_request_timeout_and_metrics_for_test(
        authenticated_router(service, authenticator),
        Duration::from_secs(10),
        Some(Arc::clone(&metrics)),
    );

    // The record route, a profile no caller holds, an unparsable query, and
    // both discovery documents: without a credential each is refused alike.
    let mut refusals = Vec::new();
    for uri in [
        "/v1/records/public-records".to_owned(),
        format!("/v1/records/public-records?accessProfile={QUERY_VALUE_CANARY}"),
        format!("/v1/records/public-records?pageSize={QUERY_VALUE_CANARY}"),
        "/v1/registry".to_owned(),
        "/openapi.json".to_owned(),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&uri)
                    .body(Body::empty())
                    .expect("unauthenticated request builds"),
            )
            .await
            .expect("unauthenticated request responds");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("refusal body reads");
        let mut problem: Value = serde_json::from_slice(&body).expect("refusal is JSON");
        assert_eq!(problem["code"], "authentication.refused", "{uri}");
        assert_forbidden_values_absent(std::str::from_utf8(&body).expect("refusal is UTF-8"));
        problem
            .as_object_mut()
            .expect("problem object")
            .remove("traceId");
        refusals.push(problem);
    }
    assert!(
        refusals.windows(2).all(|pair| pair[0] == pair[1]),
        "every unauthenticated refusal has one shape"
    );
    assert!(records
        .correlations
        .lock()
        .expect("correlation capture")
        .is_empty());

    let scrape = metrics::metrics_app(Arc::clone(&metrics))
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .expect("scrape request builds"),
        )
        .await
        .expect("scrape request responds");
    assert_eq!(scrape.status(), StatusCode::OK);
    let body = to_bytes(scrape.into_body(), 1024 * 1024)
        .await
        .expect("scrape body reads");
    let body = std::str::from_utf8(&body).expect("scrape body is UTF-8");
    assert!(
        body.contains(
            "breg_http_requests_total{route=\"/v1/records/public-records\",method=\"GET\",status=\"client_error\"} 3\n"
        ),
        "the refusals are counted under their registered route template: {body}"
    );
    assert!(
        !body.contains("anonymous"),
        "no metric family is reserved for unauthenticated callers: {body}"
    );
    assert_forbidden_values_absent(body);
}

/// The static key set the authenticated tests verify against: the shared
/// testing key, pinned without a network fetch.
fn pinned_authenticator(registry: &CompiledRegistry) -> Arc<RegistryAuthenticator> {
    let document = jwks_from_private_jwk(
        &PrivateJwk::parse(fixtures::ED25519_PRIVATE_JWK).expect("fixture JWK parses"),
    );
    let keys = serde_json::from_value::<JwkSet>(document).expect("static JWKS document parses");
    Arc::new(
        RegistryAuthenticator::new(
            registry,
            TokenVerifierConfig::access_token_profile(
                "https://issuer.example",
                vec!["urn:breg:test".to_owned()],
                vec![Algorithm::EdDSA],
                vec!["at+jwt".to_owned()],
            ),
            Arc::new(JwksFetcher::new_static(keys, JwksFetcherConfig::defaults())),
            AuthorityClaimConfig::new("registry_principal", None),
        )
        .expect("Registry has a valid production authenticator"),
    )
}

/// A bearer the pinned authenticator accepts for the `public` profile.
fn reader_bearer() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    let token = sign_ed25519_compact_jwt(
        fixtures::ED25519_PRIVATE_JWK,
        "at+jwt",
        "registry-platform-testing-ed25519-1",
        json!({
            "iss": "https://issuer.example",
            "aud": "urn:breg:test",
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "registry_actor_kind": "service",
            "registry_principal": "startup-reader",
        }),
    );
    format!("Bearer {token}")
}

/// The verified claims of a `public` profile caller, for the router without
/// the authentication layer.
fn reader_claims() -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        "startup-reader",
        BTreeSet::new(),
        None,
        std::collections::BTreeMap::new(),
    )
    .expect("reader claims are valid")
}

struct TestDirectory {
    directory: PathBuf,
}

impl TestDirectory {
    fn create() -> Self {
        let directory =
            std::env::temp_dir().join(format!("breg-startup-http-{}", uuid::Uuid::new_v4()));
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
        r#"apiVersion: registry.registrystack.org/breg-runtime/v1alpha1
kind: BRegRuntimeConfig
telemetry:
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
    let audit_path = root.join("audit").join("audit.jsonl").display().to_string();
    format!(
        r#"apiVersion: registry.registrystack.org/breg-runtime/v1alpha1
kind: BRegRuntimeConfig
listener:
  bind: 127.0.0.1:8080
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
  runtimeUrlRef: secret:env/BREG_RUNTIME_CONFIG_DATABASE_URL
  migrationUrlRef: secret:env/BREG_RUNTIME_CONFIG_MIGRATION_DATABASE_URL
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
authentication:
  oidc:
    issuer: https://issuer.example
    audience: urn:breg:test
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
audit:
  hashKeyRef: secret:file/audit-key
  path: {audit_path}
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
        root.display()
    )
}

#[cfg(feature = "postgres-test")]
#[tokio::test]
async fn serve_returns_after_graceful_shutdown_signal() {
    use axum::routing::get;
    use registry_breg::startup::{serve_until_shutdown, PreparedServer};
    use registry_breg::webhook::WebhookWorkerLifecycleProbe;

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
    use registry_breg::startup::{serve_until_shutdown, PreparedServer, StartupError};
    use registry_breg::webhook::WebhookWorkerLifecycleProbe;
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
    use registry_breg::startup::{serve_until_shutdown, PreparedServer, StartupError};
    use registry_breg::webhook::WebhookWorkerLifecycleProbe;
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
    use registry_breg::startup::{serve_until_shutdown, PreparedServer, StartupError};
    use registry_breg::webhook::WebhookWorkerLifecycleProbe;
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

/// Serve with a webhook worker probe that stops on its own, and return what
/// serve returned plus the operational records it emitted.
#[cfg(feature = "postgres-test")]
async fn serve_with_self_stopping_worker(
    probe: &registry_breg::webhook::WebhookWorkerLifecycleProbe,
) -> (
    registry_breg::startup::Result<()>,
    Vec<Value>,
    std::net::SocketAddr,
) {
    use axum::routing::get;
    use registry_breg::startup::{serve_until_shutdown, PreparedServer};
    use tokio::net::TcpListener;

    let reservation = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ephemeral listener reservation binds");
    let bind = reservation
        .local_addr()
        .expect("ephemeral listener address reads");
    drop(reservation);
    let app = axum::Router::new().route("/healthz", get(|| async { "ok" }));
    let prepared = PreparedServer::from_parts_with_webhook_worker_for_test(
        bind,
        app,
        Duration::from_secs(2),
        probe.worker(),
    );
    let writer = CapturedOperationalLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_target(false)
        .with_current_span(false)
        .with_span_list(false)
        .with_writer(writer.clone())
        .finish();
    let result = {
        // The current-thread runtime runs every spawned task on this thread,
        // so the thread default subscriber observes the supervisors too.
        let _default = tracing::subscriber::set_default(subscriber);
        tokio::time::timeout(
            Duration::from_secs(5),
            serve_until_shutdown(
                prepared,
                std::future::pending::<registry_breg::startup::Result<()>>(),
            ),
        )
        .await
        .expect("a stopped background task ends serve without a shutdown signal")
    };
    let records = writer
        .text()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("operational log is JSON"))
        .collect();
    (result, records, bind)
}

#[cfg(feature = "postgres-test")]
fn background_task_stop_codes(records: &[Value]) -> Vec<String> {
    records
        .iter()
        .filter(|record| {
            record["fields"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("background task"))
        })
        .filter_map(|record| record["fields"]["code"].as_str().map(str::to_owned))
        .collect()
}

#[cfg(feature = "postgres-test")]
#[tokio::test(flavor = "current_thread")]
async fn a_panicking_background_task_stops_serve_with_a_distinct_error() {
    use registry_breg::webhook::WebhookWorkerLifecycleProbe;

    let _capture_guard = TRACING_CAPTURE.lock().await;
    let probe = WebhookWorkerLifecycleProbe::panicking();
    let (result, records, bind) = serve_with_self_stopping_worker(&probe).await;

    assert_eq!(result, Err(StartupError::BackgroundTaskStopped));
    assert_eq!(
        background_task_stop_codes(&records),
        vec!["webhook.worker.panicked".to_owned()]
    );
    let stopped = records
        .iter()
        .find(|record| record["fields"]["code"] == "webhook.worker.panicked")
        .expect("the panicked task is reported");
    assert_eq!(stopped["level"], "ERROR");
    assert_eq!(
        stopped["fields"]
            .as_object()
            .expect("fields are an object")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["code", "message"])
    );
    assert!(probe.started());
    assert!(probe.stopped());
    let rebound = tokio::net::TcpListener::bind(bind)
        .await
        .expect("serve joined the HTTP server after the task stopped");
    drop(rebound);
}

#[cfg(feature = "postgres-test")]
#[tokio::test(flavor = "current_thread")]
async fn an_early_returning_background_task_stops_serve_with_a_distinct_error() {
    use registry_breg::webhook::WebhookWorkerLifecycleProbe;

    let _capture_guard = TRACING_CAPTURE.lock().await;
    let probe = WebhookWorkerLifecycleProbe::returning();
    let (result, records, bind) = serve_with_self_stopping_worker(&probe).await;

    assert_eq!(result, Err(StartupError::BackgroundTaskStopped));
    assert_eq!(
        background_task_stop_codes(&records),
        vec!["webhook.worker.returned".to_owned()]
    );
    assert!(probe.started());
    assert!(probe.stopped());
    let rebound = tokio::net::TcpListener::bind(bind)
        .await
        .expect("serve joined the HTTP server after the task stopped");
    drop(rebound);
}

#[cfg(feature = "postgres-test")]
#[tokio::test(flavor = "current_thread")]
async fn a_requested_shutdown_reports_no_background_task_stop() {
    use axum::routing::get;
    use registry_breg::startup::{serve_until_shutdown, PreparedServer};
    use registry_breg::webhook::WebhookWorkerLifecycleProbe;

    let _capture_guard = TRACING_CAPTURE.lock().await;
    let probe = WebhookWorkerLifecycleProbe::new(false);
    let prepared = PreparedServer::from_parts_with_webhook_worker_for_test(
        "127.0.0.1:0".parse().expect("ephemeral bind parses"),
        axum::Router::new().route("/healthz", get(|| async { "ok" })),
        Duration::from_secs(2),
        probe.worker(),
    );
    let writer = CapturedOperationalLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(writer.clone())
        .finish();
    let result = {
        let _default = tracing::subscriber::set_default(subscriber);
        serve_until_shutdown(prepared, async { Ok(()) }).await
    };

    assert_eq!(result, Ok(()));
    assert!(probe.stopped());
    assert!(!writer.text().contains("background task"));
}

fn compiled_registry() -> Arc<CompiledRegistry> {
    let project = parse_project_yaml(PROJECT.as_bytes()).expect("project parses");
    Arc::new(compile_project(&project, &[], CompileProfile::Authoring).expect("project compiles"))
}
