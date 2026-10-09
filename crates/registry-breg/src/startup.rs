// SPDX-License-Identifier: Apache-2.0
//! Startup ordering gate for one verified Registry package.

use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use axum::{middleware, Router};
use registry_platform_audit::AuditWriter;
use registry_platform_oidc::JwksFetcher;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, watch};
use tokio_postgres::{Client, GenericClient};
use tracing_subscriber::filter::LevelFilter;

use crate::api::{
    authenticated_router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture,
};
use crate::attachment_verification_worker::AttachmentVerificationWorker;
use crate::audit::RegistryAudit;
use crate::auth::{AuthenticationConfigError, RegistryAuthenticator};
use crate::field_encryption::{FieldEncryptionProvider, FieldEncryptionService};
use crate::metrics::{self, LastSuccess, Metrics, ProgressWorker};
#[cfg(all(feature = "runtime", feature = "tooling"))]
use crate::model::CompiledRegistry;
use crate::package::{
    load_package_with_verified_envelope, PackageError, PackageLoadContext, VerifiedPackage,
};
use crate::postgres::{
    inspect_baseline, verify_catalog_identity_for_catalog, AdvisorySeverity, BaselineAdvisory,
    ExpectedManagedCatalog, ExpectedRegistryIdentity, PostgresRecordMutationService,
    PostgresRecordReadService, PostgresRevisionReadService, PostgresSnapshotReadService,
    RegistryLockKey, RoleMode, RuntimePool, SqlIdentifier,
};
use crate::runtime_config::{load_runtime_config, RuntimeConfig, RuntimeConfigError};
use crate::webhook::{WebhookDeliveryService, WebhookRetainedBindingError, WebhookWorker};

/// Bounded startup refusal. Package paths, request identifiers, stored review
/// values, and physical catalog details are intentionally unavailable through
/// Display and Debug. A missing review authority may expose its authored
/// logical id and an aggregate retained-submission count to operator tooling;
/// production operational logs still render only the closed refusal class.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum StartupError {
    #[error("the Registry runtime configuration was refused")]
    RuntimeConfig(RuntimeConfigError),
    #[error("the Registry package was refused")]
    PackageRefused(PackageError),
    #[error("{0}")]
    PackageEnvelopeRefused(String),
    #[error("the Registry database connection was refused")]
    DatabaseConnection,
    #[error("the Registry database is not ready for this package")]
    DatabaseUnready,
    /// The database holds no registry state: no package was ever applied.
    #[error(
        "the Registry database records no activated package; run `bregctl apply --package DIR \
         --initial` to activate the first package"
    )]
    DatabaseUninitialized,
    /// The database holds registry state this release does not recognise,
    /// such as the state a release before the activation ledger installed.
    #[error(
        "the Registry database holds registry state this release does not recognise; a release \
         reads only the state its predecessor wrote, so upgrade the database one release at a time"
    )]
    UnrecognizedDatabase,
    /// The database records a database id other than the runtime file's
    /// `identity.databaseId`.
    #[error(
        "the Registry database records a different database id than identity.databaseId; point \
         the runtime file at the database it names or correct identity.databaseId"
    )]
    DatabaseIdentityMismatch,
    /// The database records another package as active than the one at
    /// `package.root`.
    #[error(
        "the Registry database has not activated the package at package.root; run `bregctl plan \
         --package DIR` then `bregctl apply --package DIR`"
    )]
    ActivePackageMismatch,
    /// The database is not the physical instance the Registry's instance
    /// claim names, as a restored copy is until an operator adopts it.
    #[error("the Registry database is not the instance its claim names")]
    InstanceClaimMismatch,
    /// A separate runtime role can write the activation ledger or the
    /// registry state. The apply names the object and the exact fix, so the
    /// serving log carries no catalog detail.
    #[error(
        "the Registry runtime role can write the activation ledger or the registry state; run \
         `bregctl apply --package DIR` to name the fix"
    )]
    RuntimeWriteAuthority,
    /// A separate runtime role lacks a grant the active package gives it.
    #[error(
        "the Registry runtime role is missing grants the active package gives it; run `bregctl \
         apply --package DIR` to reissue them"
    )]
    RuntimeGrantsMissing,
    /// The runtime file names one role for a database the ledger records as
    /// activated for a separate runtime role.
    #[error(
        "the Registry database was activated for a separate runtime role but the runtime file \
         names one role; run `bregctl apply --package DIR` to activate it for one role"
    )]
    RoleModeChanged,
    /// Authored field address only, never the expression or database diagnostic.
    #[error("a persisted field pattern has invalid PostgreSQL syntax")]
    FieldPatternSyntax { entity_id: String, field_id: String },
    #[error("the Registry audit profile or destination was refused")]
    Audit,
    /// The audit writer refused the destination. The reason is the writer's
    /// own rule and recovery sentence, never a path or a secret.
    #[error("the Registry audit destination was refused: {0}")]
    AuditDestination(String),
    #[error("the Registry cursor profile was refused")]
    Cursor,
    #[error("the Registry OIDC key source was refused")]
    Oidc,
    #[error("the Registry authentication profile was refused")]
    Authentication,
    /// The project names clients that `authentication.oidc.allowedClients`
    /// does not list; `unrestricted` lists none.
    #[error(
        "the project names clients that authentication.oidc.allowedClients does not list; list \
         each client named in requesterClients, trusted actors, or consent recipients there"
    )]
    AuthenticationClientsUnlisted,
    #[error("the Registry event destination bindings were refused")]
    EventDestinations,
    #[error(
        "{retained_deliveries} retained webhook deliveries require superseded bindings; inspect \
         them with `bregctl webhook list` and either restore the exact bindings or explicitly \
         discard each delivery"
    )]
    RetainedWebhookBindings { retained_deliveries: u64 },
    /// Pending or leased webhook deliveries were captured under an event
    /// source other than the one `identity.instanceId` derives. The worker
    /// would refuse each stored envelope and dead-letter it, so startup
    /// refuses first. Both values are deployment identifiers, not secrets.
    #[error(
        "{pending_deliveries} pending webhook deliveries were captured under event source \
         {stored_source}, but identity.instanceId {configured_instance_id} derives another; \
         restore the previous identity.instanceId until those deliveries drain, then change it"
    )]
    InstanceIdChangedWithPendingDeliveries {
        stored_source: String,
        configured_instance_id: String,
        pending_deliveries: u64,
    },
    #[error("the Registry retained review bindings were refused")]
    ReviewBindings,
    #[error(
        "review authority {authority} is required by {retained_submissions} retained submissions"
    )]
    ReviewAuthorityMissing {
        authority: String,
        retained_submissions: u64,
    },
    #[error("the Registry attachment storage or verification binding was refused")]
    AttachmentStorage,
    #[error("the Registry field-encryption key state was refused")]
    FieldEncryption,
    #[error("the Registry field-encryption data-key custody was refused")]
    FieldEncryptionCustody,
    #[error("the Registry listener could not be started")]
    Listener,
    #[error("the Registry shutdown signal failed")]
    Shutdown,
    #[error("a Registry background task stopped before shutdown was requested")]
    BackgroundTaskStopped,
    #[error("the Registry operational log level was refused")]
    Logging,
}

pub type Result<T> = std::result::Result<T, StartupError>;

/// The closed severity vocabulary emitted by Base Registry Engine operational
/// events. Audit and Registry provenance use separate channels and types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationalLogLevel {
    Info,
    Warn,
    Error,
}

/// Closed webhook state-transition failure codes. These codes identify only
/// the failed transition class and never carry destination or event values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebhookStateTransitionCode {
    ClaimIdentityRefused,
    ClaimRecoveryFailed,
    ClaimSelectFailed,
    ClaimPolicyRefused,
    ClaimUpdateFailed,
    ClaimAuditFailed,
    ClaimCommitFailed,
}

impl WebhookStateTransitionCode {
    /// Every allowed state-transition code, used by exhaustive operational-log
    /// contract tests.
    pub const ALL: [Self; 7] = [
        Self::ClaimIdentityRefused,
        Self::ClaimRecoveryFailed,
        Self::ClaimSelectFailed,
        Self::ClaimPolicyRefused,
        Self::ClaimUpdateFailed,
        Self::ClaimAuditFailed,
        Self::ClaimCommitFailed,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClaimIdentityRefused => "webhook.claim.identity_refused",
            Self::ClaimRecoveryFailed => "webhook.claim.recovery_failed",
            Self::ClaimSelectFailed => "webhook.claim.select_failed",
            Self::ClaimPolicyRefused => "webhook.claim.policy_refused",
            Self::ClaimUpdateFailed => "webhook.claim.update_failed",
            Self::ClaimAuditFailed => "webhook.claim.audit_failed",
            Self::ClaimCommitFailed => "webhook.claim.commit_failed",
        }
    }
}

/// The closed set of background tasks `serve` runs beside the HTTP listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackgroundTask {
    WebhookWorker,
    AttachmentVerificationWorker,
    ReviewWorker,
    SubjectAccessLogRetention,
    MetricsListener,
}

impl BackgroundTask {
    /// Every supervised task, used by exhaustive operational-log contract
    /// tests.
    pub const ALL: [Self; 5] = [
        Self::WebhookWorker,
        Self::AttachmentVerificationWorker,
        Self::ReviewWorker,
        Self::SubjectAccessLogRetention,
        Self::MetricsListener,
    ];
}

/// How a supervised background task ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackgroundTaskStop {
    Panicked,
    Returned,
}

impl BackgroundTaskStop {
    /// Both ways a task can end, used by exhaustive operational-log contract
    /// tests.
    pub const ALL: [Self; 2] = [Self::Panicked, Self::Returned];
}

const fn background_task_stop_code(task: BackgroundTask, stop: BackgroundTaskStop) -> &'static str {
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

/// A rendered operational event. Its fields are an allowlist of low-cardinality,
/// value-free process state. It is deliberately unrelated to Registry audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationalLogRecord {
    level: OperationalLogLevel,
    target: &'static str,
    message: &'static str,
    error: Option<&'static str>,
    code: Option<&'static str>,
}

impl OperationalLogRecord {
    #[must_use]
    pub const fn level(self) -> OperationalLogLevel {
        self.level
    }

    #[must_use]
    pub const fn target(self) -> &'static str {
        self.target
    }

    #[must_use]
    pub const fn message(self) -> &'static str {
        self.message
    }

    #[must_use]
    pub const fn error(self) -> Option<&'static str> {
        self.error
    }

    #[must_use]
    pub const fn code(self) -> Option<&'static str> {
        self.code
    }
}

/// The complete production operational-event vocabulary. Variants accept only
/// closed errors or codes, so request, record, SQL, secret, path, destination,
/// payload, upstream, and caller trace values cannot reach the renderer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationalEvent {
    StartupBegan,
    Listening,
    Stopped,
    StoppedWithError(StartupError),
    WebhookWorkerIterationFailed,
    AttachmentVerificationIterationFailed,
    AttachmentVerificationRetryPending,
    ReviewWorkerIterationFailed,
    /// At least one due review result lookup could not reach its authority on
    /// this pass.
    ReviewResultLookupsUnavailable,
    /// The queue ages could not be read for one metrics scrape, so that
    /// scrape publishes none.
    MetricsQueueSampleFailed,
    WebhookStateTransitionFailed(WebhookStateTransitionCode),
    /// One PostgreSQL baseline advisory, logged once at startup. It carries a
    /// closed code and message plus the server's observed setting counts.
    PostgresBaselineAdvisory(BaselineAdvisory),
    /// The role mode the runtime file selects, logged once at startup.
    RoleMode(RoleMode),
    /// The runtime file leaves `authentication.oidc.allowedClients`
    /// unrestricted, logged once at startup. It names the member only.
    ClientsUnrestricted,
    /// A supervised background task panicked, or returned before shutdown
    /// was requested. The code names the task and how it ended.
    BackgroundTaskStopped(BackgroundTask, BackgroundTaskStop),
}

impl OperationalEvent {
    #[must_use]
    pub const fn record(&self) -> OperationalLogRecord {
        match self {
            Self::StartupBegan => OperationalLogRecord {
                level: OperationalLogLevel::Info,
                target: "registry_breg::startup",
                message: "Base Registry Engine startup began",
                error: None,
                code: None,
            },
            Self::Listening => OperationalLogRecord {
                level: OperationalLogLevel::Info,
                target: "registry_breg::startup",
                message: "Base Registry Engine is listening",
                error: None,
                code: None,
            },
            Self::Stopped => OperationalLogRecord {
                level: OperationalLogLevel::Error,
                target: "registry_breg::startup",
                message: "Base Registry Engine stopped",
                error: None,
                code: None,
            },
            Self::StoppedWithError(error) => OperationalLogRecord {
                level: OperationalLogLevel::Error,
                target: "registry_breg::startup",
                message: "Base Registry Engine stopped",
                error: Some(error.operational_message()),
                code: None,
            },
            Self::RoleMode(RoleMode::Single) => OperationalLogRecord {
                level: OperationalLogLevel::Info,
                target: "registry_breg::startup",
                message: "Base Registry Engine serves with the migration role (roleMode single); \
                          the activation ledger check catches mistakes but not someone holding \
                          that credential",
                error: None,
                code: Some("startup.role_mode.single"),
            },
            Self::RoleMode(RoleMode::Split) => OperationalLogRecord {
                level: OperationalLogLevel::Info,
                target: "registry_breg::startup",
                message:
                    "Base Registry Engine serves with a separate runtime role (roleMode split)",
                error: None,
                code: Some("startup.role_mode.split"),
            },
            Self::ClientsUnrestricted => OperationalLogRecord {
                level: OperationalLogLevel::Info,
                target: "registry_breg::startup",
                message: "authentication.oidc.allowedClients is unrestricted: a token from any client is accepted",
                error: None,
                code: Some("startup.authentication.clients_unrestricted"),
            },
            Self::WebhookWorkerIterationFailed => OperationalLogRecord {
                level: OperationalLogLevel::Warn,
                target: "registry_breg::webhook",
                message: "webhook worker iteration failed",
                error: None,
                code: Some("webhook.worker.iteration_failed"),
            },
            Self::AttachmentVerificationIterationFailed => OperationalLogRecord {
                level: OperationalLogLevel::Warn,
                target: "registry_breg::attachment_verification",
                message: "attachment verification worker iteration failed",
                error: None,
                code: Some("attachment_verification.worker.iteration_failed"),
            },
            Self::AttachmentVerificationRetryPending => OperationalLogRecord {
                level: OperationalLogLevel::Warn,
                target: "registry_breg::attachment_verification",
                message: "attachment verification retry is pending",
                error: None,
                code: Some("attachment_verification.retry_pending"),
            },
            Self::ReviewWorkerIterationFailed => OperationalLogRecord {
                level: OperationalLogLevel::Warn,
                target: "registry_breg::review",
                message: "review worker iteration failed",
                error: None,
                code: Some("review.worker.iteration_failed"),
            },
            Self::ReviewResultLookupsUnavailable => OperationalLogRecord {
                level: OperationalLogLevel::Warn,
                target: "registry_breg::review",
                message: "BReg review result lookups are temporarily unavailable",
                error: None,
                code: Some("review.result_lookups.unavailable"),
            },
            Self::MetricsQueueSampleFailed => OperationalLogRecord {
                level: OperationalLogLevel::Warn,
                target: "registry_breg::metrics",
                message: "queue ages could not be sampled for this metrics scrape",
                error: None,
                code: Some("metrics.queue_sample.failed"),
            },
            Self::WebhookStateTransitionFailed(code) => OperationalLogRecord {
                level: OperationalLogLevel::Warn,
                target: "registry_breg::webhook",
                message: "webhook state transition failed",
                error: None,
                code: Some(code.as_str()),
            },
            Self::BackgroundTaskStopped(task, stop) => OperationalLogRecord {
                level: OperationalLogLevel::Error,
                target: "registry_breg::startup",
                message: match stop {
                    BackgroundTaskStop::Panicked => {
                        "a Base Registry Engine background task panicked"
                    }
                    BackgroundTaskStop::Returned => {
                        "a Base Registry Engine background task returned before shutdown was requested"
                    }
                },
                error: None,
                code: Some(background_task_stop_code(*task, *stop)),
            },
            Self::PostgresBaselineAdvisory(advisory) => OperationalLogRecord {
                level: match advisory.severity() {
                    AdvisorySeverity::Warning => OperationalLogLevel::Warn,
                    AdvisorySeverity::Information => OperationalLogLevel::Info,
                },
                target: "registry_breg::postgres",
                message: advisory.message(),
                error: None,
                code: Some(advisory.code()),
            },
        }
    }

    /// Emit one record through the production JSON tracing subscriber. This is
    /// the entry point for the closed operational event vocabulary. It is not
    /// the only production tracing call in Base Registry Engine: some modules
    /// call `tracing` macros directly, and those records are outside this
    /// vocabulary and its value-free contract test.
    pub fn emit(&self) {
        let record = self.record();
        match self {
            Self::StartupBegan | Self::Listening => {
                tracing::info!(target: "registry_breg::startup", message = record.message);
            }
            Self::RoleMode(_) | Self::ClientsUnrestricted => {
                let code = record.code.expect("startup notes have a code");
                tracing::info!(target: "registry_breg::startup", code, message = record.message);
            }
            Self::Stopped => {
                tracing::error!(target: "registry_breg::startup", message = record.message);
            }
            Self::BackgroundTaskStopped(..) => {
                let code = record
                    .code
                    .expect("background task stop records have a code");
                tracing::error!(target: "registry_breg::startup", code, message = record.message);
            }
            Self::StoppedWithError(StartupError::AuditDestination(reason)) => {
                let error = record
                    .error
                    .expect("stopped-with-error records have a closed error");
                tracing::error!(
                    target: "registry_breg::startup",
                    error,
                    reason = reason.as_str(),
                    message = record.message
                );
            }
            Self::StoppedWithError(_) => {
                let error = record
                    .error
                    .expect("stopped-with-error records have a closed error");
                tracing::error!(target: "registry_breg::startup", error, message = record.message);
            }
            Self::AttachmentVerificationIterationFailed
            | Self::AttachmentVerificationRetryPending => {
                let code = record
                    .code
                    .expect("verification warning records have a code");
                tracing::warn!(target: "registry_breg::attachment_verification", code, message = record.message);
            }
            Self::ReviewWorkerIterationFailed | Self::ReviewResultLookupsUnavailable => {
                let code = record.code.expect("review warning records have a code");
                tracing::warn!(target: "registry_breg::review", code, message = record.message);
            }
            Self::MetricsQueueSampleFailed => {
                let code = record.code.expect("metrics warning records have a code");
                tracing::warn!(target: "registry_breg::metrics", code, message = record.message);
            }
            Self::WebhookWorkerIterationFailed | Self::WebhookStateTransitionFailed(_) => {
                let code = record.code.expect("webhook warning records have a code");
                tracing::warn!(target: "registry_breg::webhook", code, message = record.message);
            }
            Self::PostgresBaselineAdvisory(advisory) => {
                let code = record.code.expect("baseline advisory records have a code");
                let observed = advisory
                    .observed()
                    .iter()
                    .map(|(name, value)| format!("{name}={value}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                match advisory.severity() {
                    AdvisorySeverity::Warning => {
                        tracing::warn!(target: "registry_breg::postgres", code, observed, message = record.message);
                    }
                    AdvisorySeverity::Information => {
                        tracing::info!(target: "registry_breg::postgres", code, observed, message = record.message);
                    }
                }
            }
        }
    }
}

impl StartupError {
    const fn operational_message(&self) -> &'static str {
        match self {
            Self::RuntimeConfig(_) => "the Registry runtime configuration was refused",
            Self::PackageRefused(PackageError::RetiredApiVersion) => {
                "the Registry package carries the retired apiVersion registry.registrystack.org/package/v2; rebuild it with this release's `bregctl package`, naming the deployed package with --baseline-package, then run `bregctl plan --package DIR` and `bregctl apply --package DIR`"
            }
            Self::PackageRefused(_) => "the Registry package was refused",
            Self::PackageEnvelopeRefused(_) => "the Registry package was refused",
            Self::DatabaseConnection => "the Registry database connection was refused",
            Self::DatabaseUnready => "the Registry database is not ready for this package",
            Self::DatabaseUninitialized => {
                "the Registry database records no activated package; run `bregctl apply --package DIR --initial` to activate the first package"
            }
            Self::UnrecognizedDatabase => {
                "the Registry database holds registry state this release does not recognise; a release reads only the state its predecessor wrote, so upgrade the database one release at a time"
            }
            Self::DatabaseIdentityMismatch => {
                "the Registry database records a different database id than identity.databaseId; point the runtime file at the database it names or correct identity.databaseId"
            }
            Self::ActivePackageMismatch => {
                "the Registry database has not activated the package at package.root; run `bregctl plan --package DIR` then `bregctl apply --package DIR`"
            }
            Self::InstanceClaimMismatch => {
                "the Registry database is not the instance its claim names; adopt a restored copy with bregctl instance-claim adopt"
            }
            Self::RuntimeWriteAuthority => {
                "the Registry runtime role can write the activation ledger or the registry state; run `bregctl apply --package DIR` to name the fix"
            }
            Self::RuntimeGrantsMissing => {
                "the Registry runtime role is missing grants the active package gives it; run `bregctl apply --package DIR` to reissue them"
            }
            Self::RoleModeChanged => {
                "the Registry database was activated for a separate runtime role but the runtime file names one role; run `bregctl apply --package DIR` to activate it for one role"
            }
            Self::FieldPatternSyntax { .. } => {
                "a persisted field pattern has invalid PostgreSQL syntax"
            }
            Self::Audit => "the Registry audit profile or destination was refused",
            Self::AuditDestination(_) => "the Registry audit destination was refused",
            Self::Cursor => "the Registry cursor profile was refused",
            Self::Oidc => "the Registry OIDC key source was refused",
            Self::Authentication => "the Registry authentication profile was refused",
            Self::AuthenticationClientsUnlisted => {
                "the project names clients that authentication.oidc.allowedClients does not list; list each client named in requesterClients, trusted actors, or consent recipients there"
            }
            Self::AttachmentStorage => {
                "the Registry attachment storage or verification binding was refused"
            }
            Self::EventDestinations => "the Registry event destination bindings were refused",
            Self::RetainedWebhookBindings { .. } => {
                "retained webhook deliveries require superseded bindings; run `bregctl doctor` to name the recovery"
            }
            Self::InstanceIdChangedWithPendingDeliveries { .. } => {
                "pending webhook deliveries were captured under a different identity.instanceId; restore the previous identity.instanceId until they drain, and run `bregctl doctor` to name it"
            }
            Self::FieldEncryption => "the Registry field-encryption key state was refused",
            Self::FieldEncryptionCustody => {
                "the Registry field-encryption data-key custody was refused"
            }
            Self::ReviewBindings | Self::ReviewAuthorityMissing { .. } => {
                "the Registry retained review bindings were refused"
            }
            Self::Listener => "the Registry listener could not be started",
            Self::Shutdown => "the Registry shutdown signal failed",
            Self::BackgroundTaskStopped => {
                "a Registry background task stopped before shutdown was requested"
            }
            Self::Logging => "the Registry operational log level was refused",
        }
    }
}

/// Unforgeable listener gate produced only after package closure and database
/// readiness verification. Listener construction must consume this object.
pub struct VerifiedStartup {
    package: VerifiedPackage,
    expected: ExpectedRegistryIdentity,
    expected_catalog: ExpectedManagedCatalog,
    lock_key: RegistryLockKey,
}

impl VerifiedStartup {
    pub fn package(&self) -> &VerifiedPackage {
        &self.package
    }

    pub fn into_package(self) -> VerifiedPackage {
        self.package
    }

    pub fn expected_identity(&self) -> &ExpectedRegistryIdentity {
        &self.expected
    }

    pub fn expected_catalog(&self) -> &ExpectedManagedCatalog {
        &self.expected_catalog
    }

    /// Whether the database holds the subject access-log storage. A database
    /// an earlier release activated gains it at its next apply.
    pub fn subject_access_log_installed(&self) -> bool {
        self.expected_catalog.includes_subject_access_log()
    }

    pub fn lock_key(&self) -> RegistryLockKey {
        self.lock_key
    }
}

/// Fully verified server state. Fields are private so production listeners can
/// only be created by consuming this value through [`serve`].
pub struct PreparedServer {
    bind: SocketAddr,
    app: Router,
    shutdown_grace: Duration,
    webhook_worker: Option<WebhookWorker>,
    attachment_verification_worker: Option<AttachmentVerificationWorker>,
    review_worker: Option<crate::review_store::ReviewWorker>,
    access_log_retention: Option<(RuntimePool, Arc<LastSuccess>)>,
    metrics: Option<PreparedMetricsListener>,
    #[cfg(feature = "wasm")]
    wasm_runtime: Option<crate::wasm_runtime::ConfiguredWasmRuntime>,
    postgres_advisories: Vec<BaselineAdvisory>,
    role_mode: RoleMode,
    #[cfg(all(feature = "postgres-test", feature = "tooling"))]
    fixture_pool: Option<RuntimePool>,
}

/// The operator-private metrics listener assembled by the verified startup
/// path, served on its own binding beside the Registry listener.
pub struct PreparedMetricsListener {
    bind: SocketAddr,
    app: Router,
}

impl PreparedServer {
    pub fn app(&self) -> Router {
        self.app.clone()
    }

    #[must_use]
    pub fn bind(&self) -> SocketAddr {
        self.bind
    }

    /// The PostgreSQL baseline advisories decided while this server was
    /// prepared. They never refused startup.
    #[must_use]
    pub fn postgres_advisories(&self) -> &[BaselineAdvisory] {
        &self.postgres_advisories
    }

    /// The role mode the runtime file selects and startup verified.
    #[must_use]
    pub fn role_mode(&self) -> RoleMode {
        self.role_mode
    }

    /// The runtime pool the verified startup path built, so a test can check
    /// the session settings its connections carry.
    #[cfg(all(feature = "postgres-test", feature = "tooling"))]
    #[doc(hidden)]
    #[must_use]
    pub fn runtime_pool_for_test(&self) -> Option<RuntimePool> {
        self.fixture_pool.clone()
    }

    /// The metrics listener's Router, when the runtime file configured one,
    /// so a test can scrape the registry the verified startup path built.
    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    #[must_use]
    pub fn metrics_app_for_test(&self) -> Option<Router> {
        self.metrics.as_ref().map(|metrics| metrics.app.clone())
    }

    /// Return the Router and PostgreSQL pool only when both were assembled by
    /// the verified startup path. Raw test-part constructors deliberately
    /// carry no such capability, so fixture receipt code cannot attest canned
    /// Routers or a caller-selected database.
    #[cfg(all(feature = "postgres-test", feature = "tooling"))]
    pub(crate) fn fixture_runtime(&self) -> Option<(Router, RuntimePool)> {
        self.fixture_pool
            .as_ref()
            .map(|pool| (self.app.clone(), pool.clone()))
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    #[must_use]
    pub fn from_parts_for_test(bind: SocketAddr, app: Router, shutdown_grace: Duration) -> Self {
        Self {
            bind,
            app,
            shutdown_grace,
            webhook_worker: None,
            attachment_verification_worker: None,
            review_worker: None,
            access_log_retention: None,
            metrics: None,
            postgres_advisories: Vec::new(),
            role_mode: RoleMode::Split,
            #[cfg(feature = "wasm")]
            wasm_runtime: None,
            #[cfg(feature = "tooling")]
            fixture_pool: None,
        }
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    #[must_use]
    pub fn from_parts_with_webhook_worker_for_test(
        bind: SocketAddr,
        app: Router,
        shutdown_grace: Duration,
        webhook_worker: WebhookWorker,
    ) -> Self {
        Self {
            bind,
            app,
            shutdown_grace,
            webhook_worker: Some(webhook_worker),
            attachment_verification_worker: None,
            review_worker: None,
            access_log_retention: None,
            metrics: None,
            postgres_advisories: Vec::new(),
            role_mode: RoleMode::Split,
            #[cfg(feature = "wasm")]
            wasm_runtime: None,
            #[cfg(feature = "tooling")]
            fixture_pool: None,
        }
    }
}

/// Production startup. The package is verified before any secret resolution,
/// database connection, OIDC discovery, audit profile, or listener bind.
pub async fn prepare(config_path: &Path) -> Result<PreparedServer> {
    let config = load_runtime_config(config_path).map_err(map_runtime_config_error)?;
    prepare_loaded(config).await
}

/// Production startup over a runtime configuration the caller has already
/// loaded, so the caller can report a refused file in full before startup
/// begins. Everything after the load is [`prepare`].
pub async fn prepare_loaded(config: RuntimeConfig) -> Result<PreparedServer> {
    let shared = config
        .verify_package_envelope()
        .map_err(|error| StartupError::PackageEnvelopeRefused(error.to_string()))?;
    let package_root = config.package().root().to_path_buf();
    let package = {
        let package_context = config.package_load_context();
        load_package_with_verified_envelope(&package_root, &package_context, &shared)
            .map_err(StartupError::PackageRefused)?
    };
    let connection = config
        .runtime_database_connection_config()
        .map_err(map_runtime_config_error)?;
    prepare_verified_package_with_connection(config, package, connection, AuditOpening::Serve).await
}

/// Check every dependency [`prepare`] opens, then discard the unbound state,
/// keeping only the PostgreSQL baseline advisories it decided.
///
/// The audit destination is checked with `check_writable` instead of being
/// opened, so the check takes no writer lock, creates no audit file, and can
/// run beside a serving process that holds the destination. The discarded
/// state is built over a writer that refuses every entry, so nothing it holds
/// can append.
pub async fn check(config_path: &Path) -> Result<CheckedStartup> {
    let config = load_runtime_config(config_path).map_err(map_runtime_config_error)?;
    let shared = config
        .verify_package_envelope()
        .map_err(|error| StartupError::PackageEnvelopeRefused(error.to_string()))?;
    let package_root = config.package().root().to_path_buf();
    let package = {
        let package_context = config.package_load_context();
        load_package_with_verified_envelope(&package_root, &package_context, &shared)
            .map_err(StartupError::PackageRefused)?
    };
    let connection = config
        .runtime_database_connection_config()
        .map_err(map_runtime_config_error)?;
    prepare_verified_package_with_connection(config, package, connection, AuditOpening::CheckOnly)
        .await
        .map(|prepared| CheckedStartup {
            postgres_advisories: prepared.postgres_advisories().to_vec(),
            role_mode: prepared.role_mode(),
        })
}

/// What a startup check that passed decided without refusing: the
/// PostgreSQL baseline advisories and the role mode it verified.
#[derive(Debug, Clone)]
pub struct CheckedStartup {
    pub postgres_advisories: Vec<BaselineAdvisory>,
    pub role_mode: RoleMode,
}

/// Prepare the clean database capability consumed by the production pre-sign
/// schema-test executor. This is not a serving path and returns no listener,
/// router, pool, or client.
#[cfg(all(feature = "runtime", feature = "tooling"))]
pub async fn prepare_schema_test_database(
    config: &RuntimeConfig,
    candidate: &crate::package::PreparedPackage,
) -> Result<crate::postgres::PreparedSchemaTestDatabase> {
    validate_schema_test_candidate_binding(candidate)?;
    let migration = config
        .migration_database_connection_config()
        .map_err(map_runtime_config_error)?;
    let runtime = config
        .runtime_database_connection_config()
        .map_err(map_runtime_config_error)?;
    prepare_schema_test_database_with_connection_configs(config, candidate, &migration, &runtime)
        .await
}

/// Rehearse the managed schema fingerprint for one production-compiled
/// Registry using the configured migration and runtime roles. This boundary
/// validates deployment bindings before resolving database secrets and returns
/// only the measured fingerprint.
#[cfg(all(feature = "runtime", feature = "tooling"))]
pub async fn rehearse_schema_fingerprint(
    config: &RuntimeConfig,
    registry: &CompiledRegistry,
) -> Result<String> {
    validate_rehearsal_registry_binding(registry)?;
    let migration = config
        .migration_database_connection_config()
        .map_err(map_runtime_config_error)?;
    rehearse_schema_fingerprint_with_connection_config(config, registry, &migration).await
}

/// Rehearse a successor candidate's migration over an empty reproduction of
/// its verified predecessor schema, using the configured migration role
/// against the clean schema-test database. The outer error is a deployment
/// binding or configuration refusal; the inner one is the rehearsal's own
/// value-free refusal. The rehearsal always rolls back.
#[cfg(all(feature = "runtime", feature = "tooling"))]
pub async fn rehearse_successor_migration(
    config: &RuntimeConfig,
    rehearsal: crate::postgres::SuccessorMigrationRehearsal<'_>,
) -> Result<
    std::result::Result<
        crate::postgres::RehearsalOutcome,
        crate::postgres::MigrationRehearsalError,
    >,
> {
    validate_schema_test_candidate_binding(rehearsal.candidate)?;
    let migration = config
        .migration_database_connection_config()
        .map_err(map_runtime_config_error)?;
    Ok(crate::postgres::rehearse_successor_migration(
        &migration,
        config.database().roles().migration(),
        config.database().roles().runtime(),
        rehearsal,
    )
    .await)
}

#[cfg(all(feature = "runtime", feature = "tooling", feature = "postgres-test"))]
#[doc(hidden)]
pub async fn rehearse_schema_fingerprint_with_connection_config_for_test(
    config: &RuntimeConfig,
    registry: &CompiledRegistry,
    migration: &crate::postgres::ConnectionConfig,
) -> Result<String> {
    validate_rehearsal_registry_binding(registry)?;
    rehearse_schema_fingerprint_with_connection_config(config, registry, migration).await
}

#[cfg(all(feature = "runtime", feature = "tooling"))]
async fn rehearse_schema_fingerprint_with_connection_config(
    config: &RuntimeConfig,
    registry: &CompiledRegistry,
    migration: &crate::postgres::ConnectionConfig,
) -> Result<String> {
    crate::postgres::rehearse_schema_fingerprint_with_connection(
        migration,
        config.database().roles().migration(),
        config.database().roles().runtime(),
        registry,
    )
    .await
    .map_err(schema_preparation_error)
}

#[cfg(all(feature = "runtime", feature = "tooling", feature = "postgres-test"))]
#[doc(hidden)]
pub async fn prepare_schema_test_database_with_connection_configs_for_test(
    config: &RuntimeConfig,
    candidate: &crate::package::PreparedPackage,
    migration: &crate::postgres::ConnectionConfig,
    runtime: &crate::postgres::ConnectionConfig,
) -> Result<crate::postgres::PreparedSchemaTestDatabase> {
    validate_schema_test_candidate_binding(candidate)?;
    prepare_schema_test_database_with_connection_configs(config, candidate, migration, runtime)
        .await
}

#[cfg(all(feature = "runtime", feature = "tooling"))]
async fn prepare_schema_test_database_with_connection_configs(
    config: &RuntimeConfig,
    candidate: &crate::package::PreparedPackage,
    migration: &crate::postgres::ConnectionConfig,
    runtime: &crate::postgres::ConnectionConfig,
) -> Result<crate::postgres::PreparedSchemaTestDatabase> {
    // The scratch database records the candidate's package digest as its
    // active package, so the schema test executes only the package it was
    // prepared for.
    let package_digest = candidate
        .package_digest()
        .map_err(StartupError::PackageRefused)?;
    crate::postgres::prepare_schema_test_database_with_connections(
        migration,
        runtime,
        config.database().roles().migration(),
        config.database().roles().runtime(),
        candidate.registry(),
        crate::postgres::SchemaTestDatabaseIdentity {
            database_id: config.identity().database_id(),
            package_digest: &package_digest,
        },
    )
    .await
    .map_err(schema_preparation_error)
}

#[cfg(all(feature = "runtime", feature = "tooling"))]
fn schema_preparation_error(error: crate::postgres::PostgresKernelError) -> StartupError {
    match error {
        crate::postgres::PostgresKernelError::FieldPatternSyntax {
            entity_id,
            field_id,
        } => StartupError::FieldPatternSyntax {
            entity_id,
            field_id,
        },
        _ => StartupError::DatabaseUnready,
    }
}

#[cfg(all(feature = "runtime", feature = "tooling"))]
fn validate_schema_test_candidate_binding(
    candidate: &crate::package::PreparedPackage,
) -> Result<()> {
    if candidate.registry().registry_id() != candidate.manifest().package_id {
        return Err(StartupError::PackageRefused(PackageError::Binding));
    }
    Ok(())
}

#[cfg(all(feature = "runtime", feature = "tooling"))]
/// A rehearsal measures a production-compiled Registry, which always names
/// its package source.
fn validate_rehearsal_registry_binding(registry: &CompiledRegistry) -> Result<()> {
    registry
        .package()
        .map(|_| ())
        .ok_or(StartupError::PackageRefused(PackageError::Binding))
}

#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn prepare_with_connection_config_for_test(
    config_path: &Path,
    connection: crate::postgres::ConnectionConfig,
) -> Result<PreparedServer> {
    let config = load_runtime_config(config_path).map_err(map_runtime_config_error)?;
    let shared = config
        .verify_package_envelope()
        .map_err(|error| StartupError::PackageEnvelopeRefused(error.to_string()))?;
    let package_root = config.package().root().to_path_buf();
    let package = {
        let package_context = config.package_load_context();
        load_package_with_verified_envelope(&package_root, &package_context, &shared)
            .map_err(StartupError::PackageRefused)?
    };
    prepare_verified_package_with_connection(config, package, connection, AuditOpening::Serve).await
}

#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn check_with_connection_config_for_test(
    config_path: &Path,
    connection: crate::postgres::ConnectionConfig,
) -> Result<()> {
    let config = load_runtime_config(config_path).map_err(map_runtime_config_error)?;
    let shared = config
        .verify_package_envelope()
        .map_err(|error| StartupError::PackageEnvelopeRefused(error.to_string()))?;
    let package_root = config.package().root().to_path_buf();
    let package = {
        let package_context = config.package_load_context();
        load_package_with_verified_envelope(&package_root, &package_context, &shared)
            .map_err(StartupError::PackageRefused)?
    };
    prepare_verified_package_with_connection(config, package, connection, AuditOpening::CheckOnly)
        .await
        .map(drop)
}

#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn prepare_with_connection_and_key_source_for_test(
    config_path: &Path,
    connection: crate::postgres::ConnectionConfig,
    key_source: Arc<JwksFetcher>,
) -> Result<PreparedServer> {
    let config = load_runtime_config(config_path).map_err(map_runtime_config_error)?;
    let shared = config
        .verify_package_envelope()
        .map_err(|error| StartupError::PackageEnvelopeRefused(error.to_string()))?;
    let package_root = config.package().root().to_path_buf();
    let package = {
        let package_context = config.package_load_context();
        load_package_with_verified_envelope(&package_root, &package_context, &shared)
            .map_err(StartupError::PackageRefused)?
    };
    prepare_verified_package_with_key_source(config, package, connection, key_source).await
}

/// Whether startup opens the configured audit destination for serving or only
/// checks that a writer could open it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuditOpening {
    Serve,
    CheckOnly,
}

async fn prepare_verified_package_with_connection(
    config: RuntimeConfig,
    package: VerifiedPackage,
    connection: crate::postgres::ConnectionConfig,
    opening: AuditOpening,
) -> Result<PreparedServer> {
    let (pool, startup, postgres_advisories) = prepare_database_startup(
        package,
        &connection,
        config.identity().database_id(),
        config.database().roles().migration(),
        config.database().roles().runtime(),
    )
    .await?;
    let audit = match opening {
        AuditOpening::Serve => open_registry_audit(&config).await?,
        AuditOpening::CheckOnly => check_registry_audit(&config)?,
    };
    let cursor_codec = Arc::new(config.cursor_codec().map_err(|_| StartupError::Cursor)?);
    let key_source = config
        .oidc_key_source()
        .await
        .map_err(map_runtime_config_error)?;
    finish_prepared_server(
        config,
        startup,
        pool,
        postgres_advisories,
        key_source,
        audit,
        cursor_codec,
    )
    .await
}

#[cfg(feature = "postgres-test")]
async fn prepare_verified_package_with_key_source(
    config: RuntimeConfig,
    package: VerifiedPackage,
    connection: crate::postgres::ConnectionConfig,
    key_source: Arc<JwksFetcher>,
) -> Result<PreparedServer> {
    let (pool, startup, postgres_advisories) = prepare_database_startup(
        package,
        &connection,
        config.identity().database_id(),
        config.database().roles().migration(),
        config.database().roles().runtime(),
    )
    .await?;
    let audit = open_registry_audit(&config).await?;
    let cursor_codec = Arc::new(config.cursor_codec().map_err(|_| StartupError::Cursor)?);
    finish_prepared_server(
        config,
        startup,
        pool,
        postgres_advisories,
        key_source,
        audit,
        cursor_codec,
    )
    .await
}

/// Resolve the keyed reference profile and open the one audit writer this
/// process appends to for its whole lifetime. The file destination takes the
/// single-writer lock here, so a second process configured with the same path
/// refuses to start instead of interleaving entries.
async fn open_registry_audit(config: &RuntimeConfig) -> Result<RegistryAudit> {
    let profile = config.audit_profile().map_err(|_| StartupError::Audit)?;
    let writer = AuditWriter::open(config.audit().destination().clone())
        .await
        .map_err(|error| StartupError::AuditDestination(error.operator_description()))?;
    Ok(RegistryAudit::new(profile, writer))
}

/// Resolve the keyed reference profile and check, without opening it, that a
/// writer could open the configured destination. The returned handle refuses
/// every entry.
///
/// This also checks the `bregctl` companion destination operator commands
/// append to beside the runtime (see [`crate::audit::RegistryAudit::open_companion`]):
/// an unwritable or loosely owned directory, a lock or active file that is not
/// an owner-only regular file, an active file that does not open with a
/// current-format entry, a final line longer than any entry, or a torn final
/// line whose `<path>.torn` side file already holds other bytes blocks an
/// operator command exactly as it would in the runtime's own destination, so
/// doctor must refuse it too instead of reporting a clean audit dependency. A
/// torn final line the writer can move to its side file at open blocks
/// neither.
fn check_registry_audit(config: &RuntimeConfig) -> Result<RegistryAudit> {
    let profile = config.audit_profile().map_err(|_| StartupError::Audit)?;
    let destination = config.audit().destination();
    destination
        .check_writable()
        .map_err(|error| StartupError::AuditDestination(error.operator_description()))?;
    destination
        .for_process(crate::audit::COMPANION_PROCESS_ROLE)
        .map_err(|_| StartupError::Audit)?
        .check_writable()
        .map_err(|error| StartupError::AuditDestination(error.operator_description()))?;
    Ok(RegistryAudit::new(
        profile,
        AuditWriter::from_line_sink(Box::new(RefuseEveryEntry)),
    ))
}

/// A line sink that refuses every write, so a checked-only startup state
/// fails closed if anything in it tries to append.
struct RefuseEveryEntry;

impl std::io::Write for RefuseEveryEntry {
    fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other(
            "a checked-only startup appends no audit entry",
        ))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// How long a server session may sit idle inside an open transaction before
/// PostgreSQL ends it and rolls the transaction back.
///
/// Every request, including the transactions it holds, is abandoned after the
/// configured request timeout, at most one minute. Outside a request, the
/// longest wait a server transaction holds open is one object-store read by
/// the attachment verification worker, also capped at one minute; webhook,
/// review, Evidence, and verifier calls run between transactions. A pool
/// checkout waits at most one minute too. The bound is twice the largest of
/// those caps, so it only ends a transaction that nothing is still bounding.
const SERVER_IDLE_IN_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(120);
const _: () = {
    let bound = SERVER_IDLE_IN_TRANSACTION_TIMEOUT.as_millis();
    assert!(bound >= 2 * crate::runtime_config::MAX_HTTP_REQUEST_TIMEOUT_MILLISECONDS as u128);
    assert!(bound >= 2 * crate::attachment_storage::MAXIMUM_TIMEOUT_MILLISECONDS as u128);
    assert!(bound >= 2 * crate::postgres::MAX_POOL_TIMEOUT.as_millis());
};

async fn prepare_database_startup(
    package: VerifiedPackage,
    connection: &crate::postgres::ConnectionConfig,
    database_id: &str,
    migration_role: &SqlIdentifier,
    runtime_role: &SqlIdentifier,
) -> Result<(RuntimePool, VerifiedStartup, Vec<BaselineAdvisory>)> {
    let pool = connection
        .clone()
        .with_jit_disabled()
        .with_idle_in_transaction_session_timeout(SERVER_IDLE_IN_TRANSACTION_TIMEOUT)
        .map_err(|_| StartupError::DatabaseConnection)?
        .build_pool()
        .map_err(|_| StartupError::DatabaseConnection)?;
    let mut client = pool
        .get()
        .await
        .map_err(|_| StartupError::DatabaseConnection)?;
    let startup = verify_opened_startup(
        package,
        database_id,
        &mut client,
        migration_role,
        runtime_role,
        StartupPurpose::Serve,
    )
    .await?;
    let advisories = inspect_baseline(&client, pool.status().max_size).await;
    drop(client);
    Ok((pool, startup, advisories))
}

async fn finish_prepared_server(
    config: RuntimeConfig,
    startup: VerifiedStartup,
    pool: RuntimePool,
    postgres_advisories: Vec<BaselineAdvisory>,
    key_source: Arc<JwksFetcher>,
    audit: RegistryAudit,
    cursor_codec: Arc<crate::cursor::CursorCodec>,
) -> Result<PreparedServer> {
    let oidc = config.authentication().oidc();
    key_source
        .ensure_key_set()
        .await
        .map_err(|_| StartupError::Oidc)?;

    let registry = Arc::new(startup.package().registry().clone());
    if registry
        .queries()
        .operations
        .iter()
        .any(|operation| operation.gis_collection_id().is_some())
        && config.listener().public_origin().is_none()
    {
        return Err(StartupError::RuntimeConfig(
            RuntimeConfigError::InvalidListener,
        ));
    }
    #[cfg(all(feature = "postgres-test", feature = "tooling"))]
    let fixture_pool = pool.clone();
    // Captured before `pool` moves into the mutation service, so the metrics
    // listener can sample live pool gauges at scrape time.
    let telemetry_pool = pool.clone();
    // Retention runs only where the storage exists; a Registry that collects
    // a subject access log is never verified without it.
    let access_log_retention = startup
        .subject_access_log_installed()
        .then(|| (pool.clone(), Arc::<LastSuccess>::default()));
    let event_destinations = Arc::new(
        config
            .activate_event_destinations(&registry)
            .map_err(|_| StartupError::EventDestinations)?,
    );
    let authenticator = Arc::new(
        RegistryAuthenticator::new(
            &registry,
            oidc.token_verifier_config(),
            Arc::clone(&key_source),
            config.authentication().authority_claim_config(),
        )
        .map_err(|error| match error {
            AuthenticationConfigError::NamedClientNotListed => {
                StartupError::AuthenticationClientsUnlisted
            }
            _ => StartupError::Authentication,
        })?,
    );
    let expected = startup.expected_identity().clone();
    let expected_catalog = startup.expected_catalog().clone();
    let lock_key = startup.lock_key();
    let readiness = Arc::new(DynamicRuntimeReadiness {
        pool: pool.clone(),
        expected: expected.clone(),
        expected_catalog: expected_catalog.clone(),
        migration_role: config.database().roles().migration().clone(),
        runtime_role: config.database().roles().runtime().clone(),
        lock_key,
        key_source: Arc::clone(&key_source),
        requires_postgis: registry.ddl().requires_postgis,
        audit_writer: audit.writer().clone(),
    });
    if !readiness.is_ready().await {
        return Err(StartupError::DatabaseUnready);
    }

    let attachment_storage = config
        .activate_attachment_storage(registry.registry_id())
        .await
        .map_err(|_| StartupError::AttachmentStorage)?;
    let attachment_verification = config
        .activate_attachment_verification()
        .map_err(|_| StartupError::AttachmentStorage)?;
    verify_attachment_storage(
        &pool,
        &expected,
        lock_key,
        config.operational_timeouts().record_lock,
        &attachment_storage.binding_digest(),
        &attachment_verification.binding_digest(),
    )
    .await?;
    // Field-encryption key state is required exactly when the active package
    // declares an encrypted field. Without one the service stays absent and
    // per-entity admission never engages.
    let declares_encrypted_fields = registry.entities().values().any(|entity| {
        entity
            .fields
            .values()
            .any(|field| field.encryption.is_some())
    });
    let field_encryption = if declares_encrypted_fields {
        let provider = config
            .field_encryption()
            .provider()
            .ok_or(StartupError::FieldEncryption)?;
        if matches!(provider, FieldEncryptionProvider::LocalFile { .. })
            && config.identity().database_initialization_environment() != "local"
        {
            // A plaintext data-key file is development custody; production
            // initialization refuses it before any key material is read.
            return Err(StartupError::FieldEncryptionCustody);
        }
        let secrets = config
            .secret_resolver()
            .map_err(|_| StartupError::FieldEncryption)?;
        let key_client = pool
            .get()
            .await
            .map_err(|_| StartupError::FieldEncryption)?;
        let service = FieldEncryptionService::open_existing(
            provider,
            registry.registry_id(),
            &secrets,
            &**key_client,
        )
        .await
        .map_err(|_| StartupError::FieldEncryption)?;
        drop(key_client);
        Some(Arc::new(service))
    } else {
        None
    };
    let records = PostgresRecordReadService::new(
        pool.clone(),
        Arc::clone(&registry),
        expected.clone(),
        lock_key,
        config.operational_timeouts().record_lock,
        audit.clone(),
        Arc::clone(&cursor_codec),
    )
    .with_attachment_storage(attachment_storage.clone())
    .with_attachment_verification(attachment_verification.clone());
    let records = Arc::new(match field_encryption.clone() {
        Some(field_encryption) => records.with_field_encryption(field_encryption),
        None => records,
    });
    let read_identity = ReadRuntimeIdentity {
        package_revision: expected.activation_id.clone(),
        schema_fingerprint: expected.schema_fingerprint.clone(),
    };
    let revisions = PostgresRevisionReadService::new(
        pool.clone(),
        Arc::clone(&registry),
        expected.clone(),
        lock_key,
        config.operational_timeouts().record_lock,
        audit.clone(),
    );
    let revisions = Arc::new(match field_encryption.clone() {
        Some(field_encryption) => revisions.with_field_encryption(field_encryption),
        None => revisions,
    });
    let snapshots = PostgresSnapshotReadService::new(
        pool.clone(),
        Arc::clone(&registry),
        expected.clone(),
        lock_key,
        config.operational_timeouts().record_lock,
        audit.clone(),
        Arc::clone(&cursor_codec),
    );
    let snapshots = Arc::new(match field_encryption.clone() {
        Some(field_encryption) => snapshots.with_field_encryption(field_encryption),
        None => snapshots,
    });
    let hook_handlers = Arc::new(crate::hook_handler::HookHandlerRegistry::new(
        &registry,
        &expected.activation_id,
    ));
    // Every write path spends idempotency keys under the one verified issuer
    // and holds responses for the configured receipt horizon.
    let idempotency = config
        .idempotency_policy()
        .map_err(StartupError::RuntimeConfig)?;
    let webhook_delivery = WebhookDeliveryService::new_with_runtime_bindings(
        pool.clone(),
        Arc::clone(&event_destinations),
        hook_handlers,
        Arc::clone(&registry),
        expected.clone(),
        config.identity().instance_id(),
        lock_key,
        config.operational_timeouts().record_lock,
        audit.clone(),
        field_encryption.clone(),
        idempotency.clone(),
    );
    verify_pending_delivery_source(&pool, &expected.package_id, config.identity().instance_id())
        .await?;
    webhook_delivery
        .verify_retained_bindings()
        .await
        .map_err(|error| match error {
            WebhookRetainedBindingError::Mismatch {
                retained_deliveries,
            } => StartupError::RetainedWebhookBindings {
                retained_deliveries,
            },
            WebhookRetainedBindingError::Unavailable => StartupError::EventDestinations,
        })?;
    // The worker also owns payload expiry, so it runs even when the active
    // package declares no events. Compatible retained work is checked above.
    let webhook_progress = webhook_delivery.last_success();
    let webhook_worker = Some(WebhookWorker::new(webhook_delivery));
    let evidence = config
        .activate_evidence(&registry)
        .map_err(StartupError::RuntimeConfig)?;
    let review_authorities = config
        .activate_review_authorities(&registry)
        .map_err(StartupError::RuntimeConfig)?;
    let review_executors = config
        .activate_review_executors(&registry)
        .map_err(StartupError::RuntimeConfig)?;
    crate::review_store::verify_retained_bindings(
        &pool,
        review_authorities.as_deref(),
        review_executors.as_deref(),
    )
    .await
    .map_err(review_binding_startup_error)?;
    // Review retention is source-owned durable state, so housekeeping keeps
    // running after the last authority or executor binding is safely removed.
    let review_worker = Some(crate::review_store::ReviewWorker::new(
        pool.clone(),
        review_authorities.clone(),
        review_executors,
    ));
    let review_completion_receiver = review_authorities.as_ref().map(|authorities| {
        Arc::new(crate::review_store::ReviewCompletionReceiver::new(
            pool.clone(),
            Arc::clone(authorities),
        ))
    });
    let task_status = config
        .activate_task_status(&registry)
        .map_err(StartupError::RuntimeConfig)?;
    // The process WASM executor is installed from the operator budgets and
    // backend before any request can evaluate a WASM handler. Builds without
    // the wasm feature refuse WASM handlers at admission; the section still
    // parses.
    #[cfg(feature = "wasm")]
    let wasm_runtime = crate::wasm_runtime::install_configured(*config.wasm_execution())
        .map_err(|_| StartupError::RuntimeConfig(RuntimeConfigError::InvalidWasmExecution))?;
    let attachment_verification_worker = if matches!(
        attachment_verification,
        crate::attachment_verification::AttachmentVerification::Disabled
    ) {
        None
    } else {
        Some(AttachmentVerificationWorker::new(
            pool.clone(),
            expected.clone(),
            lock_key,
            config.operational_timeouts().record_lock,
            audit.clone(),
            attachment_storage.clone(),
            attachment_verification.clone(),
        ))
    };
    let statistics = Arc::new(
        crate::postgres::PostgresStatisticsService::new(
            pool.clone(),
            Arc::clone(&registry),
            expected.clone(),
            lock_key,
            config.operational_timeouts().record_lock,
            audit.clone(),
        )
        .with_idempotency_policy(idempotency.clone()),
    );
    let mutations = PostgresRecordMutationService::new_with_event_destinations(
        pool,
        Arc::clone(&registry),
        expected,
        config.identity().instance_id(),
        lock_key,
        config.operational_timeouts().record_lock,
        audit,
        Some(event_destinations),
    )
    .with_idempotency_policy(idempotency)
    .with_task_status(task_status)
    .with_attachment_storage(attachment_storage)
    .with_attachment_verification(attachment_verification);
    let mutations = match field_encryption.clone() {
        Some(field_encryption) => mutations.with_field_encryption(field_encryption),
        None => mutations,
    };
    let mutations = match review_authorities {
        Some(authorities) => mutations.with_review_result_source(authorities),
        None => mutations,
    };
    let mutations = Arc::new(match evidence {
        Some(evaluator) => mutations
            .with_evidence_evaluator(evaluator)
            .with_evidence_timeout(config.operational_timeouts().http_request),
        None => mutations,
    });
    let mut service = HttpService::new(registry, read_identity, records, readiness, cursor_codec)
        .with_postgres_revisions(revisions)
        .with_snapshots(snapshots)
        .with_postgres_mutations(mutations)
        .with_statistics(statistics);
    if let Some(receiver) = review_completion_receiver {
        service = service.with_review_completions(receiver);
    }
    if let Some(origin) = config.listener().public_origin() {
        service = service.with_public_origin(origin.clone());
    }
    if let Some(field_encryption) = field_encryption {
        service = service.with_field_encryption(field_encryption);
    }
    let service = Arc::new(service);
    // The metrics registry exists only when the operator configured the
    // separate metrics listener; when absent, no series are recorded and no
    // metrics surface is served at all.
    let telemetry_metrics = config.metrics_listener().map(|_| {
        let mut registry = Metrics::new(telemetry_pool)
            .with_active_package(startup.package().package_digest())
            .with_worker_progress(ProgressWorker::Webhook, webhook_progress);
        if let Some(worker) = &attachment_verification_worker {
            registry = registry.with_worker_progress(
                ProgressWorker::AttachmentVerification,
                worker.last_success(),
            );
        }
        if let Some(worker) = &review_worker {
            registry = registry.with_worker_progress(ProgressWorker::Review, worker.last_success());
        }
        if let Some((_, last_success)) = &access_log_retention {
            registry = registry.with_worker_progress(
                ProgressWorker::SubjectAccessLogRetention,
                Arc::clone(last_success),
            );
        }
        Arc::new(registry)
    });
    let app = with_request_timeout(
        authenticated_router(service, authenticator),
        config.operational_timeouts().http_request,
        telemetry_metrics.clone(),
    );
    let metrics = config
        .metrics_listener()
        .zip(telemetry_metrics)
        .map(|(listener, registry)| PreparedMetricsListener {
            bind: listener.bind(),
            app: metrics::metrics_app(registry),
        });
    Ok(PreparedServer {
        bind: config.listener().bind(),
        app,
        shutdown_grace: config.operational_timeouts().shutdown_grace,
        webhook_worker,
        attachment_verification_worker,
        review_worker,
        access_log_retention,
        metrics,
        postgres_advisories,
        role_mode: RoleMode::from_roles(
            config.database().roles().migration(),
            config.database().roles().runtime(),
        ),
        #[cfg(feature = "wasm")]
        wasm_runtime: Some(wasm_runtime),
        #[cfg(all(feature = "postgres-test", feature = "tooling"))]
        fixture_pool: Some(fixture_pool),
    })
}

/// Startup may inspect storage binding identities, never attachment bytes. This
/// closed system context is installed only after exact package admission, under
/// the same shared registry interlock that excludes activation and maintenance.
async fn verify_attachment_storage(
    pool: &RuntimePool,
    expected: &ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    backend: &str,
    verification_policy: &str,
) -> Result<()> {
    let mut client = pool
        .get()
        .await
        .map_err(|_| StartupError::AttachmentStorage)?;
    let tx = client
        .transaction()
        .await
        .map_err(|_| StartupError::AttachmentStorage)?;
    tx.execute(
        "SELECT set_config('lock_timeout', $1, true), set_config('statement_timeout', '30s', true)",
        &[&format!("{}ms", lock_timeout.as_millis())],
    )
    .await
    .map_err(|_| StartupError::AttachmentStorage)?;
    tx.execute(
        "SELECT pg_advisory_xact_lock_shared($1)",
        &[&lock_key.get()],
    )
    .await
    .map_err(|_| StartupError::AttachmentStorage)?;
    let ready: bool = tx
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM registry_internal.registry_state WHERE singleton
         AND package_id=$1 AND database_id=$2 AND active_package_digest=$3
         AND active_activation_id::text=$4 AND schema_fingerprint=$5
         AND maintenance_status='ready')",
            &[
                &expected.package_id,
                &expected.database_id,
                &expected.package_digest,
                &expected.activation_id,
                &expected.schema_fingerprint,
            ],
        )
        .await
        .map_err(|_| StartupError::AttachmentStorage)?
        .get(0);
    if !ready {
        return Err(StartupError::AttachmentStorage);
    }
    tx.execute(
        "SELECT set_config('registry.active_package_revision', $1, true),
                       set_config('registry.principal', 'breg:startup:attachment-binding', true)",
        &[&expected.activation_id],
    )
    .await
    .map_err(|_| StartupError::AttachmentStorage)?;
    crate::attachment_store::verify_backend_binding(&*tx, backend, verification_policy)
        .await
        .map_err(|_| StartupError::AttachmentStorage)?;
    tx.commit()
        .await
        .map_err(|_| StartupError::AttachmentStorage)
}

/// The startup refusal class a runtime configuration refusal reports under in
/// the operational log.
pub fn map_runtime_config_error(error: RuntimeConfigError) -> StartupError {
    match error {
        RuntimeConfigError::InvalidDatabase | RuntimeConfigError::Secret => {
            StartupError::DatabaseConnection
        }
        RuntimeConfigError::InvalidMetricsListener => StartupError::Listener,
        RuntimeConfigError::InvalidAudit => StartupError::Audit,
        RuntimeConfigError::InvalidCursor => StartupError::Cursor,
        RuntimeConfigError::InvalidOidc => StartupError::Oidc,
        other => StartupError::RuntimeConfig(other),
    }
}

fn review_binding_startup_error(
    error: crate::review_store::RetainedReviewBindingError,
) -> StartupError {
    match error {
        crate::review_store::RetainedReviewBindingError::MissingAuthority {
            authority,
            retained_submissions,
        } => StartupError::ReviewAuthorityMissing {
            authority,
            retained_submissions,
        },
        crate::review_store::RetainedReviewBindingError::Refused
        | crate::review_store::RetainedReviewBindingError::Unavailable => {
            StartupError::ReviewBindings
        }
    }
}

#[doc(hidden)]
pub fn with_request_timeout_for_test(app: Router, timeout: Duration) -> Router {
    with_request_timeout(app, timeout, None)
}

#[doc(hidden)]
pub fn with_request_timeout_and_metrics_for_test(
    app: Router,
    timeout: Duration,
    metrics: Option<Arc<Metrics>>,
) -> Router {
    with_request_timeout(app, timeout, metrics)
}

/// State of the request-timeout boundary: the HTTP deadline plus the metrics
/// registry, which exists only when the operator configured the metrics
/// listener.
#[derive(Clone)]
struct RequestTelemetry {
    timeout: Duration,
    metrics: Option<Arc<Metrics>>,
}

fn with_request_timeout(app: Router, timeout: Duration, metrics: Option<Arc<Metrics>>) -> Router {
    app.layer(middleware::from_fn_with_state(
        RequestTelemetry { timeout, metrics },
        request_timeout,
    ))
}

async fn request_timeout(
    axum::extract::State(telemetry): axum::extract::State<RequestTelemetry>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let method = crate::correlation::method_name(request.method());
    let route = metrics::route_template(&request).to_owned();
    let started = std::time::Instant::now();
    let (correlation, owns_boundary) = crate::correlation::begin_request(&mut request);
    request
        .extensions_mut()
        .insert(crate::correlation::RequestDeadline(
            tokio::time::Instant::now() + telemetry.timeout,
        ));
    let response = match tokio::time::timeout(telemetry.timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => timeout_problem(),
    };
    let status = crate::correlation::status_class(response.status());
    let elapsed = started.elapsed();
    let response = if owns_boundary {
        crate::correlation::finish_response(response, &correlation, method, started)
    } else {
        response
    };
    if let Some(metrics) = &telemetry.metrics {
        metrics.record_http(&route, method, status, elapsed);
    }
    response
}

fn timeout_problem() -> Response {
    let mut response = crate::correlation::problem_response(
        StatusCode::GATEWAY_TIMEOUT,
        "Gateway Timeout",
        "The request timed out.",
        "request.timeout",
    );
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

/// Bind and serve a previously prepared server. Binding consumes the
/// preparation gate, which prevents production from accepting an externally
/// opened database connection before package verification.
pub async fn serve(prepared: PreparedServer) -> Result<()> {
    serve_until_shutdown(prepared, shutdown_signal()).await
}

pub async fn serve_until_shutdown(
    prepared: PreparedServer,
    shutdown: impl Future<Output = Result<()>>,
) -> Result<()> {
    let PreparedServer {
        bind,
        app,
        shutdown_grace,
        webhook_worker,
        attachment_verification_worker,
        review_worker,
        access_log_retention,
        metrics,
        #[cfg(feature = "wasm")]
            wasm_runtime: _wasm_runtime,
        ..
    } = prepared;
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|_| StartupError::Listener)?;
    // Bound before the listening event so a configured metrics listener is
    // either serving or startup has already refused.
    let metrics = match metrics {
        Some(metrics) => {
            let listener = TcpListener::bind(metrics.bind)
                .await
                .map_err(|_| StartupError::Listener)?;
            Some((metrics.app, listener))
        }
        None => None,
    };
    OperationalEvent::Listening.emit();
    let (worker_shutdown_tx, worker_shutdown_rx) = watch::channel(false);
    let (task_stopped_tx, mut task_stopped_rx) = mpsc::unbounded_channel();
    let mut verification_worker = attachment_verification_worker.map(|worker| {
        SupervisedTask::spawn(
            BackgroundTask::AttachmentVerificationWorker,
            worker.run(worker_shutdown_rx.clone()),
            worker_shutdown_rx.clone(),
            task_stopped_tx.clone(),
        )
    });
    let mut review_worker = review_worker.map(|worker| {
        SupervisedTask::spawn(
            BackgroundTask::ReviewWorker,
            worker.run(worker_shutdown_rx.clone()),
            worker_shutdown_rx.clone(),
            task_stopped_tx.clone(),
        )
    });
    let mut access_log_worker = access_log_retention.map(|(pool, last_success)| {
        SupervisedTask::spawn(
            BackgroundTask::SubjectAccessLogRetention,
            crate::subject_access_log::run_retention(
                pool,
                last_success,
                worker_shutdown_rx.clone(),
            ),
            worker_shutdown_rx.clone(),
            task_stopped_tx.clone(),
        )
    });
    let mut worker = webhook_worker.map(|worker| {
        SupervisedTask::spawn(
            BackgroundTask::WebhookWorker,
            worker.run(worker_shutdown_rx.clone()),
            worker_shutdown_rx.clone(),
            task_stopped_tx.clone(),
        )
    });
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let (metrics_shutdown_tx, metrics_shutdown_rx) = oneshot::channel::<()>();
    let mut metrics_server = metrics.map(|(metrics_app, metrics_listener)| {
        SupervisedTask::spawn(
            BackgroundTask::MetricsListener,
            async move {
                axum::serve(metrics_listener, metrics_app)
                    .with_graceful_shutdown(async move {
                        let _ = metrics_shutdown_rx.await;
                    })
                    .await
            },
            worker_shutdown_rx.clone(),
            task_stopped_tx.clone(),
        )
    });
    // Only the supervisors hold senders, so the stop branch below is disabled
    // once every supervised task has finished, and absent when none runs.
    drop(worker_shutdown_rx);
    drop(task_stopped_tx);
    let mut server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
    });
    let exit = tokio::select! {
        result = &mut server => ServeExit::BReg(result),
        signal = shutdown => ServeExit::Signal(signal),
        Some(_) = task_stopped_rx.recv() => ServeExit::TaskStopped,
    };
    let mut server_joined = matches!(exit, ServeExit::BReg(_));
    worker_shutdown_tx.send_replace(true);
    let _ = shutdown_tx.send(());
    let _ = metrics_shutdown_tx.send(());
    let graceful = async {
        let result = match exit {
            ServeExit::BReg(result) => map_server_result(result),
            ServeExit::Signal(signal) => {
                let server_result = map_server_result((&mut server).await);
                server_joined = true;
                signal.and(server_result)
            }
            ServeExit::TaskStopped => {
                let server_result = map_server_result((&mut server).await);
                server_joined = true;
                server_result.and(Err(StartupError::BackgroundTaskStopped))
            }
        };
        if let Some(worker) = worker.as_mut() {
            worker.join().await;
        }
        if let Some(worker) = verification_worker.as_mut() {
            worker.join().await;
        }
        if let Some(worker) = review_worker.as_mut() {
            worker.join().await;
        }
        if let Some(worker) = access_log_worker.as_mut() {
            worker.join().await;
        }
        if let Some(metrics_server) = metrics_server.as_mut() {
            metrics_server.join().await;
        }
        result
    };
    let outcome = match tokio::time::timeout(shutdown_grace, graceful).await {
        Ok(result) => result,
        Err(_) => {
            if !server_joined {
                server.abort();
                let _ = (&mut server).await;
            }
            if let Some(metrics_server) = metrics_server.as_mut() {
                metrics_server.abort_and_join().await;
            }
            if let Some(worker) = worker.as_mut() {
                worker.abort_and_join().await;
            }
            if let Some(worker) = verification_worker.as_mut() {
                worker.abort_and_join().await;
            }
            if let Some(worker) = review_worker.as_mut() {
                worker.abort_and_join().await;
            }
            if let Some(worker) = access_log_worker.as_mut() {
                worker.abort_and_join().await;
            }
            Err(StartupError::Shutdown)
        }
    };
    outcome
}

enum ServeExit {
    BReg(std::result::Result<std::result::Result<(), std::io::Error>, tokio::task::JoinError>),
    Signal(Result<()>),
    TaskStopped,
}

/// One background task `serve` owns. The task runs under a supervisor that
/// reports how it ended; serve cancels the task itself and joins the
/// supervisor, so a joined supervisor means the task has stopped too.
struct SupervisedTask {
    task: BackgroundTask,
    supervisor: tokio::task::JoinHandle<()>,
    cancel: tokio::task::AbortHandle,
    joined: bool,
}

impl SupervisedTask {
    /// Run `future` under a supervisor. A panic is always reported. A return
    /// before `shutdown` turns true is reported and sent on `stopped`, which
    /// ends serve; a return after it is the requested stop. Only the shutdown
    /// grace timeout cancels a task, and serve reports that timeout itself.
    /// A task's own output, such as the metrics listener's accept error,
    /// counts as a return.
    fn spawn<F>(
        task: BackgroundTask,
        future: F,
        shutdown: watch::Receiver<bool>,
        stopped: mpsc::UnboundedSender<BackgroundTask>,
    ) -> Self
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let running = tokio::spawn(future);
        let cancel = running.abort_handle();
        let supervisor = tokio::spawn(async move {
            let stop = match running.await {
                Ok(_) => BackgroundTaskStop::Returned,
                Err(error) if error.is_panic() => BackgroundTaskStop::Panicked,
                Err(_) => return,
            };
            let requested = *shutdown.borrow();
            if requested && stop == BackgroundTaskStop::Returned {
                return;
            }
            OperationalEvent::BackgroundTaskStopped(task, stop).emit();
            if !requested {
                // serve holds the receiver until it has joined every
                // supervisor, so a refused send means serve is already
                // stopping and has nothing left to end.
                let _ = stopped.send(task);
            }
        });
        Self {
            task,
            supervisor,
            cancel,
            joined: false,
        }
    }

    /// Wait for the supervisor once. A supervisor that panicked is reported
    /// as its task panicking.
    async fn join(&mut self) {
        if self.joined {
            return;
        }
        let joined = (&mut self.supervisor).await;
        self.joined = true;
        if joined.is_err() {
            OperationalEvent::BackgroundTaskStopped(self.task, BackgroundTaskStop::Panicked).emit();
        }
    }

    async fn abort_and_join(&mut self) {
        self.cancel.abort();
        self.join().await;
    }
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|_| StartupError::Shutdown)?;
        first_shutdown_signal(tokio::signal::ctrl_c(), terminate.recv()).await
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|_| StartupError::Shutdown)
    }
}

#[cfg(unix)]
async fn first_shutdown_signal<C, T, E>(ctrl_c: C, terminate: T) -> Result<()>
where
    C: Future<Output = std::result::Result<(), E>>,
    T: Future<Output = Option<()>>,
{
    tokio::select! {
        result = ctrl_c => result.map_err(|_| StartupError::Shutdown),
        result = terminate => result.ok_or(StartupError::Shutdown),
    }
}

fn map_server_result(
    result: std::result::Result<std::result::Result<(), std::io::Error>, tokio::task::JoinError>,
) -> Result<()> {
    match result {
        Ok(Ok(())) => Ok(()),
        _ => Err(StartupError::Listener),
    }
}

pub fn operational_log_level(value: Option<&str>) -> Result<LevelFilter> {
    match value.unwrap_or("info") {
        "error" => Ok(LevelFilter::ERROR),
        "warn" => Ok(LevelFilter::WARN),
        "info" => Ok(LevelFilter::INFO),
        _ => Err(StartupError::Logging),
    }
}

/// Verify the complete local package first, then require the configured
/// database id, the package digest as the active package, the schema
/// fingerprint, ready maintenance state, ownership, RLS, and ACL catalog
/// before returning a listener gate.
pub async fn prepare_startup(
    package_root: &Path,
    context: &PackageLoadContext<'_>,
    database_id: &str,
    client: &mut Client,
    migration_role: &SqlIdentifier,
    runtime_role: &SqlIdentifier,
) -> Result<VerifiedStartup> {
    let shared = registry_platform_config::package::verify_package(
        package_root,
        &crate::package::shared_package_limits(),
        "bregctl package",
    )
    .map_err(|error| StartupError::PackageEnvelopeRefused(error.to_string()))?;
    // Ordering is security-relevant: no database call precedes package closure
    // and compiler-derivation verification.
    let package = load_package_with_verified_envelope(package_root, context, &shared)
        .map_err(StartupError::PackageRefused)?;
    prepare_loaded_startup(package, database_id, client, migration_role, runtime_role).await
}

/// Verify database readiness for a package already loaded through the runtime
/// configuration's retained shared envelope.
pub(crate) async fn prepare_loaded_startup(
    package: VerifiedPackage,
    database_id: &str,
    client: &mut Client,
    migration_role: &SqlIdentifier,
    runtime_role: &SqlIdentifier,
) -> Result<VerifiedStartup> {
    verify_opened_startup(
        package,
        database_id,
        client,
        migration_role,
        runtime_role,
        StartupPurpose::Inspect,
    )
    .await
}

/// Who opens the verified startup, which decides whether the instance claim
/// is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartupPurpose {
    /// The serving runtime, which refuses a database its claim does not name.
    Serve,
    /// Operator tooling, which must keep working on a copy so the copy can be
    /// inspected, verified, and adopted.
    Inspect,
}

async fn verify_opened_startup(
    package: VerifiedPackage,
    database_id: &str,
    client: &mut Client,
    migration_role: &SqlIdentifier,
    runtime_role: &SqlIdentifier,
    purpose: StartupPurpose,
) -> Result<VerifiedStartup> {
    let manifest = package.manifest();
    let lock_key =
        RegistryLockKey::derive(&manifest.package_id).map_err(|_| StartupError::DatabaseUnready)?;
    let expected_catalog = ExpectedManagedCatalog::compiled(package.registry());
    let transaction = client
        .transaction()
        .await
        .map_err(|_| StartupError::DatabaseUnready)?;
    transaction
        .batch_execute("SET LOCAL lock_timeout = '5s'")
        .await
        .map_err(|_| StartupError::DatabaseUnready)?;
    crate::postgres::verify_postgres_17_or_newer(&transaction)
        .await
        .map_err(|_| StartupError::DatabaseUnready)?;
    transaction
        .execute(
            "SELECT pg_advisory_xact_lock_shared($1)",
            &[&lock_key.get()],
        )
        .await
        .map_err(|_| StartupError::DatabaseUnready)?;
    // A database no package was applied to, or one holding registry state
    // this release does not recognise, is named before any check that reads
    // the state it lacks.
    match crate::postgres::registry_state_shape(&transaction)
        .await
        .map_err(|_| StartupError::DatabaseUnready)?
    {
        crate::postgres::RegistryStateShape::Absent => {
            return Err(StartupError::DatabaseUninitialized)
        }
        crate::postgres::RegistryStateShape::Unrecognized => {
            return Err(StartupError::UnrecognizedDatabase)
        }
        crate::postgres::RegistryStateShape::Ledger => {}
    }
    verify_configured_runtime_role(&transaction, migration_role, runtime_role).await?;
    let expected_catalog =
        crate::postgres::installed_managed_catalog(&transaction, &expected_catalog)
            .await
            .map_err(|_| StartupError::DatabaseUnready)?
            .into_owned();
    // A separate runtime role missing its grants may not even read the state
    // the checks below read, so the grants are checked first.
    verify_runtime_grants(
        &transaction,
        &expected_catalog,
        migration_role,
        runtime_role,
    )
    .await?;
    if package.registry().ddl().requires_postgis {
        crate::postgres::verify_postgis(&transaction, migration_role, runtime_role)
            .await
            .map_err(|_| StartupError::DatabaseUnready)?;
    }
    // The physical claim is checked before the recorded identity, so a
    // restored copy is named as a copy whatever package or database id it
    // records.
    if purpose == StartupPurpose::Serve {
        verify_instance_claim(&transaction).await?;
    }
    let expected = recorded_startup_identity(&transaction, &package, database_id).await?;
    verify_single_role_activation(&transaction, &expected, migration_role, runtime_role).await?;
    verify_catalog_identity_for_catalog(
        &transaction,
        &expected,
        &expected_catalog,
        migration_role,
        runtime_role,
    )
    .await
    .map_err(|_| StartupError::DatabaseUnready)?;
    transaction
        .commit()
        .await
        .map_err(|_| StartupError::DatabaseUnready)?;
    Ok(VerifiedStartup {
        package,
        expected,
        expected_catalog,
        lock_key,
    })
}

/// Read the registry state the database records and bind it to this
/// deployment and package.
///
/// Threat: a runtime pointed at another database, or at a package the
/// database never activated, would serve one registry's rows under another
/// package's contract. Enforcement: the recorded database id must equal the
/// runtime file's `identity.databaseId`, and the recorded active package must
/// be this package's digest; each mismatch has its own refusal. The recorded
/// activation is the database's own and is carried unchanged into the
/// expected identity every later check compares.
async fn recorded_startup_identity(
    client: &impl GenericClient,
    package: &VerifiedPackage,
    database_id: &str,
) -> Result<ExpectedRegistryIdentity> {
    let row = client
        .query_opt(
            "SELECT package_id, database_id, active_package_digest,
                    active_activation_id::text, maintenance_status
             FROM registry_internal.registry_state
             WHERE singleton",
            &[],
        )
        .await
        .map_err(|_| StartupError::DatabaseUnready)?
        .ok_or(StartupError::DatabaseUnready)?;
    let manifest = package.manifest();
    if row.get::<_, String>(0) != manifest.package_id {
        return Err(StartupError::DatabaseUnready);
    }
    if row.get::<_, String>(1) != database_id {
        return Err(StartupError::DatabaseIdentityMismatch);
    }
    if row.get::<_, String>(2) != package.package_digest() {
        return Err(StartupError::ActivePackageMismatch);
    }
    if row.get::<_, String>(4) != "ready" {
        return Err(StartupError::DatabaseUnready);
    }
    Ok(ExpectedRegistryIdentity {
        package_id: manifest.package_id.clone(),
        database_id: database_id.to_owned(),
        package_digest: package.package_digest().to_owned(),
        activation_id: row.get(3),
        schema_fingerprint: manifest.schema_fingerprint.clone(),
    })
}

struct DynamicRuntimeReadiness {
    pool: RuntimePool,
    expected: ExpectedRegistryIdentity,
    expected_catalog: ExpectedManagedCatalog,
    migration_role: SqlIdentifier,
    runtime_role: SqlIdentifier,
    lock_key: RegistryLockKey,
    key_source: Arc<JwksFetcher>,
    requires_postgis: bool,
    audit_writer: AuditWriter,
}

impl DynamicRuntimeReadiness {
    async fn check(&self) -> Result<()> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| StartupError::DatabaseUnready)?;
        let transaction = client
            .transaction()
            .await
            .map_err(|_| StartupError::DatabaseUnready)?;
        transaction
            .batch_execute("SET LOCAL lock_timeout = '5s'")
            .await
            .map_err(|_| StartupError::DatabaseUnready)?;
        crate::postgres::verify_postgres_17_or_newer(&*transaction)
            .await
            .map_err(|_| StartupError::DatabaseUnready)?;
        transaction
            .execute(
                "SELECT pg_advisory_xact_lock_shared($1)",
                &[&self.lock_key.get()],
            )
            .await
            .map_err(|_| StartupError::DatabaseUnready)?;
        verify_configured_runtime_role(&*transaction, &self.migration_role, &self.runtime_role)
            .await
            .map_err(|_| StartupError::DatabaseUnready)?;
        if self.requires_postgis {
            crate::postgres::verify_postgis(
                &*transaction,
                &self.migration_role,
                &self.runtime_role,
            )
            .await
            .map_err(|_| StartupError::DatabaseUnready)?;
        }
        let maintenance = transaction
            .query_opt(
                "SELECT maintenance_status
                 FROM registry_internal.registry_state
                 WHERE singleton",
                &[],
            )
            .await
            .map_err(|_| StartupError::DatabaseUnready)?
            .ok_or(StartupError::DatabaseUnready)?
            .get::<_, String>(0);
        if maintenance != "ready" {
            return Err(StartupError::DatabaseUnready);
        }
        verify_catalog_identity_for_catalog(
            &*transaction,
            &self.expected,
            &self.expected_catalog,
            &self.migration_role,
            &self.runtime_role,
        )
        .await
        .map_err(|_| StartupError::DatabaseUnready)?;
        verify_instance_claim(&*transaction).await?;
        transaction
            .commit()
            .await
            .map_err(|_| StartupError::DatabaseUnready)?;
        self.key_source
            .ensure_key_set()
            .await
            .map_err(|_| StartupError::Oidc)?;
        // A writer that refused an append refuses every later one, so every
        // audited request would answer audit-unavailable until a restart.
        if !self.audit_writer.ready().await {
            return Err(StartupError::Audit);
        }
        Ok(())
    }
}

/// Bind retained webhook work to the event source this deployment stamps.
///
/// Threat: the delivery worker accepts a stored envelope only when its
/// `source` equals the source `identity.instanceId` derives, so renaming the
/// instance while deliveries are pending would dead-letter each of them
/// silently, one attempt at a time. Enforcement: startup refuses while any
/// pending or leased delivery with an unexpired payload names another source,
/// naming the stored source, the configured instance id, and how many wait.
/// Delivered, dead-lettered, and expired work never reaches the worker again,
/// so it does not hold the rename back.
async fn verify_pending_delivery_source(
    pool: &RuntimePool,
    package_id: &str,
    instance_id: &str,
) -> Result<()> {
    let expected_source = crate::webhook::delivery_source(package_id, instance_id);
    let client = pool
        .get()
        .await
        .map_err(|_| StartupError::DatabaseUnready)?;
    let row = client
        .query_opt(
            "SELECT left(captured.source, 512), count(*)
               FROM (
                   SELECT convert_from(outbox.payload, 'UTF8')::jsonb ->> 'source' AS source
                     FROM registry_internal.registry_webhook_delivery_state AS state
                     JOIN registry_internal.registry_outbox AS outbox
                       ON outbox.event_id = state.event_id
                    WHERE state.state IN ('pending', 'leased')
                      AND outbox.payload IS NOT NULL
                      AND outbox.payload_expires_at > transaction_timestamp()
               ) AS captured
              WHERE captured.source IS NOT NULL
                AND captured.source <> $1
              GROUP BY captured.source
              ORDER BY count(*) DESC, captured.source
              LIMIT 1",
            &[&expected_source],
        )
        .await
        .map_err(|_| StartupError::DatabaseUnready)?;
    let Some(row) = row else {
        return Ok(());
    };
    let stored_source: String = row.try_get(0).map_err(|_| StartupError::DatabaseUnready)?;
    let pending_deliveries: i64 = row.try_get(1).map_err(|_| StartupError::DatabaseUnready)?;
    Err(StartupError::InstanceIdChangedWithPendingDeliveries {
        stored_source,
        configured_instance_id: instance_id.to_owned(),
        pending_deliveries: u64::try_from(pending_deliveries)
            .map_err(|_| StartupError::DatabaseUnready)?,
    })
}

/// Refuse a database the instance claim does not name, by name.
async fn verify_instance_claim(client: &impl GenericClient) -> Result<()> {
    match crate::instance_claim::check(client).await {
        crate::instance_claim::ClaimCheck::Current => Ok(()),
        crate::instance_claim::ClaimCheck::Mismatch => Err(StartupError::InstanceClaimMismatch),
        crate::instance_claim::ClaimCheck::Unavailable => Err(StartupError::DatabaseUnready),
    }
}

impl ReadinessProbe for DynamicRuntimeReadiness {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async move { self.check().await.is_ok() })
    }
}

/// Bind a separate runtime role to the grants the active package gives it.
///
/// Threat: a separate runtime role serving without the grants the package
/// issues, as after a one-role activation or a reassignment, would fail
/// request by request instead of refusing. Enforcement: the role must hold
/// every runtime grant the compiled package issues; the refusal names the
/// apply that reissues them. The separate runtime role cannot read the
/// activation ledger, so its grants are what bind it to the activation.
async fn verify_runtime_grants(
    client: &impl GenericClient,
    expected_catalog: &ExpectedManagedCatalog,
    migration_role: &SqlIdentifier,
    runtime_role: &SqlIdentifier,
) -> Result<()> {
    if migration_role == runtime_role {
        return Ok(());
    }
    if crate::postgres::runtime_grants_missing(client, runtime_role, expected_catalog)
        .await
        .map_err(|_| StartupError::DatabaseUnready)?
    {
        return Err(StartupError::RuntimeGrantsMissing);
    }
    Ok(())
}

/// Bind a one-role runtime file to an activation recorded for one role.
///
/// Threat: one role serving a database the ledger records as guarded by a
/// separate runtime role would drop that separation without an activation
/// recording it. Enforcement: the active activation must record the single
/// role mode; the refusal names the apply that activates it for one role.
async fn verify_single_role_activation(
    client: &impl GenericClient,
    expected: &ExpectedRegistryIdentity,
    migration_role: &SqlIdentifier,
    runtime_role: &SqlIdentifier,
) -> Result<()> {
    if migration_role != runtime_role {
        return Ok(());
    }
    let recorded: String = client
        .query_opt(
            "SELECT role_mode
               FROM registry_internal.registry_migrations
              WHERE activation_id = $1::text::uuid",
            &[&expected.activation_id],
        )
        .await
        .map_err(|_| StartupError::DatabaseUnready)?
        .ok_or(StartupError::DatabaseUnready)?
        .get(0);
    if recorded != RoleMode::Single.as_str() {
        return Err(StartupError::RoleModeChanged);
    }
    Ok(())
}

async fn verify_configured_runtime_role(
    client: &impl GenericClient,
    migration_role: &SqlIdentifier,
    runtime_role: &SqlIdentifier,
) -> Result<()> {
    let row = client
        .query_one(
            "SELECT current_user,
                    rolsuper,
                    rolbypassrls,
                    rolcreatedb,
                    rolcreaterole,
                    current_user = $1,
                    pg_has_role(current_user, $1, 'MEMBER'),
                    has_database_privilege(current_user, current_database(), 'CREATE'),
                    has_schema_privilege(current_user, 'registry_internal', 'CREATE'),
                    has_schema_privilege(current_user, 'registry_data', 'CREATE'),
                    has_schema_privilege(current_user, 'registry_source', 'CREATE'),
                    has_schema_privilege(current_user, 'registry_derived', 'CREATE'),
                    has_schema_privilege(current_user, 'registry_context', 'CREATE'),
                    EXISTS (
                        SELECT 1
                        FROM pg_catalog.pg_class c
                        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname IN (
                            'registry_internal',
                            'registry_data',
                            'registry_source',
                            'registry_derived',
                            'registry_context'
                        )
                          AND c.relowner = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)
                    )
             FROM pg_catalog.pg_roles
             WHERE rolname = current_user",
            &[&migration_role.as_str()],
        )
        .await
        .map_err(|_| StartupError::DatabaseUnready)?;
    let actual_role: String = row.get(0);
    if actual_role != runtime_role.as_str() {
        return Err(StartupError::DatabaseUnready);
    }
    // A separate runtime role that can write the activation ledger or the
    // registry state is named, so the operator runs the apply that names the
    // object and the fix.
    if migration_role != runtime_role
        && crate::postgres::find_runtime_write_authority(client, migration_role, runtime_role)
            .await
            .map_err(|_| StartupError::DatabaseUnready)?
            .is_some()
    {
        return Err(StartupError::RuntimeWriteAuthority);
    }
    // Superuser, row-security bypass, role and database creation are refused in
    // either role mode. In single-role mode the runtime role is the migration
    // role, so it owns the managed schemas and their objects by design.
    let refused: &[usize] = if migration_role == runtime_role {
        &[1, 2, 3, 4, 7]
    } else {
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
    };
    if refused.iter().any(|index| row.get::<_, bool>(*index)) {
        return Err(StartupError::DatabaseUnready);
    }
    Ok(())
}
