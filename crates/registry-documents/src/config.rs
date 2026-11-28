// SPDX-License-Identifier: Apache-2.0

//! The operator runtime configuration document.
//!
//! The document is read through the shared runtime loader, so its envelope,
//! keys, and value types are refused exactly as every Registry Stack runtime
//! refuses them. The rules below are the ones a document must satisfy on its
//! own; each finding names the member it concerns and never a configured
//! value.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::Path;

use registry_documents_core::{
    DocumentsProject, HookHandler, DOCUMENTS_RUNTIME_API_VERSION, DOCUMENTS_RUNTIME_KIND,
};
use registry_platform_audit::{
    AuditDestination, AuditDestinationError, AuditDestinationKind, MAX_AUDIT_RETAIN_DAYS,
    MIN_AUDIT_ROTATE_BYTES,
};
use registry_platform_config::JwksSource;
use registry_platform_config::{
    AccessTokenType, CallerIssuerCore, CallerIssuerEntry, CallerIssuers, ConfigBlockError,
    DeclaredPosture, DevelopmentClass, DevelopmentSetting, DevelopmentWitness,
    FoundExplicitSetting, Gated, OidcClientsConfig, Posture, PostureReport, PostureSource,
    RemovedKey, RuntimeConfigLoader, RuntimeEnvelope, RuntimeFileCheck, SecretResolver,
    DEFAULT_STAND_IN,
};
pub use registry_platform_config::{
    AdmittedClients, AttachmentVerifierConfig, AuditKeyConfig, DatabaseConfig,
    MetricsListenerConfig, ObjectStorageConfig, PackageClients, PackageClientsError, PackageConfig,
    PrivateListenerConfig as ListenerConfig, SecretProvidersConfig, TlsTermination,
    UrlHookDestinationConfig,
};
use registry_platform_httputil::{client::transport_protects_the_credential, PeerPolicy};
use registry_platform_objectstore::{s3::S3Settings, verifier::HttpVerifierSettings};
use registry_platform_oidc::{
    fetch_discovery_for_issuer, parse_static_jwks, AccessTokenAlgorithm, DeclaredKinds,
    IssuerNetworkPolicy, JwksFetcher, JwksFetcherConfig, OidcDiscoveryConfig, OidcError,
    TokenVerifierConfig,
};
use registry_platform_yaml::{BoundedU32, BoundedU64, Diagnostic, LocalId, Report};
use serde::Deserialize;
use thiserror::Error;

use crate::auth::IssuerSource;

pub(crate) use registry_platform_config::describe_secret_failure;

/// The default listener binding. Each Registry Stack runtime has its own
/// default port so a laptop can run several side by side.
pub const DEFAULT_LISTENER_BIND: &str = "127.0.0.1:8116";

/// The stand-in for a `metricsListener.bind` expression the offline check
/// does not substitute. It differs from [`DEFAULT_LISTENER_BIND`].
const DEFAULT_METRICS_BIND: &str = "127.0.0.1:9100";

pub const DOCUMENTS_RUNTIME_ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: DOCUMENTS_RUNTIME_API_VERSION,
    kind: DOCUMENTS_RUNTIME_KIND,
};

/// The keys the runtime document refuses with the sentence naming what
/// replaced them (CFG-CHANGE-2): the members of the one issuer block, now
/// declared per issuer entry.
const DOCUMENTS_REMOVED_KEYS: &[RemovedKey] = &[
    RemovedKey {
        path: "authentication.oidc.issuer",
        replacement: "declare it under authentication.oidc.issuers.ISSUER_ID",
    },
    RemovedKey {
        path: "authentication.oidc.audience",
        replacement: "declare it under authentication.oidc.issuers.ISSUER_ID",
    },
    RemovedKey {
        path: "authentication.oidc.jwksUri",
        replacement:
            "declare it under authentication.oidc.issuers.ISSUER_ID as jwksSource with type: uri",
    },
    RemovedKey {
        path: "authentication.oidc.jwksSource",
        replacement: "declare it under authentication.oidc.issuers.ISSUER_ID",
    },
    RemovedKey {
        path: "authentication.oidc.allowInsecureHttp",
        replacement: "declare it under authentication.oidc.issuers.ISSUER_ID",
    },
    RemovedKey {
        path: "authentication.oidc.allowedClients",
        replacement: "declare it under authentication.oidc.issuers.ISSUER_ID",
    },
    RemovedKey {
        path: "authentication.oidc.assertionIssuers",
        replacement: "declare it under authentication.oidc.issuers.ISSUER_ID",
    },
    RemovedKey {
        path: "authentication.oidc.scopeClaim",
        replacement: "declare it under authentication.oidc.issuers.ISSUER_ID",
    },
];

/// The JSON Pointer of the `issuers` member.
const ISSUERS_POINTER: &str = "/authentication/oidc/issuers";

const METRICS_LISTENER_CODE: &str = "documents.runtime.invalid-metrics-listener";
/// The config path of the exposure key a wildcard metrics refusal names.
const METRICS_NETWORK_EXPOSURE_KEY: &str = "metricsListener.networkExposure";
const METRICS_OVERLAP_CODE: &str = "documents.runtime.metrics-listener-overlaps-listener";

/// The largest transfer deadline floor, in seconds.
pub const MAXIMUM_TRANSFER_DEADLINE_SECONDS: u32 = 3_600;

/// The largest allowance per mebibyte transferred, in seconds.
pub const MAXIMUM_MEBIBYTE_ALLOWANCE_SECONDS: u32 = 600;

/// The longest a submission receipt may be retained, in days.
pub const MAXIMUM_RECEIPT_RETENTION_DAYS: u32 = 365;

/// The longest a hook payload may be retained, in days.
pub const MAXIMUM_HOOK_PAYLOAD_RETENTION_DAYS: u32 = 30;

/// The largest `audit.rotateBytes`.
pub const MAXIMUM_AUDIT_ROTATE_BYTES: u64 = u32::MAX as u64;

const ALLOWED_CLIENTS_REQUIRED_CODE: &str = "documents.runtime.allowed-clients-required";
const PROFILE_CLIENT_NOT_ALLOWED_CODE: &str = "documents.runtime.profile-client-not-allowed";
const ASSERTION_ISSUER_CLIENT_NOT_ALLOWED_CODE: &str =
    "documents.runtime.assertion-issuer-client-not-allowed";
const CLIENT_IN_TWO_ISSUERS_CODE: &str = "platform.oidc.client-in-two-issuers";
const AUDIENCE_IS_A_CLIENT_CODE: &str = "platform.oidc.audience-is-a-client";
const ACTOR_KIND_FOR_UNADMITTED_CLIENT_CODE: &str =
    "platform.oidc.actor-kind-for-unadmitted-client";

/// The code of the refusal a runtime document earns when `destinations.hooks`
/// leaves unbound a destination the project's hooks name. `documentsctl
/// check` reports it at `/destinations/hooks`, and the runtime's startup
/// refusal reports it at the same position.
pub const UNBOUND_HOOK_DESTINATION_CODE: &str = "documents.runtime.unbound-hook-destination";

/// What the unbound hook destination refusal says, wherever it is reported.
pub const UNBOUND_HOOK_DESTINATION_MESSAGE: &str =
    "destinations.hooks must bind every destination documents.yaml hooks[].handler.destinationId names";

/// What an operator does about the unbound hook destination refusal.
pub const UNBOUND_HOOK_DESTINATION_ACTION: &str =
    "Add a destinations.hooks entry for each destination documents.yaml hooks[].handler.destinationId names.";

/// The operator runtime configuration document.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    pub api_version: String,
    pub kind: String,
    /// Optional in the type so a missing block gets a refusal naming the key
    /// to add; the document requires it.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(required, with = "IdentityConfig"))]
    pub identity: Option<IdentityConfig>,
    pub package: PackageConfig,
    pub listener: ListenerConfig,
    /// The operator-private listener that serves `/metrics`. Omit it to
    /// serve no metrics.
    #[serde(default)]
    pub metrics_listener: Option<MetricsListenerConfig>,
    pub secret_providers: SecretProvidersConfig,
    pub database: DatabaseConfig,
    pub authentication: AuthenticationConfig,
    pub audit: AuditConfig,
    pub storage: StorageConfig,
    #[serde(default)]
    pub transfers: TransfersConfig,
    pub content_verification: Gated<ContentVerificationConfig>,
    #[serde(skip)]
    #[cfg_attr(feature = "schema", schemars(skip))]
    pub posture: Option<PostureReport>,
    #[serde(skip)]
    #[cfg_attr(feature = "schema", schemars(skip))]
    declared: Option<DeclaredPosture>,
    #[serde(skip)]
    #[cfg_attr(feature = "schema", schemars(skip))]
    pub development: Option<DevelopmentWitness>,
    pub cleanup: CleanupConfig,
    #[serde(default)]
    pub destinations: DestinationsConfig,
    #[serde(default)]
    pub retention: RetentionConfig,
}

/// The logical database identity this deployment owns. It is independent of
/// the connection URL and PostgreSQL database name.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityConfig {
    pub database_id: LocalId,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticationConfig {
    pub oidc: OidcConfig,
}

/// The OIDC issuers whose access tokens this runtime accepts, each with the
/// clients it admits and the claim carrying their scopes.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OidcConfig {
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-issuers"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    pub issuers: CallerIssuers<IssuerConfig>,
}

/// One issuer the Document Store accepts access tokens from: the shared
/// caller-issuer members and the assertion authorities each client may
/// exchange from.
///
/// `allowedClients` is `from-package` for the requester clients of the
/// project's access profiles, or a list. Every access profile resolves its
/// caller from the matched client, so the admitted set is never empty and
/// `unrestricted` is refused. A client belongs to one issuer, and the lists of
/// all entries together cover every client a profile names.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssuerConfig {
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-issuer-core"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    core: CallerIssuerCore<PackageClients>,
    /// Assertion authorities each client may exchange a subject token from,
    /// keyed by client identifier. Omitted, no assertion-issuer rule applies
    /// and a token that arrived through an exchange is refused. Written, it
    /// lists at least one client, each with at least one authority.
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "registry_platform_config::non_empty_assertion_issuers"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "registry_platform_config::assertion_issuers_schema")
    )]
    pub assertion_issuers: BTreeMap<String, Vec<String>>,
}

impl CallerIssuerEntry for IssuerConfig {
    type Clients = PackageClients;

    fn core(&self) -> &CallerIssuerCore<PackageClients> {
        &self.core
    }
}

/// Where the audit journal is written and the key its hashes are made with.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditConfig {
    /// The secret keying the audit journal's hashes, `hashKeyRef`.
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/audit-key"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    pub key: AuditKeyConfig,
    /// Where audit entries go: a rotated `file` (the default) or `stdout`.
    #[serde(default)]
    pub destination: AuditDestinationKind,
    /// The absolute path of the active audit file, for `destination: file`.
    #[serde(default)]
    pub path: Option<std::path::PathBuf>,
    /// The size at which the active file is sealed and a new one begun,
    /// for `destination: file`; 100 MiB when omitted.
    #[serde(default)]
    pub rotate_bytes: Option<BoundedU64<MIN_AUDIT_ROTATE_BYTES, MAXIMUM_AUDIT_ROTATE_BYTES>>,
    /// How many days a sealed audit file is kept, for `destination: file`;
    /// 90 when omitted.
    #[serde(default)]
    pub retention_days: Option<BoundedU32<1, MAX_AUDIT_RETAIN_DAYS>>,
}

impl AuditConfig {
    /// The destination this block names, with its rotation and retention.
    pub fn destination(&self) -> Result<AuditDestination, AuditDestinationError> {
        AuditDestination::from_settings(
            self.destination,
            self.path.clone(),
            self.rotate_bytes.map(u64::from),
            self.retention_days.map(u32::from),
        )
    }
}

/// The member an audit destination refusal concerns, as a JSON pointer.
fn audit_pointer(error: &AuditDestinationError) -> &'static str {
    match error {
        AuditDestinationError::FileOnlyField {
            field: "rotateBytes",
        }
        | AuditDestinationError::RotateBytesOutOfRange { .. } => "/audit/rotateBytes",
        AuditDestinationError::FileOnlyField {
            field: "retainDays",
        }
        | AuditDestinationError::RetainDaysOutOfRange { .. } => "/audit/retentionDays",
        _ => "/audit",
    }
}

/// An audit destination refusal in the runtime document's own spelling.
fn audit_message(error: &AuditDestinationError) -> String {
    match error {
        AuditDestinationError::FileOnlyField {
            field: "retainDays",
        } => "audit.retentionDays applies only when audit.destination is file".to_owned(),
        AuditDestinationError::RetainDaysOutOfRange { maximum } => {
            format!("audit.retentionDays must be between 1 and {maximum}")
        }
        error => error.to_string(),
    }
}

fn audit_action(error: &AuditDestinationError) -> &'static str {
    match error {
        AuditDestinationError::FileOnlyField { .. } => {
            "Remove the member, or set audit.destination: file."
        }
        AuditDestinationError::RotateBytesOutOfRange { .. }
        | AuditDestinationError::RetainDaysOutOfRange { .. } => {
            "Write a value within the range the message names, or remove the member to use its default."
        }
        _ => "Write audit.path as an absolute file path for destination file, or choose destination stdout.",
    }
}

/// The largest document version held in PostgreSQL, and the default
/// ceiling for either storage type: 16 MiB, in line with BReg.
pub const DATABASE_MAXIMUM_DOCUMENT_BYTES: u64 = 16 * 1024 * 1024;

/// The largest document version held in S3: 64 MiB. The upload body is
/// buffered in memory, so the ceiling stays a small multiple of the
/// database one.
pub const S3_MAXIMUM_DOCUMENT_BYTES: u64 = 64 * 1024 * 1024;

/// Where document version bytes are held.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
#[derive(Clone, Debug, Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum StorageConfig {
    /// Document version bytes held in PostgreSQL `bytea`.
    Database {
        /// The deployment ceiling on one document version; a policy's
        /// mandatory restriction may only be lower. Omitted, 16 MiB.
        #[serde(default = "default_database_maximum_document_bytes")]
        maximum_document_bytes: BoundedU64<1, DATABASE_MAXIMUM_DOCUMENT_BYTES>,
    },
    /// Document version bytes held in one S3-compatible bucket, under
    /// server-chosen opaque keys.
    S3 {
        /// The bucket and the runtime's credentials for it. Boxed: the
        /// bucket settings are several times the size of the database
        /// variant.
        #[serde(rename(deserialize = "registry-platform-yaml/shared-block/object-storage"))]
        #[cfg_attr(feature = "schema", schemars(flatten))]
        settings: Box<ObjectStorageConfig>,
        /// The deployment ceiling on one document version; a policy's
        /// mandatory restriction may only be lower. Omitted, 16 MiB.
        #[serde(default = "default_s3_maximum_document_bytes")]
        maximum_document_bytes: BoundedU64<1, S3_MAXIMUM_DOCUMENT_BYTES>,
    },
}
registry_platform_yaml::tagged_union!(StorageConfig);

fn default_database_maximum_document_bytes() -> BoundedU64<1, DATABASE_MAXIMUM_DOCUMENT_BYTES> {
    BoundedU64::new(DATABASE_MAXIMUM_DOCUMENT_BYTES)
        .expect("the database ceiling is within its own bounds")
}

fn default_s3_maximum_document_bytes() -> BoundedU64<1, S3_MAXIMUM_DOCUMENT_BYTES> {
    BoundedU64::new(DATABASE_MAXIMUM_DOCUMENT_BYTES)
        .expect("the database ceiling is within the S3 bounds")
}

impl StorageConfig {
    /// The deployment ceiling on one document version, in bytes.
    #[must_use]
    pub fn maximum_document_bytes(&self) -> u64 {
        match self {
            Self::Database {
                maximum_document_bytes,
            } => u64::from(*maximum_document_bytes),
            Self::S3 {
                maximum_document_bytes,
                ..
            } => u64::from(*maximum_document_bytes),
        }
    }
}

/// The content verifier every document version passes before it becomes
/// releasable.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
#[derive(Clone, Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ContentVerificationConfig {
    /// An HTTP verifier the runtime asks about each document version.
    Http {
        /// The verifier URL, its credential, policy generation, and attempt
        /// timeout.
        #[serde(rename(deserialize = "registry-platform-yaml/shared-block/attachment-verifier"))]
        #[cfg_attr(feature = "schema", schemars(flatten))]
        settings: AttachmentVerifierConfig,
    },
    /// No verifier, accepted only when the process declares development.
    /// Every finalized version is recorded as
    /// approved under the `disabled` verifier binding.
    Disabled {},
}
registry_platform_yaml::tagged_union!(ContentVerificationConfig);

static DOCUMENTS_CONTENT_VERIFICATION_DISABLED: DevelopmentSetting = DevelopmentSetting {
    code: "documents.posture.content-verification-disabled",
    key: "contentVerification",
    summary: "Finalized document versions are approved without content verification.",
    production: "Configure an HTTP content verifier.",
};

impl DevelopmentClass for ContentVerificationConfig {
    const SETTINGS: &'static [&'static DevelopmentSetting] =
        &[&DOCUMENTS_CONTENT_VERIFICATION_DISABLED];

    fn development_setting(&self) -> Option<&'static DevelopmentSetting> {
        match self {
            Self::Disabled {} => Some(&DOCUMENTS_CONTENT_VERIFICATION_DISABLED),
            Self::Http { .. } => None,
        }
    }
}

impl std::fmt::Debug for ContentVerificationConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Http { .. } => "ContentVerificationConfig::Http(<redacted>)",
            Self::Disabled {} => "ContentVerificationConfig::Disabled",
        })
    }
}

/// Erasure of the bytes of documents whose custodian asked for their
/// removal.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CleanupConfig {
    pub erasure: Erasure,
}

/// Whether erasure work runs. `paused` stops every erasure and the sweep
/// of orphaned objects; a removal request still stops release at once, and
/// lapsed uploads are still expired.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Erasure {
    Active,
    Paused,
}

/// Where the project's hooks deliver, by destination id.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DestinationsConfig {
    /// Logical URL hook destinations. The project names only these ids; the
    /// URL, signing key, and delivery budget stay deployment-owned. At most
    /// 128 are bound, each keyed by a local identifier.
    #[serde(
        default,
        deserialize_with = "registry_platform_config::url_hook_destinations"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "registry_platform_config::url_hook_destinations_schema")
    )]
    pub hooks: BTreeMap<String, UrlHookDestinationConfig>,
}

/// How long one upload or download may take: a floor, plus an allowance
/// for every mebibyte the document carries. A transfer still running at its
/// deadline is cut off and lets go of its bytes.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransfersConfig {
    /// The deadline of the smallest transfer.
    #[serde(default = "default_minimum_deadline_seconds")]
    pub minimum_deadline_seconds: BoundedU32<1, MAXIMUM_TRANSFER_DEADLINE_SECONDS>,
    /// The time added for every started mebibyte of the document.
    #[serde(default = "default_mebibyte_allowance_seconds")]
    pub mebibyte_allowance_seconds: BoundedU32<1, MAXIMUM_MEBIBYTE_ALLOWANCE_SECONDS>,
}

impl Default for TransfersConfig {
    fn default() -> Self {
        Self {
            minimum_deadline_seconds: default_minimum_deadline_seconds(),
            mebibyte_allowance_seconds: default_mebibyte_allowance_seconds(),
        }
    }
}

fn default_minimum_deadline_seconds() -> BoundedU32<1, MAXIMUM_TRANSFER_DEADLINE_SECONDS> {
    BoundedU32::new(60).expect("sixty seconds is within the transfer deadline bounds")
}

fn default_mebibyte_allowance_seconds() -> BoundedU32<1, MAXIMUM_MEBIBYTE_ALLOWANCE_SECONDS> {
    BoundedU32::new(8).expect("eight seconds is within the mebibyte allowance bounds")
}

/// Retention periods, in days. A jurisdiction's retention schedule approves
/// the deployed values; the bounds only keep a typo from becoming a policy.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetentionConfig {
    #[serde(default = "default_receipt_retention_days")]
    pub receipt_retention_days: BoundedU32<1, MAXIMUM_RECEIPT_RETENTION_DAYS>,
    #[serde(default = "default_hook_payload_retention_days")]
    pub hook_payload_retention_days: BoundedU32<1, MAXIMUM_HOOK_PAYLOAD_RETENTION_DAYS>,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            receipt_retention_days: default_receipt_retention_days(),
            hook_payload_retention_days: default_hook_payload_retention_days(),
        }
    }
}

fn default_receipt_retention_days() -> BoundedU32<1, MAXIMUM_RECEIPT_RETENTION_DAYS> {
    BoundedU32::new(7).expect("seven days is within the receipt retention bounds")
}

fn default_hook_payload_retention_days() -> BoundedU32<1, MAXIMUM_HOOK_PAYLOAD_RETENTION_DAYS> {
    BoundedU32::new(7).expect("seven days is within the hook payload retention bounds")
}

/// One rule the runtime document breaks: the member it concerns, as a JSON
/// pointer, and what to do about it. It never carries a configured value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Finding {
    pub code: String,
    pub pointer: String,
    pub message: String,
    pub suggested_action: String,
    /// Another member the finding involves, as a JSON pointer, and what it
    /// holds that matters here.
    pub related: Option<(String, String)>,
}

impl Finding {
    fn new(
        code: impl Into<String>,
        pointer: &str,
        message: impl Into<String>,
        suggested_action: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            pointer: pointer.to_owned(),
            message: message.into(),
            suggested_action: suggested_action.into(),
            related: None,
        }
    }

    fn related(mut self, pointer: String, note: impl Into<String>) -> Self {
        self.related = Some((pointer, note.into()));
        self
    }

    fn block(pointer: &str, error: &ConfigBlockError) -> Self {
        Self::new(
            "documents.runtime.invalid-block",
            pointer,
            error.to_string(),
            "Correct the member the message names.",
        )
    }
}

/// Why the runtime document was refused.
#[derive(Debug, Error)]
pub enum RuntimeConfigError {
    /// The shared loader refused the file: it could not be read, or its
    /// envelope, keys, or values are not the format.
    #[error("{0}")]
    Load(#[from] registry_platform_config::RuntimeConfigError),
    /// The file decoded and breaks at least one runtime rule.
    #[error("{}", refused(.0))]
    Refused(Vec<Finding>),
    /// The secret providers could not be prepared.
    #[error("the secret providers could not be prepared: {0}")]
    SecretProviders(String),
    /// An issuer entry's discovery document or key set could not be fetched
    /// or read.
    #[error("the OIDC issuer's signing keys could not be loaded")]
    Oidc,
    /// An issuer entry the load checks passed could not be built. The text
    /// names the entry and what it lacked.
    #[error("the issuer configuration is inconsistent: {0}")]
    Inconsistent(String),
    /// The static key set an issuer entry names by `jwksSource.documentRef`
    /// could not be resolved.
    #[error("{0}")]
    OidcJwksSecret(String),
}

/// The static key set the operator pinned at `field`. A document that breaks
/// a key set rule is the operator's to fix, so the refusal says which rule: it
/// never holds a key value.
fn parse_static_key_set(
    field: &str,
    document: &[u8],
) -> Result<jsonwebtoken::jwk::JwkSet, RuntimeConfigError> {
    parse_static_jwks(document).map_err(|error| match error {
        OidcError::StaticKeySet(refusal) => RuntimeConfigError::OidcJwksSecret(format!(
            "the document at {field} was refused: {refusal}"
        )),
        _ => RuntimeConfigError::Oidc,
    })
}

fn refused(findings: &[Finding]) -> String {
    match findings {
        [] => "the runtime configuration was refused".to_owned(),
        [only] => only.message.clone(),
        [first, rest @ ..] => format!(
            "{} (and {} more; run documentsctl check --runtime-config for every finding)",
            first.message,
            rest.len()
        ),
    }
}

pub const DEFAULT_POSTURE: DeclaredPosture = DeclaredPosture {
    posture: Posture::Production,
    source: PostureSource::Default,
};

impl RuntimeConfig {
    #[must_use]
    pub const fn loader() -> RuntimeConfigLoader {
        Self::loader_with_posture(DEFAULT_POSTURE)
    }

    pub const fn loader_with_posture(declared: DeclaredPosture) -> RuntimeConfigLoader {
        RuntimeConfigLoader::new(DOCUMENTS_RUNTIME_ENVELOPE, declared)
            .removed_keys(DOCUMENTS_REMOVED_KEYS)
            .require_trusted_ownership()
    }

    /// Load and check the operator document at an absolute path, reading
    /// `${VAR}` expressions from the process environment.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RuntimeConfigError> {
        Self::load_with_posture(path, DEFAULT_POSTURE)
    }

    pub fn load_with_posture(
        path: impl AsRef<Path>,
        declared: DeclaredPosture,
    ) -> Result<Self, RuntimeConfigError> {
        let loaded = Self::loader_with_posture(declared).load::<Self>(path.as_ref())?;
        loaded.posture.decide(path.as_ref())?;
        let mut config = loaded.config;
        config.posture = Some(loaded.posture);
        config.declared = Some(declared);
        config.development = loaded.development;
        let findings = config.findings();
        if findings.is_empty() {
            Ok(config)
        } else {
            Err(RuntimeConfigError::Refused(findings))
        }
    }

    pub fn declared_posture(&self) -> DeclaredPosture {
        self.declared.unwrap_or(DEFAULT_POSTURE)
    }

    pub fn peer_policy(&self) -> PeerPolicy {
        match self.declared_posture().posture {
            Posture::Production => PeerPolicy::RefuseDevelopmentPeer,
            Posture::Development => PeerPolicy::AcceptDevelopmentPeer,
        }
    }

    /// The resolver for every secret reference this document names.
    pub fn secret_resolver(&self) -> Result<SecretResolver, RuntimeConfigError> {
        self.secret_providers
            .resolver()
            .map_err(|error| RuntimeConfigError::SecretProviders(error.to_string()))
    }

    /// The entry `id` names.
    fn issuer(&self, id: &str) -> Result<&IssuerConfig, RuntimeConfigError> {
        self.authentication
            .oidc
            .issuers
            .iter()
            .find_map(|(entry_id, entry)| (entry_id.as_str() == id).then_some(entry))
            .ok_or_else(|| {
                RuntimeConfigError::Inconsistent(format!("no issuer entry is named `{id}`"))
            })
    }

    /// Build the key source of the issuer entry `id` from its configured JWKS
    /// source.
    pub async fn jwks_fetcher(
        &self,
        id: &str,
        secrets: &SecretResolver,
    ) -> Result<std::sync::Arc<JwksFetcher>, RuntimeConfigError> {
        let provider = &self.issuer(id)?.core().provider;
        let document_field = format!("authentication.oidc.issuers.{id}.jwksSource.documentRef");
        let network =
            IssuerNetworkPolicy::new(provider.issuer.as_str(), provider.allow_insecure_http)
                .map_err(|_| RuntimeConfigError::Oidc)?;
        let fetcher = match &provider.jwks_source {
            JwksSource::Discovery {} => {
                let (discovery, policy) = fetch_discovery_for_issuer(
                    &OidcDiscoveryConfig {
                        issuer: provider.issuer.to_string(),
                        jwks_uri_override: None,
                        discovery_timeout: std::time::Duration::from_secs(5),
                        max_doc_bytes: 1024 * 1024,
                    },
                    provider.allow_insecure_http,
                )
                .await
                .map_err(|_| RuntimeConfigError::Oidc)?;
                JwksFetcher::new_with_fetch_url_policy(
                    discovery.jwks_uri,
                    JwksFetcherConfig::defaults(),
                    policy,
                )
            }
            JwksSource::Uri { uri } => JwksFetcher::new_with_fetch_url_policy(
                uri.to_string(),
                JwksFetcherConfig::defaults(),
                network.declared_jwks_fetch_policy(),
            ),
            JwksSource::Static { document_ref } | JwksSource::TestIssuer { document_ref } => {
                let document = secrets.resolve(document_ref).map_err(|error| {
                    RuntimeConfigError::OidcJwksSecret(describe_secret_failure(
                        &document_field,
                        document_ref,
                        &error,
                    ))
                })?;
                let jwks = parse_static_key_set(&document_field, document.expose_secret())?;
                JwksFetcher::new_static(jwks, JwksFetcherConfig::defaults())
            }
        };
        Ok(std::sync::Arc::new(fetcher))
    }

    /// The access-token verifier profile of the issuer entry `id`, over the
    /// clients `admitted` resolved for it.
    ///
    /// The entry's `accessTokenType` selects the token media type. An ID token
    /// is refused under either type.
    pub fn verifier_profile(
        &self,
        id: &str,
        admitted: &AdmittedClients,
    ) -> Result<TokenVerifierConfig, RuntimeConfigError> {
        let entry = self.issuer(id)?;
        TokenVerifierConfig::for_caller_issuer(
            entry.core(),
            vec![
                AccessTokenAlgorithm::RS256.to_jsonwebtoken(),
                AccessTokenAlgorithm::ES256.to_jsonwebtoken(),
            ],
            Some(admitted),
        )
        .map(|profile| profile.with_assertion_issuers(entry.assertion_issuers.clone()))
        .map_err(|_| {
            RuntimeConfigError::Inconsistent(format!(
                "the issuer entry `{id}` could not make a verifier profile"
            ))
        })
    }

    /// Every issuer entry as the authenticator takes it: its verifier
    /// profile over the clients resolved against `project`, its signing keys,
    /// and the caller kinds it declares.
    pub async fn issuer_sources(
        &self,
        secrets: &SecretResolver,
        project: &DocumentsProject,
    ) -> Result<Vec<IssuerSource>, RuntimeConfigError> {
        let admitted = self
            .admitted_clients(project)
            .map_err(|finding| RuntimeConfigError::Refused(vec![*finding]))?;
        let mut sources = Vec::new();
        for (id, entry) in self.authentication.oidc.issuers.iter() {
            let id = id.as_str();
            let entry_admitted = admitted.get(id).ok_or_else(|| {
                RuntimeConfigError::Inconsistent(format!(
                    "the issuer entry `{id}` has no resolved clients"
                ))
            })?;
            sources.push(IssuerSource::new(
                id,
                self.verifier_profile(id, entry_admitted)?,
                self.jwks_fetcher(id, secrets).await?,
                DeclaredKinds::from_core(entry.core()).map_err(|_| {
                    RuntimeConfigError::Inconsistent(format!(
                        "the issuer entry `{id}` declares its actor kinds twice"
                    ))
                })?,
            ));
        }
        Ok(sources)
    }

    /// The refusal for an issuer set the entries could not make. The shared
    /// check reports the same rules at load, so this names them when it is
    /// reached after one.
    #[must_use]
    pub fn issuer_set_refusal(&self) -> RuntimeConfigError {
        let findings = self.issuer_findings();
        if findings.is_empty() {
            RuntimeConfigError::Inconsistent(
                "two issuer entries could not be set side by side".to_owned(),
            )
        } else {
            RuntimeConfigError::Refused(findings)
        }
    }

    /// The id of every issuer entry.
    fn issuer_ids(&self) -> Vec<&str> {
        self.authentication
            .oidc
            .issuers
            .iter()
            .map(|(id, _)| id.as_str())
            .collect()
    }

    /// Every rule this document breaks, in document order.
    #[must_use]
    pub fn findings(&self) -> Vec<Finding> {
        let mut findings = self.own_findings();
        findings.extend(self.issuer_findings());
        findings
    }

    /// Every rule this document breaks except the ones the shared issuer
    /// block holds about its entries together. An offline check reports those
    /// through [`CallerIssuers::check_file`], at their positions and with the
    /// entry each involves.
    fn own_findings(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        self.check_identity(&mut findings);
        if let Err(error) = self.package.check() {
            findings.push(Finding::block("/package", &error));
        }
        self.check_listener(&mut findings);
        self.check_metrics_listener(&mut findings);
        self.check_secret_providers(&mut findings);
        self.check_database(&mut findings);
        self.check_oidc(&mut findings);
        self.check_audit(&mut findings);
        self.check_storage(&mut findings);
        self.check_content_verification(&mut findings);
        self.check_hook_destinations(&mut findings);
        findings
    }

    fn check_identity(&self, findings: &mut Vec<Finding>) {
        if self.identity.is_none() {
            findings.push(Finding::new(
                "documents.runtime.missing-identity",
                "/identity",
                "identity.databaseId is required",
                "Add `identity: {databaseId: registry-documents-production}` with a logical id chosen for this deployment.",
            ));
        }
    }

    fn check_listener(&self, findings: &mut Vec<Finding>) {
        if !self.listener.is_valid() {
            findings.push(Finding::new(
                "documents.runtime.invalid-listener",
                "/listener",
                "listener.bind is not allowed for the declared tlsTermination and networkExposure",
                "Bind a loopback address for loopback-plaintext, a loopback or private address behind operator-controlled-upstream, or the unspecified address only with container-private.",
            ));
        }
    }

    fn check_metrics_listener(&self, findings: &mut Vec<Finding>) {
        let Some(metrics) = &self.metrics_listener else {
            return;
        };
        let exposure = metrics.network_exposure;
        let metrics = metrics.bind.socket_addr();
        if let Err(cause) = check_metrics_address(metrics, exposure) {
            findings.push(Finding::new(
                METRICS_LISTENER_CODE,
                "/metricsListener/bind",
                format!("metricsListener.bind is refused: {cause}"),
                cause.remedy(METRICS_NETWORK_EXPOSURE_KEY),
            ));
        } else if let Err(cause) = check_metrics_apart(metrics, self.listener.bind.socket_addr()) {
            findings.push(Finding::new(
                METRICS_OVERLAP_CODE,
                "/metricsListener/bind",
                format!("metricsListener.bind is refused: {cause}"),
                cause.remedy(METRICS_NETWORK_EXPOSURE_KEY),
            ));
        }
    }

    fn check_secret_providers(&self, findings: &mut Vec<Finding>) {
        if let Err(error) = self.secret_providers.check() {
            findings.push(Finding::block("/secretProviders", &error));
            return;
        }
        let mut references: Vec<(String, &str)> = self
            .database
            .references()
            .into_iter()
            .map(|(field, reference)| (field.to_owned(), reference))
            .collect();
        if let StorageConfig::S3 { settings, .. } = &self.storage {
            references.push((
                "storage.accessKeyIdRef".to_owned(),
                settings.access_key_id_ref.as_str(),
            ));
            references.push((
                "storage.secretAccessKeyRef".to_owned(),
                settings.secret_access_key_ref.as_str(),
            ));
            if let Some(reference) = &settings.session_token_ref {
                references.push(("storage.sessionTokenRef".to_owned(), reference.as_str()));
            }
            if let Some(reference) = &settings.ca_bundle_ref {
                references.push(("storage.caBundleRef".to_owned(), reference.as_str()));
            }
        }
        if let Ok(ContentVerificationConfig::Http { settings }) =
            self.content_verification.get(self.development.as_ref())
        {
            references.push((
                "contentVerification.authorizationRef".to_owned(),
                settings.authorization_ref.as_str(),
            ));
        }
        for (id, destination) in &self.destinations.hooks {
            references.push((
                format!("destinations.hooks.{id}.hmacSha256KeyRef"),
                destination.hmac_sha256_key_ref.as_str(),
            ));
            if let Some(reference) = &destination.previous_hmac_sha256_key_ref {
                references.push((
                    format!("destinations.hooks.{id}.previousHmacSha256KeyRef"),
                    reference.as_str(),
                ));
            }
        }
        for (field, reference) in references {
            if let Err(error) = self.secret_providers.check_reference(&field, reference) {
                findings.push(Finding::block(&dotted_pointer(&field), &error));
            }
        }
        if let Err(error) = self.audit.key.check(&self.secret_providers) {
            findings.push(Finding::block("/audit/hashKeyRef", &error));
        }
    }

    fn check_database(&self, findings: &mut Vec<Finding>) {
        if let Err(error) = self.database.check(cfg!(feature = "postgres-test")) {
            findings.push(Finding::new(
                error.code(),
                if self.database.test_only_plaintext {
                    "/database/testOnlyPlaintext"
                } else {
                    "/database/transport"
                },
                error.to_string(),
                error.suggested_action(),
            ));
        }
    }

    /// The rules the shared issuer block holds about the entries together.
    fn issuer_findings(&self) -> Vec<Finding> {
        self.authentication
            .oidc
            .issuers
            .check(ISSUERS_POINTER)
            .into_iter()
            .map(|diagnostic| {
                Finding::new(
                    diagnostic.code,
                    &diagnostic.path,
                    diagnostic.message,
                    diagnostic.suggested_action,
                )
            })
            .collect()
    }

    fn check_oidc(&self, findings: &mut Vec<Finding>) {
        for (id, entry) in self.authentication.oidc.issuers.iter() {
            let id = id.as_str();
            let field = format!("authentication.oidc.issuers.{id}");
            let pointer = entry_pointer(id);
            if let Err(error) = entry.core().provider.check(&field) {
                findings.push(Finding::block(&pointer, &error));
            }
            let assertions = OidcClientsConfig {
                allowed_clients: Vec::new(),
                assertion_issuers: entry.assertion_issuers.clone(),
            };
            if let Err(error) = assertions.check(&field) {
                findings.push(Finding::block(&pointer, &error));
            }
            // Every access profile resolves its caller from the matched
            // client, so `allowedClients: unrestricted` would admit every
            // client the issuer verifies while reaching no profile.
            if entry.core().allowed_clients == PackageClients::Unrestricted {
                findings.push(allowed_clients_required(id));
            }
        }
    }

    fn check_audit(&self, findings: &mut Vec<Finding>) {
        if let Err(error) = self.audit.destination() {
            findings.push(Finding::new(
                "documents.runtime.invalid-audit",
                audit_pointer(&error),
                audit_message(&error),
                audit_action(&error),
            ));
        }
    }

    fn check_storage(&self, findings: &mut Vec<Finding>) {
        let StorageConfig::S3 { settings, .. } = &self.storage else {
            return;
        };
        if !transport_protects_the_credential(&settings.url.to_url()) {
            findings.push(Finding::new(
                "documents.runtime.insecure-url",
                "/storage/url",
                "storage.url must use HTTPS or HTTP on loopback",
                "Write an HTTPS URL or use HTTP with a loopback host.",
            ));
        } else if S3Settings::from_config(settings, self.peer_policy()).is_err() {
            findings.push(Finding::new(
                "documents.runtime.invalid-object-storage",
                "/storage",
                "storage is not a usable S3 bucket: url must be https (http only for a loopback host) with no path, query, or fragment, and bucket and region must be lowercase S3 names",
                "Correct storage.url, storage.bucket, and storage.region.",
            ));
        }
    }

    fn check_content_verification(&self, findings: &mut Vec<Finding>) {
        let Ok(verification) = self.content_verification.get(self.development.as_ref()) else {
            return;
        };
        match verification {
            ContentVerificationConfig::Http { settings }
                if !transport_protects_the_credential(&settings.url.to_url()) =>
            {
                findings.push(Finding::new(
                    "documents.runtime.insecure-url",
                    "/contentVerification/url",
                    "contentVerification.url must use HTTPS or HTTP on loopback",
                    "Write an HTTPS URL or use HTTP with a loopback host.",
                ));
            }
            ContentVerificationConfig::Http { settings }
                if HttpVerifierSettings::from_config(settings, self.peer_policy()).is_err() =>
            {
                findings.push(Finding::new(
                    "documents.runtime.invalid-content-verification",
                    "/contentVerification",
                    "contentVerification is not a usable verifier: url must be https (http only for a loopback host) with no credentials or fragment, and policyId must be 1 to 128 printable ASCII characters",
                    "Correct contentVerification.url and contentVerification.policyId.",
                ));
            }
            _ => {}
        }
    }

    fn check_hook_destinations(&self, findings: &mut Vec<Finding>) {
        for (id, destination) in &self.destinations.hooks {
            if !transport_protects_the_credential(&destination.url.to_url()) {
                findings.push(Finding::new(
                    "documents.runtime.insecure-url",
                    &format!("/destinations/hooks/{}/url", escape(id)),
                    format!("destinations.hooks.{id}.url must use HTTPS or HTTP on loopback"),
                    "Write an HTTPS URL or use HTTP with a loopback host.",
                ));
            }
        }
    }
}

impl RuntimeConfig {
    /// Every rule this runtime document breaks against the project it serves:
    /// each destination the project's hooks name must be bound under
    /// `destinations.hooks`.
    #[must_use]
    pub fn project_findings(&self, project: &DocumentsProject) -> Vec<Finding> {
        let mut findings = self.client_findings(project);
        findings.extend(self.hook_findings(project));
        findings
    }

    /// The clients each token verifier admits, by issuer id, given the project
    /// this runtime serves. `from-package` is the sorted union of the access
    /// profiles' requester clients and a list is the list. A client belongs to
    /// one issuer, so an entry that reads its clients from the package refuses
    /// every other entry's list naming a package client. Without such an
    /// entry, the lists together must cover every client a profile names, or
    /// the profile naming the missing client could never be reached. No
    /// verifier is handed an empty list, which it reads as "every client".
    pub fn admitted_clients(
        &self,
        project: &DocumentsProject,
    ) -> Result<BTreeMap<String, AdmittedClients>, Box<Finding>> {
        let (admitted, findings) = self.resolve_clients(project);
        match findings.into_iter().next() {
            Some(finding) => Err(Box::new(finding)),
            None => Ok(admitted),
        }
    }

    /// What the admitted clients leave wrong against the project, every rule
    /// in one pass. An `unrestricted` value is reported once, as a missing
    /// client list.
    fn client_findings(&self, project: &DocumentsProject) -> Vec<Finding> {
        self.resolve_clients(project).1
    }

    /// The clients each entry admits and every rule they break against the
    /// project: a list an entry leaves empty, a client two entries admit, a
    /// package client no entry admits, an assertion authority for a client
    /// the entry does not admit, and the audience and client kind rules over
    /// the clients `from-package` resolved to.
    fn resolve_clients(
        &self,
        project: &DocumentsProject,
    ) -> (BTreeMap<String, AdmittedClients>, Vec<Finding>) {
        let package_clients = requester_clients(project);
        let issuers = &self.authentication.oidc.issuers;
        let mut admitted = BTreeMap::new();
        let mut findings = Vec::new();
        let mut from_package: Option<&str> = None;
        for (id, entry) in issuers.iter() {
            let list = match &entry.core().allowed_clients {
                PackageClients::FromPackage => {
                    from_package.get_or_insert(id.as_str());
                    AdmittedClients::new(package_clients.clone())
                }
                PackageClients::Listed(listed) => AdmittedClients::new(listed.clone()),
                PackageClients::Unrestricted => None,
            };
            match list {
                Some(list) => {
                    admitted.insert(id.as_str().to_owned(), list);
                }
                None => findings.push(allowed_clients_required(id.as_str())),
            }
        }
        match from_package {
            Some(reading) => {
                for (id, entry) in issuers.iter() {
                    let PackageClients::Listed(listed) = &entry.core().allowed_clients else {
                        continue;
                    };
                    for (index, client) in listed.iter().enumerate() {
                        if package_clients.contains(client) {
                            findings.push(client_in_two_issuers(id.as_str(), index, reading));
                        }
                    }
                }
            }
            None => findings.extend(self.uncovered_package_clients(project, &package_clients)),
        }
        for (id, entry) in issuers.iter() {
            let Some(clients) = admitted.get(id.as_str()) else {
                continue;
            };
            findings.extend(assertion_issuer_findings(id.as_str(), entry, clients));
            if entry.core().allowed_clients == PackageClients::FromPackage {
                findings.extend(resolved_client_findings(id.as_str(), entry, clients));
            }
        }
        (admitted, findings)
    }

    /// The package clients no entry's list names, each as the profile that
    /// could never be reached.
    fn uncovered_package_clients(
        &self,
        project: &DocumentsProject,
        package_clients: &[String],
    ) -> Vec<Finding> {
        let issuers = &self.authentication.oidc.issuers;
        let listed: BTreeSet<&str> = issuers
            .iter()
            .filter_map(|(_, entry)| match &entry.core().allowed_clients {
                PackageClients::Listed(clients) => Some(clients),
                PackageClients::FromPackage | PackageClients::Unrestricted => None,
            })
            .flatten()
            .map(String::as_str)
            .collect();
        // An entry that states no list has already been reported.
        if issuers
            .iter()
            .any(|(_, entry)| entry.core().allowed_clients == PackageClients::Unrestricted)
        {
            return Vec::new();
        }
        let pointer = match (issuers.len(), issuers.iter().next()) {
            (1, Some((id, _))) => clients_pointer(id.as_str()),
            _ => ISSUERS_POINTER.to_owned(),
        };
        package_clients
            .iter()
            .filter(|client| !listed.contains(client.as_str()))
            .map(|client| {
                let profile = project
                    .access_profiles
                    .iter()
                    .find(|(_, profile)| {
                        profile
                            .requester_clients
                            .as_slice()
                            .iter()
                            .any(|listed| listed.as_str() == client)
                    })
                    .map_or("", |(id, _)| id.as_str());
                Finding::new(
                    PROFILE_CLIENT_NOT_ALLOWED_CODE,
                    &pointer,
                    format!(
                        "authentication.oidc.issuers allowedClients lists do not name {client}, a requester client of access profile {profile}"
                    ),
                    "Add the client to the allowedClients of one issuer entry, or write allowedClients: from-package on one entry to admit every requester client the project names.",
                )
            })
            .collect()
    }

    fn hook_findings(&self, project: &DocumentsProject) -> Vec<Finding> {
        let unbound = project.hooks.iter().any(|hook| {
            let HookHandler::Url { destination_id } = &hook.handler;
            !self
                .destinations
                .hooks
                .contains_key(destination_id.as_str())
        });
        if unbound {
            vec![Finding::new(
                UNBOUND_HOOK_DESTINATION_CODE,
                "/destinations/hooks",
                UNBOUND_HOOK_DESTINATION_MESSAGE,
                UNBOUND_HOOK_DESTINATION_ACTION,
            )]
        } else {
            Vec::new()
        }
    }
}

fn escape(segment: &str) -> String {
    registry_platform_yaml::escape_pointer_segment(segment)
}

/// The JSON pointer of a dotted field name.
fn dotted_pointer(field: &str) -> String {
    field
        .split('.')
        .map(|segment| format!("/{}", escape(segment)))
        .collect()
}

/// The requester clients of every access profile of `project`, sorted and
/// distinct.
fn requester_clients(project: &DocumentsProject) -> Vec<String> {
    let mut clients: Vec<String> = project
        .access_profiles
        .values()
        .flat_map(|profile| profile.requester_clients.as_slice())
        .map(|client| client.as_str().to_owned())
        .collect();
    clients.sort();
    clients.dedup();
    clients
}

/// The JSON Pointer of the issuer entry `id`.
fn entry_pointer(id: &str) -> String {
    format!("{ISSUERS_POINTER}/{}", escape(id))
}

/// The JSON Pointer of the `allowedClients` member of the issuer entry `id`.
fn clients_pointer(id: &str) -> String {
    format!("{}/allowedClients", entry_pointer(id))
}

fn allowed_clients_required(id: &str) -> Finding {
    Finding::new(
        ALLOWED_CLIENTS_REQUIRED_CODE,
        &clients_pointer(id),
        format!(
            "authentication.oidc.issuers.{id}.allowedClients must be `from-package` or list the clients this issuer admits. `unrestricted` is refused"
        ),
        "Write allowedClients: from-package, or list every OAuth client an access profile names that this issuer admits.",
    )
}

/// The client listed at `index` of entry `id` is also admitted by the entry
/// `reading`, which reads its clients from the package.
fn client_in_two_issuers(id: &str, index: usize, reading: &str) -> Finding {
    Finding::new(
        CLIENT_IN_TWO_ISSUERS_CODE,
        &format!("{}/{index}", clients_pointer(id)),
        format!("the client is already admitted by the entry {reading}"),
        "Admit each client through one issuer entry, so a client rule binds to one issuer.",
    )
    .related(
        clients_pointer(reading),
        format!("the entry {reading} reads its clients from the package"),
    )
}

/// Every client an entry's `assertionIssuers` names must be one the entry
/// admits.
fn assertion_issuer_findings(
    id: &str,
    entry: &IssuerConfig,
    admitted: &AdmittedClients,
) -> Vec<Finding> {
    entry
        .assertion_issuers
        .keys()
        .filter(|client| !admitted.as_slice().contains(client))
        .map(|client| {
            Finding::new(
                ASSERTION_ISSUER_CLIENT_NOT_ALLOWED_CODE,
                &format!("{}/assertionIssuers/{}", entry_pointer(id), escape(client)),
                format!(
                    "authentication.oidc.issuers.{id}.assertionIssuers names {client}, which the entry does not admit"
                ),
                "Name a client the entry admits, or remove the assertion authority.",
            )
        })
        .collect()
}

/// The rules about an entry's audience and client kinds, run again over the
/// clients `from-package` resolved to, as the shared check runs them over a
/// list.
fn resolved_client_findings(
    id: &str,
    entry: &IssuerConfig,
    admitted: &AdmittedClients,
) -> Vec<Finding> {
    let core = entry.core();
    let clients = admitted.as_slice();
    let mut findings = Vec::new();
    if core.access_token_type.get() == &AccessTokenType::Jwt
        && clients.contains(&core.provider.audience)
    {
        findings.push(Finding::new(
            AUDIENCE_IS_A_CLIENT_CODE,
            &format!("{}/audience", entry_pointer(id)),
            "with accessTokenType JWT the audience is also one of the clients the project names",
            "Use an audience that names this service and no client, so an ID token issued to a client is not read as an access token.",
        ));
    }
    if let Some(kinds) = &core.client_actor_kinds {
        findings.extend(
            kinds
                .get()
                .0
                .keys()
                .filter(|client| !clients.iter().any(|admitted| admitted == client.as_str()))
                .map(|client| {
                    Finding::new(
                        ACTOR_KIND_FOR_UNADMITTED_CLIENT_CODE,
                        &format!("{}/clientActorKinds/{}", entry_pointer(id), escape(client.as_str())),
                        "clientActorKinds names a client the project does not name",
                        "Name only clients the project's access profiles name, or list the client in allowedClients.",
                    )
                }),
        );
    }
    findings
}

/// What an offline check of one runtime document found (CFG-CHECK-1).
#[derive(Debug)]
pub struct RuntimeCheck {
    /// Every finding, positioned at the member it concerns, in file order.
    pub report: Report,
    /// The file could not be read at all, as opposed to read and refused.
    pub unavailable: bool,
    /// The explicit production settings the document states, each with its
    /// position. A setting is never a finding: it records a choice the
    /// operator made on purpose. `None` when the document never decoded, so
    /// nothing was read to state any. `Some` of an empty list says the
    /// document was read and stated none.
    pub explicit_settings: Option<Vec<FoundExplicitSetting>>,
}

/// Check the runtime document at the absolute `path` as `documents serve`
/// reads it, with no database, network, or secret material, and report every
/// rule it breaks.
///
/// With `substitute` set, `${NAME}` expressions are filled from the process
/// environment and every value is checked. Without it, each expression is
/// checked by syntax and position only, and a rule about its value is left
/// out.
///
/// With `project` given, the document is also checked against the project it
/// serves, as `documents serve` checks it against the package it loads.
#[must_use]
pub fn check_runtime_file(
    path: &Path,
    substitute: bool,
    project: Option<&DocumentsProject>,
) -> RuntimeCheck {
    check_runtime_file_with_posture(path, substitute, project, DEFAULT_POSTURE)
}

pub fn check_runtime_file_with_posture(
    path: &Path,
    substitute: bool,
    project: Option<&DocumentsProject>,
    declared: DeclaredPosture,
) -> RuntimeCheck {
    let check = RuntimeConfig::loader_with_posture(declared).check_offline::<RuntimeConfig>(
        path,
        substitute,
        stand_in_for,
    );
    let (diagnostics, explicit_settings) = match &check.loaded {
        Some(loaded) => {
            let mut findings = loaded.config.own_findings();
            if let Some(project) = project {
                findings.extend(loaded.config.project_findings(project));
            }
            let mut diagnostics: Vec<Diagnostic> = findings
                .iter()
                .filter(|finding| !is_deferred(&check, loaded.config.issuer_ids(), finding))
                .map(|finding| positioned(&check, finding))
                .collect();
            diagnostics.extend(loaded.config.authentication.oidc.issuers.check_file(
                ISSUERS_POINTER,
                &check,
                DOCUMENTS_RUNTIME_KIND,
            ));
            let hook_destinations = hook_destination_diagnostics(&check, &loaded.config);
            extend_unreported(&mut diagnostics, hook_destinations);
            (
                diagnostics,
                Some(loaded.posture.explicit_settings().to_vec()),
            )
        }
        None => (Vec::new(), None),
    };
    RuntimeCheck {
        report: check.report_with(DOCUMENTS_RUNTIME_KIND, diagnostics),
        unavailable: check.unavailable,
        explicit_settings,
    }
}

/// What hook activation would refuse in each bound destination, from the
/// shared hook destination check, at the destination's own pointer.
fn hook_destination_diagnostics(
    check: &RuntimeFileCheck<RuntimeConfig>,
    config: &RuntimeConfig,
) -> Vec<Diagnostic> {
    config
        .destinations
        .hooks
        .iter()
        .flat_map(|(id, destination)| {
            registry_platform_hooks::delivery::check_url_hook_destination_file(
                destination,
                &format!("/destinations/hooks/{}", escape(id)),
                check,
                DOCUMENTS_RUNTIME_KIND,
            )
        })
        .collect()
}

/// Add each of `shared` at a member no diagnostic in `diagnostics` already
/// names, so a refusal the product reports in its own words is not repeated.
fn extend_unreported(diagnostics: &mut Vec<Diagnostic>, shared: Vec<Diagnostic>) {
    for diagnostic in shared {
        if !diagnostics
            .iter()
            .any(|known| known.path == diagnostic.path)
        {
            diagnostics.push(diagnostic);
        }
    }
}

/// Whether `finding` reads a member the check left as an expression, so a
/// stand-in, not the operator's value, decided it. The overlap finding reads
/// both binds, and sits at the metrics bind: when only the serving bind is
/// an expression it is the only finding left out.
///
/// A rule that compares the lists of several entries reads every entry's
/// `allowedClients`. A rule about one entry reads that entry's list and the
/// member its pointer names, and the audience rule also reads the token type.
fn is_deferred(
    check: &RuntimeFileCheck<RuntimeConfig>,
    issuer_ids: Vec<&str>,
    finding: &Finding,
) -> bool {
    let entry_list_deferred =
        || entry_of(&finding.pointer).is_some_and(|id| check.defers_within(&clients_pointer(id)));
    match finding.code.as_str() {
        PROFILE_CLIENT_NOT_ALLOWED_CODE | CLIENT_IN_TWO_ISSUERS_CODE => issuer_ids
            .iter()
            .any(|id| check.defers_within(&clients_pointer(id))),
        AUDIENCE_IS_A_CLIENT_CODE => {
            check.defers_within(&finding.pointer)
                || entry_list_deferred()
                || entry_of(&finding.pointer).is_some_and(|id| {
                    check.defers_within(&format!("{}/accessTokenType", entry_pointer(id)))
                })
        }
        ACTOR_KIND_FOR_UNADMITTED_CLIENT_CODE | ASSERTION_ISSUER_CLIENT_NOT_ALLOWED_CODE => {
            check.defers_within(&finding.pointer) || entry_list_deferred()
        }
        METRICS_OVERLAP_CODE => {
            check.defers_within(&finding.pointer) || check.defers("/listener/bind")
        }
        METRICS_LISTENER_CODE => {
            check.defers_within(&finding.pointer)
                || check.defers("/metricsListener/networkExposure")
        }
        _ => check.defers_within(&finding.pointer),
    }
}

/// The id of the issuer entry a pointer is at or below.
fn entry_of(pointer: &str) -> Option<&str> {
    pointer
        .strip_prefix(ISSUERS_POINTER)?
        .strip_prefix('/')?
        .split('/')
        .next()
        .filter(|id| !id.is_empty())
}

/// The metrics listener binds a concrete loopback or private address on a
/// non-zero port. Link-local, public, and multicast addresses are refused, and
/// a wildcard only under `container-private`, so the series are never
/// published on a routable interface by accident.
fn check_metrics_address(
    metrics: SocketAddr,
    exposure: registry_platform_config::ListenerNetworkExposure,
) -> Result<(), registry_platform_config::MetricsBindError> {
    registry_platform_config::check_metrics_bind_address(metrics, exposure)
}

/// Check that binding `metrics` would not take the socket the serving
/// `listener` holds.
fn check_metrics_apart(
    metrics: SocketAddr,
    listener: SocketAddr,
) -> Result<(), registry_platform_config::MetricsBindError> {
    registry_platform_config::check_metrics_bind_apart(metrics, &[("listener", listener)])
}

/// The report `documents serve` prints when it refuses the runtime document
/// at `path`: every diagnostic the shared loader or the runtime rules hold,
/// each at its position. `None` for a refusal that is not about the file.
#[must_use]
pub fn startup_report(path: &Path, error: &RuntimeConfigError) -> Option<Report> {
    startup_report_with_posture(path, error, DEFAULT_POSTURE)
}

pub fn startup_report_with_posture(
    path: &Path,
    error: &RuntimeConfigError,
    declared: DeclaredPosture,
) -> Option<Report> {
    match error {
        RuntimeConfigError::Load(error) => Some(Report::new(error.diagnostics().to_vec())),
        RuntimeConfigError::Refused(_) => {
            let report = check_runtime_file_with_posture(path, true, None, declared).report;
            (!report.is_empty()).then_some(report)
        }
        RuntimeConfigError::SecretProviders(_)
        | RuntimeConfigError::Oidc
        | RuntimeConfigError::Inconsistent(_)
        | RuntimeConfigError::OidcJwksSecret(_) => None,
    }
}

/// `finding` at the value of its member, or, for a member that is absent, at
/// the nearest mapping above it that is present.
fn positioned(check: &RuntimeFileCheck<RuntimeConfig>, finding: &Finding) -> Diagnostic {
    let mut diagnostic = check.error_at(
        DOCUMENTS_RUNTIME_KIND,
        &finding.code,
        &finding.pointer,
        finding.message.clone(),
        finding.suggested_action.clone(),
    );
    let mut located = finding.pointer.as_str();
    while diagnostic
        .source
        .as_ref()
        .is_some_and(|source| source.line.is_none())
        && !located.is_empty()
    {
        located = &located[..located.rfind('/').unwrap_or(0)];
        diagnostic.source = check
            .error_at(DOCUMENTS_RUNTIME_KIND, "", located, "", "")
            .source;
    }
    if let Some((pointer, note)) = &finding.related {
        check.add_related_at(&mut diagnostic, pointer, note.clone());
    }
    diagnostic
}

/// A value for an expression the offline check does not substitute, chosen
/// so the member it fills decodes and passes the rules about its value.
fn stand_in_for(pointer: &str) -> &'static str {
    let segments: Vec<&str> = pointer.split('/').skip(1).collect();
    match segments.as_slice() {
        ["listener", "bind"] => DEFAULT_LISTENER_BIND,
        ["metricsListener", "bind"] => DEFAULT_METRICS_BIND,
        ["metricsListener", "networkExposure"] => "private-address",
        ["listener", "tlsTermination"] => "loopback-plaintext",
        ["listener", "networkExposure"] => "private-address",
        ["audit", "destination"] => "file",
        ["package", "root"] | ["audit", "path"] | ["secretProviders", "file", "root"] => {
            "/deferred"
        }
        ["package", "expectedDigest"] => {
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
        ["authentication", "oidc", "issuers", _, "issuer"]
        | ["authentication", "oidc", "issuers", _, "jwksSource", "uri"]
        | ["contentVerification", "url"]
        | ["storage", "url"]
        | ["destinations", "hooks", _, "url"] => "https://deferred.invalid",
        _ => DEFAULT_STAND_IN,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use registry_platform_audit::{DEFAULT_AUDIT_RETAIN_DAYS, DEFAULT_AUDIT_ROTATE_BYTES};
    #[cfg(unix)]
    use std::path::PathBuf;

    pub(crate) const STARTER_RUNTIME: &str =
        include_str!("../../../products/documents/examples/starter/runtime.example.yaml");

    fn parse(text: &str) -> Result<RuntimeConfig, RuntimeConfigError> {
        parse_with_posture(text, DEFAULT_POSTURE)
    }

    fn parse_with_posture(
        text: &str,
        declared: DeclaredPosture,
    ) -> Result<RuntimeConfig, RuntimeConfigError> {
        let loaded = RuntimeConfig::loader_with_posture(declared)
            .parse_str::<RuntimeConfig>(text, |_| None)?;
        let mut config = loaded.config;
        config.development = loaded.development;
        let findings = config.findings();
        if findings.is_empty() {
            Ok(config)
        } else {
            Err(RuntimeConfigError::Refused(findings))
        }
    }

    fn codes(error: RuntimeConfigError) -> Vec<String> {
        match error {
            RuntimeConfigError::Refused(findings) => findings
                .iter()
                .map(|finding| finding.code.to_owned())
                .collect(),
            RuntimeConfigError::Load(error) => error
                .diagnostics()
                .iter()
                .map(|diagnostic| diagnostic.code.clone())
                .collect(),
            RuntimeConfigError::SecretProviders(message) => vec![message],
            RuntimeConfigError::Oidc => vec!["oidc".to_owned()],
            RuntimeConfigError::Inconsistent(message) => vec![message],
            RuntimeConfigError::OidcJwksSecret(message) => vec![message],
        }
    }

    #[cfg(unix)]
    fn write_ownership_test_runtime(directory: &Path) -> PathBuf {
        let path = directory.join("runtime.yaml");
        std::fs::write(&path, STARTER_RUNTIME).unwrap();
        path
    }

    #[cfg(unix)]
    fn assert_unsafe_runtime(error: RuntimeConfigError) {
        let RuntimeConfigError::Load(error) = error else {
            panic!("the shared loader refuses unsafe ownership");
        };
        let diagnostic = error
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "platform.runtime-config.unsafe-file")
            .expect("the ownership refusal is reported");
        assert!(diagnostic.message.contains("is writable by its group"));
        assert!(diagnostic.suggested_action.contains("chmod g-w "));
    }

    #[cfg(unix)]
    #[test]
    fn runtime_loader_ownership_accepts_an_owner_writable_file_in_a_private_directory() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = write_ownership_test_runtime(directory.path());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        RuntimeConfig::load(&path).expect("an owner-writable runtime in a private directory loads");
    }

    #[cfg(unix)]
    #[test]
    fn runtime_loader_ownership_refuses_a_group_writable_file() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = write_ownership_test_runtime(directory.path());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
        let result = RuntimeConfig::load(&path);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert_unsafe_runtime(result.expect_err("a group-writable runtime is refused"));
    }

    #[cfg(unix)]
    #[test]
    fn runtime_loader_ownership_refuses_a_group_writable_ancestor() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let writable = directory.path().join("writable");
        std::fs::create_dir(&writable).unwrap();
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o770)).unwrap();
        let path = write_ownership_test_runtime(&writable);
        let result = RuntimeConfig::load(&path);
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert_unsafe_runtime(
            result.expect_err("a runtime below a group-writable directory is refused"),
        );
    }

    const PUBLIC_KEY: &str = r#"{"kty":"EC","crv":"P-256","kid":"k1","alg":"ES256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;

    fn key_set(extra: &str) -> String {
        let key = if extra.is_empty() {
            PUBLIC_KEY.to_owned()
        } else {
            PUBLIC_KEY.replacen('}', &format!(",{extra}}}"), 1)
        };
        format!(r#"{{"keys":[{key}]}}"#)
    }

    #[test]
    fn a_static_key_set_with_unknown_public_members_loads() {
        let document = key_set(r#""ext":true,"x5t":"abc","x5c":["AAAA"]"#);
        let jwks = parse_static_key_set(
            "authentication.oidc.issuers.main.jwksSource.documentRef",
            document.as_bytes(),
        )
        .expect("unknown public members load");
        assert_eq!(jwks.keys.len(), 1);
    }

    #[test]
    fn a_static_key_set_that_holds_a_private_member_is_refused_by_rule_and_not_by_value() {
        let secret = "private-canary-value";
        let document = key_set(&format!(r#""d":"{secret}""#));
        let RuntimeConfigError::OidcJwksSecret(message) = parse_static_key_set(
            "authentication.oidc.issuers.main.jwksSource.documentRef",
            document.as_bytes(),
        )
        .expect_err("a private member is refused") else {
            panic!("a refused key set is not an issuer outage");
        };
        assert!(
            message.contains(r#"private-key member "d""#),
            "the refusal names the private-key member rule"
        );
        assert!(message.contains("authentication.oidc.issuers.main.jwksSource.documentRef"));
        assert!(
            !message.contains(secret),
            "the refusal holds the private member's value"
        );
    }

    #[test]
    fn a_static_key_set_that_is_not_json_is_not_an_issuer_outage() {
        assert!(matches!(
            parse_static_key_set(
                "authentication.oidc.issuers.main.jwksSource.documentRef",
                b"not json"
            ),
            Err(RuntimeConfigError::OidcJwksSecret(_))
        ));
    }

    #[test]
    fn the_starter_runtime_document_is_accepted() {
        let config = parse(STARTER_RUNTIME).expect("the starter runtime document");
        assert_eq!(
            config.identity.as_ref().unwrap().database_id.as_str(),
            "registry-documents-production"
        );
        assert_eq!(
            config.listener.bind.socket_addr().to_string(),
            DEFAULT_LISTENER_BIND
        );
        assert!(matches!(
            config.storage,
            StorageConfig::Database { maximum_document_bytes } if u64::from(maximum_document_bytes) == 16_777_216
        ));
        assert_eq!(config.storage.maximum_document_bytes(), 16_777_216);
        assert!(matches!(
            config.content_verification.get(None).unwrap(),
            ContentVerificationConfig::Http { .. }
        ));
        assert_eq!(config.cleanup.erasure, Erasure::Active);
        assert_eq!(config.destinations.hooks.len(), 1);
        assert_eq!(config.retention, RetentionConfig::default());
    }

    #[test]
    fn an_unknown_member_is_refused_by_the_shared_reader() {
        let text = STARTER_RUNTIME.replace("cleanup:\n", "unexpected: true\ncleanup:\n");
        assert!(codes(parse(&text).unwrap_err()).contains(&"config.unknown-key".to_owned()));
    }

    #[test]
    fn a_missing_identity_is_refused_by_name() {
        let text = STARTER_RUNTIME.replace(
            "identity:\n  # The one database this deployment owns.\n  databaseId: registry-documents-production\n",
            "",
        );
        assert_ne!(
            text, STARTER_RUNTIME,
            "the fixture names the identity block"
        );
        assert_eq!(
            codes(parse(&text).unwrap_err()),
            ["documents.runtime.missing-identity"]
        );
    }

    #[test]
    fn shared_runtime_loader_refuses_environment_expressions_in_secret_references() {
        for (written, substituted, pointer) in [
            (
                "runtimeUrlRef: secret:file/runtime-database-url",
                "runtimeUrlRef: ${DATABASE_URL}",
                "/database/runtimeUrlRef",
            ),
            (
                "hashKeyRef: secret:file/documents-audit-key",
                "hashKeyRef: secret:env/${KEY_NAME:-AUDIT}",
                "/audit/hashKeyRef",
            ),
        ] {
            let text = STARTER_RUNTIME.replacen(written, substituted, 1);
            assert_ne!(text, STARTER_RUNTIME, "{pointer}");
            let RuntimeConfigError::Load(error) = parse(&text).unwrap_err() else {
                panic!("{pointer}: the shared loader refuses the reference");
            };
            let found: Vec<(&str, &str)> = error
                .diagnostics()
                .iter()
                .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
                .collect();
            assert_eq!(found, [("config.substitution-not-allowed", pointer)]);
        }
    }

    #[test]
    fn unrestricted_clients_are_refused() {
        let text = STARTER_RUNTIME.replace(
            "allowedClients: [civil-registry-app, citizen-portal, case-portal, partner-portal]",
            "allowedClients: unrestricted",
        );
        assert_ne!(text, STARTER_RUNTIME);
        assert_eq!(
            codes(parse(&text).unwrap_err()),
            ["documents.runtime.allowed-clients-required"]
        );
    }

    const STARTER_CLIENTS: &str =
        "allowedClients: [civil-registry-app, citizen-portal, case-portal, partner-portal]";

    fn from_package_runtime() -> String {
        let text = STARTER_RUNTIME.replace(STARTER_CLIENTS, "allowedClients: from-package");
        assert_ne!(text, STARTER_RUNTIME);
        text
    }

    fn starter_project() -> DocumentsProject {
        DocumentsProject::decode(
            "documents.yaml",
            include_bytes!("../../../products/documents/examples/starter/documents.yaml"),
        )
        .expect("the starter project decodes")
        .value
    }

    fn project_finding_codes(config: &RuntimeConfig, project: &DocumentsProject) -> Vec<String> {
        config
            .project_findings(project)
            .iter()
            .map(|finding| format!("{} {}", finding.code, finding.pointer))
            .collect()
    }

    #[test]
    fn from_package_is_accepted_and_names_no_second_list() {
        let config = parse(&from_package_runtime()).expect("from-package loads");
        assert_eq!(
            config.issuer("main").unwrap().core().allowed_clients,
            PackageClients::FromPackage
        );
        assert_eq!(
            project_finding_codes(&config, &starter_project()),
            [] as [String; 0]
        );
    }

    #[test]
    fn an_omitted_allowed_clients_member_is_refused() {
        let text = STARTER_RUNTIME.replace(STARTER_CLIENTS, "");
        assert_ne!(text, STARTER_RUNTIME);
        let found = codes(parse(&text).unwrap_err());
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].starts_with("config."), "{found:?}");
    }

    #[test]
    fn an_empty_list_and_an_unknown_keyword_are_refused() {
        for written in ["allowedClients: []", "allowedClients: any"] {
            let text = STARTER_RUNTIME.replace(STARTER_CLIENTS, written);
            assert!(parse(&text).is_err(), "{written}");
        }
    }

    #[test]
    fn explicit_list_missing_a_package_client_is_refused() {
        let text = STARTER_RUNTIME.replace(
            STARTER_CLIENTS,
            "allowedClients: [civil-registry-app, citizen-portal, case-portal]",
        );
        let config = parse(&text).expect("a list is a valid file on its own");
        assert_eq!(
            project_finding_codes(&config, &starter_project()),
            ["documents.runtime.profile-client-not-allowed /authentication/oidc/issuers/main/allowedClients"]
        );
    }

    #[test]
    fn an_explicit_list_with_a_client_the_package_does_not_name_is_accepted() {
        let text = STARTER_RUNTIME.replace(
            STARTER_CLIENTS,
            "allowedClients: [civil-registry-app, citizen-portal, case-portal, partner-portal, extra-app]",
        );
        let config = parse(&text).unwrap();
        assert_eq!(
            project_finding_codes(&config, &starter_project()),
            [] as [String; 0]
        );
    }

    #[test]
    fn assertion_issuer_client_outside_the_package_is_refused_under_from_package() {
        let with_issuers = |client: &str| {
            from_package_runtime().replace(
                "allowedClients: from-package\n",
                &format!(
                    "allowedClients: from-package\n        assertionIssuers:\n          {client}: [https://assertions.example.test]\n"
                ),
            )
        };
        let config = parse(&with_issuers("unknown-client")).unwrap();
        assert_eq!(
            project_finding_codes(&config, &starter_project()),
            ["documents.runtime.assertion-issuer-client-not-allowed /authentication/oidc/issuers/main/assertionIssuers/unknown-client"]
        );
        let config = parse(&with_issuers("citizen-portal")).unwrap();
        assert_eq!(
            project_finding_codes(&config, &starter_project()),
            [] as [String; 0]
        );
    }

    #[test]
    fn an_assertion_issuer_client_with_dots_is_reported_at_its_own_pointer() {
        let text = from_package_runtime().replace(
            "allowedClients: from-package\n",
            "allowedClients: from-package\n        assertionIssuers:\n          com.example.portal: [https://assertions.example.test]\n",
        );
        let config = parse(&text).unwrap();
        assert_eq!(
            project_finding_codes(&config, &starter_project()),
            ["documents.runtime.assertion-issuer-client-not-allowed /authentication/oidc/issuers/main/assertionIssuers/com.example.portal"]
        );
    }

    #[test]
    fn assertion_issuer_client_outside_an_explicit_list_is_refused() {
        let text = STARTER_RUNTIME.replace(
            "allowedClients: [civil-registry-app, citizen-portal, case-portal, partner-portal]\n",
            "allowedClients: [civil-registry-app, citizen-portal, case-portal, partner-portal]\n        assertionIssuers:\n          unknown-client: [https://assertions.example.test]\n",
        );
        assert_ne!(text, STARTER_RUNTIME);
        let config = parse(&text).unwrap();
        assert_eq!(
            project_finding_codes(&config, &starter_project()),
            ["documents.runtime.assertion-issuer-client-not-allowed /authentication/oidc/issuers/main/assertionIssuers/unknown-client"]
        );
    }

    #[tokio::test]
    async fn from_package_admits_exactly_the_package_clients() {
        use crate::auth::tests::{keys, token};
        use registry_platform_oidc::TokenVerifier;

        let project = DocumentsProject::decode(
            "documents.yaml",
            include_str!("../../../products/documents/examples/starter/documents.yaml")
                .replacen(
                    "requesterClients: [civil-registry-app]",
                    "requesterClients: [civil-registry-app, second-app]",
                    1,
                )
                .as_bytes(),
        )
        .expect("the project decodes")
        .value;
        let config = parse(&from_package_runtime()).unwrap();
        let admitted = config.admitted_clients(&project).unwrap();
        let admitted = admitted.get("main").expect("the main entry's clients");
        assert_eq!(
            admitted.as_slice(),
            [
                "case-portal",
                "citizen-portal",
                "civil-registry-app",
                "partner-portal",
                "second-app"
            ]
        );
        let mut profile = config.verifier_profile("main", admitted).unwrap();
        profile.allowed_algorithms = vec![jsonwebtoken::Algorithm::HS256];
        let verifier = TokenVerifier::new(profile, keys());
        let signed = |client: &str| {
            token(serde_json::json!({
                "iss": "https://identity.example.test/realms/registry",
                "aud": "urn:example:documents",
                "sub": "principal",
                "azp": client,
                "scope": "documents:read",
            }))
        };
        for client in admitted.as_slice() {
            verifier
                .verify(&signed(client))
                .await
                .unwrap_or_else(|error| panic!("{client} is admitted: {error}"));
        }
        let refused = verifier.verify(&signed("stranger-app")).await;
        assert!(
            matches!(
                refused,
                Err(registry_platform_oidc::OidcError::ClientNotAllowed)
            ),
            "{refused:?}"
        );
    }

    /// The starter runtime with a second issuer entry, `partner`, naming
    /// `clients`.
    fn with_partner(base: &str, clients: &str) -> String {
        let text = base.replace(
            "    issuers:\n      main:\n",
            &format!(
                "    issuers:\n      partner:\n        issuer: https://partner.example.test\n        audience: urn:example:documents-partner\n        allowedClients: {clients}\n      main:\n"
            ),
        );
        assert_ne!(text, base, "the starter names the issuers block");
        text
    }

    /// The first finding of a refused file, as its code and pointer.
    fn first_finding(error: RuntimeConfigError) -> (String, String) {
        match error {
            RuntimeConfigError::Refused(findings) => {
                (findings[0].code.clone(), findings[0].pointer.clone())
            }
            other => panic!("expected findings, got {other:?}"),
        }
    }

    #[test]
    fn two_issuers_with_the_same_iss_refuse_at_startup() {
        let text = with_partner(STARTER_RUNTIME, "[partner-service]").replace(
            "https://partner.example.test",
            "https://identity.example.test/realms/registry",
        );
        let (code, pointer) = first_finding(parse(&text).unwrap_err());
        assert_eq!(code, "platform.oidc.duplicate-issuer");
        assert_eq!(pointer, "/authentication/oidc/issuers/partner/issuer");
    }

    #[test]
    fn a_client_listed_by_two_issuers_is_refused_and_the_check_names_the_other_entry() {
        let text = with_partner(STARTER_RUNTIME, "[citizen-portal]");
        let (code, pointer) = first_finding(parse(&text).unwrap_err());
        assert_eq!(code, CLIENT_IN_TWO_ISSUERS_CODE);
        assert_eq!(
            pointer,
            "/authentication/oidc/issuers/partner/allowedClients/0"
        );

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("runtime.yaml");
        std::fs::write(&path, &text).unwrap();
        let checked = check_runtime_file(&path, false, Some(&starter_project()));
        let found = checked
            .report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == CLIENT_IN_TWO_ISSUERS_CODE)
            .unwrap_or_else(|| panic!("{:?}", checked.report.diagnostics()));
        assert!(!found.related.is_empty(), "{found:?}");
    }

    #[test]
    fn every_conflict_of_a_package_client_beside_from_package_is_reported() {
        let text = with_partner(&from_package_runtime(), "[citizen-portal, case-portal]");
        let config = parse(&text).expect("each file is valid on its own");
        let findings = config.project_findings(&starter_project());
        let conflicts: Vec<_> = findings
            .iter()
            .filter(|finding| finding.code == CLIENT_IN_TWO_ISSUERS_CODE)
            .collect();
        assert_eq!(conflicts.len(), 2, "{findings:?}");
        assert!(conflicts.iter().all(|finding| finding.related.is_some()));
    }

    #[test]
    fn a_resolved_package_client_equal_to_the_audience_under_jwt_is_refused() {
        let jwt = from_package_runtime()
            .replace(
                "        # accessTokenType: at+jwt\n",
                "        accessTokenType: JWT\n",
            )
            .replace(
                "audience: urn:example:documents",
                "audience: citizen-portal",
            );
        assert!(jwt.contains("accessTokenType: JWT"));
        let config = parse(&jwt).expect("the file is valid before clients resolve");
        let findings = config.project_findings(&starter_project());
        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.code.as_str(), finding.pointer.as_str()))
                .collect::<Vec<_>>(),
            [(
                AUDIENCE_IS_A_CLIENT_CODE,
                "/authentication/oidc/issuers/main/audience"
            )]
        );
        assert!(
            !findings[0].message.contains("citizen-portal"),
            "the message names no client: {findings:?}"
        );

        // The same audience under the default token type is not refused.
        let default = from_package_runtime().replace(
            "audience: urn:example:documents",
            "audience: citizen-portal",
        );
        let config = parse(&default).unwrap();
        let findings = config.project_findings(&starter_project());
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn a_client_actor_kind_for_a_client_the_package_does_not_name_is_refused() {
        let kinds = |client: &str| {
            from_package_runtime().replace(
                "        # clientActorKinds:\n        #   civil-registry-app: service\n",
                &format!("        clientActorKinds:\n          {client}: service\n"),
            )
        };
        let config = parse(&kinds("reporting-job")).expect("valid before clients resolve");
        let findings = config.project_findings(&starter_project());
        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.code.as_str(), finding.pointer.as_str()))
                .collect::<Vec<_>>(),
            [(
                ACTOR_KIND_FOR_UNADMITTED_CLIENT_CODE,
                "/authentication/oidc/issuers/main/clientActorKinds/reporting-job"
            )]
        );
        let config = parse(&kinds("civil-registry-app")).unwrap();
        let findings = config.project_findings(&starter_project());
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn an_issuer_list_with_no_entry_is_refused_by_one_code() {
        let a = STARTER_RUNTIME.find("    issuers:\n").unwrap();
        let b = STARTER_RUNTIME.find("audit:\n").unwrap();
        let text = format!(
            "{}    issuers: {{}}\n{}",
            &STARTER_RUNTIME[..a],
            &STARTER_RUNTIME[b..]
        );
        let error = parse(&text).unwrap_err();
        let found = codes(error);
        assert_eq!(found, ["platform.oidc.no-issuer"], "{found:?}");
    }

    #[test]
    fn an_issuer_expression_does_not_mask_a_client_the_profiles_name() {
        // The offline check leaves `issuer` as an expression. A package
        // client no list admits is still reported.
        let directory = tempfile::tempdir().unwrap();
        let text = STARTER_RUNTIME
            .replace(
                "issuer: https://identity.example.test/realms/registry",
                "issuer: ${DOCUMENTS_ISSUER_UNSET}",
            )
            .replace(
                STARTER_CLIENTS,
                "allowedClients: [civil-registry-app, citizen-portal, case-portal]",
            );
        let path = directory.path().join("runtime.yaml");
        std::fs::write(&path, text).unwrap();
        let checked = check_runtime_file(&path, false, Some(&starter_project()));
        assert!(
            checked
                .report
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == PROFILE_CLIENT_NOT_ALLOWED_CODE),
            "{:?}",
            checked.report.diagnostics()
        );
    }

    /// The starter runtime with a second entry `partner` that admits two of
    /// the four package clients, and `main` the other two.
    fn two_entry_runtime() -> String {
        STARTER_RUNTIME
            .replace(
                STARTER_CLIENTS,
                "allowedClients: [civil-registry-app, citizen-portal]",
            )
            .replace(
                "    issuers:\n      main:\n",
                "    issuers:\n      partner:\n        issuer: https://partner.example.test\n        audience: urn:example:documents-partner\n        allowedClients: [case-portal, partner-portal]\n      main:\n",
            )
    }

    /// The codes and pointers the offline check reports for `text` against
    /// the starter project.
    fn offline_findings(text: &str) -> Vec<(String, String)> {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("runtime.yaml");
        std::fs::write(&path, text).unwrap();
        check_runtime_file(&path, false, Some(&starter_project()))
            .report
            .diagnostics()
            .iter()
            .map(|diagnostic| (diagnostic.code.clone(), diagnostic.path.clone()))
            .collect()
    }

    #[test]
    fn an_expression_in_an_entry_list_defers_that_entrys_client_rules() {
        let kinds = "        clientActorKinds:\n          reporting-job: service\n        assertionIssuers:\n          reporting-job: [https://authority.example.test]\n";
        let with_kinds = |list: &str| {
            two_entry_runtime().replace(
                "allowedClients: [civil-registry-app, citizen-portal]\n",
                &format!("allowedClients: {list}\n{kinds}"),
            )
        };
        let reported = offline_findings(&with_kinds("[civil-registry-app, citizen-portal]"));
        for code in [
            ACTOR_KIND_FOR_UNADMITTED_CLIENT_CODE,
            ASSERTION_ISSUER_CLIENT_NOT_ALLOWED_CODE,
        ] {
            assert!(
                reported.iter().any(|(found, _)| found == code),
                "{code} is reported when the list is whole: {reported:?}"
            );
        }
        let deferred = offline_findings(&with_kinds(
            "[civil-registry-app, \"${DOCUMENTS_CLIENT_UNSET}\"]",
        ));
        for code in [
            ACTOR_KIND_FOR_UNADMITTED_CLIENT_CODE,
            ASSERTION_ISSUER_CLIENT_NOT_ALLOWED_CODE,
        ] {
            assert!(
                deferred.iter().all(|(found, _)| found != code),
                "{code} waits for the list: {deferred:?}"
            );
        }
    }

    #[test]
    fn an_expression_in_another_entrys_list_leaves_an_entrys_audience_rule_reported() {
        let text = two_entry_runtime()
            .replace(
                "        # accessTokenType: at+jwt\n",
                "        accessTokenType: JWT\n",
            )
            .replace(
                "audience: urn:example:documents\n",
                "audience: citizen-portal\n",
            )
            .replace(
                "allowedClients: [case-portal, partner-portal]",
                "allowedClients: [case-portal, \"${DOCUMENTS_CLIENT_UNSET}\"]",
            );
        assert!(text.contains("accessTokenType: JWT"));
        let reported = offline_findings(&text);
        assert!(
            reported.contains(&(
                AUDIENCE_IS_A_CLIENT_CODE.to_owned(),
                "/authentication/oidc/issuers/main/audience".to_owned()
            )),
            "{reported:?}"
        );
    }

    #[test]
    fn a_profile_client_no_entry_admits_is_reported_at_the_entry_or_at_the_list() {
        let pointer_of = |text: &str| {
            let config = parse(text).expect("valid before clients resolve");
            config
                .project_findings(&starter_project())
                .into_iter()
                .filter(|finding| finding.code == PROFILE_CLIENT_NOT_ALLOWED_CODE)
                .map(|finding| finding.pointer)
                .collect::<Vec<_>>()
        };
        let one = STARTER_RUNTIME.replace(
            STARTER_CLIENTS,
            "allowedClients: [civil-registry-app, citizen-portal, case-portal]",
        );
        assert_eq!(
            pointer_of(&one),
            ["/authentication/oidc/issuers/main/allowedClients"]
        );
        let several = two_entry_runtime().replace(
            "allowedClients: [case-portal, partner-portal]",
            "allowedClients: [case-portal]",
        );
        assert_eq!(pointer_of(&several), ["/authentication/oidc/issuers"]);
    }

    #[test]
    fn every_removed_single_issuer_key_names_the_entry_it_moves_under() {
        for key in [
            "issuer",
            "audience",
            "jwksUri",
            "jwksSource",
            "allowInsecureHttp",
            "allowedClients",
            "assertionIssuers",
            "scopeClaim",
        ] {
            let text =
                STARTER_RUNTIME.replace("    issuers:\n", &format!("    {key}: x\n    issuers:\n"));
            let RuntimeConfigError::Load(error) = parse(&text).unwrap_err() else {
                panic!("{key}: a load refusal");
            };
            let moved: Vec<_> = error
                .diagnostics()
                .iter()
                .filter(|diagnostic| diagnostic.code == "config.removed-key")
                .collect();
            assert_eq!(moved.len(), 1, "{key}: {:?}", error.diagnostics());
            assert!(
                moved[0]
                    .suggested_action
                    .contains("authentication.oidc.issuers.ISSUER_ID"),
                "{key}: {}",
                moved[0].suggested_action
            );
        }
    }

    #[test]
    fn a_non_default_token_type_or_scope_claim_is_an_explicit_production_setting() {
        let directory = tempfile::tempdir().unwrap();
        let strict = directory.path().join("strict.yaml");
        std::fs::write(&strict, STARTER_RUNTIME).unwrap();
        assert_eq!(
            check_runtime_file(&strict, false, None)
                .explicit_settings
                .map(|settings| settings.len()),
            Some(0)
        );
        let text = STARTER_RUNTIME
            .replace(
                "        # accessTokenType: at+jwt\n",
                "        accessTokenType: JWT\n",
            )
            .replace("        # scopeClaim: scope\n", "        scopeClaim: scp\n");
        let path = directory.path().join("runtime.yaml");
        std::fs::write(&path, text).unwrap();
        let checked = check_runtime_file(&path, false, None);
        let found: Vec<(&str, Option<&str>)> = checked
            .explicit_settings
            .iter()
            .flatten()
            .map(|found| (found.setting.code, found.pointer.as_deref()))
            .collect();
        assert!(
            found.contains(&(
                "platform.posture.jwt-access-token",
                Some("/authentication/oidc/issuers/main/accessTokenType")
            )),
            "{found:?}"
        );
        assert!(
            found.contains(&(
                "platform.posture.scope-claim",
                Some("/authentication/oidc/issuers/main/scopeClaim")
            )),
            "{found:?}"
        );
    }

    #[test]
    fn explicit_settings_are_absent_for_a_file_that_never_decoded_and_empty_for_a_refused_one() {
        let directory = tempfile::tempdir().unwrap();
        let undecoded = directory.path().join("undecoded.yaml");
        std::fs::write(
            &undecoded,
            STARTER_RUNTIME.replace("    issuers:\n", "    scopeClaim: scp\n    issuers:\n"),
        )
        .unwrap();
        let checked = check_runtime_file(&undecoded, false, None);
        assert!(checked.report.has_errors());
        assert!(checked.explicit_settings.is_none());
        let refused = directory.path().join("refused.yaml");
        std::fs::write(
            &refused,
            STARTER_RUNTIME.replace(STARTER_CLIENTS, "allowedClients: unrestricted"),
        )
        .unwrap();
        let checked = check_runtime_file(&refused, false, None);
        assert!(checked.report.has_errors());
        assert_eq!(
            checked.explicit_settings.map(|settings| settings.len()),
            Some(0)
        );
    }

    #[test]
    fn the_old_single_issuer_keys_are_refused_with_the_entry_they_move_under() {
        let text = STARTER_RUNTIME.replace("    issuers:\n", "    scopeClaim: scp\n    issuers:\n");
        let found = codes(parse(&text).unwrap_err());
        assert_eq!(found, ["config.removed-key"], "{found:?}");
    }

    #[test]
    fn from_package_never_reaches_the_verifier_as_an_empty_list() {
        let config = parse(&from_package_runtime()).unwrap();
        let mut project = starter_project();
        project.access_profiles.clear();
        let finding = config.admitted_clients(&project).unwrap_err();
        assert_eq!(finding.code, "documents.runtime.allowed-clients-required");
    }

    #[test]
    fn disabled_content_verification_requires_declared_development() {
        let disabled = STARTER_RUNTIME.replace(HTTP_VERIFIER, "  type: disabled\n");
        assert_ne!(disabled, STARTER_RUNTIME);
        for declared in [
            DEFAULT_POSTURE,
            DeclaredPosture {
                posture: Posture::Production,
                source: PostureSource::Flag,
            },
        ] {
            assert_eq!(
                codes(parse_with_posture(&disabled, declared).unwrap_err()),
                ["documents.posture.content-verification-disabled"]
            );
        }
    }

    #[test]
    fn disabled_verification_is_readable_with_the_development_witness() {
        let document = STARTER_RUNTIME.replace(HTTP_VERIFIER, "  type: disabled\n");
        let declared = DeclaredPosture {
            posture: Posture::Development,
            source: PostureSource::Flag,
        };
        let loaded = RuntimeConfig::loader_with_posture(declared)
            .parse_str::<RuntimeConfig>(&document, |_| None)
            .unwrap();
        assert_eq!(
            loaded.posture.ready_member()["developmentSettings"],
            serde_json::json!([{
                "code": "documents.posture.content-verification-disabled",
                "pointer": "/contentVerification",
            }])
        );
        assert!(loaded.config.content_verification.get(None).is_err());
        assert!(matches!(
            loaded
                .config
                .content_verification
                .get(loaded.development.as_ref())
                .unwrap(),
            ContentVerificationConfig::Disabled {}
        ));
    }

    #[test]
    fn plain_http_transport_accepts_only_loopback() {
        for (host, accepted) in [("127.0.0.1", true), ("10.0.0.5", false)] {
            for text in [
                with_s3(&format!("http://{host}"), ""),
                STARTER_RUNTIME.replace("https://scanner.example.test", &format!("http://{host}")),
                STARTER_RUNTIME.replace(
                    "https://civil-registry.example.test",
                    &format!("http://{host}"),
                ),
            ] {
                for posture in [Posture::Production, Posture::Development] {
                    let declared = DeclaredPosture {
                        posture,
                        source: PostureSource::Flag,
                    };
                    match parse_with_posture(&text, declared) {
                        Ok(_) => assert!(accepted, "{host}"),
                        Err(error) => {
                            assert!(!accepted, "{host}: {error}");
                            assert_eq!(codes(error), ["documents.runtime.insecure-url"]);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn a_reference_to_a_disabled_provider_is_refused() {
        let text = STARTER_RUNTIME.replace(
            "hmacSha256KeyRef: secret:file/owning-system-events-hmac",
            "hmacSha256KeyRef: secret:env/OWNING_SYSTEM_EVENTS_HMAC",
        );
        assert_ne!(text, STARTER_RUNTIME);
        let error = parse(&text).unwrap_err();
        let RuntimeConfigError::Refused(findings) = error else {
            panic!("a refused document");
        };
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].pointer,
            "/destinations/hooks/owning-system-events/hmacSha256KeyRef"
        );
        assert!(!findings[0].message.contains("OWNING_SYSTEM_EVENTS_HMAC"));
    }

    #[cfg(unix)]
    fn activate_test_hook_keys(
        text: &str,
        keys: &[(&str, &[u8])],
    ) -> Result<crate::hooks::ActivatedHooks, crate::hooks::HookActivationError> {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        for (name, bytes) in keys {
            let path = directory.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let configuration = parse(&text.replace(
            "/run/secrets/registry-documents",
            directory.path().to_str().unwrap(),
        ))
        .expect("the runtime document parses");
        crate::hooks::ActivatedHooks::activate(
            &[],
            &configuration.destinations.hooks,
            &configuration.secret_resolver().unwrap(),
            crate::hooks::HookRuntimeIdentity {
                project_id: "civil-registry-documents".to_owned(),
                package_digest: format!("sha256:{}", "0".repeat(64)),
                database_id: "documents-test".to_owned(),
            },
            "public".to_owned(),
            std::time::Duration::from_secs(86400),
        )
    }

    const CURRENT_HOOK_KEY_REF: &str = "hmacSha256KeyRef: secret:file/owning-system-events-hmac";
    #[cfg(unix)]
    const CURRENT_HOOK_KEY: &[u8] = b"synthetic-current-hook-key-123456";

    fn rotating_hook_runtime() -> String {
        STARTER_RUNTIME.replace(
            CURRENT_HOOK_KEY_REF,
            &format!(
                "{CURRENT_HOOK_KEY_REF}\n      previousHmacSha256KeyRef: secret:file/previous"
            ),
        )
    }

    #[test]
    fn hook_signing_keys_refuse_a_previous_reference_to_a_disabled_provider() {
        let text =
            rotating_hook_runtime().replace("secret:file/previous", "secret:env/PREVIOUS_HOOK_KEY");
        let error = parse(&text).expect_err("a disabled secret provider is refused");
        let RuntimeConfigError::Refused(findings) = error else {
            panic!("a refused document");
        };
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].pointer,
            "/destinations/hooks/owning-system-events/previousHmacSha256KeyRef"
        );
        assert!(!findings[0].message.contains("PREVIOUS_HOOK_KEY"));
    }

    #[cfg(unix)]
    #[test]
    fn hook_signing_keys_accept_a_distinct_previous_key() {
        activate_test_hook_keys(
            &rotating_hook_runtime(),
            &[
                ("owning-system-events-hmac", CURRENT_HOOK_KEY),
                ("previous", &[b'p'; 32]),
            ],
        )
        .expect("distinct current and previous keys activate");
    }

    #[cfg(unix)]
    #[test]
    fn hook_signing_keys_refuse_a_previous_key_equal_to_the_current_key() {
        let error = activate_test_hook_keys(
            &rotating_hook_runtime(),
            &[
                ("owning-system-events-hmac", CURRENT_HOOK_KEY),
                ("previous", CURRENT_HOOK_KEY),
            ],
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            error,
            "destinations.hooks.owning-system-events.previousHmacSha256KeyRef holds the same bytes as destinations.hooks.owning-system-events.hmacSha256KeyRef. To rotate, write 32 new random bytes to the secret destinations.hooks.owning-system-events.hmacSha256KeyRef references and keep the old bytes behind destinations.hooks.owning-system-events.previousHmacSha256KeyRef."
        );
        assert!(!error.contains(std::str::from_utf8(CURRENT_HOOK_KEY).unwrap()));
    }

    #[cfg(unix)]
    #[test]
    fn hook_signing_keys_report_length_and_trailing_newline() {
        let mut key = [b'x'; 65];
        key[64] = b'\n';
        let error =
            activate_test_hook_keys(STARTER_RUNTIME, &[("owning-system-events-hmac", &key)])
                .unwrap_err()
                .to_string();
        for detail in [
            "destinations.hooks.owning-system-events.hmacSha256KeyRef",
            "65 bytes",
            "trailing newline: true",
            "Supply 32 to 64 exact key bytes.",
        ] {
            assert!(error.contains(detail), "{error}");
        }
        assert!(!error.contains("xxxxxxxx"));
    }

    #[cfg(unix)]
    #[test]
    fn hook_signing_keys_refuse_previous_key_secret_text() {
        let text = b"whsec_synthetic-secret-encoding";
        let error = activate_test_hook_keys(
            &rotating_hook_runtime(),
            &[
                ("owning-system-events-hmac", CURRENT_HOOK_KEY),
                ("previous", text),
            ],
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.starts_with("destinations.hooks.owning-system-events.previousHmacSha256KeyRef:")
        );
        assert!(error.contains("starts with whsec_"));
        assert!(error.ends_with("Supply the exact key bytes without the whsec_ encoding."));
        assert!(!error.contains(std::str::from_utf8(text).unwrap()));
    }

    #[cfg(unix)]
    #[test]
    fn hook_signing_keys_report_both_destinations_when_their_keys_match() {
        let text = STARTER_RUNTIME.replace(
            "    owning-system-events:\n",
            "    audit-mirror:\n      url: https://mirror.example.test/documents\n      hmacSha256KeyRef: secret:file/mirror\n    owning-system-events:\n",
        );
        let error = activate_test_hook_keys(
            &text,
            &[
                ("owning-system-events-hmac", CURRENT_HOOK_KEY),
                ("mirror", CURRENT_HOOK_KEY),
            ],
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            error,
            "destinations.hooks.audit-mirror.hmacSha256KeyRef and destinations.hooks.owning-system-events.hmacSha256KeyRef resolve to the same key bytes. Give destinations.hooks.owning-system-events.hmacSha256KeyRef its own key by writing 32 new random bytes to another secret and referencing it there."
        );
        assert!(!error.contains(std::str::from_utf8(CURRENT_HOOK_KEY).unwrap()));
    }

    #[test]
    fn a_non_loopback_plaintext_hook_destination_is_refused_in_both_postures() {
        let text = STARTER_RUNTIME.replace(
            "url: https://civil-registry.example.test/document-events",
            "url: http://civil-registry.example.test/document-events",
        );
        assert_ne!(text, STARTER_RUNTIME);
        for posture in [Posture::Production, Posture::Development] {
            let declared = DeclaredPosture {
                posture,
                source: PostureSource::Flag,
            };
            assert_eq!(
                codes(parse_with_posture(&text, declared).unwrap_err()),
                ["documents.runtime.insecure-url"]
            );
        }
    }

    const HTTP_VERIFIER: &str = "  type: http\n  url: https://scanner.example.test/v1/verify\n  authorizationRef: secret:file/content-verifier-authorization\n  policyId: documents-default\n  attemptTimeoutMilliseconds: 10000\n";

    const DATABASE_STORAGE: &str = "  type: database\n  maximumDocumentBytes: 16777216\n";

    fn with_s3(url: &str, extra: &str) -> String {
        let text = STARTER_RUNTIME.replace(
            DATABASE_STORAGE,
            &format!(
                "  type: s3\n  url: {url}\n  bucket: registry-documents\n  region: eu-west-1\n  accessKeyIdRef: secret:file/s3-access-key-id\n  secretAccessKeyRef: secret:file/s3-secret-access-key\n{extra}"
            ),
        );
        assert_ne!(text, STARTER_RUNTIME, "the fixture names database storage");
        text
    }

    #[test]
    fn a_database_ceiling_above_sixteen_mebibytes_is_out_of_range() {
        let text = STARTER_RUNTIME.replace(
            "maximumDocumentBytes: 16777216",
            "maximumDocumentBytes: 16777217",
        );
        assert_ne!(text, STARTER_RUNTIME);
        assert!(codes(parse(&text).unwrap_err()).contains(&"config.out-of-range".to_owned()));
    }

    #[test]
    fn an_omitted_database_ceiling_is_sixteen_mebibytes() {
        let text = STARTER_RUNTIME.replace(DATABASE_STORAGE, "  type: database\n");
        assert_ne!(text, STARTER_RUNTIME);
        let config = parse(&text).expect("an omitted ceiling");
        assert_eq!(config.storage.maximum_document_bytes(), 16_777_216);
    }

    #[test]
    fn s3_storage_reads_the_shared_object_storage_block() {
        let config = parse(&with_s3(
            "https://objects.example.test",
            "  maximumDocumentBytes: 67108864\n",
        ))
        .expect("an s3 storage block");
        let StorageConfig::S3 { settings, .. } = &config.storage else {
            panic!("s3 storage");
        };
        assert_eq!(settings.bucket, "registry-documents");
        assert!(settings.path_style);
        assert_eq!(config.storage.maximum_document_bytes(), 67_108_864);
        let omitted = parse(&with_s3("https://objects.example.test", "")).unwrap();
        assert_eq!(omitted.storage.maximum_document_bytes(), 16_777_216);
    }

    #[test]
    fn an_s3_ceiling_above_sixty_four_mebibytes_is_out_of_range() {
        let text = with_s3(
            "https://objects.example.test",
            "  maximumDocumentBytes: 67108865\n",
        );
        assert!(codes(parse(&text).unwrap_err()).contains(&"config.out-of-range".to_owned()));
    }

    #[test]
    fn an_unknown_s3_member_names_the_shared_keys() {
        let text = with_s3("https://objects.example.test", "  bucketPolicy: open\n");
        assert!(codes(parse(&text).unwrap_err()).contains(&"config.unknown-key".to_owned()));
    }

    #[test]
    fn plaintext_s3_is_refused_outside_development() {
        let text = with_s3("http://objects.example.test", "");
        assert_eq!(
            codes(parse(&text).unwrap_err()),
            ["documents.runtime.insecure-url"]
        );
    }

    #[test]
    fn an_s3_url_with_a_path_is_refused_without_naming_it() {
        let text = with_s3("https://objects.example.test/private-path", "");
        let RuntimeConfigError::Refused(findings) = parse(&text).unwrap_err() else {
            panic!("a refused document");
        };
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "documents.runtime.invalid-object-storage");
        assert_eq!(findings[0].pointer, "/storage");
        assert!(!findings[0].message.contains("private-path"));
    }

    #[test]
    fn s3_credentials_name_an_enabled_provider() {
        let text = with_s3("https://objects.example.test", "").replace(
            "secret:file/s3-access-key-id",
            "secret:env/S3_ACCESS_KEY_ID",
        );
        let RuntimeConfigError::Refused(findings) = parse(&text).unwrap_err() else {
            panic!("a refused document");
        };
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pointer, "/storage/accessKeyIdRef");
        assert!(!findings[0].message.contains("S3_ACCESS_KEY_ID"));
    }

    #[test]
    fn a_verifier_policy_id_outside_printable_ascii_is_refused() {
        let text = STARTER_RUNTIME.replace(
            "policyId: documents-default",
            "policyId: \"documents default\"",
        );
        assert_ne!(text, STARTER_RUNTIME);
        assert_eq!(
            codes(parse(&text).unwrap_err()),
            ["documents.runtime.invalid-content-verification"]
        );
    }

    #[test]
    fn plaintext_database_is_refused_outside_test_builds() {
        let text = STARTER_RUNTIME.replace(
            "  migrationUrlRef: secret:file/migration-database-url\n",
            "  migrationUrlRef: secret:file/migration-database-url\n  testOnlyPlaintext: true\n",
        );
        assert_ne!(text, STARTER_RUNTIME);
        let result = parse(&text);
        if cfg!(feature = "postgres-test") {
            assert!(result.is_ok());
        } else {
            assert_eq!(
                codes(result.unwrap_err()),
                ["platform.database.test-only-plaintext"]
            );
        }
    }

    /// The starter document with its audit block replaced by one writing to
    /// `destination` with `members`, and no rotation or retention else.
    fn with_audit(destination: &str, members: &str) -> String {
        let start = STARTER_RUNTIME
            .find("audit:\n")
            .expect("the starter audit block");
        let hash_key = "  hashKeyRef: secret:file/documents-audit-key\n";
        let end = STARTER_RUNTIME[start..]
            .find(hash_key)
            .expect("the audit hash key")
            + start;
        let path = if destination == "file" {
            "  path: /var/lib/registry-documents/audit.ndjson\n"
        } else {
            ""
        };
        format!(
            "{}audit:\n  destination: {destination}\n{path}{members}{}",
            &STARTER_RUNTIME[..start],
            &STARTER_RUNTIME[end..]
        )
    }

    /// The JSON pointers a refusal names.
    fn pointers(error: RuntimeConfigError) -> Vec<String> {
        match error {
            RuntimeConfigError::Refused(findings) => findings
                .into_iter()
                .map(|finding| finding.pointer)
                .collect(),
            RuntimeConfigError::Load(error) => error
                .diagnostics()
                .iter()
                .map(|diagnostic| diagnostic.path.clone())
                .collect(),
            error => panic!("a refusal naming a member, not {error}"),
        }
    }

    #[test]
    fn the_audit_file_rotates_and_is_kept_as_configured() {
        let text = with_audit("file", "  rotateBytes: 2097152\n  retentionDays: 30\n");
        let config = parse(&text).expect("the audit rotation and retention");
        let AuditDestination::File(file) = config.audit.destination().unwrap() else {
            panic!("a file destination");
        };
        assert_eq!(file.rotate_bytes(), 2_097_152);
        assert_eq!(file.retain_days(), 30);
    }

    #[test]
    fn an_audit_file_without_rotation_or_retention_takes_the_platform_defaults() {
        let config = parse(&with_audit("file", "")).unwrap();
        let AuditDestination::File(file) = config.audit.destination().unwrap() else {
            panic!("a file destination");
        };
        assert_eq!(file.rotate_bytes(), DEFAULT_AUDIT_ROTATE_BYTES);
        assert_eq!(file.retain_days(), DEFAULT_AUDIT_RETAIN_DAYS);
    }

    #[test]
    fn audit_rotation_and_retention_outside_their_bounds_are_refused() {
        for (member, pointer) in [
            ("  rotateBytes: 1048575\n", "/audit/rotateBytes"),
            ("  rotateBytes: 4294967296\n", "/audit/rotateBytes"),
            ("  retentionDays: 0\n", "/audit/retentionDays"),
            ("  retentionDays: 36501\n", "/audit/retentionDays"),
        ] {
            let text = with_audit("file", member);
            assert_eq!(
                codes(parse(&text).unwrap_err()),
                ["config.out-of-range"],
                "{member}"
            );
            assert_eq!(pointers(parse(&text).unwrap_err()), [pointer], "{member}");
        }
        for member in [
            "  rotateBytes: 1048576\n",
            "  rotateBytes: 4294967295\n",
            "  retentionDays: 1\n",
            "  retentionDays: 36500\n",
        ] {
            parse(&with_audit("file", member)).expect(member);
        }
    }

    #[test]
    fn the_audit_retention_takes_the_shared_name() {
        let text = with_audit("file", "  retainDays: 30\n");
        assert_eq!(codes(parse(&text).unwrap_err()), ["config.unknown-key"]);
    }

    #[test]
    fn audit_rotation_and_retention_apply_only_to_a_file() {
        for (member, field) in [
            ("  rotateBytes: 2097152\n", "rotateBytes"),
            ("  retentionDays: 30\n", "retentionDays"),
        ] {
            let text = with_audit("stdout", member);
            let RuntimeConfigError::Refused(findings) = parse(&text).unwrap_err() else {
                panic!("a runtime refusal for {field}");
            };
            assert_eq!(findings.len(), 1, "{findings:?}");
            assert_eq!(findings[0].code, "documents.runtime.invalid-audit");
            assert_eq!(findings[0].pointer, format!("/audit/{field}"));
            assert_eq!(
                findings[0].message,
                format!("audit.{field} applies only when audit.destination is file")
            );
            assert_eq!(
                findings[0].suggested_action,
                "Remove the member, or set audit.destination: file."
            );
        }
    }

    /// The starter runtime with a `metricsListener` bound to `bind` and its
    /// serving listener bound to `listener`.
    fn with_metrics(listener: &str, bind: &str) -> String {
        STARTER_RUNTIME
            .replace("bind: 127.0.0.1:8116", &format!("bind: {listener}"))
            .replace("bind: 127.0.0.1:9116", &format!("bind: \"{bind}\""))
    }

    #[test]
    fn the_metrics_listener_is_off_unless_named() {
        assert!(parse(STARTER_RUNTIME).unwrap().metrics_listener.is_some());
        let start = STARTER_RUNTIME.find("metricsListener:").unwrap();
        let end = STARTER_RUNTIME.find("secretProviders:").unwrap();
        let omitted = format!("{}{}", &STARTER_RUNTIME[..start], &STARTER_RUNTIME[end..]);
        assert!(parse(&omitted).unwrap().metrics_listener.is_none());
    }

    #[test]
    fn the_metrics_listener_must_be_private_and_apart_from_the_listener() {
        for bind in [
            "0.0.0.0:9090",
            "[::]:9090",
            "203.0.113.4:9090",
            "169.254.1.1:9090",
            "[fe80::1]:9090",
            "127.0.0.1:0",
            "[2001:db8::1]:9090",
            "224.0.0.1:9090",
            "127.0.0.1:8116",
        ] {
            let text = with_metrics("127.0.0.1:8116", bind);
            let RuntimeConfigError::Refused(findings) = parse(&text).expect_err(bind) else {
                panic!("a runtime refusal for {bind}");
            };
            assert_eq!(findings.len(), 1, "{bind}: {findings:?}");
            assert_eq!(findings[0].pointer, "/metricsListener/bind", "{bind}");
            assert!(!findings[0].message.contains(bind), "{bind}");
        }
        for bind in [
            "127.0.0.1:9100",
            "10.1.2.3:9100",
            "[::1]:9100",
            "[fd00::5]:9100",
        ] {
            let config = parse(&with_metrics("127.0.0.1:8116", bind)).expect(bind);
            assert!(config.metrics_listener.is_some(), "{bind}");
        }
    }

    #[test]
    fn the_metrics_wildcard_needs_container_private_exposure() {
        let declared = |listener: &str, bind: &str| {
            with_metrics(listener, bind).replace(
                &format!("bind: \"{bind}\""),
                &format!("bind: \"{bind}\"\n  networkExposure: container-private"),
            )
        };
        assert!(parse(&with_metrics("127.0.0.1:8116", "0.0.0.0:9100")).is_err());
        let config = parse(&declared("127.0.0.1:8116", "0.0.0.0:9100"))
            .expect("container-private permits the wildcard");
        assert!(config.metrics_listener.is_some());
        let RuntimeConfigError::Refused(findings) =
            parse(&declared("127.0.0.1:8116", "203.0.113.4:9100")).unwrap_err()
        else {
            panic!("a runtime refusal");
        };
        assert_eq!(findings[0].code, METRICS_LISTENER_CODE);
        let RuntimeConfigError::Refused(findings) =
            parse(&declared("127.0.0.1:8116", "0.0.0.0:8116")).unwrap_err()
        else {
            panic!("a runtime refusal");
        };
        assert_eq!(findings[0].code, METRICS_OVERLAP_CODE);
    }

    #[test]
    fn a_metrics_refusal_names_its_cause_and_remedy() {
        let refusal = |bind: &str| {
            let text = with_metrics("127.0.0.1:8116", bind);
            let RuntimeConfigError::Refused(mut findings) = parse(&text).expect_err(bind) else {
                panic!("a runtime refusal for {bind}");
            };
            findings.remove(0)
        };
        let public = refusal("203.0.113.4:9090");
        assert!(
            public.message.contains("must be loopback or private"),
            "{}",
            public.message
        );
        assert!(
            public
                .suggested_action
                .contains("keep metrics off public addresses"),
            "{}",
            public.suggested_action
        );
        assert!(!public.suggested_action.contains("container-private"));
        let port_zero = refusal("127.0.0.1:0");
        assert!(port_zero.suggested_action.contains("non-zero port"));
        assert!(!port_zero.suggested_action.contains("container-private"));
        let overlap = refusal("127.0.0.1:8116");
        assert!(overlap.suggested_action.contains("its own port"));
        assert!(!overlap.suggested_action.contains("container-private"));
        let wildcard = refusal("0.0.0.0:9090");
        assert!(wildcard
            .suggested_action
            .contains("metricsListener.networkExposure: container-private"));
    }

    #[test]
    fn the_metrics_listener_may_not_share_a_wildcard_listener_port() {
        let shares = |metrics: &str, listener: &str| {
            check_metrics_apart(metrics.parse().unwrap(), listener.parse().unwrap()).is_err()
        };
        assert!(shares("10.0.0.5:8100", "0.0.0.0:8100"));
        assert!(shares("10.0.0.5:8100", "[::]:8100"));
        assert!(!shares("[fd00::5]:8100", "0.0.0.0:8100"));
        assert!(!shares("10.0.0.5:8101", "0.0.0.0:8100"));
    }

    #[cfg(unix)]
    fn offline_codes(text: &str) -> Vec<String> {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .canonicalize()
            .unwrap()
            .join("runtime.yaml");
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let check = check_runtime_file(&path, false, None);
        check
            .report
            .diagnostics()
            .iter()
            .map(|diagnostic| format!("{} {}", diagnostic.code, diagnostic.path))
            .collect()
    }

    /// The offline check runs the shared hook destination check, so it
    /// refuses at the destination's own URL what activation refuses.
    #[cfg(unix)]
    #[test]
    fn the_offline_check_refuses_what_hook_activation_refuses() {
        let starter_url = "url: https://civil-registry.example.test/document-events";
        assert!(STARTER_RUNTIME.contains(starter_url));
        let with_hook = |url: &str| STARTER_RUNTIME.replace(starter_url, &format!("url: {url}"));
        for refused in [
            "https://localhost.:9443/hooks",
            "https://receiver.localhost:9443/hooks",
        ] {
            assert_eq!(
                offline_codes(&with_hook(refused)),
                ["config.invalid-value /destinations/hooks/owning-system-events/url"],
                "{refused}"
            );
        }
        for admitted in [
            "https://localhost:9443/hooks",
            "https://127.0.0.1:9443/hooks",
            "https://[::1]:9443/hooks",
        ] {
            assert_eq!(
                offline_codes(&with_hook(admitted)),
                Vec::<String>::new(),
                "{admitted}"
            );
        }
        // A finding the product already makes at the URL is not repeated.
        assert_eq!(
            offline_codes(&with_hook("http://receiver.example.test/hooks")),
            ["documents.runtime.insecure-url /destinations/hooks/owning-system-events/url"]
        );
    }

    /// Startup names the code and the pointer the offline check reports for
    /// the same runtime document: from the load when the product refuses the
    /// member itself, and from hook activation otherwise.
    #[cfg(unix)]
    #[test]
    fn startup_reports_the_hook_refusal_the_offline_check_reports() {
        let starter_url = "url: https://civil-registry.example.test/document-events";
        let with_hook = |url: &str| STARTER_RUNTIME.replace(starter_url, &format!("url: {url}"));
        let mut documents = [
            "https://localhost.:9443/hooks",
            "https://localhost:0/hooks",
            "https://receiver.localhost:9443/hooks",
            "http://receiver.example.test/hooks",
        ]
        .map(with_hook)
        .to_vec();
        let starter_id = "\n    owning-system-events:\n";
        assert!(STARTER_RUNTIME.contains(starter_id));
        documents.push(STARTER_RUNTIME.replace(starter_id, "\n    \"a/b~c\":\n"));
        for document in documents {
            let offline = offline_codes(&document);
            assert!(!offline.is_empty(), "{document}");
            assert_eq!(startup_refusal(&document), offline, "{document}");
        }
    }

    /// What startup reports for `text`: the load's refusals, or the code and
    /// pointer of the hook activation refusal.
    #[cfg(unix)]
    fn startup_refusal(text: &str) -> Vec<String> {
        let config = match parse(text) {
            Ok(config) => config,
            Err(RuntimeConfigError::Refused(findings)) => {
                return findings
                    .iter()
                    .map(|finding| format!("{} {}", finding.code, finding.pointer))
                    .collect();
            }
            Err(RuntimeConfigError::Load(error)) => {
                return error
                    .diagnostics()
                    .iter()
                    .map(|diagnostic| format!("{} {}", diagnostic.code, diagnostic.path))
                    .collect();
            }
            Err(other) => panic!("an unexpected load refusal: {other}"),
        };
        let secrets = registry_platform_config::SecretResolver::new(
            [registry_platform_config::SecretProvider::Environment],
            "/",
        )
        .expect("the test secret resolver");
        let error = crate::hooks::activate_destinations(
            &std::collections::BTreeSet::new(),
            &config.destinations.hooks,
            &secrets,
        )
        .map(drop)
        .expect_err("startup refuses the destination");
        match (error.code(), error.pointer()) {
            (Some(code), Some(pointer)) => vec![format!("{code} {pointer}")],
            _ => panic!("an unpositioned activation refusal: {error}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn an_expression_serving_bind_defers_only_the_overlap_comparison() {
        // The serving bind is not known, so a metrics bind equal to the
        // stand-in or to the file's other value is not compared.
        let deferred = with_metrics("${DOCUMENTS_BIND}", "127.0.0.1:8116");
        assert_eq!(offline_codes(&deferred), Vec::<String>::new());
        // A metrics bind that is itself public is still reported.
        let public = with_metrics("${DOCUMENTS_BIND}", "203.0.113.4:9090");
        assert_eq!(
            offline_codes(&public),
            ["documents.runtime.invalid-metrics-listener /metricsListener/bind"]
        );
        // A concrete overlap is reported when both binds are known.
        let overlap = with_metrics("127.0.0.1:8116", "127.0.0.1:8116");
        assert_eq!(
            offline_codes(&overlap),
            ["documents.runtime.metrics-listener-overlaps-listener /metricsListener/bind"]
        );
        // An expression metrics bind is not judged at all.
        let expression = with_metrics("127.0.0.1:8116", "${DOCUMENTS_METRICS_BIND}");
        assert_eq!(offline_codes(&expression), Vec::<String>::new());
    }
}
