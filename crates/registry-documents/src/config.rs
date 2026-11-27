// SPDX-License-Identifier: Apache-2.0

//! The operator runtime configuration document.
//!
//! The document is read through the shared runtime loader, so its envelope,
//! keys, and value types are refused exactly as every Registry Stack runtime
//! refuses them. The rules below are the ones a document must satisfy on its
//! own; each finding names the member it concerns and never a configured
//! value.

use std::collections::BTreeMap;
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
pub use registry_platform_config::{
    AdmittedClients, AttachmentVerifierConfig, AuditKeyConfig, DatabaseConfig,
    MetricsListenerConfig, ObjectStorageConfig, OidcIssuerConfig, OidcPackageClientsConfig,
    PackageClients, PackageClientsError, PackageConfig, PrivateListenerConfig as ListenerConfig,
    SecretProvidersConfig, TlsTermination, UrlHookDestinationConfig,
};
use registry_platform_config::{
    ConfigBlockError, RuntimeConfigLoader, RuntimeEnvelope, RuntimeFileCheck, SecretResolver,
    DEFAULT_STAND_IN, REMOVED_OIDC_JWKS_SOURCE_KIND, REMOVED_OIDC_JWKS_URI,
};
use registry_platform_objectstore::{s3::S3Settings, verifier::HttpVerifierSettings};
use registry_platform_oidc::{
    access_token_typ_set, fetch_discovery_for_issuer, parse_static_jwks, AccessTokenAlgorithm,
    IssuerNetworkPolicy, JwksFetcher, JwksFetcherConfig, OidcDiscoveryConfig, OidcError,
    TokenVerifierConfig,
};
use registry_platform_yaml::{BoundedU32, BoundedU64, Diagnostic, ExternalId, LocalId, Report};
use serde::Deserialize;
use thiserror::Error;

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
/// replaced them (CFG-CHANGE-2): the shared OIDC key-source spellings.
const DOCUMENTS_REMOVED_KEYS: &[registry_platform_config::RemovedKey] =
    &[REMOVED_OIDC_JWKS_URI, REMOVED_OIDC_JWKS_SOURCE_KIND];

const METRICS_LISTENER_CODE: &str = "documents.runtime.invalid-metrics-listener";
/// The config path of the exposure key a wildcard metrics refusal names.
const METRICS_NETWORK_EXPOSURE_KEY: &str = "metricsListener.networkExposure";
const METRICS_OVERLAP_CODE: &str = "documents.runtime.metrics-listener-overlaps-listener";

/// The media type an access token must declare (RFC 9068).
const DOCUMENTS_ACCESS_TOKEN_TYPE: &str = "at+jwt";

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
    pub content_verification: ContentVerificationConfig,
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

/// The OIDC issuer whose access tokens this runtime accepts, the clients it
/// admits, and the claim carrying their scopes.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OidcConfig {
    /// The exact token issuer, audience, and signing-key source.
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-issuer"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    pub provider: OidcIssuerConfig,
    /// The OAuth clients this runtime admits: `from-package` for the
    /// requester clients of the project's access profiles, or a list that
    /// covers every client a profile names. Every access profile resolves its
    /// caller from the matched client, so the admitted set is never empty.
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-package-clients"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    pub clients: OidcPackageClientsConfig,
    #[serde(default = "default_scope_claim")]
    pub scope_claim: ExternalId,
}

fn default_scope_claim() -> ExternalId {
    ExternalId::new("scope").expect("`scope` is an external identifier")
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
    /// No verifier, accepted only beside `tlsTermination:
    /// development-loopback`. Every finalized version is recorded as
    /// approved under the `disabled` verifier binding.
    Disabled {},
}
registry_platform_yaml::tagged_union!(ContentVerificationConfig);

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
    pub code: &'static str,
    pub pointer: String,
    pub message: String,
    pub suggested_action: String,
}

impl Finding {
    fn new(
        code: &'static str,
        pointer: &str,
        message: impl Into<String>,
        suggested_action: impl Into<String>,
    ) -> Self {
        Self {
            code,
            pointer: pointer.to_owned(),
            message: message.into(),
            suggested_action: suggested_action.into(),
        }
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
    /// The token issuer's discovery document or key set could not be
    /// fetched or read.
    #[error("the OIDC issuer's signing keys could not be loaded")]
    Oidc,
    /// The static key set named by `authentication.oidc.jwksSource.documentRef`
    /// could not be resolved.
    #[error("{0}")]
    OidcJwksSecret(String),
}

/// The static key set the operator pinned. A document that breaks a key set
/// rule is the operator's to fix, so the refusal says which rule: it never
/// holds a key value.
fn parse_static_key_set(document: &[u8]) -> Result<jsonwebtoken::jwk::JwkSet, RuntimeConfigError> {
    parse_static_jwks(document).map_err(|error| match error {
        OidcError::StaticKeySet(refusal) => RuntimeConfigError::OidcJwksSecret(format!(
            "the document at authentication.oidc.jwksSource.documentRef was refused: {refusal}"
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

impl RuntimeConfig {
    #[must_use]
    pub const fn loader() -> RuntimeConfigLoader {
        RuntimeConfigLoader::new_without_posture(DOCUMENTS_RUNTIME_ENVELOPE)
            .removed_keys(DOCUMENTS_REMOVED_KEYS)
            .require_trusted_ownership()
    }

    /// Load and check the operator document at an absolute path, reading
    /// `${VAR}` expressions from the process environment.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RuntimeConfigError> {
        let loaded = Self::loader().load::<Self>(path.as_ref())?;
        let findings = loaded.config.findings();
        if findings.is_empty() {
            Ok(loaded.config)
        } else {
            Err(RuntimeConfigError::Refused(findings))
        }
    }

    /// The resolver for every secret reference this document names.
    pub fn secret_resolver(&self) -> Result<SecretResolver, RuntimeConfigError> {
        self.secret_providers
            .resolver()
            .map_err(|error| RuntimeConfigError::SecretProviders(error.to_string()))
    }

    /// Build the token verifier's key source from the configured JWKS
    /// source.
    pub async fn jwks_fetcher(
        &self,
        secrets: &SecretResolver,
    ) -> Result<std::sync::Arc<JwksFetcher>, RuntimeConfigError> {
        let provider = &self.authentication.oidc.provider;
        if provider.allow_insecure_http {
            tracing::warn!(
                "authentication.oidc.allowInsecureHttp permits plain HTTP to the configured issuer and to a JWKS URI declared in configuration"
            );
        }
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
                        "authentication.oidc.jwksSource.documentRef",
                        document_ref,
                        &error,
                    ))
                })?;
                let jwks = parse_static_key_set(document.expose_secret())?;
                JwksFetcher::new_static(jwks, JwksFetcherConfig::defaults())
            }
        };
        Ok(std::sync::Arc::new(fetcher))
    }

    /// The access-token verifier profile this deployment's OIDC settings
    /// describe: RFC 9068 access tokens only, from the configured issuer,
    /// for the configured audience, from an admitted client.
    #[must_use]
    pub fn verifier_profile(&self, admitted: &AdmittedClients) -> TokenVerifierConfig {
        let oidc = &self.authentication.oidc;
        TokenVerifierConfig::access_token_profile(
            oidc.provider.issuer.to_string(),
            vec![oidc.provider.audience.clone()],
            vec![
                AccessTokenAlgorithm::RS256.to_jsonwebtoken(),
                AccessTokenAlgorithm::ES256.to_jsonwebtoken(),
            ],
            access_token_typ_set(DOCUMENTS_ACCESS_TOKEN_TYPE),
        )
        .with_scope_claim(oidc.scope_claim.as_str().to_owned())
        .with_allowed_clients(admitted.as_slice().to_vec())
        .with_assertion_issuers(oidc.clients.assertion_issuers.clone())
    }

    /// Whether this deployment declared any token-exchange authority.
    #[must_use]
    pub fn binds_assertion_issuers(&self) -> bool {
        !self
            .authentication
            .oidc
            .clients
            .assertion_issuers
            .is_empty()
    }

    /// Every rule this document breaks, in document order.
    #[must_use]
    pub fn findings(&self) -> Vec<Finding> {
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
                "Bind a loopback address for development-loopback, a loopback or private address behind operator-controlled-upstream, or the unspecified address only with container-private.",
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
        if let ContentVerificationConfig::Http { settings } = &self.content_verification {
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
        if self.database.test_only_plaintext && !cfg!(feature = "postgres-test") {
            findings.push(Finding::new(
                "documents.runtime.plaintext-database",
                "/database/testOnlyPlaintext",
                "database.testOnlyPlaintext is accepted only by test builds",
                "Remove database.testOnlyPlaintext and connect over TLS.",
            ));
        }
    }

    fn check_oidc(&self, findings: &mut Vec<Finding>) {
        let oidc = &self.authentication.oidc;
        let development = self.listener.tls_termination == TlsTermination::DevelopmentLoopback;
        if let Err(error) = oidc
            .provider
            .check_without_posture("authentication.oidc", development)
        {
            findings.push(Finding::block("/authentication/oidc", &error));
        }
        if let Err(error) = oidc.clients.check("authentication.oidc") {
            findings.push(Finding::block("/authentication/oidc", &error));
        }
        if oidc.clients.allowed_clients == PackageClients::Unrestricted {
            findings.push(allowed_clients_required());
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
        let development = self.listener.tls_termination == TlsTermination::DevelopmentLoopback;
        if !settings.url.is_https() && !development {
            findings.push(Finding::new(
                "documents.runtime.insecure-url",
                "/storage/url",
                "storage.url must be an https URL",
                "Write an https URL, or run the listener in development-loopback mode.",
            ));
        } else if S3Settings::from_config(settings).is_err() {
            findings.push(Finding::new(
                "documents.runtime.invalid-object-storage",
                "/storage",
                "storage is not a usable S3 bucket: url must be https (http only for a loopback host) with no path, query, or fragment, and bucket and region must be lowercase S3 names",
                "Correct storage.url, storage.bucket, and storage.region.",
            ));
        }
    }

    fn check_content_verification(&self, findings: &mut Vec<Finding>) {
        let development = self.listener.tls_termination == TlsTermination::DevelopmentLoopback;
        match &self.content_verification {
            ContentVerificationConfig::Disabled {} if !development => {
                findings.push(Finding::new(
                    "documents.runtime.content-verification-disabled",
                    "/contentVerification/type",
                    "contentVerification type disabled is accepted only beside listener.tlsTermination development-loopback",
                    "Configure an http content verifier, or run the listener in development-loopback mode.",
                ));
            }
            ContentVerificationConfig::Http { settings }
                if !settings.url.is_https() && !development =>
            {
                findings.push(Finding::new(
                    "documents.runtime.insecure-url",
                    "/contentVerification/url",
                    "contentVerification.url must be an https URL",
                    "Write an https URL, or run the listener in development-loopback mode.",
                ));
            }
            ContentVerificationConfig::Http { settings }
                if HttpVerifierSettings::from_config(settings).is_err() =>
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
        let development = self.listener.tls_termination == TlsTermination::DevelopmentLoopback;
        for (id, destination) in &self.destinations.hooks {
            if !destination.url.is_https() && !development {
                findings.push(Finding::new(
                    "documents.runtime.insecure-url",
                    &format!("/destinations/hooks/{}/url", escape(id)),
                    format!("destinations.hooks.{id}.url must be an https URL"),
                    "Write an https URL, or run the listener in development-loopback mode.",
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

    /// The clients the token verifier admits, given the project this runtime
    /// serves. `from-package` is the sorted union of the access profiles'
    /// requester clients, and a list must cover every one of them, or the
    /// profile naming the missing client could never be reached. The verifier
    /// is never handed an empty list, which it reads as "every client".
    pub fn admitted_clients(&self, project: &DocumentsProject) -> Result<AdmittedClients, Finding> {
        self.authentication
            .oidc
            .clients
            .allowed_clients
            .resolve(&requester_clients(project))
            .map_err(|error| match error {
                PackageClientsError::Unrestricted | PackageClientsError::Empty => {
                    allowed_clients_required()
                }
                PackageClientsError::Missing(client) => {
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
                        "/authentication/oidc/allowedClients",
                        format!(
                            "authentication.oidc.allowedClients does not list {client}, a requester client of access profile {profile}"
                        ),
                        "Add the client to allowedClients, or write allowedClients: from-package to admit every requester client the project names.",
                    )
                }
            })
    }

    /// What the admitted clients leave wrong against the project. An
    /// `unrestricted` value is reported by [`Self::findings`] alone.
    fn client_findings(&self, project: &DocumentsProject) -> Vec<Finding> {
        let oidc = &self.authentication.oidc;
        if oidc.clients.allowed_clients == PackageClients::Unrestricted {
            return Vec::new();
        }
        let admitted = match self.admitted_clients(project) {
            Ok(admitted) => admitted,
            Err(finding) => return vec![finding],
        };
        oidc.clients
            .assertion_issuers
            .keys()
            .filter(|client| !admitted.as_slice().contains(client))
            .map(|client| {
                Finding::new(
                    ASSERTION_ISSUER_CLIENT_NOT_ALLOWED_CODE,
                    &format!("/authentication/oidc/assertionIssuers/{}", escape(client)),
                    format!(
                        "authentication.oidc.assertionIssuers names {client}, which no access profile of the project lists as a requester client"
                    ),
                    "Name a requester client of an access profile, or remove the entry.",
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

fn allowed_clients_required() -> Finding {
    Finding::new(
        ALLOWED_CLIENTS_REQUIRED_CODE,
        "/authentication/oidc/allowedClients",
        "authentication.oidc.allowedClients must be `from-package` or list the clients this runtime admits; `unrestricted` is refused",
        "Write allowedClients: from-package, or list every OAuth client an access profile names.",
    )
}

/// What an offline check of one runtime document found (CFG-CHECK-1).
#[derive(Debug)]
pub struct RuntimeCheck {
    /// Every finding, positioned at the member it concerns, in file order.
    pub report: Report,
    /// The file could not be read at all, as opposed to read and refused.
    pub unavailable: bool,
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
    let check =
        RuntimeConfig::loader().check_offline::<RuntimeConfig>(path, substitute, stand_in_for);
    let diagnostics: Vec<Diagnostic> = match &check.loaded {
        Some(loaded) => {
            let mut findings = loaded.config.findings();
            if let Some(project) = project {
                findings.extend(loaded.config.project_findings(project));
            }
            findings
                .iter()
                .filter(|finding| !is_deferred(&check, finding))
                .map(|finding| positioned(&check, finding))
                .collect()
        }
        None => Vec::new(),
    };
    RuntimeCheck {
        report: check.report_with(DOCUMENTS_RUNTIME_KIND, diagnostics),
        unavailable: check.unavailable,
    }
}

/// Whether `finding` reads a member the check left as an expression, so a
/// stand-in, not the operator's value, decided it. The overlap finding reads
/// both binds, and sits at the metrics bind: when only the serving bind is
/// an expression it is the only finding left out.
fn is_deferred(check: &RuntimeFileCheck<RuntimeConfig>, finding: &Finding) -> bool {
    check.defers_within(&finding.pointer)
        || (finding.code == METRICS_OVERLAP_CODE && check.defers("/listener/bind"))
        || (finding.code == METRICS_LISTENER_CODE
            && check.defers("/metricsListener/networkExposure"))
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
    match error {
        RuntimeConfigError::Load(error) => Some(Report::new(error.diagnostics().to_vec())),
        RuntimeConfigError::Refused(_) => {
            let report = check_runtime_file(path, true, None).report;
            (!report.is_empty()).then_some(report)
        }
        RuntimeConfigError::SecretProviders(_)
        | RuntimeConfigError::Oidc
        | RuntimeConfigError::OidcJwksSecret(_) => None,
    }
}

/// `finding` at the value of its member, or, for a member that is absent, at
/// the nearest mapping above it that is present.
fn positioned(check: &RuntimeFileCheck<RuntimeConfig>, finding: &Finding) -> Diagnostic {
    let mut diagnostic = check.error_at(
        DOCUMENTS_RUNTIME_KIND,
        finding.code,
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
        ["listener", "tlsTermination"] => "development-loopback",
        ["listener", "networkExposure"] => "private-address",
        ["audit", "destination"] => "file",
        ["package", "root"] | ["audit", "path"] | ["secretProviders", "file", "root"] => {
            "/deferred"
        }
        ["package", "expectedDigest"] => {
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
        ["authentication", "oidc", "issuer"]
        | ["authentication", "oidc", "jwksSource", "uri"]
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
        let config = RuntimeConfig::loader()
            .parse_str::<RuntimeConfig>(text, |_| None)?
            .config;
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
        assert!(diagnostic
            .message
            .contains("owned by root or the runtime user"));
        assert!(diagnostic
            .suggested_action
            .contains("remove group and other write permission"));
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
        let jwks = parse_static_key_set(document.as_bytes()).expect("unknown public members load");
        assert_eq!(jwks.keys.len(), 1);
    }

    #[test]
    fn a_static_key_set_that_holds_a_private_member_is_refused_by_rule_and_not_by_value() {
        let secret = "private-canary-value";
        let document = key_set(&format!(r#""d":"{secret}""#));
        let RuntimeConfigError::OidcJwksSecret(message) =
            parse_static_key_set(document.as_bytes()).expect_err("a private member is refused")
        else {
            panic!("a refused key set is not an issuer outage");
        };
        assert!(
            message.contains(r#"private-key member "d""#),
            "the refusal names the private-key member rule"
        );
        assert!(message.contains("authentication.oidc.jwksSource.documentRef"));
        assert!(
            !message.contains(secret),
            "the refusal holds the private member's value"
        );
    }

    #[test]
    fn a_static_key_set_that_is_not_json_is_not_an_issuer_outage() {
        assert!(matches!(
            parse_static_key_set(b"not json"),
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
            config.content_verification,
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
            config.authentication.oidc.clients.allowed_clients,
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
            ["documents.runtime.profile-client-not-allowed /authentication/oidc/allowedClients"]
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
                    "allowedClients: from-package\n    assertionIssuers:\n      {client}: [https://assertions.example.test]\n"
                ),
            )
        };
        let config = parse(&with_issuers("unknown-client")).unwrap();
        assert_eq!(
            project_finding_codes(&config, &starter_project()),
            ["documents.runtime.assertion-issuer-client-not-allowed /authentication/oidc/assertionIssuers/unknown-client"]
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
            "allowedClients: from-package\n    assertionIssuers:\n      com.example.portal: [https://assertions.example.test]\n",
        );
        let config = parse(&text).unwrap();
        assert_eq!(
            project_finding_codes(&config, &starter_project()),
            ["documents.runtime.assertion-issuer-client-not-allowed /authentication/oidc/assertionIssuers/com.example.portal"]
        );
    }

    #[test]
    fn assertion_issuer_client_outside_an_explicit_list_is_refused() {
        let text = STARTER_RUNTIME.replace(
            "allowedClients: [civil-registry-app, citizen-portal, case-portal, partner-portal]\n",
            "allowedClients: [civil-registry-app, citizen-portal, case-portal, partner-portal]\n    assertionIssuers:\n      unknown-client: [https://assertions.example.test]\n",
        );
        assert_ne!(text, STARTER_RUNTIME);
        let config = parse(&text).unwrap();
        assert_eq!(
            project_finding_codes(&config, &starter_project()),
            ["documents.runtime.assertion-issuer-client-not-allowed /authentication/oidc/assertionIssuers/unknown-client"]
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
        let mut profile = config.verifier_profile(&admitted);
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

    #[test]
    fn from_package_never_reaches_the_verifier_as_an_empty_list() {
        let config = parse(&from_package_runtime()).unwrap();
        let mut project = starter_project();
        project.access_profiles.clear();
        let finding = config.admitted_clients(&project).unwrap_err();
        assert_eq!(finding.code, "documents.runtime.allowed-clients-required");
    }

    #[test]
    fn disabled_content_verification_requires_development_loopback() {
        let disabled = STARTER_RUNTIME.replace(HTTP_VERIFIER, "  type: disabled\n");
        assert_ne!(disabled, STARTER_RUNTIME);
        assert_eq!(
            codes(parse(&disabled).unwrap_err()),
            ["documents.runtime.content-verification-disabled"]
        );
        let development = disabled.replace(
            "tlsTermination: operator-controlled-upstream",
            "tlsTermination: development-loopback",
        );
        assert!(parse(&development).is_ok());
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
            "`destinations.hooks.owning-system-events.previousHmacSha256KeyRef` holds the same bytes as `destinations.hooks.owning-system-events.hmacSha256KeyRef`. To rotate, write 32 new random bytes to the secret `destinations.hooks.owning-system-events.hmacSha256KeyRef` references and keep the old bytes behind `destinations.hooks.owning-system-events.previousHmacSha256KeyRef`."
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
    fn a_plaintext_hook_destination_is_refused_outside_development() {
        let text = STARTER_RUNTIME.replace(
            "url: https://civil-registry.example.test/document-events",
            "url: http://civil-registry.example.test/document-events",
        );
        assert_ne!(text, STARTER_RUNTIME);
        assert_eq!(
            codes(parse(&text).unwrap_err()),
            ["documents.runtime.insecure-url"]
        );
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
                ["documents.runtime.plaintext-database"]
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
