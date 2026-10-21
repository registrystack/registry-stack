// SPDX-License-Identifier: Apache-2.0

//! The operator runtime configuration document.
//!
//! The document is read through the shared runtime loader, so its envelope,
//! keys, and value types are refused exactly as every Registry Stack runtime
//! refuses them. The rules below are the ones a document must satisfy on its
//! own; each finding names the member it concerns and never a configured
//! value.

use std::collections::BTreeMap;
use std::path::Path;

use jsonwebtoken::Algorithm;
use registry_documents_core::{DOCUMENTS_RUNTIME_API_VERSION, DOCUMENTS_RUNTIME_KIND};
use registry_platform_audit::{AuditDestination, AuditDestinationKind};
use registry_platform_config::JwksSource;
pub use registry_platform_config::{
    AttachmentVerifierConfig, AuditKeyConfig, DatabaseConfig, ObjectStorageConfig,
    OidcClientsConfig, OidcIssuerConfig, PackageConfig, PrivateListenerConfig as ListenerConfig,
    SecretProvidersConfig, TlsTermination, UrlHookDestinationConfig,
};
use registry_platform_config::{
    ConfigBlockError, RuntimeConfigLoader, RuntimeEnvelope, RuntimeFileCheck, SecretResolver,
    DEFAULT_STAND_IN, REMOVED_OIDC_JWKS_SOURCE_KIND, REMOVED_OIDC_JWKS_URI,
};
use registry_platform_objectstore::{s3::S3Settings, verifier::HttpVerifierSettings};
use registry_platform_oidc::{
    access_token_typ_set, fetch_discovery_for_issuer, parse_static_jwks, IssuerNetworkPolicy,
    JwksFetcher, JwksFetcherConfig, OidcDiscoveryConfig, TokenVerifierConfig,
};
use registry_platform_yaml::{BoundedU32, BoundedU64, Diagnostic, ExternalId, LocalId, Report};
use serde::Deserialize;
use thiserror::Error;

pub(crate) use registry_platform_config::describe_secret_failure;

/// The default listener binding. Each Registry Stack runtime has its own
/// default port so a laptop can run several side by side.
pub const DEFAULT_LISTENER_BIND: &str = "127.0.0.1:8116";

pub const DOCUMENTS_RUNTIME_ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: DOCUMENTS_RUNTIME_API_VERSION,
    kind: DOCUMENTS_RUNTIME_KIND,
};

/// The keys the runtime document refuses with the sentence naming what
/// replaced them (CFG-CHANGE-2): the shared OIDC key-source spellings.
const DOCUMENTS_REMOVED_KEYS: &[registry_platform_config::RemovedKey] =
    &[REMOVED_OIDC_JWKS_URI, REMOVED_OIDC_JWKS_SOURCE_KIND];

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
    /// The OAuth clients this runtime admits. Every access profile resolves
    /// its caller from the matched client, so the list is never empty.
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-clients"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    pub clients: OidcClientsConfig,
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
    pub suggested_action: &'static str,
}

impl Finding {
    fn new(
        code: &'static str,
        pointer: &str,
        message: impl Into<String>,
        suggested_action: &'static str,
    ) -> Self {
        Self {
            code,
            pointer: pointer.to_owned(),
            message: message.into(),
            suggested_action,
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
        RuntimeConfigLoader::new(DOCUMENTS_RUNTIME_ENVELOPE).removed_keys(DOCUMENTS_REMOVED_KEYS)
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
            JwksSource::Static { document_ref } => {
                let document = secrets.resolve(document_ref).map_err(|error| {
                    RuntimeConfigError::OidcJwksSecret(describe_secret_failure(
                        "authentication.oidc.jwksSource.documentRef",
                        document_ref,
                        &error,
                    ))
                })?;
                let jwks = parse_static_jwks(document.expose_secret())
                    .map_err(|_| RuntimeConfigError::Oidc)?;
                JwksFetcher::new_static(jwks, JwksFetcherConfig::defaults())
            }
        };
        Ok(std::sync::Arc::new(fetcher))
    }

    /// The access-token verifier profile this deployment's OIDC settings
    /// describe: RFC 9068 access tokens only, from the configured issuer,
    /// for the configured audience, from an admitted client.
    #[must_use]
    pub fn verifier_profile(&self) -> TokenVerifierConfig {
        let oidc = &self.authentication.oidc;
        TokenVerifierConfig::access_token_profile(
            oidc.provider.issuer.to_string(),
            vec![oidc.provider.audience.clone()],
            vec![Algorithm::RS256, Algorithm::ES256],
            access_token_typ_set(DOCUMENTS_ACCESS_TOKEN_TYPE),
        )
        .with_scope_claim(oidc.scope_claim.as_str().to_owned())
        .with_allowed_clients(oidc.clients.allowed_clients.clone())
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
        if let Err(error) = oidc.provider.check("authentication.oidc", development) {
            findings.push(Finding::block("/authentication/oidc", &error));
        }
        if let Err(error) = oidc.clients.check("authentication.oidc") {
            findings.push(Finding::block("/authentication/oidc", &error));
        }
        if oidc.clients.allowed_clients.is_empty() {
            findings.push(Finding::new(
                "documents.runtime.allowed-clients-required",
                "/authentication/oidc/allowedClients",
                "authentication.oidc.allowedClients must list the clients this runtime admits; `unrestricted` is refused",
                "List every OAuth client an access profile names under allowedClients.",
            ));
        }
    }

    fn check_audit(&self, findings: &mut Vec<Finding>) {
        if let Err(error) = AuditDestination::from_settings(
            self.audit.destination,
            self.audit.path.clone(),
            None,
            None,
        ) {
            findings.push(Finding::new(
                "documents.runtime.invalid-audit",
                "/audit",
                error.to_string(),
                "Write audit.path as an absolute file path for destination file, or choose destination stdout.",
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
#[must_use]
pub fn check_runtime_file(path: &Path, substitute: bool) -> RuntimeCheck {
    let check =
        RuntimeConfig::loader().check_offline::<RuntimeConfig>(path, substitute, stand_in_for);
    let diagnostics: Vec<Diagnostic> = match &check.loaded {
        Some(loaded) => loaded
            .config
            .findings()
            .iter()
            .filter(|finding| !check.defers_within(&finding.pointer))
            .map(|finding| positioned(&check, finding))
            .collect(),
        None => Vec::new(),
    };
    RuntimeCheck {
        report: check.report_with(DOCUMENTS_RUNTIME_KIND, diagnostics),
        unavailable: check.unavailable,
    }
}

/// The report `documents serve` prints when it refuses the runtime document
/// at `path`: every diagnostic the shared loader or the runtime rules hold,
/// each at its position. `None` for a refusal that is not about the file.
#[must_use]
pub fn startup_report(path: &Path, error: &RuntimeConfigError) -> Option<Report> {
    match error {
        RuntimeConfigError::Load(error) => Some(Report::new(error.diagnostics().to_vec())),
        RuntimeConfigError::Refused(_) => {
            let report = check_runtime_file(path, true).report;
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
        finding.suggested_action,
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
            "hmacSha256KeyRef: secret:file/custodian-events-hmac",
            "hmacSha256KeyRef: secret:env/CUSTODIAN_EVENTS_HMAC",
        );
        assert_ne!(text, STARTER_RUNTIME);
        let error = parse(&text).unwrap_err();
        let RuntimeConfigError::Refused(findings) = error else {
            panic!("a refused document");
        };
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].pointer,
            "/destinations/hooks/custodian-events/hmacSha256KeyRef"
        );
        assert!(!findings[0].message.contains("CUSTODIAN_EVENTS_HMAC"));
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
}
