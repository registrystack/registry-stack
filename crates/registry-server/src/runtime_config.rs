// SPDX-License-Identifier: Apache-2.0
//! Strict deployment-only runtime configuration for Registry Server.

use std::{
    collections::HashSet,
    fmt, fs,
    io::Read,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::jwk::JwkSet;
use registry_platform_audit::AuditProfile;
use registry_platform_config::{
    expand_config_env_vars_with, SecretError, SecretProvider, SecretReference, SecretResolver,
};
use registry_platform_crypto::{parse_json_strict, PublicJwk, SigningAlgorithm};
#[cfg(feature = "schema")]
use registry_platform_httputil::destination::{
    MAX_DESTINATION_ORIGIN_URL_BYTES, MAX_DESTINATION_PRIVATE_CIDRS, MAX_DESTINATION_TARGET_BYTES,
};
use registry_platform_oidc::{
    fetch_discovery, JwksFetcher, JwksFetcherConfig, OidcDiscoveryConfig, TokenVerifierConfig,
};
use serde::Deserialize;
use serde_json::{Map, Value};
use thiserror::Error;
use zeroize::Zeroizing;

#[cfg(feature = "schema")]
use crate::compiler::{
    MAX_WEBHOOK_ATTEMPTS, MAX_WEBHOOK_ATTEMPT_TIMEOUT_MS, MIN_WEBHOOK_ATTEMPT_TIMEOUT_MS,
};
use crate::{
    auth::AuthorityClaimConfig,
    cursor::CursorCodec,
    event_destination::{
        ActivatedEventDestinationRegistry, EventDestinationConfigs, RawEventDestinationConfigs,
    },
    model::CompiledRegistry,
    package::{PackageIntent, PackageLoadContext},
    postgres::{ConnectionConfig, PoolBounds, SqlIdentifier},
};

const MAX_RUNTIME_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_PATH_BYTES: usize = 512;
const MAX_DEPLOYMENT_VALUE_BYTES: usize = 256;
const MAX_OIDC_VALUE_BYTES: usize = 2048;
const MAX_LIST_ITEMS: usize = 128;
const MAX_LIST_VALUE_BYTES: usize = 512;
const MAX_JWKS_DOCUMENT_BYTES: u64 = 1024 * 1024;
const MIN_RSA_MODULUS_BITS: usize = 2048;
const MAX_RSA_MODULUS_BITS: usize = 8192;
const MAX_RSA_EXPONENT_BYTES: usize = 8;
const DEFAULT_WEBHOOK_PAYLOAD_RETENTION_DAYS: u8 = 7;
const MAX_WEBHOOK_PAYLOAD_RETENTION_DAYS: u8 = 30;
const DEFAULT_POOL_WAIT_TIMEOUT_MILLISECONDS: u64 = 30_000;
const DEFAULT_POOL_CREATE_TIMEOUT_MILLISECONDS: u64 = 30_000;
const DEFAULT_POOL_RECYCLE_TIMEOUT_MILLISECONDS: u64 = 30_000;
const DEFAULT_JWKS_CACHE_TTL_SECONDS: u64 = 600;
const DEFAULT_JWKS_NEGATIVE_CACHE_TTL_SECONDS: u64 = 60;
const DEFAULT_JWKS_REFRESH_COOLDOWN_SECONDS: u64 = 30;
const DEFAULT_JWKS_MAX_DOCUMENT_BYTES: u64 = 65_536;
const DEFAULT_JWKS_REQUEST_TIMEOUT_MILLISECONDS: u64 = 5_000;
const DEFAULT_JWKS_OUTAGE_TOLERANCE_SECONDS: u64 = 900;
const DEFAULT_CURSOR_MAX_AGE_SECONDS: u64 = 300;
const DEFAULT_HTTP_REQUEST_TIMEOUT_MILLISECONDS: u64 = 10_000;
const DEFAULT_SHUTDOWN_GRACE_MILLISECONDS: u64 = 30_000;
const DEFAULT_RECORD_LOCK_MILLISECONDS: u64 = 5_000;
const DEFAULT_MIGRATION_LOCK_MILLISECONDS: u64 = 30_000;
const DEFAULT_MIGRATION_STATEMENT_MILLISECONDS: u64 = 60_000;
#[cfg(feature = "schema")]
const MAX_DATABASE_POOL_SIZE: u64 = 128;
#[cfg(feature = "schema")]
const SECRET_REFERENCE_SCHEMA_PATTERN: &str =
    "^(secret:env/[A-Z][A-Z0-9_]{0,127}|secret:file/[a-z][a-z0-9._-]{0,127})$";
#[cfg(feature = "schema")]
const MAX_SECRET_REFERENCE_SCHEMA_LENGTH: usize = "secret:file/".len() + 128;
#[cfg(feature = "schema")]
const SQL_IDENTIFIER_SCHEMA_PATTERN: &str = "^[_a-z][_a-z0-9]{0,62}$";
#[cfg(feature = "schema")]
const CLAIM_NAME_SCHEMA_PATTERN: &str = "^[\\x21-\\x7E]+$";
#[cfg(feature = "schema")]
const LIST_VALUE_SCHEMA_PATTERN: &str = "^[^\\x00-\\x20\\x7F]+$";
#[cfg(feature = "schema")]
const VALUE_NO_EDGE_WHITESPACE_SCHEMA_PATTERN: &str =
    "^[^\\s\\x00-\\x1F\\x7F](?:[^\\x00-\\x1F\\x7F]*[^\\s\\x00-\\x1F\\x7F])?$";
#[cfg(feature = "schema")]
const SCOPE_SEPARATOR_SCHEMA_PATTERN: &str = "^[^A-Za-z0-9\\x00-\\x1F\\x7F]$";
#[cfg(feature = "schema")]
const EVENT_DESTINATION_ID_SCHEMA_PATTERN: &str = "^[a-z][a-z0-9_-]{0,63}$";
#[cfg(feature = "schema")]
const EVENT_DESTINATION_PATH_SCHEMA_PATTERN: &str =
    "^/[\\x20-\\x22\\x24\\x26-\\x3E\\x40-\\x5B\\x5D-\\x7E]*$";

pub const RUNTIME_CONFIG_API_VERSION: &str = "registry.registrystack.org/server-runtime/v1alpha1";
pub const RUNTIME_CONFIG_KIND: &str = "RegistryServerRuntimeConfig";

#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
pub enum RuntimeConfigError {
    #[error("the runtime configuration file is unavailable")]
    Unavailable,
    #[error("the runtime configuration file is unsafe")]
    UnsafeFile,
    #[error("the runtime configuration exceeds its resource bounds")]
    Bounds,
    #[error("runtime configuration environment expansion was refused")]
    EnvExpansion,
    #[error("the runtime configuration document is invalid")]
    Document,
    #[error("runtime configuration uses an unsupported apiVersion")]
    InvalidApiVersion,
    #[error("runtime configuration uses an unsupported kind")]
    InvalidKind,
    #[error("runtime configuration contains a governed member")]
    GovernedMember,
    #[error("runtime configuration contains an invalid deployment binding")]
    InvalidBinding,
    #[error("runtime configuration contains an invalid listener binding")]
    InvalidListener,
    #[error("runtime configuration contains an invalid secret provider binding")]
    InvalidSecretProvider,
    #[error("runtime configuration contains an invalid database binding")]
    InvalidDatabase,
    #[error("runtime configuration contains an invalid package binding")]
    InvalidPackage,
    #[error("runtime configuration contains an invalid OIDC binding")]
    InvalidOidc,
    #[error("runtime configuration contains an invalid audit binding")]
    InvalidAudit,
    #[error("runtime configuration contains an invalid cursor binding")]
    InvalidCursor,
    #[error("runtime configuration contains an invalid event destination binding")]
    InvalidEventDestination,
    #[error("runtime configuration contains invalid operational bounds")]
    InvalidBounds,
    #[error("runtime configuration secret resolution failed")]
    Secret,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeConfigErrorMetadata {
    code: &'static str,
    path: &'static str,
}

impl RuntimeConfigErrorMetadata {
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn path(self) -> &'static str {
        self.path
    }
}

impl RuntimeConfigError {
    #[must_use]
    pub const fn metadata(self) -> RuntimeConfigErrorMetadata {
        RuntimeConfigErrorMetadata {
            code: self.code(),
            path: self.path(),
        }
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "runtime_config.unavailable",
            Self::UnsafeFile => "runtime_config.unsafe_file",
            Self::Bounds => "runtime_config.bounds",
            Self::EnvExpansion => "runtime_config.env_expansion",
            Self::Document => "runtime_config.document",
            Self::InvalidApiVersion => "runtime_config.invalid_api_version",
            Self::InvalidKind => "runtime_config.invalid_kind",
            Self::GovernedMember => "runtime_config.governed_member",
            Self::InvalidBinding => "runtime_config.invalid_binding",
            Self::InvalidListener => "runtime_config.invalid_listener",
            Self::InvalidSecretProvider => "runtime_config.invalid_secret_provider",
            Self::InvalidDatabase => "runtime_config.invalid_database",
            Self::InvalidPackage => "runtime_config.invalid_package",
            Self::InvalidOidc => "runtime_config.invalid_oidc",
            Self::InvalidAudit => "runtime_config.invalid_audit",
            Self::InvalidCursor => "runtime_config.invalid_cursor",
            Self::InvalidEventDestination => "runtime_config.invalid_event_destination",
            Self::InvalidBounds => "runtime_config.invalid_bounds",
            Self::Secret => "runtime_config.secret",
        }
    }

    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::Unavailable
            | Self::UnsafeFile
            | Self::Bounds
            | Self::EnvExpansion
            | Self::Document
            | Self::GovernedMember
            | Self::InvalidBinding
            | Self::Secret => "/",
            Self::InvalidApiVersion => "/apiVersion",
            Self::InvalidKind => "/kind",
            Self::InvalidListener => "/listener",
            Self::InvalidSecretProvider => "/secretProviders",
            Self::InvalidDatabase => "/database",
            Self::InvalidPackage => "/package",
            Self::InvalidOidc => "/authentication/oidc",
            Self::InvalidAudit => "/audit",
            Self::InvalidCursor => "/cursor",
            Self::InvalidEventDestination => "/eventDestinations",
            Self::InvalidBounds => "/operationalTimeouts",
        }
    }
}

impl From<SecretError> for RuntimeConfigError {
    fn from(_error: SecretError) -> Self {
        Self::Secret
    }
}

pub type Result<T> = std::result::Result<T, RuntimeConfigError>;

pub fn load_runtime_config(path: &Path) -> Result<RuntimeConfig> {
    load_runtime_config_with_env(path, |name| std::env::var(name).ok())
}

pub fn load_runtime_config_with_env(
    path: &Path,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<RuntimeConfig> {
    validate_absolute_lexical_path(path, RuntimeConfigError::UnsafeFile)?;
    reject_symlink_components(path, RuntimeConfigError::UnsafeFile)?;
    let bytes = read_bounded_runtime_config(path, MAX_RUNTIME_CONFIG_BYTES)?;
    let raw = std::str::from_utf8(&bytes).map_err(|_| RuntimeConfigError::Document)?;
    parse_runtime_config_with_env(raw, lookup).and_then(|config| {
        config.validate_loaded_paths()?;
        Ok(config)
    })
}

pub fn parse_runtime_config(raw: &str) -> Result<RuntimeConfig> {
    parse_runtime_config_with_env(raw, |name| std::env::var(name).ok())
}

pub fn parse_runtime_config_with_env(
    raw: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<RuntimeConfig> {
    if raw.is_empty() || raw.len() > usize::try_from(MAX_RUNTIME_CONFIG_BYTES).unwrap_or(usize::MAX)
    {
        return Err(RuntimeConfigError::Bounds);
    }
    let expanded =
        expand_config_env_vars_with(raw, lookup).map_err(|_| RuntimeConfigError::EnvExpansion)?;
    if expanded.len() > usize::try_from(MAX_RUNTIME_CONFIG_BYTES).unwrap_or(usize::MAX) {
        return Err(RuntimeConfigError::Bounds);
    }
    parse_expanded_runtime_config(&expanded)
}

fn parse_expanded_runtime_config(expanded: &str) -> Result<RuntimeConfig> {
    reject_governed_members(expanded)?;
    let raw: RawRuntimeConfig =
        serde_norway::from_str(expanded).map_err(|_| RuntimeConfigError::Document)?;
    RuntimeConfig::from_raw(raw)
}

fn reject_governed_members(raw: &str) -> Result<()> {
    let value: serde_norway::Value =
        serde_norway::from_str(raw).map_err(|_| RuntimeConfigError::Document)?;
    if contains_governed_member(&value) {
        return Err(RuntimeConfigError::GovernedMember);
    }
    Ok(())
}

fn contains_governed_member(value: &serde_norway::Value) -> bool {
    const GOVERNED: &[&str] = &[
        "entities",
        "fields",
        "accessProfiles",
        "routes",
        "events",
        "packages",
        "sources",
        "semantics",
        "classifications",
        "relationships",
        "mutationMode",
        "readableFields",
        "writableFields",
        "rowBoundaries",
        "requiredScopes",
        "requiredPurposes",
        "retention",
        "webhooks",
        "telemetry",
        "cors",
    ];
    match value {
        serde_norway::Value::Mapping(mapping) => mapping.iter().any(|(key, value)| {
            key.as_str().is_some_and(|key| GOVERNED.contains(&key))
                // Destination-map keys are compiler-issued logical ids. Do not
                // reinterpret an id such as `events` as a governed field; the
                // strict destination value type rejects every undeployed key.
                || (!key
                    .as_str()
                    .is_some_and(|key| key == "eventDestinations")
                    && contains_governed_member(value))
        }),
        serde_norway::Value::Sequence(values) => values.iter().any(contains_governed_member),
        _ => false,
    }
}

#[derive(Clone)]
pub struct RuntimeConfig {
    listener: ListenerConfig,
    identity: DeploymentIdentity,
    secret_providers: SecretProvidersConfig,
    database: DatabaseConfig,
    package: PackageConfig,
    authentication: AuthenticationConfig,
    audit: AuditConfig,
    cursor: CursorConfig,
    event_destinations: EventDestinationConfigs,
    event_delivery: EventDeliveryConfig,
    operational_timeouts: OperationalTimeouts,
}

impl RuntimeConfig {
    fn from_raw(raw: RawRuntimeConfig) -> Result<Self> {
        if raw.api_version != RUNTIME_CONFIG_API_VERSION {
            return Err(RuntimeConfigError::InvalidApiVersion);
        }
        if raw.kind != RUNTIME_CONFIG_KIND {
            return Err(RuntimeConfigError::InvalidKind);
        }
        let listener = ListenerConfig::from_raw(raw.listener)?;
        let identity = DeploymentIdentity::from_raw(raw.identity)?;
        let secret_providers = SecretProvidersConfig::from_raw(raw.secret_providers)?;
        let database = DatabaseConfig::from_raw(raw.database)?;
        let package = PackageConfig::from_raw(raw.package)?;
        let authentication = AuthenticationConfig::from_raw(raw.authentication)?;
        let audit = AuditConfig::from_raw(raw.audit)?;
        let cursor = CursorConfig::from_raw(raw.cursor)?;
        let event_destinations = EventDestinationConfigs::from_raw(raw.event_destinations)
            .map_err(|_| RuntimeConfigError::InvalidEventDestination)?;
        let event_delivery = EventDeliveryConfig::from_raw(raw.event_delivery)?;
        let operational_timeouts = OperationalTimeouts::from_raw(raw.operational_timeouts)?;
        Ok(Self {
            listener,
            identity,
            secret_providers,
            database,
            package,
            authentication,
            audit,
            cursor,
            event_destinations,
            event_delivery,
            operational_timeouts,
        })
    }

    pub fn listener(&self) -> &ListenerConfig {
        &self.listener
    }

    pub fn identity(&self) -> &DeploymentIdentity {
        &self.identity
    }

    pub fn database(&self) -> &DatabaseConfig {
        &self.database
    }

    pub fn package(&self) -> &PackageConfig {
        &self.package
    }

    pub fn authentication(&self) -> &AuthenticationConfig {
        &self.authentication
    }

    pub fn audit(&self) -> &AuditConfig {
        &self.audit
    }

    pub fn cursor(&self) -> &CursorConfig {
        &self.cursor
    }

    pub fn event_delivery(&self) -> &EventDeliveryConfig {
        &self.event_delivery
    }

    pub async fn oidc_key_source(&self) -> Result<Arc<JwksFetcher>> {
        self.authentication
            .oidc
            .key_source(&self.secret_resolver()?)
            .await
    }

    /// Activate the exact deployment bindings required by the compiled Registry.
    pub fn activate_event_destinations(
        &self,
        compiled: &CompiledRegistry,
    ) -> std::result::Result<
        ActivatedEventDestinationRegistry,
        crate::event_destination::EventDestinationActivationError,
    > {
        let resolver = self
            .secret_resolver()
            .map_err(|_| crate::event_destination::EventDestinationActivationError::Secret)?;
        ActivatedEventDestinationRegistry::activate(compiled, &self.event_destinations, &resolver)
            .map(|destinations| {
                destinations.with_payload_retention(self.event_delivery.payload_retention)
            })
    }

    pub fn operational_timeouts(&self) -> &OperationalTimeouts {
        &self.operational_timeouts
    }

    pub fn secret_resolver(&self) -> Result<SecretResolver> {
        self.secret_providers.resolver()
    }

    pub fn runtime_database_connection_config(&self) -> Result<ConnectionConfig> {
        self.database_connection_config_for(
            &self.database.runtime_url_ref,
            self.database.roles.runtime(),
        )
    }

    pub fn migration_database_connection_config(&self) -> Result<ConnectionConfig> {
        self.database_connection_config_for(
            &self.database.migration_url_ref,
            self.database.roles.migration(),
        )
    }

    fn database_connection_config_for(
        &self,
        url_ref: &SecretReference,
        expected_role: &SqlIdentifier,
    ) -> Result<ConnectionConfig> {
        let secret = self.secret_resolver()?.resolve_reference(url_ref)?;
        let url =
            std::str::from_utf8(secret.expose_secret()).map_err(|_| RuntimeConfigError::Secret)?;
        let postgres = url
            .parse::<tokio_postgres::Config>()
            .map_err(|_| RuntimeConfigError::InvalidDatabase)?;
        if postgres.get_user() != Some(expected_role.as_str()) {
            return Err(RuntimeConfigError::InvalidDatabase);
        }
        ConnectionConfig::require_tls_config(postgres, self.database.pool_bounds)
            .map_err(|_| RuntimeConfigError::InvalidDatabase)
    }

    pub fn audit_profile(&self) -> Result<AuditProfile> {
        let secret = self
            .secret_resolver()?
            .resolve_reference(&self.audit.hash_key_ref)?;
        AuditProfile::production_from_secret_bytes(Zeroizing::new(secret.expose_secret().to_vec()))
            .map_err(|_| RuntimeConfigError::InvalidAudit)
    }

    pub fn cursor_codec(&self) -> Result<CursorCodec> {
        let secret = self
            .secret_resolver()?
            .resolve_reference(&self.cursor.secret_ref)?;
        CursorCodec::new(
            Zeroizing::new(secret.expose_secret().to_vec()),
            self.cursor.max_age,
        )
        .map_err(|_| RuntimeConfigError::InvalidCursor)
    }

    pub fn package_load_context(&self) -> PackageLoadContext<'_> {
        PackageLoadContext {
            environment: self.identity.environment.as_str(),
            instance_id: self.identity.instance_id.as_str(),
            database_id: self.identity.database_id.as_str(),
            database_initialization_environment: self
                .identity
                .database_initialization_environment
                .as_str(),
            compiler_source_revision: self.package.compiler_source_revision.as_str(),
            trust_anchor: self.package_trust_anchor(),
            intent: PackageIntent::Startup {
                active_revision: self.package.active_revision.as_str(),
                active_sequence: self.package.active_sequence,
            },
        }
    }

    /// Production package verification is anchored. Local unsigned packages
    /// must not carry trust authority into the package verifier.
    pub fn package_trust_anchor(&self) -> Option<&Path> {
        (self.identity.database_initialization_environment != "local")
            .then_some(self.package.trust_anchor_path.as_path())
    }

    fn validate_loaded_paths(&self) -> Result<()> {
        validate_existing_directory(&self.package.root, RuntimeConfigError::InvalidPackage)?;
        if let Some(trust_anchor) = self.package_trust_anchor() {
            validate_existing_file(trust_anchor, RuntimeConfigError::InvalidPackage)?;
        }
        if let Some(root) = self.secret_providers.file_root() {
            validate_existing_directory(root, RuntimeConfigError::InvalidSecretProvider)?;
        }
        Ok(())
    }
}

impl fmt::Debug for RuntimeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeConfig")
            .field("listener", &self.listener)
            .field("identity", &self.identity)
            .field("secret_providers", &self.secret_providers)
            .field("database", &self.database)
            .field("package", &self.package)
            .field("authentication", &self.authentication)
            .field("audit", &self.audit)
            .field("cursor", &self.cursor)
            .field("event_destinations", &self.event_destinations)
            .field("event_delivery", &self.event_delivery)
            .field("operational_timeouts", &self.operational_timeouts)
            .finish()
    }
}

#[derive(Clone)]
pub struct ListenerConfig {
    bind: SocketAddr,
    trusted_proxy: TrustedProxyPosture,
}

impl ListenerConfig {
    fn from_raw(raw: RawListenerConfig) -> Result<Self> {
        let bind = raw
            .bind
            .parse::<SocketAddr>()
            .map_err(|_| RuntimeConfigError::InvalidListener)?;
        Ok(Self {
            bind,
            trusted_proxy: raw.trusted_proxy,
        })
    }

    pub fn bind(&self) -> SocketAddr {
        self.bind
    }

    pub fn trusted_proxy(&self) -> TrustedProxyPosture {
        self.trusted_proxy
    }
}

impl fmt::Debug for ListenerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListenerConfig")
            .field("bind", &"<redacted>")
            .field("trusted_proxy", &self.trusted_proxy)
            .finish()
    }
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum TrustedProxyPosture {
    Direct,
    OperatorControlledUpstream,
}

#[derive(Clone)]
pub struct DeploymentIdentity {
    environment: String,
    instance_id: String,
    database_id: String,
    database_initialization_environment: String,
}

impl DeploymentIdentity {
    fn from_raw(raw: RawDeploymentIdentity) -> Result<Self> {
        validate_deployment_value(&raw.environment)?;
        validate_deployment_value(&raw.instance_id)?;
        validate_deployment_value(&raw.database_id)?;
        validate_deployment_value(&raw.database_initialization_environment)?;
        Ok(Self {
            environment: raw.environment,
            instance_id: raw.instance_id,
            database_id: raw.database_id,
            database_initialization_environment: raw.database_initialization_environment,
        })
    }

    pub fn environment(&self) -> &str {
        &self.environment
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub fn database_id(&self) -> &str {
        &self.database_id
    }

    pub fn database_initialization_environment(&self) -> &str {
        &self.database_initialization_environment
    }
}

impl fmt::Debug for DeploymentIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeploymentIdentity")
            .field("environment", &"<redacted>")
            .field("instance_id", &"<redacted>")
            .field("database_id", &"<redacted>")
            .field("database_initialization_environment", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub struct SecretProvidersConfig {
    environment: bool,
    file: Option<FileSecretProviderConfig>,
}

impl SecretProvidersConfig {
    fn from_raw(raw: RawSecretProvidersConfig) -> Result<Self> {
        if raw.environment.is_none() && raw.file.is_none() {
            return Err(RuntimeConfigError::InvalidSecretProvider);
        }
        let file = raw
            .file
            .map(FileSecretProviderConfig::from_raw)
            .transpose()?;
        Ok(Self {
            environment: raw.environment.is_some(),
            file,
        })
    }

    fn resolver(&self) -> Result<SecretResolver> {
        let mut providers = Vec::new();
        if self.environment {
            providers.push(SecretProvider::Environment);
        }
        if self.file.is_some() {
            providers.push(SecretProvider::File);
        }
        let root = self
            .file
            .as_ref()
            .map_or_else(PathBuf::new, |file| file.root.clone());
        SecretResolver::new(providers, root).map_err(Into::into)
    }

    fn file_root(&self) -> Option<&Path> {
        self.file.as_ref().map(|file| file.root.as_path())
    }
}

impl fmt::Debug for SecretProvidersConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretProvidersConfig")
            .field("environment", &self.environment)
            .field("file", &self.file.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[derive(Clone)]
pub struct FileSecretProviderConfig {
    root: PathBuf,
}

impl FileSecretProviderConfig {
    fn from_raw(raw: RawFileSecretProviderConfig) -> Result<Self> {
        validate_absolute_lexical_path(&raw.root, RuntimeConfigError::InvalidSecretProvider)?;
        Ok(Self { root: raw.root })
    }
}

#[derive(Clone)]
pub struct DatabaseConfig {
    runtime_url_ref: SecretReference,
    migration_url_ref: SecretReference,
    pool_bounds: PoolBounds,
    roles: SqlRoles,
}

impl DatabaseConfig {
    fn from_raw(raw: RawDatabaseConfig) -> Result<Self> {
        if raw.plaintext.is_some() || raw.url.is_some() || raw.password.is_some() {
            return Err(RuntimeConfigError::InvalidDatabase);
        }
        let runtime_url_ref =
            parse_secret_reference(raw.runtime_url_ref, RuntimeConfigError::InvalidDatabase)?;
        let migration_url_ref =
            parse_secret_reference(raw.migration_url_ref, RuntimeConfigError::InvalidDatabase)?;
        if runtime_url_ref == migration_url_ref {
            return Err(RuntimeConfigError::InvalidDatabase);
        }
        let pool_bounds = PoolBounds::new(
            raw.pool.max_size,
            millis(raw.pool.wait_timeout_milliseconds)?,
            millis(raw.pool.create_timeout_milliseconds)?,
            millis(raw.pool.recycle_timeout_milliseconds)?,
        )
        .map_err(|_| RuntimeConfigError::InvalidBounds)?;
        Ok(Self {
            runtime_url_ref,
            migration_url_ref,
            pool_bounds,
            roles: SqlRoles::from_raw(raw.roles)?,
        })
    }

    pub fn pool_bounds(&self) -> PoolBounds {
        self.pool_bounds
    }
}

impl fmt::Debug for DatabaseConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseConfig")
            .field("runtime_url_ref", &"<redacted>")
            .field("migration_url_ref", &"<redacted>")
            .field("pool_bounds", &self.pool_bounds)
            .finish()
    }
}

#[derive(Clone)]
pub struct PackageConfig {
    root: PathBuf,
    trust_anchor_path: PathBuf,
    compiler_source_revision: String,
    active_revision: String,
    active_sequence: u64,
}

impl PackageConfig {
    fn from_raw(raw: RawPackageConfig) -> Result<Self> {
        validate_absolute_lexical_path(&raw.root, RuntimeConfigError::InvalidPackage)?;
        validate_absolute_lexical_path(&raw.trust_anchor_path, RuntimeConfigError::InvalidPackage)?;
        validate_deployment_value(&raw.compiler_source_revision)?;
        validate_deployment_value(&raw.active_revision)?;
        if raw.active_sequence == 0 {
            return Err(RuntimeConfigError::InvalidPackage);
        }
        Ok(Self {
            root: raw.root,
            trust_anchor_path: raw.trust_anchor_path,
            compiler_source_revision: raw.compiler_source_revision,
            active_revision: raw.active_revision,
            active_sequence: raw.active_sequence,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn trust_anchor_path(&self) -> &Path {
        &self.trust_anchor_path
    }

    pub fn compiler_source_revision(&self) -> &str {
        &self.compiler_source_revision
    }

    pub fn active_revision(&self) -> &str {
        &self.active_revision
    }

    pub fn active_sequence(&self) -> u64 {
        self.active_sequence
    }
}

impl fmt::Debug for PackageConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackageConfig")
            .field("root", &"<redacted>")
            .field("trust_anchor_path", &"<redacted>")
            .field("compiler_source_revision", &"<redacted>")
            .field("active_revision", &"<redacted>")
            .field("active_sequence", &self.active_sequence)
            .finish()
    }
}

#[derive(Clone)]
pub struct AuthenticationConfig {
    oidc: OidcVerifierConfig,
    authority_claims: AuthorityClaimsConfig,
}

impl AuthenticationConfig {
    fn from_raw(raw: RawAuthenticationConfig) -> Result<Self> {
        Ok(Self {
            oidc: OidcVerifierConfig::from_raw(raw.oidc)?,
            authority_claims: AuthorityClaimsConfig::from_raw(raw.authority_claims)?,
        })
    }

    pub fn oidc(&self) -> &OidcVerifierConfig {
        &self.oidc
    }

    pub fn authority_claim_config(&self) -> AuthorityClaimConfig {
        self.authority_claims.to_platform_config()
    }
}

impl fmt::Debug for AuthenticationConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticationConfig")
            .field("oidc", &self.oidc)
            .field("authority_claims", &self.authority_claims)
            .finish()
    }
}

#[derive(Clone)]
pub struct OidcVerifierConfig {
    issuer: String,
    audience: String,
    allowed_algorithm: OidcAlgorithm,
    access_token_type: String,
    scope_claim: String,
    scope_separator: char,
    allowed_clients: Vec<String>,
    denied_kids: Vec<String>,
    max_token_lifetime: Duration,
    leeway: Duration,
    jwks_cache: JwksCacheConfig,
    jwks_source: OidcJwksSource,
}

impl OidcVerifierConfig {
    fn from_raw(raw: RawOidcVerifierConfig) -> Result<Self> {
        validate_oidc_value(&raw.issuer)?;
        validate_oidc_value(&raw.audience)?;
        validate_oidc_value(&raw.access_token_type)?;
        validate_claim_name(&raw.scope_claim)?;
        if raw.scope_separator.is_control() || raw.scope_separator.is_alphanumeric() {
            return Err(RuntimeConfigError::InvalidOidc);
        }
        validate_bounded_list(&raw.allowed_clients)?;
        validate_bounded_list(&raw.denied_kids)?;
        let denied_unique = raw.denied_kids.iter().collect::<HashSet<_>>();
        if denied_unique.len() != raw.denied_kids.len() {
            return Err(RuntimeConfigError::InvalidOidc);
        }
        let allowed_unique = raw.allowed_clients.iter().collect::<HashSet<_>>();
        if allowed_unique.len() != raw.allowed_clients.len() {
            return Err(RuntimeConfigError::InvalidOidc);
        }
        let max_token_lifetime = seconds_bounded(raw.max_token_lifetime_seconds, 1, 3600)?;
        let leeway = millis_bounded(raw.leeway_milliseconds, 0, 300_000)?;
        Ok(Self {
            issuer: raw.issuer,
            audience: raw.audience,
            allowed_algorithm: raw.allowed_algorithm,
            access_token_type: raw.access_token_type,
            scope_claim: raw.scope_claim,
            scope_separator: raw.scope_separator,
            allowed_clients: raw.allowed_clients,
            denied_kids: raw.denied_kids,
            max_token_lifetime,
            leeway,
            jwks_cache: JwksCacheConfig::from_raw(raw.jwks_cache)?,
            jwks_source: raw
                .jwks_source
                .map(OidcJwksSource::from_raw)
                .transpose()?
                .unwrap_or(OidcJwksSource::Discovery),
        })
    }

    pub fn discovery_config(&self) -> OidcDiscoveryConfig {
        OidcDiscoveryConfig {
            issuer: self.issuer.clone(),
            jwks_uri_override: None,
            discovery_timeout: self.jwks_cache.request_timeout,
            max_doc_bytes: self.jwks_cache.max_document_bytes,
        }
    }

    pub fn jwks_fetcher_config(&self) -> JwksFetcherConfig {
        JwksFetcherConfig {
            cache_ttl: self.jwks_cache.cache_ttl,
            negative_cache_ttl: self.jwks_cache.negative_cache_ttl,
            refresh_cooldown: self.jwks_cache.refresh_cooldown,
            max_doc_bytes: self.jwks_cache.max_document_bytes,
            request_timeout: self.jwks_cache.request_timeout,
            outage_tolerance: self.jwks_cache.outage_tolerance,
        }
    }

    pub fn token_verifier_config(&self) -> TokenVerifierConfig {
        TokenVerifierConfig::access_token_profile(
            self.issuer.clone(),
            vec![self.audience.clone()],
            vec![self.allowed_algorithm.as_jsonwebtoken()],
            vec![self.access_token_type.clone()],
        )
        .with_scope_claim(self.scope_claim.clone())
        .with_scope_separator(self.scope_separator)
        .with_allowed_clients(self.allowed_clients.clone())
        .with_denied_kids(self.denied_kids.iter().cloned().collect())
        .with_max_token_lifetime(Some(self.max_token_lifetime))
        .with_leeway(self.leeway)
    }

    async fn key_source(&self, resolver: &SecretResolver) -> Result<Arc<JwksFetcher>> {
        match &self.jwks_source {
            OidcJwksSource::Discovery => {
                let discovery = fetch_discovery(&self.discovery_config())
                    .await
                    .map_err(|_| RuntimeConfigError::InvalidOidc)?;
                Ok(Arc::new(JwksFetcher::new(
                    discovery.jwks_uri,
                    self.jwks_fetcher_config(),
                )))
            }
            OidcJwksSource::Static { document_ref } => {
                let document = resolver
                    .resolve_reference(document_ref)
                    .map_err(|_| RuntimeConfigError::InvalidOidc)?;
                if document.is_empty()
                    || u64::try_from(document.len())
                        .map_or(true, |len| len > self.jwks_cache.max_document_bytes)
                {
                    return Err(RuntimeConfigError::InvalidOidc);
                }
                let jwks = validate_static_jwks(
                    document.expose_secret(),
                    self.allowed_algorithm,
                    &self.denied_kids,
                )?;
                Ok(Arc::new(JwksFetcher::new_static(
                    jwks,
                    self.jwks_fetcher_config(),
                )))
            }
        }
    }
}

impl fmt::Debug for OidcVerifierConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcVerifierConfig")
            .field("issuer", &"<redacted>")
            .field("audience", &"<redacted>")
            .field("allowed_algorithm", &self.allowed_algorithm)
            .field("access_token_type", &"<redacted>")
            .field("scope_claim", &"<redacted>")
            .field("scope_separator", &"<redacted>")
            .field("allowed_clients_count", &self.allowed_clients.len())
            .field("denied_kids_count", &self.denied_kids.len())
            .field("max_token_lifetime", &self.max_token_lifetime)
            .field("leeway", &self.leeway)
            .field("jwks_cache", &self.jwks_cache)
            .field("jwks_source", &self.jwks_source.kind())
            .finish()
    }
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum OidcAlgorithm {
    EdDSA,
    ES256,
    ES384,
    RS256,
    RS384,
}

impl OidcAlgorithm {
    fn as_jsonwebtoken(self) -> jsonwebtoken::Algorithm {
        match self {
            Self::EdDSA => jsonwebtoken::Algorithm::EdDSA,
            Self::ES256 => jsonwebtoken::Algorithm::ES256,
            Self::ES384 => jsonwebtoken::Algorithm::ES384,
            Self::RS256 => jsonwebtoken::Algorithm::RS256,
            Self::RS384 => jsonwebtoken::Algorithm::RS384,
        }
    }

    fn as_signing_algorithm(self) -> SigningAlgorithm {
        match self {
            Self::EdDSA => SigningAlgorithm::EdDsa,
            Self::ES256 => SigningAlgorithm::Es256,
            Self::ES384 => SigningAlgorithm::Es384,
            Self::RS256 => SigningAlgorithm::Rs256,
            Self::RS384 => SigningAlgorithm::Rs384,
        }
    }

    fn as_jwa_name(self) -> &'static str {
        self.as_signing_algorithm().jwa_name()
    }
}

#[derive(Clone)]
enum OidcJwksSource {
    Discovery,
    Static { document_ref: SecretReference },
}

impl OidcJwksSource {
    fn from_raw(raw: RawOidcJwksSource) -> Result<Self> {
        match raw {
            RawOidcJwksSource::Discovery {} => Ok(Self::Discovery),
            RawOidcJwksSource::Static { document_ref } => Ok(Self::Static {
                document_ref: parse_secret_reference(
                    document_ref,
                    RuntimeConfigError::InvalidOidc,
                )?,
            }),
        }
    }

    const fn kind(&self) -> OidcJwksSourceKind {
        match self {
            Self::Discovery => OidcJwksSourceKind::Discovery,
            Self::Static { .. } => OidcJwksSourceKind::Static,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum OidcJwksSourceKind {
    Discovery,
    Static,
}

fn validate_static_jwks(
    bytes: &[u8],
    allowed_algorithm: OidcAlgorithm,
    denied_kids: &[String],
) -> Result<JwkSet> {
    let value = parse_json_strict(bytes).map_err(|_| RuntimeConfigError::InvalidOidc)?;
    let object = value.as_object().ok_or(RuntimeConfigError::InvalidOidc)?;
    if object.len() != 1 || !object.contains_key("keys") {
        return Err(RuntimeConfigError::InvalidOidc);
    }
    let keys = object
        .get("keys")
        .and_then(Value::as_array)
        .ok_or(RuntimeConfigError::InvalidOidc)?;
    if keys.is_empty() || keys.len() > MAX_LIST_ITEMS {
        return Err(RuntimeConfigError::InvalidOidc);
    }
    let mut kids = HashSet::new();
    for key in keys {
        validate_static_jwk(key, allowed_algorithm, denied_kids, &mut kids)?;
    }
    serde_json::from_value::<JwkSet>(value).map_err(|_| RuntimeConfigError::InvalidOidc)
}

fn validate_static_jwk(
    value: &Value,
    allowed_algorithm: OidcAlgorithm,
    denied_kids: &[String],
    kids: &mut HashSet<String>,
) -> Result<()> {
    let object = value.as_object().ok_or(RuntimeConfigError::InvalidOidc)?;
    validate_static_jwk_members(object)?;
    validate_static_jwk_use(object)?;
    validate_static_jwk_key_ops(object)?;
    let kid = object
        .get("kid")
        .and_then(Value::as_str)
        .ok_or(RuntimeConfigError::InvalidOidc)?;
    validate_bounded_list(&[kid.to_owned()])?;
    if denied_kids.iter().any(|denied| denied == kid) || !kids.insert(kid.to_owned()) {
        return Err(RuntimeConfigError::InvalidOidc);
    }
    if object.get("alg").and_then(Value::as_str) != Some(allowed_algorithm.as_jwa_name()) {
        return Err(RuntimeConfigError::InvalidOidc);
    }
    let public_jwk = PublicJwk::parse(
        std::str::from_utf8(
            &serde_json::to_vec(value).map_err(|_| RuntimeConfigError::InvalidOidc)?,
        )
        .map_err(|_| RuntimeConfigError::InvalidOidc)?,
    )
    .map_err(|_| RuntimeConfigError::InvalidOidc)?;
    if public_jwk
        .algorithm()
        .map_err(|_| RuntimeConfigError::InvalidOidc)?
        != allowed_algorithm.as_signing_algorithm()
    {
        return Err(RuntimeConfigError::InvalidOidc);
    }
    validate_static_jwk_shape(object, allowed_algorithm)?;
    Ok(())
}

fn validate_static_jwk_members(object: &Map<String, Value>) -> Result<()> {
    const ALLOWED: &[&str] = &[
        "kty", "kid", "alg", "use", "key_ops", "crv", "x", "y", "n", "e",
    ];
    if object
        .keys()
        .any(|member| !ALLOWED.contains(&member.as_str()))
    {
        return Err(RuntimeConfigError::InvalidOidc);
    }
    Ok(())
}

fn validate_static_jwk_use(object: &Map<String, Value>) -> Result<()> {
    match object.get("use") {
        None => Ok(()),
        Some(Value::String(value)) if value == "sig" => Ok(()),
        Some(_) => Err(RuntimeConfigError::InvalidOidc),
    }
}

fn validate_static_jwk_key_ops(object: &Map<String, Value>) -> Result<()> {
    match object.get("key_ops") {
        None => Ok(()),
        Some(Value::Array(values)) => match values.as_slice() {
            [Value::String(value)] if value == "verify" => Ok(()),
            _ => Err(RuntimeConfigError::InvalidOidc),
        },
        Some(_) => Err(RuntimeConfigError::InvalidOidc),
    }
}

fn validate_static_jwk_shape(
    object: &Map<String, Value>,
    allowed_algorithm: OidcAlgorithm,
) -> Result<()> {
    match allowed_algorithm {
        OidcAlgorithm::EdDSA => {
            if object.get("kty").and_then(Value::as_str) != Some("OKP")
                || object.get("crv").and_then(Value::as_str) != Some("Ed25519")
                || object.contains_key("y")
                || object.contains_key("n")
                || object.contains_key("e")
            {
                return Err(RuntimeConfigError::InvalidOidc);
            }
            decode_exact_jwk_member(object, "x", 32)?;
        }
        OidcAlgorithm::ES256 | OidcAlgorithm::ES384 => {
            let (curve, coordinate_len) = match allowed_algorithm {
                OidcAlgorithm::ES256 => ("P-256", 32),
                OidcAlgorithm::ES384 => ("P-384", 48),
                _ => unreachable!("only EC algorithms enter this branch"),
            };
            if object.get("kty").and_then(Value::as_str) != Some("EC")
                || object.get("crv").and_then(Value::as_str) != Some(curve)
                || object.contains_key("n")
                || object.contains_key("e")
            {
                return Err(RuntimeConfigError::InvalidOidc);
            }
            decode_exact_jwk_member(object, "x", coordinate_len)?;
            decode_exact_jwk_member(object, "y", coordinate_len)?;
        }
        OidcAlgorithm::RS256 | OidcAlgorithm::RS384 => {
            if object.get("kty").and_then(Value::as_str) != Some("RSA")
                || object.contains_key("crv")
                || object.contains_key("x")
                || object.contains_key("y")
            {
                return Err(RuntimeConfigError::InvalidOidc);
            }
            validate_static_rsa_members(object)?;
        }
    }
    Ok(())
}

fn decode_exact_jwk_member(
    object: &Map<String, Value>,
    member: &'static str,
    expected_len: usize,
) -> Result<Vec<u8>> {
    let value = object
        .get(member)
        .and_then(Value::as_str)
        .ok_or(RuntimeConfigError::InvalidOidc)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| RuntimeConfigError::InvalidOidc)?;
    if decoded.len() != expected_len {
        return Err(RuntimeConfigError::InvalidOidc);
    }
    Ok(decoded)
}

fn validate_static_rsa_members(object: &Map<String, Value>) -> Result<()> {
    let modulus = decode_nonempty_jwk_member(object, "n")?;
    let significant_bits = significant_bit_len(&modulus);
    if !(MIN_RSA_MODULUS_BITS..=MAX_RSA_MODULUS_BITS).contains(&significant_bits) {
        return Err(RuntimeConfigError::InvalidOidc);
    }
    let exponent = decode_nonempty_jwk_member(object, "e")?;
    if exponent.len() > MAX_RSA_EXPONENT_BYTES {
        return Err(RuntimeConfigError::InvalidOidc);
    }
    let exponent_value = exponent
        .iter()
        .fold(0_u64, |acc, byte| (acc << 8) | u64::from(*byte));
    if exponent_value < 3 || exponent_value % 2 == 0 {
        return Err(RuntimeConfigError::InvalidOidc);
    }
    Ok(())
}

fn decode_nonempty_jwk_member(
    object: &Map<String, Value>,
    member: &'static str,
) -> Result<Vec<u8>> {
    let value = object
        .get(member)
        .and_then(Value::as_str)
        .ok_or(RuntimeConfigError::InvalidOidc)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| RuntimeConfigError::InvalidOidc)?;
    if decoded.is_empty() {
        return Err(RuntimeConfigError::InvalidOidc);
    }
    Ok(decoded)
}

fn significant_bit_len(bytes: &[u8]) -> usize {
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    let significant = &bytes[first_non_zero..];
    significant
        .first()
        .map(|first| (significant.len() - 1) * 8 + (8 - first.leading_zeros() as usize))
        .unwrap_or(0)
}

#[derive(Clone)]
pub struct JwksCacheConfig {
    cache_ttl: Duration,
    negative_cache_ttl: Duration,
    refresh_cooldown: Duration,
    max_document_bytes: u64,
    request_timeout: Duration,
    outage_tolerance: Duration,
}

impl JwksCacheConfig {
    fn from_raw(raw: RawJwksCacheConfig) -> Result<Self> {
        if raw.max_document_bytes == 0 || raw.max_document_bytes > MAX_JWKS_DOCUMENT_BYTES {
            return Err(RuntimeConfigError::InvalidOidc);
        }
        Ok(Self {
            cache_ttl: seconds_bounded(raw.cache_ttl_seconds, 1, 86_400)?,
            negative_cache_ttl: seconds_bounded(raw.negative_cache_ttl_seconds, 1, 3_600)?,
            refresh_cooldown: seconds_bounded(raw.refresh_cooldown_seconds, 1, 3_600)?,
            max_document_bytes: raw.max_document_bytes,
            request_timeout: millis_bounded(raw.request_timeout_milliseconds, 1, 30_000)?,
            outage_tolerance: seconds_bounded(raw.outage_tolerance_seconds, 0, 86_400)?,
        })
    }
}

impl fmt::Debug for JwksCacheConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JwksCacheConfig")
            .field("cache_ttl", &self.cache_ttl)
            .field("negative_cache_ttl", &self.negative_cache_ttl)
            .field("refresh_cooldown", &self.refresh_cooldown)
            .field("max_document_bytes", &self.max_document_bytes)
            .field("request_timeout", &self.request_timeout)
            .field("outage_tolerance", &self.outage_tolerance)
            .finish()
    }
}

#[derive(Clone)]
pub struct AuthorityClaimsConfig {
    principal: String,
    purpose: Option<String>,
}

impl AuthorityClaimsConfig {
    fn from_raw(raw: RawAuthorityClaimsConfig) -> Result<Self> {
        validate_authority_claim_name(&raw.principal)?;
        if let Some(purpose) = &raw.purpose {
            validate_authority_claim_name(purpose)?;
        }
        let mut names = HashSet::new();
        names.insert(raw.principal.as_str());
        if let Some(purpose) = &raw.purpose {
            if !names.insert(purpose.as_str()) {
                return Err(RuntimeConfigError::InvalidOidc);
            }
        }
        Ok(Self {
            principal: raw.principal,
            purpose: raw.purpose,
        })
    }

    fn to_platform_config(&self) -> AuthorityClaimConfig {
        AuthorityClaimConfig::new(self.principal.clone(), self.purpose.clone())
    }
}

impl fmt::Debug for AuthorityClaimsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityClaimsConfig")
            .field("principal", &"<redacted>")
            .field("purpose", &self.purpose.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[derive(Clone)]
pub struct AuditConfig {
    hash_key_ref: SecretReference,
}

impl AuditConfig {
    fn from_raw(raw: RawAuditConfig) -> Result<Self> {
        let hash_key_ref =
            parse_secret_reference(raw.hash_key_ref, RuntimeConfigError::InvalidAudit)?;
        Ok(Self { hash_key_ref })
    }
}

impl fmt::Debug for AuditConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditConfig")
            .field("hash_key_ref", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub struct CursorConfig {
    secret_ref: SecretReference,
    max_age: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventDeliveryConfig {
    payload_retention: Duration,
}

impl EventDeliveryConfig {
    fn from_raw(raw: RawEventDeliveryConfig) -> Result<Self> {
        if raw.payload_retention_days == 0
            || raw.payload_retention_days > MAX_WEBHOOK_PAYLOAD_RETENTION_DAYS
        {
            return Err(RuntimeConfigError::InvalidBounds);
        }
        Ok(Self {
            payload_retention: Duration::from_secs(
                u64::from(raw.payload_retention_days) * 24 * 60 * 60,
            ),
        })
    }

    #[must_use]
    pub fn payload_retention(&self) -> Duration {
        self.payload_retention
    }
}

impl CursorConfig {
    fn from_raw(raw: RawCursorConfig) -> Result<Self> {
        Ok(Self {
            secret_ref: parse_secret_reference(raw.secret_ref, RuntimeConfigError::InvalidCursor)?,
            max_age: seconds_bounded(raw.max_age_seconds, 1, 86_400)?,
        })
    }

    pub fn max_age(&self) -> Duration {
        self.max_age
    }
}

impl fmt::Debug for CursorConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CursorConfig")
            .field("secret_ref", &"<redacted>")
            .field("max_age", &self.max_age)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationalTimeouts {
    pub http_request: Duration,
    pub shutdown_grace: Duration,
    pub record_lock: Duration,
    pub migration_lock: Duration,
    pub migration_statement: Duration,
}

impl OperationalTimeouts {
    fn from_raw(raw: RawOperationalTimeouts) -> Result<Self> {
        Ok(Self {
            http_request: millis_bounded(raw.http_request_milliseconds, 1, 60_000)?,
            shutdown_grace: millis_bounded(raw.shutdown_grace_milliseconds, 1, 300_000)?,
            record_lock: millis_bounded(raw.record_lock_milliseconds, 1, 30_000)?,
            migration_lock: millis_bounded(raw.migration_lock_milliseconds, 1, 300_000)?,
            migration_statement: millis_bounded(
                raw.migration_statement_milliseconds,
                1,
                3_600_000,
            )?,
        })
    }
}

#[derive(Clone)]
pub struct SqlRoles {
    migration: SqlIdentifier,
    runtime: SqlIdentifier,
}

impl SqlRoles {
    fn from_raw(raw: RawSqlRoles) -> Result<Self> {
        if raw.migration == raw.runtime {
            return Err(RuntimeConfigError::InvalidDatabase);
        }
        Ok(Self {
            migration: SqlIdentifier::parse(&raw.migration)
                .map_err(|_| RuntimeConfigError::InvalidDatabase)?,
            runtime: SqlIdentifier::parse(&raw.runtime)
                .map_err(|_| RuntimeConfigError::InvalidDatabase)?,
        })
    }

    pub fn migration(&self) -> &SqlIdentifier {
        &self.migration
    }

    pub fn runtime(&self) -> &SqlIdentifier {
        &self.runtime
    }
}

impl fmt::Debug for SqlRoles {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqlRoles")
            .field("migration", &"<redacted>")
            .field("runtime", &"<redacted>")
            .finish()
    }
}

impl DatabaseConfig {
    pub fn roles(&self) -> &SqlRoles {
        &self.roles
    }
}

pub(crate) fn parse_secret_reference(
    value: String,
    error: RuntimeConfigError,
) -> Result<SecretReference> {
    SecretReference::parse(value).map_err(|_| error)
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawRuntimeConfig {
    api_version: String,
    kind: String,
    listener: RawListenerConfig,
    identity: RawDeploymentIdentity,
    secret_providers: RawSecretProvidersConfig,
    database: RawDatabaseConfig,
    package: RawPackageConfig,
    authentication: RawAuthenticationConfig,
    audit: RawAuditConfig,
    cursor: RawCursorConfig,
    #[serde(default)]
    event_destinations: RawEventDestinationConfigs,
    /// Optional event-delivery tuning. Defaults to the server's bounded retention policy.
    #[serde(default)]
    event_delivery: RawEventDeliveryConfig,
    /// Optional operational request, shutdown, locking, and migration timeout tuning.
    #[serde(default)]
    operational_timeouts: RawOperationalTimeouts,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawListenerConfig {
    bind: String,
    trusted_proxy: TrustedProxyPosture,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawDeploymentIdentity {
    environment: String,
    instance_id: String,
    database_id: String,
    database_initialization_environment: String,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawSecretProvidersConfig {
    environment: Option<RawEnvironmentSecretProviderConfig>,
    file: Option<RawFileSecretProviderConfig>,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEnvironmentSecretProviderConfig {}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFileSecretProviderConfig {
    root: PathBuf,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawDatabaseConfig {
    runtime_url_ref: String,
    migration_url_ref: String,
    pool: RawPoolBounds,
    roles: RawSqlRoles,
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(skip))]
    plaintext: Option<bool>,
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(skip))]
    url: Option<String>,
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(skip))]
    password: Option<String>,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawPoolBounds {
    max_size: usize,
    /// Defaults to the bounded PostgreSQL pool wait timeout.
    #[serde(default = "default_pool_wait_timeout_milliseconds")]
    wait_timeout_milliseconds: u64,
    /// Defaults to the bounded PostgreSQL pool connection-creation timeout.
    #[serde(default = "default_pool_create_timeout_milliseconds")]
    create_timeout_milliseconds: u64,
    /// Defaults to the bounded PostgreSQL pool connection-recycle timeout.
    #[serde(default = "default_pool_recycle_timeout_milliseconds")]
    recycle_timeout_milliseconds: u64,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawSqlRoles {
    migration: String,
    runtime: String,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawPackageConfig {
    root: PathBuf,
    trust_anchor_path: PathBuf,
    compiler_source_revision: String,
    active_revision: String,
    active_sequence: u64,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawAuthenticationConfig {
    oidc: RawOidcVerifierConfig,
    authority_claims: RawAuthorityClaimsConfig,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawOidcVerifierConfig {
    issuer: String,
    audience: String,
    allowed_algorithm: OidcAlgorithm,
    access_token_type: String,
    scope_claim: String,
    scope_separator: char,
    #[serde(default)]
    allowed_clients: Vec<String>,
    #[serde(default)]
    denied_kids: Vec<String>,
    max_token_lifetime_seconds: u64,
    leeway_milliseconds: u64,
    /// Optional JWKS fetch and cache tuning. Defaults to bounded cache behavior.
    #[serde(default)]
    jwks_cache: RawJwksCacheConfig,
    #[serde(default)]
    jwks_source: Option<RawOidcJwksSource>,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields,
    tag = "kind"
)]
enum RawOidcJwksSource {
    Discovery {},
    Static { document_ref: String },
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawJwksCacheConfig {
    /// Defaults to the bounded JWKS cache time-to-live.
    #[serde(default = "default_jwks_cache_ttl_seconds")]
    cache_ttl_seconds: u64,
    /// Defaults to the bounded JWKS negative-cache time-to-live.
    #[serde(default = "default_jwks_negative_cache_ttl_seconds")]
    negative_cache_ttl_seconds: u64,
    /// Defaults to the bounded JWKS refresh cooldown.
    #[serde(default = "default_jwks_refresh_cooldown_seconds")]
    refresh_cooldown_seconds: u64,
    /// Defaults to the bounded maximum JWKS document size.
    #[serde(default = "default_jwks_max_document_bytes")]
    max_document_bytes: u64,
    /// Defaults to the bounded JWKS fetch timeout.
    #[serde(default = "default_jwks_request_timeout_milliseconds")]
    request_timeout_milliseconds: u64,
    /// Defaults to the bounded cached-key outage tolerance.
    #[serde(default = "default_jwks_outage_tolerance_seconds")]
    outage_tolerance_seconds: u64,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawAuthorityClaimsConfig {
    principal: String,
    #[serde(default)]
    purpose: Option<String>,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawAuditConfig {
    hash_key_ref: String,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawCursorConfig {
    secret_ref: String,
    /// Defaults to the bounded cursor validity lifetime.
    #[serde(default = "default_cursor_max_age_seconds")]
    max_age_seconds: u64,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawEventDeliveryConfig {
    /// Defaults to the bounded retained payload lifetime for pending or dead-letter webhook work.
    #[serde(default = "default_webhook_payload_retention_days")]
    payload_retention_days: u8,
}

impl Default for RawEventDeliveryConfig {
    fn default() -> Self {
        Self {
            payload_retention_days: default_webhook_payload_retention_days(),
        }
    }
}

const fn default_webhook_payload_retention_days() -> u8 {
    DEFAULT_WEBHOOK_PAYLOAD_RETENTION_DAYS
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawOperationalTimeouts {
    /// Defaults to the bounded per-request HTTP timeout.
    #[serde(default = "default_http_request_timeout_milliseconds")]
    http_request_milliseconds: u64,
    /// Defaults to the bounded graceful-shutdown timeout.
    #[serde(default = "default_shutdown_grace_milliseconds")]
    shutdown_grace_milliseconds: u64,
    /// Defaults to the bounded record lock timeout.
    #[serde(default = "default_record_lock_milliseconds")]
    record_lock_milliseconds: u64,
    /// Defaults to the bounded migration lock timeout.
    #[serde(default = "default_migration_lock_milliseconds")]
    migration_lock_milliseconds: u64,
    /// Defaults to the bounded migration statement timeout.
    #[serde(default = "default_migration_statement_milliseconds")]
    migration_statement_milliseconds: u64,
}

impl Default for RawOperationalTimeouts {
    fn default() -> Self {
        Self {
            http_request_milliseconds: default_http_request_timeout_milliseconds(),
            shutdown_grace_milliseconds: default_shutdown_grace_milliseconds(),
            record_lock_milliseconds: default_record_lock_milliseconds(),
            migration_lock_milliseconds: default_migration_lock_milliseconds(),
            migration_statement_milliseconds: default_migration_statement_milliseconds(),
        }
    }
}

impl Default for RawJwksCacheConfig {
    fn default() -> Self {
        Self {
            cache_ttl_seconds: default_jwks_cache_ttl_seconds(),
            negative_cache_ttl_seconds: default_jwks_negative_cache_ttl_seconds(),
            refresh_cooldown_seconds: default_jwks_refresh_cooldown_seconds(),
            max_document_bytes: default_jwks_max_document_bytes(),
            request_timeout_milliseconds: default_jwks_request_timeout_milliseconds(),
            outage_tolerance_seconds: default_jwks_outage_tolerance_seconds(),
        }
    }
}

const fn default_pool_wait_timeout_milliseconds() -> u64 {
    DEFAULT_POOL_WAIT_TIMEOUT_MILLISECONDS
}

const fn default_pool_create_timeout_milliseconds() -> u64 {
    DEFAULT_POOL_CREATE_TIMEOUT_MILLISECONDS
}

const fn default_pool_recycle_timeout_milliseconds() -> u64 {
    DEFAULT_POOL_RECYCLE_TIMEOUT_MILLISECONDS
}

const fn default_jwks_cache_ttl_seconds() -> u64 {
    DEFAULT_JWKS_CACHE_TTL_SECONDS
}

const fn default_jwks_negative_cache_ttl_seconds() -> u64 {
    DEFAULT_JWKS_NEGATIVE_CACHE_TTL_SECONDS
}

const fn default_jwks_refresh_cooldown_seconds() -> u64 {
    DEFAULT_JWKS_REFRESH_COOLDOWN_SECONDS
}

const fn default_jwks_max_document_bytes() -> u64 {
    DEFAULT_JWKS_MAX_DOCUMENT_BYTES
}

const fn default_jwks_request_timeout_milliseconds() -> u64 {
    DEFAULT_JWKS_REQUEST_TIMEOUT_MILLISECONDS
}

const fn default_jwks_outage_tolerance_seconds() -> u64 {
    DEFAULT_JWKS_OUTAGE_TOLERANCE_SECONDS
}

const fn default_cursor_max_age_seconds() -> u64 {
    DEFAULT_CURSOR_MAX_AGE_SECONDS
}

const fn default_http_request_timeout_milliseconds() -> u64 {
    DEFAULT_HTTP_REQUEST_TIMEOUT_MILLISECONDS
}

const fn default_shutdown_grace_milliseconds() -> u64 {
    DEFAULT_SHUTDOWN_GRACE_MILLISECONDS
}

const fn default_record_lock_milliseconds() -> u64 {
    DEFAULT_RECORD_LOCK_MILLISECONDS
}

const fn default_migration_lock_milliseconds() -> u64 {
    DEFAULT_MIGRATION_LOCK_MILLISECONDS
}

const fn default_migration_statement_milliseconds() -> u64 {
    DEFAULT_MIGRATION_STATEMENT_MILLISECONDS
}

#[cfg(feature = "schema")]
pub fn runtime_config_schema() -> std::result::Result<Value, serde_json::Error> {
    let mut schema = serde_json::to_value(schemars::schema_for!(RawRuntimeConfig))?;
    install_schema_const_property(&mut schema, "apiVersion", RUNTIME_CONFIG_API_VERSION);
    install_schema_const_property(&mut schema, "kind", RUNTIME_CONFIG_KIND);
    install_schema_constraints(&mut schema);
    for pointer in [
        "/properties/eventDestinations",
        "/$defs/RawAuthorityClaimsConfig/properties/purpose",
        "/$defs/RawDatabaseConfig/properties/password",
        "/$defs/RawDatabaseConfig/properties/plaintext",
        "/$defs/RawDatabaseConfig/properties/url",
        "/$defs/RawEventDestinationConfig/properties/tls",
        "/$defs/RawEventDestinationTlsConfig/properties/caBundleRef",
        "/$defs/RawEventDestinationTlsConfig/properties/clientIdentityRef",
        "/$defs/RawOidcVerifierConfig/properties/allowedClients",
        "/$defs/RawOidcVerifierConfig/properties/deniedKids",
        "/$defs/RawOidcVerifierConfig/properties/jwksSource",
    ] {
        remove_schema_default(&mut schema, pointer);
    }
    Ok(schema)
}

#[cfg(feature = "schema")]
fn install_schema_constraints(schema: &mut Value) {
    for (pointer, minimum, maximum) in [
        (
            "/$defs/RawPoolBounds/properties/maxSize",
            1,
            MAX_DATABASE_POOL_SIZE,
        ),
        (
            "/$defs/RawPoolBounds/properties/waitTimeoutMilliseconds",
            1,
            60_000,
        ),
        (
            "/$defs/RawPoolBounds/properties/createTimeoutMilliseconds",
            1,
            60_000,
        ),
        (
            "/$defs/RawPoolBounds/properties/recycleTimeoutMilliseconds",
            1,
            60_000,
        ),
        (
            "/$defs/RawPackageConfig/properties/activeSequence",
            1,
            u64::MAX,
        ),
        (
            "/$defs/RawOidcVerifierConfig/properties/maxTokenLifetimeSeconds",
            1,
            3_600,
        ),
        (
            "/$defs/RawOidcVerifierConfig/properties/leewayMilliseconds",
            0,
            300_000,
        ),
        (
            "/$defs/RawJwksCacheConfig/properties/cacheTtlSeconds",
            1,
            86_400,
        ),
        (
            "/$defs/RawJwksCacheConfig/properties/negativeCacheTtlSeconds",
            1,
            3_600,
        ),
        (
            "/$defs/RawJwksCacheConfig/properties/refreshCooldownSeconds",
            1,
            3_600,
        ),
        (
            "/$defs/RawJwksCacheConfig/properties/maxDocumentBytes",
            1,
            MAX_JWKS_DOCUMENT_BYTES,
        ),
        (
            "/$defs/RawJwksCacheConfig/properties/requestTimeoutMilliseconds",
            1,
            30_000,
        ),
        (
            "/$defs/RawJwksCacheConfig/properties/outageToleranceSeconds",
            0,
            86_400,
        ),
        ("/$defs/RawCursorConfig/properties/maxAgeSeconds", 1, 86_400),
        (
            "/$defs/RawEventDeliveryConfig/properties/payloadRetentionDays",
            1,
            u64::from(MAX_WEBHOOK_PAYLOAD_RETENTION_DAYS),
        ),
        (
            "/$defs/RawOperationalTimeouts/properties/httpRequestMilliseconds",
            1,
            60_000,
        ),
        (
            "/$defs/RawOperationalTimeouts/properties/shutdownGraceMilliseconds",
            1,
            300_000,
        ),
        (
            "/$defs/RawOperationalTimeouts/properties/recordLockMilliseconds",
            1,
            30_000,
        ),
        (
            "/$defs/RawOperationalTimeouts/properties/migrationLockMilliseconds",
            1,
            300_000,
        ),
        (
            "/$defs/RawOperationalTimeouts/properties/migrationStatementMilliseconds",
            1,
            3_600_000,
        ),
        (
            "/$defs/RawEventDestinationDeliveryCeilings/properties/attemptTimeoutMilliseconds",
            u64::from(MIN_WEBHOOK_ATTEMPT_TIMEOUT_MS),
            u64::from(MAX_WEBHOOK_ATTEMPT_TIMEOUT_MS),
        ),
        (
            "/$defs/RawEventDestinationDeliveryCeilings/properties/maximumAttempts",
            1,
            u64::from(MAX_WEBHOOK_ATTEMPTS),
        ),
    ] {
        install_schema_integer_bounds(schema, pointer, minimum, maximum);
    }

    for (pointer, minimum, maximum, pattern) in [
        (
            "/$defs/RawDeploymentIdentity/properties/environment",
            1,
            MAX_DEPLOYMENT_VALUE_BYTES,
            VALUE_NO_EDGE_WHITESPACE_SCHEMA_PATTERN,
        ),
        (
            "/$defs/RawDeploymentIdentity/properties/instanceId",
            1,
            MAX_DEPLOYMENT_VALUE_BYTES,
            VALUE_NO_EDGE_WHITESPACE_SCHEMA_PATTERN,
        ),
        (
            "/$defs/RawDeploymentIdentity/properties/databaseId",
            1,
            MAX_DEPLOYMENT_VALUE_BYTES,
            VALUE_NO_EDGE_WHITESPACE_SCHEMA_PATTERN,
        ),
        (
            "/$defs/RawDeploymentIdentity/properties/databaseInitializationEnvironment",
            1,
            MAX_DEPLOYMENT_VALUE_BYTES,
            VALUE_NO_EDGE_WHITESPACE_SCHEMA_PATTERN,
        ),
        (
            "/$defs/RawFileSecretProviderConfig/properties/root",
            1,
            MAX_PATH_BYTES,
            "",
        ),
        (
            "/$defs/RawDatabaseConfig/properties/runtimeUrlRef",
            1,
            MAX_SECRET_REFERENCE_SCHEMA_LENGTH,
            SECRET_REFERENCE_SCHEMA_PATTERN,
        ),
        (
            "/$defs/RawDatabaseConfig/properties/migrationUrlRef",
            1,
            MAX_SECRET_REFERENCE_SCHEMA_LENGTH,
            SECRET_REFERENCE_SCHEMA_PATTERN,
        ),
        (
            "/$defs/RawSqlRoles/properties/migration",
            1,
            63,
            SQL_IDENTIFIER_SCHEMA_PATTERN,
        ),
        (
            "/$defs/RawSqlRoles/properties/runtime",
            1,
            63,
            SQL_IDENTIFIER_SCHEMA_PATTERN,
        ),
        (
            "/$defs/RawPackageConfig/properties/root",
            1,
            MAX_PATH_BYTES,
            "",
        ),
        (
            "/$defs/RawPackageConfig/properties/trustAnchorPath",
            1,
            MAX_PATH_BYTES,
            "",
        ),
        (
            "/$defs/RawPackageConfig/properties/compilerSourceRevision",
            1,
            MAX_DEPLOYMENT_VALUE_BYTES,
            VALUE_NO_EDGE_WHITESPACE_SCHEMA_PATTERN,
        ),
        (
            "/$defs/RawPackageConfig/properties/activeRevision",
            1,
            MAX_DEPLOYMENT_VALUE_BYTES,
            VALUE_NO_EDGE_WHITESPACE_SCHEMA_PATTERN,
        ),
        (
            "/$defs/RawOidcVerifierConfig/properties/issuer",
            1,
            MAX_OIDC_VALUE_BYTES,
            VALUE_NO_EDGE_WHITESPACE_SCHEMA_PATTERN,
        ),
        (
            "/$defs/RawOidcVerifierConfig/properties/audience",
            1,
            MAX_OIDC_VALUE_BYTES,
            VALUE_NO_EDGE_WHITESPACE_SCHEMA_PATTERN,
        ),
        (
            "/$defs/RawOidcVerifierConfig/properties/accessTokenType",
            1,
            MAX_OIDC_VALUE_BYTES,
            VALUE_NO_EDGE_WHITESPACE_SCHEMA_PATTERN,
        ),
        (
            "/$defs/RawOidcVerifierConfig/properties/scopeClaim",
            1,
            128,
            CLAIM_NAME_SCHEMA_PATTERN,
        ),
        (
            "/$defs/RawOidcVerifierConfig/properties/scopeSeparator",
            1,
            1,
            SCOPE_SEPARATOR_SCHEMA_PATTERN,
        ),
        (
            "/$defs/RawOidcJwksSource/oneOf/1/properties/documentRef",
            1,
            MAX_SECRET_REFERENCE_SCHEMA_LENGTH,
            SECRET_REFERENCE_SCHEMA_PATTERN,
        ),
        (
            "/$defs/RawAuthorityClaimsConfig/properties/principal",
            1,
            128,
            CLAIM_NAME_SCHEMA_PATTERN,
        ),
        (
            "/$defs/RawAuthorityClaimsConfig/properties/purpose",
            1,
            128,
            CLAIM_NAME_SCHEMA_PATTERN,
        ),
        (
            "/$defs/RawAuditConfig/properties/hashKeyRef",
            1,
            MAX_SECRET_REFERENCE_SCHEMA_LENGTH,
            SECRET_REFERENCE_SCHEMA_PATTERN,
        ),
        (
            "/$defs/RawCursorConfig/properties/secretRef",
            1,
            MAX_SECRET_REFERENCE_SCHEMA_LENGTH,
            SECRET_REFERENCE_SCHEMA_PATTERN,
        ),
        (
            "/$defs/RawEventDestinationConfig/properties/origin",
            1,
            MAX_DESTINATION_ORIGIN_URL_BYTES,
            "",
        ),
        (
            "/$defs/RawEventDestinationConfig/properties/path",
            1,
            MAX_DESTINATION_TARGET_BYTES,
            EVENT_DESTINATION_PATH_SCHEMA_PATTERN,
        ),
        (
            "/$defs/RawEventDestinationConfig/properties/hmacSha256KeyRef",
            1,
            MAX_SECRET_REFERENCE_SCHEMA_LENGTH,
            SECRET_REFERENCE_SCHEMA_PATTERN,
        ),
        (
            "/$defs/RawEventDestinationTlsConfig/properties/caBundleRef",
            1,
            MAX_SECRET_REFERENCE_SCHEMA_LENGTH,
            SECRET_REFERENCE_SCHEMA_PATTERN,
        ),
        (
            "/$defs/RawEventDestinationTlsConfig/properties/clientIdentityRef",
            1,
            MAX_SECRET_REFERENCE_SCHEMA_LENGTH,
            SECRET_REFERENCE_SCHEMA_PATTERN,
        ),
    ] {
        install_schema_string_constraints(schema, pointer, minimum, maximum, pattern);
    }

    for pointer in [
        "/$defs/RawOidcVerifierConfig/properties/allowedClients",
        "/$defs/RawOidcVerifierConfig/properties/deniedKids",
    ] {
        install_schema_array_constraints(schema, pointer, MAX_LIST_ITEMS, true);
        if let Some(items) = schema
            .pointer_mut(pointer)
            .and_then(Value::as_object_mut)
            .and_then(|member| member.get_mut("items"))
            .and_then(Value::as_object_mut)
        {
            install_string_constraints_in_object(
                items,
                1,
                MAX_LIST_VALUE_BYTES,
                LIST_VALUE_SCHEMA_PATTERN,
            );
        }
    }
    install_schema_array_constraints(
        schema,
        "/$defs/RawEventDestinationConfig/properties/allowedPrivateCidrs",
        MAX_DESTINATION_PRIVATE_CIDRS,
        true,
    );
    install_schema_property_names(
        schema,
        "/properties/eventDestinations",
        EVENT_DESTINATION_ID_SCHEMA_PATTERN,
    );
    if let Some(member) = schema
        .pointer_mut("/properties/eventDestinations")
        .and_then(Value::as_object_mut)
    {
        member.insert("maxProperties".to_owned(), Value::from(128_u64));
    }
    install_schema_authority_claim_exclusions(schema);
    install_schema_tls_presence_constraint(schema);
}

#[cfg(feature = "schema")]
fn install_schema_const_property(schema: &mut Value, property: &'static str, expected: &str) {
    let Some(properties) = schema
        .get_mut("properties")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    let Some(member) = properties
        .get_mut(property)
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    member.clear();
    member.insert("type".to_owned(), Value::String("string".to_owned()));
    member.insert("const".to_owned(), Value::String(expected.to_owned()));
}

#[cfg(feature = "schema")]
fn install_schema_integer_bounds(schema: &mut Value, pointer: &str, minimum: u64, maximum: u64) {
    if let Some(member) = schema.pointer_mut(pointer).and_then(Value::as_object_mut) {
        member.insert("minimum".to_owned(), Value::from(minimum));
        if maximum != u64::MAX {
            member.insert("maximum".to_owned(), Value::from(maximum));
        }
    }
}

#[cfg(feature = "schema")]
fn install_schema_string_constraints(
    schema: &mut Value,
    pointer: &str,
    minimum: usize,
    maximum: usize,
    pattern: &str,
) {
    if let Some(member) = schema.pointer_mut(pointer).and_then(Value::as_object_mut) {
        install_string_constraints_in_object(member, minimum, maximum, pattern);
    }
}

#[cfg(feature = "schema")]
fn install_string_constraints_in_object(
    member: &mut Map<String, Value>,
    minimum: usize,
    maximum: usize,
    pattern: &str,
) {
    member.insert("minLength".to_owned(), Value::from(minimum));
    member.insert("maxLength".to_owned(), Value::from(maximum));
    if !pattern.is_empty() {
        member.insert("pattern".to_owned(), Value::String(pattern.to_owned()));
    }
}

#[cfg(feature = "schema")]
fn install_schema_array_constraints(
    schema: &mut Value,
    pointer: &str,
    maximum: usize,
    unique_items: bool,
) {
    if let Some(member) = schema.pointer_mut(pointer).and_then(Value::as_object_mut) {
        member.insert("maxItems".to_owned(), Value::from(maximum));
        if unique_items {
            member.insert("uniqueItems".to_owned(), Value::Bool(true));
        }
    }
}

#[cfg(feature = "schema")]
fn install_schema_property_names(schema: &mut Value, pointer: &str, pattern: &str) {
    if let Some(member) = schema.pointer_mut(pointer).and_then(Value::as_object_mut) {
        member.insert(
            "propertyNames".to_owned(),
            serde_json::json!({
                "type": "string",
                "pattern": pattern,
            }),
        );
    }
}

#[cfg(feature = "schema")]
fn install_schema_authority_claim_exclusions(schema: &mut Value) {
    let registered = serde_json::json!({
        "enum": [
            "iss",
            "aud",
            "exp",
            "iat",
            "nbf",
            "sub",
            "client_id",
            "azp",
            "jti",
            "cnf"
        ]
    });
    for pointer in [
        "/$defs/RawAuthorityClaimsConfig/properties/principal",
        "/$defs/RawAuthorityClaimsConfig/properties/purpose",
    ] {
        if let Some(member) = schema.pointer_mut(pointer).and_then(Value::as_object_mut) {
            member.insert("not".to_owned(), registered.clone());
        }
    }
}

#[cfg(feature = "schema")]
fn install_schema_tls_presence_constraint(schema: &mut Value) {
    let Some(member) = schema
        .pointer_mut("/$defs/RawEventDestinationTlsConfig")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    member.insert(
        "anyOf".to_owned(),
        serde_json::json!([
            {
                "required": ["caBundleRef"],
                "properties": {
                    "caBundleRef": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_SECRET_REFERENCE_SCHEMA_LENGTH,
                        "pattern": SECRET_REFERENCE_SCHEMA_PATTERN
                    }
                }
            },
            {
                "required": ["clientIdentityRef"],
                "properties": {
                    "clientIdentityRef": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_SECRET_REFERENCE_SCHEMA_LENGTH,
                        "pattern": SECRET_REFERENCE_SCHEMA_PATTERN
                    }
                }
            }
        ]),
    );
}

#[cfg(feature = "schema")]
fn remove_schema_default(schema: &mut Value, pointer: &str) {
    if let Some(member) = schema.pointer_mut(pointer).and_then(Value::as_object_mut) {
        member.remove("default");
    }
}

fn read_bounded_runtime_config(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let scanned = fs::symlink_metadata(path).map_err(|_| RuntimeConfigError::Unavailable)?;
    if scanned.file_type().is_symlink() || !scanned.is_file() {
        return Err(RuntimeConfigError::UnsafeFile);
    }
    if scanned.len() == 0 || scanned.len() > maximum {
        return Err(RuntimeConfigError::Bounds);
    }
    let file = open_runtime_config_file(path)?;
    let opened = file
        .metadata()
        .map_err(|_| RuntimeConfigError::Unavailable)?;
    let current = fs::symlink_metadata(path).map_err(|_| RuntimeConfigError::Unavailable)?;
    if current.file_type().is_symlink()
        || !opened.is_file()
        || !same_file(&scanned, &opened)
        || !same_file(&opened, &current)
    {
        return Err(RuntimeConfigError::UnsafeFile);
    }
    if opened.len() == 0 || opened.len() > maximum {
        return Err(RuntimeConfigError::Bounds);
    }
    let capacity = usize::try_from(opened.len()).map_err(|_| RuntimeConfigError::Bounds)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve(capacity)
        .map_err(|_| RuntimeConfigError::Bounds)?;
    let mut reader = file.take(maximum + 1);
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| RuntimeConfigError::Unavailable)?;
    let after = reader
        .get_ref()
        .metadata()
        .map_err(|_| RuntimeConfigError::Unavailable)?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(RuntimeConfigError::Bounds);
    }
    if !same_file(&opened, &after) || bytes.len() as u64 != after.len() {
        return Err(RuntimeConfigError::UnsafeFile);
    }
    Ok(bytes)
}

fn open_runtime_config_file(path: &Path) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(runtime_config_no_follow_flag());
    }
    options.open(path).map_err(|_| {
        fs::symlink_metadata(path).map_or(RuntimeConfigError::Unavailable, |metadata| {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                RuntimeConfigError::UnsafeFile
            } else {
                RuntimeConfigError::Unavailable
            }
        })
    })
}

#[cfg(unix)]
fn runtime_config_no_follow_flag() -> i32 {
    (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC).bits() as i32
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.permissions().mode() == right.permissions().mode()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
        && left.permissions().readonly() == right.permissions().readonly()
        && left.modified().ok() == right.modified().ok()
        && left.created().ok() == right.created().ok()
}

fn validate_existing_directory(path: &Path, error: RuntimeConfigError) -> Result<()> {
    reject_symlink_components(path, error)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| error)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(error);
    }
    Ok(())
}

fn validate_existing_file(path: &Path, error: RuntimeConfigError) -> Result<()> {
    reject_symlink_components(path, error)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| error)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(error);
    }
    Ok(())
}

fn reject_symlink_components(path: &Path, error: RuntimeConfigError) -> Result<()> {
    let mut checked = PathBuf::new();
    for component in path.components() {
        checked.push(component.as_os_str());
        if matches!(component, Component::RootDir | Component::Prefix(_)) {
            continue;
        }
        match fs::symlink_metadata(&checked) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Err(error),
            Ok(_) => {}
            Err(_) => return Err(error),
        }
    }
    Ok(())
}

fn validate_absolute_lexical_path(path: &Path, error: RuntimeConfigError) -> Result<()> {
    if path.as_os_str().is_empty()
        || !path.is_absolute()
        || path.to_string_lossy().len() > MAX_PATH_BYTES
    {
        return Err(error);
    }
    if path.components().any(|component| {
        !matches!(
            component,
            Component::Prefix(_) | Component::RootDir | Component::Normal(_)
        )
    }) {
        return Err(error);
    }
    Ok(())
}

fn validate_deployment_value(value: &str) -> Result<()> {
    if value.trim().is_empty()
        || value.trim() != value
        || value.len() > MAX_DEPLOYMENT_VALUE_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(RuntimeConfigError::InvalidBinding);
    }
    Ok(())
}

fn validate_oidc_value(value: &str) -> Result<()> {
    if value.trim().is_empty()
        || value.trim() != value
        || value.len() > MAX_OIDC_VALUE_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(RuntimeConfigError::InvalidOidc);
    }
    Ok(())
}

fn validate_claim_name(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(RuntimeConfigError::InvalidOidc);
    }
    Ok(())
}

fn validate_authority_claim_name(value: &str) -> Result<()> {
    const REGISTERED: &[&str] = &[
        "iss",
        "aud",
        "exp",
        "iat",
        "nbf",
        "sub",
        "client_id",
        "azp",
        "jti",
        "cnf",
    ];
    validate_claim_name(value)?;
    if REGISTERED.contains(&value) {
        return Err(RuntimeConfigError::InvalidOidc);
    }
    Ok(())
}

fn validate_bounded_list(values: &[String]) -> Result<()> {
    if values.len() > MAX_LIST_ITEMS {
        return Err(RuntimeConfigError::InvalidOidc);
    }
    for value in values {
        if value.is_empty()
            || value.len() > MAX_LIST_VALUE_BYTES
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(RuntimeConfigError::InvalidOidc);
        }
    }
    Ok(())
}

fn millis(value: u64) -> Result<Duration> {
    millis_bounded(value, 1, 60_000)
}

fn millis_bounded(value: u64, min: u64, max: u64) -> Result<Duration> {
    if value < min || value > max {
        return Err(RuntimeConfigError::InvalidBounds);
    }
    Ok(Duration::from_millis(value))
}

fn seconds_bounded(value: u64, min: u64, max: u64) -> Result<Duration> {
    if value < min || value > max {
        return Err(RuntimeConfigError::InvalidBounds);
    }
    Ok(Duration::from_secs(value))
}
