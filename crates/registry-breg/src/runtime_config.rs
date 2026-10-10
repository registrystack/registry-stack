// SPDX-License-Identifier: Apache-2.0
//! Strict deployment-only runtime configuration for Base Registry Engine.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fmt, fs,
    net::{IpAddr, SocketAddr},
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::jwk::JwkSet;
use registry_platform_audit::{AuditDestination, AuditDestinationKind, AuditProfile};
use registry_platform_config::{
    AuditKeyConfig, JwksSource, ListenerBind, OidcIssuerConfig,
    PackageConfig as SharedPackageConfig, RemovedKey, RuntimeConfigLoader, RuntimeEnvelope,
    SecretError, SecretReference, SecretResolver, REMOVED_OIDC_JWKS_SOURCE_KIND,
};
use registry_platform_crypto::{parse_json_strict, PublicJwk, SigningAlgorithm};
#[cfg(feature = "schema")]
use registry_platform_httputil::destination::{
    MAX_DESTINATION_ORIGIN_URL_BYTES, MAX_DESTINATION_PRIVATE_CIDRS, MAX_DESTINATION_TARGET_BYTES,
};
use registry_platform_oidc::{
    access_token_typ_set, fetch_discovery, ClaimNames, JwksFetcher, JwksFetcherConfig,
    OidcDiscoveryConfig, TokenVerifierConfig,
};
#[cfg(feature = "schema")]
use registry_platform_yaml::{BoundedU32, BoundedU64};
use registry_platform_yaml::{Diagnostic, Report, RetiredApiVersion, Severity, Source, Url};
use serde::Deserialize;
use serde_json::{Map, Value};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::contract::{external_id_map, local_id_map};
#[cfg(feature = "schema")]
use crate::contract::{external_id_map_schema, local_id_map_schema};
use crate::{
    auth::{AuthenticationConfigError, AuthorityClaimConfig},
    cursor::CursorCodec,
    event_destination::{
        ActivatedEventDestinationRegistry, EventDestinationConfigs, RawEventDestinationConfigs,
    },
    model::CompiledRegistry,
    package::{
        load_package_with_verified_envelope, load_predecessor_package_with_verified_envelope,
        PackageError, PackageLoadContext, VerifiedPackage, VerifiedPredecessorPackage,
    },
    postgres::{ConnectionConfig, PoolBounds, SqlIdentifier},
};

const MAX_PATH_BYTES: usize = 512;
const MAX_DEPLOYMENT_VALUE_BYTES: usize = 256;
const MAX_OIDC_VALUE_BYTES: usize = 2048;
const MAX_PUBLIC_ORIGIN_BYTES: usize = 2048;
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
const MAX_OIDC_LEEWAY_MILLISECONDS: u64 = 300_000;
const DEFAULT_JWKS_CACHE_TTL_SECONDS: u64 = 600;
const DEFAULT_JWKS_NEGATIVE_CACHE_TTL_SECONDS: u64 = 60;
const DEFAULT_JWKS_REFRESH_COOLDOWN_SECONDS: u64 = 30;
const DEFAULT_JWKS_MAX_DOCUMENT_BYTES: u64 = 65_536;
const DEFAULT_JWKS_REQUEST_TIMEOUT_MILLISECONDS: u64 = 5_000;
const DEFAULT_JWKS_OUTAGE_TOLERANCE_SECONDS: u64 = 900;
const DEFAULT_CURSOR_MAX_AGE_SECONDS: u64 = 300;
const DEFAULT_HTTP_REQUEST_TIMEOUT_MILLISECONDS: u64 = 10_000;
/// The longest a Registry request may run before the server abandons it.
pub(crate) const MAX_HTTP_REQUEST_TIMEOUT_MILLISECONDS: u64 = 60_000;
const DEFAULT_SHUTDOWN_GRACE_MILLISECONDS: u64 = 30_000;
const DEFAULT_RECORD_LOCK_MILLISECONDS: u64 = 5_000;
const DEFAULT_MIGRATION_LOCK_MILLISECONDS: u64 = 30_000;
const DEFAULT_MIGRATION_STATEMENT_MILLISECONDS: u64 = 60_000;
/// Floor for the execution-time module ceiling.
const MINIMUM_WASM_EXECUTION_MODULE_BYTES: u64 = 1_024;
/// Default execution-time module ceiling: the authored admission default an
/// ordinary module already satisfies.
const DEFAULT_WASM_EXECUTION_MODULE_BYTES: u64 =
    crate::wasm_handler::DEFAULT_WASM_MODULE_BYTES as u64;
/// Cap on the execution-time module ceiling, equal to the structural
/// authoring ceiling: configuration admits nothing authoring refused.
const MAXIMUM_WASM_EXECUTION_MODULE_BYTES: u64 =
    crate::wasm_handler::MAXIMUM_WASM_MODULE_BYTES as u64;
const MINIMUM_WASM_EXECUTION_GUEST_MEMORY_BYTES: u64 = 1_048_576;
const DEFAULT_WASM_EXECUTION_GUEST_MEMORY_BYTES: u64 =
    crate::wasm_handler::DEFAULT_WASM_GUEST_MEMORY_BYTES as u64;
const MAXIMUM_WASM_EXECUTION_GUEST_MEMORY_BYTES: u64 = 1_073_741_824;
const MAX_DATABASE_POOL_SIZE: u32 = 128;
/// The longest a pool waits for, creates, or recycles a connection.
const MAX_POOL_TIMEOUT_MILLISECONDS: u64 = 60_000;
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
const INSTANCE_ID_SCHEMA_PATTERN: &str = "^[a-z][a-z0-9_-]{0,63}$";
#[cfg(feature = "schema")]
const EVENT_DESTINATION_PATH_SCHEMA_PATTERN: &str =
    "^/[\\x20-\\x22\\x24\\x26-\\x3E\\x40-\\x5B\\x5D-\\x7E]*$";

pub const RUNTIME_CONFIG_API_VERSION: &str = "id.registrystack.org/formats/breg/runtime/v1alpha1";
pub const RUNTIME_CONFIG_KIND: &str = "BRegRuntimeConfig";

/// The apiVersion a runtime file carried before it took the shared identifier
/// form, refused with the value that replaces it.
const RETIRED_RUNTIME_API_VERSIONS: &[RetiredApiVersion<'static>] = &[RetiredApiVersion {
    api_version: "registry.registrystack.org/breg-runtime/v1alpha1",
    replacement: "Write apiVersion id.registrystack.org/formats/breg/runtime/v1alpha1.",
}];

/// Keys the runtime file no longer accepts, each refused with the edit that
/// replaces it.
const REMOVED_KEYS: &[RemovedKey] = &[
    RemovedKey {
        path: "database.url",
        replacement: "delete database.url and name the connection URL by secret reference in database.runtimeUrlRef and database.migrationUrlRef",
    },
    RemovedKey {
        path: "database.password",
        replacement: "delete database.password and put the password inside the connection URL that database.runtimeUrlRef and database.migrationUrlRef name by secret reference",
    },
    RemovedKey {
        path: "database.plaintext",
        replacement: "delete database.plaintext; the connection URL is always named by secret reference in database.runtimeUrlRef and database.migrationUrlRef",
    },
    RemovedKey {
        path: "database.pool.maxSize",
        replacement: "rename database.pool.maxSize to database.pool.maximumConnections; the value stays as it is",
    },
    RemovedKey {
        path: "authentication.oidc.maxTokenLifetimeSeconds",
        replacement: "rename authentication.oidc.maxTokenLifetimeSeconds to authentication.oidc.maximumTokenLifetimeSeconds; the value stays as it is",
    },
    RemovedKey {
        path: "authentication.oidc.jwksCache.maxDocumentBytes",
        replacement: "rename authentication.oidc.jwksCache.maxDocumentBytes to authentication.oidc.jwksCache.maximumDocumentBytes; the value stays as it is",
    },
    RemovedKey {
        path: "authentication.oidc.jwksCache.requestTimeoutMilliseconds",
        replacement: "rename authentication.oidc.jwksCache.requestTimeoutMilliseconds to authentication.oidc.jwksCache.attemptTimeoutMilliseconds; the value stays as it is",
    },
    RemovedKey {
        path: "audit.retainDays",
        replacement: "rename audit.retainDays to audit.retentionDays; the value stays as it is",
    },
    RemovedKey {
        path: "cursor.maxAgeSeconds",
        replacement: "rename cursor.maxAgeSeconds to cursor.maximumAgeSeconds; the value stays as it is",
    },
    RemovedKey {
        path: "wasmExecution.maxModuleBytes",
        replacement: "rename wasmExecution.maxModuleBytes to wasmExecution.maximumModuleBytes; the value stays as it is",
    },
    RemovedKey {
        path: "wasmExecution.maxGuestMemoryBytes",
        replacement: "rename wasmExecution.maxGuestMemoryBytes to wasmExecution.maximumGuestMemoryBytes; the value stays as it is",
    },
    RemovedKey {
        path: "fieldEncryption.provider.timeoutMilliseconds",
        replacement: "rename fieldEncryption.provider.timeoutMilliseconds to fieldEncryption.provider.attemptTimeoutMilliseconds; the value stays as it is",
    },
    RemovedKey {
        path: "attachmentStorage.timeoutMilliseconds",
        replacement: "rename attachmentStorage.timeoutMilliseconds to attachmentStorage.attemptTimeoutMilliseconds; the value stays as it is",
    },
    RemovedKey {
        path: "attachmentVerification.timeoutMilliseconds",
        replacement: "rename attachmentVerification.timeoutMilliseconds to attachmentVerification.attemptTimeoutMilliseconds; the value stays as it is",
    },
    RemovedKey {
        path: "fieldEncryption.provider.kind",
        replacement: "rename fieldEncryption.provider.kind to fieldEncryption.provider.type, and write the value localFile as local-file",
    },
    RemovedKey {
        path: "attachmentStorage.kind",
        replacement: "rename attachmentStorage.kind to attachmentStorage.type; the value stays as it is",
    },
    RemovedKey {
        path: "attachmentVerification.kind",
        replacement: "rename attachmentVerification.kind to attachmentVerification.type; the value stays as it is",
    },
    REMOVED_OIDC_JWKS_SOURCE_KIND,
];

/// The shared reader's refusal of a runtime configuration file: every
/// diagnostic it reported, each with its code, pointer, line, and column.
///
/// `Debug` names the deciding code and pointer only, so a refusal carried in
/// a startup error never prints the configured file path.
#[derive(Clone, Eq, PartialEq)]
pub struct ReaderRefusal(registry_platform_config::RuntimeConfigError);

impl ReaderRefusal {
    /// Every diagnostic, in the order the reader reported them.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        self.0.diagnostics()
    }

    /// The diagnostic the refusal is classified by: the first error of the
    /// earliest kind.
    #[must_use]
    pub fn deciding_diagnostic(&self) -> &Diagnostic {
        self.0.deciding_diagnostic()
    }
}

/// The deciding diagnostic on one line, without the file: its pointer, its
/// message, and after `next:` its suggested action. Like every diagnostic, it
/// never repeats a value.
impl fmt::Display for ReaderRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let deciding = self.deciding_diagnostic();
        let path = if deciding.path.is_empty() {
            "/"
        } else {
            deciding.path.as_str()
        };
        write!(formatter, "{path}: {}", deciding.message)?;
        if !deciding.suggested_action.is_empty() {
            write!(formatter, "; next: {}", deciding.suggested_action)?;
        }
        Ok(())
    }
}

impl fmt::Debug for ReaderRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let deciding = self.deciding_diagnostic();
        formatter
            .debug_struct("ReaderRefusal")
            .field("code", &deciding.code)
            .field("path", &deciding.path)
            .finish()
    }
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum RuntimeConfigError {
    /// The shared reader refused the file: it could not be read, it is not
    /// in the shared YAML subset, its envelope is wrong, a substitution
    /// failed, or a member does not fit its typed shape. The message is the
    /// deciding diagnostic on one line and never repeats a value.
    #[error("{0}")]
    Reader(ReaderRefusal),
    #[error("runtime configuration contains an invalid deployment binding")]
    InvalidBinding,
    #[error(
        "runtime configuration identity.instanceId must start with a lowercase letter and hold at most 64 lowercase letters, digits, `-`, or `_`; set identity.instanceId to such a value"
    )]
    InvalidInstanceId,
    #[error(
        "runtime configuration identity.environment and identity.databaseInitializationEnvironment must be identical; set both to the environment the database was initialized in"
    )]
    EnvironmentIdentityConflict,
    #[error("runtime configuration contains an invalid listener binding")]
    InvalidListener,
    #[error("runtime configuration contains an invalid metrics listener binding")]
    InvalidMetricsListener,
    #[error("runtime configuration contains an invalid secret provider binding")]
    InvalidSecretProvider,
    #[error("the configured file secret provider root is missing or is not a readable directory")]
    SecretProviderRootUnavailable,
    #[error("the configured file secret provider root path contains a symbolic link")]
    UnsafeSecretProviderRoot,
    #[error("runtime configuration contains an invalid database binding")]
    InvalidDatabase,
    #[error("runtime configuration asks for a plaintext database connection")]
    PlaintextDatabase,
    #[error("runtime configuration contains an invalid package binding")]
    InvalidPackage,
    #[error("the configured package root is missing or is not a readable directory")]
    PackageRootUnavailable,
    #[error("the configured package root path contains a symbolic link")]
    UnsafePackageRoot,
    #[error("runtime configuration contains an invalid OIDC binding")]
    InvalidOidc,
    #[error("the OIDC leeway must be a whole number of seconds from 0 to 300000 milliseconds")]
    InvalidOidcLeeway,
    #[error("runtime configuration contains an invalid audit binding")]
    InvalidAudit,
    #[error("runtime configuration contains an invalid cursor binding")]
    InvalidCursor,
    #[error("runtime configuration contains an invalid event destination binding")]
    InvalidEventDestination,
    #[error("runtime configuration contains an invalid attachment storage binding")]
    InvalidAttachmentStorage,
    #[error("runtime configuration contains an invalid attachment verification binding")]
    InvalidAttachmentVerification,
    #[error("runtime configuration contains an invalid field encryption binding")]
    InvalidFieldEncryption,
    #[error("runtime configuration contains invalid operational bounds")]
    InvalidBounds,
    #[error("runtime configuration contains invalid WASM execution budgets")]
    InvalidWasmExecution,
    #[error("runtime configuration secret resolution failed")]
    Secret,
}

impl RuntimeConfigError {
    /// The code of the refusal: the deciding reader diagnostic's code, or
    /// this runtime's code for a rule the reader cannot state.
    #[must_use]
    fn code(&self) -> &str {
        match self {
            Self::Reader(refusal) => &refusal.deciding_diagnostic().code,
            Self::InvalidBinding => "breg.runtime.invalid-binding",
            Self::InvalidInstanceId => "breg.runtime.invalid-instance-id",
            Self::EnvironmentIdentityConflict => "breg.runtime.environment-identity-conflict",
            Self::InvalidListener => "breg.runtime.invalid-listener",
            Self::InvalidMetricsListener => "breg.runtime.invalid-metrics-listener",
            Self::InvalidSecretProvider => "breg.runtime.invalid-secret-provider",
            Self::SecretProviderRootUnavailable => "breg.runtime.secret-provider-root-unavailable",
            Self::UnsafeSecretProviderRoot => "breg.runtime.unsafe-secret-provider-root",
            Self::InvalidDatabase => "breg.runtime.invalid-database",
            Self::PlaintextDatabase => "breg.runtime.plaintext-database",
            Self::InvalidPackage => "breg.runtime.invalid-package",
            Self::PackageRootUnavailable => "breg.runtime.package-root-unavailable",
            Self::UnsafePackageRoot => "breg.runtime.unsafe-package-root",
            Self::InvalidOidc => "breg.runtime.invalid-oidc",
            Self::InvalidOidcLeeway => "breg.runtime.invalid-oidc-leeway",
            Self::InvalidAudit => "breg.runtime.invalid-audit",
            Self::InvalidCursor => "breg.runtime.invalid-cursor",
            Self::InvalidEventDestination => "breg.runtime.invalid-event-destination",
            Self::InvalidAttachmentStorage => "breg.runtime.invalid-attachment-storage",
            Self::InvalidAttachmentVerification => "breg.runtime.invalid-attachment-verification",
            Self::InvalidFieldEncryption => "breg.runtime.invalid-field-encryption",
            Self::InvalidBounds => "breg.runtime.invalid-bounds",
            Self::InvalidWasmExecution => "breg.runtime.invalid-wasm-execution",
            Self::Secret => "breg.runtime.secret",
        }
    }

    /// The RFC 6901 pointer the refusal concerns; `""` for the whole file.
    #[must_use]
    fn path(&self) -> &str {
        match self {
            Self::Reader(refusal) => &refusal.deciding_diagnostic().path,
            Self::InvalidBinding | Self::Secret => "",
            Self::InvalidInstanceId => "/identity/instanceId",
            Self::EnvironmentIdentityConflict => "/identity/databaseInitializationEnvironment",
            Self::InvalidListener => "/listener",
            Self::InvalidMetricsListener => "/metricsListener",
            Self::InvalidSecretProvider => "/secretProviders",
            Self::SecretProviderRootUnavailable | Self::UnsafeSecretProviderRoot => {
                "/secretProviders/file/root"
            }
            Self::InvalidDatabase => "/database",
            Self::PlaintextDatabase => "/database/testOnlyPlaintext",
            Self::InvalidPackage => "/package",
            Self::PackageRootUnavailable | Self::UnsafePackageRoot => "/package/root",
            Self::InvalidOidc => "/authentication/oidc",
            Self::InvalidOidcLeeway => "/authentication/oidc/leewayMilliseconds",
            Self::InvalidAudit => "/audit",
            Self::InvalidCursor => "/cursor",
            Self::InvalidEventDestination => "/eventDestinations",
            Self::InvalidAttachmentStorage => "/attachmentStorage",
            Self::InvalidAttachmentVerification => "/attachmentVerification",
            Self::InvalidFieldEncryption => "/fieldEncryption",
            Self::InvalidBounds => "/operationalTimeouts",
            Self::InvalidWasmExecution => "/wasmExecution",
        }
    }

    /// The edit that fixes a refusal this runtime decides itself
    /// (CFG-DIAG-6). A reader refusal carries its own action in each
    /// diagnostic.
    fn suggested_action(&self) -> &'static str {
        match self {
            Self::Reader(_) => "",
            Self::InvalidBinding => {
                "Give every identity value as trimmed text without control characters, and declare in the runtime file, with a valid endpoint and credential, every task grant status source, Evidence provider, review authority, and review executor the package relies on."
            }
            Self::InvalidInstanceId => {
                "Set identity.instanceId to a lowercase letter followed by at most 63 lowercase letters, digits, `-`, or `_`."
            }
            Self::EnvironmentIdentityConflict => {
                "Set identity.environment and identity.databaseInitializationEnvironment to the environment the database was initialized in."
            }
            Self::InvalidListener => {
                "Set listener.bind to a numeric address and port, and listener.publicOrigin, when given, to an https origin (http only on loopback) with no query, fragment, or user information."
            }
            Self::InvalidMetricsListener => {
                "Set metricsListener.bind to a loopback or private numeric address with a named port, on a socket the Registry listener does not also bind."
            }
            Self::InvalidSecretProvider => {
                "Declare each secret provider once, with the file provider's root an absolute normal path."
            }
            Self::SecretProviderRootUnavailable => {
                "Create the file secret provider root as a readable directory, or point secretProviders.file.root at one."
            }
            Self::UnsafeSecretProviderRoot => {
                "Point secretProviders.file.root at a path with no symbolic link in it."
            }
            Self::InvalidDatabase => {
                "Name database.runtimeUrlRef, database.migrationUrlRef, and database.trustedRootCertificateRef (PEM root certificates), when given, by secret reference, give each SQL role a lowercase identifier, and use two references when the roles differ."
            }
            Self::PlaintextDatabase => {
                "Remove database.testOnlyPlaintext; a deployment reaches PostgreSQL over TLS."
            }
            Self::InvalidPackage => {
                "Set package.root to an absolute normal path and package.expectedDigest, when given, to the package's sha256 digest."
            }
            Self::PackageRootUnavailable => {
                "Create the package root as a readable directory, or point package.root at one."
            }
            Self::UnsafePackageRoot => "Point package.root at a path with no symbolic link in it.",
            Self::InvalidOidc => {
                "Correct authentication.oidc and authentication.authorityClaims: an https issuer (http only on loopback), bounded values with no whitespace, distinct list entries, and claim names that do not repeat."
            }
            Self::InvalidOidcLeeway => {
                "Set authentication.oidc.leewayMilliseconds to a multiple of 1000 no greater than 300000."
            }
            Self::InvalidAudit => {
                "Give the file audit destination an absolute path, and leave audit.path, audit.rotateBytes, and audit.retentionDays out for the stdout destination."
            }
            Self::InvalidCursor => "Name cursor.secretRef by secret reference.",
            Self::InvalidEventDestination => {
                "Correct the event destination bindings: an https origin, a path that starts with `/`, and secret references for keys and TLS material."
            }
            Self::InvalidAttachmentStorage => {
                "Correct attachmentStorage: name every credential by secret reference and give the S3 endpoint as an https URL."
            }
            Self::InvalidAttachmentVerification => {
                "Correct attachmentVerification: give the verifier as an https URL and name its authorization by secret reference."
            }
            Self::InvalidFieldEncryption => {
                "Correct fieldEncryption: name the data key by secret reference and give the transit endpoint as an https URL."
            }
            Self::InvalidBounds => {
                "Keep every timeout, retention, and pool member within the bounds the runtime schema states."
            }
            Self::InvalidWasmExecution => {
                "Set wasmExecution.backend to a supported backend and keep its module and guest memory ceilings within the bounds the runtime schema states."
            }
            Self::Secret => {
                "Make every secret reference resolve through the declared secret providers."
            }
        }
    }

    /// The refusal as diagnostics in the shared shape (CFG-DIAG-1): every
    /// diagnostic the reader reported, or one for a rule this runtime
    /// decides itself, naming `file` as its source when one is given.
    #[must_use]
    pub fn diagnostics(&self, file: Option<&Path>) -> Vec<Diagnostic> {
        if let Self::Reader(refusal) = self {
            return refusal.diagnostics().to_vec();
        }
        let mut diagnostic = Diagnostic::error(
            self.code(),
            self.path(),
            self.to_string(),
            self.suggested_action(),
        );
        diagnostic.source = file.map(|file| Source {
            file: file.display().to_string(),
            line: None,
            column: None,
        });
        vec![diagnostic]
    }

    /// The refusal in the shared human form (CFG-DIAG-2): every diagnostic,
    /// then the summary line.
    #[must_use]
    pub fn render_human(&self, file: Option<&Path>) -> String {
        let mut report = Report::new(self.diagnostics(file));
        report.set_files_checked(1);
        report.render_human()
    }
}

impl From<SecretError> for RuntimeConfigError {
    fn from(_error: SecretError) -> Self {
        Self::Secret
    }
}

pub type Result<T> = std::result::Result<T, RuntimeConfigError>;

/// The configured package's envelope refusal, as the active package loaders
/// report it. A `package.expectedDigest` pin that names another package keeps
/// both digests, which are package identities and not secrets; every other
/// envelope refusal stays value free, since it can name files in the package.
fn active_package_envelope_error(
    error: registry_platform_config::package::PackageError,
) -> PackageError {
    match error.kind() {
        registry_platform_config::package::PackageErrorKind::DigestMismatch(mismatch) => {
            PackageError::ExpectedDigestMismatch(mismatch.clone())
        }
        _ => PackageError::Envelope,
    }
}

pub fn load_runtime_config(path: &Path) -> Result<RuntimeConfig> {
    load_runtime_config_with_env(path, |name| std::env::var(name).ok())
}

pub fn load_runtime_config_with_env(
    path: &Path,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<RuntimeConfig> {
    let raw = runtime_config_loader()
        .load_with::<RawRuntimeConfig>(path, lookup)
        .map_err(|error| RuntimeConfigError::Reader(ReaderRefusal(error)))?
        .config;
    let config = RuntimeConfig::from_raw(raw)?;
    config.validate_loaded_paths()?;
    Ok(config)
}

pub fn parse_runtime_config(raw: &str) -> Result<RuntimeConfig> {
    parse_runtime_config_with_env(raw, |name| std::env::var(name).ok())
}

pub fn parse_runtime_config_with_env(
    raw: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<RuntimeConfig> {
    let raw = runtime_config_loader()
        .parse_str::<RawRuntimeConfig>(raw, lookup)
        .map_err(|error| RuntimeConfigError::Reader(ReaderRefusal(error)))?
        .config;
    RuntimeConfig::from_raw(raw)
}

/// What an offline check of one runtime file found (CFG-CHECK-1).
#[derive(Debug)]
pub struct RuntimeConfigCheck {
    /// Every finding, each naming the file as `path` was given to
    /// [`check_runtime_config`].
    pub diagnostics: Vec<Diagnostic>,
    /// The file could not be read at all, as opposed to read and refused.
    pub unavailable: bool,
}

/// Check the runtime file at the absolute `path` as `breg` reads it at
/// startup, with no package, database, network, or secret material
/// (CFG-CHECK-1).
///
/// With `substitute` set, `${NAME}` expressions are filled from the process
/// environment and every value is checked. Without it, each expression is
/// checked by syntax and position only, and a member that takes a URL, a URI,
/// or an absolute path is read as a placeholder of that form. The runtime's
/// own rules stop at their first refusal, as they do at startup; when that
/// refusal is about a block that holds an expression, it says nothing about
/// the file, and the check reports the warning
/// `platform.runtime-config.check-incomplete` there in its place. The package
/// root and the file secret provider root are not looked for: a runtime file
/// is checked before the deployment it describes exists.
///
/// With the `registry` the file will serve, the authentication block is also
/// held to the compiled access profiles, as startup holds it: a client the
/// registry names that `authentication.oidc.allowedClients` does not list, or
/// a principal claim the profiles do not use, is refused here.
#[must_use]
pub fn check_runtime_config(
    path: &Path,
    substitute: bool,
    registry: Option<&CompiledRegistry>,
) -> RuntimeConfigCheck {
    let mut check = runtime_config_loader().check_offline::<RawRuntimeConfig>(
        path,
        substitute,
        runtime_stand_in,
    );
    let mut diagnostics = std::mem::take(&mut check.diagnostics);
    if let Some(loaded) = check.loaded.take() {
        match RuntimeConfig::from_raw(loaded.config) {
            Err(error) => {
                for refusal in error.diagnostics(None) {
                    diagnostics.push(if check.defers_within(&refusal.path) {
                        // The rule read a stand-in, so its refusal says
                        // nothing about the file; the rules after it did
                        // not run, and the check says so.
                        let mut warning = check.error_at(
                            RUNTIME_CONFIG_KIND,
                            registry_platform_config::INCOMPLETE_CODE,
                            &refusal.path,
                            "The check does not fill an expression this block holds, and a rule about the block needs its value; the check stopped here, and the rules after it were not checked.",
                            "Check the file again with --environment, where the variable the expression names is set.",
                        );
                        warning.severity = Severity::Warning;
                        warning
                    } else {
                        check.error_at(
                            RUNTIME_CONFIG_KIND,
                            &refusal.code,
                            &refusal.path,
                            refusal.message,
                            refusal.suggested_action,
                        )
                    });
                }
            }
            Ok(config) => {
                for index in config.authentication().oidc().wildcard_spelled_clients() {
                    let mut warning = check.error_at(
                        RUNTIME_CONFIG_KIND,
                        "breg.access.wildcard-spelled-item",
                        &format!("/authentication/oidc/allowedClients/{index}"),
                        "The item is spelled like a wildcard but names one client: `*` and `unrestricted` match nothing else in this list.",
                        "List each client by its exact identifier, or write allowedClients: unrestricted to admit every client.",
                    );
                    warning.severity = Severity::Warning;
                    diagnostics.push(warning);
                }
                if let Some(registry) = registry {
                    if !check.defers_within("/authentication") {
                        if let Err(error) = config.authentication().check_against(registry) {
                            let (pointer, code) = authentication_refusal_site(error);
                            diagnostics.push(check.error_at(
                                RUNTIME_CONFIG_KIND,
                                code,
                                pointer,
                                error.to_string(),
                                "Correct the authentication block so it agrees with the project's access profiles.",
                            ));
                        }
                    }
                }
            }
        }
    }
    RuntimeConfigCheck {
        diagnostics,
        unavailable: check.unavailable,
    }
}

/// The member of the runtime file an authentication refusal is about, and its
/// diagnostic code.
fn authentication_refusal_site(error: AuthenticationConfigError) -> (&'static str, &'static str) {
    match error {
        AuthenticationConfigError::NamedClientNotListed => (
            "/authentication/oidc/allowedClients",
            "breg.runtime.clients-unlisted",
        ),
        AuthenticationConfigError::PrincipalClaimMismatch => (
            "/authentication/authorityClaims/principal",
            "breg.runtime.principal-claim-mismatch",
        ),
        _ => (
            "/authentication/authorityClaims",
            "breg.runtime.invalid-authority-claims",
        ),
    }
}

/// A value that satisfies the member at `pointer`, so a deferred expression
/// decides neither whether its neighbours decode nor whether the rules about
/// its block run. Every member that takes a URL, a URI, or an absolute path
/// has one; any other member takes the shared default.
fn runtime_stand_in(pointer: &str) -> &'static str {
    let segments: Vec<&str> = pointer.split('/').skip(1).collect();
    match segments.as_slice() {
        ["listener", "bind"] => "127.0.0.1:8080",
        ["metricsListener", "bind"] => "127.0.0.1:9100",
        ["listener", "publicOrigin"] => "https://registry.invalid",
        ["authentication", "oidc", "issuer"] => "https://issuer.invalid",
        ["authentication", "oidc", "jwksSource", "uri"] => "https://issuer.invalid/jwks",
        ["package", "root"] => "/",
        ["package", "expectedDigest"] => {
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
        ["audit", "path"]
        | ["fieldEncryption", "provider", "unixSocketPath"]
        | ["eventDestinations", _, "path"] => "/deferred",
        ["attachmentStorage" | "attachmentVerification", "endpoint"]
        | ["eventDestinations", _, "origin"]
        | ["evidenceProviders", _, "baseUrl"]
        | ["taskGrantStatus", _, "baseUrl" | "sourceIssuer"]
        | ["reviewAuthorities" | "reviewExecutors", _, "endpoint"]
        | ["reviewAuthorities" | "reviewExecutors", _, "privateKeyJwt", "tokenEndpoint" | "assertionAudience" | "resource"] => {
            "https://deferred.invalid/"
        }
        _ => registry_platform_config::DEFAULT_STAND_IN,
    }
}

/// The shared runtime configuration loader under BReg's envelope. BReg reads
/// the file through it: the loader holds the path, symbolic link, regular
/// file, and bounded read checks, and the shared reader decodes the typed
/// configuration, so every unknown key, its closest accepted key, and every
/// position reach the operator. The file is held to the shared 1 MiB bound
/// (CFG-YAML-6).
const fn runtime_config_loader() -> RuntimeConfigLoader {
    RuntimeConfigLoader::new(RuntimeEnvelope {
        api_version: RUNTIME_CONFIG_API_VERSION,
        kind: RUNTIME_CONFIG_KIND,
    })
    .removed_keys(REMOVED_KEYS)
    .retired_api_versions(RETIRED_RUNTIME_API_VERSIONS)
}

#[derive(Clone)]
pub struct RuntimeConfig {
    listener: ListenerConfig,
    identity: DeploymentIdentity,
    secret_providers: SecretProvidersConfig,
    database: DatabaseConfig,
    attachment_storage: crate::attachment_storage::AttachmentStorageConfig,
    attachment_verification: crate::attachment_verification::AttachmentVerificationConfig,
    field_encryption: crate::field_encryption::FieldEncryptionConfig,
    package: PackageConfig,
    authentication: AuthenticationConfig,
    task_grant_status: Vec<crate::task_grant::TaskGrantStatusConfig>,
    audit: AuditConfig,
    cursor: CursorConfig,
    event_destinations: EventDestinationConfigs,
    evidence_providers:
        std::collections::BTreeMap<String, crate::action_evidence_config::EvidenceProviderConfig>,
    review_authorities: BTreeMap<String, ReviewAuthorityConfig>,
    review_executors: BTreeMap<String, ReviewExecutorConfig>,
    event_delivery: EventDeliveryConfig,
    idempotency: IdempotencyConfig,
    operational_timeouts: OperationalTimeouts,
    wasm_execution: WasmExecutionConfig,
    metrics_listener: Option<MetricsListenerConfig>,
}

impl RuntimeConfig {
    fn from_raw(raw: RawRuntimeConfig) -> Result<Self> {
        let listener = ListenerConfig::from_raw(raw.listener)?;
        let identity = DeploymentIdentity::from_raw(raw.identity)?;
        let secret_providers = SecretProvidersConfig::from_raw(raw.secret_providers)?;
        let database = DatabaseConfig::from_raw(raw.database)?;
        let attachment_storage =
            crate::attachment_storage::AttachmentStorageConfig::from_raw(raw.attachment_storage)
                .map_err(|_| RuntimeConfigError::InvalidAttachmentStorage)?;
        let attachment_verification =
            crate::attachment_verification::AttachmentVerificationConfig::from_raw(
                raw.attachment_verification,
            )
            .map_err(|_| RuntimeConfigError::InvalidAttachmentVerification)?;
        let field_encryption =
            crate::field_encryption::FieldEncryptionConfig::from_raw(raw.field_encryption)
                .map_err(|_| RuntimeConfigError::InvalidFieldEncryption)?;
        let package = PackageConfig::from_raw(raw.package)?;
        let authentication = AuthenticationConfig::from_raw(raw.authentication)?;
        let audit = AuditConfig::from_raw(raw.audit)?;
        let cursor = CursorConfig::from_raw(raw.cursor)?;
        let event_destinations = EventDestinationConfigs::from_raw(raw.event_destinations)
            .map_err(|_| RuntimeConfigError::InvalidEventDestination)?;
        let event_delivery = EventDeliveryConfig::from_raw(raw.event_delivery)?;
        let idempotency = IdempotencyConfig::from_raw(raw.idempotency)?;
        let review_authorities = raw
            .review_authorities
            .into_iter()
            .map(|(id, authority)| {
                ReviewAuthorityConfig::from_raw(&id, authority).map(|authority| (id, authority))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let review_executors = raw
            .review_executors
            .into_iter()
            .map(|(id, executor)| {
                ReviewExecutorConfig::from_raw(&id, executor).map(|executor| (id, executor))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let operational_timeouts = OperationalTimeouts::from_raw(raw.operational_timeouts)?;
        let wasm_execution = WasmExecutionConfig::from_raw(raw.wasm_execution)?;
        let metrics_listener = raw
            .metrics_listener
            .map(MetricsListenerConfig::from_raw)
            .transpose()?;
        if let Some(metrics) = &metrics_listener {
            metrics.validate_separate_binding(&listener)?;
        }
        Ok(Self {
            listener,
            identity,
            secret_providers,
            database,
            attachment_storage,
            attachment_verification,
            field_encryption,
            package,
            authentication,
            task_grant_status: raw.task_grant_status,
            audit,
            cursor,
            event_destinations,
            evidence_providers: raw.evidence_providers,
            review_authorities,
            review_executors,
            event_delivery,
            idempotency,
            operational_timeouts,
            wasm_execution,
            metrics_listener,
        })
    }

    pub fn activate_task_status(
        &self,
        compiled: &CompiledRegistry,
    ) -> Result<Arc<crate::task_grant::TaskGrantStatusRegistry>> {
        let status = crate::task_grant::TaskGrantStatusRegistry::activate(
            &self.task_grant_status,
            &self.authentication.oidc.audience,
            &self.secret_resolver()?,
        )
        .map_err(|_| RuntimeConfigError::InvalidBinding)?;
        for profile in compiled
            .entities()
            .values()
            .flat_map(|entity| entity.access_profiles.values())
        {
            if let Some(grant) = &profile.task_grant {
                if !status.contains(&grant.source_issuer) {
                    return Err(RuntimeConfigError::InvalidBinding);
                }
            }
        }
        Ok(Arc::new(status))
    }

    pub fn activate_evidence(
        &self,
        compiled: &CompiledRegistry,
    ) -> Result<Option<Arc<crate::action_evidence::ActionEvidenceEvaluator>>> {
        crate::action_evidence_config::activate(
            compiled,
            &self.evidence_providers,
            &self.secret_resolver()?,
        )
    }

    fn review_token_provider(
        &self,
        token_ref: Option<&SecretReference>,
        private_key_jwt: Option<&ReviewPrivateKeyJwtConfig>,
    ) -> Result<Arc<dyn registry_platform_httputil::TokenProvider>> {
        let resolver = self.secret_resolver()?;
        Ok(if let Some(token_ref) = token_ref {
            let token = resolver.resolve_reference(token_ref)?;
            let token = std::str::from_utf8(token.expose_secret())
                .map_err(|_| RuntimeConfigError::Secret)?;
            Arc::new(
                registry_platform_httputil::StaticToken::new(token.to_owned())
                    .map_err(|_| RuntimeConfigError::Secret)?,
            )
        } else {
            let oauth = private_key_jwt.ok_or(RuntimeConfigError::InvalidBinding)?;
            let client_id = resolver.resolve_reference(&oauth.client_id_ref)?;
            let client_id = std::str::from_utf8(client_id.expose_secret())
                .map_err(|_| RuntimeConfigError::Secret)?;
            let key = resolver.resolve_reference(&oauth.client_assertion_key_ref)?;
            let key =
                std::str::from_utf8(key.expose_secret()).map_err(|_| RuntimeConfigError::Secret)?;
            let key = registry_platform_crypto::PrivateJwk::parse(key)
                .map_err(|_| RuntimeConfigError::InvalidBinding)?;
            let mut provider = registry_platform_httputil::PrivateKeyJwtConfig::new(
                oauth.token_endpoint.clone(),
                client_id.to_owned(),
                key,
            )
            .with_audience(oauth.assertion_audience.clone())
            .with_resource(oauth.resource.clone())
            .with_scopes(oauth.scopes.clone())
            .with_request_timeout(self.operational_timeouts.http_request)
            .with_connect_timeout(self.operational_timeouts.http_request);
            if let Some(reference) = &oauth.ca_bundle_ref {
                let ca = resolver.resolve_reference(reference)?;
                provider = provider.with_trusted_root_certificates(ca.expose_secret().to_vec());
            }
            Arc::new(
                registry_platform_httputil::PrivateKeyJwt::new(provider)
                    .map_err(|_| RuntimeConfigError::InvalidBinding)?,
            )
        })
    }

    pub fn activate_review_authorities(
        &self,
        compiled: &CompiledRegistry,
    ) -> Result<Option<Arc<crate::review_store::ReviewAuthorityRegistry>>> {
        let required = compiled
            .entities()
            .values()
            .filter_map(|entity| entity.change_request.as_ref())
            .filter_map(|request| match &request.review {
                crate::model::CompiledChangeRequestReview::Required(requirement) => {
                    Some(requirement.authority.as_str())
                }
                crate::model::CompiledChangeRequestReview::None => None,
            })
            .collect::<BTreeSet<_>>();
        if required.is_empty() && self.review_authorities.is_empty() {
            return Ok(None);
        }
        if required
            .iter()
            .any(|authority| !self.review_authorities.contains_key(*authority))
        {
            return Err(RuntimeConfigError::InvalidBinding);
        }
        let resolver = self.secret_resolver()?;
        let mut activated = BTreeMap::new();
        // Activate retained operator bindings as well as bindings referenced by
        // the new package. Durable submissions created by the previous package
        // must keep their worker after a review policy is changed or removed.
        for (authority, config) in &self.review_authorities {
            let token_provider = self.review_token_provider(
                config.token_ref.as_ref(),
                config.private_key_jwt.as_ref(),
            )?;
            let completion = config
                .completion
                .as_ref()
                .map(
                    |(token_ref, recipient)| -> Result<(Zeroizing<String>, String)> {
                        let token = resolver.resolve_reference(token_ref)?;
                        let token = std::str::from_utf8(token.expose_secret())
                            .map_err(|_| RuntimeConfigError::Secret)?;
                        Ok((Zeroizing::new(token.to_owned()), recipient.clone()))
                    },
                )
                .transpose()?;
            let client = registry_review_client::ReviewClient::new(
                registry_review_client::ReviewClientConfig::new(config.endpoint.clone())
                    .with_request_timeout(self.operational_timeouts.http_request)
                    .with_connect_timeout(self.operational_timeouts.http_request),
            )
            .map_err(|_| RuntimeConfigError::InvalidBinding)?;
            let authority_client = crate::review_store::ReviewAuthorityClient::new(
                authority.clone(),
                client,
                token_provider,
                config.profile.clone(),
                config.producer_id.clone(),
                config.recovery_days,
                completion.as_ref().map(|(token, _)| token.clone()),
                completion.map(|(_, recipient)| recipient),
            )
            .map_err(|_| RuntimeConfigError::InvalidBinding)?;
            activated.insert(authority.clone(), Arc::new(authority_client));
        }
        crate::review_store::ReviewAuthorityRegistry::new(activated)
            .map(Arc::new)
            .map(Some)
            .map_err(|_| RuntimeConfigError::InvalidBinding)
    }

    pub fn activate_review_executors(
        &self,
        compiled: &CompiledRegistry,
    ) -> Result<Option<Arc<crate::review_store::ReviewExecutorRegistry>>> {
        let required = compiled
            .entities()
            .values()
            .filter_map(|entity| entity.change_request.as_ref())
            .filter(|request| {
                matches!(
                    request.review,
                    crate::model::CompiledChangeRequestReview::Required(_)
                ) && request.on_approved.mode
                    == crate::model::CompiledChangeRequestOnApprovedMode::Automatic
            })
            .filter_map(|request| request.on_approved.executor.as_deref())
            .collect::<BTreeSet<_>>();
        if required.is_empty() && self.review_executors.is_empty() {
            return Ok(None);
        }
        if required
            .iter()
            .any(|executor| !self.review_executors.contains_key(*executor))
        {
            return Err(RuntimeConfigError::InvalidBinding);
        }
        for entity in compiled.entities().values() {
            let Some(request) = entity.change_request.as_ref() else {
                continue;
            };
            if !matches!(
                request.review,
                crate::model::CompiledChangeRequestReview::Required(_)
            ) || request.on_approved.mode
                != crate::model::CompiledChangeRequestOnApprovedMode::Automatic
            {
                continue;
            }
            let executor = request
                .on_approved
                .executor
                .as_deref()
                .ok_or(RuntimeConfigError::InvalidBinding)?;
            let config = self
                .review_executors
                .get(executor)
                .ok_or(RuntimeConfigError::InvalidBinding)?;
            if entity
                .access_profiles
                .get(&config.access_profile)
                .is_none_or(|profile| {
                    !profile
                        .operations
                        .contains(&crate::contract::Operation::ApplyRequest)
                })
            {
                return Err(RuntimeConfigError::InvalidBinding);
            }
        }
        let mut activated = BTreeMap::new();
        // An executor can remain necessary for an application job accepted
        // under the previous package even when the new package no longer
        // selects it. Activate every retained binding and derive the routes it
        // is still authorized to call from the new package.
        for (executor, config) in &self.review_executors {
            if config.registry_id != compiled.registry_id() {
                return Err(RuntimeConfigError::InvalidBinding);
            }
            let request_entities = compiled
                .entities()
                .values()
                .filter(|entity| {
                    entity.change_request.is_some()
                        && entity
                            .access_profiles
                            .get(&config.access_profile)
                            .is_some_and(|profile| {
                                profile
                                    .operations
                                    .contains(&crate::contract::Operation::ApplyRequest)
                            })
                })
                .collect::<Vec<_>>();
            if request_entities.is_empty()
                || request_entities.iter().any(|entity| {
                    entity
                        .access_profiles
                        .get(&config.access_profile)
                        .is_none_or(|profile| {
                            !profile
                                .operations
                                .contains(&crate::contract::Operation::ApplyRequest)
                        })
                })
            {
                return Err(RuntimeConfigError::InvalidBinding);
            }
            let request_routes = request_entities
                .into_iter()
                .map(|entity| (entity.id.clone(), entity.route.clone()))
                .collect::<BTreeMap<_, _>>();
            let token_provider = self.review_token_provider(
                config.token_ref.as_ref(),
                config.private_key_jwt.as_ref(),
            )?;
            let executor_client = crate::review_store::ReviewExecutorClient::new(
                executor.to_owned(),
                config.endpoint.clone(),
                token_provider,
                config.registry_id.clone(),
                config.access_profile.clone(),
                request_routes,
                self.operational_timeouts.http_request,
            )
            .map_err(|_| RuntimeConfigError::InvalidBinding)?;
            activated.insert(executor.clone(), Arc::new(executor_client));
        }
        crate::review_store::ReviewExecutorRegistry::new(activated)
            .map(Arc::new)
            .map(Some)
            .map_err(|_| RuntimeConfigError::InvalidBinding)
    }

    /// Resolve the selected content backend before accepting attachment requests.
    pub async fn activate_attachment_storage(
        &self,
        registry_id: &str,
    ) -> std::result::Result<
        crate::attachment_storage::AttachmentStorage,
        crate::attachment_storage::AttachmentStorageError,
    > {
        let resolver = self
            .secret_resolver()
            .map_err(|_| crate::attachment_storage::AttachmentStorageError::Secret)?;
        // Separate databases may activate the same portable Registry package.
        // They must never share a last-reference deletion namespace.
        let scope = serde_json::to_string(&(self.identity.database_id(), registry_id))
            .map_err(|_| crate::attachment_storage::AttachmentStorageError::InvalidConfiguration)?;
        self.attachment_storage.activate(&scope, &resolver).await
    }

    /// Activate the external verification transport without submitting content.
    pub fn activate_attachment_verification(
        &self,
    ) -> std::result::Result<
        crate::attachment_verification::AttachmentVerification,
        crate::attachment_verification::AttachmentVerificationError,
    > {
        let resolver = self
            .secret_resolver()
            .map_err(|_| crate::attachment_verification::AttachmentVerificationError::Secret)?;
        self.attachment_verification.activate(&resolver)
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

    /// Verify the shared package envelope and optional package digest pin
    /// before any product-specific closure or derivation work.
    pub fn verify_package_envelope(
        &self,
    ) -> std::result::Result<
        registry_platform_config::package::VerifiedPackage,
        registry_platform_config::package::PackageError,
    > {
        self.package
            .shared
            .verify_package(&crate::package::shared_package_limits(), "bregctl package")
            .map_err(|error| error.naming_root_as("package.root"))
    }

    /// Verify the configured package pin and consume that same shared
    /// envelope through BReg's closure and derivation checks.
    pub fn load_active_package(&self) -> std::result::Result<VerifiedPackage, PackageError> {
        let shared = self
            .verify_package_envelope()
            .map_err(active_package_envelope_error)?;
        load_package_with_verified_envelope(
            self.package().root(),
            &self.package_load_context(),
            &shared,
        )
    }

    /// Verify and retain the configured shared package while loading the
    /// database-active predecessor representation used for successor planning.
    pub fn load_active_predecessor_package(
        &self,
    ) -> std::result::Result<VerifiedPredecessorPackage, PackageError> {
        let shared = self
            .verify_package_envelope()
            .map_err(active_package_envelope_error)?;
        load_predecessor_package_with_verified_envelope(
            self.package().root(),
            &self.package_load_context(),
            &shared,
        )
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

    pub fn idempotency(&self) -> &IdempotencyConfig {
        &self.idempotency
    }

    /// The idempotency policy every write path of this runtime spends keys
    /// under: caller keys are scoped under the configured OIDC issuer, the
    /// only issuer whose tokens this runtime verifies.
    pub fn idempotency_policy(&self) -> Result<crate::idempotency::IdempotencyPolicy> {
        crate::idempotency::IdempotencyPolicy::new(
            self.authentication.oidc.issuer(),
            self.idempotency.receipt_retention_days(),
        )
        .map_err(|_| RuntimeConfigError::InvalidBounds)
    }

    /// The field-encryption binding, defaulting to no provider.
    pub fn field_encryption(&self) -> &crate::field_encryption::FieldEncryptionConfig {
        &self.field_encryption
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

    pub fn wasm_execution(&self) -> &WasmExecutionConfig {
        &self.wasm_execution
    }

    /// The operator-private metrics listener binding, when one is configured.
    pub fn metrics_listener(&self) -> Option<&MetricsListenerConfig> {
        self.metrics_listener.as_ref()
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
        #[cfg(feature = "postgres-test")]
        if self.database.test_only_plaintext {
            return ConnectionConfig::from_test_config(postgres, self.database.pool_bounds)
                .map_err(|_| RuntimeConfigError::InvalidDatabase);
        }
        let connection = match &self.database.trusted_root_certificate_ref {
            Some(roots_ref) => {
                let roots = self.secret_resolver()?.resolve_reference(roots_ref)?;
                ConnectionConfig::require_tls_config_with_roots_pem(
                    postgres,
                    roots.expose_secret(),
                    self.database.pool_bounds,
                )
            }
            None => ConnectionConfig::require_tls_config(postgres, self.database.pool_bounds),
        };
        connection.map_err(|_| RuntimeConfigError::InvalidDatabase)
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

    /// How strictly this deployment loads a package: file-mode strictness
    /// follows the database initialization environment.
    pub fn package_load_context(&self) -> PackageLoadContext<'_> {
        PackageLoadContext {
            database_initialization_environment: self
                .identity
                .database_initialization_environment
                .as_str(),
        }
    }

    fn validate_loaded_paths(&self) -> Result<()> {
        validate_existing_directory(
            self.package.root(),
            RuntimeConfigError::UnsafePackageRoot,
            RuntimeConfigError::PackageRootUnavailable,
        )?;
        if let Some(root) = self.secret_providers.file_root() {
            validate_existing_directory(
                root,
                RuntimeConfigError::UnsafeSecretProviderRoot,
                RuntimeConfigError::SecretProviderRootUnavailable,
            )?;
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
            .field("attachment_storage", &self.attachment_storage)
            .field("attachment_verification", &self.attachment_verification)
            .field("field_encryption", &self.field_encryption)
            .field("package", &self.package)
            .field("authentication", &self.authentication)
            .field("audit", &self.audit)
            .field("cursor", &self.cursor)
            .field("event_destinations", &self.event_destinations)
            .field("event_delivery", &self.event_delivery)
            .field("idempotency", &self.idempotency)
            .field("operational_timeouts", &self.operational_timeouts)
            .field("wasm_execution", &self.wasm_execution)
            .field("metrics_listener", &self.metrics_listener)
            .finish()
    }
}

#[derive(Clone)]
pub struct ListenerConfig {
    bind: SocketAddr,
    public_origin: Option<PublicOrigin>,
}

impl ListenerConfig {
    fn from_raw(raw: RawRegistryListener) -> Result<Self> {
        let bind = raw.listener.bind.socket_addr();
        Ok(Self {
            bind,
            public_origin: raw
                .public_origin
                .as_deref()
                .map(PublicOrigin::parse)
                .transpose()?,
        })
    }

    pub fn bind(&self) -> SocketAddr {
        self.bind
    }

    pub fn public_origin(&self) -> Option<&PublicOrigin> {
        self.public_origin.as_ref()
    }
}

impl fmt::Debug for ListenerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListenerConfig")
            .field("bind", &"<redacted>")
            .field("public_origin", &self.public_origin)
            .finish()
    }
}

/// Operator-only metrics listener binding.
///
/// It is a separate binding rather than a route on the Registry listener so
/// that reaching the counters requires reaching a different socket. Only
/// loopback or private addresses on a named port are accepted: the counters
/// are operator material and the public Registry contract never describes
/// them.
#[derive(Clone, Eq, PartialEq)]
pub struct MetricsListenerConfig {
    bind: SocketAddr,
}

impl MetricsListenerConfig {
    fn from_raw(raw: RawMetricsListenerConfig) -> Result<Self> {
        let bind = raw.bind.socket_addr();
        if bind.port() == 0 {
            return Err(RuntimeConfigError::InvalidMetricsListener);
        }
        let address = bind.ip();
        let private = match address {
            IpAddr::V4(address) => address.is_loopback() || address.is_private(),
            IpAddr::V6(address) => address.is_loopback() || is_unique_local_ipv6(address),
        };
        if !private || address.is_unspecified() || address.is_multicast() {
            return Err(RuntimeConfigError::InvalidMetricsListener);
        }
        Ok(Self { bind })
    }

    /// Sharing the Registry binding would publish the counters on the
    /// listener the public contract describes, which is the separation this
    /// binding exists to enforce.
    fn validate_separate_binding(&self, listener: &ListenerConfig) -> Result<()> {
        let metrics_address = self.bind.ip();
        let listener_address = listener.bind().ip();
        // Linux commonly creates an IPv6 wildcard socket as dual-stack, so
        // `[::]:port` can also occupy the corresponding IPv4 port.
        // Configuration validation must be portable across the hosts on
        // which the process can run, so treat the IPv6 wildcard as covering
        // both families; the IPv4 wildcard covers only IPv4.
        let wildcard_covers_metrics = match listener_address {
            IpAddr::V4(address) => address.is_unspecified() && metrics_address.is_ipv4(),
            IpAddr::V6(address) => address.is_unspecified(),
        };
        if (metrics_address == listener_address || wildcard_covers_metrics)
            && self.bind.port() == listener.bind().port()
        {
            return Err(RuntimeConfigError::InvalidMetricsListener);
        }
        Ok(())
    }

    #[must_use]
    pub fn bind(&self) -> SocketAddr {
        self.bind
    }
}

impl fmt::Debug for MetricsListenerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MetricsListenerConfig")
            .field("bind", &"<redacted>")
            .finish()
    }
}

/// RFC 4193 unique-local IPv6 address check for the metrics listener binding.
fn is_unique_local_ipv6(address: std::net::Ipv6Addr) -> bool {
    (address.segments()[0] & 0xfe00) == 0xfc00
}

/// Operator-configured public base URL for authenticated absolute discovery
/// and paging links. It never derives authority from request Host or forwarded
/// headers.
#[derive(Clone, Eq, PartialEq)]
pub struct PublicOrigin {
    value: String,
    deployment_prefix: String,
}

impl PublicOrigin {
    pub fn parse(value: &str) -> Result<Self> {
        if value.len() > MAX_PUBLIC_ORIGIN_BYTES || value.contains(['?', '#', '@']) {
            return Err(RuntimeConfigError::InvalidListener);
        }
        let uri: axum::http::Uri = value
            .parse()
            .map_err(|_| RuntimeConfigError::InvalidListener)?;
        let authority = uri.authority().ok_or(RuntimeConfigError::InvalidListener)?;
        let host = authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']');
        let loopback = host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback());
        let scheme_allowed = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => loopback,
            _ => false,
        };
        let path = uri.path();
        let deployment_prefix = path.strip_suffix('/').unwrap_or(path);
        let valid_deployment_prefix = deployment_prefix.is_empty()
            || deployment_prefix.starts_with('/')
                && deployment_prefix.split('/').skip(1).all(|segment| {
                    !segment.is_empty()
                        && segment != "."
                        && segment != ".."
                        && segment.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric()
                                || matches!(byte, b'-' | b'.' | b'_' | b'~')
                        })
                });
        if authority.host().is_empty()
            || (authority.as_str() != authority.host() && authority.port_u16().is_none())
            || authority.port_u16() == Some(0)
            || !valid_deployment_prefix
            || uri.query().is_some()
            || !scheme_allowed
        {
            return Err(RuntimeConfigError::InvalidListener);
        }
        Ok(Self {
            value: format!(
                "{}://{}{}",
                uri.scheme_str().unwrap(),
                authority,
                deployment_prefix
            ),
            deployment_prefix: deployment_prefix.to_owned(),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn deployment_prefix(&self) -> &str {
        &self.deployment_prefix
    }
}

impl fmt::Debug for PublicOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublicOrigin(<redacted>)")
    }
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
        // The instance id is the event source URN's instance term, whose
        // envelope budget holds only inside this closed grammar.
        if !crate::package::valid_build_id(&raw.instance_id) {
            return Err(RuntimeConfigError::InvalidInstanceId);
        }
        validate_deployment_value(&raw.database_id)?;
        validate_deployment_value(&raw.database_initialization_environment)?;
        // Package loading keys its permission strictness on the
        // initialization environment, so a deployment that names another
        // environment would load its package under the wrong strictness.
        if raw.environment != raw.database_initialization_environment {
            return Err(RuntimeConfigError::EnvironmentIdentityConflict);
        }
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

/// The shared secret-provider block, checked once at load. Its `Debug` keeps
/// the file root out of logs.
#[derive(Clone)]
pub struct SecretProvidersConfig {
    block: registry_platform_config::SecretProvidersConfig,
}

impl SecretProvidersConfig {
    fn from_raw(raw: registry_platform_config::SecretProvidersConfig) -> Result<Self> {
        raw.check()
            .map_err(|_| RuntimeConfigError::InvalidSecretProvider)?;
        if let Some(file) = &raw.file {
            validate_absolute_lexical_path(&file.root, RuntimeConfigError::InvalidSecretProvider)?;
        }
        Ok(Self { block: raw })
    }

    fn resolver(&self) -> Result<SecretResolver> {
        self.block.resolver().map_err(Into::into)
    }

    fn file_root(&self) -> Option<&Path> {
        self.block.file.as_ref().map(|file| file.root.as_path())
    }
}

impl fmt::Debug for SecretProvidersConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretProvidersConfig")
            .field("environment", &self.block.environment.is_some())
            .field("file", &self.block.file.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[derive(Clone)]
pub struct DatabaseConfig {
    runtime_url_ref: SecretReference,
    migration_url_ref: SecretReference,
    trusted_root_certificate_ref: Option<SecretReference>,
    #[cfg(feature = "postgres-test")]
    test_only_plaintext: bool,
    pool_bounds: PoolBounds,
    roles: SqlRoles,
}

impl DatabaseConfig {
    fn from_raw(raw: RawRegistryDatabase) -> Result<Self> {
        #[cfg(not(feature = "postgres-test"))]
        if raw.database.test_only_plaintext {
            return Err(RuntimeConfigError::PlaintextDatabase);
        }
        let runtime_url_ref = parse_secret_reference(
            raw.database.runtime_url_ref,
            RuntimeConfigError::InvalidDatabase,
        )?;
        let migration_url_ref = parse_secret_reference(
            raw.database.migration_url_ref,
            RuntimeConfigError::InvalidDatabase,
        )?;
        let trusted_root_certificate_ref = raw
            .database
            .trusted_root_certificate_ref
            .map(|reference| parse_secret_reference(reference, RuntimeConfigError::InvalidDatabase))
            .transpose()?;
        let roles = SqlRoles::from_raw(raw.roles)?;
        // One database reference logs in as one role, so two references are
        // required only when the runtime and migration roles differ.
        if runtime_url_ref == migration_url_ref && roles.migration != roles.runtime {
            return Err(RuntimeConfigError::InvalidDatabase);
        }
        let pool_bounds = PoolBounds::new(
            raw.pool.maximum_connections,
            Duration::from_millis(raw.pool.wait_timeout_milliseconds),
            Duration::from_millis(raw.pool.create_timeout_milliseconds),
            Duration::from_millis(raw.pool.recycle_timeout_milliseconds),
        )
        .map_err(|_| RuntimeConfigError::InvalidBounds)?;
        Ok(Self {
            runtime_url_ref,
            migration_url_ref,
            trusted_root_certificate_ref,
            #[cfg(feature = "postgres-test")]
            test_only_plaintext: raw.database.test_only_plaintext,
            pool_bounds,
            roles,
        })
    }

    pub fn pool_bounds(&self) -> PoolBounds {
        self.pool_bounds
    }

    /// The secret reference to the PEM root certificates the database
    /// connections trust, when the platform roots are not used.
    pub fn trusted_root_certificate_ref(&self) -> Option<&SecretReference> {
        self.trusted_root_certificate_ref.as_ref()
    }
}

impl fmt::Debug for DatabaseConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseConfig")
            .field("runtime_url_ref", &"<redacted>")
            .field("migration_url_ref", &"<redacted>")
            .field(
                "trusted_root_certificate_ref",
                &self
                    .trusted_root_certificate_ref
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field("pool_bounds", &self.pool_bounds)
            .finish()
    }
}

#[derive(Clone)]
pub struct PackageConfig {
    shared: SharedPackageConfig,
}

impl PackageConfig {
    fn from_raw(raw: RawPackageConfig) -> Result<Self> {
        raw.shared
            .check()
            .map_err(|_| RuntimeConfigError::InvalidPackage)?;
        Ok(Self { shared: raw.shared })
    }

    pub fn root(&self) -> &Path {
        &self.shared.root
    }

    pub fn shared(&self) -> &SharedPackageConfig {
        &self.shared
    }
}

impl fmt::Debug for PackageConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackageConfig")
            .field("shared", &"<redacted>")
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

    /// Hold this block to the compiled access profiles, as startup does.
    pub fn check_against(
        &self,
        registry: &CompiledRegistry,
    ) -> std::result::Result<(), AuthenticationConfigError> {
        crate::auth::check_claim_mapping(
            registry,
            &self.oidc.token_verifier_config(),
            &self.authority_claim_config(),
        )
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
    assertion_issuers: BTreeMap<String, Vec<String>>,
    max_token_lifetime: Duration,
    leeway: Duration,
    jwks_cache: JwksCacheConfig,
    jwks_source: OidcJwksSource,
}

impl OidcVerifierConfig {
    /// The one token issuer this runtime verifies.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    fn from_raw(raw: RawOidcVerifierConfig) -> Result<Self> {
        validate_oidc_value(&raw.provider.issuer)?;
        validate_oidc_value(&raw.provider.audience)?;
        // A loopback `http` issuer or key URI stays accepted for the local
        // development and test deployments that run their issuer beside the
        // registry; every other issuer and key URI is `https`.
        raw.provider
            .check("authentication.oidc", true)
            .map_err(|_| RuntimeConfigError::InvalidOidc)?;
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
        // Duplicate assertion-issuer client keys are already refused before this
        // point: the shared reader refuses any duplicate YAML mapping key
        // anywhere in the document, including here.
        let assertion_issuers = raw.assertion_issuers;
        let assertion_issuer_clients = assertion_issuers.keys().cloned().collect::<Vec<_>>();
        validate_bounded_list(&assertion_issuer_clients)?;
        for issuers in assertion_issuers.values() {
            validate_bounded_list(issuers)?;
            let issuer_unique = issuers.iter().collect::<HashSet<_>>();
            if issuer_unique.len() != issuers.len() {
                return Err(RuntimeConfigError::InvalidOidc);
            }
        }
        let max_token_lifetime = Duration::from_secs(raw.maximum_token_lifetime_seconds);
        let leeway = oidc_leeway(raw.leeway_milliseconds)?;
        let jwks_source = OidcJwksSource::from_block(raw.provider.jwks_source)?;
        Ok(Self {
            issuer: raw.provider.issuer.into_string(),
            audience: raw.provider.audience,
            allowed_algorithm: raw.allowed_algorithm,
            access_token_type: raw.access_token_type,
            scope_claim: raw.scope_claim,
            scope_separator: raw.scope_separator,
            allowed_clients: raw.allowed_clients,
            denied_kids: raw.denied_kids,
            assertion_issuers,
            max_token_lifetime,
            leeway,
            jwks_cache: JwksCacheConfig::from_raw(raw.jwks_cache)?,
            jwks_source,
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

    /// Whether the file leaves `allowedClients` unrestricted, so a token from
    /// any client is accepted.
    #[must_use]
    pub fn admits_every_client(&self) -> bool {
        self.allowed_clients.is_empty()
    }

    /// The positions of listed clients spelled like a wildcard, which name one
    /// client each.
    fn wildcard_spelled_clients(&self) -> impl Iterator<Item = usize> + '_ {
        self.allowed_clients
            .iter()
            .enumerate()
            .filter(|(_, client)| matches!(client.as_str(), "*" | "unrestricted"))
            .map(|(index, _)| index)
    }

    pub fn token_verifier_config(&self) -> TokenVerifierConfig {
        TokenVerifierConfig::access_token_profile(
            self.issuer.clone(),
            vec![self.audience.clone()],
            vec![self.allowed_algorithm.as_jsonwebtoken()],
            access_token_typ_set(&self.access_token_type),
        )
        .with_scope_claim(self.scope_claim.clone())
        .with_scope_separator(self.scope_separator)
        .with_allowed_clients(self.allowed_clients.clone())
        .with_denied_kids(self.denied_kids.iter().cloned().collect())
        .with_assertion_issuers(self.assertion_issuers.clone())
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
            OidcJwksSource::Uri { uri } => Ok(Arc::new(JwksFetcher::new(
                uri.clone(),
                self.jwks_fetcher_config(),
            ))),
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
            .field(
                "assertion_issuers_client_count",
                &self.assertion_issuers.len(),
            )
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
    Uri { uri: String },
    Static { document_ref: SecretReference },
}

impl OidcJwksSource {
    fn from_block(block: JwksSource) -> Result<Self> {
        match block {
            JwksSource::Discovery {} => Ok(Self::Discovery),
            JwksSource::Uri { uri } => Ok(Self::Uri {
                uri: uri.into_string(),
            }),
            JwksSource::Static { document_ref } => Ok(Self::Static {
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
            Self::Uri { .. } => OidcJwksSourceKind::Uri,
            Self::Static { .. } => OidcJwksSourceKind::Static,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum OidcJwksSourceKind {
    Discovery,
    Uri,
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
        Ok(Self {
            cache_ttl: Duration::from_secs(raw.cache_ttl_seconds),
            negative_cache_ttl: Duration::from_secs(raw.negative_cache_ttl_seconds),
            refresh_cooldown: Duration::from_secs(raw.refresh_cooldown_seconds),
            max_document_bytes: raw.maximum_document_bytes,
            request_timeout: Duration::from_millis(raw.attempt_timeout_milliseconds),
            outage_tolerance: Duration::from_secs(raw.outage_tolerance_seconds),
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
    contextual: ClaimNames,
    trusted_actors: BTreeMap<String, String>,
}

impl AuthorityClaimsConfig {
    fn from_raw(raw: RawAuthorityClaimsConfig) -> Result<Self> {
        if raw.principal != "sub" {
            validate_authority_claim_name(&raw.principal)?;
        }
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
        let contextual = ClaimNames::from(raw.contextual);
        contextual
            .validate()
            .map_err(|_| RuntimeConfigError::InvalidOidc)?;
        if raw.trusted_actors.len() > MAX_LIST_ITEMS
            || raw.trusted_actors.iter().any(|(client, actor)| {
                client.is_empty()
                    || client.len() > MAX_LIST_VALUE_BYTES
                    || actor.is_empty()
                    || actor.len() > MAX_LIST_VALUE_BYTES
                    || client.chars().any(char::is_whitespace)
                    || actor.chars().any(char::is_whitespace)
            })
        {
            return Err(RuntimeConfigError::InvalidOidc);
        }
        Ok(Self {
            principal: raw.principal,
            purpose: raw.purpose,
            contextual,
            trusted_actors: raw.trusted_actors,
        })
    }

    fn to_platform_config(&self) -> AuthorityClaimConfig {
        AuthorityClaimConfig::new(self.principal.clone(), self.purpose.clone())
            .with_contextual_claims(self.contextual.clone(), self.trusted_actors.clone())
    }
}

impl fmt::Debug for AuthorityClaimsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityClaimsConfig")
            .field("principal", &"<redacted>")
            .field("purpose", &self.purpose.as_ref().map(|_| "<redacted>"))
            .field("contextual", &self.contextual)
            .field("trusted_actor_clients", &self.trusted_actors.keys())
            .finish()
    }
}

#[derive(Clone)]
pub struct AuditConfig {
    hash_key_ref: SecretReference,
    destination: AuditDestination,
}

impl AuditConfig {
    fn from_raw(raw: RawAuditConfig) -> Result<Self> {
        let hash_key_ref = raw.key.hash_key_ref;
        let destination = AuditDestination::from_settings(
            raw.destination,
            raw.path.map(PathBuf::from),
            raw.rotate_bytes,
            raw.retention_days,
        )
        .map_err(|_| RuntimeConfigError::InvalidAudit)?;
        Ok(Self {
            hash_key_ref,
            destination,
        })
    }

    /// Where the service writes its audit entries. Operator tooling that runs
    /// beside the service writes to the sibling destination
    /// `destination().for_process("bregctl")`, so the two never share a
    /// writer lock.
    #[must_use]
    pub fn destination(&self) -> &AuditDestination {
        &self.destination
    }
}

impl fmt::Debug for AuditConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditConfig")
            .field("hash_key_ref", &"<redacted>")
            .field("destination", &self.destination)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdempotencyConfig {
    receipt_retention_days: u16,
}

impl IdempotencyConfig {
    fn from_raw(raw: RawIdempotencyConfig) -> Result<Self> {
        Ok(Self {
            receipt_retention_days: raw.receipt_retention_days,
        })
    }

    /// How many days a held response is kept after its commit.
    #[must_use]
    pub fn receipt_retention_days(&self) -> u16 {
        self.receipt_retention_days
    }
}

impl CursorConfig {
    fn from_raw(raw: RawCursorConfig) -> Result<Self> {
        Ok(Self {
            secret_ref: raw.secret_ref,
            max_age: Duration::from_secs(raw.maximum_age_seconds),
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
            http_request: Duration::from_millis(raw.http_request_milliseconds),
            shutdown_grace: Duration::from_millis(raw.shutdown_grace_milliseconds),
            record_lock: Duration::from_millis(raw.record_lock_milliseconds),
            migration_lock: Duration::from_millis(raw.migration_lock_milliseconds),
            migration_statement: Duration::from_millis(raw.migration_statement_milliseconds),
        })
    }
}

/// Operator budgets and backend for process WASM handler execution. Parsed
/// and validated in every build so the runtime configuration contract is
/// independent of the server's compiled features; builds without the
/// `wasm` feature keep refusing WASM handlers at evaluation admission
/// whatever these values say.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WasmExecutionConfig {
    max_module_bytes: u64,
    max_guest_memory_bytes: u64,
    backend: crate::wasm_handler::WasmExecutionBackend,
}

impl WasmExecutionConfig {
    pub(crate) fn from_raw(raw: RawWasmExecutionConfig) -> Result<Self> {
        let backend = crate::wasm_handler::WasmExecutionBackend::parse(&raw.backend)
            .ok_or(RuntimeConfigError::InvalidWasmExecution)?;
        Ok(Self {
            max_module_bytes: raw.maximum_module_bytes,
            max_guest_memory_bytes: raw.maximum_guest_memory_bytes,
            backend,
        })
    }

    /// Byte ceiling for one handler module at execution time.
    pub fn max_module_bytes(&self) -> u64 {
        self.max_module_bytes
    }

    /// Byte ceiling for guest memory growth during one call.
    pub fn max_guest_memory_bytes(&self) -> u64 {
        self.max_guest_memory_bytes
    }

    /// The backend handler modules are compiled and executed for.
    pub fn backend(&self) -> crate::wasm_handler::WasmExecutionBackend {
        self.backend
    }
}

#[derive(Clone)]
pub struct SqlRoles {
    migration: SqlIdentifier,
    runtime: SqlIdentifier,
}

impl SqlRoles {
    fn from_raw(raw: RawSqlRoles) -> Result<Self> {
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

#[derive(Clone)]
struct ReviewAuthorityConfig {
    endpoint: reqwest::Url,
    profile: String,
    token_ref: Option<SecretReference>,
    private_key_jwt: Option<ReviewPrivateKeyJwtConfig>,
    producer_id: String,
    recovery_days: u32,
    completion: Option<(SecretReference, String)>,
}

impl ReviewAuthorityConfig {
    fn from_raw(id: &str, raw: RawReviewAuthorityConfig) -> Result<Self> {
        if id.trim().is_empty() || id.len() > 128 || id.chars().any(char::is_control) {
            return Err(RuntimeConfigError::InvalidBinding);
        }
        let endpoint =
            reqwest::Url::parse(&raw.endpoint).map_err(|_| RuntimeConfigError::InvalidBinding)?;
        // The review client performs the complete credential-destination
        // validation during activation. Refuse URL suffixes here as well so a
        // typo never survives configuration parsing.
        if !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(RuntimeConfigError::InvalidBinding);
        }
        let completion = match (raw.completion_token_ref, raw.completion_recipient) {
            (None, None) => None,
            (Some(token_ref), Some(recipient))
                if crate::review_store::valid_completion_recipient(&recipient) =>
            {
                Some((token_ref, recipient))
            }
            _ => return Err(RuntimeConfigError::InvalidBinding),
        };
        let token_ref = raw.token_ref;
        let private_key_jwt = raw
            .private_key_jwt
            .map(ReviewPrivateKeyJwtConfig::from_raw)
            .transpose()?;
        if token_ref.is_some() == private_key_jwt.is_some()
            || raw.profile.trim().is_empty()
            || raw.profile.len() > 128
            || !raw.profile.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
            || raw.producer_id.trim().is_empty()
            || raw.producer_id.len() > 128
            || raw.producer_id.chars().any(char::is_control)
        {
            return Err(RuntimeConfigError::InvalidBinding);
        }
        Ok(Self {
            endpoint,
            profile: raw.profile,
            token_ref,
            private_key_jwt,
            producer_id: raw.producer_id,
            recovery_days: raw.recovery_days,
            completion,
        })
    }
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawReviewAuthorityConfig {
    endpoint: String,
    profile: String,
    /// A static bearer token for the review service. Exactly one of
    /// `tokenRef` and `privateKeyJwt` is written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token_ref: Option<SecretReference>,
    /// A refreshing client-assertion credential for the review service.
    /// Exactly one of `tokenRef` and `privateKeyJwt` is written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    private_key_jwt: Option<RawReviewPrivateKeyJwtConfig>,
    producer_id: String,
    #[serde(
        deserialize_with = "crate::contract::bounded_u32::<_, 1, { crate::review_store::MAXIMUM_REVIEW_RECOVERY_DAYS }>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BoundedU32<1, { crate::review_store::MAXIMUM_REVIEW_RECOVERY_DAYS }>")
    )]
    recovery_days: u32,
    /// The bearer token the review authority presents when it notifies this
    /// registry that a review completed. Written together with
    /// `completionRecipient`; omitted, no completion notification is
    /// accepted and the registry polls for results.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completion_token_ref: Option<SecretReference>,
    /// The logical recipient the review authority names in each completion
    /// notification. Written together with `completionTokenRef`; omitted, no
    /// completion notification is accepted and the registry polls for
    /// results.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completion_recipient: Option<String>,
}

#[derive(Clone)]
struct ReviewPrivateKeyJwtConfig {
    token_endpoint: reqwest::Url,
    client_id_ref: SecretReference,
    client_assertion_key_ref: SecretReference,
    assertion_audience: String,
    resource: String,
    scopes: Vec<String>,
    ca_bundle_ref: Option<SecretReference>,
}

impl ReviewPrivateKeyJwtConfig {
    fn from_raw(raw: RawReviewPrivateKeyJwtConfig) -> Result<Self> {
        let token_endpoint = raw
            .token_endpoint
            .parse()
            .map_err(|_| RuntimeConfigError::InvalidBinding)?;
        if !registry_platform_httputil::valid_resource_uri(&raw.assertion_audience)
            || !registry_platform_httputil::valid_resource_uri(&raw.resource)
            || raw.scopes.is_empty()
            || raw.scopes.len() > registry_platform_httputil::MAXIMUM_REQUESTED_SCOPES
            || raw.scopes.iter().collect::<BTreeSet<_>>().len() != raw.scopes.len()
            || raw.scopes.join(" ").len()
                > registry_platform_httputil::MAXIMUM_SCOPE_PARAMETER_BYTES
            || raw.scopes.iter().any(|scope| {
                scope.len() > registry_platform_httputil::MAXIMUM_REQUESTED_SCOPE_BYTES
                    || !registry_platform_httputil::valid_scope_token(scope)
            })
        {
            return Err(RuntimeConfigError::InvalidBinding);
        }
        Ok(Self {
            token_endpoint,
            client_id_ref: raw.client_id_ref,
            client_assertion_key_ref: raw.client_assertion_key_ref,
            assertion_audience: raw.assertion_audience,
            resource: raw.resource,
            scopes: raw.scopes,
            ca_bundle_ref: raw.ca_bundle_ref,
        })
    }
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawReviewPrivateKeyJwtConfig {
    token_endpoint: String,
    client_id_ref: SecretReference,
    client_assertion_key_ref: SecretReference,
    assertion_audience: String,
    resource: String,
    scopes: Vec<String>,
    /// A PEM bundle of the roots that sign the token endpoint's certificate.
    /// Omitted, the platform's trusted roots verify it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ca_bundle_ref: Option<SecretReference>,
}

#[derive(Clone)]
struct ReviewExecutorConfig {
    endpoint: reqwest::Url,
    token_ref: Option<SecretReference>,
    private_key_jwt: Option<ReviewPrivateKeyJwtConfig>,
    registry_id: String,
    access_profile: String,
}

impl ReviewExecutorConfig {
    fn from_raw(id: &str, raw: RawReviewExecutorConfig) -> Result<Self> {
        if id.trim().is_empty()
            || id.len() > 128
            || id.chars().any(char::is_control)
            || raw.registry_id.trim().is_empty()
            || raw.registry_id.len() > 128
            || raw.registry_id.chars().any(char::is_control)
            || raw.access_profile.trim().is_empty()
            || raw.access_profile.len() > 128
            || raw.access_profile.chars().any(char::is_control)
        {
            return Err(RuntimeConfigError::InvalidBinding);
        }
        let endpoint =
            reqwest::Url::parse(&raw.endpoint).map_err(|_| RuntimeConfigError::InvalidBinding)?;
        registry_platform_httputil::client::ServiceBaseUrl::new(endpoint.clone())
            .map_err(|_| RuntimeConfigError::InvalidBinding)?;
        let token_ref = raw.token_ref;
        let private_key_jwt = raw
            .private_key_jwt
            .map(ReviewPrivateKeyJwtConfig::from_raw)
            .transpose()?;
        if token_ref.is_some() == private_key_jwt.is_some() {
            return Err(RuntimeConfigError::InvalidBinding);
        }
        Ok(Self {
            endpoint,
            token_ref,
            private_key_jwt,
            registry_id: raw.registry_id,
            access_profile: raw.access_profile,
        })
    }
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawReviewExecutorConfig {
    endpoint: String,
    /// A static bearer token for the executing registry. Exactly one of
    /// `tokenRef` and `privateKeyJwt` is written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token_ref: Option<SecretReference>,
    /// A refreshing client-assertion credential for the executing registry.
    /// Exactly one of `tokenRef` and `privateKeyJwt` is written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    private_key_jwt: Option<RawReviewPrivateKeyJwtConfig>,
    registry_id: String,
    access_profile: String,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawRuntimeConfig {
    /// The reader checks the envelope before it decodes; the members are
    /// declared only so the generated schema describes them.
    #[cfg(feature = "schema")]
    api_version: String,
    #[cfg(feature = "schema")]
    kind: String,
    listener: RawRegistryListener,
    identity: RawDeploymentIdentity,
    secret_providers: registry_platform_config::SecretProvidersConfig,
    database: RawRegistryDatabase,
    /// Defaults to PostgreSQL; S3 requires a bucket with versioning never enabled.
    #[serde(default)]
    attachment_storage: crate::attachment_storage::RawAttachmentStorageConfig,
    /// Optional external verdict hook. Disabled by default.
    #[serde(default)]
    attachment_verification: crate::attachment_verification::RawAttachmentVerificationConfig,
    /// Optional field-encryption data-key provider. Absent by default, which
    /// serves unencrypted entities only.
    #[serde(default)]
    field_encryption: crate::field_encryption::RawFieldEncryptionConfig,
    package: RawPackageConfig,
    authentication: RawAuthenticationConfig,
    #[serde(default)]
    task_grant_status: Vec<crate::task_grant::TaskGrantStatusConfig>,
    audit: RawAuditConfig,
    cursor: RawCursorConfig,
    #[serde(default, deserialize_with = "local_id_map")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            schema_with = "local_id_map_schema::<crate::event_destination::RawEventDestinationConfig>"
        )
    )]
    event_destinations: RawEventDestinationConfigs,
    #[serde(default, deserialize_with = "local_id_map")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            schema_with = "local_id_map_schema::<crate::action_evidence_config::EvidenceProviderConfig>"
        )
    )]
    evidence_providers:
        std::collections::BTreeMap<String, crate::action_evidence_config::EvidenceProviderConfig>,
    #[serde(default, deserialize_with = "local_id_map")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "local_id_map_schema::<RawReviewAuthorityConfig>")
    )]
    review_authorities: BTreeMap<String, RawReviewAuthorityConfig>,
    #[serde(default, deserialize_with = "local_id_map")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "local_id_map_schema::<RawReviewExecutorConfig>")
    )]
    review_executors: BTreeMap<String, RawReviewExecutorConfig>,
    /// Optional event-delivery tuning. Defaults to the server's bounded retention policy.
    #[serde(default)]
    event_delivery: RawEventDeliveryConfig,
    /// Optional idempotency tuning. Defaults to a seven-day receipt horizon.
    #[serde(default)]
    idempotency: RawIdempotencyConfig,
    /// Optional operational request, shutdown, locking, and migration timeout tuning.
    #[serde(default)]
    operational_timeouts: RawOperationalTimeouts,
    /// Optional WASM handler execution budgets. Parsed in every build;
    /// executed only in builds with the `wasm` cargo feature, on by default.
    #[serde(default)]
    wasm_execution: RawWasmExecutionConfig,
    /// Optional operator-private metrics listener. Absent by default, which
    /// serves no metrics surface at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metrics_listener: Option<RawMetricsListenerConfig>,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// The registry's listener: the shared listener block and an optional public
/// origin.
struct RawRegistryListener {
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/listener"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    listener: registry_platform_config::ListenerConfig,
    /// Canonical public origin for QGIS discovery and pagination links, with
    /// an optional deployment path prefix such as
    /// `https://registry.example.org/breg`. It is `https`; `http` is accepted
    /// only for a loopback host, for local development. Required when the
    /// registry exposes GIS collections; omitted, the registry builds no
    /// absolute discovery or paging links.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_origin: Option<Url>,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawMetricsListenerConfig {
    /// Operator-private loopback or private numeric address and named port,
    /// for example `127.0.0.1:9100`.
    bind: ListenerBind,
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
/// The registry's database: the shared database block and the connection
/// pool and SQL roles the registry adds.
struct RawRegistryDatabase {
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/database"))]
    #[cfg_attr(feature = "schema", schemars(flatten), serde(skip_serializing))]
    database: registry_platform_config::DatabaseConfig,
    pool: RawPoolBounds,
    roles: RawSqlRoles,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawPoolBounds {
    #[serde(deserialize_with = "crate::contract::bounded_usize::<_, 1, MAX_DATABASE_POOL_SIZE>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BoundedU32<1, MAX_DATABASE_POOL_SIZE>")
    )]
    maximum_connections: usize,
    /// Defaults to the bounded PostgreSQL pool wait timeout.
    #[serde(default = "default_pool_wait_timeout_milliseconds")]
    #[serde(
        deserialize_with = "crate::contract::bounded_u64::<_, 1, MAX_POOL_TIMEOUT_MILLISECONDS>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BoundedU64<1, MAX_POOL_TIMEOUT_MILLISECONDS>")
    )]
    wait_timeout_milliseconds: u64,
    /// Defaults to the bounded PostgreSQL pool connection-creation timeout.
    #[serde(default = "default_pool_create_timeout_milliseconds")]
    #[serde(
        deserialize_with = "crate::contract::bounded_u64::<_, 1, MAX_POOL_TIMEOUT_MILLISECONDS>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BoundedU64<1, MAX_POOL_TIMEOUT_MILLISECONDS>")
    )]
    create_timeout_milliseconds: u64,
    /// Defaults to the bounded PostgreSQL pool connection-recycle timeout.
    #[serde(default = "default_pool_recycle_timeout_milliseconds")]
    #[serde(
        deserialize_with = "crate::contract::bounded_u64::<_, 1, MAX_POOL_TIMEOUT_MILLISECONDS>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BoundedU64<1, MAX_POOL_TIMEOUT_MILLISECONDS>")
    )]
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
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/package"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    shared: SharedPackageConfig,
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
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-issuer"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    provider: OidcIssuerConfig,
    allowed_algorithm: OidcAlgorithm,
    /// The one admitted access-token `typ` semantics. Configuring the
    /// RFC 9068 access-token media type as `at+jwt` or
    /// `application/at+jwt` admits both spellings of that one type; any
    /// other value (for example `JWT`) admits only that token type, matched
    /// case-insensitively.
    access_token_type: String,
    scope_claim: String,
    scope_separator: char,
    /// The OAuth clients whose tokens this registry accepts: `unrestricted`
    /// to accept a token from every client, or a list of at least one
    /// client.
    #[serde(deserialize_with = "crate::contract::sentinel::allowed_clients")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "crate::contract::sentinel::AllowedClients")
    )]
    allowed_clients: Vec<String>,
    /// The signing key identifiers this registry refuses a token from.
    /// Omitted, no key is denied; written, it names at least one key.
    #[serde(default, deserialize_with = "non_empty_denied_kids")]
    denied_kids: Vec<String>,
    /// The assertion authorities each client may exchange a subject token
    /// from, keyed by client identifier. Omitted, no assertion-issuer rule
    /// applies; written, it lists at least one client, each with at least one
    /// authority, and a client not listed may exchange from no authority.
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "non_empty_assertion_issuers"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "external_id_map_schema::<Vec<String>>")
    )]
    assertion_issuers: BTreeMap<String, Vec<String>>,
    #[serde(deserialize_with = "crate::contract::bounded_u64::<_, 1, 7_200>")]
    #[cfg_attr(feature = "schema", schemars(with = "BoundedU64<1, 7_200>"))]
    maximum_token_lifetime_seconds: u64,
    #[serde(
        deserialize_with = "crate::contract::bounded_u64::<_, 0, MAX_OIDC_LEEWAY_MILLISECONDS>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BoundedU64<0, MAX_OIDC_LEEWAY_MILLISECONDS>")
    )]
    leeway_milliseconds: u64,
    /// Optional JWKS fetch and cache tuning. Defaults to bounded cache behavior.
    #[serde(default)]
    jwks_cache: RawJwksCacheConfig,
}

/// An empty list is not how the file says "deny no key" (CFG-EMPTY-2):
/// omitting the member says it.
fn non_empty_denied_kids<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<String>, D::Error> {
    let kids = Vec::<String>::deserialize(deserializer)?;
    if kids.is_empty() {
        return Err(registry_platform_yaml::Invalid::expected(
            "at least one key identifier",
            "List at least one key identifier to deny, or delete deniedKids to deny no key.",
        )
        .into_error());
    }
    Ok(kids)
}

/// An empty mapping is not how the file says "no assertion-issuer rule"
/// (CFG-EMPTY-2): omitting the member says it.
fn non_empty_assertion_issuers<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, Vec<String>>, D::Error> {
    let issuers = external_id_map::<_, ListedIssuers>(deserializer)?;
    if issuers.is_empty() {
        return Err(registry_platform_yaml::Invalid::expected(
            "at least one client",
            "List at least one client with its assertion issuers, or omit assertionIssuers to apply no assertion-issuer rule.",
        ).into_error());
    }
    Ok(issuers
        .into_iter()
        .map(|(client, issuers)| (client, issuers.0))
        .collect())
}

/// The authorities one listed client may exchange from. An empty list is not
/// how the file says "this client may exchange from no authority"
/// (CFG-EMPTY-2): leaving the client out says it.
struct ListedIssuers(Vec<String>);

impl<'de> Deserialize<'de> for ListedIssuers {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let issuers = Vec::<String>::deserialize(deserializer)?;
        if issuers.is_empty() {
            return Err(registry_platform_yaml::Invalid::expected(
                "at least one assertion issuer",
                "List at least one assertion issuer for this client, or remove the client: a client that is not listed may exchange from no authority.",
            )
            .into_error());
        }
        Ok(Self(issuers))
    }
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawJwksCacheConfig {
    /// Defaults to the bounded JWKS cache time-to-live.
    #[serde(default = "default_jwks_cache_ttl_seconds")]
    #[serde(deserialize_with = "crate::contract::bounded_u64::<_, 1, 86_400>")]
    #[cfg_attr(feature = "schema", schemars(with = "BoundedU64<1, 86_400>"))]
    cache_ttl_seconds: u64,
    /// Defaults to the bounded JWKS negative-cache time-to-live.
    #[serde(default = "default_jwks_negative_cache_ttl_seconds")]
    #[serde(deserialize_with = "crate::contract::bounded_u64::<_, 1, 3_600>")]
    #[cfg_attr(feature = "schema", schemars(with = "BoundedU64<1, 3_600>"))]
    negative_cache_ttl_seconds: u64,
    /// Defaults to the bounded JWKS refresh cooldown.
    #[serde(default = "default_jwks_refresh_cooldown_seconds")]
    #[serde(deserialize_with = "crate::contract::bounded_u64::<_, 1, 3_600>")]
    #[cfg_attr(feature = "schema", schemars(with = "BoundedU64<1, 3_600>"))]
    refresh_cooldown_seconds: u64,
    /// Defaults to the bounded maximum JWKS document size.
    #[serde(default = "default_jwks_max_document_bytes")]
    #[serde(deserialize_with = "crate::contract::bounded_u64::<_, 1, MAX_JWKS_DOCUMENT_BYTES>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BoundedU64<1, MAX_JWKS_DOCUMENT_BYTES>")
    )]
    maximum_document_bytes: u64,
    /// Defaults to the bounded JWKS fetch timeout.
    #[serde(default = "default_jwks_request_timeout_milliseconds")]
    #[serde(deserialize_with = "crate::contract::bounded_u64::<_, 1, 30_000>")]
    #[cfg_attr(feature = "schema", schemars(with = "BoundedU64<1, 30_000>"))]
    attempt_timeout_milliseconds: u64,
    /// Defaults to the bounded cached-key outage tolerance.
    #[serde(default = "default_jwks_outage_tolerance_seconds")]
    #[serde(deserialize_with = "crate::contract::bounded_u64::<_, 0, 86_400>")]
    #[cfg_attr(feature = "schema", schemars(with = "BoundedU64<0, 86_400>"))]
    outage_tolerance_seconds: u64,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawAuthorityClaimsConfig {
    principal: String,
    #[serde(default)]
    purpose: Option<String>,
    /// The claim names that carry delegated-authority context. Each name
    /// defaults to its `registry_` claim; written, every name is given.
    #[serde(default)]
    contextual: RawContextualClaimNames,
    #[serde(default, deserialize_with = "external_id_map")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "external_id_map_schema::<String>")
    )]
    trusted_actors: BTreeMap<String, String>,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawContextualClaimNames {
    actor_kind: ClaimName,
    purpose: ClaimName,
    grant_id: ClaimName,
    grant_source_issuer: ClaimName,
    grant_client: ClaimName,
    grant_resource: ClaimName,
    grant_exp: ClaimName,
    grant_bounds: ClaimName,
    approver: ClaimName,
}

/// The name of one top-level claim of an access token. The reader accepts any
/// text; the runtime then refuses a name that is not a valid claim name, one
/// that repeats another contextual name, and one that is a registered or
/// authentication claim.
#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(transparent)]
struct ClaimName(String);

impl Default for RawContextualClaimNames {
    fn default() -> Self {
        let names = ClaimNames::default();
        Self {
            actor_kind: ClaimName(names.actor_kind),
            purpose: ClaimName(names.purpose),
            grant_id: ClaimName(names.grant_id),
            grant_source_issuer: ClaimName(names.grant_source_issuer),
            grant_client: ClaimName(names.grant_client),
            grant_resource: ClaimName(names.grant_resource),
            grant_exp: ClaimName(names.grant_exp),
            grant_bounds: ClaimName(names.grant_bounds),
            approver: ClaimName(names.approver),
        }
    }
}

impl From<RawContextualClaimNames> for ClaimNames {
    fn from(value: RawContextualClaimNames) -> Self {
        Self {
            actor_kind: value.actor_kind.0,
            purpose: value.purpose.0,
            grant_id: value.grant_id.0,
            grant_source_issuer: value.grant_source_issuer.0,
            grant_client: value.grant_client.0,
            grant_resource: value.grant_resource.0,
            grant_exp: value.grant_exp.0,
            grant_bounds: value.grant_bounds.0,
            approver: value.approver.0,
        }
    }
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawAuditConfig {
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/audit-key"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    key: AuditKeyConfig,
    /// `file` (the default) writes a durable, rotated JSON Lines file at
    /// `path`; `stdout` writes one JSON line per entry to standard output.
    #[serde(default)]
    destination: AuditDestinationKind,
    /// Absolute path of the active audit file. Required for, and accepted
    /// only with, the `file` destination; omitted with `stdout`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    /// Size in bytes at which the active file rotates, accepted only with the
    /// `file` destination. Omitted, the file rotates at 100 MiB.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::contract::optional_bounded_u64::<_, { registry_platform_audit::MIN_AUDIT_ROTATE_BYTES }, { u32::MAX as u64 }>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "BoundedU64<{ registry_platform_audit::MIN_AUDIT_ROTATE_BYTES }, { u32::MAX as u64 }>"
        )
    )]
    rotate_bytes: Option<u64>,
    /// Days a rotated file is retained, accepted only with the `file`
    /// destination. Omitted, a rotated file is retained for 90 days.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::contract::optional_bounded_u32::<_, 1, { registry_platform_audit::MAX_AUDIT_RETAIN_DAYS }>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BoundedU32<1, { registry_platform_audit::MAX_AUDIT_RETAIN_DAYS }>")
    )]
    retention_days: Option<u32>,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawCursorConfig {
    secret_ref: SecretReference,
    /// Defaults to the bounded cursor validity lifetime.
    #[serde(default = "default_cursor_max_age_seconds")]
    #[serde(deserialize_with = "crate::contract::bounded_u64::<_, 1, 86_400>")]
    #[cfg_attr(feature = "schema", schemars(with = "BoundedU64<1, 86_400>"))]
    maximum_age_seconds: u64,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawEventDeliveryConfig {
    /// Defaults to the bounded retained payload lifetime for pending or dead-letter webhook work.
    #[serde(default = "default_webhook_payload_retention_days")]
    #[serde(
        deserialize_with = "crate::contract::bounded_u8::<_, 1, { MAX_WEBHOOK_PAYLOAD_RETENTION_DAYS as u32 }>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BoundedU32<1, { MAX_WEBHOOK_PAYLOAD_RETENTION_DAYS as u32 }>")
    )]
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
struct RawIdempotencyConfig {
    /// Days a held response is kept after its commit. A retry after it is
    /// refused as expired and never executed; the key stays spent.
    #[serde(default = "default_receipt_retention_days")]
    #[serde(
        deserialize_with = "crate::contract::bounded_u16::<_, 1, { crate::idempotency::MAX_RECEIPT_RETENTION_DAYS as u32 }>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "BoundedU32<1, { crate::idempotency::MAX_RECEIPT_RETENTION_DAYS as u32 }>"
        )
    )]
    receipt_retention_days: u16,
}

impl Default for RawIdempotencyConfig {
    fn default() -> Self {
        Self {
            receipt_retention_days: default_receipt_retention_days(),
        }
    }
}

const fn default_receipt_retention_days() -> u16 {
    crate::idempotency::DEFAULT_RECEIPT_RETENTION_DAYS
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawOperationalTimeouts {
    /// Defaults to the bounded per-request HTTP timeout.
    #[serde(default = "default_http_request_timeout_milliseconds")]
    #[serde(
        deserialize_with = "crate::contract::bounded_u64::<_, 1, MAX_HTTP_REQUEST_TIMEOUT_MILLISECONDS>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BoundedU64<1, MAX_HTTP_REQUEST_TIMEOUT_MILLISECONDS>")
    )]
    http_request_milliseconds: u64,
    /// Defaults to the bounded graceful-shutdown timeout.
    #[serde(default = "default_shutdown_grace_milliseconds")]
    #[serde(deserialize_with = "crate::contract::bounded_u64::<_, 1, 300_000>")]
    #[cfg_attr(feature = "schema", schemars(with = "BoundedU64<1, 300_000>"))]
    shutdown_grace_milliseconds: u64,
    /// Defaults to the bounded record lock timeout.
    #[serde(default = "default_record_lock_milliseconds")]
    #[serde(deserialize_with = "crate::contract::bounded_u64::<_, 1, 30_000>")]
    #[cfg_attr(feature = "schema", schemars(with = "BoundedU64<1, 30_000>"))]
    record_lock_milliseconds: u64,
    /// Defaults to the bounded migration lock timeout.
    #[serde(default = "default_migration_lock_milliseconds")]
    #[serde(deserialize_with = "crate::contract::bounded_u64::<_, 1, 300_000>")]
    #[cfg_attr(feature = "schema", schemars(with = "BoundedU64<1, 300_000>"))]
    migration_lock_milliseconds: u64,
    /// Defaults to the bounded migration statement timeout.
    #[serde(default = "default_migration_statement_milliseconds")]
    #[serde(deserialize_with = "crate::contract::bounded_u64::<_, 1, 3_600_000>")]
    #[cfg_attr(feature = "schema", schemars(with = "BoundedU64<1, 3_600_000>"))]
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

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RawWasmExecutionConfig {
    /// Defaults to the default execution-time module ceiling (2 MiB); the
    /// structural admission ceiling (5 MiB) is operator-reachable here.
    #[serde(default = "default_wasm_execution_max_module_bytes")]
    #[serde(
        deserialize_with = "crate::contract::bounded_u64::<_, MINIMUM_WASM_EXECUTION_MODULE_BYTES, MAXIMUM_WASM_EXECUTION_MODULE_BYTES>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "BoundedU64<MINIMUM_WASM_EXECUTION_MODULE_BYTES, MAXIMUM_WASM_EXECUTION_MODULE_BYTES>"
        )
    )]
    maximum_module_bytes: u64,
    /// Defaults to the platform guest-memory ceiling (32 MiB).
    #[serde(default = "default_wasm_execution_max_guest_memory_bytes")]
    #[serde(
        deserialize_with = "crate::contract::bounded_u64::<_, MINIMUM_WASM_EXECUTION_GUEST_MEMORY_BYTES, MAXIMUM_WASM_EXECUTION_GUEST_MEMORY_BYTES>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "BoundedU64<MINIMUM_WASM_EXECUTION_GUEST_MEMORY_BYTES, MAXIMUM_WASM_EXECUTION_GUEST_MEMORY_BYTES>"
        )
    )]
    maximum_guest_memory_bytes: u64,
    /// The backend handler modules are compiled and executed for: `pulley`
    /// (default, the portable interpreter target) or `native`. Any other
    /// value is refused as an invalid `wasmExecution` section.
    #[serde(default = "default_wasm_execution_backend")]
    backend: String,
}

impl Default for RawWasmExecutionConfig {
    fn default() -> Self {
        Self {
            maximum_module_bytes: default_wasm_execution_max_module_bytes(),
            maximum_guest_memory_bytes: default_wasm_execution_max_guest_memory_bytes(),
            backend: default_wasm_execution_backend(),
        }
    }
}

impl Default for RawJwksCacheConfig {
    fn default() -> Self {
        Self {
            cache_ttl_seconds: default_jwks_cache_ttl_seconds(),
            negative_cache_ttl_seconds: default_jwks_negative_cache_ttl_seconds(),
            refresh_cooldown_seconds: default_jwks_refresh_cooldown_seconds(),
            maximum_document_bytes: default_jwks_max_document_bytes(),
            attempt_timeout_milliseconds: default_jwks_request_timeout_milliseconds(),
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

const fn default_wasm_execution_max_module_bytes() -> u64 {
    DEFAULT_WASM_EXECUTION_MODULE_BYTES
}

const fn default_wasm_execution_max_guest_memory_bytes() -> u64 {
    DEFAULT_WASM_EXECUTION_GUEST_MEMORY_BYTES
}

fn default_wasm_execution_backend() -> String {
    crate::wasm_handler::WasmExecutionBackend::default()
        .as_str()
        .to_owned()
}

#[cfg(feature = "schema")]
pub fn runtime_config_schema() -> std::result::Result<Value, serde_json::Error> {
    let mut schema = serde_json::to_value(schemars::schema_for!(RawRuntimeConfig))?;
    install_schema_const_property(&mut schema, "apiVersion", RUNTIME_CONFIG_API_VERSION);
    install_schema_const_property(&mut schema, "kind", RUNTIME_CONFIG_KIND);
    install_schema_constraints(&mut schema);
    if let Some(provider) = schema
        .pointer_mut("/$defs/EvidenceProviderConfig")
        .and_then(Value::as_object_mut)
    {
        provider.insert(
            "oneOf".to_owned(),
            serde_json::json!([
                {"required": ["tokenRef"]},
                {"required": ["privateKeyJwt"]}
            ]),
        );
    }
    for pointer in [
        "/properties/eventDestinations",
        "/$defs/RawAuthorityClaimsConfig/properties/purpose",
        "/$defs/RawEventDestinationConfig/properties/tls",
        "/$defs/RawOidcVerifierConfig/properties/deniedKids",
        "/$defs/RawOidcVerifierConfig/properties/jwksSource",
        "/$defs/RawOidcVerifierConfig/properties/assertionIssuers",
    ] {
        remove_schema_default(&mut schema, pointer);
    }
    Ok(schema)
}

#[cfg(feature = "schema")]
fn install_schema_constraints(schema: &mut Value) {
    // `AuditDestination::from_settings`: the `stdout` destination refuses
    // every file setting, and the `file` destination needs an absolute path.
    if let Some(audit) = schema
        .pointer_mut("/$defs/RawAuditConfig")
        .and_then(Value::as_object_mut)
    {
        let set = |name: &str| serde_json::json!({"required": [name]});
        audit.insert(
            "if".to_owned(),
            serde_json::json!({
                "required": ["destination"],
                "properties": {"destination": {"const": "stdout"}}
            }),
        );
        audit.insert(
            "then".to_owned(),
            serde_json::json!({
                "not": {"anyOf": [set("path"), set("rotateBytes"), set("retentionDays")]}
            }),
        );
        audit.insert(
            "else".to_owned(),
            serde_json::json!({
                "required": ["path"],
                "properties": {"path": {
                    "type": "string",
                    "pattern": registry_platform_audit::ABSOLUTE_AUDIT_PATH_PATTERN
                }}
            }),
        );
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
            crate::compiler::MAX_BUILD_ID_BYTES as usize,
            INSTANCE_ID_SCHEMA_PATTERN,
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
            "/$defs/RawOidcVerifierConfig/properties/issuer",
            1,
            MAX_OIDC_VALUE_BYTES,
            "",
        ),
        (
            "/$defs/RawOidcVerifierConfig/properties/audience",
            1,
            registry_platform_config::MAX_OIDC_AUDIENCE_CHARACTERS,
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
    ] {
        install_schema_string_constraints(schema, pointer, minimum, maximum, pattern);
    }

    for pointer in [
        // The list arm of `allowedClients`; the other arm is the keyword
        // `unrestricted`.
        "/$defs/AllowedClients/anyOf/1",
        "/$defs/RawOidcVerifierConfig/properties/deniedKids",
        "/$defs/RawOidcVerifierConfig/properties/assertionIssuers/additionalProperties",
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
    // `non_empty_denied_kids` refuses a list that names no key, and
    // `ListedIssuers` a client listed with no assertion issuer.
    for pointer in [
        "/$defs/RawOidcVerifierConfig/properties/deniedKids",
        "/$defs/RawOidcVerifierConfig/properties/assertionIssuers/additionalProperties",
    ] {
        if let Some(member) = schema.pointer_mut(pointer).and_then(Value::as_object_mut) {
            member.insert("minItems".to_owned(), Value::from(1_u64));
        }
    }
    // `OidcVerifierConfig::from_raw` passes these client keys through
    // `validate_bounded_list`, so the published schema carries that pattern
    // and length bound beside the `ExternalId` the reader reads, rather than
    // accepting a document the runtime refuses at startup.
    if let Some(names) = schema
        .pointer_mut("/$defs/RawOidcVerifierConfig/properties/assertionIssuers/propertyNames")
        .and_then(Value::as_object_mut)
    {
        install_string_constraints_in_object(
            names,
            1,
            MAX_LIST_VALUE_BYTES,
            LIST_VALUE_SCHEMA_PATTERN,
        );
    }
    if let Some(member) = schema
        .pointer_mut("/$defs/RawOidcVerifierConfig/properties/assertionIssuers")
        .and_then(Value::as_object_mut)
    {
        member.insert("minProperties".to_owned(), Value::from(1_u64));
        member.insert("maxProperties".to_owned(), Value::from(MAX_LIST_ITEMS));
    }
    install_schema_array_constraints(
        schema,
        "/$defs/RawEventDestinationConfig/properties/allowedPrivateCidrs",
        MAX_DESTINATION_PRIVATE_CIDRS,
        true,
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
fn install_schema_authority_claim_exclusions(schema: &mut Value) {
    for (pointer, allow_subject) in [
        ("/$defs/RawAuthorityClaimsConfig/properties/principal", true),
        ("/$defs/RawAuthorityClaimsConfig/properties/purpose", false),
    ] {
        let registered = [
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
        ]
        .into_iter()
        .filter(|name| !allow_subject || *name != "sub")
        .collect::<Vec<_>>();
        if let Some(member) = schema.pointer_mut(pointer).and_then(Value::as_object_mut) {
            member.insert("not".to_owned(), serde_json::json!({"enum": registered}));
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
            {"required": ["caBundleRef"]},
            {"required": ["clientIdentityRef"]}
        ]),
    );
}

#[cfg(feature = "schema")]
fn remove_schema_default(schema: &mut Value, pointer: &str) {
    if let Some(member) = schema.pointer_mut(pointer).and_then(Value::as_object_mut) {
        member.remove("default");
    }
}

fn validate_existing_directory(
    path: &Path,
    unsafe_error: RuntimeConfigError,
    unavailable_error: RuntimeConfigError,
) -> Result<()> {
    reject_symlink_components(path, unsafe_error.clone(), unavailable_error.clone())?;
    let metadata = fs::symlink_metadata(path).map_err(|_| unavailable_error.clone())?;
    if metadata.file_type().is_symlink() {
        return Err(unsafe_error);
    }
    if !metadata.is_dir() {
        return Err(unavailable_error);
    }
    Ok(())
}

/// Refuses a path any of whose components is a symbolic link. A component the
/// process cannot read is a separate outcome: it reports the configured path as
/// unavailable rather than accusing the deployment of an unsafe path.
fn reject_symlink_components(
    path: &Path,
    unsafe_error: RuntimeConfigError,
    unavailable_error: RuntimeConfigError,
) -> Result<()> {
    let mut checked = PathBuf::new();
    for component in path.components() {
        checked.push(component.as_os_str());
        if matches!(component, Component::RootDir | Component::Prefix(_)) {
            continue;
        }
        match fs::symlink_metadata(&checked) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Err(unsafe_error),
            Ok(_) => {}
            Err(_) => return Err(unavailable_error),
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

/// The token verifier applies leeway in whole seconds, so a value carrying
/// sub-second precision would be truncated without the operator being told.
fn oidc_leeway(milliseconds: u64) -> Result<Duration> {
    if !milliseconds.is_multiple_of(1_000) {
        return Err(RuntimeConfigError::InvalidOidcLeeway);
    }
    Ok(Duration::from_millis(milliseconds))
}

#[cfg(all(test, feature = "schema"))]
mod schema_tests {
    use serde_json::json;

    #[test]
    fn audit_schema_states_the_destination_rules_the_runtime_enforces() {
        let schema = super::runtime_config_schema().unwrap();
        let audit = json!({
            "$defs": schema["$defs"],
            "$ref": "#/$defs/RawAuditConfig"
        });
        let validator = jsonschema::JSONSchema::compile(&audit).unwrap();
        let key = "secret:env/AUDIT_HASH_KEY";
        for accepted in [
            json!({"hashKeyRef": key, "path": "/var/lib/breg/audit.jsonl"}),
            json!({"hashKeyRef": key, "destination": "file", "path": "/audit.jsonl",
                "rotateBytes": 1_048_576, "retentionDays": 1}),
            json!({"hashKeyRef": key, "destination": "stdout"}),
        ] {
            assert!(validator.is_valid(&accepted), "{accepted}");
        }
        for refused in [
            json!({"hashKeyRef": key}),
            json!({"hashKeyRef": key, "path": null}),
            json!({"hashKeyRef": key, "destination": "stdout", "path": null}),
            json!({"hashKeyRef": key, "path": "audit.jsonl"}),
            json!({"hashKeyRef": key, "destination": "stdout", "path": "/audit.jsonl"}),
            json!({"hashKeyRef": key, "destination": "stdout", "rotateBytes": 1_048_576}),
            json!({"hashKeyRef": key, "destination": "stdout", "retentionDays": 1}),
        ] {
            assert!(!validator.is_valid(&refused), "{refused}");
        }
    }

    #[test]
    fn schema_types_the_keys_of_a_map_as_the_identifier_the_reader_reads() {
        let schema = super::runtime_config_schema().unwrap();
        for (map, identifier) in [
            ("/properties/eventDestinations", "LocalId"),
            (
                "/$defs/RawAuthorityClaimsConfig/properties/trustedActors",
                "ExternalId",
            ),
            (
                "/$defs/RawOidcVerifierConfig/properties/assertionIssuers",
                "ExternalId",
            ),
        ] {
            assert_eq!(
                schema.pointer(&format!("{map}/propertyNames/$ref")),
                Some(&json!(format!("#/$defs/{identifier}"))),
                "{map}"
            );
            assert!(schema["$defs"][identifier].is_object(), "{identifier}");
        }
    }

    #[test]
    fn schema_refuses_a_client_listed_with_no_assertion_issuer() {
        let schema = super::runtime_config_schema().unwrap();
        assert_eq!(
            schema.pointer(
                "/$defs/RawOidcVerifierConfig/properties/assertionIssuers/additionalProperties/minItems"
            ),
            Some(&json!(1))
        );
    }
}
