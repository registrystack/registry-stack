//! The runtime configuration blocks every Registry Stack runtime shares.
//!
//! A product's runtime configuration embeds these types under the same keys,
//! so an operator reads `secretProviders`, `database`, `listener.bind`,
//! `package`, `audit.hashKeyRef` and `authentication.oidc` the same way in
//! every product, and one implementation checks them. Product-specific
//! siblings stay in the product's own configuration types: the audit key and
//! the OIDC issuer and clients are embedded with `#[serde(flatten)]` beside
//! them.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use registry_platform_yaml::{BoundedU32, ExternalId, Invalid, LocalId, Url};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    DestinationTransport, DevelopmentClass, DevelopmentOnlyRefused, DevelopmentSetting,
    DevelopmentWitness, Gated, PrivateRanges, SecretError, SecretProvider, SecretReference,
    SecretResolver, Stated, MAX_SECRET_BYTES,
};

/// The schema pattern of a field that must name an enabled secret provider.
pub const SECRET_PROVIDER_PATTERN: &str = "^secret:(?:env|file)/";

/// The schema pattern of an exact secret reference.
pub const SECRET_REFERENCE_PATTERN: &str = registry_platform_yaml::SECRET_REFERENCE_PATTERN;

/// Why a shared block was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigBlockErrorKind {
    /// A path that must be absolute is not.
    RelativePath,
    /// `secretProviders` enables no provider.
    NoSecretProvider,
    /// A `*Ref` field is not an exact secret reference.
    InvalidSecretReference,
    /// A `*Ref` field names a provider `secretProviders` does not enable.
    SecretProviderDisabled,
    /// A required value is empty.
    Empty,
    /// `package.expectedDigest` is not a `sha256:` label.
    InvalidDigest,
    /// A JWKS URI or an OIDC issuer is not an absolute `https` URL.
    InvalidUri,
    /// An OIDC audience is empty, too long, or holds a control character.
    InvalidAudience,
    /// `assertionIssuers` exceeds a bound, names an empty value, or repeats
    /// an issuer for one client.
    InvalidAssertionIssuers,
}

/// A shared block refusal naming its field and never a configured value.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{message}")]
pub struct ConfigBlockError {
    kind: ConfigBlockErrorKind,
    field: String,
    message: String,
}

impl ConfigBlockError {
    fn new(kind: ConfigBlockErrorKind, field: &str, message: String) -> Self {
        Self {
            kind,
            field: field.to_owned(),
            message,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> ConfigBlockErrorKind {
        self.kind
    }

    /// The dotted field the refusal concerns.
    #[must_use]
    pub fn field(&self) -> &str {
        &self.field
    }
}

fn require_absolute(field: &str, path: &Path) -> Result<(), ConfigBlockError> {
    let normal = path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        });
    if normal {
        Ok(())
    } else {
        Err(ConfigBlockError::new(
            ConfigBlockErrorKind::RelativePath,
            field,
            format!("{field} must be an absolute path without . or .. components"),
        ))
    }
}

/// The secret providers a runtime enables. A reference is resolved only by a
/// provider declared here: `secret:file/name` under `file.root`, and
/// `secret:env/NAME` only when `environment: {}` is present.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "schema",
    schemars(extend("anyOf" = [
        {"required": ["file"], "properties": {"file": {"$ref": "#/$defs/FileSecretProviderConfig"}}},
        {"required": ["environment"], "properties": {"environment": {"$ref": "#/$defs/EnvironmentSecretProviderConfig"}}}
    ]))
)]
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretProvidersConfig {
    /// Enables `secret:file/name` references, read from files under `root`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "FileSecretProviderConfig"))]
    pub file: Option<FileSecretProviderConfig>,
    /// Enables `secret:env/NAME` references, read from the process
    /// environment. Declared as an empty mapping: `environment: {}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "EnvironmentSecretProviderConfig"))]
    pub environment: Option<EnvironmentSecretProviderConfig>,
}

/// The file secret provider.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileSecretProviderConfig {
    /// Absolute directory holding one file per secret. A name may be a
    /// relative link that stays below this directory, through at most 8 links.
    /// The file it reaches must be a regular file with one hard link, owned by
    /// the runtime user with mode 0400 or 0600, or owned by root with no
    /// access beyond group read (0440 or 0640) when the runtime is not root.
    /// A process that declared development loads a file with looser read or
    /// mode bits and logs a warning.
    #[cfg_attr(feature = "schema", schemars(extend("pattern" = "^/")))]
    pub root: PathBuf,
}

/// The environment secret provider. It takes no settings.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentSecretProviderConfig {}

impl SecretProvidersConfig {
    /// At least one provider is enabled, and the file root is absolute.
    pub fn check(&self) -> Result<(), ConfigBlockError> {
        if self.file.is_none() && self.environment.is_none() {
            return Err(ConfigBlockError::new(
                ConfigBlockErrorKind::NoSecretProvider,
                "secretProviders",
                "secretProviders must enable file, environment, or both".to_owned(),
            ));
        }
        if let Some(file) = &self.file {
            require_absolute("secretProviders.file.root", &file.root)?;
        }
        Ok(())
    }

    /// `raw`, configured at `field`, is an exact secret reference whose
    /// provider this block enables.
    pub fn check_reference(&self, field: &str, raw: &str) -> Result<(), ConfigBlockError> {
        let reference = SecretReference::parse(raw).map_err(|_| {
            ConfigBlockError::new(
                ConfigBlockErrorKind::InvalidSecretReference,
                field,
                format!("{field} must be an exact secret:env/NAME or secret:file/name reference"),
            )
        })?;
        let (enabled, provider) = match reference.provider() {
            SecretProvider::File => (self.file.is_some(), "secretProviders.file"),
            SecretProvider::Environment => {
                (self.environment.is_some(), "secretProviders.environment")
            }
        };
        if enabled {
            Ok(())
        } else {
            Err(ConfigBlockError::new(
                ConfigBlockErrorKind::SecretProviderDisabled,
                field,
                format!("{field} uses a provider that is not enabled; declare {provider}"),
            ))
        }
    }

    /// The providers this block enables.
    #[must_use]
    pub fn providers(&self) -> Vec<SecretProvider> {
        let mut providers = Vec::new();
        if self.file.is_some() {
            providers.push(SecretProvider::File);
        }
        if self.environment.is_some() {
            providers.push(SecretProvider::Environment);
        }
        providers
    }

    /// A resolver for exactly the providers this block enables.
    pub fn resolver(&self) -> Result<SecretResolver, SecretError> {
        SecretResolver::new(
            self.providers(),
            self.file
                .as_ref()
                .map_or_else(|| Path::new(""), |file| file.root.as_path()),
        )
    }
}

/// Explain one refused secret reference without disclosing what it protects.
///
/// The reference is operator-authored text read from a configuration file, so
/// it is never repeated: the member path and a fixed reason are named. The
/// resolved bytes and opened path never appear either. The reference parameter
/// stays so a caller keeps one call shape; it is not read.
#[must_use]
pub fn describe_secret_failure(field: &str, _reference: &str, error: &SecretError) -> String {
    let reason = match error {
        SecretError::InvalidReference => {
            "it is not an exact secret:env/NAME or secret:file/name reference".to_owned()
        }
        SecretError::ProviderDisabled => "its provider is not enabled for this runtime".to_owned(),
        SecretError::InvalidProviderConfiguration => {
            "the secret provider configuration is invalid".to_owned()
        }
        SecretError::Unavailable => {
            "no readable secret of that name exists under the configured provider".to_owned()
        }
        SecretError::UnsafeFile(check) => format!(
            "{} ({}). {}",
            check.message(),
            check.code(),
            check.suggested_action()
        ),
        SecretError::Read => "the secret could not be read".to_owned(),
        SecretError::InvalidValue => format!(
            "the secret value must be non-empty text of at most {MAX_SECRET_BYTES} bytes \
             without NUL bytes"
        ),
    };
    format!("the secret reference configured at {field} could not be resolved: {reason}")
}

/// The PostgreSQL connection a stateful runtime uses. Both URLs are secret
/// references and may name the same secret.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DatabaseConfig {
    /// Secret reference to the least-privileged runtime connection URL.
    #[cfg_attr(feature = "schema", schemars(with = "SecretReference"))]
    pub runtime_url_ref: String,
    /// Secret reference to the migration connection URL.
    #[cfg_attr(feature = "schema", schemars(with = "SecretReference"))]
    pub migration_url_ref: String,
    /// Secret reference to a PEM root certificate the connection trusts.
    /// Absent, the connection trusts the platform's root certificates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "SecretReference"))]
    pub ca_bundle_ref: Option<String>,
    /// Allow a plaintext connection. Refused outside test builds.
    #[serde(default)]
    pub test_only_plaintext: bool,
    /// How the connection is protected. Absent means `verified-tls`. A
    /// plaintext transport must match the database hosts, and cannot be
    /// written beside `testOnlyPlaintext`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "Gated<DatabaseTransport>"))]
    pub transport: Option<Gated<DatabaseTransport>>,
}

impl fmt::Debug for DatabaseConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseConfig")
            .field("runtime_url_ref", &"<redacted>")
            .field("migration_url_ref", &"<redacted>")
            .field(
                "ca_bundle_ref",
                &self.ca_bundle_ref.as_ref().map(|_| "<redacted>"),
            )
            .field("test_only_plaintext", &self.test_only_plaintext)
            .field("transport", &self.transport)
            .finish()
    }
}

impl DatabaseConfig {
    /// Every secret reference this block configures, with its field.
    #[must_use]
    pub fn references(&self) -> Vec<(&'static str, &str)> {
        let mut references = vec![
            ("database.runtimeUrlRef", self.runtime_url_ref.as_str()),
            ("database.migrationUrlRef", self.migration_url_ref.as_str()),
        ];
        if let Some(reference) = &self.ca_bundle_ref {
            references.push(("database.caBundleRef", reference.as_str()));
        }
        references
    }
}

/// How a PostgreSQL connection is protected.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DatabaseTransport {
    /// TLS with verification. `caBundleRef` is optional.
    #[default]
    VerifiedTls,
    /// No TLS. Every host must be a Unix socket, a numeric loopback address
    /// or `localhost`.
    LoopbackPlaintext,
    /// No TLS, in development only. Every host must also be loopback, a
    /// socket, a private IPv4 address (RFC 1918), an IPv6 unique local
    /// address (`fc00::/7`), or a name that resolves only to such addresses.
    PrivateNetworkPlaintext,
}

static DATABASE_PRIVATE_PLAINTEXT: DevelopmentSetting = DevelopmentSetting {
    code: "platform.posture.database-private-plaintext",
    key: "transport",
    summary: "The database connection is not encrypted and reaches a private network",
    production: "Write database.transport: verified-tls, and give the database a certificate the runtime trusts.",
};

impl DevelopmentClass for DatabaseTransport {
    const SETTINGS: &'static [&'static DevelopmentSetting] = &[&DATABASE_PRIVATE_PLAINTEXT];

    fn development_setting(&self) -> Option<&'static DevelopmentSetting> {
        match self {
            Self::VerifiedTls | Self::LoopbackPlaintext => None,
            Self::PrivateNetworkPlaintext => Some(&DATABASE_PRIVATE_PLAINTEXT),
        }
    }
}

/// A host a PostgreSQL URL names, once the secret is resolved and the URL
/// parsed by the product's driver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DatabaseHost {
    /// A host name or address, with no brackets required around an IPv6
    /// literal.
    Tcp(String),
    /// A Unix socket directory.
    Unix,
}

/// Why a database transport was refused. No variant repeats a configured
/// value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseTransportError {
    /// A host is not one the plaintext transport permits.
    HostMismatch(DatabaseTransport),
    /// The transport is development-only and the caller holds no witness.
    DevelopmentOnly(DevelopmentOnlyRefused),
    /// `transport` and `testOnlyPlaintext` are both written.
    Conflict,
    /// `testOnlyPlaintext` in a build that is not a test build.
    TestOnlyPlaintext,
}

impl DatabaseTransportError {
    /// The stable code of the refusal (CFG-DIAG-3).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::HostMismatch(_) => "platform.database.transport-host-mismatch",
            Self::DevelopmentOnly(refused) => refused.setting.code,
            Self::Conflict => "platform.database.transport-conflict",
            Self::TestOnlyPlaintext => "platform.database.test-only-plaintext",
        }
    }

    /// What to write instead.
    #[must_use]
    pub const fn suggested_action(&self) -> &'static str {
        match self {
            Self::HostMismatch(DatabaseTransport::PrivateNetworkPlaintext) => {
                "Name a Unix socket, a loopback address, a private-network address or a name that resolves only to such addresses, or write database.transport: verified-tls."
            }
            Self::HostMismatch(_) => {
                "Name a Unix socket, a loopback address, or localhost where it resolves only to loopback addresses, or write database.transport: verified-tls."
            }
            Self::DevelopmentOnly(refused) => refused.setting.production,
            Self::Conflict => "Remove database.testOnlyPlaintext, and keep database.transport.",
            Self::TestOnlyPlaintext => {
                "Remove it, and set database.transport for a plaintext connection on the same host."
            }
        }
    }
}

impl fmt::Display for DatabaseTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::HostMismatch(_) => {
                "a database host is not one the configured plaintext transport permits"
            }
            Self::DevelopmentOnly(_) => {
                "the database transport is accepted only when the process declares development"
            }
            Self::Conflict => "database.transport and database.testOnlyPlaintext are both set",
            Self::TestOnlyPlaintext => "database.testOnlyPlaintext is accepted only by test builds",
        })
    }
}

impl std::error::Error for DatabaseTransportError {}

impl DatabaseConfig {
    /// The checks every posture applies to the transport: `transport` is not
    /// written beside `testOnlyPlaintext`, and `testOnlyPlaintext` is
    /// written only in a test build, which the product states with
    /// `test_build`.
    pub fn check(&self, test_build: bool) -> Result<(), DatabaseTransportError> {
        if self.test_only_plaintext && self.transport.is_some() {
            return Err(DatabaseTransportError::Conflict);
        }
        if self.test_only_plaintext && !test_build {
            return Err(DatabaseTransportError::TestOnlyPlaintext);
        }
        Ok(())
    }

    /// The transport the connection uses, once `hosts` are known: a plaintext
    /// transport is returned only when every host is one it permits. A
    /// development-only transport is readable with `witness` alone. A name,
    /// `localhost` included, is resolved here, once, so a later re-resolution
    /// by the driver is outside the check; a name that does not resolve is
    /// refused.
    pub fn plaintext_permitted(
        &self,
        hosts: &[DatabaseHost],
        witness: Option<&DevelopmentWitness>,
    ) -> Result<DatabaseTransport, DatabaseTransportError> {
        plaintext_permitted_with(self, hosts, witness, &resolve_host)
    }
}

fn resolve_host(name: &str) -> std::io::Result<Vec<IpAddr>> {
    use std::net::ToSocketAddrs;
    (name, 0)
        .to_socket_addrs()
        .map(|addresses| addresses.map(|address| address.ip()).collect())
}

pub(crate) fn plaintext_permitted_with(
    config: &DatabaseConfig,
    hosts: &[DatabaseHost],
    witness: Option<&DevelopmentWitness>,
    resolve: &dyn Fn(&str) -> std::io::Result<Vec<IpAddr>>,
) -> Result<DatabaseTransport, DatabaseTransportError> {
    let transport = match &config.transport {
        None => DatabaseTransport::VerifiedTls,
        Some(gated) => *gated
            .get(witness)
            .map_err(DatabaseTransportError::DevelopmentOnly)?,
    };
    let permitted = |host: &DatabaseHost| match (transport, host) {
        (DatabaseTransport::VerifiedTls, _) | (_, DatabaseHost::Unix) => true,
        (DatabaseTransport::LoopbackPlaintext, DatabaseHost::Tcp(name)) => {
            loopback_database_host(name, resolve)
        }
        (DatabaseTransport::PrivateNetworkPlaintext, DatabaseHost::Tcp(name)) => {
            private_network_host(name, resolve)
        }
    };
    if hosts.iter().all(permitted) {
        Ok(transport)
    } else {
        Err(DatabaseTransportError::HostMismatch(transport))
    }
}

/// Whether `name` is a loopback address literal, or the name `localhost`
/// resolving, and resolving only, to loopback addresses. The PostgreSQL
/// driver resolves a name itself, so `localhost` is looked up here with the
/// same resolver rather than trusted by its spelling.
fn loopback_database_host(
    name: &str,
    resolve: &dyn Fn(&str) -> std::io::Result<Vec<IpAddr>>,
) -> bool {
    match registry_platform_loopback::loopback_host(name) {
        Some(host @ registry_platform_loopback::LoopbackHost::LocalhostName) => {
            resolve(name).is_ok_and(|addresses| host.pinned_by(&addresses))
        }
        Some(_) => true,
        None => false,
    }
}

/// Whether `name` is loopback, a private IPv4 address, an IPv6 unique local
/// address, or a name that resolves, and resolves only, to such addresses.
fn private_network_host(
    name: &str,
    resolve: &dyn Fn(&str) -> std::io::Result<Vec<IpAddr>>,
) -> bool {
    if loopback_database_host(name, resolve) {
        return true;
    }
    let literal = name
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(name);
    if let Ok(address) = literal.parse::<IpAddr>() {
        return private_address(address);
    }
    match resolve(name) {
        Ok(addresses) => !addresses.is_empty() && addresses.into_iter().all(private_address),
        Err(_) => false,
    }
}

fn private_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_loopback() || address.is_private(),
        IpAddr::V6(address) => address.is_loopback() || is_unique_local(address),
    }
}

/// Where a runtime obtains the OIDC issuer's signing keys.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
pub enum JwksSource {
    /// Read `jwks_uri` from the issuer's OpenID Connect discovery document.
    // A struct variant, so `deny_unknown_fields` refuses a `uri` or a
    // `documentRef` written beside `type: discovery`; serde ignores extra
    // members on a unit variant of an internally tagged enum.
    Discovery {},
    /// Fetch the key set from this absolute `https` URI, skipping discovery.
    /// A plain `http` URI is accepted on loopback for supervised local
    /// development, and beyond loopback only when the issuer block sets
    /// `allowInsecureHttp`.
    Uri { uri: Url },
    /// Read the key set from a secret, for deployments without network access
    /// to the issuer.
    Static {
        #[serde(rename = "documentRef")]
        #[cfg_attr(feature = "schema", schemars(with = "SecretReference"))]
        document_ref: String,
    },
    /// Read the key set from a secret, as `static` does, for a test issuer a
    /// development run supervises. Development only: production refuses it.
    TestIssuer {
        #[serde(rename = "documentRef")]
        #[cfg_attr(feature = "schema", schemars(with = "SecretReference"))]
        document_ref: String,
    },
}

registry_platform_yaml::tagged_union!(JwksSource);

static TEST_ISSUER: DevelopmentSetting = DevelopmentSetting {
    code: "platform.posture.test-issuer",
    key: "type",
    summary: "The issuer's signing keys come from a test issuer",
    production:
        "Write jwksSource: {type: discovery}, or a static or uri source for the real issuer.",
};

impl DevelopmentClass for JwksSource {
    const SETTINGS: &'static [&'static DevelopmentSetting] = &[&TEST_ISSUER];

    fn development_setting(&self) -> Option<&'static DevelopmentSetting> {
        match self {
            Self::Discovery {} | Self::Uri { .. } | Self::Static { .. } => None,
            Self::TestIssuer { .. } => Some(&TEST_ISSUER),
        }
    }
}

impl Serialize for JwksSource {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let (tag, member) = match self {
            Self::Discovery {} => ("discovery", None),
            Self::Uri { uri } => ("uri", Some(("uri", uri.as_str()))),
            Self::Static { document_ref } => {
                ("static", Some(("documentRef", document_ref.as_str())))
            }
            Self::TestIssuer { document_ref } => {
                ("test-issuer", Some(("documentRef", document_ref.as_str())))
            }
        };
        let mut map = serializer.serialize_map(Some(1 + usize::from(member.is_some())))?;
        map.serialize_entry("type", tag)?;
        if let Some((key, value)) = member {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

impl Default for JwksSource {
    fn default() -> Self {
        Self::Discovery {}
    }
}

impl JwksSource {
    /// A `uri` source names an absolute `https` URL without credentials. A
    /// loopback `http` URL is accepted only when `allow_loopback_http` is set,
    /// for supervised local development.
    pub fn check(&self, field: &str, allow_loopback_http: bool) -> Result<(), ConfigBlockError> {
        self.check_with_insecure_http(field, allow_loopback_http, false)
    }

    /// Check this key source while carrying the containing issuer's explicit
    /// plain-HTTP decision into a fixed endpoint.
    pub fn check_with_insecure_http(
        &self,
        field: &str,
        allow_loopback_http: bool,
        allow_insecure_http: bool,
    ) -> Result<(), ConfigBlockError> {
        match self {
            Self::Discovery {} => Ok(()),
            Self::Uri { uri } => {
                let field = format!("{field}.uri");
                if valid_jwks_uri(uri, allow_loopback_http, allow_insecure_http) {
                    Ok(())
                } else {
                    Err(ConfigBlockError::new(
                        ConfigBlockErrorKind::InvalidUri,
                        &field,
                        format!(
                            "{field} must be an absolute https URL without credentials; plain http beyond loopback needs allowInsecureHttp: true"
                        ),
                    ))
                }
            }
            Self::Static { document_ref } | Self::TestIssuer { document_ref } => {
                if document_ref.is_empty() {
                    let field = format!("{field}.documentRef");
                    Err(ConfigBlockError::new(
                        ConfigBlockErrorKind::Empty,
                        &field,
                        format!("{field} must be a secret reference"),
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// The URI a `uri` source fetches from.
    #[must_use]
    pub fn uri(&self) -> Option<&str> {
        match self {
            Self::Uri { uri } => Some(uri),
            _ => None,
        }
    }

    /// The secret reference a `static` or `test-issuer` source reads.
    #[must_use]
    pub fn document_ref(&self) -> Option<&str> {
        match self {
            Self::Static { document_ref } | Self::TestIssuer { document_ref } => Some(document_ref),
            _ => None,
        }
    }
}

fn valid_jwks_uri(value: &Url, allow_loopback_http: bool, allow_insecure_http: bool) -> bool {
    let parsed = value.to_url();
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.host().is_none() {
        return false;
    }
    match parsed.scheme() {
        "https" => true,
        "http" => {
            allow_insecure_http
                || (allow_loopback_http
                    && parsed
                        .host_str()
                        .and_then(registry_platform_loopback::loopback_host)
                        .is_some())
        }
        _ => false,
    }
}

/// The key for the keyed references an audit record carries in place of raw
/// identifiers, written `audit.hashKeyRef` beside the product's own audit
/// settings.
// A product's `audit` block holds this as a member renamed to the reader's
// shared-block marker `registry-platform-yaml/shared-block/...`, which the
// reader reads as this block's members inline, so every product spells the key
// the same way and one implementation checks it.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", schemars(deny_unknown_fields))]
pub struct AuditKeyConfig {
    /// Secret reference to the audit hash key.
    pub hash_key_ref: SecretReference,
    /// Who provisioned the key. Absent means `operator-provisioned`.
    /// `development-generated` marks a key a development tool made.
    #[serde(
        default = "operator_provisioned",
        skip_serializing_if = "is_operator_provisioned"
    )]
    pub hash_key_custody: Gated<AuditKeyCustody>,
}

/// Who provisioned the audit hash key.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditKeyCustody {
    /// The operator provisioned the key.
    #[default]
    OperatorProvisioned,
    /// A development tool generated the key.
    DevelopmentGenerated,
}

static GENERATED_AUDIT_KEY: DevelopmentSetting = DevelopmentSetting {
    code: "platform.posture.generated-audit-key",
    key: "hashKeyCustody",
    summary: "The audit hash key was generated by a development tool",
    production: "Provision an audit hash key, reference it in audit.hashKeyRef, and write audit.hashKeyCustody: operator-provisioned.",
};

impl DevelopmentClass for AuditKeyCustody {
    const SETTINGS: &'static [&'static DevelopmentSetting] = &[&GENERATED_AUDIT_KEY];

    fn development_setting(&self) -> Option<&'static DevelopmentSetting> {
        match self {
            Self::OperatorProvisioned => None,
            Self::DevelopmentGenerated => Some(&GENERATED_AUDIT_KEY),
        }
    }
}

fn operator_provisioned() -> Gated<AuditKeyCustody> {
    Gated::wrap(AuditKeyCustody::OperatorProvisioned)
}

fn is_operator_provisioned(custody: &Gated<AuditKeyCustody>) -> bool {
    custody.development_setting().is_none()
}

impl AuditKeyConfig {
    /// The key names a provider `secret_providers` enables.
    pub fn check(&self, secret_providers: &SecretProvidersConfig) -> Result<(), ConfigBlockError> {
        secret_providers.check_reference("audit.hashKeyRef", self.hash_key_ref.as_str())
    }
}

/// The longest `authentication.oidc.audience` accepted, in characters.
pub const MAX_OIDC_AUDIENCE_CHARACTERS: usize = 512;

/// The OIDC issuer a runtime accepts access tokens from: the exact `iss`
/// value, the `aud` value a token must carry, and where the issuer's signing
/// keys come from, written under `authentication.oidc` beside the product's
/// own token rules.
// A product's `authentication.oidc` block holds this as a member renamed to the
// reader's shared-block marker `registry-platform-yaml/shared-block/...`, which
// the reader reads as this block's members inline, beside the product's own
// token rules.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", schemars(deny_unknown_fields))]
pub struct OidcIssuerConfig {
    /// Exact issuer accepted in access-token `iss` claims, an absolute
    /// `https` URL, or a plain `http` URL when `allowInsecureHttp` is set.
    pub issuer: Url,
    /// The audience every accepted access token must carry in `aud`.
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 512)))]
    pub audience: String,
    /// Where the issuer's signing keys come from. Absent reads the issuer's
    /// OpenID Connect discovery document.
    #[serde(default, deserialize_with = "deserialize_jwks_source")]
    #[cfg_attr(
        feature = "schema",
        schemars(extend("x-registry-development-only" = ["platform.posture.test-issuer"]))
    )]
    pub jwks_source: JwksSource,
    /// Permit plain HTTP beyond loopback to the configured issuer and to a
    /// JWKS URI declared in configuration. Loopback needs no setting. The
    /// value `true` is a development-only setting: the loader records it, and
    /// production refuses it.
    #[serde(default, deserialize_with = "deserialize_insecure_http")]
    #[cfg_attr(
        feature = "schema",
        schemars(extend("x-registry-development-only" = ["platform.posture.insecure-issuer-http"]))
    )]
    pub allow_insecure_http: bool,
}

/// The value of `allowInsecureHttp`.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct InsecureHttp(pub bool);

static INSECURE_ISSUER_HTTP: DevelopmentSetting = DevelopmentSetting {
    code: "platform.posture.insecure-issuer-http",
    key: "allowInsecureHttp",
    summary: "Plain http is permitted to an issuer beyond loopback",
    production: "Delete allowInsecureHttp and use an https issuer.",
};

impl DevelopmentClass for InsecureHttp {
    const SETTINGS: &'static [&'static DevelopmentSetting] = &[&INSECURE_ISSUER_HTTP];

    fn development_setting(&self) -> Option<&'static DevelopmentSetting> {
        self.0.then_some(&INSECURE_ISSUER_HTTP)
    }
}

/// Read `allowInsecureHttp` through [`Gated`], so a loader that collects
/// development-only settings records `true` with its pointer.
fn deserialize_insecure_http<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    Gated::<InsecureHttp>::deserialize(deserializer)
        .map(|value| value.development_setting().is_some())
}

/// Read `jwksSource` through [`Gated`], so a loader that collects
/// development-only settings records a test issuer with its pointer.
fn deserialize_jwks_source<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<JwksSource, D::Error> {
    Gated::<JwksSource>::deserialize(deserializer).map(Gated::into_inner)
}

impl OidcIssuerConfig {
    /// The issuer is an absolute `https` URL without credentials, query, or
    /// fragment, a loopback `http` one, or a plain `http` one when
    /// `allow_insecure_http` is set, the audience is non-empty bounded text
    /// without control characters, and the key source passes
    /// [`JwksSource::check`]. Loopback needs no setting in any posture. A
    /// plain `http` issuer beyond loopback is accepted here when
    /// `allow_insecure_http` is set, and the posture decision refuses it in
    /// production. `field` is the dotted path of the block, such as
    /// `authentication.oidc`.
    pub fn check(&self, field: &str) -> Result<(), ConfigBlockError> {
        self.check_without_posture(field, true)
    }

    /// [`OidcIssuerConfig::check`] for a runtime that has not adopted the
    /// posture: a loopback `http` issuer or key URI is accepted only when
    /// `allow_loopback_http` is set.
    pub fn check_without_posture(
        &self,
        field: &str,
        allow_loopback_http: bool,
    ) -> Result<(), ConfigBlockError> {
        let issuer = self.issuer.to_url();
        let issuer_ok = valid_jwks_uri(&self.issuer, allow_loopback_http, self.allow_insecure_http)
            && issuer.query().is_none()
            && issuer.fragment().is_none();
        if !issuer_ok {
            let field = format!("{field}.issuer");
            return Err(ConfigBlockError::new(
                ConfigBlockErrorKind::InvalidUri,
                &field,
                format!(
                    "{field} must be an absolute https URL without credentials, query, or fragment; plain http beyond loopback needs allowInsecureHttp: true"
                ),
            ));
        }
        let audience_ok = !self.audience.is_empty()
            && self.audience.chars().count() <= MAX_OIDC_AUDIENCE_CHARACTERS
            && !self.audience.chars().any(char::is_control);
        if !audience_ok {
            let field = format!("{field}.audience");
            return Err(ConfigBlockError::new(
                ConfigBlockErrorKind::InvalidAudience,
                &field,
                format!(
                    "{field} must be non-empty text of at most {MAX_OIDC_AUDIENCE_CHARACTERS} \
                     characters without control characters"
                ),
            ));
        }
        self.jwks_source.check_with_insecure_http(
            &format!("{field}.jwksSource"),
            allow_loopback_http,
            self.allow_insecure_http,
        )
    }
}

/// The most clients `authentication.oidc.assertionIssuers` may list.
pub const MAX_ASSERTION_ISSUER_CLIENTS: usize = 64;
/// The longest client key in `assertionIssuers`, in bytes.
pub const MAX_ASSERTION_ISSUER_CLIENT_BYTES: usize = 128;
/// The most assertion issuers one client may list.
pub const MAX_ASSERTION_ISSUERS_PER_CLIENT: usize = 16;
/// The longest assertion issuer, in bytes.
pub const MAX_ASSERTION_ISSUER_BYTES: usize = 512;

/// The OAuth clients a runtime admits access tokens for, and the assertion
/// authorities each client may exchange a subject token from, written under
/// `authentication.oidc` beside the issuer.
// A product's `authentication.oidc` block embeds this with
// `#[serde(flatten)]`, so the bounds on the authored map hold in every
// product that exchanges tokens.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", schemars(deny_unknown_fields))]
pub struct OidcClientsConfig {
    /// The OAuth clients whose access tokens are admitted: `unrestricted` to
    /// admit a token from every client the issuer verifies, or a list of at
    /// least one distinct client. A runtime decides whether `unrestricted`
    /// is acceptable in production.
    // Held as the list the token verifier takes, where empty admits every
    // client.
    #[serde(
        deserialize_with = "allowed_clients",
        serialize_with = "serialize_allowed_clients"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "OidcAllowedClients"))]
    pub allowed_clients: Vec<String>,
    /// Assertion authorities each client may exchange a subject token from,
    /// keyed by client identifier. Omitted, no assertion-issuer rule applies;
    /// written, it lists at least one client, each with at least one
    /// authority. Once a client is listed, a token it exchanged is accepted
    /// only for one of that client's declared authorities, and a client that
    /// is not listed may exchange from no authority.
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "non_empty_assertion_issuers"
    )]
    #[cfg_attr(feature = "schema", schemars(schema_with = "assertion_issuers_schema"))]
    pub assertion_issuers: BTreeMap<String, Vec<String>>,
}

const UNRESTRICTED: &str = "unrestricted";

fn allowed_clients_refused<E: serde::de::Error>() -> E {
    registry_platform_yaml::Invalid::expected(
        "unrestricted, or a list of at least one OAuth client",
        "List the OAuth clients whose access tokens are admitted, or write unrestricted to admit every client the issuer verifies.",
    )
    .into_error()
}

/// How `allowedClients` is written (CFG-EMPTY-2): the keyword `unrestricted`,
/// or a list of at least one client. An empty list is refused, because it
/// reads as both "none" and "any".
// Its schema name is the block's own: a runtime that reads the member through
// a type of its own keeps that definition under a different name, which the
// shared-block drift check compares by name.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(untagged))]
pub(crate) enum OidcAllowedClients {
    /// Admit a token from every client the issuer verifies.
    Unrestricted(UnrestrictedClients),
    /// Admit a token only from a listed client.
    Listed(ListedClients),
}

registry_platform_yaml::shape_union!(OidcAllowedClients { scalar => Unrestricted, list => Listed });

/// The keyword `unrestricted`.
pub(crate) struct UnrestrictedClients;

impl<'de> Deserialize<'de> for UnrestrictedClients {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if String::deserialize(deserializer)? == UNRESTRICTED {
            Ok(Self)
        } else {
            Err(allowed_clients_refused())
        }
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for UnrestrictedClients {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "UnrestrictedClients".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({"type": "string", "const": UNRESTRICTED})
    }
}

/// At least one client, none repeated (CFG-ID-6).
pub(crate) struct ListedClients(pub(crate) Vec<String>);

impl<'de> Deserialize<'de> for ListedClients {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let clients = registry_platform_yaml::UniqueList::<String>::deserialize(deserializer)?;
        if clients.is_empty() {
            return Err(allowed_clients_refused());
        }
        Ok(Self(clients.into_iter().collect()))
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for ListedClients {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ListedClients".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let mut schema = generator.subschema_for::<registry_platform_yaml::UniqueList<String>>();
        schema.insert("minItems".to_owned(), 1.into());
        schema
    }
}

/// Reads the authored member into the list the token verifier holds, where
/// empty admits every client.
fn allowed_clients<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    Ok(match OidcAllowedClients::deserialize(deserializer)? {
        OidcAllowedClients::Unrestricted(UnrestrictedClients) => Vec::new(),
        OidcAllowedClients::Listed(ListedClients(clients)) => clients,
    })
}

fn serialize_allowed_clients<S: serde::Serializer>(
    clients: &[String],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    if clients.is_empty() {
        serializer.serialize_str(UNRESTRICTED)
    } else {
        clients.serialize(serializer)
    }
}

/// Client identifiers are external identifiers (CFG-ID-2) with a stated
/// bound, so the schema types the keys with the shared `ExternalId` and states
/// the bounds `OidcClientsConfig::check` enforces. A product that holds
/// `assertionIssuers` in its own issuer entry uses it as `schema_with`.
#[cfg(feature = "schema")]
pub fn assertion_issuers_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let mut client = generator.subschema_for::<registry_platform_yaml::ExternalId>();
    client.insert(
        "maxLength".to_owned(),
        serde_json::json!(MAX_ASSERTION_ISSUER_CLIENT_BYTES),
    );
    schemars::json_schema!({
        "type": "object",
        "minProperties": 1,
        "maxProperties": MAX_ASSERTION_ISSUER_CLIENTS,
        "propertyNames": client,
        "additionalProperties": {
            "type": "array",
            "minItems": 1,
            "maxItems": MAX_ASSERTION_ISSUERS_PER_CLIENT,
            "uniqueItems": true,
            "items": {"type": "string", "minLength": 1, "maxLength": MAX_ASSERTION_ISSUER_BYTES}
        }
    })
}

/// An empty mapping is not how a file says "no assertion-issuer rule"
/// (CFG-EMPTY-2): omitting the member says it. A product that holds
/// `assertionIssuers` in its own issuer entry reads it with this as
/// `deserialize_with`, beside `#[serde(default)]`.
pub fn non_empty_assertion_issuers<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, Vec<String>>, D::Error> {
    let issuers = BTreeMap::<String, ListedIssuers>::deserialize(deserializer)?;
    if issuers.is_empty() {
        return Err(registry_platform_yaml::Invalid::expected(
            "at least one client",
            "List at least one client with its assertion issuers, or omit assertionIssuers to apply no assertion-issuer rule.",
        )
        .into_error());
    }
    Ok(issuers
        .into_iter()
        .map(|(client, issuers)| (client, issuers.0))
        .collect())
}

/// The assertion issuers of one listed client. An empty list is not how a
/// file says "no authority" (CFG-EMPTY-2): leaving the client out says it.
struct ListedIssuers(Vec<String>);

impl<'de> Deserialize<'de> for ListedIssuers {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
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

impl OidcClientsConfig {
    /// Refuse an assertion-issuer map with too many clients, an empty or
    /// oversized client key or issuer, too many issuers for one client, or an
    /// issuer repeated within one client's list, so one operator document
    /// cannot become an unbounded verifier input. `field` is the dotted path
    /// of the block, such as `authentication.oidc`.
    pub fn check(&self, field: &str) -> Result<(), ConfigBlockError> {
        let within_bounds = self.assertion_issuers.len() <= MAX_ASSERTION_ISSUER_CLIENTS
            && self.assertion_issuers.iter().all(|(client, issuers)| {
                let mut seen = BTreeSet::new();
                !client.is_empty()
                    && client.len() <= MAX_ASSERTION_ISSUER_CLIENT_BYTES
                    && issuers.len() <= MAX_ASSERTION_ISSUERS_PER_CLIENT
                    && issuers.iter().all(|issuer| {
                        !issuer.is_empty()
                            && issuer.len() <= MAX_ASSERTION_ISSUER_BYTES
                            && seen.insert(issuer)
                    })
            });
        if within_bounds {
            return Ok(());
        }
        let field = format!("{field}.assertionIssuers");
        Err(ConfigBlockError::new(
            ConfigBlockErrorKind::InvalidAssertionIssuers,
            &field,
            format!(
                "{field} must list at most {MAX_ASSERTION_ISSUER_CLIENTS} non-empty client \
                 identifiers of at most {MAX_ASSERTION_ISSUER_CLIENT_BYTES} bytes, each with at \
                 most {MAX_ASSERTION_ISSUERS_PER_CLIENT} distinct non-empty issuers of at most \
                 {MAX_ASSERTION_ISSUER_BYTES} bytes"
            ),
        ))
    }
}

const FROM_PACKAGE: &str = "from-package";

/// How `allowedClients` is written where the governed package names the
/// clients (CFG-EMPTY-2): the keyword `from-package`, the keyword
/// `unrestricted`, or a list of at least one client. The member stays
/// required and an empty list is refused. A runtime resolves the value with
/// [`PackageClients::resolve`] before it builds a token verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PackageClients {
    /// Admit exactly the clients the package's access profiles name.
    FromPackage,
    /// Admit a token from every client the issuer verifies. A runtime decides
    /// whether that is acceptable in production.
    Unrestricted,
    /// Admit the listed clients, which must cover every package client.
    Listed(Vec<String>),
}

/// The keywords `allowedClients` takes beside a list.
enum PackageClientsKeyword {
    FromPackage,
    Unrestricted,
}

fn package_clients_refused<E: serde::de::Error>() -> E {
    registry_platform_yaml::Invalid::expected(
        "from-package, unrestricted, or a list of at least one OAuth client",
        "Write from-package to admit the package's requester clients, list the OAuth clients whose access tokens are admitted, or write unrestricted to admit every client the issuer verifies.",
    )
    .into_error()
}

impl<'de> Deserialize<'de> for PackageClientsKeyword {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match String::deserialize(deserializer)?.as_str() {
            FROM_PACKAGE => Ok(Self::FromPackage),
            UNRESTRICTED => Ok(Self::Unrestricted),
            _ => Err(package_clients_refused()),
        }
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for PackageClientsKeyword {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "PackageClientsKeyword".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({"type": "string", "enum": [FROM_PACKAGE, UNRESTRICTED]})
    }
}

/// The authored shape of [`PackageClients`], so the schema and the reader
/// agree on the two forms.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(untagged))]
enum OidcPackageAllowedClients {
    /// A keyword.
    Keyword(PackageClientsKeyword),
    /// Admit a token only from a listed client.
    Listed(ListedClients),
}

registry_platform_yaml::shape_union!(OidcPackageAllowedClients { scalar => Keyword, list => Listed });

impl<'de> Deserialize<'de> for PackageClients {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(
            match OidcPackageAllowedClients::deserialize(deserializer)? {
                OidcPackageAllowedClients::Keyword(PackageClientsKeyword::FromPackage) => {
                    Self::FromPackage
                }
                OidcPackageAllowedClients::Keyword(PackageClientsKeyword::Unrestricted) => {
                    Self::Unrestricted
                }
                OidcPackageAllowedClients::Listed(ListedClients(clients)) => Self::Listed(clients),
            },
        )
    }
}

impl Serialize for PackageClients {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::FromPackage => serializer.serialize_str(FROM_PACKAGE),
            Self::Unrestricted => serializer.serialize_str(UNRESTRICTED),
            Self::Listed(clients) => clients.serialize(serializer),
        }
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for PackageClients {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "OidcPackageAllowedClients".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        OidcPackageAllowedClients::json_schema(generator)
    }
}

/// The OAuth clients a runtime admits access tokens for when the governed
/// package names its requester clients, and the assertion authorities each
/// client may exchange a subject token from, written under
/// `authentication.oidc` beside the issuer. Runtimes whose package does not
/// name clients keep [`OidcClientsConfig`].
// A product's `authentication.oidc` block embeds this with
// `#[serde(flatten)]`, as it does `OidcClientsConfig`.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", schemars(deny_unknown_fields))]
pub struct OidcPackageClientsConfig {
    /// The OAuth clients whose access tokens are admitted: `from-package` for
    /// the package's requester clients, `unrestricted` for every client the
    /// issuer verifies, or a list of at least one distinct client that covers
    /// the package's requester clients.
    pub allowed_clients: PackageClients,
    /// Assertion authorities each client may exchange a subject token from,
    /// with the meaning and bounds of `OidcClientsConfig::assertion_issuers`.
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "non_empty_assertion_issuers"
    )]
    #[cfg_attr(feature = "schema", schemars(schema_with = "assertion_issuers_schema"))]
    pub assertion_issuers: BTreeMap<String, Vec<String>>,
}

impl OidcPackageClientsConfig {
    /// The bounds of [`OidcClientsConfig::check`] on `assertionIssuers`.
    pub fn check(&self, field: &str) -> Result<(), ConfigBlockError> {
        OidcClientsConfig {
            allowed_clients: Vec::new(),
            assertion_issuers: self.assertion_issuers.clone(),
        }
        .check(field)
    }
}

/// A non-empty, sorted list of the clients a token verifier admits. It is the
/// only value a runtime passes to a verifier built from [`PackageClients`], so
/// an unresolved keyword cannot reach it as the empty list, which a verifier
/// reads as "every client".
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedClients(Vec<String>);

impl AdmittedClients {
    /// The sorted, de-duplicated clients, or `None` when there are none.
    #[must_use]
    pub fn new(clients: Vec<String>) -> Option<Self> {
        let clients: BTreeSet<String> = clients.into_iter().collect();
        if clients.is_empty() {
            None
        } else {
            Some(Self(clients.into_iter().collect()))
        }
    }

    #[must_use]
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }

    #[must_use]
    pub fn into_vec(self) -> Vec<String> {
        self.0
    }
}

/// Why [`PackageClients::resolve`] produced no admitted clients. Client
/// identifiers are not secrets.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PackageClientsError {
    /// `allowedClients` is `unrestricted`, which this resolution never turns
    /// into a list.
    #[error("allowedClients is unrestricted and admits no resolved list of clients")]
    Unrestricted,
    /// The resolved list has no client: the package names none, or the list
    /// is empty.
    #[error("allowedClients resolves to no client")]
    Empty,
    /// The explicit list leaves out a client the package names.
    #[error("allowedClients does not list the package client {0}")]
    Missing(String),
}

impl PackageClients {
    /// The clients to admit, given the requester clients of every access
    /// profile of the loaded package. `FromPackage` is the sorted union of
    /// `package_clients`. `Listed` is returned when it covers every package
    /// client, and refused naming the first missing one otherwise. Extra
    /// clients in a list stay admitted. `Unrestricted` and an empty result are
    /// errors: the runtime decides what `Unrestricted` means for it.
    pub fn resolve(
        &self,
        package_clients: &[String],
    ) -> Result<AdmittedClients, PackageClientsError> {
        match self {
            Self::Unrestricted => Err(PackageClientsError::Unrestricted),
            Self::FromPackage => {
                AdmittedClients::new(package_clients.to_vec()).ok_or(PackageClientsError::Empty)
            }
            Self::Listed(listed) => {
                let admitted =
                    AdmittedClients::new(listed.clone()).ok_or(PackageClientsError::Empty)?;
                let missing = package_clients
                    .iter()
                    .filter(|client| !admitted.0.contains(client))
                    .min();
                match missing {
                    Some(client) => Err(PackageClientsError::Missing(client.clone())),
                    None => Ok(admitted),
                }
            }
        }
    }
}

/// The package a runtime serves: `root` is the absolute package directory,
/// and `expectedDigest`, when set, pins the package digest the runtime must
/// find there. The package digest is the digest of the package's
/// `SHA256SUMS` file; see [`crate::package`].
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackageConfig {
    /// Absolute path of the package directory.
    #[cfg_attr(feature = "schema", schemars(extend("pattern" = "^/")))]
    pub root: PathBuf,
    /// `sha256:` label of the package digest, the digest of the package's
    /// `SHA256SUMS` file. When set, the runtime refuses to start on any other
    /// package.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Digest"))]
    pub expected_digest: Option<String>,
}

impl PackageConfig {
    /// `root` is absolute and `expectedDigest`, if set, is a `sha256:` label.
    pub fn check(&self) -> Result<(), ConfigBlockError> {
        require_absolute("package.root", &self.root)?;
        if let Some(digest) = &self.expected_digest {
            if !is_sha256_label(digest) {
                return Err(ConfigBlockError::new(
                    ConfigBlockErrorKind::InvalidDigest,
                    "package.expectedDigest",
                    "package.expectedDigest must be sha256: followed by 64 lowercase hex digits"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Compare the digest of the package found at `root` with the pin.
    pub fn verify_digest(&self, found: &str) -> Result<(), PackageDigestMismatch> {
        match &self.expected_digest {
            Some(expected) if expected != found => Err(PackageDigestMismatch {
                expected: expected.clone(),
                found: found.to_owned(),
            }),
            _ => Ok(()),
        }
    }
}

/// The package at `package.root` is not the one `package.expectedDigest` pins.
/// Both values are package identities, not secrets.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error(
    "package.expectedDigest is {expected} but the package at package.root is {found}; \
     deploy the pinned package or update package.expectedDigest"
)]
pub struct PackageDigestMismatch {
    pub expected: String,
    pub found: String,
}

/// Whether `value` is `sha256:` followed by 64 lowercase hex digits.
#[must_use]
pub fn is_sha256_label(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// The longest `listener.bind` text accepted. A socket address parser accepts
/// any number of leading zeroes in the port, so the text is bounded first.
pub const MAX_LISTENER_BIND_CHARACTERS: usize = 128;

/// A listener socket address written `host:port`, with an IP literal host
/// (`[addr]:port` for IPv6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenerBind(pub SocketAddr);

impl ListenerBind {
    #[must_use]
    pub const fn socket_addr(self) -> SocketAddr {
        self.0
    }

    #[must_use]
    pub const fn ip(self) -> IpAddr {
        self.0.ip()
    }
}

impl FromStr for ListenerBind {
    type Err = std::net::AddrParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value.parse().map(Self)
    }
}

impl Serialize for ListenerBind {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ListenerBind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        let bounded = value.chars().count() <= MAX_LISTENER_BIND_CHARACTERS;
        bounded
            .then(|| value.parse().ok())
            .flatten()
            .ok_or_else(|| {
                serde::de::Error::custom(registry_platform_yaml::Invalid::expected(
                    "host:port with an IP address host, such as 127.0.0.1:8080 or [::1]:8080",
                    "Write the address as host:port with an IP address host.",
                ))
            })
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for ListenerBind {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ListenerBind".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "Socket address the runtime listens on, written host:port with an IP address host ([addr]:port for IPv6).",
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_LISTENER_BIND_CHARACTERS
        })
    }
}

/// The listener of a runtime that declares no TLS or exposure settings.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListenerConfig {
    pub bind: ListenerBind,
}

/// The operator-private metrics listener of a runtime. `networkExposure`
/// has the meaning it has on the serving listener: `private-address` (the
/// default) requires a loopback or private address, and `container-private`
/// also permits the unspecified address inside a private container network.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetricsListenerConfig {
    pub bind: ListenerBind,
    #[serde(default)]
    pub network_exposure: ListenerNetworkExposure,
}

/// Declares the trusted transport boundary for a runtime's plaintext HTTP
/// listener. Production listeners require operator-controlled upstream TLS
/// termination; direct plaintext is limited to the explicit loopback-only
/// development mode.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsTermination {
    OperatorControlledUpstream,
    DevelopmentLoopback,
    /// Plaintext on a loopback bind, behind a proxy on the same host. Valid
    /// in every posture. It is placement only: it relaxes nothing a product
    /// relaxes under `development-loopback`.
    LoopbackPlaintext,
}

/// The operator-declared private network placement of an HTTP listener.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ListenerNetworkExposure {
    #[default]
    PrivateAddress,
    ContainerPrivate,
}

/// The listener of a runtime that declares its TLS termination and network
/// exposure.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivateListenerConfig {
    pub bind: ListenerBind,
    pub tls_termination: TlsTermination,
    #[serde(default)]
    pub network_exposure: ListenerNetworkExposure,
}

impl PrivateListenerConfig {
    /// Whether the bind address is allowed for the declared TLS termination
    /// and network exposure: loopback only in development; a loopback or
    /// private address behind an operator-controlled terminator; the
    /// unspecified address only inside a private container network.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        let address = self.bind.ip();
        if address.is_multicast() {
            return false;
        }
        match self.tls_termination {
            TlsTermination::DevelopmentLoopback => {
                return self.network_exposure == ListenerNetworkExposure::PrivateAddress
                    && address.is_loopback();
            }
            TlsTermination::LoopbackPlaintext => {
                return self.network_exposure == ListenerNetworkExposure::PrivateAddress
                    && registry_platform_loopback::loopback_address(address);
            }
            TlsTermination::OperatorControlledUpstream => {}
        }
        match (address, self.network_exposure) {
            (IpAddr::V4(address), ListenerNetworkExposure::PrivateAddress) => {
                address.is_loopback() || address.is_private()
            }
            (IpAddr::V6(address), ListenerNetworkExposure::PrivateAddress) => {
                address.is_loopback() || is_unique_local(address)
            }
            (IpAddr::V4(address), ListenerNetworkExposure::ContainerPrivate) => {
                address.is_unspecified() || address.is_loopback() || address.is_private()
            }
            (IpAddr::V6(address), ListenerNetworkExposure::ContainerPrivate) => {
                address.is_unspecified() || address.is_loopback() || is_unique_local(address)
            }
        }
    }
}

fn is_unique_local(address: Ipv6Addr) -> bool {
    address.octets()[0] & 0xfe == 0xfc
}

/// The status route a task-grant status check appends to `baseUrl` when
/// `statusPath` is omitted, Casework's route.
pub const DEFAULT_TASK_GRANT_STATUS_PATH: &str = "/v1/task-grants/{grantId}/status";

/// The scope a task-grant status credential is requested with when
/// `statusScope` is omitted, Casework's status scope.
pub const DEFAULT_TASK_GRANT_STATUS_SCOPE: &str = "casework:grants:status";

/// One task authority whose grants a runtime checks for fresh status, and the
/// runtime's own credentials for that check, written as one entry of
/// `taskGrantStatus`. The status route and scope default to Casework's.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskGrantStatusConfig {
    /// The task authority's issuer, exactly as the authority states it,
    /// including an absolute URN issuer. It is compared rather than fetched
    /// and must be an absolute resource URI.
    pub source_issuer: ExternalId,
    /// The authority's base URL the status check calls. It is `https`;
    /// `http` is accepted only for a loopback host, for local development.
    pub base_url: Url,
    pub token_endpoint: Url,
    pub client_assertion_audience: ExternalId,
    pub client_id: ExternalId,
    pub private_key_ref: SecretReference,
    /// The audience the runtime requests its status credential for, an
    /// absolute resource URI.
    pub status_resource: ExternalId,
    /// The one scope the runtime requests its status credential with.
    /// Omitted, `casework:grants:status`.
    #[serde(default = "default_task_grant_status_scope")]
    pub status_scope: ExternalId,
    /// The status route appended to `baseUrl`'s path. It starts with `/` and
    /// has exactly one whole `{grantId}` segment; every other segment uses
    /// only letters, digits, `-`, `.`, `_`, and `~`. Omitted,
    /// `/v1/task-grants/{grantId}/status`.
    #[serde(default = "default_task_grant_status_path")]
    pub status_path: String,
    /// PEM CA bundle for the authority and its token endpoint. Omitted, the
    /// platform's trusted roots verify them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "SecretReference"))]
    pub ca_bundle_ref: Option<SecretReference>,
}

impl fmt::Debug for TaskGrantStatusConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TaskGrantStatusConfig(<configured>)")
    }
}

fn default_task_grant_status_scope() -> ExternalId {
    ExternalId::new(DEFAULT_TASK_GRANT_STATUS_SCOPE)
        .expect("the default status scope is an external id")
}

fn default_task_grant_status_path() -> String {
    DEFAULT_TASK_GRANT_STATUS_PATH.to_owned()
}

/// The longest one object-store or verifier attempt may run, body included,
/// the upper bound of each block's `attemptTimeoutMilliseconds`.
pub const MAX_ATTEMPT_TIMEOUT_MILLISECONDS: u64 = 60_000;

/// The shortest attempt an object-store or verifier block accepts.
pub const MIN_ATTEMPT_TIMEOUT_MILLISECONDS: u64 = 100;

/// The attempt timeout an object-store or verifier block applies when
/// `attemptTimeoutMilliseconds` is omitted.
pub const DEFAULT_ATTEMPT_TIMEOUT_MILLISECONDS: u64 = 10_000;

/// A bounded attempt timeout in milliseconds.
pub type AttemptTimeoutMilliseconds = registry_platform_yaml::BoundedU64<
    MIN_ATTEMPT_TIMEOUT_MILLISECONDS,
    MAX_ATTEMPT_TIMEOUT_MILLISECONDS,
>;

/// One S3-compatible bucket a runtime keeps content bytes in, and the
/// runtime's credentials for it. The decode checks only the shape; the
/// object-store transport refuses a non-loopback `http` URL, a URL carrying a
/// path, query, or fragment, and a malformed bucket or region name before it
/// sends anything.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObjectStorageConfig {
    /// The service's base URL, with no path. It is `https`; `http` is
    /// accepted only for a loopback host, for local development.
    pub url: Url,
    /// The bucket name: lowercase letters, digits, `-` and `.`.
    #[cfg_attr(feature = "schema", schemars(length(min = 3, max = 63)))]
    pub bucket: String,
    /// The signing region: lowercase letters, digits and `-`.
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 64)))]
    pub region: String,
    /// Address the bucket as a path under `url` rather than as a host name.
    /// Omitted, `true`.
    #[serde(default = "default_path_style")]
    pub path_style: bool,
    pub access_key_id_ref: SecretReference,
    pub secret_access_key_ref: SecretReference,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "SecretReference"))]
    pub session_token_ref: Option<SecretReference>,
    /// PEM CA bundle for the service. Omitted, the platform's trusted roots
    /// verify it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "SecretReference"))]
    pub ca_bundle_ref: Option<SecretReference>,
    /// The longest one request may run, body included. Omitted, 10000.
    #[serde(default = "default_attempt_timeout")]
    pub attempt_timeout_milliseconds: AttemptTimeoutMilliseconds,
}

impl fmt::Debug for ObjectStorageConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ObjectStorageConfig(<configured>)")
    }
}

/// One external HTTP verifier a runtime submits content bytes to for an
/// `approved` or `rejected` verdict, and the runtime's bearer credential for
/// it. The block carries no default: a runtime that makes verification
/// optional states its own disabled form beside it.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttachmentVerifierConfig {
    /// The URL the content is posted to. It is `https`; `http` is accepted
    /// only for a loopback host, for local development.
    pub url: Url,
    pub authorization_ref: SecretReference,
    /// Non-secret identity of the external scanner and its rules generation.
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = 128), regex(pattern = r"^[\x21-\x7E]+$"))
    )]
    pub policy_id: String,
    /// The longest one verification attempt may run, body included.
    /// Omitted, 10000.
    #[serde(default = "default_attempt_timeout")]
    pub attempt_timeout_milliseconds: AttemptTimeoutMilliseconds,
}

impl fmt::Debug for AttachmentVerifierConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AttachmentVerifierConfig(<configured>)")
    }
}

/// The most URL hook destinations one runtime may bind.
pub const MAX_HOOK_DESTINATIONS: usize = 128;

/// The shortest one URL hook delivery attempt may be bounded to, in
/// milliseconds.
pub const MIN_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS: u32 = 100;

/// The longest one URL hook delivery attempt may be bounded to, in
/// milliseconds.
pub const MAX_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS: u32 = 10_000;

/// The attempt timeout a URL hook destination applies when
/// `attemptTimeoutMilliseconds` is omitted.
pub const DEFAULT_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS: u32 = 5_000;

/// The most delivery attempts a URL hook destination may allow one event.
pub const MAX_HOOK_ATTEMPTS: u8 = 20;

/// The attempt count a URL hook destination applies when `maximumAttempts`
/// is omitted.
pub const DEFAULT_HOOK_MAXIMUM_ATTEMPTS: u8 = 8;

/// One URL hook destination a runtime signs and sends hook deliveries to:
/// the URL, how it is reached, the HMAC-SHA256 key references, and the
/// delivery budget. `registry-platform-hooks` activates it under the
/// transport and private ranges it declares, with no client certificate. A
/// runtime whose destinations need a client certificate configures its own
/// full outbound policy instead.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UrlHookDestinationConfig {
    /// An https URL, or http on 127.0.0.1, localhost, or [::1], without a
    /// query or fragment. Plain http to any other host needs
    /// `transport: private-network-plaintext`.
    pub url: Url,
    /// How the destination is reached. Absent, https reads `verified-tls`
    /// and http to a loopback host reads `loopback-plaintext`.
    /// `private-network-plaintext` needs `allowedPrivateCidrs`, and is
    /// reported as an explicit production setting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "Stated<DestinationTransport>"))]
    pub transport: Option<Stated<DestinationTransport>>,
    /// The private ranges the destination's host may resolve to. Empty
    /// admits none.
    #[serde(default, skip_serializing_if = "PrivateRanges::is_empty")]
    pub allowed_private_cidrs: PrivateRanges,
    pub hmac_sha256_key_ref: SecretReference,
    /// Optional previous signing key for rotation, excluded from the
    /// destination binding digest.
    #[serde(
        default,
        deserialize_with = "present_hook_key_reference",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "SecretReference"))]
    pub previous_hmac_sha256_key_ref: Option<SecretReference>,
    /// How long one delivery attempt may take, from 100 through 10000
    /// milliseconds.
    #[serde(
        default = "default_hook_attempt_timeout_milliseconds",
        deserialize_with = "hook_attempt_timeout_milliseconds"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(range(
            min = MIN_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS,
            max = MAX_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS
        ))
    )]
    pub attempt_timeout_milliseconds: u32,
    /// How many delivery attempts one event gets, from 1 through 20.
    #[serde(
        default = "default_hook_maximum_attempts",
        deserialize_with = "hook_maximum_attempts"
    )]
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = MAX_HOOK_ATTEMPTS)))]
    pub maximum_attempts: u8,
}

fn present_hook_key_reference<'de, D>(deserializer: D) -> Result<Option<SecretReference>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    SecretReference::deserialize(deserializer).map(Some)
}

impl UrlHookDestinationConfig {
    /// Whether the attempt timeout and attempt count stay inside the
    /// delivery budget: the bound the reader enforces at load and hook
    /// activation enforces again before it binds the destination.
    #[must_use]
    pub fn within_delivery_budget(&self) -> bool {
        (MIN_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS..=MAX_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS)
            .contains(&self.attempt_timeout_milliseconds)
            && (1..=MAX_HOOK_ATTEMPTS).contains(&self.maximum_attempts)
    }
}

impl fmt::Debug for UrlHookDestinationConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UrlHookDestinationConfig(<configured>)")
    }
}

/// A URL hook destination map: at most [`MAX_HOOK_DESTINATIONS`] bindings,
/// each keyed by a local identifier (CFG-ID-1). A host field reads it with
/// `#[serde(deserialize_with = "url_hook_destinations")]` and describes it
/// with [`url_hook_destinations_schema`].
pub fn url_hook_destinations<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, UrlHookDestinationConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    let hooks = BTreeMap::<LocalId, UrlHookDestinationConfig>::deserialize(deserializer)?;
    if hooks.len() > MAX_HOOK_DESTINATIONS {
        return Err(Invalid::expected(
            "at most 128 hook destinations",
            "Remove hook destinations until at most 128 remain.",
        )
        .into_error());
    }
    Ok(hooks
        .into_iter()
        .map(|(id, destination)| (id.into_string(), destination))
        .collect())
}

/// The schema of a [`url_hook_destinations`] map.
#[cfg(feature = "schema")]
pub fn url_hook_destinations_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "object",
        "maxProperties": MAX_HOOK_DESTINATIONS,
        "propertyNames": generator.subschema_for::<LocalId>(),
        "additionalProperties": generator.subschema_for::<UrlHookDestinationConfig>()
    })
}

fn hook_attempt_timeout_milliseconds<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    BoundedU32::<MIN_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS, MAX_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS>::deserialize(
        deserializer,
    )
    .map(BoundedU32::get)
}

/// A URL hook destination's attempt count, from 1 through
/// [`MAX_HOOK_ATTEMPTS`].
fn hook_maximum_attempts<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: Deserializer<'de>,
{
    const MAX: u32 = MAX_HOOK_ATTEMPTS as u32;
    let attempts = BoundedU32::<1, MAX>::deserialize(deserializer)?.get();
    u8::try_from(attempts).map_err(|_| Invalid::out_of_range(1, MAX).into_error())
}

const fn default_hook_attempt_timeout_milliseconds() -> u32 {
    DEFAULT_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS
}

const fn default_hook_maximum_attempts() -> u8 {
    DEFAULT_HOOK_MAXIMUM_ATTEMPTS
}

fn default_path_style() -> bool {
    true
}

fn default_attempt_timeout() -> AttemptTimeoutMilliseconds {
    AttemptTimeoutMilliseconds::new(DEFAULT_ATTEMPT_TIMEOUT_MILLISECONDS)
        .expect("the default attempt timeout is in bounds")
}

#[cfg(test)]
#[path = "blocks_tests.rs"]
mod tests;
