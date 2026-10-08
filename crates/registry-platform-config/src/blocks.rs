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

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{SecretError, SecretProvider, SecretReference, SecretResolver, MAX_SECRET_BYTES};

/// The schema pattern of a field that must name an enabled secret provider.
pub const SECRET_PROVIDER_PATTERN: &str = "^secret:(?:env|file)/";

/// The schema pattern of an exact secret reference.
pub const SECRET_REFERENCE_PATTERN: &str =
    "^(?:secret:env/[A-Z][A-Z0-9_]{0,127}|secret:file/[a-z][a-z0-9._-]{0,127})$";

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
    /// Absolute directory holding one file per secret. Each file must be a
    /// regular file owned by the runtime user, mode 0400 or 0600, with exactly
    /// one hard link.
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
/// A valid reference is safe and useful to name, but invalid operator-authored
/// text might itself be a literal credential, so only its field is named. The
/// resolved bytes and opened path never appear.
#[must_use]
pub fn describe_secret_failure(field: &str, reference: &str, error: &SecretError) -> String {
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
        SecretError::UnsafeFile => concat!(
            "the secret file must be a regular file owned by the runtime user, ",
            "with mode 0400 or 0600, and exactly one hard link"
        )
        .to_owned(),
        SecretError::Read => "the secret could not be read".to_owned(),
        SecretError::InvalidValue => format!(
            "the secret value must be non-empty text of at most {MAX_SECRET_BYTES} bytes \
             without NUL bytes"
        ),
    };
    if error == &SecretError::InvalidReference {
        format!("the secret reference configured at {field} could not be resolved: {reason}")
    } else {
        format!("the secret reference {reference} could not be resolved: {reason}")
    }
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
    pub trusted_root_certificate_ref: Option<String>,
    /// Allow a plaintext connection. Refused outside test builds.
    #[serde(default)]
    pub test_only_plaintext: bool,
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
            .field("test_only_plaintext", &self.test_only_plaintext)
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
        if let Some(reference) = &self.trusted_root_certificate_ref {
            references.push(("database.trustedRootCertificateRef", reference.as_str()));
        }
        references
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
#[cfg_attr(feature = "schema", schemars(!remote, tag = "kind"))]
pub enum JwksSource {
    /// Read `jwks_uri` from the issuer's OpenID Connect discovery document.
    // A struct variant, so `deny_unknown_fields` refuses a `uri` or a
    // `documentRef` written beside `kind: discovery`; serde ignores extra
    // members on a unit variant of an internally tagged enum.
    Discovery {},
    /// Fetch the key set from this absolute `https` URI, skipping discovery.
    Uri {
        #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
        uri: String,
    },
    /// Read the key set from a secret, for deployments without network access
    /// to the issuer.
    Static {
        #[serde(rename = "documentRef")]
        #[cfg_attr(feature = "schema", schemars(with = "SecretReference"))]
        document_ref: String,
    },
}

registry_platform_yaml::tagged_union!(JwksSource, tag = "kind");

impl Serialize for JwksSource {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let (kind, member) = match self {
            Self::Discovery {} => ("discovery", None),
            Self::Uri { uri } => ("uri", Some(("uri", uri))),
            Self::Static { document_ref } => ("static", Some(("documentRef", document_ref))),
        };
        let mut map = serializer.serialize_map(Some(1 + usize::from(member.is_some())))?;
        map.serialize_entry("kind", kind)?;
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
        match self {
            Self::Discovery {} => Ok(()),
            Self::Uri { uri } => {
                let field = format!("{field}.uri");
                if valid_jwks_uri(uri, allow_loopback_http) {
                    Ok(())
                } else {
                    Err(ConfigBlockError::new(
                        ConfigBlockErrorKind::InvalidUri,
                        &field,
                        format!("{field} must be an absolute https URL without credentials"),
                    ))
                }
            }
            Self::Static { document_ref } => {
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

    /// The secret reference a `static` source reads.
    #[must_use]
    pub fn document_ref(&self) -> Option<&str> {
        match self {
            Self::Static { document_ref } => Some(document_ref),
            _ => None,
        }
    }
}

fn valid_jwks_uri(value: &str, allow_loopback_http: bool) -> bool {
    let Ok(parsed) = url::Url::parse(value) else {
        return false;
    };
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.host().is_none() {
        return false;
    }
    match parsed.scheme() {
        "https" => true,
        "http" => {
            allow_loopback_http
                && matches!(
                    parsed.host(),
                    Some(url::Host::Ipv4(address)) if address.is_loopback()
                )
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
    /// `https` URL.
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub issuer: String,
    /// The audience every accepted access token must carry in `aud`.
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 512)))]
    pub audience: String,
    /// Where the issuer's signing keys come from. Absent reads the issuer's
    /// OpenID Connect discovery document.
    #[serde(default)]
    pub jwks_source: JwksSource,
}

impl OidcIssuerConfig {
    /// The issuer is an absolute `https` URL without credentials, query, or
    /// fragment, the audience is non-empty bounded text without control characters, and
    /// the key source passes [`JwksSource::check`]. A loopback `http` issuer
    /// or key URI is accepted only when `allow_loopback_http` is set, for
    /// supervised local development. `field` is the dotted path of the block,
    /// such as `authentication.oidc`.
    pub fn check(&self, field: &str, allow_loopback_http: bool) -> Result<(), ConfigBlockError> {
        let issuer_ok = valid_jwks_uri(&self.issuer, allow_loopback_http)
            && url::Url::parse(&self.issuer)
                .is_ok_and(|url| url.query().is_none() && url.fragment().is_none());
        if !issuer_ok {
            let field = format!("{field}.issuer");
            return Err(ConfigBlockError::new(
                ConfigBlockErrorKind::InvalidUri,
                &field,
                format!(
                    "{field} must be an absolute https URL without credentials, query, or fragment"
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
        self.jwks_source
            .check(&format!("{field}.jwksSource"), allow_loopback_http)
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
    /// Client identifiers whose access tokens are admitted. A runtime decides
    /// whether an empty list is acceptable in production.
    #[serde(default)]
    pub allowed_clients: Vec<String>,
    /// Assertion authorities each client may exchange a subject token from,
    /// keyed by client identifier. Omitted, no assertion-issuer rule applies;
    /// written, it lists at least one client. Once a client is listed, a
    /// token it exchanged is accepted only for one of that client's declared
    /// authorities.
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "non_empty_assertion_issuers"
    )]
    #[cfg_attr(feature = "schema", schemars(schema_with = "assertion_issuers_schema"))]
    pub assertion_issuers: BTreeMap<String, Vec<String>>,
}

/// Client identifiers are external identifiers (CFG-ID-2) with a stated
/// bound, so the schema types the keys with the shared `ExternalId` and states
/// the bounds `OidcClientsConfig::check` enforces.
#[cfg(feature = "schema")]
fn assertion_issuers_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
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
            "maxItems": MAX_ASSERTION_ISSUERS_PER_CLIENT,
            "uniqueItems": true,
            "items": {"type": "string", "minLength": 1, "maxLength": MAX_ASSERTION_ISSUER_BYTES}
        }
    })
}

/// An empty mapping is not how a file says "no assertion-issuer rule"
/// (CFG-EMPTY-2): omitting the member says it.
fn non_empty_assertion_issuers<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, Vec<String>>, D::Error> {
    let issuers = BTreeMap::<String, Vec<String>>::deserialize(deserializer)?;
    if issuers.is_empty() {
        return Err(registry_platform_yaml::Invalid::expected(
            "at least one client",
            "List at least one client with its assertion issuers, or omit assertionIssuers to apply no assertion-issuer rule.",
        )
        .into_error());
    }
    Ok(issuers)
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
        if self.tls_termination == TlsTermination::DevelopmentLoopback {
            return self.network_exposure == ListenerNetworkExposure::PrivateAddress
                && address.is_loopback();
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

#[cfg(test)]
#[path = "blocks_tests.rs"]
mod tests;
