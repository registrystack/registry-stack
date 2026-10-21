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

use crate::{SecretError, SecretProvider, SecretReference, SecretResolver, MAX_SECRET_BYTES};

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
}

registry_platform_yaml::tagged_union!(JwksSource);

impl Serialize for JwksSource {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let (tag, member) = match self {
            Self::Discovery {} => ("discovery", None),
            Self::Uri { uri } => ("uri", Some(("uri", uri.as_str()))),
            Self::Static { document_ref } => {
                ("static", Some(("documentRef", document_ref.as_str())))
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
                    && match parsed.host() {
                        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
                        Some(url::Host::Ipv4(address)) => address.is_loopback(),
                        Some(url::Host::Ipv6(address)) => address.is_loopback(),
                        None => false,
                    })
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
    /// `https` URL, or a plain `http` URL when `allowInsecureHttp` is set.
    pub issuer: Url,
    /// The audience every accepted access token must carry in `aud`.
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 512)))]
    pub audience: String,
    /// Where the issuer's signing keys come from. Absent reads the issuer's
    /// OpenID Connect discovery document.
    #[serde(default)]
    pub jwks_source: JwksSource,
    /// Permit plain HTTP beyond loopback to the configured issuer and to a
    /// JWKS URI declared in configuration. TLS remains required unless the
    /// operator explicitly accepts this transport risk.
    #[serde(default)]
    pub allow_insecure_http: bool,
}

impl OidcIssuerConfig {
    /// The issuer is an absolute `https` URL without credentials, query, or
    /// fragment, or a plain `http` one when `allow_insecure_http` is set, the
    /// audience is non-empty bounded text without control characters, and
    /// the key source passes [`JwksSource::check`]. Without
    /// `allow_insecure_http`, a loopback `http` issuer or key URI is accepted
    /// only when `allow_loopback_http` is set, for supervised local
    /// development. `field` is the dotted path of the block,
    /// such as `authentication.oidc`.
    pub fn check(&self, field: &str, allow_loopback_http: bool) -> Result<(), ConfigBlockError> {
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
enum OidcAllowedClients {
    /// Admit a token from every client the issuer verifies.
    Unrestricted(UnrestrictedClients),
    /// Admit a token only from a listed client.
    Listed(ListedClients),
}

registry_platform_yaml::shape_union!(OidcAllowedClients { scalar => Unrestricted, list => Listed });

/// The keyword `unrestricted`.
struct UnrestrictedClients;

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
struct ListedClients(Vec<String>);

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
            "minItems": 1,
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
/// the URL, the HMAC-SHA256 key reference, and the delivery budget. The
/// outbound policy is fixed: `registry-platform-hooks` activates it with no
/// private address range and no client certificate. A runtime whose
/// destinations need either configures its own full outbound policy instead.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UrlHookDestinationConfig {
    /// An https URL, or http on 127.0.0.1, localhost, or [::1], without a
    /// query or fragment.
    pub url: Url,
    pub hmac_sha256_key_ref: SecretReference,
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
