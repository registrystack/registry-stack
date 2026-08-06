//! Startup-only Mint configuration.
//!
//! Everything in this file is fixed for the lifetime of the serving process:
//! issuer identity, signing and audit keys, listener, and token policy. The one part of
//! Mint's state that is intentionally reloadable is the client registry, which
//! lives in [`crate::clients`].

use std::{
    collections::BTreeSet,
    net::IpAddr,
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use thiserror::Error;
use url::Url;

/// Supported signature algorithms, shared by minted tokens and accepted client
/// assertions.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
pub enum Algorithm {
    EdDSA,
    ES256,
    RS256,
}

impl Algorithm {
    #[must_use]
    pub fn as_jsonwebtoken(self) -> jsonwebtoken::Algorithm {
        match self {
            Self::EdDSA => jsonwebtoken::Algorithm::EdDSA,
            Self::ES256 => jsonwebtoken::Algorithm::ES256,
            Self::RS256 => jsonwebtoken::Algorithm::RS256,
        }
    }

    #[must_use]
    pub fn as_header_value(self) -> &'static str {
        match self {
            Self::EdDSA => "EdDSA",
            Self::ES256 => "ES256",
            Self::RS256 => "RS256",
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ConfigError {
    #[error("the configuration file is unavailable")]
    Unavailable,
    #[error("the configuration document is invalid: {0}")]
    Document(String),
    #[error("configuration is invalid: {0}")]
    Invalid(&'static str),
}

fn default_jwks_path() -> String {
    MINT_JWKS_PATH.to_owned()
}

pub(crate) const MINT_JWKS_PATH: &str = "/.well-known/jwks.json";
pub(crate) const MINT_TOKEN_PATH: &str = "/token";
pub(crate) const MINT_METADATA_PATH: &str = "/.well-known/oauth-authorization-server";
pub(crate) const MINT_HEALTH_PATH: &str = "/health";
pub(crate) const MINT_READY_PATH: &str = "/ready";

/// Every path the router registers besides the configured JWKS path.
///
/// The router panics when one path is registered twice, so the configured
/// JWKS path is checked against this list where the configuration is read.
pub(crate) const MINT_FIXED_ROUTES: [&str; 4] = [
    MINT_TOKEN_PATH,
    MINT_METADATA_PATH,
    MINT_HEALTH_PATH,
    MINT_READY_PATH,
];

fn default_maximum_request_bytes() -> u32 {
    16 * 1024
}

fn default_request_timeout_milliseconds() -> u64 {
    5_000
}

fn default_assertion_lifetime_seconds() -> u64 {
    300
}

fn default_replay_cache_entries() -> usize {
    8_192
}

fn default_principal_claim() -> String {
    "sub".to_owned()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListenerConfig {
    pub address: String,
    pub port: u16,
    #[serde(default = "default_maximum_request_bytes")]
    pub maximum_request_bytes: u32,
    #[serde(default = "default_request_timeout_milliseconds")]
    pub request_timeout_milliseconds: u64,
}

impl ListenerConfig {
    pub fn bind_address(&self) -> Result<IpAddr, ConfigError> {
        self.address
            .parse()
            .map_err(|_| ConfigError::Invalid("listener address is not an IP address"))
    }

    /// Reject limits no token request can survive.
    ///
    /// A zero body limit or a zero timeout leaves Mint reporting itself ready
    /// while every token request fails, which is an outage the readiness probe
    /// cannot see. The bounds match the Evidence listener.
    fn validate(&self) -> Result<(), ConfigError> {
        if !(1_024..=1_048_576).contains(&self.maximum_request_bytes) {
            return Err(ConfigError::Invalid(
                "listener maximumRequestBytes must be 1024..=1048576",
            ));
        }
        if !(1..=30_000).contains(&self.request_timeout_milliseconds) {
            return Err(ConfigError::Invalid(
                "listener requestTimeoutMilliseconds must be 1..=30000",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SigningConfig {
    pub algorithm: Algorithm,
    /// Governed public JWK of the key that signs newly issued tokens.
    pub active_public_jwk_file: PathBuf,
    /// Public JWKs whose already-issued tokens may still be live.
    #[serde(default)]
    pub published_public_jwk_files: Vec<PathBuf>,
    /// Compromised key identifiers that must never be published or activated.
    #[serde(default)]
    pub revoked_key_ids: Vec<String>,
    #[serde(default = "default_jwks_path")]
    pub jwks_path: String,
}

/// Process-local access to the active signing key.
#[derive(Debug, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SignerConfig {
    /// A mounted private JWK, admitted only in supervised local development.
    LocalJwk { private_key_ref: String },
    /// Vault/OpenBao Transit reached only through a workload-local Unix socket.
    Transit {
        unix_socket_path: PathBuf,
        mount: String,
        key_name: String,
        key_version: u32,
        timeout_milliseconds: u64,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretProvidersConfig {
    pub file: FileSecretProviderConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSecretProviderConfig {
    /// Absolute directory beneath which logical `secret:file/...` names resolve.
    pub root: PathBuf,
}

/// Required, fail-closed audit storage for token decisions.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditConfig {
    /// Append-only keyed JSONL chain, resolved relative to the configuration.
    pub path: PathBuf,
    /// Per-segment rotation threshold. Sealed segments are never deleted.
    pub maximum_file_bytes: u64,
    /// Owner-only master HMAC key resolved through the configured provider.
    pub hash_key_ref: String,
    /// Version label written into privacy-preserving audit handles.
    pub hash_key_version: u32,
}

/// Names of the claims Mint writes into minted access tokens.
///
/// These must match the resource server's `authentication` block. Evidence, for
/// example, reads its principal, requester tags, evidence audience, and grant
/// pair from configurable claim names.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClaimNames {
    #[serde(default = "default_principal_claim")]
    pub principal: String,
    pub requester_tags: String,
    pub evidence_audience: String,
    pub grant_id: String,
    pub grant_authority: String,
    /// The delegated actor identity, present only where a deployment issues
    /// delegated tokens. Omitting it is what stops a registry entry that
    /// declares delegation from ever being served.
    #[serde(default)]
    pub actor: Option<String>,
}

impl ClaimNames {
    fn validate(&self) -> Result<(), ConfigError> {
        let mut names = vec![
            self.principal.as_str(),
            self.requester_tags.as_str(),
            self.evidence_audience.as_str(),
            self.grant_id.as_str(),
            self.grant_authority.as_str(),
        ];
        names.extend(self.actor.as_deref());
        for name in &names {
            if name.trim().is_empty() || name.len() > 128 {
                return Err(ConfigError::Invalid("claim names must be 1..=128 bytes"));
            }
        }
        // A duplicated name would make one claim silently overwrite another,
        // so authority could be smuggled through the wrong field.
        let unique = names.iter().collect::<BTreeSet<_>>();
        if unique.len() != names.len() {
            return Err(ConfigError::Invalid("claim names must be distinct"));
        }
        // These are written by Mint itself and must not be overridable. Minting
        // writes the registered claims last, so any of these reused as a claim
        // name would silently replace what Mint decided with what the registry
        // did: an `aud` shadow yields a token whose audience is the principal
        // and which still verifies.
        for reserved in ["iss", "aud", "exp", "iat", "nbf", "jti", "client_id"] {
            if names.contains(&reserved) {
                return Err(ConfigError::Invalid(
                    "authority claim names must not shadow registered JWT claims",
                ));
            }
        }
        // `sub` is the exception. It always carries the principal, so naming
        // the principal claim `sub` rewrites the same value and is the default;
        // any other claim named `sub` would replace the principal.
        if names.iter().skip(1).any(|name| *name == "sub") {
            return Err(ConfigError::Invalid(
                "authority claim names must not shadow registered JWT claims",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessTokenConfig {
    /// The `aud` written into minted tokens. Matches the resource server's
    /// configured audiences.
    pub audiences: Vec<String>,
    pub lifetime_seconds: u64,
    pub claims: ClaimNames,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientAssertionConfig {
    /// The value clients must set as the assertion `aud`. Binding assertions to
    /// this endpoint stops one presented to another service being replayed here.
    pub audience: String,
    #[serde(default = "default_assertion_lifetime_seconds")]
    pub maximum_lifetime_seconds: u64,
    pub algorithms: Vec<Algorithm>,
    #[serde(default = "default_replay_cache_entries")]
    pub replay_cache_entries: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientsConfig {
    /// Directory of per-client registration files, relative to the config file.
    pub directory: PathBuf,
}

/// The transport validation boundary selected for this Mint process.
///
/// The strict default preserves Mint's HTTPS-only deployment contract.
/// `SupervisedLocalDevelopment` is an explicit exception for a supervised
/// process pair on one canonical loopback origin.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ValidationMode {
    #[default]
    Strict,
    SupervisedLocalDevelopment,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintConfig {
    pub version: u32,
    #[serde(default)]
    pub validation_mode: ValidationMode,
    pub issuer: String,
    pub listener: ListenerConfig,
    pub signing: SigningConfig,
    pub signer: SignerConfig,
    pub secret_providers: SecretProvidersConfig,
    pub audit: AuditConfig,
    pub access_tokens: AccessTokenConfig,
    pub client_assertion: ClientAssertionConfig,
    pub clients: ClientsConfig,
}

impl MintConfig {
    /// Load and validate a configuration document, resolving governed public
    /// keys, audit storage, and the client registry relative to its directory.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|_| ConfigError::Unavailable)?;
        let mut config: Self = serde_norway::from_str(&text)
            .map_err(|error| ConfigError::Document(error.to_string()))?;
        let root = path
            .parent()
            .ok_or(ConfigError::Invalid("configuration path has no parent"))?;
        config.resolve_paths(root);
        config.validate()?;
        Ok(config)
    }

    fn resolve_paths(&mut self, root: &Path) {
        let resolve = |path: &Path| -> PathBuf {
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                root.join(path)
            }
        };
        self.signing.active_public_jwk_file = resolve(&self.signing.active_public_jwk_file);
        self.signing.published_public_jwk_files = self
            .signing
            .published_public_jwk_files
            .iter()
            .map(|path| resolve(path))
            .collect();
        self.audit.path = resolve(&self.audit.path);
        self.clients.directory = resolve(&self.clients.directory);
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.version != 1 {
            return Err(ConfigError::Invalid(
                "only configuration version 1 is supported",
            ));
        }
        match self.validation_mode {
            ValidationMode::Strict => validate_https_issuer(&self.issuer)?,
            ValidationMode::SupervisedLocalDevelopment => {
                if self.issuer.starts_with("https://") {
                    validate_https_issuer(&self.issuer)?;
                    validate_https_endpoint(&self.client_assertion.audience)?;
                } else {
                    self.validate_supervised_local_development_transport()?;
                }
            }
        }
        self.listener.bind_address()?;
        self.listener.validate()?;

        if self.signing.algorithm != Algorithm::ES256 {
            return Err(ConfigError::Invalid(
                "Mint service signing algorithm must be ES256",
            ));
        }
        if self.signing.active_public_jwk_file.as_os_str().is_empty() {
            return Err(ConfigError::Invalid("active public JWK file is required"));
        }
        if self.signing.published_public_jwk_files.len() > 32 {
            return Err(ConfigError::Invalid(
                "active and published public key set must contain at most 33 keys",
            ));
        }
        if self.signing.revoked_key_ids.len() > 33
            || self
                .signing
                .revoked_key_ids
                .iter()
                .any(|kid| !is_thumbprint_key_id(kid))
            || self
                .signing
                .revoked_key_ids
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != self.signing.revoked_key_ids.len()
        {
            return Err(ConfigError::Invalid(
                "revoked key ids must be unique 43-character RFC 7638 thumbprints",
            ));
        }
        match (&self.validation_mode, &self.signer) {
            (ValidationMode::Strict, SignerConfig::Transit { .. })
            | (ValidationMode::SupervisedLocalDevelopment, SignerConfig::LocalJwk { .. })
            | (ValidationMode::SupervisedLocalDevelopment, SignerConfig::Transit { .. }) => {}
            (ValidationMode::Strict, SignerConfig::LocalJwk { .. }) => {
                return Err(ConfigError::Invalid(
                    "strict mode requires a Transit signer",
                ));
            }
        }
        match &self.signer {
            SignerConfig::LocalJwk { private_key_ref } => {
                validate_file_secret_ref(private_key_ref)?;
            }
            SignerConfig::Transit {
                unix_socket_path,
                mount,
                key_name,
                key_version,
                timeout_milliseconds,
            } => {
                if !unix_socket_path.is_absolute()
                    || !valid_transit_name(mount)
                    || !valid_transit_name(key_name)
                    || *key_version == 0
                    || !(1..=30_000).contains(timeout_milliseconds)
                {
                    return Err(ConfigError::Invalid(
                        "Transit signer requires an absolute Unix socket, simple mount and key names, a non-zero key version, and a 1..=30000 millisecond timeout",
                    ));
                }
            }
        }
        if !self.secret_providers.file.root.is_absolute() {
            return Err(ConfigError::Invalid(
                "secret provider file root must be absolute",
            ));
        }
        if !self.signing.jwks_path.starts_with('/') {
            return Err(ConfigError::Invalid("jwks path must be absolute"));
        }
        if !is_plain_route_path(&self.signing.jwks_path) {
            return Err(ConfigError::Invalid(
                "jwks path must be a plain absolute path with no query, fragment, or route pattern",
            ));
        }
        if MINT_FIXED_ROUTES.contains(&self.signing.jwks_path.as_str()) {
            return Err(ConfigError::Invalid(
                "jwks path must not take a route Mint already serves",
            ));
        }
        if self.audit.path.as_os_str().is_empty() || self.audit.hash_key_version == 0 {
            return Err(ConfigError::Invalid(
                "audit path, hash key reference, and non-zero hash key version are required",
            ));
        }
        validate_file_secret_ref(&self.audit.hash_key_ref)?;
        if !(1_048_576..=1_099_511_627_776).contains(&self.audit.maximum_file_bytes) {
            return Err(ConfigError::Invalid(
                "audit maximumFileBytes must be 1048576..=1099511627776",
            ));
        }
        let audit_secret_path = self
            .secret_providers
            .file
            .root
            .join(file_secret_name(&self.audit.hash_key_ref));
        if self.audit.path == audit_secret_path
            || matches!(
                &self.signer,
                SignerConfig::LocalJwk { private_key_ref }
                    if private_key_ref == &self.audit.hash_key_ref
                        || self.audit.path
                            == self.secret_providers.file.root.join(file_secret_name(private_key_ref))
            )
        {
            return Err(ConfigError::Invalid(
                "audit storage, audit key, and local signing material must be distinct",
            ));
        }

        if self.access_tokens.audiences.is_empty() || self.access_tokens.audiences.len() > 16 {
            return Err(ConfigError::Invalid(
                "between 1 and 16 audiences are required",
            ));
        }
        for audience in &self.access_tokens.audiences {
            if audience.trim().is_empty() || audience.len() > 512 {
                return Err(ConfigError::Invalid("audiences must be 1..=512 bytes"));
            }
        }
        // A long-lived bearer token is the thing Mint exists to avoid, and a
        // token shorter than the verifier's clock skew is unusable.
        if !(60..=3600).contains(&self.access_tokens.lifetime_seconds) {
            return Err(ConfigError::Invalid(
                "access token lifetime must be 60..=3600 seconds",
            ));
        }
        self.access_tokens.claims.validate()?;

        if self.validation_mode == ValidationMode::Strict {
            validate_https_endpoint(&self.client_assertion.audience)?;
        }
        if !(30..=600).contains(&self.client_assertion.maximum_lifetime_seconds) {
            return Err(ConfigError::Invalid(
                "client assertion lifetime must be 30..=600 seconds",
            ));
        }
        if self.client_assertion.algorithms.is_empty() {
            return Err(ConfigError::Invalid(
                "at least one client assertion algorithm is required",
            ));
        }
        if self.client_assertion.replay_cache_entries < 256 {
            return Err(ConfigError::Invalid(
                "the replay cache must hold at least 256 entries",
            ));
        }
        Ok(())
    }

    fn validate_supervised_local_development_transport(&self) -> Result<(), ConfigError> {
        let port = parse_canonical_supervised_local_origin(&self.issuer)?;
        if self.listener.address != "127.0.0.1" || self.listener.port != port {
            return Err(ConfigError::Invalid(
                "supervised local development listener must exactly match its canonical issuer origin",
            ));
        }
        if self.signing.jwks_path != MINT_JWKS_PATH {
            return Err(ConfigError::Invalid(
                "supervised local development JWKS path must match the fixed Mint path",
            ));
        }
        if self.client_assertion.audience != format!("{}{MINT_TOKEN_PATH}", self.issuer) {
            return Err(ConfigError::Invalid(
                "supervised local development client assertion audience must match the fixed Mint token endpoint",
            ));
        }
        Ok(())
    }
}

/// Accept only a path that survives both trips the JWKS path has to make.
///
/// The router registers this string literally and the metadata document
/// publishes it as `jwks_uri`. A query or fragment is lost on the way back: a
/// client fetching the advertised URI sends the path alone, so it would never
/// reach a route registered with the decoration attached. A route pattern is
/// the opposite failure, matching paths the metadata never advertised. Either
/// way Mint reports itself ready while its published key set does not resolve,
/// which is an outage no probe can see.
///
/// So: one or more non-empty segments of unreserved path characters, no dot
/// segments, and nothing that could be read as a pattern.
fn is_plain_route_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    rest.split('/').all(|segment| {
        !segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
            })
    })
}

fn is_thumbprint_key_id(value: &str) -> bool {
    if value.len() != 43 {
        return false;
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|bytes| bytes.len() == 32 && URL_SAFE_NO_PAD.encode(bytes) == value)
}

fn validate_file_secret_ref(reference: &str) -> Result<(), ConfigError> {
    let Some(name) = reference.strip_prefix("secret:file/") else {
        return Err(ConfigError::Invalid(
            "secret references must use the exact secret:file/<name> grammar",
        ));
    };
    let bytes = name.as_bytes();
    if !matches!(bytes.first(), Some(b'a'..=b'z'))
        || bytes.len() > 128
        || !bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(ConfigError::Invalid(
            "secret references must use the exact secret:file/<name> grammar",
        ));
    }
    Ok(())
}

fn file_secret_name(reference: &str) -> &str {
    reference
        .strip_prefix("secret:file/")
        .expect("validated file secret reference")
}

fn valid_transit_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// Parse the only HTTP origin admitted for supervised local development.
///
/// Exact reconstruction rejects URL-parser aliases such as a trailing slash,
/// leading-zero port, alternate IPv4 spelling, credentials, query, or fragment.
fn parse_canonical_supervised_local_origin(value: &str) -> Result<u16, ConfigError> {
    let port = value
        .strip_prefix("http://127.0.0.1:")
        .filter(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
        .filter(|port| !port.starts_with('0'))
        .and_then(|port| port.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or(ConfigError::Invalid(
            "supervised local development issuer must be a canonical 127.0.0.1 HTTP origin with an explicit non-zero port",
        ))?;
    if value != format!("http://127.0.0.1:{port}") {
        return Err(ConfigError::Invalid(
            "supervised local development issuer must be a canonical 127.0.0.1 HTTP origin with an explicit non-zero port",
        ));
    }
    Ok(port)
}

/// Require an issuer that is `https`, has a host, and carries no credentials,
/// query, or fragment. Resource servers compare this string exactly, so any
/// variable part of it would weaken the comparison.
pub fn validate_https_issuer(issuer: &str) -> Result<(), ConfigError> {
    let url =
        Url::parse(issuer).map_err(|_| ConfigError::Invalid("issuer must be an absolute URL"))?;
    if url.scheme() != "https" {
        return Err(ConfigError::Invalid("issuer must use https"));
    }
    if !url.has_host() {
        return Err(ConfigError::Invalid("issuer must have a host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ConfigError::Invalid("issuer must not carry credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(ConfigError::Invalid(
            "issuer must not carry a query or fragment",
        ));
    }
    Ok(())
}

fn validate_https_endpoint(endpoint: &str) -> Result<(), ConfigError> {
    let url = Url::parse(endpoint)
        .map_err(|_| ConfigError::Invalid("client assertion audience must be an absolute URL"))?;
    if url.scheme() != "https" {
        return Err(ConfigError::Invalid(
            "client assertion audience must use https",
        ));
    }
    if !url.has_host() {
        return Err(ConfigError::Invalid(
            "client assertion audience must have a host",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ConfigError::Invalid(
            "client assertion audience must not carry credentials",
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(ConfigError::Invalid(
            "client assertion audience must not carry a query or fragment",
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::fs;

    pub(crate) const VALID: &str = r#"
version: 1
issuer: https://mint.example.org
listener: {address: 127.0.0.1, port: 8081}
signing:
  algorithm: ES256
  activePublicJwkFile: public-keys/mint.jwk.json
  publishedPublicJwkFiles: []
  revokedKeyIds: []
signer:
  kind: transit
  unixSocketPath: /run/registry-mint/transit-proxy.sock
  mount: transit
  keyName: mint-signing
  keyVersion: 7
  timeoutMilliseconds: 2000
secretProviders:
  file: {root: /run/registry-mint/secrets}
audit:
  path: audit/mint.jsonl
  maximumFileBytes: 1073741824
  hashKeyRef: secret:file/audit-hmac-key
  hashKeyVersion: 1
accessTokens:
  audiences: [evidence]
  lifetimeSeconds: 300
  claims:
    principal: sub
    requesterTags: evidence_tags
    evidenceAudience: evidence_audience
    grantId: evidence_grant_id
    grantAuthority: evidence_authority
clientAssertion:
  audience: https://mint.example.org/token
  algorithms: [EdDSA]
clients:
  directory: clients
"#;

    fn load_from(text: &str) -> Result<MintConfig, ConfigError> {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("mint.yaml");
        fs::write(&path, text).expect("write config");
        MintConfig::load(&path)
    }

    fn load_error(text: &str) -> ConfigError {
        load_from(text).expect_err("the document must be rejected")
    }

    /// A valid configuration for tests in other modules that need one but do
    /// not exercise loading itself.
    pub(crate) fn sample_config() -> MintConfig {
        load_from(VALID).expect("the sample configuration is valid")
    }

    #[test]
    fn a_valid_document_loads_and_resolves_paths_against_the_config_directory() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("mint.yaml");
        fs::write(&path, VALID).expect("write config");
        let config = MintConfig::load(&path).expect("valid config loads");

        assert_eq!(config.issuer, "https://mint.example.org");
        assert_eq!(config.validation_mode, ValidationMode::Strict);
        assert_eq!(
            config.signing.active_public_jwk_file,
            directory.path().join("public-keys/mint.jwk.json")
        );
        assert_eq!(config.clients.directory, directory.path().join("clients"));
        assert_eq!(config.audit.path, directory.path().join("audit/mint.jsonl"));
        assert_eq!(config.audit.maximum_file_bytes, 1_073_741_824);
        assert_eq!(config.audit.hash_key_ref, "secret:file/audit-hmac-key");
        assert_eq!(config.audit.hash_key_version, 1);
        assert_eq!(config.signing.jwks_path, "/.well-known/jwks.json");
        assert_eq!(config.client_assertion.maximum_lifetime_seconds, 300);
    }

    #[test]
    fn audit_configuration_is_required_bounded_and_separate_from_secrets() {
        assert!(load_from(&VALID.replace(
            "audit:\n  path: audit/mint.jsonl\n  maximumFileBytes: 1073741824\n  hashKeyRef: secret:file/audit-hmac-key\n  hashKeyVersion: 1\n",
            ""
        ))
        .is_err());
        assert_eq!(
            load_error(&VALID.replace("hashKeyVersion: 1", "hashKeyVersion: 0")),
            ConfigError::Invalid(
                "audit path, hash key reference, and non-zero hash key version are required"
            )
        );
        assert_eq!(
            load_error(&VALID.replace("maximumFileBytes: 1073741824", "maximumFileBytes: 1024")),
            ConfigError::Invalid("audit maximumFileBytes must be 1048576..=1099511627776")
        );
        assert_eq!(
            load_error(&VALID.replace(
                "path: audit/mint.jsonl",
                "path: /run/registry-mint/secrets/audit-hmac-key"
            )),
            ConfigError::Invalid(
                "audit storage, audit key, and local signing material must be distinct"
            )
        );
    }

    #[test]
    fn a_jwks_path_may_not_take_a_route_mint_already_serves() {
        for path in MINT_FIXED_ROUTES {
            let text = VALID.replace(
                "activePublicJwkFile: public-keys/mint.jwk.json",
                &format!("activePublicJwkFile: public-keys/mint.jwk.json\n  jwksPath: {path}"),
            );
            assert_eq!(
                load_error(&text),
                ConfigError::Invalid("jwks path must not take a route Mint already serves"),
                "jwks path {path} must be rejected"
            );
        }
    }

    #[test]
    fn a_jwks_path_must_be_a_path_a_client_can_fetch() {
        // The path is registered as a route and published as `jwks_uri`. A
        // query or fragment survives neither trip: the router matches the
        // literal string, and a client sends only the path back. A route
        // pattern is worse, because it matches paths the metadata never named.
        for path in [
            "/keys?tenant=a",
            "/keys#v1",
            "/keys/{tenant}",
            "/{*rest}",
            "/keys//v1",
            "/keys/",
            "/keys/../token",
            "/keys/.",
            "/keys v1",
            "/keys%2ftoken",
        ] {
            let text = VALID.replace(
                "activePublicJwkFile: public-keys/mint.jwk.json",
                &format!("activePublicJwkFile: public-keys/mint.jwk.json\n  jwksPath: \"{path}\""),
            );
            assert_eq!(
                load_error(&text),
                ConfigError::Invalid("jwks path must be a plain absolute path with no query, fragment, or route pattern"),
                "jwks path {path} must be rejected"
            );
        }
    }

    #[test]
    fn a_plain_absolute_jwks_path_is_accepted() {
        for path in [
            "/.well-known/jwks.json",
            "/keys",
            "/v1/keys.json",
            "/a~b-c_d",
        ] {
            let text = VALID.replace(
                "activePublicJwkFile: public-keys/mint.jwk.json",
                &format!("activePublicJwkFile: public-keys/mint.jwk.json\n  jwksPath: \"{path}\""),
            );
            let config = load_from(&text).expect("a plain absolute path loads");
            assert_eq!(config.signing.jwks_path, path);
        }
    }

    #[test]
    fn listener_limits_must_admit_a_request() {
        for (field, value) in [
            ("maximumRequestBytes", 0),
            ("maximumRequestBytes", 1_048_577),
            ("requestTimeoutMilliseconds", 0),
            ("requestTimeoutMilliseconds", 30_001),
        ] {
            let text = VALID.replace(
                "listener: {address: 127.0.0.1, port: 8081}",
                &format!("listener: {{address: 127.0.0.1, port: 8081, {field}: {value}}}"),
            );
            assert!(
                matches!(load_from(&text), Err(ConfigError::Invalid(_))),
                "{field} {value} must be rejected"
            );
        }
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let text = VALID.replace("version: 1", "version: 1\nunexpected: true");
        assert!(matches!(load_from(&text), Err(ConfigError::Document(_))));
    }

    #[test]
    fn issuers_must_be_https_hosts_without_credentials_or_query() {
        for issuer in [
            "http://mint.example.org",
            "https://user:pass@mint.example.org",
            "https://mint.example.org?tenant=a",
            "https://mint.example.org#frag",
            "mint.example.org",
            "https://",
        ] {
            let text = VALID.replace("https://mint.example.org\n", &format!("{issuer}\n"));
            assert!(
                matches!(load_from(&text), Err(ConfigError::Invalid(_))),
                "issuer {issuer} must be rejected"
            );
        }
    }

    #[test]
    fn supervised_local_development_accepts_only_the_exact_mint_transport() {
        let local = VALID
            .replace(
                "version: 1",
                "version: 1\nvalidationMode: supervised-local-development",
            )
            .replace(
                "issuer: https://mint.example.org",
                "issuer: http://127.0.0.1:8081",
            )
            .replace(
                "audience: https://mint.example.org/token",
                "audience: http://127.0.0.1:8081/token",
            )
            .replace(
                "signer:\n  kind: transit\n  unixSocketPath: /run/registry-mint/transit-proxy.sock\n  mount: transit\n  keyName: mint-signing\n  keyVersion: 7\n  timeoutMilliseconds: 2000",
                "signer:\n  kind: local-jwk\n  privateKeyRef: secret:file/mint-signing",
            );
        let config = load_from(&local).expect("the supervised local transport is valid");
        assert_eq!(
            config.validation_mode,
            ValidationMode::SupervisedLocalDevelopment
        );

        for port in [1_u16, u16::MAX] {
            let boundary = local.replace("8081", &port.to_string());
            load_from(&boundary).unwrap_or_else(|error| {
                panic!("canonical boundary port {port} must be accepted: {error}")
            });
        }

        for invalid_issuer in [
            "http://localhost:8081",
            "http://[::1]:8081",
            "http://127.0.0.2:8081",
            "http://127.00.0.1:8081",
            "http://127.0.0.1",
            "http://127.0.0.1:0",
            "http://127.0.0.1:08081",
            "http://127.0.0.1:65536",
            "http://user@127.0.0.1:8081",
            "http://127.0.0.1:8081/",
            "http://127.0.0.1:8081?tenant=x",
            "http://127.0.0.1:8081#fragment",
            "https://127.0.0.1:8081",
        ] {
            let invalid = local.replace(
                "issuer: http://127.0.0.1:8081",
                &format!("issuer: {invalid_issuer}"),
            );
            assert!(
                load_from(&invalid).is_err(),
                "accepted supervised local issuer {invalid_issuer}"
            );
        }

        for invalid_audience in [
            "http://127.0.0.1:8081",
            "http://127.0.0.1:8081/token/",
            "http://127.0.0.1:8081/TOKEN",
            "http://127.0.0.1:8081/oauth/token",
            "http://127.0.0.1:8081/token?tenant=x",
            "http://127.0.0.1:8081/token#fragment",
            "http://127.0.0.1:8082/token",
        ] {
            let invalid = local.replace(
                "audience: http://127.0.0.1:8081/token",
                &format!("audience: {invalid_audience}"),
            );
            assert!(
                load_from(&invalid).is_err(),
                "accepted supervised local assertion audience {invalid_audience}"
            );
        }

        for replacement in [
            "listener: {address: 127.0.0.2, port: 8081}",
            "listener: {address: 127.0.0.1, port: 8082}",
            "listener: {address: 127.0.0.1, port: 0}",
        ] {
            let invalid = local.replace("listener: {address: 127.0.0.1, port: 8081}", replacement);
            assert!(
                load_from(&invalid).is_err(),
                "accepted mismatched listener {replacement}"
            );
        }

        let wrong_jwks = local.replace(
            "activePublicJwkFile: public-keys/mint.jwk.json",
            "activePublicJwkFile: public-keys/mint.jwk.json\n  jwksPath: /.well-known/keys.json",
        );
        assert!(
            load_from(&wrong_jwks).is_err(),
            "accepted a non-Mint JWKS path"
        );
    }

    #[test]
    fn strict_mode_is_the_https_only_default() {
        let default = load_from(VALID).expect("the existing strict document remains valid");
        assert_eq!(default.validation_mode, ValidationMode::Strict);

        let explicit = VALID.replace("version: 1", "version: 1\nvalidationMode: strict");
        assert_eq!(
            load_from(&explicit)
                .expect("the explicit strict mode is valid")
                .validation_mode,
            ValidationMode::Strict
        );

        let local_without_mode = VALID
            .replace(
                "issuer: https://mint.example.org",
                "issuer: http://127.0.0.1:8081",
            )
            .replace(
                "audience: https://mint.example.org/token",
                "audience: http://127.0.0.1:8081/token",
            );
        assert!(
            load_from(&local_without_mode).is_err(),
            "strict Mint inherited the local HTTP exception"
        );

        for invalid_audience in [
            "http://127.0.0.1:8081/token",
            "https://user:pass@mint.example.org/token",
            "https://mint.example.org/token?tenant=x",
            "https://mint.example.org/token#fragment",
            "mint.example.org/token",
            "https://",
        ] {
            let invalid = VALID.replace(
                "audience: https://mint.example.org/token",
                &format!("audience: {invalid_audience}"),
            );
            assert!(
                load_from(&invalid).is_err(),
                "strict Mint accepted assertion audience {invalid_audience}"
            );
        }
    }

    #[test]
    fn signer_kind_follows_the_assurance_matrix() {
        let strict_local = VALID.replace(
            "signer:\n  kind: transit\n  unixSocketPath: /run/registry-mint/transit-proxy.sock\n  mount: transit\n  keyName: mint-signing\n  keyVersion: 7\n  timeoutMilliseconds: 2000",
            "signer:\n  kind: local-jwk\n  privateKeyRef: secret:file/mint-signing",
        );
        assert_eq!(
            load_error(&strict_local),
            ConfigError::Invalid("strict mode requires a Transit signer")
        );

        let supervised_transit = VALID
            .replace(
                "version: 1",
                "version: 1\nvalidationMode: supervised-local-development",
            )
            .replace(
                "issuer: https://mint.example.org",
                "issuer: http://127.0.0.1:8081",
            )
            .replace(
                "audience: https://mint.example.org/token",
                "audience: http://127.0.0.1:8081/token",
            );
        load_from(&supervised_transit).expect("supervised local mode also permits Transit");
    }

    #[test]
    fn service_signing_is_fixed_to_es256_and_thumbprint_revocations() {
        assert_eq!(
            load_error(&VALID.replace("algorithm: ES256", "algorithm: EdDSA")),
            ConfigError::Invalid("Mint service signing algorithm must be ES256")
        );
        let noncanonical = format!("{}B", "A".repeat(42));
        for revoked in [
            "short",
            "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
            &noncanonical,
        ] {
            let document =
                VALID.replace("revokedKeyIds: []", &format!("revokedKeyIds: [{revoked}]"));
            assert!(
                load_from(&document).is_err(),
                "accepted revoked id {revoked}"
            );
        }
    }

    #[test]
    fn access_token_lifetime_is_bounded_on_both_sides() {
        for lifetime in ["1", "59", "3601", "86400"] {
            let text = VALID.replace(
                "lifetimeSeconds: 300",
                &format!("lifetimeSeconds: {lifetime}"),
            );
            assert_eq!(
                load_error(&text),
                ConfigError::Invalid("access token lifetime must be 60..=3600 seconds"),
                "lifetime {lifetime} must be rejected"
            );
        }
    }

    #[test]
    fn duplicate_claim_names_are_rejected() {
        let text = VALID.replace("grantId: evidence_grant_id", "grantId: evidence_tags");
        assert_eq!(
            load_error(&text),
            ConfigError::Invalid("claim names must be distinct")
        );
    }

    #[test]
    fn authority_claims_cannot_shadow_registered_jwt_claims() {
        for reserved in ["iss", "aud", "exp", "jti", "client_id"] {
            let text = VALID.replace(
                "requesterTags: evidence_tags",
                &format!("requesterTags: {reserved}"),
            );
            assert_eq!(
                load_error(&text),
                ConfigError::Invalid("authority claim names must not shadow registered JWT claims"),
                "claim {reserved} must be rejected"
            );
        }
    }

    #[test]
    fn the_principal_claim_is_bound_by_the_same_rule_as_the_others() {
        // Minting writes the registered claims after the JWT ones, so a
        // principal named for a reserved claim would overwrite it. `aud` is the
        // one that matters most: the token would carry the principal as its
        // audience and still verify.
        for reserved in ["iss", "aud", "exp", "iat", "nbf", "jti", "client_id"] {
            let text = VALID.replace("principal: sub", &format!("principal: {reserved}"));
            assert_eq!(
                load_error(&text),
                ConfigError::Invalid("authority claim names must not shadow registered JWT claims"),
                "principal {reserved} must be rejected"
            );
        }
    }

    #[test]
    fn only_the_principal_may_be_named_sub() {
        // `sub` always carries the principal, so naming the principal claim
        // `sub` is the default and merely rewrites the same value.
        load_from(VALID).expect("principal may be named sub");

        // Any other claim named `sub` would replace the principal with its own
        // value, which for requester tags is not even a string. The principal
        // moves off `sub` first, so this is the shadowing rule answering rather
        // than the distinctness rule.
        let renamed = VALID.replace("principal: sub", "principal: evidence_principal");
        for field in [
            "requesterTags: evidence_tags",
            "evidenceAudience: evidence_audience",
            "grantId: evidence_grant_id",
            "grantAuthority: evidence_authority",
        ] {
            let name = field.split(':').next().expect("a claim field name");
            let text = renamed.replace(field, &format!("{name}: sub"));
            assert_eq!(
                load_error(&text),
                ConfigError::Invalid("authority claim names must not shadow registered JWT claims"),
                "{name} must not be named sub"
            );
        }
    }

    #[test]
    fn the_actor_claim_is_optional_and_obeys_every_other_claim_name_rule() {
        // A deployment that never delegates names no actor claim at all.
        assert!(sample_config().access_tokens.claims.actor.is_none());

        let with_actor = |name: &str| {
            VALID.replace(
                "grantAuthority: evidence_authority",
                &format!("grantAuthority: evidence_authority\n    actor: {name}"),
            )
        };

        let config = load_from(&with_actor("evidence_actor")).expect("an actor claim is accepted");
        assert_eq!(
            config.access_tokens.claims.actor.as_deref(),
            Some("evidence_actor")
        );

        // Reusing another authority claim would let the actor overwrite it.
        assert_eq!(
            load_error(&with_actor("evidence_tags")),
            ConfigError::Invalid("claim names must be distinct")
        );
        assert_eq!(
            load_error(&with_actor("client_id")),
            ConfigError::Invalid("authority claim names must not shadow registered JWT claims")
        );
        assert_eq!(
            load_error(&with_actor("\"\"")),
            ConfigError::Invalid("claim names must be 1..=128 bytes")
        );
    }

    #[test]
    fn version_must_be_one_and_audiences_must_be_present() {
        let text = VALID.replace("version: 1", "version: 2");
        assert_eq!(
            load_error(&text),
            ConfigError::Invalid("only configuration version 1 is supported")
        );

        let text = VALID.replace("audiences: [evidence]", "audiences: []");
        assert_eq!(
            load_error(&text),
            ConfigError::Invalid("between 1 and 16 audiences are required")
        );
    }
}
