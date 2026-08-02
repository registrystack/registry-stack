//! Startup-only Mint configuration.
//!
//! Everything in this file is fixed for the lifetime of the serving process:
//! issuer identity, signing keys, listener, and token policy. The one part of
//! Mint's state that is intentionally reloadable is the client registry, which
//! lives in [`crate::clients`].

use std::{
    collections::BTreeSet,
    net::IpAddr,
    path::{Path, PathBuf},
};

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
    "/.well-known/jwks.json".to_owned()
}

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
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SigningConfig {
    pub algorithm: Algorithm,
    pub active_key_id: String,
    /// Path to the private JWK, resolved relative to the configuration file.
    pub active_key_file: PathBuf,
    /// Public JWKs of keys that no longer sign but may still have live tokens.
    #[serde(default)]
    pub retired_public_jwk_files: Vec<PathBuf>,
    #[serde(default = "default_jwks_path")]
    pub jwks_path: String,
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
}

impl ClaimNames {
    fn validate(&self) -> Result<(), ConfigError> {
        let names = [
            self.principal.as_str(),
            self.requester_tags.as_str(),
            self.evidence_audience.as_str(),
            self.grant_id.as_str(),
            self.grant_authority.as_str(),
        ];
        for name in names {
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
        // These are written by Mint itself and must not be overridable.
        for reserved in ["iss", "aud", "exp", "iat", "nbf", "jti", "client_id"] {
            if names.iter().skip(1).any(|name| *name == reserved) {
                return Err(ConfigError::Invalid(
                    "authority claim names must not shadow registered JWT claims",
                ));
            }
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintConfig {
    pub version: u32,
    pub issuer: String,
    pub listener: ListenerConfig,
    pub signing: SigningConfig,
    pub access_tokens: AccessTokenConfig,
    pub client_assertion: ClientAssertionConfig,
    pub clients: ClientsConfig,
}

impl MintConfig {
    /// Load and validate a configuration document, resolving every path
    /// relative to the document's own directory.
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
        self.signing.active_key_file = resolve(&self.signing.active_key_file);
        self.signing.retired_public_jwk_files = self
            .signing
            .retired_public_jwk_files
            .iter()
            .map(|path| resolve(path))
            .collect();
        self.clients.directory = resolve(&self.clients.directory);
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.version != 1 {
            return Err(ConfigError::Invalid(
                "only configuration version 1 is supported",
            ));
        }
        validate_https_issuer(&self.issuer)?;
        self.listener.bind_address()?;

        if self.signing.active_key_id.trim().is_empty() || self.signing.active_key_id.len() > 256 {
            return Err(ConfigError::Invalid("active key id must be 1..=256 bytes"));
        }
        if !self.signing.jwks_path.starts_with('/') {
            return Err(ConfigError::Invalid("jwks path must be absolute"));
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

        let assertion_audience = Url::parse(&self.client_assertion.audience)
            .map_err(|_| ConfigError::Invalid("client assertion audience must be a URL"))?;
        if !assertion_audience.has_host() {
            return Err(ConfigError::Invalid(
                "client assertion audience must have a host",
            ));
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::fs;

    pub(crate) const VALID: &str = r#"
version: 1
issuer: https://mint.example.org
listener: {address: 127.0.0.1, port: 8081}
signing:
  algorithm: EdDSA
  activeKeyId: mint-2026-01
  activeKeyFile: secrets/signing.jwk
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
        assert_eq!(
            config.signing.active_key_file,
            directory.path().join("secrets/signing.jwk")
        );
        assert_eq!(config.clients.directory, directory.path().join("clients"));
        assert_eq!(config.signing.jwks_path, "/.well-known/jwks.json");
        assert_eq!(config.client_assertion.maximum_lifetime_seconds, 300);
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
