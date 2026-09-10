use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use jsonwebtoken::Algorithm;
use registry_casework_core::CaseworkProject;
use registry_platform_config::SecretResolver;
use registry_platform_oidc::{
    fetch_discovery, JwksFetcher, JwksFetcherConfig, OidcDiscoveryConfig, TokenVerifierConfig,
};
use serde::Deserialize;
use thiserror::Error;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    pub project: PathBuf,
    pub listen: SocketAddr,
    pub tls_termination: TlsTermination,
    #[serde(default)]
    pub network_exposure: ListenerNetworkExposure,
    pub secret_providers: SecretProvidersConfig,
    pub database: DatabaseConfig,
    pub authentication: AuthenticationConfig,
    pub audit: AuditConfig,
    #[serde(default)]
    pub sources: BTreeMap<String, registry_casework_breg::BregBinding>,
}

/// Declares the trusted transport boundary for the runtime's plaintext HTTP listener.
///
/// Production listeners require operator-controlled upstream TLS termination.
/// Direct plaintext is limited to the explicit loopback-only development mode.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum TlsTermination {
    OperatorControlledUpstream,
    DevelopmentLoopback,
}

/// The operator-declared private network placement of the HTTP listener.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ListenerNetworkExposure {
    #[default]
    PrivateAddress,
    ContainerPrivate,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretProvidersConfig {
    pub file: FileSecretProviderConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileSecretProviderConfig {
    pub root: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticationConfig {
    pub oidc: OidcConfig,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DatabaseConfig {
    pub runtime_url_ref: String,
    pub migration_url_ref: String,
    #[serde(default)]
    pub trusted_root_certificate_ref: Option<String>,
    #[serde(default)]
    pub test_only_plaintext: bool,
}

impl std::fmt::Debug for DatabaseConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OidcConfig {
    pub issuer: String,
    pub audience: String,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub jwks_source: OidcJwksSource,
    #[serde(default = "default_principal_claim")]
    pub principal_claim: String,
    #[serde(default = "default_scope_claim")]
    pub scope_claim: String,
    #[serde(default)]
    pub human_identity: HumanIdentityConfig,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HumanIdentityConfig {
    #[serde(default = "default_human_identity_claim")]
    pub claim: String,
    #[serde(default = "default_human_identity_value")]
    pub value: String,
}

impl Default for HumanIdentityConfig {
    fn default() -> Self {
        Self {
            claim: default_human_identity_claim(),
            value: default_human_identity_value(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum OidcJwksSource {
    #[default]
    Discovery,
    Static {
        #[serde(rename = "documentRef")]
        document_ref: String,
    },
}

fn default_principal_claim() -> String {
    "sub".to_owned()
}
fn default_scope_claim() -> String {
    "registry_scopes".to_owned()
}
fn default_human_identity_claim() -> String {
    "registry_actor_kind".to_owned()
}
fn default_human_identity_value() -> String {
    "human".to_owned()
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditConfig {
    pub path: PathBuf,
    pub secret_ref: String,
}

impl RuntimeConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RuntimeConfigError> {
        let bytes = std::fs::read(path.as_ref()).map_err(RuntimeConfigError::Read)?;
        let mut config: Self =
            serde_norway::from_slice(&bytes).map_err(RuntimeConfigError::Parse)?;
        let parent = path.as_ref().parent().unwrap_or_else(|| Path::new("."));
        if config.project.is_relative() {
            config.project = parent.join(&config.project);
        }
        if config.secret_providers.file.root.is_relative() {
            config.secret_providers.file.root = parent.join(&config.secret_providers.file.root);
        }
        if config.audit.path.is_relative() {
            config.audit.path = parent.join(&config.audit.path);
        }
        config.check()?;
        Ok(config)
    }

    pub fn check(&self) -> Result<(), RuntimeConfigError> {
        let project = CaseworkProject::load(&self.project).map_err(RuntimeConfigError::Project)?;
        if !valid_listener(
            self.listen.ip(),
            self.network_exposure,
            self.tls_termination,
        ) || self.authentication.oidc.issuer.is_empty()
            || self.authentication.oidc.audience.is_empty()
            || self.authentication.oidc.principal_claim.is_empty()
            || self.authentication.oidc.scope_claim.is_empty()
            || self.authentication.oidc.human_identity.claim.is_empty()
            || self.authentication.oidc.human_identity.value.is_empty()
            || self.authentication.oidc.human_identity.claim == self.authentication.oidc.scope_claim
            || project.access_profiles.iter().any(|profile| {
                profile.principal_claim == self.authentication.oidc.human_identity.claim
            })
            || self.database.runtime_url_ref.is_empty()
            || self.database.migration_url_ref.is_empty()
            || self.audit.secret_ref.is_empty()
            || self.sources.keys().any(String::is_empty)
        {
            return Err(RuntimeConfigError::Invalid);
        }
        #[cfg(not(feature = "postgres-test"))]
        if self.database.test_only_plaintext {
            return Err(RuntimeConfigError::PlaintextDatabase);
        }
        Ok(())
    }

    pub async fn oidc_verifier(
        &self,
        secrets: &SecretResolver,
    ) -> Result<(TokenVerifierConfig, std::sync::Arc<JwksFetcher>), RuntimeConfigError> {
        let discovery_config = OidcDiscoveryConfig {
            issuer: self.authentication.oidc.issuer.clone(),
            jwks_uri_override: self.authentication.oidc.jwks_uri.clone(),
            discovery_timeout: Duration::from_secs(5),
            max_doc_bytes: 1024 * 1024,
        };
        let fetcher = match &self.authentication.oidc.jwks_source {
            OidcJwksSource::Discovery => {
                let discovery = fetch_discovery(&discovery_config)
                    .await
                    .map_err(|_| RuntimeConfigError::Oidc)?;
                JwksFetcher::new(discovery.jwks_uri, JwksFetcherConfig::defaults())
            }
            OidcJwksSource::Static { document_ref } => {
                let document = secrets
                    .resolve(document_ref)
                    .map_err(|_| RuntimeConfigError::Oidc)?;
                let jwks = parse_static_jwks(document.expose_secret())?;
                JwksFetcher::new_static(jwks, JwksFetcherConfig::defaults())
            }
        };
        let verifier = TokenVerifierConfig::access_token_profile(
            self.authentication.oidc.issuer.clone(),
            vec![self.authentication.oidc.audience.clone()],
            vec![Algorithm::RS256, Algorithm::ES256],
            vec!["at+jwt".to_owned(), "JWT".to_owned()],
        )
        .with_scope_claim(self.authentication.oidc.scope_claim.clone());
        Ok((verifier, std::sync::Arc::new(fetcher)))
    }
}

fn valid_listener(
    address: IpAddr,
    exposure: ListenerNetworkExposure,
    tls_termination: TlsTermination,
) -> bool {
    if address.is_multicast() {
        return false;
    }
    if tls_termination == TlsTermination::DevelopmentLoopback {
        return exposure == ListenerNetworkExposure::PrivateAddress && address.is_loopback();
    }
    match (address, exposure) {
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

fn is_unique_local(address: Ipv6Addr) -> bool {
    address.octets()[0] & 0xfe == 0xfc
}

fn parse_static_jwks(bytes: &[u8]) -> Result<JwkSet, RuntimeConfigError> {
    let jwks: JwkSet = serde_json::from_slice(bytes).map_err(|_| RuntimeConfigError::Oidc)?;
    let mut kids = BTreeSet::new();
    if jwks.keys.is_empty()
        || jwks.keys.iter().any(|key| {
            !matches!(
                key.algorithm,
                AlgorithmParameters::RSA(_) | AlgorithmParameters::EllipticCurve(_)
            ) || key
                .common
                .key_id
                .as_ref()
                .is_none_or(|kid| kid.is_empty() || !kids.insert(kid.clone()))
        })
    {
        return Err(RuntimeConfigError::Oidc);
    }
    Ok(jwks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_jwks_requires_unique_named_asymmetric_keys() {
        assert!(parse_static_jwks(
            br#"{"keys":[{"kty":"RSA","kid":"one","n":"AQAB","e":"AQAB"}]}"#
        )
        .is_ok());
        for invalid in [br#"{}"#.as_slice(),br#"{"keys":[]}"#,br#"{"keys":[{"kty":"oct","kid":"one","k":"AA"}]}"#,br#"{"keys":[{"kty":"RSA","kid":"one","n":"AQAB","e":"AQAB"},{"kty":"RSA","kid":"one","n":"AQAB","e":"AQAB"}]}"#,b"not-json"] {
            assert!(parse_static_jwks(invalid).is_err());
        }
    }

    #[test]
    fn static_source_uses_document_ref_camel_case() {
        let source: OidcJwksSource =
            serde_json::from_str(r#"{"kind":"static","documentRef":"secret:file/keys.json"}"#)
                .expect("static source");
        assert!(
            matches!(source,OidcJwksSource::Static{document_ref} if document_ref=="secret:file/keys.json")
        );
    }

    #[test]
    fn human_identity_defaults_to_an_explicit_fail_closed_claim_contract() {
        let oidc: OidcConfig = serde_json::from_value(serde_json::json!({
            "issuer": "https://identity.example.test",
            "audience": "urn:example:casework"
        }))
        .expect("OIDC configuration");
        assert_eq!(
            oidc.human_identity,
            HumanIdentityConfig {
                claim: "registry_actor_kind".to_owned(),
                value: "human".to_owned(),
            }
        );
    }

    #[test]
    fn listener_requires_a_private_address_or_explicit_container_network() {
        use std::net::{Ipv4Addr, Ipv6Addr};

        assert!(valid_listener(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            ListenerNetworkExposure::PrivateAddress,
            TlsTermination::OperatorControlledUpstream,
        ));
        assert!(valid_listener(
            "10.20.30.40".parse().expect("private IPv4"),
            ListenerNetworkExposure::PrivateAddress,
            TlsTermination::OperatorControlledUpstream,
        ));
        assert!(!valid_listener(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            ListenerNetworkExposure::PrivateAddress,
            TlsTermination::OperatorControlledUpstream,
        ));
        assert!(valid_listener(
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ListenerNetworkExposure::ContainerPrivate,
            TlsTermination::OperatorControlledUpstream,
        ));
        assert!(!valid_listener(
            "203.0.113.10".parse().expect("public IPv4"),
            ListenerNetworkExposure::ContainerPrivate,
            TlsTermination::OperatorControlledUpstream,
        ));
        assert!(valid_listener(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            ListenerNetworkExposure::PrivateAddress,
            TlsTermination::DevelopmentLoopback,
        ));
        assert!(!valid_listener(
            "10.20.30.40".parse().expect("private IPv4"),
            ListenerNetworkExposure::PrivateAddress,
            TlsTermination::DevelopmentLoopback,
        ));
        assert!(!valid_listener(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            ListenerNetworkExposure::ContainerPrivate,
            TlsTermination::DevelopmentLoopback,
        ));
    }
}

#[derive(Debug, Error)]
pub enum RuntimeConfigError {
    #[error("the Casework runtime configuration could not be read")]
    Read(#[source] std::io::Error),
    #[error("the Casework runtime configuration is not valid YAML")]
    Parse(#[source] serde_norway::Error),
    #[error("the Casework project is invalid")]
    Project(#[source] registry_casework_core::ConfigLoadError),
    #[error("the Casework runtime configuration is invalid")]
    Invalid,
    #[error("plaintext PostgreSQL is test-only")]
    PlaintextDatabase,
    #[error("the OIDC issuer could not be initialized")]
    Oidc,
}
