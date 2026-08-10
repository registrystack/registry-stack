//! Startup-only configuration for the delivery service.
//!
//! Everything here is fixed for the lifetime of the serving process: the
//! published credential issuer identifier, the listener, the Evidence
//! deployment this service requests credentials from, the identity it
//! authenticates to Mint with, and the bounds of the in-memory store.
//!
//! The document is read whole and validated whole, so a deployment either
//! starts on a coherent configuration or does not start. `check` runs this same
//! validation without opening a socket.

use std::{
    net::IpAddr,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use thiserror::Error;
use url::Url;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ConfigError {
    #[error("the configuration file is unavailable")]
    Unavailable,
    #[error("the configuration document is invalid: {0}")]
    Document(String),
    #[error("configuration is invalid: {0}")]
    Invalid(&'static str),
}

/// The transport validation boundary selected for this process.
///
/// The same two-axis vocabulary Mint uses, and deliberately no third assurance
/// concept: a delivery front end that graded itself on its own scale would be
/// inventing a security property nothing else in the stack recognizes.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ValidationMode {
    #[default]
    Strict,
    SupervisedLocalDevelopment,
}

fn default_maximum_request_bytes() -> u32 {
    16 * 1024
}

fn default_request_timeout_milliseconds() -> u64 {
    5_000
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListenerConfig {
    pub address: String,
    pub port: u16,
    #[serde(default = "default_maximum_request_bytes")]
    pub maximum_request_bytes: u32,
    #[serde(default = "default_request_timeout_milliseconds")]
    pub request_timeout_milliseconds: u64,
}

/// Optional operator-only metrics listener.
///
/// Absent means no metrics endpoint exists. When present it is a distinct
/// private binding that serves no wallet or adopter route.
#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetricsListenerConfig {
    pub address: String,
    pub port: u16,
}

impl MetricsListenerConfig {
    pub fn bind_address(&self) -> Result<IpAddr, ConfigError> {
        let address: IpAddr = self.address.parse().map_err(|_| {
            ConfigError::Invalid("metrics listener address is not a private IP address")
        })?;
        let is_private = match address {
            IpAddr::V4(address) => {
                address.is_loopback() || address.is_private() || address.is_link_local()
            }
            IpAddr::V6(address) => {
                // `IpAddr` carries no interface scope, so accepting fe80::/10
                // here would admit an unscoped link-local binding.
                address.is_loopback() || address.is_unique_local()
            }
        };
        if !is_private || address.is_unspecified() || address.is_multicast() {
            return Err(ConfigError::Invalid(
                "the metrics listener must bind a loopback or private address",
            ));
        }
        Ok(address)
    }

    fn validate(&self, listener: &ListenerConfig) -> Result<(), ConfigError> {
        if self.port == 0 {
            return Err(ConfigError::Invalid(
                "the metrics listener port must be non-zero",
            ));
        }
        let address = self.bind_address()?;
        let public_address = listener.bind_address()?;
        if self.port == listener.port
            && (public_address.is_unspecified() || public_address == address)
        {
            return Err(ConfigError::Invalid(
                "the metrics listener must not share the delivery listener binding",
            ));
        }
        Ok(())
    }
}

impl ListenerConfig {
    pub fn bind_address(&self) -> Result<IpAddr, ConfigError> {
        self.address
            .parse()
            .map_err(|_| ConfigError::Invalid("listener address is not an IP address"))
    }

    /// Reject limits no wallet request can survive.
    ///
    /// A zero body limit or a zero timeout leaves the service reporting itself
    /// ready while every request fails, which is an outage no probe can see.
    /// The bounds match the Mint and Evidence listeners.
    fn validate(&self) -> Result<(), ConfigError> {
        if self.port == 0 {
            return Err(ConfigError::Invalid(
                "the listener port must be non-zero, because the published origin names it",
            ));
        }
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

/// The Evidence deployment this service requests credentials from.
///
/// A base URL and nothing else. Which credentials may be requested is the
/// Evidence bundle's decision and is read from Evidence, never restated here.
#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceConfig {
    pub base_url: String,
}

/// The identity this service authenticates to Mint with.
///
/// This is the client half of the process. It signs a private key JWT client
/// assertion with its own key and receives an access token Evidence accepts.
/// The resource-server half, which verifies tokens presented to the
/// adopter-facing offer endpoint, is a separate identity and a separate code
/// path.
#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintClientConfig {
    pub token_endpoint: String,
    pub client_id: String,
    /// The caller's own private JWK. Read owner-only when the outbound client
    /// is built, never logged and never rendered.
    pub private_key_file: PathBuf,
    /// The value the endpoint expects as the client assertion `aud`. Defaults
    /// to the token endpoint, which is the usual registration.
    #[serde(default)]
    pub client_assertion_audience: Option<String>,
}

impl MintClientConfig {
    #[must_use]
    pub fn client_assertion_audience(&self) -> &str {
        self.client_assertion_audience
            .as_deref()
            .unwrap_or(&self.token_endpoint)
    }
}

/// The signature algorithms an offer token may be signed with.
///
/// The same closed vocabulary Evidence accepts on its own resource-server
/// profile. Mixing families is refused when the configuration loads rather than
/// when the first token arrives.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum AccessTokenAlgorithm {
    EdDSA,
    ES256,
    RS256,
}

fn default_offer_token_algorithms() -> Vec<AccessTokenAlgorithm> {
    vec![AccessTokenAlgorithm::EdDSA]
}

fn default_maximum_token_lifetime_seconds() -> u64 {
    900
}

/// The authorization boundary of the adopter-facing offer endpoint.
///
/// This is the resource-server half of the process, and it is deliberately a
/// separate document from [`MintClientConfig`]: the identity this service
/// authenticates to Mint with has nothing to do with the identities it accepts
/// tokens from, and nothing here is derived from that one.
#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OfferAuthorizationConfig {
    /// The authorization server that issues offer tokens, compared exactly
    /// against a token's `iss`.
    pub issuer: String,
    pub jwks_uri: String,
    /// The audiences this service answers to. A token issued for anything else
    /// is refused, so an adopter's token for another resource server cannot be
    /// replayed here.
    pub audiences: Vec<String>,
    #[serde(default = "default_offer_token_algorithms")]
    pub algorithms: Vec<AccessTokenAlgorithm>,
    /// Client identifiers permitted to create offers. Empty accepts any client
    /// the issuer vouched for, which is the usual single-adopter deployment.
    #[serde(default)]
    pub authorized_clients: Vec<String>,
    #[serde(default = "default_maximum_token_lifetime_seconds")]
    pub maximum_token_lifetime_seconds: u64,
}

impl OfferAuthorizationConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.audiences.is_empty() {
            return Err(ConfigError::Invalid(
                "the offer endpoint must state at least one audience",
            ));
        }
        if self
            .audiences
            .iter()
            .any(|audience| audience.trim().is_empty() || audience.len() > 256)
        {
            return Err(ConfigError::Invalid(
                "every offer audience must be 1..=256 bytes",
            ));
        }
        let Some(first) = self.algorithms.first() else {
            return Err(ConfigError::Invalid(
                "the offer endpoint must accept at least one signature algorithm",
            ));
        };
        // The verifier refuses to be built over a mixed family, and these three
        // are three families, so one algorithm per deployment is the whole
        // range this can express.
        if self.algorithms.iter().any(|algorithm| algorithm != first) {
            return Err(ConfigError::Invalid(
                "the offer endpoint must accept exactly one signature algorithm family",
            ));
        }
        if self
            .authorized_clients
            .iter()
            .any(|client| client.trim().is_empty() || client.len() > 128)
        {
            return Err(ConfigError::Invalid(
                "every authorized offer client must be 1..=128 bytes",
            ));
        }
        if !(60..=3_600).contains(&self.maximum_token_lifetime_seconds) {
            return Err(ConfigError::Invalid(
                "the offer token lifetime ceiling must be 60..=3600 seconds",
            ));
        }
        Ok(())
    }
}

fn default_maximum_offers() -> usize {
    4_096
}

fn default_offer_lifetime_seconds() -> u64 {
    300
}

fn default_access_token_lifetime_seconds() -> u64 {
    300
}

fn default_nonce_lifetime_seconds() -> u64 {
    120
}

fn default_maximum_transaction_code_attempts() -> u32 {
    3
}

/// The bounds of the in-memory store.
///
/// Every one of these is a memory bound or a window, and both are load-bearing:
/// the store fails closed on saturation rather than evicting a live entry, so
/// the capacity is what an operator sizes against the offers a deployment
/// really creates, and the lifetimes are what keeps that capacity from filling
/// with state nobody is going to claim. A redeemed offer's failure ledger stays
/// for the full offer lifetime, so sustained offer creation is bounded to about
/// `maximum_offers / offer_lifetime_seconds` per second, not merely the number
/// of offers waiting to be redeemed at one instant.
#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StoreConfig {
    #[serde(default = "default_maximum_offers")]
    pub maximum_offers: usize,
    #[serde(default = "default_offer_lifetime_seconds")]
    pub offer_lifetime_seconds: u64,
    #[serde(default = "default_access_token_lifetime_seconds")]
    pub access_token_lifetime_seconds: u64,
    #[serde(default = "default_nonce_lifetime_seconds")]
    pub nonce_lifetime_seconds: u64,
    /// How many wrong transaction codes an offer survives.
    ///
    /// The counter lives as long as the offer does, so exhausting it locks the
    /// offer out for the rest of its life rather than for the rest of one
    /// request.
    #[serde(default = "default_maximum_transaction_code_attempts")]
    pub maximum_transaction_code_attempts: u32,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            maximum_offers: default_maximum_offers(),
            offer_lifetime_seconds: default_offer_lifetime_seconds(),
            access_token_lifetime_seconds: default_access_token_lifetime_seconds(),
            nonce_lifetime_seconds: default_nonce_lifetime_seconds(),
            maximum_transaction_code_attempts: default_maximum_transaction_code_attempts(),
        }
    }
}

impl StoreConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        // A store too small to hold a deployment's live offers refuses new ones
        // rather than forgetting old ones, so the floor is what keeps that
        // failure from being the normal case.
        if !(256..=1_048_576).contains(&self.maximum_offers) {
            return Err(ConfigError::Invalid(
                "the store must hold 256..=1048576 offers",
            ));
        }
        // Minutes, in both directions: shorter than a person can scan a code
        // and read a message, and the flow cannot complete; longer, and a
        // stolen offer stays useful.
        if !(60..=900).contains(&self.offer_lifetime_seconds) {
            return Err(ConfigError::Invalid(
                "the offer lifetime must be 60..=900 seconds",
            ));
        }
        if !(60..=900).contains(&self.access_token_lifetime_seconds) {
            return Err(ConfigError::Invalid(
                "the access token lifetime must be 60..=900 seconds",
            ));
        }
        if !(30..=900).contains(&self.nonce_lifetime_seconds) {
            return Err(ConfigError::Invalid(
                "the nonce lifetime must be 30..=900 seconds",
            ));
        }
        if self.nonce_lifetime_seconds > self.access_token_lifetime_seconds {
            return Err(ConfigError::Invalid(
                "the nonce lifetime must not exceed the access token lifetime",
            ));
        }
        if !(1..=10).contains(&self.maximum_transaction_code_attempts) {
            return Err(ConfigError::Invalid(
                "the transaction code attempt ceiling must be 1..=10",
            ));
        }
        Ok(())
    }
}

/// The whole startup configuration.
///
/// There is deliberately no member for the credential configurations this
/// service publishes. Every entry is derived from the Evidence bundle, so
/// published metadata cannot describe a credential Evidence would refuse to
/// issue. `deny_unknown_fields` turns an attempt to write one by hand into a
/// load failure rather than a silently ignored key, and no type in this crate
/// deserializes one.
#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeliveryConfig {
    pub version: u32,
    #[serde(default)]
    pub validation_mode: ValidationMode,
    /// The `credential_issuer` identifier this service publishes, and the value
    /// a wallet proof must carry as its `aud`. Held without a trailing slash,
    /// so what is published and what is compared are the same bytes.
    pub credential_issuer: String,
    pub listener: ListenerConfig,
    #[serde(default)]
    pub metrics_listener: Option<MetricsListenerConfig>,
    pub evidence: EvidenceConfig,
    pub mint: MintClientConfig,
    pub offers: OfferAuthorizationConfig,
    #[serde(default)]
    pub store: StoreConfig,
}

impl DeliveryConfig {
    /// Load and validate a configuration document, resolving the client key
    /// relative to its directory.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|_| ConfigError::Unavailable)?;
        let mut config: Self = serde_norway::from_str(&text)
            .map_err(|error| ConfigError::Document(error.to_string()))?;
        let root = path
            .parent()
            .ok_or(ConfigError::Invalid("configuration path has no parent"))?;
        config.resolve_paths(root);
        config.normalize_credential_issuer();
        config.validate()?;
        Ok(config)
    }

    /// Hold the published identifier in the single spelling everything reads.
    ///
    /// The metadata, the offer, and the audience a wallet proof is compared
    /// against are all this one string, and the comparison is byte for byte. A
    /// trailing slash is the one difference a URL parser calls equal and that
    /// comparison does not, so it is removed once here rather than at each
    /// place the value is read, where a site that forgot would publish an
    /// identifier no conforming wallet could address.
    fn normalize_credential_issuer(&mut self) {
        self.credential_issuer
            .truncate(self.credential_issuer.trim_end_matches('/').len());
    }

    fn resolve_paths(&mut self, root: &Path) {
        if !self.mint.private_key_file.as_os_str().is_empty()
            && self.mint.private_key_file.is_relative()
        {
            self.mint.private_key_file = root.join(&self.mint.private_key_file);
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if self.version != 1 {
            return Err(ConfigError::Invalid(
                "only configuration version 1 is supported",
            ));
        }
        match self.validation_mode {
            ValidationMode::Strict => {
                validate_https_credential_issuer(&self.credential_issuer)?;
                validate_https_origin(&self.evidence.base_url, "the Evidence base URL")?;
                validate_https_origin(&self.mint.token_endpoint, "the Mint token endpoint")?;
                validate_https_origin(
                    self.mint.client_assertion_audience(),
                    "the client assertion audience",
                )?;
                validate_https_origin(&self.offers.issuer, "the offer token issuer")?;
                validate_https_origin(&self.offers.jwks_uri, "the offer key set")?;
            }
            ValidationMode::SupervisedLocalDevelopment => {
                self.validate_supervised_local_development_transport()?;
            }
        }
        self.listener.bind_address()?;
        self.listener.validate()?;
        if let Some(metrics) = &self.metrics_listener {
            metrics.validate(&self.listener)?;
        }

        if self.mint.client_id.trim().is_empty() || self.mint.client_id.len() > 128 {
            return Err(ConfigError::Invalid(
                "the Mint client identifier must be 1..=128 bytes",
            ));
        }
        if self.mint.private_key_file.as_os_str().is_empty() {
            return Err(ConfigError::Invalid("a Mint client key file is required"));
        }
        self.offers.validate()?;
        self.store.validate()?;
        Ok(())
    }

    /// Admit one supervised process group on loopback, or nothing.
    ///
    /// The credential issuer is published to wallets and compared byte for byte
    /// by a wallet proof's `aud`, so a supervised deployment has to serve
    /// exactly the origin it publishes. Every other origin this mode reaches is
    /// loopback too: a supervised group that called a real Evidence or Mint
    /// deployment over plain HTTP would be a production deployment wearing a
    /// development label.
    fn validate_supervised_local_development_transport(&self) -> Result<(), ConfigError> {
        if self.credential_issuer.starts_with("https://") {
            validate_https_credential_issuer(&self.credential_issuer)?;
        } else {
            let port = parse_canonical_supervised_local_origin(&self.credential_issuer)?;
            if self.listener.address != "127.0.0.1" || self.listener.port != port {
                return Err(ConfigError::Invalid(
                    "the supervised local development listener must exactly match its canonical credential issuer origin",
                ));
            }
        }
        for (endpoint, subject) in [
            (self.evidence.base_url.as_str(), "the Evidence base URL"),
            (self.mint.token_endpoint.as_str(), "the Mint token endpoint"),
            (
                self.mint.client_assertion_audience(),
                "the client assertion audience",
            ),
            (self.offers.issuer.as_str(), "the offer token issuer"),
            (self.offers.jwks_uri.as_str(), "the offer key set"),
        ] {
            if endpoint.starts_with("https://") {
                validate_https_origin(endpoint, subject)?;
            } else {
                validate_supervised_local_endpoint(endpoint)?;
            }
        }
        Ok(())
    }
}

/// Require an absolute `https` URL with a host and no variable parts.
///
/// The credential issuer is compared exactly by every wallet that reads it, and
/// the two outbound endpoints are what this service authenticates against, so a
/// query, a fragment, or embedded credentials in any of them would weaken a
/// comparison or leak a secret into a URL.
fn validate_https_origin(value: &str, subject: &'static str) -> Result<(), ConfigError> {
    let url = Url::parse(value).map_err(|_| match subject {
        "the credential issuer" => {
            ConfigError::Invalid("the credential issuer must be an absolute URL")
        }
        "the Evidence base URL" => {
            ConfigError::Invalid("the Evidence base URL must be an absolute URL")
        }
        "the Mint token endpoint" => {
            ConfigError::Invalid("the Mint token endpoint must be an absolute URL")
        }
        "the offer token issuer" => {
            ConfigError::Invalid("the offer token issuer must be an absolute URL")
        }
        "the offer key set" => ConfigError::Invalid("the offer key set must be an absolute URL"),
        _ => ConfigError::Invalid("the client assertion audience must be an absolute URL"),
    })?;
    if url.scheme() != "https" {
        return Err(ConfigError::Invalid(
            "every published and called origin must use https",
        ));
    }
    if !url.has_host() {
        return Err(ConfigError::Invalid(
            "every published and called origin must have a host",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ConfigError::Invalid(
            "no published or called origin may carry credentials",
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(ConfigError::Invalid(
            "no published or called origin may carry a query or fragment",
        ));
    }
    Ok(())
}

/// Require the credential issuer to be a bare `https` origin, with no path.
///
/// Every published endpoint is built by concatenating this issuer with an
/// absolute route path, and the service only ever registers routes at the
/// root, so an issuer carrying its own path would publish an endpoint the
/// service does not serve.
fn validate_https_credential_issuer(value: &str) -> Result<(), ConfigError> {
    validate_https_origin(value, "the credential issuer")?;
    let url = Url::parse(value)
        .map_err(|_| ConfigError::Invalid("the credential issuer must be an absolute URL"))?;
    if url.path() != "/" {
        return Err(ConfigError::Invalid(
            "the credential issuer must be a bare origin with no path",
        ));
    }
    Ok(())
}

/// Accept a plain loopback HTTP endpoint, with an optional path and nothing
/// else that could vary between what is configured and what is reached.
fn validate_supervised_local_endpoint(value: &str) -> Result<(), ConfigError> {
    let url = Url::parse(value).map_err(|_| {
        ConfigError::Invalid("a supervised local development endpoint must be an absolute URL")
    })?;
    if url.scheme() != "http"
        || url.host_str() != Some("127.0.0.1")
        || url.port().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ConfigError::Invalid(
            "a supervised local development endpoint must be a canonical 127.0.0.1 HTTP origin with an explicit port and no query or fragment",
        ));
    }
    Ok(())
}

/// Parse the only HTTP origin admitted as a supervised credential issuer.
///
/// Exact reconstruction rejects URL-parser aliases such as a trailing slash,
/// leading-zero port, alternate IPv4 spelling, credentials, query, or fragment.
/// The same reasoning Mint applies to its own issuer: this string is compared,
/// not merely resolved.
fn parse_canonical_supervised_local_origin(value: &str) -> Result<u16, ConfigError> {
    let port = value
        .strip_prefix("http://127.0.0.1:")
        .filter(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
        .filter(|port| !port.starts_with('0'))
        .and_then(|port| port.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or(ConfigError::Invalid(
            "a supervised local development credential issuer must be a canonical 127.0.0.1 HTTP origin with an explicit non-zero port",
        ))?;
    if value != format!("http://127.0.0.1:{port}") {
        return Err(ConfigError::Invalid(
            "a supervised local development credential issuer must be a canonical 127.0.0.1 HTTP origin with an explicit non-zero port",
        ));
    }
    Ok(port)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::fs;

    const VALID: &str = r#"
version: 1
credentialIssuer: https://wallet.example.org
listener: {address: 127.0.0.1, port: 8090}
evidence:
  baseUrl: https://evidence.example.org
mint:
  tokenEndpoint: https://mint.example.org/token
  clientId: evidence-oid4vci
  privateKeyFile: keys/delivery-client.jwk.json
offers:
  issuer: https://mint.example.org
  jwksUri: https://mint.example.org/.well-known/jwks.json
  audiences: ["https://wallet.example.org"]
  algorithms: [EdDSA]
  authorizedClients: [adopter-front-end]
  maximumTokenLifetimeSeconds: 900
store:
  maximumOffers: 4096
  offerLifetimeSeconds: 300
  accessTokenLifetimeSeconds: 300
  nonceLifetimeSeconds: 120
  maximumTransactionCodeAttempts: 3
"#;

    /// The reference deployment, for tests in other modules that need a loaded
    /// configuration rather than a configuration decision.
    pub(crate) fn valid_config() -> DeliveryConfig {
        load_from(VALID).expect("the reference configuration loads")
    }

    fn load_from(text: &str) -> Result<DeliveryConfig, ConfigError> {
        let root = tempfile::tempdir().expect("temporary directory");
        let path = root.path().join("oid4vci.yaml");
        fs::write(&path, text).expect("configuration is written");
        DeliveryConfig::load(&path)
    }

    #[test]
    fn a_valid_document_loads() {
        let config = load_from(VALID).expect("the configuration loads");
        assert_eq!(config.credential_issuer, "https://wallet.example.org");
        assert_eq!(config.listener.port, 8090);
        assert_eq!(config.evidence.base_url, "https://evidence.example.org");
        assert_eq!(config.mint.client_id, "evidence-oid4vci");
        assert_eq!(config.store.maximum_transaction_code_attempts, 3);
        assert_eq!(config.validation_mode, ValidationMode::Strict);
    }

    #[test]
    fn the_store_block_is_optional_and_defaulted() {
        let text = VALID
            .split("store:")
            .next()
            .expect("the document has a store block");
        let config = load_from(text).expect("the configuration loads");
        assert_eq!(config.store, StoreConfig::default());
    }

    #[test]
    fn the_client_assertion_audience_defaults_to_the_token_endpoint() {
        let config = load_from(VALID).expect("the configuration loads");
        assert_eq!(
            config.mint.client_assertion_audience(),
            "https://mint.example.org/token"
        );

        let text = VALID.replace(
            "clientId: evidence-oid4vci",
            "clientId: evidence-oid4vci\n  clientAssertionAudience: https://mint.example.org/other",
        );
        let config = load_from(&text).expect("the configuration loads");
        assert_eq!(
            config.mint.client_assertion_audience(),
            "https://mint.example.org/other"
        );
    }

    #[test]
    fn an_unknown_key_is_refused() {
        let text = VALID.replace("version: 1", "version: 1\nunexpected: true");
        assert!(matches!(load_from(&text), Err(ConfigError::Document(_))));
    }

    #[test]
    fn a_hand_written_credential_configuration_cannot_be_expressed() {
        // Published metadata is derived from the Evidence bundle. There is no
        // configuration member to write one into, so a deployment that tries
        // fails to load rather than publishing a credential description
        // Evidence never agreed to.
        for text in [
            VALID.replace(
                "version: 1",
                "version: 1\ncredentialConfigurationsSupported: {}",
            ),
            VALID.replace(
                "  baseUrl: https://evidence.example.org",
                "  baseUrl: https://evidence.example.org\n  credentialConfigurationsSupported: {}",
            ),
        ] {
            assert!(matches!(load_from(&text), Err(ConfigError::Document(_))));
        }
    }

    #[test]
    fn the_offer_authorization_block_is_required_and_is_not_the_client_identity() {
        // The resource-server half and the client half are separate documents.
        // A deployment that states only the client identity does not start,
        // because there would be nothing to authorize an offer against.
        let text = VALID
            .split("offers:")
            .next()
            .expect("the document has an offers block");
        assert!(matches!(load_from(text), Err(ConfigError::Document(_))));

        let config = load_from(VALID).expect("the configuration loads");
        assert_eq!(config.offers.issuer, "https://mint.example.org");
        assert_eq!(config.offers.audiences, ["https://wallet.example.org"]);
        assert_eq!(config.offers.algorithms, [AccessTokenAlgorithm::EdDSA]);
        assert_eq!(config.offers.authorized_clients, ["adopter-front-end"]);
        assert_eq!(config.offers.maximum_token_lifetime_seconds, 900);
        // Nothing in the offer boundary is derived from the Mint client
        // identity this service authenticates with.
        assert_ne!(config.offers.issuer, config.mint.token_endpoint);
    }

    #[test]
    fn an_offer_boundary_that_authorizes_nothing_is_refused() {
        for (from, to) in [
            (
                r#"  audiences: ["https://wallet.example.org"]"#,
                "  audiences: []",
            ),
            ("  algorithms: [EdDSA]", "  algorithms: []"),
            ("  algorithms: [EdDSA]", "  algorithms: [EdDSA, RS256]"),
            (
                "  maximumTokenLifetimeSeconds: 900",
                "  maximumTokenLifetimeSeconds: 0",
            ),
            (
                "  maximumTokenLifetimeSeconds: 900",
                "  maximumTokenLifetimeSeconds: 86400",
            ),
            (
                "  authorizedClients: [adopter-front-end]",
                "  authorizedClients: [\"\"]",
            ),
        ] {
            let text = VALID.replace(from, to);
            assert!(
                matches!(load_from(&text), Err(ConfigError::Invalid(_))),
                "the offer boundary accepted {to}"
            );
        }
    }

    #[test]
    fn strict_mode_requires_https_for_the_offer_issuer_and_key_set() {
        for (from, to) in [
            (
                "  issuer: https://mint.example.org",
                "  issuer: http://mint.example.org",
            ),
            (
                "  jwksUri: https://mint.example.org/.well-known/jwks.json",
                "  jwksUri: http://mint.example.org/.well-known/jwks.json",
            ),
        ] {
            let text = VALID.replace(from, to);
            assert!(
                matches!(load_from(&text), Err(ConfigError::Invalid(_))),
                "strict mode accepted {to}"
            );
        }
    }

    #[test]
    fn only_version_one_is_supported() {
        let text = VALID.replace("version: 1", "version: 2");
        assert_eq!(
            load_from(&text),
            Err(ConfigError::Invalid(
                "only configuration version 1 is supported"
            ))
        );
    }

    #[test]
    fn strict_mode_requires_https_for_every_published_and_called_origin() {
        for (from, to) in [
            (
                "credentialIssuer: https://wallet.example.org",
                "credentialIssuer: http://wallet.example.org",
            ),
            (
                "baseUrl: https://evidence.example.org",
                "baseUrl: http://evidence.example.org",
            ),
            (
                "tokenEndpoint: https://mint.example.org/token",
                "tokenEndpoint: http://mint.example.org/token",
            ),
        ] {
            let text = VALID.replace(from, to);
            assert!(
                matches!(load_from(&text), Err(ConfigError::Invalid(_))),
                "strict mode accepted {to}"
            );
        }
    }

    #[test]
    fn a_credential_issuer_carrying_a_query_or_credentials_is_refused() {
        for issuer in [
            "https://wallet.example.org?a=b",
            "https://wallet.example.org#f",
            "https://user:secret@wallet.example.org",
        ] {
            let text = VALID.replace(
                "credentialIssuer: https://wallet.example.org",
                &format!("credentialIssuer: {issuer}"),
            );
            assert!(
                matches!(load_from(&text), Err(ConfigError::Invalid(_))),
                "the credential issuer accepted {issuer}"
            );
        }
    }

    /// The metadata endpoints are built by concatenating the issuer with each
    /// endpoint's absolute route path, and the service only ever registers
    /// routes at the root, so an issuer that already carries a path would
    /// publish an endpoint the service does not serve.
    #[test]
    fn a_credential_issuer_carrying_a_path_is_refused() {
        let text = VALID.replace(
            "credentialIssuer: https://wallet.example.org",
            "credentialIssuer: https://wallet.example.org/tenant-a",
        );
        assert!(
            matches!(load_from(&text), Err(ConfigError::Invalid(_))),
            "the credential issuer accepted a path"
        );
    }

    /// The identifier is held in one spelling, the one that is published.
    ///
    /// A trailing slash is the difference a URL parser calls equal and the
    /// byte-exact comparison a wallet proof's `aud` gets does not, so an
    /// operator who writes one must not end up serving an identifier no
    /// conforming wallet can address.
    #[test]
    fn a_credential_issuer_written_with_a_trailing_slash_is_held_as_it_is_published() {
        for written in [
            "https://wallet.example.org/",
            "https://wallet.example.org///",
        ] {
            let text = VALID.replace(
                "credentialIssuer: https://wallet.example.org",
                &format!("credentialIssuer: {written}"),
            );
            let config = load_from(&text).expect("the configuration loads");
            assert_eq!(config.credential_issuer, "https://wallet.example.org");
        }
    }

    #[test]
    fn supervised_local_development_pins_the_listener_to_the_issuer_origin() {
        let local = VALID
            .replace(
                "version: 1",
                "version: 1\nvalidationMode: supervised-local-development",
            )
            .replace(
                "credentialIssuer: https://wallet.example.org",
                "credentialIssuer: http://127.0.0.1:8090",
            )
            .replace(
                "baseUrl: https://evidence.example.org",
                "baseUrl: http://127.0.0.1:8080",
            )
            .replace(
                "tokenEndpoint: https://mint.example.org/token",
                "tokenEndpoint: http://127.0.0.1:8081/token",
            );
        let config = load_from(&local).expect("the supervised configuration loads");
        assert_eq!(
            config.validation_mode,
            ValidationMode::SupervisedLocalDevelopment
        );

        let mismatched = local.replace("port: 8090", "port: 8099");
        assert!(matches!(
            load_from(&mismatched),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn a_nonce_outliving_the_access_window_is_refused() {
        // A nonce that remains valid after the access token window can only
        // advertise a retry window the credential endpoint will not honor.
        let text = VALID.replace("nonceLifetimeSeconds: 120", "nonceLifetimeSeconds: 600");
        assert_eq!(
            load_from(&text),
            Err(ConfigError::Invalid(
                "the nonce lifetime must not exceed the access token lifetime"
            ))
        );
    }

    #[test]
    fn store_bounds_outside_their_ranges_are_refused() {
        for (from, to) in [
            ("maximumOffers: 4096", "maximumOffers: 8"),
            ("offerLifetimeSeconds: 300", "offerLifetimeSeconds: 86400"),
            (
                "accessTokenLifetimeSeconds: 300",
                "accessTokenLifetimeSeconds: 0",
            ),
            ("nonceLifetimeSeconds: 120", "nonceLifetimeSeconds: 0"),
            (
                "maximumTransactionCodeAttempts: 3",
                "maximumTransactionCodeAttempts: 0",
            ),
            (
                "maximumTransactionCodeAttempts: 3",
                "maximumTransactionCodeAttempts: 99",
            ),
        ] {
            let text = VALID.replace(from, to);
            assert!(
                matches!(load_from(&text), Err(ConfigError::Invalid(_))),
                "the store bounds accepted {to}"
            );
        }
    }

    #[test]
    fn the_listener_limits_no_request_can_survive_are_refused() {
        for limit in [
            "maximumRequestBytes: 8",
            "maximumRequestBytes: 4194304",
            "requestTimeoutMilliseconds: 0",
            "requestTimeoutMilliseconds: 120000",
        ] {
            let text = VALID.replace(
                "listener: {address: 127.0.0.1, port: 8090}",
                &format!("listener: {{address: 127.0.0.1, port: 8090, {limit}}}"),
            );
            assert!(
                matches!(load_from(&text), Err(ConfigError::Invalid(_))),
                "the listener accepted {limit}"
            );
        }
    }

    #[test]
    fn metrics_are_absent_by_default_and_the_optional_listener_is_private_and_distinct() {
        assert!(valid_config().metrics_listener.is_none());

        let configured = VALID.replace(
            "listener: {address: 127.0.0.1, port: 8090}",
            "listener: {address: 127.0.0.1, port: 8090}\nmetricsListener: {address: 127.0.0.1, port: 9090}",
        );
        let config = load_from(&configured).expect("a distinct loopback listener loads");
        assert_eq!(
            config
                .metrics_listener
                .expect("metrics were configured")
                .port,
            9090
        );

        for listener in [
            "metricsListener: {address: 0.0.0.0, port: 9090}",
            "metricsListener: {address: 8.8.8.8, port: 9090}",
            "metricsListener: {address: 127.0.0.1, port: 8090}",
            "metricsListener: {address: 127.0.0.1, port: 0}",
        ] {
            let refused = VALID.replace(
                "listener: {address: 127.0.0.1, port: 8090}",
                &format!("listener: {{address: 127.0.0.1, port: 8090}}\n{listener}"),
            );
            assert!(
                matches!(load_from(&refused), Err(ConfigError::Invalid(_))),
                "metrics accepted {listener}"
            );
        }
    }

    #[test]
    fn metrics_accept_loopback_unique_local_and_current_ipv4_private_addresses() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.0.1",
            "169.254.1.1",
            "::1",
            "fc00::1",
            "fdff:ffff::1",
        ] {
            let configured = VALID.replace(
                "listener: {address: 127.0.0.1, port: 8090}",
                &format!(
                    "listener: {{address: 127.0.0.1, port: 8090}}\nmetricsListener: {{address: \"{address}\", port: 9090}}"
                ),
            );
            assert!(load_from(&configured).is_ok(), "metrics refused {address}");
        }
    }

    #[test]
    fn unscoped_ipv6_unicast_link_local_metrics_addresses_are_refused() {
        for address in ["fe80::1", "febf:ffff::1"] {
            let configured = VALID.replace(
                "listener: {address: 127.0.0.1, port: 8090}",
                &format!(
                    "listener: {{address: 127.0.0.1, port: 8090}}\nmetricsListener: {{address: \"{address}\", port: 9090}}"
                ),
            );
            assert_eq!(
                load_from(&configured),
                Err(ConfigError::Invalid(
                    "the metrics listener must bind a loopback or private address"
                )),
                "metrics accepted {address}"
            );
        }
    }

    #[test]
    fn a_listener_port_no_wallet_could_be_told_about_is_refused() {
        // An ephemeral port leaves the service running and reachable by nobody,
        // because the origin it published names a port it is not on.
        let text = VALID.replace("port: 8090", "port: 0");
        assert_eq!(
            load_from(&text),
            Err(ConfigError::Invalid(
                "the listener port must be non-zero, because the published origin names it"
            ))
        );
    }

    #[test]
    fn a_relative_client_key_path_resolves_against_the_configuration_directory() {
        let root = tempfile::tempdir().expect("temporary directory");
        let path = root.path().join("oid4vci.yaml");
        fs::write(&path, VALID).expect("configuration is written");
        let config = DeliveryConfig::load(&path).expect("the configuration loads");
        assert_eq!(
            config.mint.private_key_file,
            root.path().join("keys/delivery-client.jwk.json")
        );
    }

    #[test]
    fn an_empty_client_identity_is_refused() {
        for (from, to) in [
            ("clientId: evidence-oid4vci", "clientId: \"\""),
            (
                "privateKeyFile: keys/delivery-client.jwk.json",
                "privateKeyFile: \"\"",
            ),
        ] {
            let text = VALID.replace(from, to);
            assert!(
                matches!(load_from(&text), Err(ConfigError::Invalid(_))),
                "the client identity accepted {to}"
            );
        }
    }

    #[test]
    fn a_missing_document_reports_that_it_is_unavailable() {
        assert_eq!(
            DeliveryConfig::load(Path::new("/nonexistent/oid4vci.yaml")),
            Err(ConfigError::Unavailable)
        );
    }
}
