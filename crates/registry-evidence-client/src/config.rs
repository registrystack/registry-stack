//! What a relying party must decide before it can talk to a deployment.
//!
//! The trusted key set is the load-bearing decision. It is pinned here, by the
//! integrator, out of band. The client never replaces it with keys a response
//! or a discovery document named.

use std::{fmt, sync::Arc, time::Duration};

use registry_evidence_verifier::model::JwksDocument;
use registry_platform_httputil::DEFAULT_OUTBOUND_CONNECT_TIMEOUT;
use url::Url;
use zeroize::Zeroizing;

use crate::{error::EvidenceClientError, token::TokenProvider};

/// Longest response body the client will read.
///
/// The verifier refuses a signed response larger than 256 KiB, so a bigger
/// body could never verify and reading it would only waste the relying party's
/// memory.
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 256 * 1024;

/// Total time allowed for one exchange, including reading the response body.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Time allowed for connection setup, including TLS negotiation.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = DEFAULT_OUTBOUND_CONNECT_TIMEOUT;

/// The one host name a cleartext base URL may carry. It is reserved for the
/// loopback interface, so a credential sent to it cannot leave the host.
const LOOPBACK_NAME: &str = "localhost";

/// Everything the client needs, decided before the first request.
pub struct EvidenceClientConfig {
    pub(crate) base_url: Url,
    pub(crate) token_provider: Arc<dyn TokenProvider>,
    pub(crate) trusted_jwks: JwksDocument,
    pub(crate) request_timeout: Duration,
    pub(crate) connect_timeout: Duration,
    pub(crate) user_agent: Option<String>,
    pub(crate) trusted_root_certificates: Option<Zeroizing<Vec<u8>>>,
    pub(crate) max_response_bytes: u64,
}

impl EvidenceClientConfig {
    /// Configure a client against one deployment.
    ///
    /// `trusted_jwks` is the key set the relying party pinned out of band. It
    /// is the only source of verification keys. Fetching the deployment's
    /// published key set at verification time would make the response's own
    /// origin the authority for trusting it, which proves nothing.
    #[must_use]
    pub fn new(
        base_url: Url,
        token_provider: Arc<dyn TokenProvider>,
        trusted_jwks: JwksDocument,
    ) -> Self {
        Self {
            base_url,
            token_provider,
            trusted_jwks,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            user_agent: None,
            trusted_root_certificates: None,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }

    #[must_use]
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    #[must_use]
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Trust exactly these PEM-encoded certificate authorities for the
    /// deployment's TLS certificate, instead of the platform's own store.
    #[must_use]
    pub fn with_trusted_root_certificates(mut self, pem_bundle: impl Into<Vec<u8>>) -> Self {
        self.trusted_root_certificates = Some(Zeroizing::new(pem_bundle.into()));
        self
    }

    #[must_use]
    pub fn with_max_response_bytes(mut self, max_response_bytes: u64) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }

    #[must_use]
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// The pinned key set every verification uses.
    #[must_use]
    pub fn trusted_jwks(&self) -> &JwksDocument {
        &self.trusted_jwks
    }

    #[must_use]
    pub fn max_response_bytes(&self) -> u64 {
        self.max_response_bytes
    }

    /// Refuse a configuration that cannot carry a credential safely or that
    /// could never produce a readable response.
    pub(crate) fn validate(&self) -> Result<(), EvidenceClientError> {
        if !self.base_url.username().is_empty()
            || self.base_url.password().is_some()
            || self.base_url.query().is_some()
            || self.base_url.fragment().is_some()
        {
            return Err(EvidenceClientError::configuration(
                "the base URL must carry no credentials, query, or fragment",
            ));
        }
        if let Some(mut segments) = self.base_url.path_segments().map(Iterator::peekable) {
            // A single trailing separator is the ordinary way to write a
            // deployment prefix, and `endpoint` drops it. Any other empty
            // segment would put `//` in every request path, which the deployment
            // answers with a confusing 404.
            while let Some(segment) = segments.next() {
                if segment.is_empty() && segments.peek().is_some() {
                    return Err(EvidenceClientError::configuration(
                        "the base URL path must carry no empty segment other than a trailing separator",
                    ));
                }
            }
        }
        // A bearer credential in cleartext is only acceptable when it cannot
        // leave the host, which is the local development and tutorial case. The
        // accepted forms are the ones an adopter types: either loopback numeric
        // family, or the reserved name `localhost`. Any other name is refused,
        // because a name that happens to resolve to a loopback address is still
        // resolved off-host, and the answer can change.
        let transport_protects_the_credential = match self.base_url.scheme() {
            "https" => true,
            "http" => self.base_url.host().is_some_and(|host| match host {
                url::Host::Ipv4(ip) => ip.is_loopback(),
                url::Host::Ipv6(ip) => ip.is_loopback(),
                url::Host::Domain(name) => name == LOOPBACK_NAME,
            }),
            _ => false,
        };
        if !transport_protects_the_credential {
            return Err(EvidenceClientError::configuration(
                "the base URL must use HTTPS, or HTTP with a loopback host",
            ));
        }
        // The pinned key set is the load-bearing decision, so it fails here
        // rather than once per request inside the verifier, where an empty set
        // looks to an adopter like a deployment fault.
        if self.trusted_jwks.keys.is_empty() {
            return Err(EvidenceClientError::configuration(
                "the pinned key set must carry at least one verification key",
            ));
        }
        if self.max_response_bytes == 0 {
            return Err(EvidenceClientError::configuration(
                "the response bound must allow at least one byte",
            ));
        }
        if self.request_timeout.is_zero() || self.connect_timeout.is_zero() {
            return Err(EvidenceClientError::configuration(
                "the timeouts must be greater than zero",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for EvidenceClientConfig {
    /// The key set, the credential source, and the pinned certificate material
    /// are all withheld. Only the operational choices are rendered.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceClientConfig")
            .field("base_url", &self.base_url.as_str())
            .field("request_timeout", &self.request_timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("user_agent", &self.user_agent)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::StaticToken;

    fn config(base_url: &str) -> EvidenceClientConfig {
        EvidenceClientConfig::new(
            Url::parse(base_url).expect("the test URL parses"),
            Arc::new(StaticToken::new("test-token").expect("the credential is accepted")),
            one_key(),
        )
    }

    /// A key set with one member. Only its presence matters here; the verifier
    /// owns everything about a key's content.
    fn one_key() -> JwksDocument {
        JwksDocument {
            keys: vec![serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "test-key",
                "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            })],
        }
    }

    /// Every loopback form an adopter or a tutorial actually types.
    #[test]
    fn https_and_loopback_http_are_accepted() {
        for base_url in [
            "https://evidence.example.org",
            "https://evidence.example.org/prefix/",
            "http://127.0.0.1:8080",
            "http://127.0.0.1:8080/",
            "http://127.0.0.2:8080",
            "http://[::1]:8080",
            "http://[::1]:8080/prefix/",
            "http://localhost:8080",
            "http://localhost",
        ] {
            config(base_url)
                .validate()
                .unwrap_or_else(|error| panic!("{base_url} was refused: {error}"));
        }
    }

    #[test]
    fn a_base_url_that_cannot_protect_the_credential_is_refused() {
        for base_url in [
            "http://evidence.example.org",
            "http://example.com",
            "http://192.168.1.1:8080",
            "http://[2001:db8::1]:8080",
            // A name that resolves to a loopback address is still a name, and
            // the credential would leave the host to be resolved.
            "http://127.0.0.2.nip.io:8080",
            "http://localhost.evidence.example.org",
            "ftp://evidence.example.org",
        ] {
            assert!(
                config(base_url).validate().is_err(),
                "{base_url} was accepted"
            );
        }
    }

    #[test]
    fn a_base_url_carrying_more_than_an_origin_and_path_is_refused() {
        for base_url in [
            "https://user:pass@evidence.example.org",
            "https://evidence.example.org/?tenant=1",
            "https://evidence.example.org/#fragment",
        ] {
            assert!(
                config(base_url).validate().is_err(),
                "{base_url} was accepted"
            );
        }
    }

    /// An empty segment in the base path would put `//` in every request path,
    /// and the deployment would answer each one with a confusing 404. A single
    /// trailing separator is the ordinary way to write a prefix.
    #[test]
    fn a_base_url_path_with_an_empty_segment_is_refused() {
        for base_url in [
            "https://evidence.example.org//",
            "https://evidence.example.org/registry//",
            "https://evidence.example.org//registry",
            "https://evidence.example.org/registry//tenant",
        ] {
            assert_eq!(
                config(base_url)
                    .validate()
                    .expect_err("{base_url} was accepted"),
                EvidenceClientError::configuration(
                    "the base URL path must carry no empty segment other than a trailing separator"
                ),
                "{base_url}"
            );
        }
        for base_url in [
            "https://evidence.example.org",
            "https://evidence.example.org/",
            "https://evidence.example.org/registry",
            "https://evidence.example.org/registry/",
        ] {
            config(base_url)
                .validate()
                .unwrap_or_else(|error| panic!("{base_url} was refused: {error}"));
        }
    }

    /// The pinned key set is the load-bearing decision, so an empty one fails
    /// here rather than once per request inside the verifier, where it looks like
    /// a deployment fault.
    #[test]
    fn an_empty_pinned_key_set_is_refused() {
        let mut config = config("https://evidence.example.org");
        config.trusted_jwks = JwksDocument { keys: Vec::new() };
        assert_eq!(
            config.validate().expect_err("an empty key set is refused"),
            EvidenceClientError::configuration(
                "the pinned key set must carry at least one verification key"
            )
        );
    }

    #[test]
    fn unusable_bounds_are_refused() {
        assert!(config("https://evidence.example.org")
            .with_max_response_bytes(0)
            .validate()
            .is_err());
        assert!(config("https://evidence.example.org")
            .with_request_timeout(Duration::ZERO)
            .validate()
            .is_err());
        assert!(config("https://evidence.example.org")
            .with_connect_timeout(Duration::ZERO)
            .validate()
            .is_err());
    }

    #[test]
    fn debug_output_withholds_the_trust_and_credential_material() {
        let config = config("https://evidence.example.org")
            .with_trusted_root_certificates(b"-----BEGIN CERTIFICATE-----canary".to_vec());
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("canary"), "{rendered}");
        assert!(!rendered.contains("token"), "{rendered}");
        assert!(
            rendered.contains("https://evidence.example.org/"),
            "{rendered}"
        );
    }
}
