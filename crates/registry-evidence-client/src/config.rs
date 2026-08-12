//! What a relying party must decide before it can talk to a deployment.
//!
//! The trusted key set is the load-bearing decision. It is pinned here, by the
//! integrator, out of band. The client never replaces it with keys a response
//! or a discovery document named.

use std::{fmt, sync::Arc, time::Duration};

use registry_evidence_verifier::{
    model::JwksDocument,
    verifier::{revoked_key_ids_are_usable, trusted_keys_are_usable},
};
use registry_platform_httputil::DEFAULT_OUTBOUND_CONNECT_TIMEOUT;
use url::Url;
use zeroize::Zeroizing;

use crate::{
    error::EvidenceClientError,
    outbound::{base_url_without_userinfo, transport_protects_the_credential},
    token::TokenProvider,
};

/// Longest signed response body the client will read.
///
/// The verifier refuses a signed response larger than 256 KiB, so a bigger
/// body could never verify and reading it would only waste the relying party's
/// memory.
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 256 * 1024;

/// Longest deployment metadata document the client will read: the discovery
/// document, and the published key set.
///
/// This is a separate decision from [`DEFAULT_MAX_RESPONSE_BYTES`], which is
/// derived from what the verifier will accept as a signed response. Neither
/// document is signed and neither is verified, so that reasoning does not reach
/// them, and a relying party that tightens one bound to what its own assertions
/// need must not thereby stop being able to read discovery. The definitions
/// contract permits far more than this: 16,384 authorized shapes, which even at
/// the smallest conforming entry is several megabytes. This carries roughly five
/// hundred definitions, which is past what a deployment publishes, and
/// [`EvidenceClientConfig::with_max_metadata_bytes`] raises it for one that
/// publishes more.
pub const DEFAULT_MAX_METADATA_BYTES: u64 = 256 * 1024;

/// Total time allowed for one exchange, including reading the response body.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Time allowed for connection setup, including TLS negotiation.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = DEFAULT_OUTBOUND_CONNECT_TIMEOUT;

/// Whether this relying party verifies the responses it receives.
///
/// The stance is decided at construction and never changes, because it decides
/// which client type the configuration can build: only a `Pinned` configuration
/// reaches [`crate::EvidenceClient`], and only that client can verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerificationStance {
    /// The relying party pinned a key set and verifies every response.
    Pinned,
    /// The relying party does not verify, and states so. Reserved for a client
    /// that only requests holder-bound credentials and hands them to a wallet,
    /// where verification happens later, at presentation, against a key-binding
    /// JWT that does not exist yet at issuance.
    Declined,
    /// Construction is profile-driven and pins a fresh snapshot before each
    /// high-level request. Low-level verification against this empty config
    /// therefore always fails closed.
    Progressive,
}

/// Everything the client needs, decided before the first request.
pub struct EvidenceClientConfig {
    pub(crate) base_url: Url,
    pub(crate) token_provider: Arc<dyn TokenProvider>,
    pub(crate) trusted_jwks: JwksDocument,
    pub(crate) revoked_key_ids: Vec<String>,
    verification: VerificationStance,
    pub(crate) request_timeout: Duration,
    pub(crate) connect_timeout: Duration,
    pub(crate) user_agent: Option<String>,
    pub(crate) trusted_root_certificates: Option<Zeroizing<Vec<u8>>>,
    pub(crate) max_response_bytes: u64,
    pub(crate) max_metadata_bytes: u64,
}

impl EvidenceClientConfig {
    pub(crate) fn progressive(base_url: Url) -> Result<Self, EvidenceClientError> {
        let token_provider = Arc::new(crate::StaticToken::new("profile-metadata-only")?);
        Ok(Self {
            base_url,
            token_provider,
            trusted_jwks: JwksDocument { keys: Vec::new() },
            revoked_key_ids: Vec::new(),
            verification: VerificationStance::Progressive,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            user_agent: None,
            trusted_root_certificates: None,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_metadata_bytes: DEFAULT_MAX_METADATA_BYTES,
        })
    }

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
        revoked_key_ids: Vec<String>,
    ) -> Self {
        Self {
            base_url,
            token_provider,
            trusted_jwks,
            revoked_key_ids,
            verification: VerificationStance::Pinned,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            user_agent: None,
            trusted_root_certificates: None,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_metadata_bytes: DEFAULT_MAX_METADATA_BYTES,
        }
    }

    /// Configure a relying party that does not verify what it receives.
    ///
    /// This states a real position rather than relaxing a check. A credential
    /// delivery front end that requests holder-bound credentials and passes
    /// them to a wallet never verifies: verification of a holder-bound
    /// credential happens at presentation, against a key-binding JWT the holder
    /// has not created at issuance time. Such a client has nothing to do with a
    /// pinned key set, and requiring one would make it carry a file whose only
    /// function is satisfying a constructor.
    ///
    /// A configuration built this way carries no key set and can only build a
    /// [`crate::NonVerifyingEvidenceClient`], which has no verification method
    /// to call. [`crate::EvidenceClient::new`] refuses it, so the audience-scoped
    /// path is unaffected: it still requires a pinned key set, and still
    /// verifies.
    #[must_use]
    pub fn without_verification(base_url: Url, token_provider: Arc<dyn TokenProvider>) -> Self {
        Self {
            base_url,
            token_provider,
            trusted_jwks: JwksDocument { keys: Vec::new() },
            revoked_key_ids: Vec::new(),
            verification: VerificationStance::Declined,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            user_agent: None,
            trusted_root_certificates: None,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_metadata_bytes: DEFAULT_MAX_METADATA_BYTES,
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

    /// Bound the signed response body, which only [`crate::EvidenceClient::send`]
    /// reads.
    #[must_use]
    pub fn with_max_response_bytes(mut self, max_response_bytes: u64) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }

    /// Bound the discovery document and the published key set, which
    /// [`crate::EvidenceClient::discover`] and
    /// [`crate::EvidenceClient::fetch_jwks`] read.
    #[must_use]
    pub fn with_max_metadata_bytes(mut self, max_metadata_bytes: u64) -> Self {
        self.max_metadata_bytes = max_metadata_bytes;
        self
    }

    #[must_use]
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// The pinned key set every verification uses. Empty when this relying
    /// party [declined to verify](Self::without_verification).
    #[must_use]
    pub fn trusted_jwks(&self) -> &JwksDocument {
        &self.trusted_jwks
    }

    /// Whether this relying party verifies the responses it receives.
    ///
    /// False only for a configuration built by
    /// [`without_verification`](Self::without_verification), which cannot build
    /// a client that has a verification method.
    #[must_use]
    pub fn verifies(&self) -> bool {
        self.verification == VerificationStance::Pinned
    }

    /// Emergency service-key denylist applied before the pinned key set.
    #[must_use]
    pub fn revoked_key_ids(&self) -> &[String] {
        &self.revoked_key_ids
    }

    #[must_use]
    pub fn max_response_bytes(&self) -> u64 {
        self.max_response_bytes
    }

    #[must_use]
    pub fn max_metadata_bytes(&self) -> u64 {
        self.max_metadata_bytes
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
        // The transport is checked before the path, so a base URL that is wrong
        // in both ways is reported for the transport it cannot protect the
        // credential over rather than for a path detail the adopter would fix
        // first and learn nothing from.
        if !transport_protects_the_credential(&self.base_url) {
            return Err(EvidenceClientError::configuration(
                "the base URL must use HTTPS, or HTTP with a loopback host",
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
        // The pinned key set is the load-bearing decision, so it fails here
        // rather than once per request inside the verifier, where a set that
        // could never verify anything looks to an adopter like a deployment
        // fault. The rule is the verifier's own, asked once at the point the
        // decision was made instead of restated here where it could drift.
        match self.verification {
            VerificationStance::Pinned => {
                if trusted_keys_are_usable(&self.trusted_jwks).is_err() {
                    return Err(EvidenceClientError::configuration(
                        "the pinned key set must be one the verifier can use",
                    ));
                }
                if revoked_key_ids_are_usable(&self.revoked_key_ids).is_err() {
                    return Err(EvidenceClientError::configuration(
                        "the revoked key identifiers must be unique RFC 7638 thumbprints within the verifier bound",
                    ));
                }
            }
            // A declined stance is only reachable through
            // `without_verification`, which sets both to empty and offers no
            // way to fill them. Checking anyway keeps the emptiness a stated
            // property rather than a fact about one constructor.
            VerificationStance::Declined => {
                if !self.trusted_jwks.keys.is_empty() || !self.revoked_key_ids.is_empty() {
                    return Err(EvidenceClientError::configuration(
                        "a client that declined to verify must carry no key material",
                    ));
                }
            }
            VerificationStance::Progressive => {
                if !self.trusted_jwks.keys.is_empty() || !self.revoked_key_ids.is_empty() {
                    return Err(EvidenceClientError::configuration(
                        "a profile client pins no key before its metadata snapshot",
                    ));
                }
            }
        }
        if self.max_response_bytes == 0 || self.max_metadata_bytes == 0 {
            return Err(EvidenceClientError::configuration(
                "the response bounds must allow at least one byte",
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
    /// are all withheld, as is any userinfo in the base URL. Only the
    /// operational choices are rendered.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceClientConfig")
            .field("base_url", &base_url_without_userinfo(&self.base_url))
            .field("verifies", &self.verifies())
            .field("request_timeout", &self.request_timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("user_agent", &self.user_agent)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("max_metadata_bytes", &self.max_metadata_bytes)
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
            Vec::new(),
        )
    }

    /// A key set with one member. Only its presence matters here; the verifier
    /// owns everything about a key's content.
    fn one_key() -> JwksDocument {
        JwksDocument {
            keys: vec![serde_json::json!({
                "kty": "EC",
                "crv": "P-256",
                "kid": "_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo",
                "alg": "ES256",
                "x": "3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4",
                "y": "GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU",
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

    /// The transport is checked before the path, so a base URL that is wrong in
    /// both ways names the transport. That is the fault an adopter has to fix
    /// first, and fixing the path alone would leave the credential exposed.
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
            // Unusable transport and an unusable path at once.
            "ftp://evidence.example.org//x",
        ] {
            let Err(error) = config(base_url).validate() else {
                panic!("{base_url} was accepted");
            };
            assert_eq!(
                error,
                EvidenceClientError::configuration(
                    "the base URL must use HTTPS, or HTTP with a loopback host"
                ),
                "{base_url}"
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
            let Err(error) = config(base_url).validate() else {
                panic!("{base_url} was accepted");
            };
            assert_eq!(
                error,
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
                "the pinned key set must be one the verifier can use"
            )
        );
    }

    #[test]
    fn an_unusable_revocation_list_is_refused_at_construction() {
        for revoked_key_ids in [
            vec!["not-a-thumbprint".to_owned()],
            vec![
                "_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo".to_owned(),
                "_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo".to_owned(),
            ],
        ] {
            let mut config = config("https://evidence.example.org");
            config.revoked_key_ids = revoked_key_ids;
            assert_eq!(
                config.validate().expect_err("the denylist is refused"),
                EvidenceClientError::configuration(
                    "the revoked key identifiers must be unique RFC 7638 thumbprints within the verifier bound"
                )
            );
        }
    }

    /// Emptiness is only one of the ways a pinned set can be unusable, and every
    /// other way costs the adopter the same: a client that constructs, then
    /// refuses every response for a reason that reads as a deployment fault. The
    /// rule belongs to the verifier, so this asks the verifier rather than
    /// restating what it accepts.
    #[test]
    fn a_pinned_key_set_the_verifier_could_never_use_is_refused_at_construction() {
        let usable = one_key().keys[0].clone();
        let mut private_material = usable.clone();
        private_material["d"] = serde_json::json!("cHJpdmF0ZS1zY2FsYXItcGxhY2Vob2xkZXI");
        let mut absent_kid = usable.clone();
        absent_kid
            .as_object_mut()
            .expect("the key is an object")
            .remove("kid");
        let mut empty_kid = usable.clone();
        empty_kid["kid"] = serde_json::json!("");
        for (description, keys) in [
            ("an empty set", vec![]),
            (
                "private material a public set must never carry",
                vec![private_material],
            ),
            ("a key with no identifier", vec![absent_kid]),
            ("a key with an empty identifier", vec![empty_kid]),
            (
                "two keys claiming one identifier",
                vec![usable.clone(), usable.clone()],
            ),
            (
                "a key of an algorithm the profile does not fix",
                vec![
                    serde_json::json!({"kty": "EC", "crv": "P-256", "kid": "es256",
                    "alg": "ES256",
                    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}),
                ],
            ),
        ] {
            let mut config = config("https://evidence.example.org");
            config.trusted_jwks = JwksDocument { keys };
            let Err(error) = config.validate() else {
                panic!("{description} was accepted");
            };
            assert_eq!(
                error,
                EvidenceClientError::configuration(
                    "the pinned key set must be one the verifier can use"
                ),
                "{description}"
            );
        }
    }

    #[test]
    fn unusable_bounds_are_refused() {
        assert!(config("https://evidence.example.org")
            .with_max_response_bytes(0)
            .validate()
            .is_err());
        assert!(config("https://evidence.example.org")
            .with_max_metadata_bytes(0)
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

    #[test]
    fn debug_output_withholds_userinfo_the_caller_put_in_the_base_url() {
        let config = config("https://operator:canary-secret@evidence.example.org");
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("canary-secret"), "{rendered}");
        assert!(!rendered.contains("operator"), "{rendered}");
        assert!(
            rendered.contains("https://evidence.example.org/"),
            "{rendered}"
        );
    }

    fn non_verifying_config(base_url: &str) -> EvidenceClientConfig {
        EvidenceClientConfig::without_verification(
            Url::parse(base_url).expect("the test URL parses"),
            Arc::new(StaticToken::new("test-token").expect("the credential is accepted")),
        )
    }

    /// The declined stance is the whole difference: an empty key set is
    /// accepted here and refused for a client that verifies, so neither
    /// constructor can be mistaken for the other.
    #[test]
    fn declining_verification_accepts_no_key_set_and_pinning_still_requires_one() {
        let declined = non_verifying_config("https://evidence.example.org");
        assert!(!declined.verifies());
        assert!(declined.trusted_jwks().keys.is_empty());
        assert!(declined.revoked_key_ids().is_empty());
        declined.validate().expect("a declined stance is accepted");

        let mut pinned = config("https://evidence.example.org");
        assert!(pinned.verifies());
        pinned.trusted_jwks = JwksDocument { keys: Vec::new() };
        let failure = pinned
            .validate()
            .expect_err("a client that verifies needs keys");
        assert!(
            matches!(
                failure,
                EvidenceClientError::Configuration {
                    reason: "the pinned key set must be one the verifier can use"
                }
            ),
            "{failure:?}"
        );
    }

    /// Declining verification relaxes only the key set. Every other rule a
    /// configuration carries still decides, so this is not a way around the
    /// checks that protect the credential.
    #[test]
    fn declining_verification_relaxes_nothing_but_the_key_set() {
        let failure = non_verifying_config("http://evidence.example.org")
            .validate()
            .expect_err("the transport still decides");
        assert!(
            matches!(
                failure,
                EvidenceClientError::Configuration {
                    reason: "the base URL must use HTTPS, or HTTP with a loopback host"
                }
            ),
            "{failure:?}"
        );

        let failure = non_verifying_config("https://evidence.example.org")
            .with_request_timeout(Duration::ZERO)
            .validate()
            .expect_err("the timeouts still decide");
        assert!(
            matches!(
                failure,
                EvidenceClientError::Configuration {
                    reason: "the timeouts must be greater than zero"
                }
            ),
            "{failure:?}"
        );
    }

    /// The stance is written down where an operator reads it, so a client that
    /// does not verify says so in its own diagnostics rather than looking like
    /// one that does.
    #[test]
    fn debug_output_states_the_verification_stance() {
        assert!(
            format!("{:?}", config("https://evidence.example.org")).contains("verifies: true"),
            "a pinned configuration states that it verifies"
        );
        assert!(
            format!("{:?}", non_verifying_config("https://evidence.example.org"))
                .contains("verifies: false"),
            "a declined configuration states that it does not"
        );
    }
}
