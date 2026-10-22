use std::{fmt, sync::Arc, time::Duration};

use registry_platform_httputil::client::{
    ServiceBaseUrl, TokenProvider, DEFAULT_MUTATION_RETRIES, MAXIMUM_MUTATION_RETRIES,
};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    BaseRegistryClientError, DEFAULT_ATTEMPT_TIMEOUT, DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_MAXIMUM_RESPONSE_BYTES,
};

/// Transport policy for one Base Registry Engine deployment.
#[derive(Clone)]
pub struct BaseRegistryClientConfig {
    pub(crate) base_url: Url,
    pub(crate) token_provider: Option<Arc<dyn TokenProvider>>,
    pub(crate) attempt_timeout: Duration,
    pub(crate) connect_timeout: Duration,
    pub(crate) maximum_response_bytes: u64,
    pub(crate) user_agent: Option<String>,
    pub(crate) trusted_root_certificates: Option<Zeroizing<Vec<u8>>>,
    pub(crate) maximum_mutation_retries: u8,
}

impl BaseRegistryClientConfig {
    #[must_use]
    pub fn new(base_url: Url) -> Self {
        Self {
            base_url,
            token_provider: None,
            attempt_timeout: DEFAULT_ATTEMPT_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            maximum_response_bytes: DEFAULT_MAXIMUM_RESPONSE_BYTES,
            user_agent: None,
            trusted_root_certificates: None,
            maximum_mutation_retries: DEFAULT_MUTATION_RETRIES,
        }
    }

    #[must_use]
    pub fn with_token_provider(mut self, provider: Arc<dyn TokenProvider>) -> Self {
        self.token_provider = Some(provider);
        self
    }

    #[must_use]
    pub fn with_attempt_timeout(mut self, timeout: Duration) -> Self {
        self.attempt_timeout = timeout;
        self
    }

    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    #[must_use]
    pub fn with_maximum_response_bytes(mut self, maximum: u64) -> Self {
        self.maximum_response_bytes = maximum;
        self
    }

    #[must_use]
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Trust exactly this PEM certificate bundle instead of platform roots.
    #[must_use]
    pub fn with_trusted_root_certificates(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.trusted_root_certificates = Some(Zeroizing::new(pem.into()));
        self
    }

    /// How many times an idempotency-keyed mutation whose outcome is unknown
    /// is resent, identically and under the same key, before its error is
    /// returned. Defaults to 2, accepts at most 2, and 0 disables the
    /// resend.
    #[must_use]
    pub fn with_maximum_mutation_retries(mut self, value: u8) -> Self {
        self.maximum_mutation_retries = value;
        self
    }

    #[must_use]
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    pub(crate) fn validate(&self) -> Result<(), BaseRegistryClientError> {
        ServiceBaseUrl::new(self.base_url.clone()).map_err(|_| {
            BaseRegistryClientError::configuration(
                "the service base URL must be an HTTPS URL, or loopback HTTP, with no credentials, query, or fragment",
            )
        })?;
        if self.attempt_timeout.is_zero() || self.connect_timeout.is_zero() {
            return Err(BaseRegistryClientError::configuration(
                "attempt and connection timeouts must be greater than zero",
            ));
        }
        if self.maximum_response_bytes == 0 {
            return Err(BaseRegistryClientError::configuration(
                "the response body bound must be greater than zero",
            ));
        }
        if self.maximum_mutation_retries > MAXIMUM_MUTATION_RETRIES {
            return Err(BaseRegistryClientError::configuration(
                "the mutation retry count exceeds the accepted bound",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for BaseRegistryClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BaseRegistryClientConfig")
            .field("base_url", &"<validated service URL>")
            .field("token_provider", &self.token_provider.is_some())
            .field("attempt_timeout", &self.attempt_timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("maximum_response_bytes", &self.maximum_response_bytes)
            .field("user_agent", &self.user_agent.is_some())
            .field("maximum_mutation_retries", &self.maximum_mutation_retries)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_validation_never_render_configuration_values() {
        let config = BaseRegistryClientConfig::new(
            Url::parse("https://sensitive-server-canary.invalid/private-prefix")
                .expect("fixture URL"),
        )
        .with_user_agent("sensitive-user-agent-canary")
        .with_trusted_root_certificates(b"certificate-material-canary".to_vec());
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("sensitive-server-canary"));
        assert!(!rendered.contains("private-prefix"));
        assert!(!rendered.contains("certificate-material-canary"));
        assert!(!rendered.contains("sensitive-user-agent-canary"));

        let invalid = BaseRegistryClientConfig::new(
            Url::parse("https://secret-user:secret-password@example.invalid/")
                .expect("fixture URL"),
        );
        let error = invalid.validate().expect_err("userinfo is refused");
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("secret-user"));
        assert!(!rendered.contains("secret-password"));
    }

    #[test]
    fn the_mutation_retry_count_is_bounded() {
        let url = Url::parse("https://registry.example.invalid/").expect("fixture URL");
        let error = BaseRegistryClientConfig::new(url.clone())
            .with_maximum_mutation_retries(MAXIMUM_MUTATION_RETRIES + 1)
            .validate()
            .expect_err("a retry count above the bound is refused");
        assert!(matches!(
            error,
            BaseRegistryClientError::Configuration {
                reason: "the mutation retry count exceeds the accepted bound"
            }
        ));
        for retries in 0..=MAXIMUM_MUTATION_RETRIES {
            assert!(BaseRegistryClientConfig::new(url.clone())
                .with_maximum_mutation_retries(retries)
                .validate()
                .is_ok());
        }
        assert_eq!(
            BaseRegistryClientConfig::new(url).maximum_mutation_retries,
            DEFAULT_MUTATION_RETRIES
        );
    }

    #[test]
    fn the_response_bound_keeps_its_default_and_refuses_zero() {
        let url = Url::parse("https://registry.example.invalid/").expect("fixture URL");
        assert_eq!(
            BaseRegistryClientConfig::new(url.clone()).maximum_response_bytes,
            DEFAULT_MAXIMUM_RESPONSE_BYTES
        );
        assert!(BaseRegistryClientConfig::new(url)
            .with_maximum_response_bytes(0)
            .validate()
            .is_err());
    }
}
