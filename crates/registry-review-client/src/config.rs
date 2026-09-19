use std::{fmt, time::Duration};

use registry_platform_httputil::client::{
    ServiceBaseUrl, DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT,
    MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES,
};
use url::Url;

use crate::ReviewClientError;

const DEFAULT_MAXIMUM_RESPONSE_BYTES: u64 = 256 * 1024;
const MAXIMUM_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone)]
pub struct ReviewClientConfig {
    pub(crate) base_url: Url,
    pub(crate) profile: Option<String>,
    pub(crate) request_timeout: Duration,
    pub(crate) connect_timeout: Duration,
    pub(crate) max_response_bytes: u64,
    pub(crate) user_agent: Option<String>,
    pub(crate) trusted_root_certificates: Option<Vec<u8>>,
}

impl ReviewClientConfig {
    #[must_use]
    pub fn new(base_url: Url) -> Self {
        Self {
            base_url,
            profile: None,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            max_response_bytes: DEFAULT_MAXIMUM_RESPONSE_BYTES,
            user_agent: None,
            trusted_root_certificates: None,
        }
    }

    /// Selects the Casework requester profile used for every authority
    /// exchange. This is intentionally independent of the producer binding.
    #[must_use]
    pub fn with_profile(mut self, value: impl Into<String>) -> Self {
        self.profile = Some(value.into());
        self
    }

    #[must_use]
    pub fn with_request_timeout(mut self, value: Duration) -> Self {
        self.request_timeout = value;
        self
    }

    #[must_use]
    pub fn with_connect_timeout(mut self, value: Duration) -> Self {
        self.connect_timeout = value;
        self
    }

    #[must_use]
    pub fn with_max_response_bytes(mut self, value: u64) -> Self {
        self.max_response_bytes = value;
        self
    }

    #[must_use]
    pub fn with_user_agent(mut self, value: impl Into<String>) -> Self {
        self.user_agent = Some(value.into());
        self
    }

    #[must_use]
    pub fn with_trusted_root_certificates(mut self, value: Vec<u8>) -> Self {
        self.trusted_root_certificates = Some(value);
        self
    }

    pub(crate) fn validate(&self) -> Result<ServiceBaseUrl, ReviewClientError> {
        let base_url = ServiceBaseUrl::new(self.base_url.clone())
            .map_err(|_| ReviewClientError::configuration("the service base URL is not usable"))?;
        let profile = self
            .profile
            .as_deref()
            .ok_or_else(|| ReviewClientError::configuration("the Casework profile is required"))?;
        if profile.is_empty()
            || profile.len() > 128
            || !profile.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(ReviewClientError::configuration(
                "the Casework profile is invalid",
            ));
        }
        if self.request_timeout.is_zero() || self.connect_timeout.is_zero() {
            return Err(ReviewClientError::configuration(
                "client timeouts must be greater than zero",
            ));
        }
        if self.max_response_bytes == 0 || self.max_response_bytes > MAXIMUM_RESPONSE_BYTES {
            return Err(ReviewClientError::configuration(
                "the response body bound is outside the accepted range",
            ));
        }
        if self
            .trusted_root_certificates
            .as_ref()
            .is_some_and(|value| value.len() > MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES)
        {
            return Err(ReviewClientError::configuration(
                "the trusted root certificate bundle exceeds the accepted bound",
            ));
        }
        Ok(base_url)
    }
}

impl fmt::Debug for ReviewClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReviewClientConfig")
            .field("base_url", &"<validated service URL>")
            .field("profile_present", &self.profile.is_some())
            .field("request_timeout", &self.request_timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("user_agent_present", &self.user_agent.is_some())
            .field(
                "trusted_root_certificates_present",
                &self.trusted_root_certificates.is_some(),
            )
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_withholds_url_and_certificate_material() {
        let config = ReviewClientConfig::new(
            Url::parse("https://secret.example.invalid/private").expect("fixture URL"),
        )
        .with_profile("secret-profile")
        .with_user_agent("secret-agent")
        .with_trusted_root_certificates(b"secret-certificate".to_vec());
        let debug = format!("{config:?}");
        assert!(!debug.contains("secret.example"));
        assert!(!debug.contains("private"));
        assert!(!debug.contains("secret-agent"));
        assert!(!debug.contains("secret-profile"));
        assert!(!debug.contains("secret-certificate"));
    }

    #[test]
    fn profile_is_required_and_bounded() {
        let endpoint = Url::parse("https://casework.example.test/").unwrap();
        for profile in [None, Some(String::new()), Some("x".repeat(129))] {
            let mut config = ReviewClientConfig::new(endpoint.clone());
            config.profile = profile;
            assert!(config.validate().is_err());
        }
        assert!(ReviewClientConfig::new(endpoint)
            .with_profile("integration-requester")
            .validate()
            .is_ok());
    }
}
