// SPDX-License-Identifier: Apache-2.0

use std::{fmt, time::Duration};

use registry_platform_httputil::client::{
    ServiceBaseUrl, DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT,
    MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES,
};
use url::Url;

use crate::MessagingClientError;

const DEFAULT_MAXIMUM_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const MAXIMUM_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

/// Where the Messaging service lives and the bounds every exchange with it
/// is held to. Nothing here is checked until `MessagingClient::new`, which
/// refuses an unusable configuration before any client exists.
#[derive(Clone)]
pub struct MessagingClientConfig {
    pub(crate) base_url: Url,
    pub(crate) request_timeout: Duration,
    pub(crate) connect_timeout: Duration,
    pub(crate) max_response_bytes: u64,
    pub(crate) user_agent: Option<String>,
    pub(crate) trusted_root_certificates: Option<Vec<u8>>,
}

impl MessagingClientConfig {
    #[must_use]
    pub fn new(base_url: Url) -> Self {
        Self {
            base_url,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            max_response_bytes: DEFAULT_MAXIMUM_RESPONSE_BYTES,
            user_agent: None,
            trusted_root_certificates: None,
        }
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

    pub(crate) fn validate(&self) -> Result<ServiceBaseUrl, MessagingClientError> {
        let base_url = ServiceBaseUrl::new(self.base_url.clone()).map_err(|_| {
            MessagingClientError::configuration("the service base URL is not usable")
        })?;
        if self.request_timeout.is_zero() || self.connect_timeout.is_zero() {
            return Err(MessagingClientError::configuration(
                "client timeouts must be greater than zero",
            ));
        }
        if self.max_response_bytes == 0 || self.max_response_bytes > MAXIMUM_RESPONSE_BYTES {
            return Err(MessagingClientError::configuration(
                "the response body bound is outside the accepted range",
            ));
        }
        if self
            .trusted_root_certificates
            .as_ref()
            .is_some_and(|value| value.len() > MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES)
        {
            return Err(MessagingClientError::configuration(
                "the trusted root certificate bundle exceeds the accepted bound",
            ));
        }
        Ok(base_url)
    }
}

impl fmt::Debug for MessagingClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MessagingClientConfig")
            .field("base_url", &"<validated service URL>")
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
        let config = MessagingClientConfig::new(
            Url::parse("https://secret.example.invalid/private").expect("fixture URL"),
        )
        .with_user_agent("secret-agent")
        .with_trusted_root_certificates(b"secret-certificate".to_vec());
        let debug = format!("{config:?}");
        assert!(!debug.contains("secret.example"));
        assert!(!debug.contains("private"));
        assert!(!debug.contains("secret-agent"));
        assert!(!debug.contains("secret-certificate"));
    }

    #[test]
    fn configuration_bounds_are_enforced_before_any_client_exists() {
        let url = Url::parse("https://messaging.example.invalid/").expect("fixture URL");
        let refused = [
            MessagingClientConfig::new(url.clone()).with_request_timeout(Duration::ZERO),
            MessagingClientConfig::new(url.clone()).with_connect_timeout(Duration::ZERO),
            MessagingClientConfig::new(url.clone()).with_max_response_bytes(0),
            MessagingClientConfig::new(url.clone())
                .with_max_response_bytes(MAXIMUM_RESPONSE_BYTES + 1),
            MessagingClientConfig::new(url.clone()).with_trusted_root_certificates(vec![
                0;
                MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES
                    + 1
            ]),
            MessagingClientConfig::new(
                Url::parse("https://user:pass@messaging.example.invalid/").expect("fixture URL"),
            ),
        ];
        for config in refused {
            assert!(
                matches!(
                    config.validate(),
                    Err(MessagingClientError::Configuration { .. })
                ),
                "{config:?}"
            );
        }
        assert!(MessagingClientConfig::new(url).validate().is_ok());
    }
}
