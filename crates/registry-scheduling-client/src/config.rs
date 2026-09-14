// SPDX-License-Identifier: Apache-2.0

use std::{fmt, time::Duration};

use registry_platform_httputil::client::{
    ServiceBaseUrl, DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT,
    MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES,
};
use url::Url;

use crate::SchedulingClientError;

const DEFAULT_MAXIMUM_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const MAXIMUM_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone)]
pub struct SchedulingClientConfig {
    pub(crate) base_url: Url,
    pub(crate) request_timeout: Duration,
    pub(crate) connect_timeout: Duration,
    pub(crate) max_response_bytes: u64,
    pub(crate) user_agent: Option<String>,
    pub(crate) trusted_root_certificates: Option<Vec<u8>>,
}

impl SchedulingClientConfig {
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

    pub(crate) fn validate(&self) -> Result<ServiceBaseUrl, SchedulingClientError> {
        let base_url = ServiceBaseUrl::new(self.base_url.clone()).map_err(|_| {
            SchedulingClientError::configuration("the service base URL is not usable")
        })?;
        if self.request_timeout.is_zero() || self.connect_timeout.is_zero() {
            return Err(SchedulingClientError::configuration(
                "client timeouts must be greater than zero",
            ));
        }
        if self.max_response_bytes == 0 || self.max_response_bytes > MAXIMUM_RESPONSE_BYTES {
            return Err(SchedulingClientError::configuration(
                "the response body bound is outside the accepted range",
            ));
        }
        if self
            .trusted_root_certificates
            .as_ref()
            .is_some_and(|value| value.len() > MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES)
        {
            return Err(SchedulingClientError::configuration(
                "the trusted root certificate bundle exceeds the accepted bound",
            ));
        }
        Ok(base_url)
    }
}

impl fmt::Debug for SchedulingClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SchedulingClientConfig")
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
        let config = SchedulingClientConfig::new(
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
        let url = Url::parse("https://scheduling.example.invalid/").expect("fixture URL");
        let zero_timeout =
            SchedulingClientConfig::new(url.clone()).with_request_timeout(Duration::ZERO);
        assert!(matches!(
            zero_timeout.validate(),
            Err(SchedulingClientError::Configuration { .. })
        ));
        let zero_body_bound = SchedulingClientConfig::new(url.clone()).with_max_response_bytes(0);
        assert!(matches!(
            zero_body_bound.validate(),
            Err(SchedulingClientError::Configuration { .. })
        ));
        let oversized_body_bound = SchedulingClientConfig::new(url.clone())
            .with_max_response_bytes(MAXIMUM_RESPONSE_BYTES + 1);
        assert!(matches!(
            oversized_body_bound.validate(),
            Err(SchedulingClientError::Configuration { .. })
        ));
        let oversized_certificate_bundle = SchedulingClientConfig::new(url)
            .with_trusted_root_certificates(vec![
                0;
                MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES + 1
            ]);
        assert!(matches!(
            oversized_certificate_bundle.validate(),
            Err(SchedulingClientError::Configuration { .. })
        ));
    }
}
