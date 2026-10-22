// SPDX-License-Identifier: Apache-2.0
use std::{fmt, time::Duration};

use registry_platform_httputil::client::{
    ServiceBaseUrl, DEFAULT_CONNECT_TIMEOUT, DEFAULT_MUTATION_RETRIES, DEFAULT_REQUEST_TIMEOUT,
    MAXIMUM_MUTATION_RETRIES, MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES,
};
use url::Url;

use crate::CoordinatorClientError;

/// Explicit destination, transport bounds and the admission retry count. No
/// credential acquisition.
#[derive(Clone)]
pub struct CoordinatorClientConfig {
    pub(crate) base_url: Url,
    pub(crate) attempt_timeout: Duration,
    pub(crate) connect_timeout: Duration,
    pub(crate) maximum_response_bytes: u64,
    pub(crate) user_agent: Option<String>,
    pub(crate) trusted_root_certificates: Option<Vec<u8>>,
    pub(crate) maximum_mutation_retries: u8,
}

impl CoordinatorClientConfig {
    #[must_use]
    pub fn new(base_url: Url) -> Self {
        Self {
            base_url,
            attempt_timeout: DEFAULT_REQUEST_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            maximum_response_bytes: 4 * 1024 * 1024,
            user_agent: None,
            trusted_root_certificates: None,
            maximum_mutation_retries: DEFAULT_MUTATION_RETRIES,
        }
    }
    #[must_use]
    pub fn with_attempt_timeout(mut self, value: Duration) -> Self {
        self.attempt_timeout = value;
        self
    }
    #[must_use]
    pub fn with_connect_timeout(mut self, value: Duration) -> Self {
        self.connect_timeout = value;
        self
    }
    #[must_use]
    pub fn with_maximum_response_bytes(mut self, value: u64) -> Self {
        self.maximum_response_bytes = value;
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
    /// How many times an admission whose outcome is unknown is resent,
    /// identically and under the same idempotency key, before its error is
    /// returned. Defaults to 2, accepts at most 2, and 0 disables the resend.
    #[must_use]
    pub fn with_maximum_mutation_retries(mut self, value: u8) -> Self {
        self.maximum_mutation_retries = value;
        self
    }
    pub(crate) fn validate(&self) -> Result<ServiceBaseUrl, CoordinatorClientError> {
        let base = ServiceBaseUrl::new(self.base_url.clone()).map_err(|_| {
            CoordinatorClientError::configuration("the service base URL is not usable")
        })?;
        if self.attempt_timeout.is_zero() || self.connect_timeout.is_zero() {
            return Err(CoordinatorClientError::configuration(
                "client timeouts must be greater than zero",
            ));
        }
        if self.maximum_response_bytes == 0 || self.maximum_response_bytes > 16 * 1024 * 1024 {
            return Err(CoordinatorClientError::configuration(
                "the response body bound is outside the accepted range",
            ));
        }
        if self
            .trusted_root_certificates
            .as_ref()
            .is_some_and(|v| v.len() > MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES)
        {
            return Err(CoordinatorClientError::configuration(
                "the certificate bundle exceeds the accepted bound",
            ));
        }
        if self.maximum_mutation_retries > MAXIMUM_MUTATION_RETRIES {
            return Err(CoordinatorClientError::configuration(
                "the mutation retry count exceeds the accepted bound",
            ));
        }
        Ok(base)
    }
}

impl fmt::Debug for CoordinatorClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoordinatorClientConfig")
            .field("base_url", &"<validated service URL>")
            .field("attempt_timeout", &self.attempt_timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("maximum_response_bytes", &self.maximum_response_bytes)
            .field("user_agent_present", &self.user_agent.is_some())
            .field(
                "trusted_root_certificates_present",
                &self.trusted_root_certificates.is_some(),
            )
            .field("maximum_mutation_retries", &self.maximum_mutation_retries)
            .finish()
    }
}
