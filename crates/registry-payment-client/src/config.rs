// SPDX-License-Identifier: Apache-2.0

use std::{fmt, time::Duration};

use registry_platform_httputil::client::{
    ServiceBaseUrl, DEFAULT_CONNECT_TIMEOUT, DEFAULT_MUTATION_RETRIES, DEFAULT_REQUEST_TIMEOUT,
    MAXIMUM_MUTATION_RETRIES, MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES,
};
use url::Url;

use crate::PaymentClientError;

const DEFAULT_MAXIMUM_RESPONSE_BYTES: u64 = 1024 * 1024;
const MAXIMUM_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

/// One Adapter origin and one operator-selected payment connection.
#[derive(Clone)]
pub struct PaymentClientConfig {
    pub(crate) base_url: Url,
    pub(crate) connection: String,
    pub(crate) attempt_timeout: Duration,
    pub(crate) connect_timeout: Duration,
    pub(crate) maximum_response_bytes: u64,
    pub(crate) user_agent: Option<String>,
    pub(crate) trusted_root_certificates: Option<Vec<u8>>,
    pub(crate) maximum_mutation_retries: u8,
}

impl PaymentClientConfig {
    #[must_use]
    pub fn new(base_url: Url, connection: impl Into<String>) -> Self {
        Self {
            base_url,
            connection: connection.into(),
            attempt_timeout: DEFAULT_REQUEST_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            maximum_response_bytes: DEFAULT_MAXIMUM_RESPONSE_BYTES,
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

    /// Maximum identical same-key resends after an unknown keyed mutation.
    /// Coordinator sets this to zero because its durable worker owns retries.
    #[must_use]
    pub fn with_maximum_mutation_retries(mut self, value: u8) -> Self {
        self.maximum_mutation_retries = value;
        self
    }

    pub(crate) fn validate(&self) -> Result<ServiceBaseUrl, PaymentClientError> {
        let base_url = ServiceBaseUrl::new(self.base_url.clone())
            .map_err(|_| PaymentClientError::configuration("the service base URL is not usable"))?;
        if !valid_connection(&self.connection) {
            return Err(PaymentClientError::configuration(
                "the payment connection is not a local identifier",
            ));
        }
        if self.attempt_timeout.is_zero() || self.connect_timeout.is_zero() {
            return Err(PaymentClientError::configuration(
                "client timeouts must be greater than zero",
            ));
        }
        if self.maximum_response_bytes == 0 || self.maximum_response_bytes > MAXIMUM_RESPONSE_BYTES
        {
            return Err(PaymentClientError::configuration(
                "the response body bound is outside the accepted range",
            ));
        }
        if self
            .trusted_root_certificates
            .as_ref()
            .is_some_and(|value| value.len() > MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES)
        {
            return Err(PaymentClientError::configuration(
                "the trusted root certificate bundle exceeds the accepted bound",
            ));
        }
        if self.maximum_mutation_retries > MAXIMUM_MUTATION_RETRIES {
            return Err(PaymentClientError::configuration(
                "the mutation retry count exceeds the accepted bound",
            ));
        }
        Ok(base_url)
    }
}

fn valid_connection(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'-' | b'_'))
        })
}

impl fmt::Debug for PaymentClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PaymentClientConfig")
            .field("base_url", &"<validated service URL>")
            .field("connection", &"<validated local identifier>")
            .field("attempt_timeout", &self.attempt_timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("maximum_response_bytes", &self.maximum_response_bytes)
            .field("user_agent_present", &self.user_agent.is_some())
            .field(
                "trusted_root_certificates_present",
                &self.trusted_root_certificates.is_some(),
            )
            .field("maximum_mutation_retries", &self.maximum_mutation_retries)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_withholds_destination_and_connection() {
        let config = PaymentClientConfig::new(
            Url::parse("https://secret.example.invalid/private").unwrap(),
            "secret-connection",
        )
        .with_user_agent("secret-agent")
        .with_trusted_root_certificates(b"secret-certificate".to_vec());
        let debug = format!("{config:?}");
        for secret in [
            "secret.example",
            "private",
            "secret-connection",
            "secret-agent",
            "secret-certificate",
        ] {
            assert!(!debug.contains(secret));
        }
    }
}
