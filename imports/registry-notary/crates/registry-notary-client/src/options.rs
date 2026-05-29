// SPDX-License-Identifier: Apache-2.0
//! Per-request options and retry policy.

use std::time::Duration;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct RequestOptions {
    pub purpose: Option<String>,
    pub request_id: Option<String>,
    pub idempotency_key: Option<String>,
    pub accept: Option<String>,
    pub traceparent: Option<String>,
}

impl RequestOptions {
    #[must_use]
    pub fn builder() -> RequestOptionsBuilder {
        RequestOptionsBuilder::default()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.purpose.is_none()
            && self.request_id.is_none()
            && self.idempotency_key.is_none()
            && self.accept.is_none()
            && self.traceparent.is_none()
    }
}

#[derive(Debug, Clone, Default)]
pub struct RequestOptionsBuilder {
    options: RequestOptions,
}

impl RequestOptionsBuilder {
    #[must_use]
    pub fn purpose(mut self, purpose: impl Into<String>) -> Self {
        self.options.purpose = Some(purpose.into());
        self
    }

    #[must_use]
    pub fn request_id(mut self, request_id: impl Into<String>) -> Self {
        self.options.request_id = Some(request_id.into());
        self
    }

    #[must_use]
    pub fn idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.options.idempotency_key = Some(key.into());
        self
    }

    #[must_use]
    pub fn accept(mut self, accept: impl Into<String>) -> Self {
        self.options.accept = Some(accept.into());
        self
    }

    #[must_use]
    pub fn traceparent(mut self, traceparent: impl Into<String>) -> Self {
        self.options.traceparent = Some(traceparent.into());
        self
    }

    #[must_use]
    pub fn build(self) -> RequestOptions {
        self.options
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_attempts: usize,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub retry_transport_errors: bool,
    pub retry_rate_limited: bool,
    pub retry_unavailable: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 1,
            base_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(1),
            retry_transport_errors: false,
            retry_rate_limited: false,
            retry_unavailable: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryAfter {
    Delta(Duration),
    HttpDate(String),
}
