// SPDX-License-Identifier: Apache-2.0
//! Per-request options and retry policy.

use std::time::Duration;

/// Per-request options shared by route methods.
///
/// These map to safe request headers. Unsupported combinations, such as an
/// idempotency key on a route that does not honor it, are rejected before a
/// request is sent.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct RequestOptions {
    /// Data-purpose value sent as the `Data-Purpose` header.
    pub purpose: Option<String>,
    /// Caller-supplied request id sent as `X-Request-Id`.
    pub request_id: Option<String>,
    /// `Idempotency-Key` for routes that explicitly support replay-safe POST.
    pub idempotency_key: Option<String>,
    /// Override the route's default `Accept` header.
    pub accept: Option<String>,
    /// W3C trace context header to propagate to the server.
    pub traceparent: Option<String>,
}

impl RequestOptions {
    /// Start building request options fluently.
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

/// Builder for [`RequestOptions`].
#[derive(Debug, Clone, Default)]
pub struct RequestOptionsBuilder {
    options: RequestOptions,
}

impl RequestOptionsBuilder {
    /// Set the `Data-Purpose` header.
    #[must_use]
    pub fn purpose(mut self, purpose: impl Into<String>) -> Self {
        self.options.purpose = Some(purpose.into());
        self
    }

    /// Set the `X-Request-Id` header.
    #[must_use]
    pub fn request_id(mut self, request_id: impl Into<String>) -> Self {
        self.options.request_id = Some(request_id.into());
        self
    }

    /// Set the `Idempotency-Key` header.
    ///
    /// The client only permits this on batch evaluation, where the server has a
    /// replay contract.
    #[must_use]
    pub fn idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.options.idempotency_key = Some(key.into());
        self
    }

    /// Override the `Accept` header for this request.
    #[must_use]
    pub fn accept(mut self, accept: impl Into<String>) -> Self {
        self.options.accept = Some(accept.into());
        self
    }

    /// Set the W3C `traceparent` header.
    #[must_use]
    pub fn traceparent(mut self, traceparent: impl Into<String>) -> Self {
        self.options.traceparent = Some(traceparent.into());
        self
    }

    /// Finish building the options.
    #[must_use]
    pub fn build(self) -> RequestOptions {
        self.options
    }
}

/// Route-aware retry policy.
///
/// Retries are conservative by default. GET routes may retry when the selected
/// error class is enabled. Batch evaluation may retry only when an
/// `Idempotency-Key` is supplied. Non-deduplicated POST routes such as
/// evaluation, render, credential issuance, OID4VCI credential, and federation
/// submission are not retried even when this policy allows retryable errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Maximum attempts, including the first request.
    pub max_attempts: usize,
    /// Base exponential-backoff delay.
    pub base_delay: Duration,
    /// Maximum delay between attempts.
    pub max_delay: Duration,
    /// Retry transport errors on retry-eligible routes.
    pub retry_transport_errors: bool,
    /// Retry HTTP 429 on retry-eligible routes.
    pub retry_rate_limited: bool,
    /// Retry HTTP 503 on retry-eligible routes.
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

/// Parsed `Retry-After` header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryAfter {
    /// Delta-seconds form.
    Delta(Duration),
    /// HTTP-date form. Callers can log or interpret this if needed.
    HttpDate(String),
}
