// SPDX-License-Identifier: Apache-2.0
use registry_platform_httputil::client::TransportKind;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoordinatorProtocolFailure {
    HeaderBounds,
    MediaType,
    Body,
    Problem,
    Status,
}

/// Closed error categories. Remote prose, URLs, credentials and input never appear.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CoordinatorClientError {
    #[error("Registry Coordinator client configuration is invalid: {reason}")]
    Configuration { reason: &'static str },
    #[error("Registry Coordinator client request is invalid: {reason}")]
    InvalidRequest { reason: &'static str },
    #[error("Registry Coordinator exchange did not complete: {kind}")]
    Transport { kind: TransportKind },
    #[error("Registry Coordinator refused the request (HTTP {status})")]
    Problem { status: u16, code: String },
    #[error("Registry Coordinator returned an invalid response")]
    Protocol {
        status: u16,
        failure: CoordinatorProtocolFailure,
    },
}

impl CoordinatorClientError {
    pub(crate) fn configuration(reason: &'static str) -> Self {
        Self::Configuration { reason }
    }
    pub(crate) fn invalid_request(reason: &'static str) -> Self {
        Self::InvalidRequest { reason }
    }
    /// A failure after possible dispatch does not establish that the request
    /// had no effect. After `start`, retain the original identity, key and
    /// input even if a subsequent retry is refused. After `retry_same` or
    /// `cancel`, which the client never resends, read the run before asking again.
    #[must_use]
    pub fn is_outcome_unknown(&self) -> bool {
        match self {
            Self::Configuration { .. } | Self::InvalidRequest { .. } => false,
            Self::Transport { kind } => !matches!(kind, TransportKind::Connect),
            Self::Problem { status, .. } => *status >= 500,
            Self::Protocol { .. } => true,
        }
    }

    /// Whether resending the identical admission under the same key may
    /// settle an unknown outcome. An oversized or unparseable non-5xx answer
    /// would be replayed unchanged, so it is not resent. A transport failure
    /// carries no status, so the shared classifier, which sees the answer's
    /// status line, still refuses to resend after a 4xx one.
    pub(crate) fn resend_may_settle(&self) -> bool {
        match self {
            Self::Transport { kind } => {
                matches!(kind, TransportKind::Timeout | TransportKind::Exchange)
            }
            Self::Problem { status, .. } | Self::Protocol { status, .. } => *status >= 500,
            Self::Configuration { .. } | Self::InvalidRequest { .. } => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_timeout_a_broken_exchange_or_a_5xx_is_resent() {
        let resent = [
            CoordinatorClientError::Transport {
                kind: TransportKind::Timeout,
            },
            CoordinatorClientError::Transport {
                kind: TransportKind::Exchange,
            },
            CoordinatorClientError::Problem {
                status: 503,
                code: "service.unavailable".into(),
            },
            CoordinatorClientError::Protocol {
                status: 500,
                failure: CoordinatorProtocolFailure::MediaType,
            },
        ];
        for error in &resent {
            assert!(error.is_outcome_unknown(), "{error:?}");
            assert!(error.resend_may_settle(), "{error:?}");
        }
        let kept = [
            CoordinatorClientError::Transport {
                kind: TransportKind::Connect,
            },
            CoordinatorClientError::Transport {
                kind: TransportKind::ResponseTooLarge,
            },
            CoordinatorClientError::Protocol {
                status: 200,
                failure: CoordinatorProtocolFailure::Body,
            },
            CoordinatorClientError::Problem {
                status: 409,
                code: "idempotency.key-reused".into(),
            },
            CoordinatorClientError::invalid_request("fixture reason"),
        ];
        for error in &kept {
            assert!(!error.resend_may_settle(), "{error:?}");
        }
    }
}
