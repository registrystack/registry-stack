// SPDX-License-Identifier: Apache-2.0

use registry_payment_protocol::PaymentProblemCode;
use registry_platform_httputil::client::TransportKind;
use thiserror::Error;

/// The response boundary that failed before a payment outcome could be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PaymentProtocolFailure {
    HeaderBounds,
    TraceContext,
    Body,
    MediaType,
    Problem,
    Status,
    /// A valid payment document belonged to another command or collection.
    Correlation,
}

/// Every failure a payment capability call can produce.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PaymentClientError {
    #[error("payment client configuration is invalid: {reason}")]
    Configuration { reason: &'static str },
    #[error("payment client request is invalid: {reason}")]
    InvalidRequest { reason: &'static str },
    #[error("payment exchange did not complete: {kind}")]
    Transport { kind: TransportKind },
    #[error("payment capability refused the request (HTTP {status}, problem {code:?})")]
    Problem {
        status: u16,
        code: PaymentProblemCode,
        trace_id: Option<String>,
        retry_after_seconds: Option<u64>,
    },
    #[error("payment capability returned an invalid response")]
    Protocol {
        status: u16,
        failure: PaymentProtocolFailure,
        trace_id: Option<String>,
    },
}

impl PaymentClientError {
    pub(crate) fn configuration(reason: &'static str) -> Self {
        Self::Configuration { reason }
    }

    pub(crate) fn invalid_request(reason: &'static str) -> Self {
        Self::InvalidRequest { reason }
    }

    /// Whether a keyed mutation might have taken effect despite this error.
    #[must_use]
    pub fn is_outcome_unknown(&self) -> bool {
        match self {
            Self::Configuration { .. } | Self::InvalidRequest { .. } => false,
            Self::Transport { kind } => !matches!(kind, TransportKind::Connect),
            Self::Problem { code, .. } => matches!(
                code,
                PaymentProblemCode::ReceiptUnresolved
                    | PaymentProblemCode::ReceiptExpired
                    | PaymentProblemCode::RecoveryHeld
                    | PaymentProblemCode::OutcomeUnknown
                    | PaymentProblemCode::ProviderProtocol
            ),
            Self::Protocol { status, .. } => !(400..500).contains(status),
        }
    }

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
