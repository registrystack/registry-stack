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
    /// A failure after possible dispatch does not establish that admission failed.
    /// Retain the original identity, key and input even if a subsequent retry is refused.
    #[must_use]
    pub fn is_outcome_unknown(&self) -> bool {
        match self {
            Self::Configuration { .. } | Self::InvalidRequest { .. } => false,
            Self::Transport { kind } => !matches!(kind, TransportKind::Connect),
            Self::Problem { status, .. } => *status >= 500,
            Self::Protocol { .. } => true,
        }
    }
}
