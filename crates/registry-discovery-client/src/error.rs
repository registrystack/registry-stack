// SPDX-License-Identifier: Apache-2.0
//! Closed, value-free Registry Discovery client failures.

use registry_platform_httputil::TransportKind;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiscoveryProblem {
    InvalidRequest,
    NotFound,
    ResultBoundExceeded,
    Unavailable,
}

impl std::fmt::Display for DiscoveryProblem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequest => "Discovery rejected the request",
            Self::NotFound => "the Discovery route was not found",
            Self::ResultBoundExceeded => "the complete result exceeded the configured bound",
            Self::Unavailable => "Discovery could not answer safely",
        })
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiscoveryClientError {
    #[error("the Discovery client configuration is invalid")]
    Configuration,
    #[error("the Discovery query is invalid")]
    Query,
    #[error("no advertised service matched the exact selection")]
    NoMatchingService,
    #[error("the exact selection is ambiguous")]
    AmbiguousSelection,
    #[error("no Evidence Type alternative matched the selection")]
    NoMatchingAlternative,
    #[error("the Evidence Type alternative selection is ambiguous")]
    AmbiguousAlternative,
    #[error("the selected advertised capability does not match the service")]
    CapabilityMismatch,
    #[error("the relying application refused the advertised service")]
    LocalAcceptanceRefused,
    #[error("the current advertised service changed and requires new acceptance")]
    SelectionChanged,
    #[error("the Discovery exchange did not complete: {kind}")]
    Transport { kind: TransportKind },
    #[error("Discovery returned {problem}: status {status}")]
    Problem {
        status: u16,
        problem: DiscoveryProblem,
    },
    #[error("the Discovery response did not satisfy its closed wire contract")]
    Protocol,
}

impl DiscoveryClientError {
    pub(crate) const fn transport(kind: TransportKind) -> Self {
        Self::Transport { kind }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_errors_are_bounded_and_value_free() {
        let canaries = [
            "secret-filter-canary",
            "https://private-host-canary.invalid/path",
            "subject-selector-canary",
        ];
        let errors = [
            DiscoveryClientError::Configuration,
            DiscoveryClientError::Query,
            DiscoveryClientError::NoMatchingAlternative,
            DiscoveryClientError::AmbiguousAlternative,
            DiscoveryClientError::CapabilityMismatch,
            DiscoveryClientError::LocalAcceptanceRefused,
            DiscoveryClientError::SelectionChanged,
            DiscoveryClientError::transport(TransportKind::Connect),
            DiscoveryClientError::Problem {
                status: 503,
                problem: DiscoveryProblem::Unavailable,
            },
        ];
        for error in errors {
            let rendered = format!("{error:?} {error}");
            assert!(rendered.len() < 512);
            for canary in canaries {
                assert!(!rendered.contains(canary));
            }
        }
    }
}
