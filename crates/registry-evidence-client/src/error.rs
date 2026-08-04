//! One coarse failure type for the whole client.
//!
//! Every variant is deliberately uninformative about response content. A
//! rendering carries the HTTP status, the closed public problem code, and the
//! opaque operation identifier for support correlation, and nothing else. It
//! never carries response bytes, a credential, a header value, a selector
//! value, or a subject binding.

use registry_evidence_verifier::verifier::VerificationError;
use thiserror::Error;

use crate::{nonce::NonceError, token::TokenError};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvidenceClientError {
    /// The client configuration or the request specification is unusable. The
    /// reason is fixed text chosen here, never caller data.
    #[error("the client cannot be used as configured: {reason}")]
    Configuration { reason: &'static str },

    /// A request nonce could not be produced.
    #[error(transparent)]
    Nonce(#[from] NonceError),

    /// The token provider could not supply a usable credential.
    #[error(transparent)]
    Token(#[from] TokenError),

    /// The exchange did not complete. Connection setup, TLS negotiation, a
    /// timeout, and a truncated body all collapse here.
    #[error("the Evidence request did not complete: {kind}")]
    Transport { kind: TransportKind },

    /// The deployment refused the request. Authentication, authorization, and
    /// rate limiting are indistinguishable by design at the public boundary.
    #[error("the deployment refused the request: status {status}, code {code}")]
    Denied {
        status: u16,
        code: String,
        operation: Option<String>,
        /// Present only when the deployment asked for a bounded wait.
        retry_after_seconds: Option<u64>,
    },

    /// The deployment could not produce evidence for this exact request. The
    /// public contract collapses no match, ambiguity, a missing required fact,
    /// and an unresolved derivation input into this one answer, so it must not
    /// be read as a statement about the subject.
    #[error("the deployment could not produce evidence for this request")]
    NotAvailable { operation: Option<String> },

    /// The response did not satisfy the wire contract, or the deployment
    /// reported a failure that is not a refusal.
    #[error("the Evidence response does not satisfy the wire contract: status {status}")]
    Protocol {
        status: u16,
        code: Option<String>,
        operation: Option<String>,
        /// Present only when the deployment reported a bounded transient
        /// failure and asked for a wait. A relying party that honors it must
        /// still prepare a fresh request before trying again.
        retry_after_seconds: Option<u64>,
    },

    /// Verification refused the response. The cause is the verifier's own
    /// coarse reason, passed through unchanged.
    #[error("the Evidence response failed verification: {0}")]
    Verification(VerificationError),
}

/// Coarse reason an exchange did not complete.
///
/// TLS failures are reported as `Connect`: distinguishing them would mean
/// reading a transport error chain whose text this crate must not copy into a
/// diagnostic.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportKind {
    #[error("connection setup failed")]
    Connect,
    #[error("the configured timeout elapsed")]
    Timeout,
    #[error("the exchange failed")]
    Exchange,
    #[error("the response body exceeded the configured maximum")]
    ResponseTooLarge,
}

impl EvidenceClientError {
    pub(crate) fn configuration(reason: &'static str) -> Self {
        Self::Configuration { reason }
    }

    pub(crate) fn transport(kind: TransportKind) -> Self {
        Self::Transport { kind }
    }

    /// A stable, machine-readable name for which kind of failure this is.
    ///
    /// It exists for callers that have to branch or aggregate without matching
    /// an enum this crate may extend: a metric label, a structured log field, or
    /// a language binding that carries the discriminant across a boundary. The
    /// rendered message is for people and may be reworded; these names are part
    /// of the crate's contract and will not be renamed. A variant added later
    /// brings a new name rather than reusing one of these.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Configuration { .. } => "configuration",
            Self::Nonce(_) => "nonce",
            Self::Token(_) => "token",
            Self::Transport { .. } => "transport",
            Self::Denied { .. } => "denied",
            Self::NotAvailable { .. } => "not_available",
            Self::Protocol { .. } => "protocol",
            Self::Verification(_) => "verification",
        }
    }

    /// The opaque per-request identifier to quote when asking the deployment
    /// operator about this failure.
    #[must_use]
    pub fn operation(&self) -> Option<&str> {
        match self {
            Self::Denied { operation, .. }
            | Self::NotAvailable { operation }
            | Self::Protocol { operation, .. } => operation.as_deref(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renderings_carry_only_the_public_problem_members() {
        let denied = EvidenceClientError::Denied {
            status: 403,
            code: "not_authorized".to_owned(),
            operation: Some("01JZZZOPERATION".to_owned()),
            retry_after_seconds: None,
        };
        assert_eq!(
            denied.to_string(),
            "the deployment refused the request: status 403, code not_authorized"
        );
        assert_eq!(denied.operation(), Some("01JZZZOPERATION"));

        let unavailable = EvidenceClientError::NotAvailable {
            operation: Some("01JZZZOPERATION".to_owned()),
        };
        assert_eq!(
            unavailable.to_string(),
            "the deployment could not produce evidence for this request"
        );

        let transport = EvidenceClientError::transport(TransportKind::ResponseTooLarge);
        assert_eq!(
            transport.to_string(),
            "the Evidence request did not complete: the response body exceeded the configured maximum"
        );
        assert_eq!(transport.operation(), None);
    }

    /// The discriminant is what a binding, a metric label, or a caller's own
    /// branch reads, so every variant has one and no two share it.
    #[test]
    fn every_failure_reports_its_own_stable_kind() {
        let cases = [
            (
                EvidenceClientError::configuration("unusable"),
                "configuration",
            ),
            (EvidenceClientError::Nonce(NonceError::Entropy), "nonce"),
            (EvidenceClientError::Token(TokenError::Unavailable), "token"),
            (
                EvidenceClientError::transport(TransportKind::Connect),
                "transport",
            ),
            (
                EvidenceClientError::Denied {
                    status: 403,
                    code: "not_authorized".to_owned(),
                    operation: None,
                    retry_after_seconds: None,
                },
                "denied",
            ),
            (
                EvidenceClientError::NotAvailable { operation: None },
                "not_available",
            ),
            (
                EvidenceClientError::Protocol {
                    status: 200,
                    code: None,
                    operation: None,
                    retry_after_seconds: None,
                },
                "protocol",
            ),
            (
                EvidenceClientError::Verification(VerificationError::Signature),
                "verification",
            ),
        ];
        for (error, kind) in &cases {
            assert_eq!(error.kind(), *kind, "{error}");
        }
        let kinds: std::collections::BTreeSet<&str> =
            cases.iter().map(|(error, _)| error.kind()).collect();
        assert_eq!(kinds.len(), cases.len(), "two variants share a kind");
    }
}
