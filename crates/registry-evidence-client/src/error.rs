//! One coarse failure type for the whole client.
//!
//! Every variant is deliberately uninformative about response content. A
//! rendering carries the HTTP status, the closed public problem code, and the
//! validated W3C trace identifier for support correlation, and nothing else. It
//! never carries response bytes, a credential, a header value, a selector
//! value, or a subject binding.

use registry_evidence_verifier::verifier::VerificationError;
use thiserror::Error;

use crate::{nonce::NonceError, token::TokenError};
pub use registry_platform_httputil::TransportKind;

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
    /// timeout, and a body that exceeded the configured bound all arrive in this
    /// one variant, and [`TransportKind`] tells them apart: TLS negotiation is
    /// reported as a connection failure, and the other three each have their own
    /// kind.
    #[error("the Evidence request did not complete: {kind}")]
    Transport { kind: TransportKind },

    /// The deployment refused the request. Authentication, authorization, and
    /// rate limiting are indistinguishable by design at the public boundary.
    #[error("the deployment refused the request: status {status}, code {code}")]
    Denied {
        status: u16,
        code: String,
        trace_id: Option<String>,
        /// Present only when the deployment asked for a bounded wait.
        retry_after_seconds: Option<u64>,
    },

    /// The deployment could not produce evidence for this exact request. The
    /// public contract collapses no match, ambiguity, a missing required fact,
    /// and an unresolved derivation input into this one answer, so it must not
    /// be read as a statement about the subject.
    #[error("the deployment could not produce evidence for this request")]
    NotAvailable { trace_id: Option<String> },

    /// The response did not satisfy the wire contract, or the deployment
    /// reported a failure that is not a refusal.
    #[error("the Evidence response does not satisfy the wire contract: status {status}")]
    Protocol {
        status: u16,
        code: Option<String>,
        trace_id: Option<String>,
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

    /// The validated W3C trace identifier to quote when asking the deployment
    /// operator about this failure. It is transport correlation only, not an
    /// Evidence audit operation identity.
    #[must_use]
    pub fn trace_id(&self) -> Option<&str> {
        match self {
            Self::Denied { trace_id, .. }
            | Self::NotAvailable { trace_id }
            | Self::Protocol { trace_id, .. } => trace_id.as_deref(),
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
            code: "evidence.denied".to_owned(),
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_owned()),
            retry_after_seconds: None,
        };
        assert_eq!(
            denied.to_string(),
            "the deployment refused the request: status 403, code evidence.denied"
        );
        assert_eq!(denied.trace_id(), Some("4bf92f3577b34da6a3ce929d0e0e4736"));

        let unavailable = EvidenceClientError::NotAvailable {
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_owned()),
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
        assert_eq!(transport.trace_id(), None);
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
                    code: "evidence.denied".to_owned(),
                    trace_id: None,
                    retry_after_seconds: None,
                },
                "denied",
            ),
            (
                EvidenceClientError::NotAvailable { trace_id: None },
                "not_available",
            ),
            (
                EvidenceClientError::Protocol {
                    status: 200,
                    code: None,
                    trace_id: None,
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

    /// The discriminant is what a binding, a metric label, or a caller's own
    /// branch reads, so every variant has one and no two share it.
    #[test]
    fn every_transport_kind_reports_its_own_stable_kind() {
        let cases = [
            (TransportKind::Connect, "connect"),
            (TransportKind::Timeout, "timeout"),
            (TransportKind::Exchange, "exchange"),
            (TransportKind::ResponseTooLarge, "response_too_large"),
        ];
        for (kind, name) in &cases {
            assert_eq!(kind.kind(), *name, "{kind}");
        }
        let kinds: std::collections::BTreeSet<&str> =
            cases.iter().map(|(kind, _)| kind.kind()).collect();
        assert_eq!(kinds.len(), cases.len(), "two variants share a kind");
    }
}
