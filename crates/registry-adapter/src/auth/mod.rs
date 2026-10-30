// SPDX-License-Identifier: Apache-2.0

//! Upstream authentication for one endpoint binding: the six closed
//! kinds of `products/adapter/CONCEPT.md` section 10.2, plus the
//! orthogonal outbound TLS a binding may add.
//!
//! The layer is adapter-local over `registry-platform-httputil`
//! primitives, as section 10.2 requires: destination TLS material, the
//! transport failure kinds, and the scope and resource validators come
//! from the platform; the credential shapes come from
//! `registry-adapter-core`, which copies them from Evidence's
//! `SourceAuthentication` so an operator configures both products the
//! same way.
//!
//! The split the engine drives:
//!
//! - [`AuthPlan::compile`] freezes one endpoint's declared kind together
//!   with its runtime binding, refusing mismatches and out-of-bounds
//!   fields before any secret is resolved.
//! - [`AuthPlan::authorize`] produces the header material for one send:
//!   static kinds resolve their secret; the OAuth2 kinds acquire a
//!   bearer credential through the fixed token endpoint, under the
//!   exchange's token budget, through the endpoint's own outbound
//!   client, with a cache clamped to the operator's ceiling. Each
//!   [`AuthorizedCredential`] names the cached issuance it carries so a
//!   late 401 can be matched to the send that drew it.
//! - [`AuthPlan::on_upstream_status`] applies the 401 rule: one refresh
//!   under an OAuth2 kind, invalidating only the issuance the refused
//!   send carried, then the uncatchable `credential.rejected`; 403
//!   stays the caller's `upstream.http`.
//!
//! Secrets live in zeroizing buffers inside this layer and inside the
//! outbound request builder, nowhere else. The exchange, scripts, packs,
//! fixtures, diagnostics, logs, and the audit journal never see a value:
//! [`AuthEvent`] records the endpoint's kind and token-request outcomes
//! in value-free form, which is all the journal may keep.

mod json;
mod material;
mod plan;
mod tls;
mod token;

pub use material::{AuthHeader, ProtectedText};
pub use plan::{
    AuthKind, AuthPlan, AuthPlanFault, AuthorizeContext, AuthorizedCredential, StaticCredential,
};
pub use tls::{EndpointMaterials, EndpointTls, TlsFault};
pub use token::{
    ClientAssertion, ClientAssertionSigner, TokenBudget, TokenCache, TokenEndpointPlan, TokenFault,
    TokenRequest, TokenSend, TokenWire, TransportFailure, UpstreamStatusAction,
    TOKEN_REQUEST_ACCEPT, TOKEN_REQUEST_CONTENT_TYPE, UNREGISTERED_ERROR_CODE,
};

use registry_platform_httputil::TransportKind;
use std::fmt;

/// The error class a fault maps to, spelled as
/// `products/adapter/CONCEPT.md` section 8.7 spells classes. The
/// `credential.rejected` class is uncatchable: no `onException` clause
/// and no `doCatch` may name it, and a fallback must not mask it.
pub const CREDENTIAL_REJECTED_CLASS: &str = "credential.rejected";

/// The uncatchable `budget.exhausted` class of section 8.7, which a
/// token budget overrun raises.
pub const BUDGET_EXHAUSTED_CLASS: &str = "budget.exhausted";

/// Why the auth layer could not produce or keep a credential. Every
/// rendering is fixed text; no member carries a credential, a response
/// body, or a header value.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthError {
    /// The endpoint's declared kind and its runtime binding do not form
    /// a usable plan; a deployment load refusal, never the caller's
    /// `validation`.
    Plan(AuthPlanFault),
    /// The deployment's credential is unusable: a secret could not be
    /// resolved, or the value cannot travel as configured.
    Credential,
    /// The exchange's token budget is spent; the class is
    /// [`BUDGET_EXHAUSTED_CLASS`].
    BudgetExhausted,
    /// The token endpoint did not issue a usable credential.
    Token(TokenFault),
    /// The endpoint's outbound TLS material could not be resolved or
    /// built; a deployment load refusal, never the caller's
    /// `validation`.
    Tls(TlsFault),
}

impl AuthError {
    /// The section 8.7 error class this fault maps to.
    ///
    /// Plan and TLS faults are deployment misconfiguration: both are
    /// refused at startup, so an occurrence here means the deployment
    /// ignored that refusal, and neither is catchable at exchange time.
    #[must_use]
    pub fn class(&self) -> &'static str {
        match self {
            Self::Plan(_) | Self::Tls(TlsFault::CaBundle | TlsFault::ClientIdentity) => {
                CREDENTIAL_REJECTED_CLASS
            }
            // The engine refuses to send without the configured trust.
            Self::Tls(TlsFault::Material) => "egress.refused",
            Self::Credential => CREDENTIAL_REJECTED_CLASS,
            Self::BudgetExhausted => BUDGET_EXHAUSTED_CLASS,
            Self::Token(fault) => match fault {
                TokenFault::Transport { kind } => match kind {
                    TransportKind::Connect | TransportKind::Exchange => "upstream.connection",
                    TransportKind::Timeout => "upstream.timeout",
                    TransportKind::ResponseTooLarge => "upstream.too-large",
                    // A transport kind this build predates may be a
                    // policy refusal in disguise: the engine did not get
                    // an answer it understands, so the fault is the
                    // uncatchable egress refusal, never a catchable
                    // connection error a fallback could mask.
                    _ => "egress.refused",
                },
                // The destination policy refused the send before it
                // went out; the engine refusing to egress is
                // uncatchable, like every other pre-send refusal.
                TokenFault::EgressRefused => "egress.refused",
                // The shed is local, not an upstream outcome, but its
                // class is the catchable timeout: the caller waited and
                // got nothing, so a route may treat it as a transient
                // outage. The journal records the shed, never a
                // transport failure that did not happen.
                TokenFault::AdmissionShed => "upstream.timeout",
                TokenFault::Refused { .. }
                | TokenFault::ScopeNarrowed
                | TokenFault::NoLifetime
                | TokenFault::Invalid => CREDENTIAL_REJECTED_CLASS,
                TokenFault::Redirect => "upstream.redirect",
                TokenFault::Unavailable { .. } => "upstream.http",
                TokenFault::Unreadable => "upstream.malformed",
            },
        }
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(fault) => fault.fmt(formatter),
            Self::Credential => formatter.write_str("the deployment's credential is unusable"),
            Self::BudgetExhausted => formatter.write_str("the exchange's token budget is spent"),
            Self::Token(fault) => fault.fmt(formatter),
            Self::Tls(fault) => fault.fmt(formatter),
        }
    }
}

impl std::error::Error for AuthError {}

/// A value-free record of one auth-layer outcome, what the journal keeps
/// for a send: the endpoint's kind and token-request outcomes, never a
/// value (`products/adapter/CONCEPT.md` section 10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthEvent {
    /// A token request was sent to the endpoint's fixed token endpoint.
    TokenRequested,
    /// The token endpoint issued a credential, now cached under the
    /// operator's ceiling.
    TokenIssued,
    /// A cached credential was still fresh; no token request was sent.
    TokenCacheHit,
    /// The token endpoint declined to issue a credential; the fixed
    /// registered code name is carried, never server text.
    TokenRefused {
        /// The registered RFC 6749 or RFC 8707 code name, or the fixed
        /// name for an unregistered spelling.
        code: &'static str,
    },
    /// The token endpoint's answer did not satisfy the OAuth 2.0
    /// contract.
    TokenProtocolRefused,
    /// The token endpoint answered with a redirect, which this client
    /// never follows.
    TokenRedirected,
    /// The token endpoint is unavailable (429 or a server error); the
    /// status is carried, catchable and retryable as `upstream.http`.
    TokenUnavailable {
        /// The HTTP status.
        status: u16,
    },
    /// The token request did not complete on the transport.
    TokenTransportFailed {
        /// The coarse transport failure kind.
        kind: &'static str,
    },
    /// The token request was refused by the destination policy before
    /// it was sent; the engine refusing to egress is uncatchable.
    TokenEgressRefused,
    /// The acquisition gave up at the endpoint's admission bound before
    /// any request was sent: the deliberate shed of a wedged endpoint,
    /// catchable as a timeout, never a recorded transport failure.
    TokenAdmissionShed,
    /// A cached credential was discarded after an upstream 401. A stale
    /// 401 about an issuance a concurrent refresh already replaced
    /// pushes nothing, because nothing was discarded.
    TokenInvalidatedAfterUnauthorized,
    /// The uncatchable credential rejection of section 10.2.
    CredentialRejected,
    /// The exchange's token budget was spent.
    TokenBudgetExhausted,
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_httputil::TransportKind;

    /// Every fault renders its own fixed text and class, and no
    /// rendering carries caller data.
    #[test]
    fn faults_render_fixed_text_and_classes() {
        assert_eq!(
            AuthError::Plan(AuthPlanFault::KindMismatch).class(),
            CREDENTIAL_REJECTED_CLASS,
            "a plan fault is never the caller's validation"
        );
        assert_eq!(AuthError::Credential.class(), CREDENTIAL_REJECTED_CLASS);
        assert_eq!(AuthError::BudgetExhausted.class(), BUDGET_EXHAUSTED_CLASS);
        assert_eq!(
            AuthError::Tls(TlsFault::CaBundle).class(),
            CREDENTIAL_REJECTED_CLASS
        );
        assert_eq!(
            AuthError::Tls(TlsFault::ClientIdentity).class(),
            CREDENTIAL_REJECTED_CLASS
        );
        assert_eq!(
            AuthError::Tls(TlsFault::Material).class(),
            "egress.refused",
            "the engine refuses to send without the configured trust"
        );

        let transport = |kind| AuthError::Token(TokenFault::Transport { kind });
        assert_eq!(
            transport(TransportKind::Connect).class(),
            "upstream.connection"
        );
        assert_eq!(
            transport(TransportKind::Timeout).class(),
            "upstream.timeout"
        );
        assert_eq!(
            transport(TransportKind::Exchange).class(),
            "upstream.connection"
        );
        assert_eq!(
            transport(TransportKind::ResponseTooLarge).class(),
            "upstream.too-large"
        );
        assert_eq!(
            AuthError::Token(TokenFault::EgressRefused).class(),
            "egress.refused",
            "a policy refusal is the engine refusing to egress"
        );
        assert_eq!(
            AuthError::Token(TokenFault::AdmissionShed).class(),
            "upstream.timeout",
            "the admission shed stays catchable as a timeout"
        );

        assert_eq!(
            AuthError::Token(TokenFault::Refused {
                code: "invalid_client"
            })
            .class(),
            CREDENTIAL_REJECTED_CLASS
        );
        assert_eq!(
            AuthError::Token(TokenFault::ScopeNarrowed).class(),
            CREDENTIAL_REJECTED_CLASS
        );
        assert_eq!(
            AuthError::Token(TokenFault::NoLifetime).class(),
            CREDENTIAL_REJECTED_CLASS
        );
        assert_eq!(
            AuthError::Token(TokenFault::Invalid).class(),
            CREDENTIAL_REJECTED_CLASS,
            "a 2xx that is not a usable token response is a credential fault"
        );
        assert_eq!(
            AuthError::Token(TokenFault::Redirect).class(),
            "upstream.redirect"
        );
        assert_eq!(
            AuthError::Token(TokenFault::Unavailable { status: 503 }).class(),
            "upstream.http"
        );
        assert_eq!(
            AuthError::Token(TokenFault::Unreadable).class(),
            "upstream.malformed"
        );

        let rendered = AuthError::Token(TokenFault::Refused {
            code: "invalid_client",
        })
        .to_string();
        assert_eq!(
            rendered,
            "the token endpoint declined to issue a token: invalid_client"
        );
        let rendered = AuthError::Plan(AuthPlanFault::TokenEndpointNotUsable).to_string();
        assert_eq!(
            rendered,
            "the token endpoint must be an absolute http or https URL without userinfo, query, or fragment"
        );
        let rendered = AuthError::Token(TokenFault::EgressRefused).to_string();
        assert_eq!(
            rendered,
            "the token request was refused by the destination policy before it was sent"
        );
        let rendered = AuthError::Token(TokenFault::AdmissionShed).to_string();
        assert_eq!(
            rendered,
            "the token acquisition was shed at the admission bound before any request was sent"
        );
        let rendered = AuthError::Tls(TlsFault::CaBundle).to_string();
        assert_eq!(rendered, "the endpoint's CA bundle could not be resolved");
        let rendered = AuthError::Credential.to_string();
        assert_eq!(rendered, "the deployment's credential is unusable");
        let rendered = AuthError::BudgetExhausted.to_string();
        assert_eq!(rendered, "the exchange's token budget is spent");
        assert!(
            !AuthError::Token(TokenFault::Transport {
                kind: TransportKind::Connect
            })
            .to_string()
            .contains("secret"),
            "no rendering carries a value"
        );
    }

    /// Every transport kind the platform knows is mapped explicitly in
    /// `class`, and the fail-closed wildcard is the platform-addition
    /// story: a kind a newer platform adds falls to the uncatchable
    /// `egress.refused` until a reviewed change classifies it. This
    /// test names all four current variants, so a renamed or removed
    /// kind breaks this build instead of reclassifying silently.
    #[test]
    fn every_known_transport_kind_maps_its_class() {
        let class_of =
            |kind: TransportKind| AuthError::Token(TokenFault::Transport { kind }).class();
        assert_eq!(class_of(TransportKind::Connect), "upstream.connection");
        assert_eq!(class_of(TransportKind::Timeout), "upstream.timeout");
        assert_eq!(class_of(TransportKind::Exchange), "upstream.connection");
        assert_eq!(
            class_of(TransportKind::ResponseTooLarge),
            "upstream.too-large"
        );
        // The machine-readable spellings are pinned with the variants:
        // a platform change to either half of a mapping is a review
        // item, because the journal event carries the spelling.
        let spelled = [
            TransportKind::Connect.kind(),
            TransportKind::Timeout.kind(),
            TransportKind::Exchange.kind(),
            TransportKind::ResponseTooLarge.kind(),
        ];
        assert_eq!(
            spelled,
            ["connect", "timeout", "exchange", "response-too-large"]
        );
    }
}
