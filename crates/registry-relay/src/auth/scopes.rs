// SPDX-License-Identifier: Apache-2.0
//! Scope set and authorisation helpers.
//!
//! Authorization scopes remain plain strings and use membership checks. The
//! reserved `registry:trust` namespace is the exception: governed request
//! context and audit projection share the canonical grammar defined here.

use std::collections::BTreeSet;

use crate::error::{AuthError, Error};

use super::Principal;

pub(crate) const TRUST_CONTEXT_SCOPE_PREFIX: &str = "registry:trust";

/// Fields that may carry exact-value governed trust context in a scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrustContextField {
    LegalBasis,
    Consent,
    Assurance,
    Jurisdiction,
    SubjectRef,
    Relationship,
    OnBehalfOf,
    RequestedCredentialFormat,
    SourceObservedAtUnixSeconds,
    SourceObservedAgeSeconds,
}

impl TrustContextField {
    const ALL: [Self; 10] = [
        Self::LegalBasis,
        Self::Consent,
        Self::Assurance,
        Self::Jurisdiction,
        Self::SubjectRef,
        Self::Relationship,
        Self::OnBehalfOf,
        Self::RequestedCredentialFormat,
        Self::SourceObservedAtUnixSeconds,
        Self::SourceObservedAgeSeconds,
    ];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::LegalBasis => "legal_basis",
            Self::Consent => "consent",
            Self::Assurance => "assurance",
            Self::Jurisdiction => "jurisdiction",
            Self::SubjectRef => "subject_ref",
            Self::Relationship => "relationship",
            Self::OnBehalfOf => "on_behalf_of",
            Self::RequestedCredentialFormat => "requested_credential_format",
            Self::SourceObservedAtUnixSeconds => "source_observed_at_unix_seconds",
            Self::SourceObservedAgeSeconds => "source_observed_age_seconds",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|field| field.as_str() == value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParsedTrustContextScope<'a> {
    NotReserved,
    Malformed,
    Canonical {
        field: TrustContextField,
        value: &'a str,
    },
}

/// Parse the reserved trust-context namespace without exposing unrecognized
/// field names to audit output. Values are split once so they may contain
/// colons.
pub(crate) fn parse_trust_context_scope(scope: &str) -> ParsedTrustContextScope<'_> {
    if scope == TRUST_CONTEXT_SCOPE_PREFIX {
        return ParsedTrustContextScope::Malformed;
    }
    let Some(payload) = scope
        .strip_prefix(TRUST_CONTEXT_SCOPE_PREFIX)
        .and_then(|suffix| suffix.strip_prefix(':'))
    else {
        return ParsedTrustContextScope::NotReserved;
    };
    let Some((field, value)) = payload.split_once(':') else {
        return ParsedTrustContextScope::Malformed;
    };
    let Some(field) = TrustContextField::parse(field) else {
        return ParsedTrustContextScope::Malformed;
    };
    if value.is_empty() {
        return ParsedTrustContextScope::Malformed;
    }
    ParsedTrustContextScope::Canonical { field, value }
}

/// Format a canonical exact-value trust-context scope.
pub(crate) fn format_trust_context_scope(field: TrustContextField, value: &str) -> Option<String> {
    (!value.is_empty()).then(|| format!("{TRUST_CONTEXT_SCOPE_PREFIX}:{}:{value}", field.as_str()))
}

/// Set of scopes carried on a [`Principal`].
///
/// Wraps `BTreeSet<String>` for stable iteration order (matters for
/// audit's `scopes_used` field, which must serialise in declaration
/// order; deterministic alphabetical order is the V1 stand-in until
/// audit grows scope tracking). Membership checks are O(log n); the
/// expected scope count per key is < 10, so performance is not a
/// concern.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeSet(BTreeSet<String>);

impl ScopeSet {
    /// Construct an empty set. Equivalent to `Default::default()`;
    /// exposed for clarity at call sites.
    #[must_use]
    pub fn new() -> Self {
        Self(BTreeSet::new())
    }

    /// Whether the set contains the given scope.
    #[must_use]
    pub fn contains(&self, scope: &str) -> bool {
        self.0.contains(scope)
    }

    /// Iterate scopes in stable (alphabetical) order.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }

    /// Number of scopes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<S: Into<String>> FromIterator<S> for ScopeSet {
    fn from_iter<I: IntoIterator<Item = S>>(iter: I) -> Self {
        Self(iter.into_iter().map(Into::into).collect())
    }
}

/// Verify the principal carries `required`; return [`AuthError::ScopeDenied`]
/// otherwise.
///
/// The error wraps the requested scope name verbatim. The error
/// module's scrubber (`sanitise_operator_string`) caps the length and
/// strips control characters before the value reaches the response
/// body, so this function does not need to defensively rewrite the
/// string itself.
///
/// # Errors
///
/// Returns `Err(Error::Auth(AuthError::ScopeDenied { .. }))` if
/// `required` is not in `principal.scopes`.
pub fn require_scope(principal: &Principal, required: &str) -> Result<(), Error> {
    if principal.scopes.contains(required) {
        Ok(())
    } else {
        Err(AuthError::ScopeDenied {
            required: required.to_string(),
        }
        .into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthMode;

    fn principal_with_scopes<I, S>(scopes: I) -> Principal
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Principal {
            principal_id: "tester".to_string(),
            scopes: scopes.into_iter().collect(),
            auth_mode: AuthMode::ApiKey,
        }
    }

    #[test]
    fn scope_set_iter_is_alphabetical() {
        let set: ScopeSet = ["zeta", "alpha", "mu"].into_iter().collect();
        let collected: Vec<&str> = set.iter().collect();
        assert_eq!(collected, vec!["alpha", "mu", "zeta"]);
    }

    #[test]
    fn empty_scope_set_is_empty() {
        let set = ScopeSet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn require_scope_admits_when_present() {
        let p = principal_with_scopes(["rows", "metadata"]);
        require_scope(&p, "rows").expect("present scope admitted");
    }

    #[test]
    fn require_scope_denies_when_missing() {
        let p = principal_with_scopes(["rows"]);
        let err = require_scope(&p, "admin").expect_err("missing scope denied");
        assert_eq!(err.code(), "auth.scope_denied");
    }

    #[test]
    fn trust_context_scope_parser_enforces_reserved_namespace_boundaries() {
        let cases = [
            ("social_registry:rows", ParsedTrustContextScope::NotReserved),
            (
                "registry:trusted:subject_ref:value",
                ParsedTrustContextScope::NotReserved,
            ),
            ("registry:trust", ParsedTrustContextScope::Malformed),
            ("registry:trust:", ParsedTrustContextScope::Malformed),
            (
                "registry:trust:subject_ref",
                ParsedTrustContextScope::Malformed,
            ),
            ("registry:trust::value", ParsedTrustContextScope::Malformed),
            (
                "registry:trust:subject_ref:",
                ParsedTrustContextScope::Malformed,
            ),
            (
                "registry:trust:unknown:value",
                ParsedTrustContextScope::Malformed,
            ),
            (
                "registry:trust:subject_ref:subject:123",
                ParsedTrustContextScope::Canonical {
                    field: TrustContextField::SubjectRef,
                    value: "subject:123",
                },
            ),
        ];

        for (scope, expected) in cases {
            assert_eq!(parse_trust_context_scope(scope), expected, "scope={scope}");
        }
    }

    #[test]
    fn trust_context_scope_formatter_and_parser_share_the_exact_field_set() {
        let expected_fields = [
            "legal_basis",
            "consent",
            "assurance",
            "jurisdiction",
            "subject_ref",
            "relationship",
            "on_behalf_of",
            "requested_credential_format",
            "source_observed_at_unix_seconds",
            "source_observed_age_seconds",
        ];
        assert_eq!(
            TrustContextField::ALL.map(TrustContextField::as_str),
            expected_fields
        );

        for field in TrustContextField::ALL {
            let scope = format_trust_context_scope(field, "value:with:colons")
                .expect("non-empty value formats");
            assert_eq!(
                parse_trust_context_scope(&scope),
                ParsedTrustContextScope::Canonical {
                    field,
                    value: "value:with:colons",
                }
            );
        }
        assert_eq!(
            format_trust_context_scope(TrustContextField::SubjectRef, ""),
            None
        );
    }
}
