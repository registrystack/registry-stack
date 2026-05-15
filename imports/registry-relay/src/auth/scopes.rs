// SPDX-License-Identifier: Apache-2.0
//! Scope set and authorisation helpers.
//!
//! V1 keeps scopes as plain strings: a scope is whatever appears in
//! `auth.api_keys[].scopes` in the config file and whatever appears in
//! the per-resource `metadata_scope` / `aggregate_scope` / `row_scope`
//! fields. The gateway does not parse or namespace them; it only
//! checks membership.
//!
//! See `decisions/wave-0.md` Section 4 for the `auth.scope_denied`
//! taxonomy entry that `require_scope` maps onto.

use std::collections::BTreeSet;

use crate::error::{AuthError, Error};

use super::Principal;

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
            api_key_id: "tester".to_string(),
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
}
