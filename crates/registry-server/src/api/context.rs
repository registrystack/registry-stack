// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const MAX_DIRECT_VALUE_BYTES: usize = 512;
const MAX_STRING_SET_VALUES: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifiedContextError {
    EmptyClaimName,
    InvalidDirectValue,
    TooManyClaimValues,
    DuplicateClaimValue,
}

/// A claim value accepted only after the configured OIDC verifier has
/// authenticated the token. Request headers and query parameters must never be
/// converted into this type.
#[derive(Clone, Eq, PartialEq)]
pub enum VerifiedClaimValue {
    DirectString(String),
    DirectStringSet(BTreeSet<String>),
}

impl VerifiedClaimValue {
    pub fn direct_string(value: impl Into<String>) -> Result<Self, VerifiedContextError> {
        Ok(Self::DirectString(validate_value(value.into())?))
    }

    pub fn direct_string_set<I, S>(values: I) -> Result<Self, VerifiedContextError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut result = BTreeSet::new();
        for value in values {
            if result.len() >= MAX_STRING_SET_VALUES {
                return Err(VerifiedContextError::TooManyClaimValues);
            }
            if !result.insert(validate_value(value.into())?) {
                return Err(VerifiedContextError::DuplicateClaimValue);
            }
        }
        if result.is_empty() {
            return Err(VerifiedContextError::InvalidDirectValue);
        }
        Ok(Self::DirectStringSet(result))
    }

    pub(crate) fn values(&self) -> BTreeSet<String> {
        match self {
            Self::DirectString(value) => BTreeSet::from([value.clone()]),
            Self::DirectStringSet(values) => values.clone(),
        }
    }
}

impl fmt::Debug for VerifiedClaimValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<verified claim redacted>")
    }
}

/// Authority material extracted from one already-verified access token.
///
/// The constructor deliberately requires the configured principal claim name
/// and its direct string value. It does not inspect `sub`, `client_id`, `azp`,
/// or any other fallback claim.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedRequestClaims {
    principal_claim: Option<String>,
    principal: Option<String>,
    scopes: BTreeSet<String>,
    purpose: Option<String>,
    direct_claims: BTreeMap<String, VerifiedClaimValue>,
}

impl VerifiedRequestClaims {
    pub fn authenticated(
        principal_claim: impl Into<String>,
        principal: impl Into<String>,
        scopes: BTreeSet<String>,
        purpose: Option<String>,
        direct_claims: BTreeMap<String, VerifiedClaimValue>,
    ) -> Result<Self, VerifiedContextError> {
        let principal_claim = validate_claim_name(principal_claim.into())?;
        let principal = validate_value(principal.into())?;
        let purpose = purpose.map(validate_value).transpose()?;
        for name in direct_claims.keys() {
            validate_claim_name(name.clone())?;
        }
        Ok(Self {
            principal_claim: Some(principal_claim),
            principal: Some(principal),
            scopes,
            purpose,
            direct_claims,
        })
    }

    #[must_use]
    pub fn anonymous() -> Self {
        Self {
            principal_claim: None,
            principal: None,
            scopes: BTreeSet::new(),
            purpose: None,
            direct_claims: BTreeMap::new(),
        }
    }

    pub(crate) fn principal_claim(&self) -> Option<&str> {
        self.principal_claim.as_deref()
    }

    pub(crate) fn principal(&self) -> Option<&str> {
        self.principal.as_deref()
    }

    pub(crate) fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(scope)
    }

    pub(crate) fn purpose(&self) -> Option<&str> {
        self.purpose.as_deref()
    }

    pub(crate) fn direct_claim(&self, name: &str) -> Option<&VerifiedClaimValue> {
        self.direct_claims.get(name)
    }
}

impl fmt::Debug for VerifiedRequestClaims {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedRequestClaims")
            .field("principal_claim", &self.principal_claim)
            .field("principal", &self.principal.as_ref().map(|_| "<redacted>"))
            .field("scope_count", &self.scopes.len())
            .field("purpose", &self.purpose.as_ref().map(|_| "<redacted>"))
            .field("direct_claims", &self.direct_claims.keys())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RowBoundaryOperator {
    Equals,
    In,
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedRowBoundary {
    field: String,
    operator: RowBoundaryOperator,
    values: BTreeSet<String>,
}

impl VerifiedRowBoundary {
    pub(super) fn new(
        field: String,
        operator: RowBoundaryOperator,
        values: BTreeSet<String>,
    ) -> Self {
        Self {
            field,
            operator,
            values,
        }
    }

    #[must_use]
    pub fn field(&self) -> &str {
        &self.field
    }

    #[must_use]
    pub fn operator(&self) -> &RowBoundaryOperator {
        &self.operator
    }

    #[must_use]
    pub fn values(&self) -> &BTreeSet<String> {
        &self.values
    }
}

impl fmt::Debug for VerifiedRowBoundary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedRowBoundary")
            .field("field", &self.field)
            .field("operator", &self.operator)
            .field("values", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizedRequestContext {
    principal: Option<String>,
    purpose: Option<String>,
    selected_profile: String,
    row_boundaries: Vec<VerifiedRowBoundary>,
}

impl AuthorizedRequestContext {
    pub(crate) fn new(
        principal: Option<String>,
        purpose: Option<String>,
        selected_profile: String,
        row_boundaries: Vec<VerifiedRowBoundary>,
    ) -> Self {
        Self {
            principal,
            purpose,
            selected_profile,
            row_boundaries,
        }
    }

    #[must_use]
    pub fn principal(&self) -> Option<&str> {
        self.principal.as_deref()
    }

    #[must_use]
    pub fn purpose(&self) -> Option<&str> {
        self.purpose.as_deref()
    }

    #[must_use]
    pub fn selected_profile(&self) -> &str {
        &self.selected_profile
    }

    #[must_use]
    pub fn row_boundaries(&self) -> &[VerifiedRowBoundary] {
        &self.row_boundaries
    }
}

impl fmt::Debug for AuthorizedRequestContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedRequestContext")
            .field("principal", &self.principal.as_ref().map(|_| "<redacted>"))
            .field("purpose", &self.purpose.as_ref().map(|_| "<redacted>"))
            .field("selected_profile", &self.selected_profile)
            .field("row_boundaries", &self.row_boundaries)
            .finish()
    }
}

fn validate_claim_name(value: String) -> Result<String, VerifiedContextError> {
    if value.is_empty() || value.len() > 128 || !value.is_ascii() {
        return Err(VerifiedContextError::EmptyClaimName);
    }
    Ok(value)
}

fn validate_value(value: String) -> Result<String, VerifiedContextError> {
    if value.is_empty()
        || value.len() > MAX_DIRECT_VALUE_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(VerifiedContextError::InvalidDirectValue);
    }
    Ok(value)
}
