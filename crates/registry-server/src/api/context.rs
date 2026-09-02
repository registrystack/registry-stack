// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::contract::Operation;
use crate::model::HttpMethod;

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
    request_actions: Vec<VerifiedRequestAction>,
    request_presence: Vec<VerifiedRequestPresence>,
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
            request_actions: Vec::new(),
            request_presence: Vec::new(),
        }
    }

    pub(crate) fn with_request_visibility(
        mut self,
        request_actions: Vec<VerifiedRequestAction>,
        request_presence: Vec<VerifiedRequestPresence>,
    ) -> Self {
        self.request_actions = request_actions;
        self.request_presence = request_presence;
        self
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

    #[must_use]
    pub fn request_actions(&self) -> &[VerifiedRequestAction] {
        &self.request_actions
    }

    #[must_use]
    pub fn request_presence(&self) -> &[VerifiedRequestPresence] {
        &self.request_presence
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
            .field("request_action_count", &self.request_actions.len())
            .field("request_presence_count", &self.request_presence.len())
            .finish()
    }
}

/// Authority for one named immediate action, resolved from verified claims.
///
/// This context is independent of an entity's ordinary CRUD profile. Target
/// boundaries apply only within the selected action's compiled effect ceiling.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizedActionContext {
    action_id: String,
    principal: String,
    purpose: Option<String>,
    selected_profile: String,
    target_authority: BTreeMap<String, Vec<VerifiedRowBoundary>>,
    result_effects: BTreeSet<String>,
}

impl AuthorizedActionContext {
    pub(crate) fn new(
        action_id: String,
        principal: String,
        purpose: Option<String>,
        selected_profile: String,
        target_authority: BTreeMap<String, Vec<VerifiedRowBoundary>>,
        result_effects: BTreeSet<String>,
    ) -> Self {
        Self {
            action_id,
            principal,
            purpose,
            selected_profile,
            target_authority,
            result_effects,
        }
    }

    #[must_use]
    pub fn action_id(&self) -> &str {
        &self.action_id
    }

    #[must_use]
    pub fn principal(&self) -> &str {
        &self.principal
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
    pub fn target_authority(&self) -> &BTreeMap<String, Vec<VerifiedRowBoundary>> {
        &self.target_authority
    }

    #[must_use]
    pub fn result_effects(&self) -> &BTreeSet<String> {
        &self.result_effects
    }
}

impl fmt::Debug for AuthorizedActionContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedActionContext")
            .field("action_id", &self.action_id)
            .field("principal", &"<redacted>")
            .field("purpose", &self.purpose.as_ref().map(|_| "<redacted>"))
            .field("selected_profile", &self.selected_profile)
            .field("target_authority", &self.target_authority)
            .field("result_effects", &self.result_effects)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedRequestAction {
    route_id: String,
    method: HttpMethod,
    path: String,
    operation: Operation,
    review_stage: Option<String>,
    response_fields: BTreeSet<String>,
    target_authority: Vec<VerifiedRequestTargetAuthority>,
    automatic_apply_authority: Option<Vec<VerifiedRequestTargetAuthority>>,
    requires_automatic_apply_if_ready: bool,
}

pub(crate) struct VerifiedRequestActionAuthority {
    target: Vec<VerifiedRequestTargetAuthority>,
    automatic_apply: Option<Vec<VerifiedRequestTargetAuthority>>,
    requires_automatic_apply_if_ready: bool,
}

impl VerifiedRequestActionAuthority {
    pub(crate) const fn new(
        target: Vec<VerifiedRequestTargetAuthority>,
        automatic_apply: Option<Vec<VerifiedRequestTargetAuthority>>,
        requires_automatic_apply_if_ready: bool,
    ) -> Self {
        Self {
            target,
            automatic_apply,
            requires_automatic_apply_if_ready,
        }
    }
}

impl VerifiedRequestAction {
    pub(crate) fn new(
        route_id: String,
        method: HttpMethod,
        path: String,
        operation: Operation,
        review_stage: Option<String>,
        response_fields: BTreeSet<String>,
        authority: VerifiedRequestActionAuthority,
    ) -> Self {
        Self {
            route_id,
            method,
            path,
            operation,
            review_stage,
            response_fields,
            target_authority: authority.target,
            automatic_apply_authority: authority.automatic_apply,
            requires_automatic_apply_if_ready: authority.requires_automatic_apply_if_ready,
        }
    }

    #[must_use]
    pub fn route_id(&self) -> &str {
        &self.route_id
    }

    #[must_use]
    pub fn method(&self) -> HttpMethod {
        self.method
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn operation(&self) -> Operation {
        self.operation
    }

    #[must_use]
    pub fn review_stage(&self) -> Option<&str> {
        self.review_stage.as_deref()
    }

    #[must_use]
    pub fn response_fields(&self) -> &BTreeSet<String> {
        &self.response_fields
    }

    #[must_use]
    pub fn target_authority(&self) -> &[VerifiedRequestTargetAuthority] {
        &self.target_authority
    }

    #[must_use]
    pub fn automatic_apply_authority(&self) -> Option<&[VerifiedRequestTargetAuthority]> {
        self.automatic_apply_authority.as_deref()
    }

    #[must_use]
    pub const fn requires_automatic_apply_if_ready(&self) -> bool {
        self.requires_automatic_apply_if_ready
    }
}

impl fmt::Debug for VerifiedRequestAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedRequestAction")
            .field("route_id", &self.route_id)
            .field("method", &self.method)
            .field("operation", &self.operation)
            .field("review_stage", &self.review_stage)
            .field("response_fields", &self.response_fields)
            .field("target_authority_count", &self.target_authority.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedRequestTargetAuthority {
    target_entity_id: String,
    readable_fields: BTreeSet<String>,
    row_boundaries: Vec<VerifiedRowBoundary>,
}

impl VerifiedRequestTargetAuthority {
    pub(crate) fn new(
        target_entity_id: String,
        readable_fields: BTreeSet<String>,
        row_boundaries: Vec<VerifiedRowBoundary>,
    ) -> Self {
        Self {
            target_entity_id,
            readable_fields,
            row_boundaries,
        }
    }

    #[must_use]
    pub fn target_entity_id(&self) -> &str {
        &self.target_entity_id
    }

    #[must_use]
    pub fn readable_fields(&self) -> &BTreeSet<String> {
        &self.readable_fields
    }

    #[must_use]
    pub fn row_boundaries(&self) -> &[VerifiedRowBoundary] {
        &self.row_boundaries
    }
}

impl fmt::Debug for VerifiedRequestTargetAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedRequestTargetAuthority")
            .field("target_entity_id", &self.target_entity_id)
            .field("readable_fields", &self.readable_fields)
            .field("row_boundary_count", &self.row_boundaries.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedRequestPresence {
    request_entity_id: String,
    request_row_boundaries: Vec<VerifiedRowBoundary>,
}

impl VerifiedRequestPresence {
    pub(crate) fn new(
        request_entity_id: String,
        request_row_boundaries: Vec<VerifiedRowBoundary>,
    ) -> Self {
        Self {
            request_entity_id,
            request_row_boundaries,
        }
    }

    #[must_use]
    pub fn request_entity_id(&self) -> &str {
        &self.request_entity_id
    }

    #[must_use]
    pub fn request_row_boundaries(&self) -> &[VerifiedRowBoundary] {
        &self.request_row_boundaries
    }
}

impl fmt::Debug for VerifiedRequestPresence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedRequestPresence")
            .field("request_entity_id", &self.request_entity_id)
            .field("row_boundary_count", &self.request_row_boundaries.len())
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
