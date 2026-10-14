// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::task_grant::TaskGrantBinding;
use registry_platform_oidc::{ActorKind, GrantClaims};
use serde_json::Value;

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
    actor_kind: Option<ActorKind>,
    requester_client: Option<String>,
    actor_subject: Option<String>,
    grant: Option<GrantClaims>,
    grant_subjects: BTreeMap<String, Value>,
    human_identity: Option<registry_review_client::HumanIdentity>,
    recipients: BTreeSet<String>,
}

/// The verified claims of an authenticated caller, as a handler extractor.
///
/// A request that reaches a handler without verified claims is refused as
/// unauthenticated, so a route served without the authentication layer fails
/// closed instead of treating the caller as someone with no authority.
pub(crate) struct Authenticated(pub(crate) VerifiedRequestClaims);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for Authenticated {
    type Rejection = axum::response::Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<VerifiedRequestClaims>()
            .cloned()
            .map(Self)
            .ok_or_else(crate::auth::authentication_refused)
    }
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
            actor_kind: None,
            requester_client: None,
            actor_subject: None,
            grant: None,
            grant_subjects: BTreeMap::new(),
            human_identity: None,
            recipients: BTreeSet::new(),
        })
    }

    /// Construct authenticated authority material with an explicitly verified
    /// actor kind. Production callers receive this value from bearer admission;
    /// offline access previews may construct the same bounded context directly.
    pub fn authenticated_with_actor_kind(
        principal_claim: impl Into<String>,
        principal: impl Into<String>,
        scopes: BTreeSet<String>,
        purpose: Option<String>,
        direct_claims: BTreeMap<String, VerifiedClaimValue>,
        actor_kind: ActorKind,
    ) -> Result<Self, VerifiedContextError> {
        let mut claims =
            Self::authenticated(principal_claim, principal, scopes, purpose, direct_claims)?;
        claims.actor_kind = Some(actor_kind);
        Ok(claims)
    }

    pub(crate) fn with_contextual_authority(
        mut self,
        actor_kind: Option<ActorKind>,
        requester_client: Option<String>,
        actor_subject: Option<String>,
        grant: Option<GrantClaims>,
        grant_subjects: BTreeMap<String, Value>,
    ) -> Result<Self, VerifiedContextError> {
        self.actor_kind = actor_kind;
        self.requester_client = requester_client.map(validate_value).transpose()?;
        self.actor_subject = actor_subject.map(validate_value).transpose()?;
        self.grant = grant;
        self.grant_subjects = grant_subjects;
        Ok(self)
    }

    pub(crate) fn with_human_identity(
        mut self,
        identity: Option<registry_review_client::HumanIdentity>,
    ) -> Result<Self, VerifiedContextError> {
        self.human_identity = identity;
        Ok(self)
    }

    /// Fill the reserved consent claims from the verified client's recipient
    /// set and the compiled feed decision sets. Any same-named value already
    /// present is discarded first: no token supplies a reserved claim. An
    /// empty recipient set leaves `registry:recipients` absent, so a feed
    /// boundary on it refuses the request.
    pub(crate) fn with_consent_claims(
        mut self,
        recipients: BTreeSet<String>,
        decisions: &BTreeMap<String, BTreeSet<String>>,
    ) -> Result<Self, VerifiedContextError> {
        self.direct_claims
            .retain(|name, _| !crate::consent::is_reserved_claim(name));
        if !recipients.is_empty() {
            self.direct_claims.insert(
                crate::consent::RECIPIENTS_CLAIM.to_owned(),
                VerifiedClaimValue::direct_string_set(recipients.iter().cloned())?,
            );
        }
        for (entity, values) in decisions {
            self.direct_claims.insert(
                crate::consent::decisions_claim(entity),
                VerifiedClaimValue::direct_string_set(values.iter().cloned())?,
            );
        }
        self.recipients = recipients;
        Ok(self)
    }

    /// The consent recipients the verified client acts for: its organization
    /// and every group containing it. Empty for an unmapped client.
    pub(crate) fn recipients(&self) -> &BTreeSet<String> {
        &self.recipients
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

    pub(crate) fn actor_kind(&self) -> Option<ActorKind> {
        self.actor_kind
    }
    pub(crate) fn requester_client(&self) -> Option<&str> {
        self.requester_client.as_deref()
    }
    pub(crate) fn actor_subject(&self) -> Option<&str> {
        self.actor_subject.as_deref()
    }
    pub(crate) fn grant(&self) -> Option<&GrantClaims> {
        self.grant.as_ref()
    }
    pub(crate) fn grant_subjects(&self) -> &BTreeMap<String, Value> {
        &self.grant_subjects
    }
    pub(crate) fn human_identity(&self) -> Option<&registry_review_client::HumanIdentity> {
        self.human_identity.as_ref()
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
            .field("actor_kind", &self.actor_kind)
            .field(
                "requester_client",
                &self.requester_client.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "actor_subject",
                &self.actor_subject.as_ref().map(|_| "<redacted>"),
            )
            .field("task_grant", &self.grant.as_ref().map(|_| "<redacted>"))
            .field("recipient_count", &self.recipients.len())
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
    requester_client: Option<String>,
    forwarded_access_attribution: Option<crate::subject_access_log::ForwardedAccessAttribution>,
    selected_profile: String,
    row_boundaries: Vec<VerifiedRowBoundary>,
    task_grant: Option<TaskGrantBinding>,
    grant_audit: Option<crate::audit::GrantAuditContext>,
    human_identity: Option<registry_review_client::HumanIdentity>,
    recipients: BTreeSet<String>,
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
            requester_client: None,
            forwarded_access_attribution: None,
            selected_profile,
            row_boundaries,
            task_grant: None,
            grant_audit: None,
            human_identity: None,
            recipients: BTreeSet::new(),
        }
    }

    /// Carry the verified client's consent recipient set into the session
    /// context every consent probe reads.
    pub(crate) fn with_recipients(mut self, claims: &VerifiedRequestClaims) -> Self {
        self.recipients = claims.recipients().clone();
        self
    }

    pub(crate) fn recipients(&self) -> &BTreeSet<String> {
        &self.recipients
    }

    pub(crate) fn with_grant_audit(mut self, claims: &VerifiedRequestClaims) -> Self {
        self.grant_audit = crate::audit::GrantAuditContext::from_claims(claims);
        self.human_identity = claims.human_identity().cloned();
        self.requester_client = claims.requester_client().map(str::to_owned);
        self
    }

    pub(crate) fn requester_client(&self) -> Option<&str> {
        self.requester_client.as_deref()
    }

    pub(crate) fn forwarded_access_attribution(
        &self,
    ) -> Option<&crate::subject_access_log::ForwardedAccessAttribution> {
        self.forwarded_access_attribution.as_ref()
    }

    pub(crate) fn bind_access_attribution(
        &mut self,
        entity: &crate::model::CompiledEntity,
        headers: &axum::http::HeaderMap,
    ) -> Result<(), ()> {
        self.forwarded_access_attribution =
            crate::subject_access_log::forwarded_attribution(entity, self, headers)?;
        Ok(())
    }
    pub(crate) fn grant_audit(&self) -> Option<&crate::audit::GrantAuditContext> {
        self.grant_audit.as_ref()
    }
    pub(crate) fn human_identity(&self) -> Option<&registry_review_client::HumanIdentity> {
        self.human_identity.as_ref()
    }

    pub(crate) fn with_task_grant(mut self, grant: Option<TaskGrantBinding>) -> Self {
        self.task_grant = grant;
        self
    }

    pub fn task_grant(&self) -> Option<&TaskGrantBinding> {
        self.task_grant.as_ref()
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
            .field(
                "task_grant",
                &self.task_grant.as_ref().map(|_| "<redacted>"),
            )
            .field("recipient_count", &self.recipients.len())
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
    grant_audit: Option<crate::audit::GrantAuditContext>,
    task_grant: Option<TaskGrantBinding>,
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
            grant_audit: None,
            task_grant: None,
        }
    }

    pub(crate) fn with_grant_audit(mut self, claims: &VerifiedRequestClaims) -> Self {
        self.grant_audit = crate::audit::GrantAuditContext::from_claims(claims);
        self
    }
    pub(crate) fn grant_audit(&self) -> Option<&crate::audit::GrantAuditContext> {
        self.grant_audit.as_ref()
    }

    pub(crate) fn with_task_grant(mut self, grant: Option<TaskGrantBinding>) -> Self {
        self.task_grant = grant;
        self
    }

    pub(crate) fn task_grant(&self) -> Option<&TaskGrantBinding> {
        self.task_grant.as_ref()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_context_preserves_identity_values_larger_than_review_protocol_bounds() {
        let identity = registry_review_client::HumanIdentity {
            issuer: format!("https://identity.example/{}", "i".repeat(300)),
            subject: "s".repeat(300),
        };
        let claims = VerifiedRequestClaims::authenticated(
            "sub",
            "ordinary-principal",
            BTreeSet::new(),
            None,
            BTreeMap::new(),
        )
        .unwrap()
        .with_human_identity(Some(identity.clone()))
        .expect("authentication supports the configured OIDC claim bounds");
        assert_eq!(claims.human_identity(), Some(&identity));
        assert!(
            identity.check().is_err(),
            "review submission remains bounded"
        );
    }
}
