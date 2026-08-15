//! One fail-closed authorization and selector-resolution decision.

use std::{collections::BTreeSet, fmt};

use chrono::NaiveDate;
use serde_json::Value;
use thiserror::Error;

use crate::{
    auth::AuthenticatedContext,
    binding::{
        subject_binding, BindingError, SelectorField as BindingField,
        SelectorScalar as BindingScalar, SubjectBindingInput, SubjectBindingScope,
    },
    bundle::{Bundle, Codelist},
    config::{
        AuthorityKind, GrantedSubject, ResponseFormat, SelectorField as ConfiguredField,
        SelectorProfile, SubjectBindingMode, ValueOrigin, MAX_SAFE_INTEGER,
    },
    model::{EvidenceRequest, RequestedSubject, SelectorValue},
};

const MAX_CANONICAL_BYTES: usize = 64 * 1024;

/// Validate configured subject-binding key material through the same primitive
/// used for released subject bindings. This keeps readiness from duplicating
/// the crypto boundary's key-length and key-version invariants.
pub(crate) fn validate_subject_binding_key(
    key: &[u8],
    key_version: u32,
    trust_domain: &str,
) -> Result<(), AuthorizationError> {
    let fields = [BindingField {
        name: "readiness",
        value: BindingScalar::Boolean(true),
    }];
    subject_binding(
        key,
        key_version,
        SubjectBindingInput {
            trust_domain,
            scope: SubjectBindingScope::Audience("urn:registry-evidence:readiness"),
            purpose: "readiness",
            role: "readiness",
            profile: "readiness-v1",
            fields: &fields,
        },
    )
    .map(|_| ())
    .map_err(|_: BindingError| AuthorizationError::Binding)
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationError {
    #[error("the Evidence request is not authorized")]
    Unauthorized,
    #[error("the Evidence request selector is invalid")]
    Selector,
    #[error("the Evidence authorization decision is ambiguous")]
    AmbiguousAuthority,
    #[error("the Evidence subject binding could not be constructed")]
    Binding,
}

/// Failure of the offline fixture harness, which resolves a captured fixture
/// case through the ordinary authorization boundary.
///
/// A fixture that does not state which purpose it exercises is a fixture
/// contract failure, not an authorization denial. Keeping the two apart stops
/// a harness omission from reading as a rejected request.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum OfflineFixtureError {
    #[error("the offline fixture does not select one of the requirement's purposes")]
    Purpose,
    #[error(transparent)]
    Authorization(#[from] AuthorizationError),
}

#[derive(Clone, PartialEq, Eq)]
pub enum ResolvedSelectorValue {
    String(String),
    Date(String),
    Integer(i64),
    Boolean(bool),
    ControlledCode(String),
}

impl fmt::Debug for ResolvedSelectorValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-selector-value>")
    }
}

impl ResolvedSelectorValue {
    pub fn as_json(&self) -> Value {
        match self {
            Self::String(value) | Self::Date(value) | Self::ControlledCode(value) => {
                Value::String(value.clone())
            }
            Self::Integer(value) => Value::from(*value),
            Self::Boolean(value) => Value::from(*value),
        }
    }

    fn binding_scalar(&self) -> BindingScalar<'_> {
        match self {
            Self::String(value) => BindingScalar::String(value),
            Self::Date(value) => BindingScalar::Date(value),
            Self::Integer(value) => BindingScalar::Integer(*value),
            Self::Boolean(value) => BindingScalar::Boolean(*value),
            Self::ControlledCode(value) => BindingScalar::ControlledCode(value),
        }
    }

    fn canonical_bytes(&self) -> &[u8] {
        match self {
            Self::String(value) | Self::Date(value) | Self::ControlledCode(value) => {
                value.as_bytes()
            }
            Self::Integer(_) | Self::Boolean(_) => &[],
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedSelectorField {
    pub name: String,
    pub value: ResolvedSelectorValue,
}

impl fmt::Debug for ResolvedSelectorField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedSelectorField")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedSubject {
    pub role: String,
    pub selector_profile: String,
    pub value_origin: ValueOrigin,
    pub fields: Vec<ResolvedSelectorField>,
}

impl fmt::Debug for ResolvedSubject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedSubject")
            .field("role", &self.role)
            .field("selector_profile", &self.selector_profile)
            .field("value_origin", &self.value_origin)
            .field(
                "field_names",
                &self
                    .fields
                    .iter()
                    .map(|field| &field.name)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl ResolvedSubject {
    pub fn value(&self, field_name: &str) -> Option<&ResolvedSelectorValue> {
        self.fields
            .iter()
            .find(|field| field.name == field_name)
            .map(|field| &field.value)
    }

    pub fn binding(
        &self,
        key: &[u8],
        key_version: u32,
        trust_domain: &str,
        scope: SubjectBindingScope<'_>,
        purpose: &str,
    ) -> Result<String, AuthorizationError> {
        let fields = self
            .fields
            .iter()
            .map(|field| BindingField {
                name: &field.name,
                value: field.value.binding_scalar(),
            })
            .collect::<Vec<_>>();
        subject_binding(
            key,
            key_version,
            SubjectBindingInput {
                trust_domain,
                scope,
                purpose,
                role: &self.role,
                profile: &self.selector_profile,
                fields: &fields,
            },
        )
        .map_err(|_: BindingError| AuthorizationError::Binding)
    }

    /// Canonical protected input for the one permitted per-subject audit pseudonym.
    ///
    /// The leading byte separates the two subject-binding modes, so an
    /// audience-scoped and a holder-bound resolution over the same purpose,
    /// role, profile, and selector fields can never derive the same pseudonym.
    ///
    /// An audience-scoped input binds the audience after that byte, which is
    /// what keeps two relying parties asking about one subject apart. A
    /// holder-bound input binds no scope component at all: the holder key
    /// thumbprint stays out of audit entirely, so the pseudonym is stable
    /// across issuances for one subject and carries nothing that could pick
    /// one wallet key's activity out of the audit chain.
    pub fn audit_pseudonym_input(
        &self,
        scope: &ResolvedSubjectScope,
        purpose: &str,
    ) -> Result<Vec<u8>, AuthorizationError> {
        let mut output = Vec::new();
        match scope {
            ResolvedSubjectScope::Audience(audience) => {
                output.push(0x01);
                push_component(&mut output, audience.as_bytes())?;
            }
            ResolvedSubjectScope::HolderKeyThumbprint(_) => output.push(0x02),
        }
        push_component(&mut output, purpose.as_bytes())?;
        push_component(&mut output, self.role.as_bytes())?;
        push_component(&mut output, self.selector_profile.as_bytes())?;
        push_count(&mut output, self.fields.len())?;
        for field in &self.fields {
            push_component(&mut output, field.name.as_bytes())?;
            match &field.value {
                ResolvedSelectorValue::String(value) => {
                    output.push(0x01);
                    push_component(&mut output, value.as_bytes())?;
                }
                ResolvedSelectorValue::Date(value) => {
                    output.push(0x02);
                    push_component(&mut output, value.as_bytes())?;
                }
                ResolvedSelectorValue::Integer(value) => {
                    output.push(0x03);
                    push_component(&mut output, value.to_string().as_bytes())?;
                }
                ResolvedSelectorValue::Boolean(value) => {
                    output.push(0x04);
                    push_component(&mut output, &[u8::from(*value)])?;
                }
                ResolvedSelectorValue::ControlledCode(value) => {
                    output.push(0x05);
                    push_component(&mut output, value.as_bytes())?;
                }
            }
        }
        Ok(output)
    }
}

/// The owned form of [`SubjectBindingScope`] carried on a resolved
/// authorization. One enum rather than two optional members keeps a resolution
/// that is holder-bound and audience-scoped at once unrepresentable.
#[derive(Clone, PartialEq, Eq)]
pub enum ResolvedSubjectScope {
    Audience(String),
    HolderKeyThumbprint(String),
}

impl ResolvedSubjectScope {
    /// The component this scope binds a subject binding under: the audience
    /// when audience-scoped and the holder key thumbprint when holder-bound.
    /// Audit pseudonymization binds it only in the audience-scoped mode.
    pub fn component(&self) -> &str {
        match self {
            Self::Audience(audience) => audience,
            Self::HolderKeyThumbprint(thumbprint) => thumbprint,
        }
    }

    /// The relying party this resolution is scoped to, if any. A holder-bound
    /// resolution has none, which is what removes the audience from its
    /// assertion.
    pub fn audience(&self) -> Option<&str> {
        match self {
            Self::Audience(audience) => Some(audience),
            Self::HolderKeyThumbprint(_) => None,
        }
    }

    pub fn as_binding_scope(&self) -> SubjectBindingScope<'_> {
        match self {
            Self::Audience(audience) => SubjectBindingScope::Audience(audience),
            Self::HolderKeyThumbprint(thumbprint) => {
                SubjectBindingScope::HolderKeyThumbprint(thumbprint)
            }
        }
    }
}

/// A holder key thumbprint is a stable public name for one wallet key. It is
/// never rendered in a diagnostic, so a captured log cannot link presentations.
impl fmt::Debug for ResolvedSubjectScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Audience(audience) => formatter
                .debug_tuple("Audience")
                .field(&audience.as_str())
                .finish(),
            Self::HolderKeyThumbprint(_) => formatter
                .debug_tuple("HolderKeyThumbprint")
                .field(&"<redacted>")
                .finish(),
        }
    }
}

#[derive(Clone)]
pub struct ResolvedAuthorization {
    pub authority_profile: String,
    pub authority_kind: AuthorityKind,
    pub grant_id: Option<String>,
    pub grant_authority: Option<String>,
    pub requirement: String,
    pub purpose: String,
    pub subject_scope: ResolvedSubjectScope,
    pub subjects: Vec<ResolvedSubject>,
}

impl fmt::Debug for ResolvedAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedAuthorization")
            .field("authority_profile", &"<redacted>")
            .field("authority_kind", &self.authority_kind)
            .field("grant_id", &self.grant_id.as_ref().map(|_| "<redacted>"))
            .field(
                "grant_authority",
                &self.grant_authority.as_ref().map(|_| "<redacted>"),
            )
            .field("requirement", &self.requirement)
            .field("purpose", &self.purpose)
            .field("subject_scope", &self.subject_scope)
            .field("subjects", &self.subjects)
            .finish()
    }
}

#[derive(Clone)]
pub struct MatchedEntitlement {
    authority_profile: String,
    authority_kind: AuthorityKind,
    response_formats: Vec<ResponseFormat>,
    subject_binding_modes: Vec<SubjectBindingMode>,
    subjects: Vec<GrantedSubject>,
}

impl MatchedEntitlement {
    pub fn authority_profile(&self) -> &str {
        &self.authority_profile
    }

    pub fn authority_kind(&self) -> AuthorityKind {
        self.authority_kind
    }

    /// Report whether this one complete matched grant permits the requested
    /// response format. Permissions are never unioned across grants.
    pub fn permits_response_format(&self, format: ResponseFormat) -> bool {
        self.response_formats.contains(&format)
    }

    pub(crate) fn response_formats(&self) -> &[ResponseFormat] {
        &self.response_formats
    }

    /// Report whether this one complete matched grant permits the binding mode
    /// the requirement is configured for. Permitting a serialization is not
    /// permitting a binding mode, so this is a separate question from
    /// [`Self::permits_response_format`] and both must answer yes.
    pub fn permits_subject_binding(&self, mode: SubjectBindingMode) -> bool {
        if self.subject_binding_modes.is_empty() {
            return mode == SubjectBindingMode::AudienceScoped;
        }
        self.subject_binding_modes.contains(&mode)
    }

    pub(crate) fn subjects(&self) -> &[GrantedSubject] {
        &self.subjects
    }
}

impl fmt::Debug for MatchedEntitlement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MatchedEntitlement")
            .field("authority_profile", &"<redacted>")
            .field("authority_kind", &self.authority_kind)
            .field("subject_count", &self.subjects.len())
            .finish()
    }
}

/// Match exactly one complete entitlement without inspecting selector values.
///
/// Keeping this decision separate lets the service charge invalid selector
/// attempts to the matched authority profile before resolving any protected
/// values. It performs no credential resolution and no source access.
pub fn match_entitlement(
    bundle: &Bundle,
    request: &EvidenceRequest,
    context: &AuthenticatedContext,
) -> Result<MatchedEntitlement, AuthorizationError> {
    let requirement = bundle
        .config
        .requirements
        .iter()
        .find(|candidate| candidate.id == request.requirement)
        .ok_or(AuthorizationError::Unauthorized)?;
    if !requirement
        .purposes
        .iter()
        .any(|purpose| purpose == &request.purpose)
    {
        return Err(AuthorizationError::Unauthorized);
    }
    validate_request_subject_shape(requirement, &request.subjects)?;

    let mut matched = Vec::new();
    for (authority_profile, authority) in bundle.config.authority_profiles.iter() {
        if !authority.requester_tags.iter().all(|required| {
            context
                .requester_tags()
                .iter()
                .any(|actual| actual == required)
        }) {
            continue;
        }
        if context.actor().is_some() && authority.kind != AuthorityKind::Delegated {
            continue;
        }
        for grant in &authority.grants {
            if grant.requirement != request.requirement
                || grant.purpose != request.purpose
                || !same_subject_tuples(&grant.subjects, &request.subjects)
            {
                continue;
            }
            let uses_authenticated_grant = grant
                .subjects
                .iter()
                .any(|subject| subject.value_origin == ValueOrigin::AuthenticatedGrant);
            if uses_authenticated_grant && context.grant_authority() != Some(authority_profile) {
                continue;
            }
            matched.push(MatchedEntitlement {
                authority_profile: authority_profile.to_owned(),
                authority_kind: authority.kind,
                response_formats: grant.response_formats.clone(),
                subject_binding_modes: grant.subject_binding_modes.clone(),
                subjects: grant.subjects.clone(),
            });
        }
    }

    match matched.len() {
        1 => Ok(matched.remove(0)),
        0 => Err(AuthorizationError::Unauthorized),
        _ => Err(AuthorizationError::AmbiguousAuthority),
    }
}

/// Resolve the complete role-bound selector set for one matched entitlement.
///
/// This is the first operation that inspects caller or authenticated-grant
/// selector values. It still performs no credential resolution or source
/// access.
pub fn resolve_selectors(
    bundle: &Bundle,
    request: &EvidenceRequest,
    context: &AuthenticatedContext,
    matched: &MatchedEntitlement,
) -> Result<ResolvedAuthorization, AuthorizationError> {
    let requirement = bundle
        .config
        .requirements
        .iter()
        .find(|candidate| candidate.id == request.requirement)
        .ok_or(AuthorizationError::Unauthorized)?;
    let subjects = resolve_grant_subjects(
        bundle,
        requirement,
        &matched.subjects,
        &request.subjects,
        context,
    )?;
    let uses_authenticated_grant = matched
        .subjects
        .iter()
        .any(|subject| subject.value_origin == ValueOrigin::AuthenticatedGrant);
    let subject_scope =
        resolve_subject_scope(requirement.subject_binding_mode(), request, context)?;
    Ok(ResolvedAuthorization {
        authority_profile: matched.authority_profile.clone(),
        authority_kind: matched.authority_kind,
        grant_id: uses_authenticated_grant
            .then(|| context.grant_id().map(ToOwned::to_owned))
            .flatten(),
        grant_authority: uses_authenticated_grant
            .then(|| context.grant_authority().map(ToOwned::to_owned))
            .flatten(),
        requirement: request.requirement.clone(),
        purpose: request.purpose.clone(),
        subject_scope,
        subjects,
    })
}

/// Derive the one scope every subject binding of this resolution is computed
/// under, from the requirement's configured binding mode.
///
/// An audience-scoped requirement binds the authenticated evidence audience, as
/// it always has. A holder-bound requirement binds the thumbprint of the holder
/// key the request presented, and never the audience: that substitution is what
/// makes a holder-bound assertion presentable to a party the issuer never named.
///
/// A holder-bound requirement reaching here without a holder key is refused. The
/// public request boundary answers a missing key earlier and more precisely;
/// this is the fail-closed floor under offline callers, which cannot be reached
/// through a served request.
///
/// A request presenting several keys resolves under the first of them. Every
/// released credential carries the binding of its own key, derived per member
/// at construction; this resolution names the one scope the audit material and
/// the declared assertion scope are computed under.
fn resolve_subject_scope(
    mode: SubjectBindingMode,
    request: &EvidenceRequest,
    context: &AuthenticatedContext,
) -> Result<ResolvedSubjectScope, AuthorizationError> {
    match mode {
        SubjectBindingMode::AudienceScoped => Ok(ResolvedSubjectScope::Audience(
            context.evidence_audience().to_owned(),
        )),
        SubjectBindingMode::HolderBound => {
            let key = request
                .holder_keys
                .first()
                .ok_or(AuthorizationError::Binding)?;
            let thumbprint = registry_evidence_verifier::sdjwt_vc::holder_thumbprint(key)
                .map_err(|_| AuthorizationError::Binding)?;
            Ok(ResolvedSubjectScope::HolderKeyThumbprint(thumbprint))
        }
    }
}

/// Confirm that selector values owned by the authenticated context or grant
/// are present and valid before advertising an entitlement. Request-owned
/// selector values are intentionally not inspected during discovery.
pub(crate) fn validate_entitlement_context(
    bundle: &Bundle,
    context: &AuthenticatedContext,
    matched: &MatchedEntitlement,
) -> Result<(), AuthorizationError> {
    let uses_authenticated_grant = matched
        .subjects
        .iter()
        .any(|subject| subject.value_origin == ValueOrigin::AuthenticatedGrant);
    if uses_authenticated_grant
        && (context.grant_id().is_none()
            || context.grant_authority() != Some(matched.authority_profile()))
    {
        return Err(AuthorizationError::Unauthorized);
    }

    for grant in &matched.subjects {
        if grant.value_origin == ValueOrigin::Request {
            continue;
        }
        let profile = bundle
            .config
            .selector_profiles
            .get(&grant.selector_profile)
            .ok_or(AuthorizationError::Unauthorized)?;
        let claims = grant
            .value_claims
            .as_ref()
            .ok_or(AuthorizationError::Unauthorized)?;
        let values = claims
            .iter()
            .map(|(field, path)| {
                let value = context
                    .claim_path(path)
                    .and_then(selector_value_from_claim)
                    .ok_or(AuthorizationError::Selector)?;
                Ok((field.to_owned(), value))
            })
            .collect::<Result<_, AuthorizationError>>()?;
        validate_values(bundle, profile, &values)?;
    }
    Ok(())
}

/// Resolve exactly one complete entitlement and its complete selector set.
///
/// Service code that applies the failed-selector budget uses
/// [`match_entitlement`] and [`resolve_selectors`] separately. Offline callers
/// may use this convenience wrapper.
pub fn authorize_and_resolve(
    bundle: &Bundle,
    request: &EvidenceRequest,
    context: &AuthenticatedContext,
) -> Result<ResolvedAuthorization, AuthorizationError> {
    let matched = match_entitlement(bundle, request, context)?;
    resolve_selectors(bundle, request, context, &matched)
}

/// Resolve one statically configured request-origin subject shape without
/// authenticating or authorizing a caller.
///
/// The local adopter path uses this before the request exists on the HTTP
/// boundary. It proves only that the bundle defines the requirement, purpose,
/// roles, profiles, and request-owned selector values needed to derive exact
/// bindings. It deliberately does not inspect requester tags or select an
/// entitlement for a caller. The running service remains the only authority
/// that may accept the eventual request.
pub(crate) fn resolve_request_origin_subjects(
    bundle: &Bundle,
    requirement: &crate::config::RequirementConfig,
    purpose: &str,
    requested: &[RequestedSubject],
) -> Result<Vec<ResolvedSubject>, AuthorizationError> {
    validate_request_subject_shape(requirement, requested)?;
    if !requirement
        .purposes
        .iter()
        .any(|configured| configured == purpose)
    {
        return Err(AuthorizationError::Unauthorized);
    }

    // Value origin belongs to the configured request shape. At least one
    // authority profile must expose this exact tuple as request-owned, but no
    // profile is chosen and no caller-specific condition is evaluated here.
    // Local access policies deliberately repeat the same shape under distinct
    // requester tags, so requiring uniqueness would turn static preparation
    // back into a premature authorization decision.
    let configured_as_request_origin = bundle
        .config
        .authority_profiles
        .iter()
        .flat_map(|(_, authority)| &authority.grants)
        .any(|grant| {
            grant.requirement == requirement.id
                && grant.purpose == purpose
                && same_subject_tuples(&grant.subjects, requested)
                && grant
                    .subjects
                    .iter()
                    .all(|subject| subject.value_origin == ValueOrigin::Request)
        });
    if !configured_as_request_origin {
        return Err(AuthorizationError::Unauthorized);
    }

    // Emit the requirement's declaration order. Request array position has no
    // meaning, while selector field declaration order is binding-significant
    // and is preserved by `validate_values`.
    requirement
        .subject_roles
        .iter()
        .map(|declared| {
            let subject = requested
                .iter()
                .find(|subject| subject.role == declared.role)
                .ok_or(AuthorizationError::Unauthorized)?;
            let profile = bundle
                .config
                .selector_profiles
                .get(&subject.selector.profile)
                .ok_or(AuthorizationError::Unauthorized)?;
            let values = subject
                .selector
                .values
                .as_ref()
                .ok_or(AuthorizationError::Selector)?;
            let fields = validate_values(bundle, profile, values)?;
            Ok(ResolvedSubject {
                role: subject.role.clone(),
                selector_profile: subject.selector.profile.clone(),
                value_origin: ValueOrigin::Request,
                fields,
            })
        })
        .collect()
}

/// Exercise the normal authorization and selector boundary for one captured
/// offline fixture subject set without token, credential, or source access.
///
/// Fixture JSON uses the compact `{role, profile, values}` representation from
/// the reviewed product bundles. No selector value is included in an error.
pub fn resolve_offline_fixture_authorization(
    bundle: &Bundle,
    requirement: &crate::config::RequirementConfig,
    common: Option<&serde_json::Map<String, Value>>,
    case: &serde_json::Map<String, Value>,
    audience: &str,
) -> Result<ResolvedAuthorization, OfflineFixtureError> {
    let purpose = fixture_purpose(&requirement.purposes, common, case)?;
    let subjects = if let Some(subjects) = case
        .get("subjects")
        .or_else(|| common.and_then(|value| value.get("subjects")))
        .and_then(Value::as_array)
    {
        subjects
            .iter()
            .map(parse_fixture_subject)
            .collect::<Result<Vec<_>, _>>()?
    } else {
        fixture_subjects_from_selectors(bundle, requirement, purpose, common, case)?
    };
    // A holder-bound requirement resolves its subject scope from a presented
    // key, so offline evaluation presents the canonical offline stand-in. The
    // mode is read from the bundle rather than from the fixture: what a
    // requirement issues under is a deployment declaration, and a case that
    // could ask for a scope of its own would be evaluating a bundle nobody
    // deployed.
    let holder_keys = match requirement.subject_binding_mode() {
        SubjectBindingMode::AudienceScoped => Vec::new(),
        SubjectBindingMode::HolderBound => vec![crate::model::offline_evaluation_holder_key()],
    };
    let request = EvidenceRequest {
        request_nonce: crate::model::OFFLINE_EVALUATION_REQUEST_NONCE.to_owned(),
        requirement: requirement.id.clone(),
        purpose: purpose.to_owned(),
        subjects,
        holder_keys,
    };
    let (authority_name, authority) = bundle
        .config
        .authority_profiles
        .iter()
        .find(|(_, authority)| {
            authority.grants.iter().any(|grant| {
                grant.requirement == request.requirement
                    && grant.purpose == request.purpose
                    && same_subject_tuples(&grant.subjects, &request.subjects)
            })
        })
        .ok_or(AuthorizationError::Unauthorized)?;
    let claims = case
        .get("verified_token_claims")
        .or_else(|| common.and_then(|value| value.get("verified_token_claims")))
        .cloned()
        .unwrap_or_else(|| Value::Object(Default::default()));
    let grant_id = claims
        .get("evidence_grant_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let grant_authority = claims
        .get("evidence_authority")
        .and_then(Value::as_str)
        .unwrap_or(authority_name)
        .to_owned();
    let context = AuthenticatedContext::offline_fixture_context(
        authority.requester_tags.clone(),
        audience,
        grant_id.as_deref(),
        Some(&grant_authority),
        claims,
    );
    Ok(authorize_and_resolve(bundle, &request, &context)?)
}

/// Resolve the purpose one fixture case exercises.
///
/// A requirement declaring more than one purpose must say which one the case
/// covers, in the case or in the inherited common block. The harness never
/// chooses on the fixture's behalf, so offline evaluation reaches every
/// authorized purpose and no purpose is silently skipped.
fn fixture_purpose<'a>(
    purposes: &'a [String],
    common: Option<&serde_json::Map<String, Value>>,
    case: &serde_json::Map<String, Value>,
) -> Result<&'a str, OfflineFixtureError> {
    match case
        .get("purpose")
        .or_else(|| common.and_then(|common| common.get("purpose")))
    {
        Some(declared) => {
            let declared = declared.as_str().ok_or(OfflineFixtureError::Purpose)?;
            purposes
                .iter()
                .find(|purpose| purpose.as_str() == declared)
                .map(String::as_str)
                .ok_or(OfflineFixtureError::Authorization(
                    AuthorizationError::Unauthorized,
                ))
        }
        None => match purposes {
            [only] => Ok(only.as_str()),
            _ => Err(OfflineFixtureError::Purpose),
        },
    }
}

fn fixture_subjects_from_selectors(
    bundle: &Bundle,
    requirement: &crate::config::RequirementConfig,
    purpose: &str,
    common: Option<&serde_json::Map<String, Value>>,
    case: &serde_json::Map<String, Value>,
) -> Result<Vec<RequestedSubject>, AuthorizationError> {
    let mut selectors = case
        .get("selectors")
        .or_else(|| common.and_then(|value| value.get("selectors")))
        .and_then(Value::as_object)
        .cloned()
        .ok_or(AuthorizationError::Selector)?;
    if let Some(overrides) = case.get("selectorOverrides") {
        let overrides = overrides.as_object().ok_or(AuthorizationError::Selector)?;
        for (role, replacement) in overrides {
            let replacement = replacement
                .as_object()
                .filter(|object| object.keys().all(|key| key == "profile" || key == "values"))
                .ok_or(AuthorizationError::Selector)?;
            let selector = selectors
                .get_mut(role)
                .and_then(Value::as_object_mut)
                .ok_or(AuthorizationError::Selector)?;
            for (name, value) in replacement {
                selector.insert(name.clone(), value.clone());
            }
        }
    }

    let mut requested = Vec::with_capacity(requirement.subject_roles.len());
    for configured_role in &requirement.subject_roles {
        let mut selector = selectors
            .remove(&configured_role.role)
            .and_then(|value| value.as_object().cloned())
            .ok_or(AuthorizationError::Selector)?;
        selector.insert(
            "role".to_owned(),
            Value::String(configured_role.role.clone()),
        );
        requested.push(parse_fixture_subject(&Value::Object(selector))?);
    }
    if !selectors.is_empty() {
        return Err(AuthorizationError::Selector);
    }

    let grant = bundle
        .config
        .authority_profiles
        .iter()
        .flat_map(|(_, authority)| authority.grants.iter())
        .find(|grant| {
            grant.requirement == requirement.id
                && grant.purpose == purpose
                && same_subject_tuples(&grant.subjects, &requested)
        })
        .ok_or(AuthorizationError::Unauthorized)?;
    for subject in &mut requested {
        let granted = grant
            .subjects
            .iter()
            .find(|granted| granted.role == subject.role)
            .ok_or(AuthorizationError::Unauthorized)?;
        if granted.value_origin != ValueOrigin::Request {
            subject.selector.values = None;
        }
    }
    Ok(requested)
}

pub fn resolve_offline_fixture_subjects(
    bundle: &Bundle,
    requirement: &crate::config::RequirementConfig,
    common: Option<&serde_json::Map<String, Value>>,
    case: &serde_json::Map<String, Value>,
    audience: &str,
) -> Result<Vec<String>, OfflineFixtureError> {
    resolve_offline_fixture_authorization(bundle, requirement, common, case, audience).map(
        |resolved| {
            resolved
                .subjects
                .into_iter()
                .map(|subject| subject.role)
                .collect()
        },
    )
}

fn parse_fixture_subject(value: &Value) -> Result<RequestedSubject, AuthorizationError> {
    let object = value.as_object().ok_or(AuthorizationError::Selector)?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "role" | "profile" | "values"))
    {
        return Err(AuthorizationError::Selector);
    }
    let role = object
        .get("role")
        .and_then(Value::as_str)
        .ok_or(AuthorizationError::Selector)?;
    let profile = object
        .get("profile")
        .and_then(Value::as_str)
        .ok_or(AuthorizationError::Selector)?;
    let values = object
        .get("values")
        .map(|values| {
            values
                .as_object()
                .ok_or(AuthorizationError::Selector)?
                .iter()
                .map(|(name, value)| {
                    let value = match value {
                        Value::String(value) => SelectorValue::String(value.clone()),
                        Value::Number(value) => value
                            .as_i64()
                            .map(SelectorValue::Integer)
                            .ok_or(AuthorizationError::Selector)?,
                        Value::Bool(value) => SelectorValue::Boolean(*value),
                        _ => return Err(AuthorizationError::Selector),
                    };
                    Ok((name.clone(), value))
                })
                .collect::<Result<_, AuthorizationError>>()
        })
        .transpose()?;
    Ok(RequestedSubject {
        role: role.to_owned(),
        selector: crate::model::RequestedSelector {
            profile: profile.to_owned(),
            values,
        },
    })
}

fn validate_request_subject_shape(
    requirement: &crate::config::RequirementConfig,
    requested: &[RequestedSubject],
) -> Result<(), AuthorizationError> {
    if requested.len() != requirement.subject_roles.len() {
        return Err(AuthorizationError::Unauthorized);
    }
    let mut roles = BTreeSet::new();
    for subject in requested {
        if !roles.insert(subject.role.as_str()) {
            return Err(AuthorizationError::Unauthorized);
        }
        let configured = requirement
            .subject_roles
            .iter()
            .find(|configured| configured.role == subject.role)
            .ok_or(AuthorizationError::Unauthorized)?;
        if !configured
            .selector_profiles
            .iter()
            .any(|profile| profile == &subject.selector.profile)
        {
            return Err(AuthorizationError::Unauthorized);
        }
    }
    Ok(())
}

fn same_subject_tuples(granted: &[GrantedSubject], requested: &[RequestedSubject]) -> bool {
    granted.len() == requested.len()
        && granted.iter().all(|grant| {
            requested.iter().any(|subject| {
                subject.role == grant.role && subject.selector.profile == grant.selector_profile
            })
        })
}

/// Resolve subjects by unique role and emit the requirement's declaration
/// order. Neither grant order nor request array order is semantic.
fn resolve_grant_subjects(
    bundle: &Bundle,
    requirement: &crate::config::RequirementConfig,
    granted: &[GrantedSubject],
    requested: &[RequestedSubject],
    context: &AuthenticatedContext,
) -> Result<Vec<ResolvedSubject>, AuthorizationError> {
    let uses_authenticated_grant = granted
        .iter()
        .any(|subject| subject.value_origin == ValueOrigin::AuthenticatedGrant);
    if uses_authenticated_grant
        && (context.grant_id().is_none() || context.grant_authority().is_none())
    {
        return Err(AuthorizationError::Unauthorized);
    }
    if granted.len() != requirement.subject_roles.len() {
        return Err(AuthorizationError::Unauthorized);
    }

    requirement
        .subject_roles
        .iter()
        .map(|declared| {
            let grant = granted
                .iter()
                .find(|grant| grant.role == declared.role)
                .ok_or(AuthorizationError::Unauthorized)?;
            let subject = requested
                .iter()
                .find(|subject| subject.role == grant.role)
                .ok_or(AuthorizationError::Unauthorized)?;
            let profile = bundle
                .config
                .selector_profiles
                .get(&grant.selector_profile)
                .ok_or(AuthorizationError::Unauthorized)?;
            let input = match grant.value_origin {
                ValueOrigin::Request => subject
                    .selector
                    .values
                    .as_ref()
                    .ok_or(AuthorizationError::Selector)?
                    .clone(),
                ValueOrigin::AuthenticatedContext | ValueOrigin::AuthenticatedGrant => {
                    if subject.selector.values.is_some() {
                        return Err(AuthorizationError::Selector);
                    }
                    let claims = grant
                        .value_claims
                        .as_ref()
                        .ok_or(AuthorizationError::Unauthorized)?;
                    claims
                        .iter()
                        .map(|(field, path)| {
                            let value = context
                                .claim_path(path)
                                .and_then(selector_value_from_claim)
                                .ok_or(AuthorizationError::Selector)?;
                            Ok((field.to_owned(), value))
                        })
                        .collect::<Result<_, AuthorizationError>>()?
                }
            };
            let fields = validate_values(bundle, profile, &input)?;
            Ok(ResolvedSubject {
                role: grant.role.clone(),
                selector_profile: subject.selector.profile.clone(),
                value_origin: grant.value_origin,
                fields,
            })
        })
        .collect()
}

fn selector_value_from_claim(value: &Value) -> Option<SelectorValue> {
    match value {
        Value::String(value) => Some(SelectorValue::String(value.clone())),
        Value::Number(value) => value.as_i64().map(SelectorValue::Integer),
        Value::Bool(value) => Some(SelectorValue::Boolean(*value)),
        _ => None,
    }
}

fn validate_values(
    bundle: &Bundle,
    profile: &SelectorProfile,
    values: &std::collections::BTreeMap<String, SelectorValue>,
) -> Result<Vec<ResolvedSelectorField>, AuthorizationError> {
    if values.len() != profile.fields.len()
        || profile
            .fields
            .keys()
            .any(|field| !values.contains_key(field))
        || values
            .keys()
            .any(|field| !profile.fields.contains_key(field))
    {
        return Err(AuthorizationError::Selector);
    }

    let mut aggregate_bytes = 0_u64;
    let mut output = Vec::with_capacity(values.len());
    for (name, configured) in profile.fields.iter() {
        let supplied = values.get(name).ok_or(AuthorizationError::Selector)?;
        let resolved = validate_value(bundle, configured, supplied)?;
        let value_bytes = match &resolved {
            ResolvedSelectorValue::Integer(value) => value.to_string().len(),
            ResolvedSelectorValue::Boolean(_) => 1,
            _ => resolved.canonical_bytes().len(),
        };
        aggregate_bytes = aggregate_bytes
            .checked_add(u64::try_from(value_bytes).map_err(|_| AuthorizationError::Selector)?)
            .ok_or(AuthorizationError::Selector)?;
        output.push(ResolvedSelectorField {
            name: name.to_owned(),
            value: resolved,
        });
    }
    if aggregate_bytes > profile.maximum_aggregate_bytes {
        return Err(AuthorizationError::Selector);
    }
    Ok(output)
}

fn validate_value(
    bundle: &Bundle,
    configured: &ConfiguredField,
    supplied: &SelectorValue,
) -> Result<ResolvedSelectorValue, AuthorizationError> {
    match (configured, supplied) {
        (
            ConfiguredField::String {
                minimum_bytes,
                maximum_bytes,
            },
            SelectorValue::String(value),
        ) if bounded(value.len(), *minimum_bytes, *maximum_bytes) => {
            Ok(ResolvedSelectorValue::String(value.clone()))
        }
        (ConfiguredField::Date, SelectorValue::String(value))
            if canonical_date(value).is_some() =>
        {
            Ok(ResolvedSelectorValue::Date(value.clone()))
        }
        (ConfiguredField::Integer { minimum, maximum }, SelectorValue::Integer(value))
            if value >= minimum
                && value <= maximum
                && value.unsigned_abs() <= MAX_SAFE_INTEGER as u64 =>
        {
            Ok(ResolvedSelectorValue::Integer(*value))
        }
        (ConfiguredField::Boolean, SelectorValue::Boolean(value)) => {
            Ok(ResolvedSelectorValue::Boolean(*value))
        }
        (
            ConfiguredField::ControlledCode {
                codelist,
                codelist_version,
                maximum_bytes,
            },
            SelectorValue::String(value),
        ) if bounded(value.len(), 1, *maximum_bytes) => {
            let list = bundle
                .codelist(codelist)
                .ok_or(AuthorizationError::Selector)?;
            if list.version() != codelist_version || !codelist_contains_selector_value(list, value)
            {
                return Err(AuthorizationError::Selector);
            }
            Ok(ResolvedSelectorValue::ControlledCode(value.clone()))
        }
        _ => Err(AuthorizationError::Selector),
    }
}

fn codelist_contains_selector_value(codelist: &Codelist, value: &str) -> bool {
    match codelist {
        Codelist::Codes { codes, .. } => codes.iter().any(|code| code == value),
        Codelist::Mapping { entries, .. } => entries.contains_key(value),
    }
}

fn canonical_date(value: &str) -> Option<NaiveDate> {
    if value.len() != 10 {
        return None;
    }
    NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .ok()
        .filter(|date| date.format("%Y-%m-%d").to_string() == value)
}

fn bounded(actual: usize, minimum: u64, maximum: u64) -> bool {
    u64::try_from(actual).is_ok_and(|actual| (minimum..=maximum).contains(&actual))
}

fn push_component(output: &mut Vec<u8>, component: &[u8]) -> Result<(), AuthorizationError> {
    if component.is_empty() || output.len().saturating_add(component.len()) > MAX_CANONICAL_BYTES {
        return Err(AuthorizationError::Selector);
    }
    let length = u32::try_from(component.len()).map_err(|_| AuthorizationError::Selector)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(component);
    Ok(())
}

fn push_count(output: &mut Vec<u8>, count: usize) -> Result<(), AuthorizationError> {
    let count = u32::try_from(count).map_err(|_| AuthorizationError::Selector)?;
    output.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::model::HolderPublicKey;

    #[test]
    fn resolved_selector_debug_never_exposes_values() {
        let subject = ResolvedSubject {
            role: "subject".to_owned(),
            selector_profile: "opaque-v1".to_owned(),
            value_origin: ValueOrigin::Request,
            fields: vec![ResolvedSelectorField {
                name: "opaque".to_owned(),
                value: ResolvedSelectorValue::String("selector-canary".to_owned()),
            }],
        };
        let debug = format!("{subject:?}");
        assert!(!debug.contains("selector-canary"));
        assert!(debug.contains("opaque"));
    }

    #[test]
    fn canonical_selector_input_is_order_and_audience_sensitive() {
        let subject = ResolvedSubject {
            role: "subject".to_owned(),
            selector_profile: "opaque-v1".to_owned(),
            value_origin: ValueOrigin::Request,
            fields: vec![ResolvedSelectorField {
                name: "field".to_owned(),
                value: ResolvedSelectorValue::String("value".to_owned()),
            }],
        };
        let first = subject
            .audit_pseudonym_input(
                &ResolvedSubjectScope::Audience("urn:audience:a".to_owned()),
                "purpose",
            )
            .expect("canonicalizes");
        let second = subject
            .audit_pseudonym_input(
                &ResolvedSubjectScope::Audience("urn:audience:b".to_owned()),
                "purpose",
            )
            .expect("canonicalizes");
        assert_ne!(first, second);

        // The mode version byte alone separates the two modes, so a
        // holder-bound input over the same purpose, role, profile, and fields
        // never collides with an audience-scoped one.
        let holder = subject
            .audit_pseudonym_input(
                &ResolvedSubjectScope::HolderKeyThumbprint("urn:audience:a".to_owned()),
                "purpose",
            )
            .expect("canonicalizes");
        assert_ne!(first, holder);
    }

    /// A holder-bound audit pseudonym names one subject under one purpose, and
    /// nothing about the wallet that asked. Two holders of the same subject
    /// material must therefore canonicalize identically, or the audit chain
    /// would carry a per-wallet handle for that subject.
    #[test]
    fn a_holder_bound_audit_input_is_the_same_for_every_holder() {
        let subject = audit_input_subject();
        let first = subject
            .audit_pseudonym_input(
                &ResolvedSubjectScope::HolderKeyThumbprint(FIRST_THUMBPRINT.to_owned()),
                "purpose",
            )
            .expect("canonicalizes");
        let second = subject
            .audit_pseudonym_input(
                &ResolvedSubjectScope::HolderKeyThumbprint(SECOND_THUMBPRINT.to_owned()),
                "purpose",
            )
            .expect("canonicalizes");
        assert_eq!(first, second);
    }

    /// The order a batch presents its keys in is not a fact about the subject.
    /// The resolution scope follows the first key, so an audit input that read
    /// that scope's component would record a different pseudonym for the same
    /// operation whenever a caller shuffled its keys.
    #[test]
    fn a_batch_audit_input_is_invariant_under_holder_key_order() {
        let subject = audit_input_subject();
        let context = AuthenticatedContext::test_context(
            "principal",
            Vec::new(),
            "urn:example:relying-party",
            None,
            None,
            Value::Null,
        );
        let presented = holder_key_request(vec![holder_key(0), holder_key(1)]);
        let shuffled = holder_key_request(vec![holder_key(1), holder_key(0)]);

        let first = resolve_subject_scope(SubjectBindingMode::HolderBound, &presented, &context)
            .expect("resolves");
        let second = resolve_subject_scope(SubjectBindingMode::HolderBound, &shuffled, &context)
            .expect("resolves");
        assert_ne!(
            first.component(),
            second.component(),
            "the two orders resolve under different keys, which is what the audit input must ignore"
        );

        assert_eq!(
            subject
                .audit_pseudonym_input(&first, "purpose")
                .expect("canonicalizes"),
            subject
                .audit_pseudonym_input(&second, "purpose")
                .expect("canonicalizes")
        );
    }

    /// Two 43-character unpadded base64url strings, the form RFC 7638 gives a
    /// SHA-256 thumbprint.
    const FIRST_THUMBPRINT: &str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG";
    const SECOND_THUMBPRINT: &str = "HIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmn";

    /// Distinct P-256 public keys as `(x, y)` coordinate pairs. Each pair is a
    /// real curve point, because a key the request boundary would refuse never
    /// reaches scope resolution.
    const HOLDER_COORDINATES: [(&str, &str); 2] = [
        (
            "rVMhRw_AQKeDul4F-iEv56CtlyJKrM6u5xi2bFAUq_4",
            "5zdn5gQRuii0hVTzcJ4hWlURtMYeQk3OGREcRy9v1ps",
        ),
        (
            "RGUpcejDhxZcjveUXQ_f5ROhMoVgUsZA8lAQgGj_p_c",
            "qGIQUPRR3_DU1U4AtI9TTqsxy5sVZFYQe3S1whoMCVQ",
        ),
    ];

    fn holder_key(index: usize) -> HolderPublicKey {
        let (x, y) = HOLDER_COORDINATES[index];
        HolderPublicKey {
            kty: "EC".to_owned(),
            crv: "P-256".to_owned(),
            x: x.to_owned(),
            y: y.to_owned(),
            alg: None,
            kid: None,
        }
    }

    fn holder_key_request(holder_keys: Vec<HolderPublicKey>) -> EvidenceRequest {
        EvidenceRequest {
            request_nonce: "A".repeat(43),
            requirement: "urn:example:requirement:v1".to_owned(),
            purpose: "purpose".to_owned(),
            subjects: Vec::new(),
            holder_keys,
        }
    }

    fn audit_input_subject() -> ResolvedSubject {
        ResolvedSubject {
            role: "subject".to_owned(),
            selector_profile: "opaque-v1".to_owned(),
            value_origin: ValueOrigin::Request,
            fields: vec![ResolvedSelectorField {
                name: "field".to_owned(),
                value: ResolvedSelectorValue::String("value".to_owned()),
            }],
        }
    }

    #[test]
    fn a_resolved_holder_scope_debug_never_exposes_the_thumbprint() {
        let scope =
            ResolvedSubjectScope::HolderKeyThumbprint("holder-thumbprint-canary".to_owned());
        let debug = format!("{scope:?}");
        assert!(!debug.contains("holder-thumbprint-canary"));
        assert!(debug.contains("<redacted>"));
        assert_eq!(scope.audience(), None);
        assert_eq!(scope.component(), "holder-thumbprint-canary");
    }

    #[test]
    fn selector_claim_values_are_scalar_only() {
        assert!(selector_value_from_claim(&serde_json::json!({"value": "x"})).is_none());
        assert!(selector_value_from_claim(&serde_json::json!(["x"])).is_none());
        assert_eq!(
            selector_value_from_claim(&serde_json::json!(false)),
            Some(SelectorValue::Boolean(false))
        );
    }

    fn fixture_object(value: Value) -> serde_json::Map<String, Value> {
        value
            .as_object()
            .expect("fixture block is an object")
            .clone()
    }

    #[test]
    fn a_single_purpose_requirement_needs_no_declared_fixture_purpose() {
        let purposes = vec!["only-purpose".to_owned()];
        assert_eq!(
            fixture_purpose(&purposes, None, &fixture_object(serde_json::json!({}))),
            Ok("only-purpose")
        );
    }

    #[test]
    fn a_fixture_selects_one_of_several_declared_purposes() {
        let purposes = vec!["first".to_owned(), "second".to_owned()];
        assert_eq!(
            fixture_purpose(
                &purposes,
                None,
                &fixture_object(serde_json::json!({"purpose": "second"}))
            ),
            Ok("second")
        );
    }

    #[test]
    fn a_common_fixture_purpose_applies_to_every_case() {
        let purposes = vec!["first".to_owned(), "second".to_owned()];
        let common = fixture_object(serde_json::json!({"purpose": "second"}));
        assert_eq!(
            fixture_purpose(
                &purposes,
                Some(&common),
                &fixture_object(serde_json::json!({}))
            ),
            Ok("second")
        );
    }

    #[test]
    fn a_case_fixture_purpose_overrides_the_common_purpose() {
        let purposes = vec!["first".to_owned(), "second".to_owned()];
        let common = fixture_object(serde_json::json!({"purpose": "first"}));
        assert_eq!(
            fixture_purpose(
                &purposes,
                Some(&common),
                &fixture_object(serde_json::json!({"purpose": "second"}))
            ),
            Ok("second")
        );
    }

    #[test]
    fn a_multi_purpose_requirement_without_a_declared_purpose_is_a_fixture_error() {
        let purposes = vec!["first".to_owned(), "second".to_owned()];
        let error = fixture_purpose(&purposes, None, &fixture_object(serde_json::json!({})))
            .expect_err("an unselected purpose is rejected");
        assert_eq!(error, OfflineFixtureError::Purpose);
        assert_ne!(
            error,
            OfflineFixtureError::Authorization(AuthorizationError::Unauthorized),
            "an unselected fixture purpose must not be reported as an authorization denial"
        );
    }

    #[test]
    fn a_non_string_fixture_purpose_is_a_fixture_error() {
        let purposes = vec!["first".to_owned(), "second".to_owned()];
        assert_eq!(
            fixture_purpose(
                &purposes,
                None,
                &fixture_object(serde_json::json!({"purpose": 1}))
            ),
            Err(OfflineFixtureError::Purpose)
        );
    }

    #[test]
    fn a_fixture_purpose_outside_the_requirement_is_unauthorized() {
        let purposes = vec!["first".to_owned()];
        assert_eq!(
            fixture_purpose(
                &purposes,
                None,
                &fixture_object(serde_json::json!({"purpose": "other"}))
            ),
            Err(OfflineFixtureError::Authorization(
                AuthorizationError::Unauthorized
            ))
        );
    }
}
