// SPDX-License-Identifier: Apache-2.0
//! Production bearer admission and OIDC claim mapping for Registry HTTP routes.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use registry_platform_authcommon::{parse_bearer_token, validate_compact_access_token};
use registry_platform_oidc::{Audience, JwksFetcher, TokenVerifier, TokenVerifierConfig};
use serde_json::Value;
use thiserror::Error;

use crate::api::{VerifiedClaimValue, VerifiedRequestClaims};
#[cfg(feature = "tooling")]
pub(crate) use crate::authority::compiled_authority_field_type;
use crate::authority::{authority_inventory, AuthorityInventoryError, DirectClaimExpectation};
use crate::contract::FieldTypeSource;
use crate::model::CompiledRegistry;

const MAX_CLAIM_NAME_BYTES: usize = 128;
const MAX_SCOPE_VALUES: usize = 128;
const MAX_SCOPE_VALUE_BYTES: usize = 512;

const REGISTERED_CLAIMS: &[&str] = &[
    "iss",
    "aud",
    "exp",
    "iat",
    "nbf",
    "sub",
    "client_id",
    "azp",
    "jti",
    "cnf",
];

/// Direct claims that may become Registry authority after OIDC verification.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorityClaimConfig {
    principal_claim: String,
    purpose_claim: Option<String>,
}

impl AuthorityClaimConfig {
    #[must_use]
    pub fn new(principal_claim: impl Into<String>, purpose_claim: Option<String>) -> Self {
        Self {
            principal_claim: principal_claim.into(),
            purpose_claim,
        }
    }
}

impl fmt::Debug for AuthorityClaimConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityClaimConfig")
            .field("principal_claim", &self.principal_claim)
            .field("purpose_claim", &self.purpose_claim)
            .finish()
    }
}

/// A closed construction failure. Each variant names the check that refused
/// the deployment, and deliberately carries no configured URL, claim name, or
/// claim value that an operator could accidentally copy into a log.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AuthenticationConfigError {
    #[error("the OIDC access-token verification profile is invalid")]
    InvalidVerifierProfile,
    #[error("an authority claim mapping is invalid")]
    InvalidClaimMapping,
    #[error("a compiled anonymous access profile carries a principal claim, required scopes, required purposes, or row boundaries")]
    AnonymousProfileCarriesAuthority,
    #[error("the configured principal claim is not the principal claim a compiled access profile requires")]
    PrincipalClaimMismatch,
    #[error("a compiled row boundary selects a field the compiled entity does not declare")]
    BoundaryFieldNotCompiled,
    #[error("a compiled authority target entity does not exist")]
    TargetEntityNotCompiled,
    #[error("a compiled verified-claim lookup names a selector profile the compiled entity does not declare")]
    LookupSelectorNotCompiled,
    #[error("a compiled verified-claim lookup leaves a selector field without a claim mapping")]
    LookupClaimMappingIncomplete,
    #[error("a compiled verified-claim lookup maps a field the compiled entity does not declare")]
    LookupFieldNotCompiled,
    #[error("a purpose claim must be configured exactly when a compiled access profile requires a purpose")]
    PurposeClaimMismatch,
    #[error("two compiled authority mappings expect different value shapes for one claim")]
    ConflictingClaimExpectation,
}

/// A closed request failure. Platform verifier details and the bearer value
/// are intentionally erased at this boundary.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AuthenticationError {
    #[error("the bearer credential is malformed")]
    MalformedCredential,
    #[error("the bearer credential was refused")]
    VerificationRefused,
    #[error("the verified credential has invalid authority claims")]
    InvalidClaims,
}

/// Production OIDC verifier plus the only claim mapping allowed to construct
/// [`VerifiedRequestClaims`].
pub struct RegistryAuthenticator {
    verifier: TokenVerifier,
    audience: String,
    principal_claim: String,
    purpose_claim: Option<String>,
    direct_claims: BTreeMap<String, DirectClaimExpectation>,
}

impl RegistryAuthenticator {
    /// Bind one exact platform verifier profile and one exact authority mapping
    /// to the immutable compiled Registry served by this process.
    pub fn new(
        registry: &CompiledRegistry,
        verifier_config: TokenVerifierConfig,
        key_source: Arc<JwksFetcher>,
        claims: AuthorityClaimConfig,
    ) -> Result<Self, AuthenticationConfigError> {
        validate_verifier_profile(&verifier_config)?;
        let direct_claims = validate_claim_mapping(registry, &verifier_config, &claims)?;
        let audience = verifier_config.audiences[0].clone();
        Ok(Self {
            verifier: TokenVerifier::new(verifier_config, key_source),
            audience,
            principal_claim: claims.principal_claim,
            purpose_claim: claims.purpose_claim,
            direct_claims,
        })
    }

    /// Verify and map one already-admitted compact bearer token.
    pub async fn authenticate(
        &self,
        token: &str,
    ) -> Result<VerifiedRequestClaims, AuthenticationError> {
        validate_compact_access_token(token)
            .map_err(|_| AuthenticationError::MalformedCredential)?;
        let verified = self
            .verifier
            .verify(token)
            .await
            .map_err(|_| AuthenticationError::VerificationRefused)?;
        if !accepted_audience(verified.claims.aud.as_ref(), &self.audience) {
            return Err(AuthenticationError::InvalidClaims);
        }

        let claims = &verified.claims.extra;
        let subject = verified
            .claims
            .sub
            .as_ref()
            .map(|value| Value::String(value.clone()));
        let principal = required_direct_string(if self.principal_claim == "sub" {
            subject.as_ref()
        } else {
            claims.get(&self.principal_claim)
        })?;
        let purpose = self
            .purpose_claim
            .as_deref()
            .map(|name| optional_direct_string(claims.get(name)))
            .transpose()?
            .flatten();
        if verified.scopes.len() > MAX_SCOPE_VALUES {
            return Err(AuthenticationError::InvalidClaims);
        }
        let scopes = verified
            .scopes
            .into_iter()
            .map(validate_scope)
            .collect::<Result<BTreeSet<_>, _>>()?;
        let direct_claims = self
            .direct_claims
            .iter()
            .filter_map(|(name, expectation)| {
                let value = if name == "sub" {
                    subject.as_ref()
                } else {
                    claims.get(name)
                };
                value.map(|value| {
                    mapped_claim(value, expectation).map(|value| (name.clone(), value))
                })
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        VerifiedRequestClaims::authenticated(
            self.principal_claim.clone(),
            principal,
            scopes,
            purpose,
            direct_claims,
        )
        .map_err(|_| AuthenticationError::InvalidClaims)
    }
}

impl fmt::Debug for RegistryAuthenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryAuthenticator")
            .field("issuer", &"<redacted>")
            .field("audience", &"<redacted>")
            .field("principal_claim", &self.principal_claim)
            .field("purpose_claim", &self.purpose_claim)
            .field("direct_claims", &self.direct_claims.keys())
            .finish()
    }
}

/// Authenticate a presented bearer before any Registry route authorization.
/// Absence is preserved for anonymous profiles, while every invalid presented
/// credential fails closed. Any caller-supplied authority extension is removed
/// before either branch.
pub(crate) async fn authenticate_request(
    State(authenticator): State<Arc<RegistryAuthenticator>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    request.extensions_mut().remove::<VerifiedRequestClaims>();
    let token = match bearer_token(request.headers()) {
        Ok(None) => return next.run(request).await,
        Ok(Some(token)) => token,
        Err(_) => return authentication_refused(),
    };
    let claims = match authenticator.authenticate(token).await {
        Ok(claims) => claims,
        Err(_) => return authentication_refused(),
    };
    request.extensions_mut().insert(claims);
    next.run(request).await
}

fn bearer_token(headers: &axum::http::HeaderMap) -> Result<Option<&str>, AuthenticationError> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(AuthenticationError::MalformedCredential);
    }
    let value = value
        .to_str()
        .map_err(|_| AuthenticationError::MalformedCredential)?;
    parse_bearer_token(value)
        .map(Some)
        .map_err(|_| AuthenticationError::MalformedCredential)
}

fn validate_verifier_profile(
    config: &TokenVerifierConfig,
) -> Result<(), AuthenticationConfigError> {
    if !valid_config_value(&config.issuer)
        || config.audiences.len() != 1
        || !valid_config_value(&config.audiences[0])
        || config.allowed_algorithms.len() != 1
        || config.allowed_typ.len() != 1
        || !valid_config_value(&config.allowed_typ[0])
        || !valid_claim_name(&config.scope_claim)
        || REGISTERED_CLAIMS.contains(&config.scope_claim.as_str())
        || config.scope_separator.is_control()
        || config.scope_separator.is_alphanumeric()
    {
        return Err(AuthenticationConfigError::InvalidVerifierProfile);
    }
    if let Some(scope_map) = &config.scope_map {
        for (source, mapped) in scope_map {
            if !valid_scope_value(source)
                || mapped.is_empty()
                || mapped.len() > MAX_SCOPE_VALUES
                || mapped.iter().any(|scope| !valid_scope_value(scope))
                || mapped.iter().collect::<BTreeSet<_>>().len() != mapped.len()
            {
                return Err(AuthenticationConfigError::InvalidVerifierProfile);
            }
        }
    }
    Ok(())
}

fn validate_claim_mapping(
    registry: &CompiledRegistry,
    verifier: &TokenVerifierConfig,
    claims: &AuthorityClaimConfig,
) -> Result<BTreeMap<String, DirectClaimExpectation>, AuthenticationConfigError> {
    if !(valid_authority_claim_name(&claims.principal_claim) || claims.principal_claim == "sub")
        || claims.principal_claim == verifier.scope_claim
    {
        return Err(AuthenticationConfigError::InvalidClaimMapping);
    }
    if let Some(purpose) = &claims.purpose_claim {
        if !valid_authority_claim_name(purpose)
            || purpose == &claims.principal_claim
            || purpose == &verifier.scope_claim
        {
            return Err(AuthenticationConfigError::InvalidClaimMapping);
        }
    }
    let inventory = authority_inventory(registry).map_err(|error| match error {
        AuthorityInventoryError::AnonymousProfileCarriesAuthority => {
            AuthenticationConfigError::AnonymousProfileCarriesAuthority
        }
        AuthorityInventoryError::PrincipalClaimMissing => {
            AuthenticationConfigError::PrincipalClaimMismatch
        }
        AuthorityInventoryError::TargetEntityNotCompiled => {
            AuthenticationConfigError::TargetEntityNotCompiled
        }
        AuthorityInventoryError::BoundaryFieldNotCompiled => {
            AuthenticationConfigError::BoundaryFieldNotCompiled
        }
        AuthorityInventoryError::LookupSelectorNotCompiled => {
            AuthenticationConfigError::LookupSelectorNotCompiled
        }
        AuthorityInventoryError::LookupClaimMappingIncomplete => {
            AuthenticationConfigError::LookupClaimMappingIncomplete
        }
        AuthorityInventoryError::LookupFieldNotCompiled => {
            AuthenticationConfigError::LookupFieldNotCompiled
        }
        AuthorityInventoryError::ConflictingClaimExpectation => {
            AuthenticationConfigError::ConflictingClaimExpectation
        }
    })?;
    if inventory
        .principal_claims
        .iter()
        .any(|name| name != &claims.principal_claim)
    {
        return Err(AuthenticationConfigError::PrincipalClaimMismatch);
    }
    for (name, expectation) in &inventory.direct_claims {
        if name == &claims.principal_claim {
            // Ownership reuses the explicitly selected principal, never a fallback.
            // The field still applies its ordinary scalar type validation.
            if expectation.multi_value
                || matches!(
                    expectation.field_type,
                    FieldTypeSource::Boolean
                        | FieldTypeSource::Int64
                        | FieldTypeSource::Crs84Point { .. }
                        | FieldTypeSource::Structured { .. }
                )
            {
                return Err(AuthenticationConfigError::ConflictingClaimExpectation);
            }
        } else if !valid_authority_claim_name(name)
            || name == &verifier.scope_claim
            || claims.purpose_claim.as_ref() == Some(name)
        {
            return Err(AuthenticationConfigError::InvalidClaimMapping);
        }
    }
    if inventory.purpose_required != claims.purpose_claim.is_some() {
        return Err(AuthenticationConfigError::PurposeClaimMismatch);
    }
    Ok(inventory.direct_claims)
}

fn accepted_audience(audience: Option<&Audience>, expected: &str) -> bool {
    const MAX_AUDIENCES: usize = 16;
    match audience {
        Some(Audience::One(value)) => valid_config_value(value) && value == expected,
        Some(Audience::Many(values)) => {
            !values.is_empty()
                && values.len() <= MAX_AUDIENCES
                && values.iter().all(|value| valid_config_value(value))
                && values.iter().collect::<BTreeSet<_>>().len() == values.len()
                && values.iter().any(|value| value == expected)
        }
        None => false,
    }
}

fn valid_claim_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CLAIM_NAME_BYTES
        && value.is_ascii()
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
}

fn valid_authority_claim_name(value: &str) -> bool {
    valid_claim_name(value) && !REGISTERED_CLAIMS.contains(&value)
}

fn valid_config_value(value: &str) -> bool {
    !value.trim().is_empty()
        && value.trim() == value
        && value.len() <= 2048
        && !value.chars().any(char::is_control)
}

fn valid_scope_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SCOPE_VALUE_BYTES
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
}

fn validate_scope(value: String) -> Result<String, AuthenticationError> {
    valid_scope_value(&value)
        .then_some(value)
        .ok_or(AuthenticationError::InvalidClaims)
}

fn required_direct_string(value: Option<&Value>) -> Result<String, AuthenticationError> {
    optional_direct_string(value)?.ok_or(AuthenticationError::InvalidClaims)
}

fn optional_direct_string(value: Option<&Value>) -> Result<Option<String>, AuthenticationError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.as_str().ok_or(AuthenticationError::InvalidClaims)?;
    let value = VerifiedClaimValue::direct_string(value.to_owned())
        .map_err(|_| AuthenticationError::InvalidClaims)?;
    match value {
        VerifiedClaimValue::DirectString(value) => Ok(Some(value)),
        VerifiedClaimValue::DirectStringSet(_) => unreachable!("direct constructor returns string"),
    }
}

fn mapped_claim(
    value: &Value,
    expectation: &DirectClaimExpectation,
) -> Result<VerifiedClaimValue, AuthenticationError> {
    map_authority_claim(value, &expectation.field_type, expectation.multi_value)
}

/// Map a typed authority value identically for verified tokens and synthetic previews.
pub(crate) fn map_authority_claim(
    value: &Value,
    field_type: &FieldTypeSource,
    multi_value: bool,
) -> Result<VerifiedClaimValue, AuthenticationError> {
    if multi_value {
        let values = value.as_array().ok_or(AuthenticationError::InvalidClaims)?;
        // A value repeated in a multi-valued claim asserts the same authority
        // once, so identical mapped values collapse. Every entry is still
        // mapped and validated, and the bound on distinct values still applies.
        let values = values
            .iter()
            .map(|value| mapped_scalar_claim(value, field_type))
            .collect::<Result<BTreeSet<_>, _>>()?;
        VerifiedClaimValue::direct_string_set(values)
            .map_err(|_| AuthenticationError::InvalidClaims)
    } else {
        VerifiedClaimValue::direct_string(mapped_scalar_claim(value, field_type)?)
            .map_err(|_| AuthenticationError::InvalidClaims)
    }
}

fn mapped_scalar_claim(
    value: &Value,
    field_type: &FieldTypeSource,
) -> Result<String, AuthenticationError> {
    let value = match field_type {
        FieldTypeSource::Boolean => value
            .as_bool()
            .map(|value| value.to_string())
            .ok_or(AuthenticationError::InvalidClaims)?,
        FieldTypeSource::Int64 => value
            .as_i64()
            .map(|value| value.to_string())
            .ok_or(AuthenticationError::InvalidClaims)?,
        FieldTypeSource::String { .. }
        | FieldTypeSource::Text { .. }
        | FieldTypeSource::Decimal { .. }
        | FieldTypeSource::Date
        | FieldTypeSource::Timestamp
        | FieldTypeSource::Uuid
        | FieldTypeSource::Reference { .. }
        | FieldTypeSource::VocabularyCode { .. } => value
            .as_str()
            .map(str::to_owned)
            .ok_or(AuthenticationError::InvalidClaims)?,
        FieldTypeSource::Crs84Point { .. } | FieldTypeSource::Structured { .. } => {
            return Err(AuthenticationError::InvalidClaims);
        }
    };
    crate::postgres::validate_field_value(&value, field_type)
        .map_err(|_| AuthenticationError::InvalidClaims)?;
    Ok(value)
}

fn authentication_refused() -> Response {
    crate::correlation::problem_response(
        StatusCode::UNAUTHORIZED,
        "Unauthorized",
        "The bearer credential is missing or refused.",
        "authentication.refused",
    )
}
