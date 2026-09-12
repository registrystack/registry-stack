// SPDX-License-Identifier: Apache-2.0

//! Strict extraction of the shared contextual-authorization claims.

use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{Claims, VerifiedToken};

const MAX_CLAIM_NAME_BYTES: usize = 128;
const MAX_CLAIM_VALUE_BYTES: usize = 512;
const MAX_PURPOSE_BYTES: usize = 128;
const MAX_BREG_PERMISSIONS: usize = 64;
const MAX_BREG_OPERATIONS: usize = 32;

const REGISTERED_OR_AUTHENTICATION_CLAIMS: &[&str] = &[
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "azp",
    "client_id",
    "scope",
    "cnf",
    "act",
];

/// Names of the direct, top-level claims in the contextual-authorization profile.
///
/// A dot is a valid character in a claim name and remains literal. This keeps
/// the direct-claim behavior of existing Registry Stack resource servers.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct ClaimNames {
    pub actor_kind: String,
    pub purpose: String,
    pub grant_id: String,
    pub grant_authority: String,
    pub grant_source_issuer: String,
    pub grant_client: String,
    pub grant_resource: String,
    pub grant_exp: String,
    pub grant_bounds: String,
    pub approver: String,
}

impl Default for ClaimNames {
    fn default() -> Self {
        Self {
            actor_kind: "registry_actor_kind".to_owned(),
            purpose: "registry_purpose".to_owned(),
            grant_id: "registry_grant_id".to_owned(),
            grant_authority: "registry_grant_authority".to_owned(),
            grant_source_issuer: "registry_grant_source_issuer".to_owned(),
            grant_client: "registry_grant_client".to_owned(),
            grant_resource: "registry_grant_resource".to_owned(),
            grant_exp: "registry_grant_exp".to_owned(),
            grant_bounds: "registry_grant_bounds".to_owned(),
            approver: "registry_approver".to_owned(),
        }
    }
}

impl ClaimNames {
    /// Validate claim-name syntax and prevent one claim from serving two roles.
    pub fn validate(&self) -> Result<(), ClaimError> {
        let names = [
            &self.actor_kind,
            &self.purpose,
            &self.grant_id,
            &self.grant_authority,
            &self.grant_source_issuer,
            &self.grant_client,
            &self.grant_resource,
            &self.grant_exp,
            &self.grant_bounds,
            &self.approver,
        ];
        if names.iter().any(|name| !valid_claim_name(name))
            || names
                .iter()
                .any(|name| REGISTERED_OR_AUTHENTICATION_CLAIMS.contains(&name.as_str()))
            || names.iter().collect::<HashSet<_>>().len() != names.len()
        {
            return Err(ClaimError::InvalidNames);
        }
        Ok(())
    }

    fn core_grant_names(&self) -> [&str; 7] {
        [
            &self.grant_id,
            &self.grant_authority,
            &self.grant_source_issuer,
            &self.grant_client,
            &self.grant_resource,
            &self.grant_exp,
            &self.grant_bounds,
        ]
    }
}

/// The kind of actor executing the authenticated operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    Human,
    Agent,
    Service,
}

impl ActorKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Agent => "agent",
            Self::Service => "service",
        }
    }
}

/// A bounded BREG permission carried inside a signed grant.
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BregPermission {
    collection: String,
    operations: Vec<String>,
}

impl BregPermission {
    #[must_use]
    pub fn collection(&self) -> &str {
        &self.collection
    }

    #[must_use]
    pub fn operations(&self) -> &[String] {
        &self.operations
    }
}

impl fmt::Debug for BregPermission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BregPermission")
            .field("collection", &"<redacted>")
            .field("operation_count", &self.operations.len())
            .finish()
    }
}

/// Product-specific bounds carried by a task grant.
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum GrantBounds {
    Evidence { requirement: String },
    Breg { permissions: Vec<BregPermission> },
}

impl GrantBounds {
    #[must_use]
    pub fn evidence_requirement(&self) -> Option<&str> {
        match self {
            Self::Evidence { requirement } => Some(requirement),
            Self::Breg { .. } => None,
        }
    }

    #[must_use]
    pub fn breg_permissions(&self) -> Option<&[BregPermission]> {
        match self {
            Self::Evidence { .. } => None,
            Self::Breg { permissions } => Some(permissions),
        }
    }

    fn validate(&self) -> Result<(), ClaimError> {
        match self {
            Self::Evidence { requirement } => {
                validate_bound_value(requirement, MAX_CLAIM_VALUE_BYTES)
                    .then_some(())
                    .ok_or(ClaimError::Malformed(ClaimMember::GrantBounds))
            }
            Self::Breg { permissions } => {
                if permissions.is_empty() || permissions.len() > MAX_BREG_PERMISSIONS {
                    return Err(ClaimError::Malformed(ClaimMember::GrantBounds));
                }
                let mut collections = HashSet::with_capacity(permissions.len());
                for permission in permissions {
                    if !validate_bound_value(&permission.collection, MAX_CLAIM_VALUE_BYTES)
                        || !collections.insert(permission.collection.as_str())
                        || permission.operations.is_empty()
                        || permission.operations.len() > MAX_BREG_OPERATIONS
                    {
                        return Err(ClaimError::Malformed(ClaimMember::GrantBounds));
                    }
                    let mut operations = HashSet::with_capacity(permission.operations.len());
                    if permission.operations.iter().any(|operation| {
                        !valid_operation(operation) || !operations.insert(operation.as_str())
                    }) {
                        return Err(ClaimError::Malformed(ClaimMember::GrantBounds));
                    }
                }
                Ok(())
            }
        }
    }
}

impl fmt::Debug for GrantBounds {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Evidence { .. } => formatter
                .debug_struct("Evidence")
                .field("requirement", &"<redacted>")
                .finish(),
            Self::Breg { permissions } => formatter
                .debug_struct("Breg")
                .field("permission_count", &permissions.len())
                .finish(),
        }
    }
}

/// Verified, normalized task-grant claims.
#[derive(Clone, Eq, PartialEq)]
pub struct GrantClaims {
    principal: String,
    id: String,
    authority: String,
    source_issuer: String,
    client: String,
    resource: String,
    purpose: String,
    exp: u64,
    bounds: GrantBounds,
    approver: Option<String>,
}

impl GrantClaims {
    #[must_use]
    pub fn principal(&self) -> &str {
        &self.principal
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    #[must_use]
    pub fn source_issuer(&self) -> &str {
        &self.source_issuer
    }

    #[must_use]
    pub fn client(&self) -> &str {
        &self.client
    }

    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }

    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    #[must_use]
    pub const fn exp(&self) -> u64 {
        self.exp
    }

    #[must_use]
    pub fn bounds(&self) -> &GrantBounds {
        &self.bounds
    }

    #[must_use]
    pub fn approver(&self) -> Option<&str> {
        self.approver.as_deref()
    }

    /// Bind immutable grant context to identities already selected by the verifier.
    pub fn verify_context(
        &self,
        token: &VerifiedToken,
        verified_resource: &str,
    ) -> Result<(), GrantContextError> {
        let client = token
            .matched_client_id()
            .map_err(|_| GrantContextError::InvalidVerifiedClient)?
            .ok_or(GrantContextError::MissingVerifiedClient)?;
        if client != self.client {
            return Err(GrantContextError::ClientMismatch);
        }
        if verified_resource != self.resource {
            return Err(GrantContextError::ResourceMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for GrantClaims {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrantClaims")
            .field("principal", &"<redacted>")
            .field("id", &"<redacted>")
            .field("authority", &"<redacted>")
            .field("source_issuer", &"<redacted>")
            .field("client", &"<redacted>")
            .field("resource", &"<redacted>")
            .field("purpose", &"<redacted>")
            .field("exp", &self.exp)
            .field("bounds", &self.bounds)
            .field("approver", &self.approver.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// A fixed member label safe to include in errors and metrics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimMember {
    ActorKind,
    Principal,
    Purpose,
    TokenExpiration,
    GrantId,
    GrantAuthority,
    GrantSourceIssuer,
    GrantClient,
    GrantResource,
    GrantExpiration,
    GrantBounds,
    Approver,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ClaimError {
    #[error("contextual authorization claim names are invalid")]
    InvalidNames,
    #[error("required contextual authorization claim is missing")]
    Missing(ClaimMember),
    #[error("task grant claims are incomplete")]
    Partial,
    #[error("contextual authorization claim is malformed")]
    Malformed(ClaimMember),
    #[error("task grant has expired")]
    Expired,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum MatchedClientError {
    #[error("verified client context is malformed")]
    Malformed,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum GrantContextError {
    #[error("verified client context is missing")]
    MissingVerifiedClient,
    #[error("verified client context is malformed")]
    InvalidVerifiedClient,
    #[error("task grant client does not match the verified client")]
    ClientMismatch,
    #[error("task grant resource does not match the verified resource")]
    ResourceMismatch,
}

/// Extract the strict actor kind from a verified token.
pub fn actor_kind(claims: &Claims, names: &ClaimNames) -> Result<ActorKind, ClaimError> {
    names.validate()?;
    match claims.extra.get(&names.actor_kind) {
        None => Err(ClaimError::Missing(ClaimMember::ActorKind)),
        Some(Value::String(value)) if value == "human" => Ok(ActorKind::Human),
        Some(Value::String(value)) if value == "agent" => Ok(ActorKind::Agent),
        Some(Value::String(value)) if value == "service" => Ok(ActorKind::Service),
        Some(_) => Err(ClaimError::Malformed(ClaimMember::ActorKind)),
    }
}

/// Extract a complete task grant from verified claims.
///
/// Only the seven `registry_grant_*` members detect grant presence. A purpose
/// or actor-kind claim by itself belongs to an ordinary standing service token
/// and returns `Ok(None)`.
pub fn grant_claims(
    claims: &Claims,
    names: &ClaimNames,
    now_unix: u64,
) -> Result<Option<GrantClaims>, ClaimError> {
    names.validate()?;
    let core = names.core_grant_names();
    let present = core
        .iter()
        .filter(|name| claims.extra.contains_key(**name))
        .count();
    if present == 0 {
        return Ok(None);
    }
    if present != core.len() {
        return Err(ClaimError::Partial);
    }

    let principal = required_standard_string(
        claims.sub.as_deref(),
        ClaimMember::Principal,
        MAX_CLAIM_VALUE_BYTES,
    )?;
    let id = required_extra_string(claims, &names.grant_id, ClaimMember::GrantId)?;
    let authority =
        required_extra_string(claims, &names.grant_authority, ClaimMember::GrantAuthority)?;
    let source_issuer = required_extra_string(
        claims,
        &names.grant_source_issuer,
        ClaimMember::GrantSourceIssuer,
    )?;
    let client = required_extra_string(claims, &names.grant_client, ClaimMember::GrantClient)?;
    let resource =
        required_extra_string(claims, &names.grant_resource, ClaimMember::GrantResource)?;
    let purpose = required_extra_string_with_bound(
        claims,
        &names.purpose,
        ClaimMember::Purpose,
        MAX_PURPOSE_BYTES,
    )?;
    if !valid_purpose(&purpose) {
        return Err(ClaimError::Malformed(ClaimMember::Purpose));
    }
    let token_exp = claims
        .exp
        .ok_or(ClaimError::Missing(ClaimMember::TokenExpiration))
        .and_then(|value| {
            u64::try_from(value)
                .ok()
                .filter(|value| *value > 0)
                .ok_or(ClaimError::Malformed(ClaimMember::TokenExpiration))
        })?;
    let grant_exp = required_unix_timestamp(claims, &names.grant_exp)?;
    if now_unix >= token_exp.min(grant_exp) {
        return Err(ClaimError::Expired);
    }
    let bounds_value = claims
        .extra
        .get(&names.grant_bounds)
        .ok_or(ClaimError::Missing(ClaimMember::GrantBounds))?;
    let bounds: GrantBounds = serde_json::from_value(bounds_value.clone())
        .map_err(|_| ClaimError::Malformed(ClaimMember::GrantBounds))?;
    bounds.validate()?;
    let approver = optional_extra_string(claims, &names.approver, ClaimMember::Approver)?;

    Ok(Some(GrantClaims {
        principal,
        id,
        authority,
        source_issuer,
        client,
        resource,
        purpose,
        exp: grant_exp,
        bounds,
        approver,
    }))
}

fn required_extra_string(
    claims: &Claims,
    name: &str,
    member: ClaimMember,
) -> Result<String, ClaimError> {
    required_extra_string_with_bound(claims, name, member, MAX_CLAIM_VALUE_BYTES)
}

fn required_extra_string_with_bound(
    claims: &Claims,
    name: &str,
    member: ClaimMember,
    maximum_bytes: usize,
) -> Result<String, ClaimError> {
    match claims.extra.get(name) {
        None => Err(ClaimError::Missing(member)),
        Some(Value::String(value)) if valid_text(value, maximum_bytes) => Ok(value.clone()),
        Some(_) => Err(ClaimError::Malformed(member)),
    }
}

fn optional_extra_string(
    claims: &Claims,
    name: &str,
    member: ClaimMember,
) -> Result<Option<String>, ClaimError> {
    match claims.extra.get(name) {
        None => Ok(None),
        Some(Value::String(value)) if valid_text(value, MAX_CLAIM_VALUE_BYTES) => {
            Ok(Some(value.clone()))
        }
        Some(_) => Err(ClaimError::Malformed(member)),
    }
}

fn required_standard_string(
    value: Option<&str>,
    member: ClaimMember,
    maximum_bytes: usize,
) -> Result<String, ClaimError> {
    match value {
        None => Err(ClaimError::Missing(member)),
        Some(value) if valid_text(value, maximum_bytes) => Ok(value.to_owned()),
        Some(_) => Err(ClaimError::Malformed(member)),
    }
}

fn required_unix_timestamp(claims: &Claims, name: &str) -> Result<u64, ClaimError> {
    let value = claims
        .extra
        .get(name)
        .ok_or(ClaimError::Missing(ClaimMember::GrantExpiration))?;
    value
        .as_u64()
        .filter(|value| *value > 0 && *value <= i64::MAX as u64)
        .ok_or(ClaimError::Malformed(ClaimMember::GrantExpiration))
}

fn valid_claim_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_CLAIM_NAME_BYTES
        && matches!(bytes.first(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn valid_text(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= maximum_bytes && !value.chars().any(char::is_control)
}

fn validate_bound_value(value: &str, maximum_bytes: usize) -> bool {
    valid_text(value, maximum_bytes)
        && !value.contains('*')
        && !value.chars().any(char::is_whitespace)
}

fn valid_operation(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= MAX_PURPOSE_BYTES
        && !value.contains('*')
        && bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b':' | b'-')
        })
}

fn valid_purpose(value: &str) -> bool {
    valid_operation(value)
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Map};

    use super::*;
    use crate::Audience;

    fn claims(extra: Value) -> Claims {
        Claims {
            sub: Some("principal-canary".to_owned()),
            iss: Some("https://issuer.example".to_owned()),
            aud: Some(Audience::One("urn:registry:breg".to_owned())),
            exp: Some(2_000),
            iat: Some(1_000),
            nbf: None,
            azp: Some("agent-client".to_owned()),
            client_id: None,
            extra: extra.as_object().cloned().unwrap_or_else(Map::new),
        }
    }

    fn complete_grant(bounds: Value) -> Value {
        json!({
            "registry_actor_kind": "agent",
            "registry_grant_id": "grant-canary",
            "registry_grant_authority": "casework-v1",
            "registry_grant_source_issuer": "https://casework.example",
            "registry_grant_client": "agent-client",
            "registry_grant_resource": "urn:registry:breg",
            "registry_grant_exp": 1_900,
            "registry_grant_bounds": bounds,
            "registry_purpose": "record-review",
            "registry_approver": "h:approver-canary"
        })
    }

    #[test]
    fn standing_service_token_with_purpose_has_no_grant() {
        let input = claims(json!({
            "registry_actor_kind": "service",
            "registry_purpose": "registry-operations"
        }));
        assert_eq!(
            actor_kind(&input, &ClaimNames::default()),
            Ok(ActorKind::Service)
        );
        assert_eq!(
            grant_claims(&input, &ClaimNames::default(), 1_500),
            Ok(None)
        );
    }

    #[test]
    fn any_partial_core_grant_set_is_rejected() {
        for name in ClaimNames::default().core_grant_names() {
            let mut extra = Map::new();
            extra.insert(name.to_owned(), json!("present"));
            let input = claims(Value::Object(extra));
            assert_eq!(
                grant_claims(&input, &ClaimNames::default(), 1_500),
                Err(ClaimError::Partial)
            );
        }
    }

    #[test]
    fn custom_direct_names_map_without_nested_path_interpretation() {
        let names = ClaimNames {
            actor_kind: "custom.actor".to_owned(),
            purpose: "custom.purpose".to_owned(),
            grant_id: "custom.grant_id".to_owned(),
            grant_authority: "custom.grant_authority".to_owned(),
            grant_source_issuer: "custom.grant_source_issuer".to_owned(),
            grant_client: "custom.grant_client".to_owned(),
            grant_resource: "custom.grant_resource".to_owned(),
            grant_exp: "custom.grant_exp".to_owned(),
            grant_bounds: "custom.grant_bounds".to_owned(),
            approver: "custom.approver".to_owned(),
        };
        let input = claims(json!({
            "custom.actor": "agent",
            "custom.purpose": "record-review",
            "custom.grant_id": "grant-canary",
            "custom.grant_authority": "casework-v1",
            "custom.grant_source_issuer": "https://casework.example",
            "custom.grant_client": "agent-client",
            "custom.grant_resource": "urn:registry:breg",
            "custom.grant_exp": 1900,
            "custom.grant_bounds": {"type":"evidence","requirement":"urn:requirement:one"},
            "custom.approver": "h:approver-canary"
        }));
        let grant = grant_claims(&input, &names, 1_500)
            .expect("custom names are valid")
            .expect("grant is present");
        assert_eq!(grant.id(), "grant-canary");
        assert_eq!(actor_kind(&input, &names), Ok(ActorKind::Agent));
    }

    #[test]
    fn overlapping_or_registered_claim_names_are_rejected() {
        let overlapping = ClaimNames {
            grant_id: "registry_purpose".to_owned(),
            ..ClaimNames::default()
        };
        assert_eq!(overlapping.validate(), Err(ClaimError::InvalidNames));

        let shadowing = ClaimNames {
            grant_id: "sub".to_owned(),
            ..ClaimNames::default()
        };
        assert_eq!(shadowing.validate(), Err(ClaimError::InvalidNames));
    }

    #[test]
    fn claim_name_deserialization_rejects_unknown_fields() {
        let value = serde_json::to_value(ClaimNames::default()).expect("serializes");
        let mut object = value.as_object().cloned().expect("object");
        object.insert("legacyGrant".to_owned(), json!("legacy_grant"));
        assert!(serde_json::from_value::<ClaimNames>(Value::Object(object)).is_err());
    }

    #[test]
    fn partial_claim_name_configuration_keeps_fixed_defaults() {
        let names: ClaimNames = serde_json::from_value(json!({"grantId":"foreign_grant"}))
            .expect("known partial override is accepted");
        assert_eq!(names.grant_id, "foreign_grant");
        assert_eq!(names.purpose, "registry_purpose");
        assert_eq!(names.grant_bounds, "registry_grant_bounds");
    }

    #[test]
    fn actor_kind_is_strict() {
        let input = claims(json!({"registry_actor_kind":"Agent"}));
        assert_eq!(
            actor_kind(&input, &ClaimNames::default()),
            Err(ClaimError::Malformed(ClaimMember::ActorKind))
        );
    }

    #[test]
    fn expiry_uses_earlier_token_or_grant_deadline_and_refuses_exact_deadline() {
        let input = claims(complete_grant(
            json!({"type":"evidence","requirement":"urn:requirement:one"}),
        ));
        assert!(grant_claims(&input, &ClaimNames::default(), 1_899).is_ok());
        assert_eq!(
            grant_claims(&input, &ClaimNames::default(), 1_900),
            Err(ClaimError::Expired)
        );

        let mut earlier_token = input;
        earlier_token.exp = Some(1_800);
        assert_eq!(
            grant_claims(&earlier_token, &ClaimNames::default(), 1_800),
            Err(ClaimError::Expired)
        );
    }

    #[test]
    fn missing_or_non_integer_or_overflowing_expiration_is_rejected() {
        let bounds = json!({"type":"evidence","requirement":"urn:requirement:one"});
        let mut missing_token_exp = claims(complete_grant(bounds.clone()));
        missing_token_exp.exp = None;
        assert_eq!(
            grant_claims(&missing_token_exp, &ClaimNames::default(), 1_500),
            Err(ClaimError::Missing(ClaimMember::TokenExpiration))
        );

        let mut missing_grant_exp = complete_grant(bounds.clone());
        missing_grant_exp
            .as_object_mut()
            .expect("grant object")
            .remove("registry_grant_exp");
        assert_eq!(
            grant_claims(&claims(missing_grant_exp), &ClaimNames::default(), 1_500),
            Err(ClaimError::Partial)
        );

        for invalid in [json!(0), json!(-1), json!(1900.5), json!(u64::MAX)] {
            let mut extra = complete_grant(bounds.clone());
            extra["registry_grant_exp"] = invalid;
            assert_eq!(
                grant_claims(&claims(extra), &ClaimNames::default(), 1_500),
                Err(ClaimError::Malformed(ClaimMember::GrantExpiration))
            );
        }
    }

    #[test]
    fn evidence_and_breg_bounds_are_distinct_and_strict() {
        let evidence = claims(complete_grant(
            json!({"type":"evidence","requirement":"urn:requirement:one"}),
        ));
        assert!(matches!(
            grant_claims(&evidence, &ClaimNames::default(), 1_500)
                .expect("valid")
                .expect("present")
                .bounds(),
            GrantBounds::Evidence { .. }
        ));

        let breg = claims(complete_grant(json!({
            "type":"breg",
            "permissions":[{"collection":"person.reviewer","operations":["get","patch"]}]
        })));
        assert!(matches!(
            grant_claims(&breg, &ClaimNames::default(), 1_500)
                .expect("valid")
                .expect("present")
                .bounds(),
            GrantBounds::Breg { .. }
        ));

        for invalid in [
            json!({"type":"evidence","requirement":"*"}),
            json!({"type":"evidence","requirement":"urn:one","extra":true}),
            json!({"type":"breg","permissions":[]}),
            json!({"type":"breg","permissions":[{"collection":"person.*","operations":["get"]}]}),
            json!({"type":"breg","permissions":[{"collection":"person.reviewer","operations":[]}]}),
            json!({"type":"breg","permissions":[{"collection":"person.reviewer","operations":["*"]}]}),
        ] {
            assert_eq!(
                grant_claims(
                    &claims(complete_grant(invalid)),
                    &ClaimNames::default(),
                    1_500
                ),
                Err(ClaimError::Malformed(ClaimMember::GrantBounds))
            );
        }
    }

    #[test]
    fn context_binding_uses_normalized_verified_client_and_exact_resource() {
        let input = claims(complete_grant(json!({
            "type":"breg",
            "permissions":[{"collection":"person.reviewer","operations":["get"]}]
        })));
        let grant = grant_claims(&input, &ClaimNames::default(), 1_500)
            .expect("valid")
            .expect("present");
        let token = VerifiedToken {
            claims: input,
            matched_client: Some("azp:agent-client".to_owned()),
            scopes: Vec::new(),
        };
        assert_eq!(grant.verify_context(&token, "urn:registry:breg"), Ok(()));
        assert_eq!(
            grant.verify_context(&token, "urn:registry:other"),
            Err(GrantContextError::ResourceMismatch)
        );

        let client_id_token = VerifiedToken {
            claims: token.claims.clone(),
            matched_client: Some("client_id:agent-client".to_owned()),
            scopes: Vec::new(),
        };
        assert_eq!(
            grant.verify_context(&client_id_token, "urn:registry:breg"),
            Ok(())
        );

        let malformed = VerifiedToken {
            claims: token.claims.clone(),
            matched_client: Some("agent-client".to_owned()),
            scopes: Vec::new(),
        };
        assert_eq!(
            grant.verify_context(&malformed, "urn:registry:breg"),
            Err(GrantContextError::InvalidVerifiedClient)
        );
    }

    #[test]
    fn grant_debug_redacts_claim_values() {
        let input = claims(complete_grant(
            json!({"type":"evidence","requirement":"sensitive-requirement-canary"}),
        ));
        let grant = grant_claims(&input, &ClaimNames::default(), 1_500)
            .expect("valid")
            .expect("present");
        let rendered = format!("{grant:?}");
        for canary in [
            "principal-canary",
            "grant-canary",
            "agent-client",
            "sensitive-requirement-canary",
            "approver-canary",
        ] {
            assert!(!rendered.contains(canary));
        }
    }
}
