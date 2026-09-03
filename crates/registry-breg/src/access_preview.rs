// SPDX-License-Identifier: Apache-2.0
//! Offline synthetic admission preview. No token verification, data access, or authority issuance.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::{authorize_profile_claims, VerifiedClaimValue, VerifiedRequestClaims};
use crate::auth::{compiled_authority_field_type, map_authority_claim};
use crate::contract::{AccessProfileSource, BoundaryOperator, Operation};
use crate::model::{CompiledEntity, CompiledRegistry};

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AccessScenario {
    pub entity: String,
    pub access_profile: String,
    pub operation: Operation,
    /// Optional root relationship path; operation must be list.
    #[serde(default)]
    pub read_path: Option<String>,
    #[serde(default)]
    pub claims: ScenarioClaims,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScenarioClaims {
    #[serde(default)]
    principal_claim: Option<String>,
    #[serde(default)]
    principal: Option<String>,
    #[serde(default)]
    scopes: BTreeSet<String>,
    #[serde(default)]
    purpose: Option<String>,
    #[serde(default)]
    direct_claims: BTreeMap<String, Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessPreview {
    pub mode: &'static str,
    pub admitted: bool,
    pub reason: &'static str,
    pub record_access: &'static str,
    pub credentials_verified: bool,
    pub authority_issued: bool,
    pub row_values_disclosed: bool,
    pub effective_profile: Option<AccessProfileSource>,
}

/// Reuse the HTTP profile-admission function. A permit is conditional on real
/// OIDC verification and row/data checks at runtime, not proof of record access.
pub fn preview_access(
    registry: &CompiledRegistry,
    scenario: AccessScenario,
) -> Result<AccessPreview, &'static str> {
    let entity = registry.entities().get(&scenario.entity);
    let profile = registry
        .entities()
        .get(&scenario.entity)
        .and_then(|entity| entity.access_profiles.get(&scenario.access_profile));
    let claims = synthetic_claims(scenario.claims, entity.zip(profile))?;
    let reason = match profile {
        None => Some("entity_or_profile_not_found"),
        Some(profile) => {
            let operation_granted = if let Some(path) = &scenario.read_path {
                scenario.operation == Operation::List
                    && profile.read_paths.iter().any(|grant| &grant.path == path)
            } else {
                profile.operations.contains(&scenario.operation)
                    && (scenario.operation != Operation::Revisions || profile.revision_access)
            };
            if !operation_granted {
                Some("operation_not_granted")
            } else {
                authorize_profile_claims(profile, &claims).err()
            }
        }
    };
    Ok(AccessPreview {
        mode: "offline_synthetic",
        admitted: reason.is_none(),
        reason: reason.unwrap_or("profile_requirements_satisfied"),
        record_access: "not_evaluated",
        credentials_verified: false,
        authority_issued: false,
        row_values_disclosed: false,
        effective_profile: profile.cloned(),
    })
}

fn synthetic_claims(
    claims: ScenarioClaims,
    target: Option<(&CompiledEntity, &AccessProfileSource)>,
) -> Result<VerifiedRequestClaims, &'static str> {
    let invalid = "use bounded synthetic claims matching the profile's declared row/lookup claim names, field types, and scalar/array shapes; never use a real token or record";
    if claims.scopes.len() > 128
        || claims.direct_claims.len() > 64
        || claims.scopes.iter().any(|s| s.is_empty() || s.len() > 512)
        || claims
            .direct_claims
            .keys()
            .any(|s| s.is_empty() || s.len() > 128)
    {
        return Err(invalid);
    }
    match (claims.principal_claim, claims.principal) {
        (None, None)
            if claims.scopes.is_empty()
                && claims.purpose.is_none()
                && claims.direct_claims.is_empty() =>
        {
            Ok(VerifiedRequestClaims::anonymous())
        }
        (Some(name), Some(principal)) => {
            let mut direct = BTreeMap::new();
            for (name, value) in claims.direct_claims {
                if let Some((entity, profile)) = target {
                    let binding = profile
                        .row_boundaries
                        .iter()
                        .find(|b| b.claim == name)
                        .map(|b| (b.field.as_str(), b.operator == BoundaryOperator::In))
                        .or_else(|| {
                            profile
                                .lookups
                                .iter()
                                .flat_map(|l| &l.claim_mapping)
                                .find(|(_, claim)| *claim == &name)
                                .map(|(field, _)| (field.as_str(), false))
                        })
                        .ok_or(invalid)?;
                    let field_type =
                        compiled_authority_field_type(entity, binding.0).ok_or(invalid)?;
                    direct.insert(
                        name,
                        map_authority_claim(&value, &field_type, binding.1).map_err(|_| invalid)?,
                    );
                    continue;
                }
                let value = match value {
                    Value::String(value) => VerifiedClaimValue::direct_string(value),
                    Value::Array(values) => {
                        let strings = values
                            .into_iter()
                            .map(|v| match v {
                                Value::String(s) => Ok(s),
                                _ => Err(invalid),
                            })
                            .collect::<Result<Vec<_>, _>>()?;
                        VerifiedClaimValue::direct_string_set(strings)
                    }
                    _ => return Err(invalid),
                }
                .map_err(|_| invalid)?;
                direct.insert(name, value);
            }
            VerifiedRequestClaims::authenticated(
                name,
                principal,
                claims.scopes,
                claims.purpose,
                direct,
            )
            .map_err(|_| invalid)
        }
        _ => Err(invalid),
    }
}
