// SPDX-License-Identifier: Apache-2.0
//! Typed authority dependencies of every compiled grant, shared by runtime and tooling.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use thiserror::Error;

use crate::contract::{BoundaryOperator, FieldTypeSource, LookupValueOrigin, RowBoundarySource};
use crate::model::{CompiledEntity, CompiledRegistry};

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityInventory {
    pub principal_claims: BTreeSet<String>,
    pub purpose_required: bool,
    pub direct_claims: BTreeMap<String, DirectClaimExpectation>,
}

/// An absent direct claim is allowed at token admission. The selected operation
/// requires its own claims; inventory membership does not grant or require access.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectClaimExpectation {
    pub field_type: FieldTypeSource,
    pub multi_value: bool,
    pub uses: Vec<AuthorityClaimUse>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityClaimUse {
    pub profile_id: String,
    pub entity_id: String,
    pub surface: String,
    pub field_id: String,
}

/// Value-free failures safe to surface during startup and offline inspection.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityInventoryError {
    #[error("a compiled anonymous grant carries authority")]
    AnonymousProfileCarriesAuthority,
    #[error("a compiled authenticated grant has no principal claim")]
    PrincipalClaimMissing,
    #[error("a compiled authority target entity does not exist")]
    TargetEntityNotCompiled,
    #[error("a compiled row boundary field does not exist")]
    BoundaryFieldNotCompiled,
    #[error("a compiled verified-claim lookup selector does not exist")]
    LookupSelectorNotCompiled,
    #[error("a compiled verified-claim lookup leaves a selector field unmapped")]
    LookupClaimMappingIncomplete,
    #[error("a compiled verified-claim lookup field does not exist")]
    LookupFieldNotCompiled,
    #[error("two compiled authority mappings expect different value shapes for one claim")]
    ConflictingClaimExpectation,
}

/// Walk the complete compiled authority surface without runtime I/O.
pub fn authority_inventory(
    registry: &CompiledRegistry,
) -> Result<AuthorityInventory, AuthorityInventoryError> {
    let mut inventory = AuthorityInventory::default();
    for entity in registry.entities().values() {
        for profile in entity.access_profiles.values() {
            inventory.profile(
                profile.anonymous,
                profile.principal_claim.as_deref(),
                &profile.required_scopes,
                &profile.required_purposes,
                !profile.row_boundaries.is_empty(),
            )?;
            let surface = format!("entities/{}/profiles/{}", entity.id, profile.id);
            inventory.boundaries(entity, &profile.id, &surface, &profile.row_boundaries)?;
            for lookup in profile
                .lookups
                .iter()
                .filter(|lookup| lookup.value_origin == LookupValueOrigin::VerifiedClaim)
            {
                let selector = entity
                    .selector_profiles
                    .get(&lookup.selector)
                    .ok_or(AuthorityInventoryError::LookupSelectorNotCompiled)?;
                for field_id in &selector.fields {
                    let claim = lookup
                        .claim_mapping
                        .get(field_id)
                        .ok_or(AuthorityInventoryError::LookupClaimMappingIncomplete)?;
                    let field_type = compiled_authority_field_type(entity, field_id)
                        .ok_or(AuthorityInventoryError::LookupFieldNotCompiled)?;
                    inventory.claim(
                        claim,
                        field_type,
                        false,
                        AuthorityClaimUse {
                            profile_id: profile.id.clone(),
                            entity_id: entity.id.clone(),
                            surface: format!("{surface}/lookups/{}", lookup.selector),
                            field_id: field_id.clone(),
                        },
                    )?;
                }
            }
            for stage in &profile.review_stages {
                for target in &stage.targets {
                    inventory.boundaries(
                        target_entity(registry, &target.entity)?,
                        &profile.id,
                        &format!(
                            "{surface}/reviewStages/{}/targets/{}",
                            stage.stage, target.entity
                        ),
                        &target.row_boundaries,
                    )?;
                }
            }
            for target in &profile.apply_targets {
                inventory.boundaries(
                    target_entity(registry, &target.entity)?,
                    &profile.id,
                    &format!("{surface}/applyTargets/{}", target.entity),
                    &target.row_boundaries,
                )?;
            }
            for presence in &profile.request_presence {
                inventory.boundaries(
                    target_entity(registry, &presence.request_type)?,
                    &profile.id,
                    &format!("{surface}/requestPresence/{}", presence.request_type),
                    &presence.row_boundaries,
                )?;
            }
        }
    }
    for action in &registry.actions().actions {
        for grant in &action.grants {
            inventory.profile(
                grant.anonymous,
                grant.principal_claim.as_deref(),
                &grant.required_scopes,
                &grant.required_purposes,
                grant
                    .targets
                    .iter()
                    .any(|target| !target.row_boundaries.is_empty()),
            )?;
            for target in &grant.targets {
                inventory.boundaries(
                    target_entity(registry, &target.entity_id)?,
                    &grant.profile_id,
                    &format!(
                        "actions/{}/profiles/{}/targets/{}",
                        action.id, grant.profile_id, target.entity_id
                    ),
                    &target.row_boundaries,
                )?;
            }
        }
    }
    Ok(inventory)
}

fn target_entity<'a>(
    registry: &'a CompiledRegistry,
    id: &str,
) -> Result<&'a CompiledEntity, AuthorityInventoryError> {
    registry
        .entities()
        .get(id)
        .ok_or(AuthorityInventoryError::TargetEntityNotCompiled)
}

impl AuthorityInventory {
    fn profile(
        &mut self,
        anonymous: bool,
        principal: Option<&str>,
        scopes: &BTreeSet<String>,
        purposes: &BTreeSet<String>,
        boundaries: bool,
    ) -> Result<(), AuthorityInventoryError> {
        if anonymous {
            if principal.is_some() || !scopes.is_empty() || !purposes.is_empty() || boundaries {
                return Err(AuthorityInventoryError::AnonymousProfileCarriesAuthority);
            }
        } else {
            self.principal_claims.insert(
                principal
                    .ok_or(AuthorityInventoryError::PrincipalClaimMissing)?
                    .to_owned(),
            );
            self.purpose_required |= !purposes.is_empty();
        }
        Ok(())
    }

    fn boundaries(
        &mut self,
        entity: &CompiledEntity,
        profile_id: &str,
        surface: &str,
        boundaries: &[RowBoundarySource],
    ) -> Result<(), AuthorityInventoryError> {
        for boundary in boundaries {
            let field_type = compiled_authority_field_type(entity, &boundary.field)
                .ok_or(AuthorityInventoryError::BoundaryFieldNotCompiled)?;
            self.claim(
                &boundary.claim,
                field_type,
                boundary.operator == BoundaryOperator::In,
                AuthorityClaimUse {
                    profile_id: profile_id.to_owned(),
                    entity_id: entity.id.clone(),
                    surface: surface.to_owned(),
                    field_id: boundary.field.clone(),
                },
            )?;
        }
        Ok(())
    }

    fn claim(
        &mut self,
        name: &str,
        field_type: FieldTypeSource,
        multi_value: bool,
        usage: AuthorityClaimUse,
    ) -> Result<(), AuthorityInventoryError> {
        if let Some(prior) = self.direct_claims.get_mut(name) {
            if prior.field_type != field_type || prior.multi_value != multi_value {
                return Err(AuthorityInventoryError::ConflictingClaimExpectation);
            }
            prior.uses.push(usage);
        } else {
            self.direct_claims.insert(
                name.to_owned(),
                DirectClaimExpectation {
                    field_type,
                    multi_value,
                    uses: vec![usage],
                },
            );
        }
        Ok(())
    }
}

pub(crate) fn compiled_authority_field_type(
    entity: &CompiledEntity,
    field_id: &str,
) -> Option<FieldTypeSource> {
    if field_id == entity.canonical_id.id {
        Some(entity.canonical_id.field_type.clone())
    } else {
        entity
            .fields
            .get(field_id)
            .map(|field| field.field_type.clone())
    }
}
