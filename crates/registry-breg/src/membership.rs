// SPDX-License-Identifier: Apache-2.0
//! One-hop current membership checks over governed stored records.

use std::collections::BTreeMap;
#[cfg(feature = "runtime")]
use std::collections::BTreeSet;

use crate::contract::{EntitySource, FieldTypeSource, Operation};
use crate::diagnostics::Diagnostic;
use crate::generated_ddl::{quote_identifier, quote_literal};
use crate::model::{CompiledEntity, CompiledMembershipBoundary};
use crate::physical_names::hex_prefix;
use sha2::{Digest, Sha256};

pub(crate) fn validate(entities: &BTreeMap<String, EntitySource>, errors: &mut Vec<Diagnostic>) {
    for entity in entities.values() {
        for profile in &entity.access_profiles {
            if profile.membership_boundaries.is_empty() {
                continue;
            }
            let location = format!(
                "entities[id={}].accessProfiles[id={}].membershipBoundaries",
                entity.id, profile.id
            );
            if profile.anonymous || profile.principal_claim.is_none() {
                errors.push(Diagnostic::error("access.membership.authentication", &location,
                    "membership boundaries require an authenticated profile with a verified principalClaim"));
            }
            if profile.operations.iter().any(|operation| {
                !matches!(
                    operation,
                    Operation::Get
                        | Operation::Lookup
                        | Operation::List
                        | Operation::Revisions
                        | Operation::Snapshot
                )
            }) || !profile.writable_fields.is_empty()
                || !profile.review_stages.is_empty()
                || !profile.apply_targets.is_empty()
                || !profile.request_presence.is_empty()
                || profile.request_visibility.is_some()
            {
                errors.push(Diagnostic::error("access.membership.read_only", &location,
                    "membership boundaries support get, lookup, list, revisions and snapshot only; use a separate directly authorized profile for writes and review"));
            }
            if profile.spatial_queries.is_some() {
                errors.push(Diagnostic::error("access.membership.spatial_unsupported", &location,
                    "spatial bbox uses a separate database authority role; use a directly authorized bbox profile or ordinary membership-filtered reads"));
            }
            if entity.change_request.is_some() {
                errors.push(Diagnostic::error("access.membership.request_unsupported", &location,
                    "membership boundaries do not authorize change-request lifecycle or retained request data; use a direct profile"));
            }
            if profile.membership_boundaries.len() > 8 {
                errors.push(Diagnostic::error(
                    "access.membership.limit",
                    &location,
                    "declare at most eight one-hop membership boundaries",
                ));
            }
            for (index, boundary) in profile.membership_boundaries.iter().enumerate() {
                let path = format!("{location}[{index}]");
                if profile.membership_boundaries[..index].contains(boundary) {
                    errors.push(Diagnostic::error(
                        "access.membership.duplicate",
                        &path,
                        "each membership boundary must be unique",
                    ));
                }
                let Some(membership) = entities.get(&boundary.membership_entity) else {
                    errors.push(Diagnostic::error(
                        "access.membership.entity_unknown",
                        &path,
                        "membershipEntity must name a governed entity",
                    ));
                    continue;
                };
                let root_field = entity
                    .fields
                    .iter()
                    .find(|field| field.id == boundary.field);
                let key_field = membership
                    .fields
                    .iter()
                    .find(|field| field.id == boundary.membership_key_field);
                let matching = match (root_field, key_field) {
                    (Some(root), Some(key)) => matches!((&root.field_type, &key.field_type),
                        (FieldTypeSource::Reference { target: a, .. }, FieldTypeSource::Reference { target: b, .. }) if a == b),
                    _ => false,
                };
                if !matching {
                    errors.push(Diagnostic::error(
                        "access.membership.key_type",
                        &path,
                        "field and membershipKeyField must be stored references to the same entity",
                    ));
                }
                if !membership.fields.iter().any(|field| {
                    field.id == boundary.principal_field
                        && matches!(
                            field.field_type,
                            FieldTypeSource::String { .. } | FieldTypeSource::Text { .. }
                        )
                }) {
                    errors.push(Diagnostic::error("access.membership.principal_type", &path,
                        "principalField must be a stored string or text field matching the verified principal"));
                }
                if !membership.fields.iter().any(|field| {
                    field.id == boundary.active_field
                        && matches!(field.field_type, FieldTypeSource::Boolean)
                }) {
                    errors.push(Diagnostic::error("access.membership.active_type", &path,
                        "activeField must be a stored Boolean field; only true memberships authorize access"));
                }
                // A membership source is a leaf authorization fact. Its own RLS must
                // never traverse back into the protected root, even through an OR arm.
                if membership.id == entity.id
                    || membership.change_request.is_some()
                    || membership
                        .access_profiles
                        .iter()
                        .any(|candidate| !candidate.membership_boundaries.is_empty())
                    || entities.values().any(|candidate| {
                        candidate
                            .read_paths
                            .iter()
                            .any(|path| path.through == membership.id || path.to == membership.id)
                    })
                {
                    errors.push(Diagnostic::error("access.membership.source_recursive", &path,
                        "membership sources must be ordinary leaf entities without membership boundaries or incoming read paths; use a separate membership fact entity"));
                }
                if let Some(requirements) = &membership.access_requirements {
                    let mut processing = requirements.clone();
                    processing.row_boundaries.clear();
                    crate::access::check_profile(&processing, profile, &path, errors);
                    if !requirements.row_boundaries.is_empty() {
                        errors.push(Diagnostic::error("access.membership.source_row_requirement", &path,
                            "membership source row requirements cannot be inferred from a root profile; use its mandatory scopes and purposes with the fixed principal membership predicate"));
                    }
                }
            }
        }
        for profile in &entity.access_profiles {
            for grant in &profile.read_paths {
                let Some(path) = entity.read_paths.iter().find(|path| path.id == grant.path) else {
                    continue;
                };
                if [&path.through, &path.to].iter().any(|id| {
                    entities.get(*id).is_some_and(|target| {
                        target
                            .access_profiles
                            .iter()
                            .any(|candidate| !candidate.membership_boundaries.is_empty())
                    })
                }) {
                    errors.push(Diagnostic::error("access.membership.read_path_target", format!("entities[id={}].accessProfiles[id={}].readPaths", entity.id, profile.id),
                        "relationship target membership boundaries are not inherited from the root profile; use the protected entity's direct read route"));
                }
            }
        }
    }
}

pub(crate) fn compile(entities: &mut BTreeMap<String, CompiledEntity>) {
    let resolved = entities
        .iter()
        .map(|(id, entity)| {
            let profiles = entity
                .access_profiles
                .iter()
                .filter_map(|(profile_id, profile)| {
                    if profile.membership_boundaries.is_empty() {
                        return None;
                    }
                    let boundaries = profile
                        .membership_boundaries
                        .iter()
                        .map(|boundary| {
                            let source = &entities[&boundary.membership_entity];
                            CompiledMembershipBoundary {
                                field: boundary.field.clone(),
                                membership_entity: source.id.clone(),
                                membership_table: source.physical_table.clone(),
                                membership_key_column: source.fields
                                    [&boundary.membership_key_field]
                                    .physical_name
                                    .clone(),
                                principal_column: source.fields[&boundary.principal_field]
                                    .physical_name
                                    .clone(),
                                active_column: source.fields[&boundary.active_field]
                                    .physical_name
                                    .clone(),
                            }
                        })
                        .collect();
                    Some((profile_id.clone(), boundaries))
                })
                .collect();
            (id.clone(), profiles)
        })
        .collect::<BTreeMap<_, _>>();
    for (id, boundaries) in resolved {
        entities
            .get_mut(&id)
            .expect("compiled entity")
            .membership_boundaries = boundaries;
    }
}

pub(crate) fn boundaries<'a>(
    entity: &'a CompiledEntity,
    profile: &str,
) -> &'a [CompiledMembershipBoundary] {
    entity
        .membership_boundaries
        .get(profile)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

#[cfg(feature = "runtime")]
pub(crate) fn fields(entity: &CompiledEntity, profile: &str) -> BTreeSet<String> {
    boundaries(entity, profile)
        .iter()
        .map(|boundary| boundary.field.clone())
        .collect()
}

pub(crate) fn function_name(entity: &str, profile: &str, index: usize) -> String {
    let mut hash = Sha256::new();
    hash.update(b"breg/current-membership/v1");
    for part in [entity, profile, &index.to_string()] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part.as_bytes());
    }
    format!("membership_{}", hex_prefix(&hash.finalize(), 12))
}

pub(crate) fn predicate(
    entity: &CompiledEntity,
    profile: &str,
    mut root_value: impl FnMut(&str) -> String,
) -> String {
    boundaries(entity, profile)
        .iter()
        .enumerate()
        .map(|(index, boundary)| {
            format!(
                "registry_context.{}({})",
                quote_identifier(&function_name(&entity.id, profile, index)),
                root_value(&boundary.field)
            )
        })
        .collect::<Vec<_>>()
        .join(" AND ")
}

pub(crate) fn source_predicate(boundary: &CompiledMembershipBoundary, alias: &str) -> String {
    format!("{alias}.record_lifecycle = 'active' AND {alias}.{} = NULLIF(current_setting('registry.principal', true), '') AND {alias}.{} IS TRUE",
        quote_identifier(&boundary.principal_column), quote_identifier(&boundary.active_column))
}

pub(crate) fn source_guard(entity: &str, profile: &str, index: usize) -> String {
    format!("NULLIF(current_setting('registry.membership_probe', true), '') = {} AND NULLIF(current_setting('registry.access_profile', true), '') = {}",
        quote_literal(&function_name(entity, profile, index)), quote_literal(profile))
}
