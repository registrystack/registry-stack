// SPDX-License-Identifier: Apache-2.0
//! Pure, value-free access inspection and compile-time requirements.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::compiler::operation_id;
use crate::contract::{
    AccessProfileSource, AccessRequirementsSource, Classification, EntitySource, FieldTypeSource,
    Operation, RowBoundarySource,
};
use crate::diagnostics::Diagnostic;
use crate::model::{CompiledActionInventory, CompiledEntity, CompiledRegistry};

fn profile_path(entity: &str, profile: &str) -> String {
    format!("entities[id={entity}].accessProfiles[id={profile}]")
}

pub(crate) fn validate_access_requirements(
    entities: &BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    for entity in entities.values() {
        if let Some(requirements) = &entity.access_requirements {
            let path = format!("entities[id={}].accessRequirements", entity.id);
            if requirements.required_scopes.is_empty()
                && requirements.allowed_purposes.is_empty()
                && requirements.row_boundaries.is_empty()
            {
                errors.push(Diagnostic::error("access.requirements.empty", &path,
                    "declare at least one scope, purpose, or row requirement; an empty block provides no protection"));
            }
            if requirements
                .required_scopes
                .iter()
                .chain(&requirements.allowed_purposes)
                .any(|s| s.is_empty())
            {
                errors.push(Diagnostic::error(
                    "access.requirements.empty_value",
                    &path,
                    "scope and purpose requirements must be nonempty strings",
                ));
            }
            for (index, boundary) in requirements.row_boundaries.iter().enumerate() {
                let valid_field = boundary.field == "id"
                    || entity.fields.iter().any(|field| {
                        field.id == boundary.field
                            && !matches!(
                                field.field_type,
                                FieldTypeSource::Structured { .. }
                                    | FieldTypeSource::Crs84Point { .. }
                            )
                    });
                if !valid_field
                    || boundary.claim.is_empty()
                    || requirements.row_boundaries[..index].contains(boundary)
                {
                    errors.push(Diagnostic::error("access.requirements.row_boundary.invalid",
                        format!("{path}.rowBoundaries[{index}]"),
                        "use a declared scalar stored field or id, a nonempty verified claim, and a unique binding"));
                }
            }
            for profile in &entity.access_profiles {
                check_profile(
                    requirements,
                    profile,
                    &profile_path(&entity.id, &profile.id),
                    errors,
                );
            }
        }
        // Relationship routes use the root profile, not the target's direct profile.
        // Check scopes/purposes against every visited entity. Target/join row requirements
        // cannot be claimed as enforced by a root-only row predicate.
        for profile in &entity.access_profiles {
            for grant in &profile.read_paths {
                let Some(path) = entity.read_paths.iter().find(|p| p.id == grant.path) else {
                    continue;
                };
                for visited in [&path.through, &path.to] {
                    let Some(requirements) = entities
                        .get(visited)
                        .and_then(|e| e.access_requirements.as_ref())
                    else {
                        continue;
                    };
                    let location = format!(
                        "{}.readPaths[path={}].requirements[entity={visited}]",
                        profile_path(&entity.id, &profile.id),
                        path.id
                    );
                    let mut request_requirements = requirements.clone();
                    request_requirements.row_boundaries.clear();
                    check_profile(&request_requirements, profile, &location, errors);
                    if !requirements.row_boundaries.is_empty() {
                        errors.push(Diagnostic::error("access.requirements.read_path.row_boundary_unsupported", location,
                            "this relationship route enforces root rows only; use a direct grant on the protected entity instead of this read-path grant"));
                    }
                }
            }
        }
    }
}

pub(crate) fn check_profile(
    requirements: &AccessRequirementsSource,
    profile: &AccessProfileSource,
    path: &str,
    errors: &mut Vec<Diagnostic>,
) {
    if profile.anonymous {
        errors.push(Diagnostic::error(
            "access.requirements.authentication",
            path,
            "this entity requires authenticated access; remove the anonymous grant",
        ));
    }
    for scope in requirements
        .required_scopes
        .difference(&profile.required_scopes)
    {
        errors.push(Diagnostic::error("access.requirements.scope_missing", format!("{path}.requiredScopes[value={scope}]"),
            "add the entity's mandatory scope to this profile; granting other scopes does not satisfy it"));
    }
    if !requirements.allowed_purposes.is_empty()
        && (profile.required_purposes.is_empty()
            || !profile
                .required_purposes
                .is_subset(&requirements.allowed_purposes))
    {
        errors.push(Diagnostic::error("access.requirements.purpose_widened", format!("{path}.requiredPurposes"),
            "require a nonempty subset of the entity's allowedPurposes; an empty list allows every purpose"));
    }
    for boundary in &requirements.row_boundaries {
        if !profile.row_boundaries.contains(boundary) {
            errors.push(Diagnostic::error("access.requirements.row_boundary_missing", format!("{path}.rowBoundaries[field={}]", boundary.field),
                "include the entity's exact field, claim, and operator binding; request filters and other claim names do not satisfy this requirement"));
        }
    }
}

pub(crate) fn access_findings(entities: &BTreeMap<String, EntitySource>) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    for entity in entities.values() {
        for profile in &entity.access_profiles {
            let path = profile_path(&entity.id, &profile.id);
            if !profile.anonymous && profile.required_scopes.is_empty() {
                findings.push(Diagnostic::finding("access.profile.no_required_scope", format!("{path}.requiredScopes"),
                    "no scope restricts who may select this profile; any authenticated principal satisfying its purpose and row claims qualifies. Add a required scope unless this is intended"));
            }
            if entity.classification != Classification::Public
                && profile.operations.contains(&Operation::List)
                && profile.row_boundaries.is_empty()
                && profile.request_visibility.is_none()
            {
                findings.push(Diagnostic::finding("access.profile.unrestricted_collection", format!("{path}.rowBoundaries"),
                    "this profile can list all rows, subject only to query bounds; caller filters are not authorization. Add a claim-bound row restriction or review this registry-wide access"));
            }
            let unrestricted_non_read = profile.request_visibility.is_some()
                && profile
                    .operations
                    .iter()
                    .any(|operation| !matches!(operation, Operation::Get | Operation::List));
            if entity.classification != Classification::Public
                && profile.row_boundaries.is_empty()
                && ((!profile.operations.contains(&Operation::List)
                    && profile.request_visibility.is_none())
                    || unrestricted_non_read)
            {
                findings.push(Diagnostic::finding("access.profile.unrestricted_rows", format!("{path}.rowBoundaries"),
                    "this profile has no claim-bound row restriction for its granted operations; requestVisibility owner limits request reads only, and other lifecycle rules still apply. Review this registry-wide access"));
            }
            if profile.anonymous
                && profile.operations.contains(&Operation::List)
                && profile.row_boundaries.is_empty()
            {
                findings.push(Diagnostic::finding("access.profile.anonymous_collection", format!("{path}.operations"),
                    "`list` is granted to unauthenticated callers, so every row this profile can read is world-readable and no claim can narrow it. Confirm the whole collection is meant to be public"));
            }
            let write_operations = [Operation::Create, Operation::Patch]
                .into_iter()
                .filter(|operation| profile.operations.contains(operation))
                .map(|operation| format!("`{}`", operation_id(operation)))
                .collect::<Vec<_>>();
            if !write_operations.is_empty() && profile.writable_fields.is_empty() {
                findings.push(Diagnostic::finding("access.profile.no_writable_fields", format!("{path}.writableFields"),
                    &format!("this profile grants {} and names no writable field, so every write naming a field is refused and a required field can never be supplied. List the fields this profile may write, or remove the write operations", write_operations.join(", "))));
            }
            if profile.operations.contains(&Operation::Patch)
                && profile
                    .row_boundaries
                    .iter()
                    .any(|b| profile.writable_fields.contains(&b.field))
            {
                findings.push(Diagnostic::finding("access.profile.writable_row_boundary", format!("{path}.writableFields"),
                    "patch can change an authorization-bound field within the caller's allowed values; remove it from writableFields unless moving records is intended"));
            }
            if profile.revision_access && profile.operations.contains(&Operation::Revisions) {
                findings.push(Diagnostic::finding("access.profile.revision_history", format!("{path}.revisionAccess"),
                    "history can disclose previous values of readable fields, including values removed from the current record; review historical disclosure separately"));
            }
            if profile.operations.contains(&Operation::Snapshot) {
                findings.push(Diagnostic::finding("access.profile.snapshot_history", format!("{path}.operations"),
                    "snapshot reads can reproduce retained historical rows under current authorization; review stored-field projection, filters, and row restrictions separately"));
            }
            if profile.allow_data_export {
                findings.push(Diagnostic::finding("access.profile.data_export", format!("{path}.allowDataExport"),
                    "bulk export is enabled; disabling it later cannot recall downloaded data. Review the readable fields and row restrictions"));
            }
            for field in &profile.readable_fields {
                if entity
                    .fields
                    .iter()
                    .any(|f| &f.id == field && f.classification > entity.classification)
                    || entity
                        .derived
                        .iter()
                        .flat_map(|d| &d.fields)
                        .any(|f| &f.id == field && f.classification > entity.classification)
                {
                    findings.push(Diagnostic::finding("access.profile.higher_classification", format!("{path}.readableFields[field={field}]"),
                        "this field is more sensitive than its entity's classification; verify the profile's scope and purpose before disclosing it"));
                }
            }
            for grant in &profile.read_paths {
                findings.push(Diagnostic::finding("access.profile.related_disclosure", format!("{path}.readPaths[path={}]", grant.path),
                    "this grant discloses related records using the root profile, not target direct-access profiles; review its fields and the target/through entity accessRequirements"));
            }
        }
    }
    findings
}

/// Findings on target grants after their types and referenced entities have compiled.
pub(crate) fn compiled_access_findings(
    entities: &BTreeMap<String, CompiledEntity>,
    actions: &CompiledActionInventory,
) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    for reach in row_reach(entities, actions) {
        // Ordinary grants retain their existing finding codes above.
        if reach.surface == "entity" {
            continue;
        }
        if reach.rows == "all"
            && entities
                .get(&reach.entity)
                .is_some_and(|entity| entity.classification != Classification::Public)
        {
            findings.push(Diagnostic::finding("access.target.unrestricted_rows", &reach.source_path,
                "this target grant has no claim-bound row restriction, within its configured operation and field limits. Review this registry-wide target authority"));
        }
    }
    for action in &actions.actions {
        for grant in &action.grants {
            if !grant.anonymous && grant.required_scopes.is_empty() {
                findings.push(Diagnostic::finding("access.action.no_required_scope",
                    format!("actions[id={}].grants[profile={}].requiredScopes", action.id, grant.profile_id),
                    "no scope restricts who may select this action profile; any authenticated principal satisfying its purpose and target claims qualifies. Add a required scope unless this is intended"));
            }
        }
    }
    findings
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessExplanation {
    pub scope_matching: &'static str,
    pub purpose_matching: &'static str,
    pub row_matching: &'static str,
    pub profile_selection: &'static str,
    pub relationship_matching: &'static str,
    pub missing_claims: &'static str,
    pub evaluation: &'static str,
    pub routes: crate::model::CompiledAccessInventory,
    pub entities: Vec<EntityAccessExplanation>,
    pub actions: CompiledActionInventory,
    pub row_reach: Vec<RowReachExplanation>,
    pub claim_contract: Option<crate::authority::AuthorityInventory>,
    pub claim_contract_error: Option<crate::authority::AuthorityInventoryError>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntityAccessExplanation {
    pub entity: String,
    pub classification: Classification,
    pub requirements: Option<AccessRequirementsSource>,
    pub profiles: Vec<AccessProfileSource>,
}

/// Configuration locations identify compiled grants, not original file line numbers.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RowReachExplanation {
    pub entity: String,
    pub profile: String,
    pub source_path: String,
    pub surface: &'static str,
    pub rows: &'static str,
    pub row_boundaries: Vec<RowBoundarySource>,
    pub owner_only_request_reads: bool,
}

fn row_reach(
    entities: &BTreeMap<String, CompiledEntity>,
    actions: &CompiledActionInventory,
) -> Vec<RowReachExplanation> {
    let mut reach = Vec::new();
    let mut add = |entity: &str,
                   profile: &str,
                   source_path: String,
                   surface,
                   boundaries: &[RowBoundarySource],
                   owner| {
        reach.push(RowReachExplanation {
            entity: entity.to_owned(),
            profile: profile.to_owned(),
            source_path,
            surface,
            rows: if boundaries.is_empty() {
                "all"
            } else {
                "claim_bound"
            },
            row_boundaries: boundaries.to_vec(),
            owner_only_request_reads: owner,
        });
    };
    for entity in entities.values() {
        for profile in entity.access_profiles.values() {
            let path = profile_path(&entity.id, &profile.id);
            add(
                &entity.id,
                &profile.id,
                format!("{path}.rowBoundaries"),
                "entity",
                &profile.row_boundaries,
                profile.request_visibility.is_some(),
            );
            for stage in &profile.review_stages {
                for target in &stage.targets {
                    add(
                        &target.entity,
                        &profile.id,
                        format!(
                            "{path}.reviewStages[stage={}].targets[entity={}].rowBoundaries",
                            stage.stage, target.entity
                        ),
                        "review_target",
                        &target.row_boundaries,
                        false,
                    );
                }
            }
            for target in &profile.apply_targets {
                add(
                    &target.entity,
                    &profile.id,
                    format!(
                        "{path}.applyTargets[entity={}].rowBoundaries",
                        target.entity
                    ),
                    "apply_target",
                    &target.row_boundaries,
                    false,
                );
            }
            for target in &profile.request_presence {
                add(
                    &target.request_type,
                    &profile.id,
                    format!(
                        "{path}.requestPresence[requestType={}].rowBoundaries",
                        target.request_type
                    ),
                    "request_presence",
                    &target.row_boundaries,
                    false,
                );
            }
        }
    }
    for action in &actions.actions {
        for grant in &action.grants {
            for target in &grant.targets {
                add(
                    &target.entity_id,
                    &grant.profile_id,
                    format!(
                        "actions[id={}].grants[profile={}].targets[entity={}].rowBoundaries",
                        action.id, grant.profile_id, target.entity_id
                    ),
                    "action_target",
                    &target.row_boundaries,
                    false,
                );
            }
        }
    }
    reach
}

/// Explain compiled authority without verifying credentials or evaluating records.
pub fn explain_access(registry: &CompiledRegistry) -> AccessExplanation {
    let (claim_contract, claim_contract_error) =
        match crate::authority::authority_inventory(registry) {
            Ok(inventory) => (Some(inventory), None),
            Err(error) => (None, Some(error)),
        };
    AccessExplanation {
        scope_matching: "all required scopes must be present",
        purpose_matching: "one allowed purpose must match; empty means unrestricted",
        row_matching: "all claim-bound row predicates must hold; explicit empty boundaries mean no claim-bound row restriction; requestVisibility owner additionally limits request reads",
        profile_selection: "one profile per request; selecting its name never grants authority and profiles are not merged",
        relationship_matching: "relationship paths use the root profile row boundaries and the path's target field permissions; target direct profiles do not apply",
        missing_claims: "missing required direct claims cannot satisfy their row boundary or verified-claim lookup; types and scalar/set shape are listed in claimContract",
        evaluation: "configuration inspection only; credentials and record access are not evaluated",
        routes: registry.access().clone(),
        entities: registry.entities().values().map(|entity| EntityAccessExplanation {
            entity: entity.id.clone(), classification: entity.classification,
            requirements: entity.access_requirements.clone(),
            profiles: entity.access_profiles.values().cloned().collect(),
        }).collect(),
        actions: registry.actions().clone(),
        row_reach: row_reach(registry.entities(), registry.actions()),
        claim_contract,
        claim_contract_error,
    }
}
