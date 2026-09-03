// SPDX-License-Identifier: Apache-2.0
//! Pure, value-free access inspection and compile-time requirements.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::compiler::operation_id;
use crate::contract::{
    AccessProfileSource, AccessRequirementsSource, Classification, EntitySource, FieldTypeSource,
    Operation,
};
use crate::diagnostics::Diagnostic;
use crate::model::CompiledRegistry;

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
            {
                findings.push(Diagnostic::finding("access.profile.unrestricted_collection", format!("{path}.rowBoundaries"),
                    "this profile can list all rows, subject only to query bounds; caller filters are not authorization. Add a claim-bound row restriction or review this registry-wide access"));
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

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessExplanation {
    pub scope_matching: &'static str,
    pub purpose_matching: &'static str,
    pub row_matching: &'static str,
    pub profile_selection: &'static str,
    pub routes: crate::model::CompiledAccessInventory,
    pub entities: Vec<EntityAccessExplanation>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntityAccessExplanation {
    pub entity: String,
    pub classification: Classification,
    pub requirements: Option<AccessRequirementsSource>,
    pub profiles: Vec<AccessProfileSource>,
}

/// Explain the effective profiles, not just route-to-profile identifiers.
pub fn explain_access(registry: &CompiledRegistry) -> AccessExplanation {
    AccessExplanation {
        scope_matching: "all required scopes must be present",
        purpose_matching: "one allowed purpose must match; empty means unrestricted",
        row_matching: "all claim-bound row predicates must hold; empty means no row restriction",
        profile_selection: "one profile per request; selecting its name never grants authority and profiles are not merged",
        routes: registry.access().clone(),
        entities: registry.entities().values().map(|entity| EntityAccessExplanation {
            entity: entity.id.clone(), classification: entity.classification,
            requirements: entity.access_requirements.clone(),
            profiles: entity.access_profiles.values().cloned().collect(),
        }).collect(),
    }
}
