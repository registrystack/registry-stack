// SPDX-License-Identifier: Apache-2.0
//! Pure, value-free access inspection and compile-time requirements.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::compiler::operation_id;
use crate::contract::{
    AccessProfileSource, AccessRequirementsSource, ActorKindSource, BoundaryOperator,
    Classification, ConsentIssuerSource, EntitySource, FieldTypeSource, MembershipBoundarySource,
    Operation, ProjectAccessProfileSource, RegistryProject, RowBoundarySource,
};
use crate::diagnostics::Diagnostic;
use crate::model::{
    CompiledActionInventory, CompiledActionTargetUseSource, CompiledEntity, CompiledRegistry,
};

fn profile_path(entity: &str, profile: &str) -> String {
    format!("recordTypes[id={entity}].accessProfiles[id={profile}]")
}

pub(crate) fn validate_access_requirements(
    entities: &BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    for entity in entities.values() {
        if let Some(requirements) = &entity.access_requirements {
            let path = format!("recordTypes[id={}].accessRequirements", entity.id);
            if requirements.required_scopes.is_empty()
                && requirements.allowed_purposes.is_empty()
                && requirements.row_boundaries.is_empty()
            {
                errors.push(Diagnostic::error("breg.access.requirements-empty", &path,
                    "declare at least one scope, purpose, or row requirement; an empty block provides no protection"));
            }
            if requirements
                .required_scopes
                .iter()
                .chain(&requirements.allowed_purposes)
                .any(|s| s.is_empty())
            {
                errors.push(Diagnostic::error(
                    "breg.access.requirements-empty-value",
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
                    errors.push(Diagnostic::error("breg.access.requirements-row-boundary-invalid",
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
                        "{}.readPaths[path={}].requirements[recordType={visited}]",
                        profile_path(&entity.id, &profile.id),
                        path.id
                    );
                    let mut request_requirements = requirements.clone();
                    request_requirements.row_boundaries.clear();
                    check_profile(&request_requirements, profile, &location, errors);
                    if !requirements.row_boundaries.is_empty() {
                        errors.push(Diagnostic::error("breg.access.requirements-read-path-row-boundary-unsupported", location,
                            "this relationship route enforces root rows only; use a direct grant on the protected record type instead of this read-path grant"));
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
    for scope in requirements
        .required_scopes
        .difference(&profile.required_scopes)
    {
        errors.push(Diagnostic::error("breg.access.requirements-scope-missing", format!("{path}.requiredScopes[value={scope}]"),
            "add the record type's mandatory scope to this profile; granting other scopes does not satisfy it"));
    }
    if !requirements.allowed_purposes.is_empty()
        && (profile.required_purposes.is_empty()
            || !profile
                .required_purposes
                .is_subset(&requirements.allowed_purposes))
    {
        errors.push(Diagnostic::error("breg.access.requirements-purpose-widened", format!("{path}.requiredPurposes"),
            "require a nonempty subset of the record type's allowedPurposes; an empty list allows every purpose"));
    }
    for boundary in &requirements.row_boundaries {
        if !profile.row_boundaries.contains(boundary) {
            errors.push(Diagnostic::error("breg.access.requirements-row-boundary-missing", format!("{path}.rowBoundaries[field={}]", boundary.field),
                "include the record type's exact field, claim, and operator binding; request filters and other claim names do not satisfy this requirement"));
        }
    }
}

pub(crate) fn access_findings(entities: &BTreeMap<String, EntitySource>) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    for entity in entities.values() {
        for profile in &entity.access_profiles {
            let path = profile_path(&entity.id, &profile.id);
            let caller_is_bounded =
                !profile.required_scopes.is_empty() && !profile.required_purposes.is_empty();
            if entity.classification != Classification::Public
                && profile.operations.contains(&Operation::List)
                && profile.row_boundaries.is_empty()
                && profile.membership_boundaries.is_empty()
                && !caller_is_bounded
            {
                findings.push(Diagnostic::finding("breg.access.profile-unrestricted-collection", format!("{path}.rowBoundaries"),
                    "this profile lists rows without claim-bound or membership restrictions; configured consent and other disclosure checks still apply. Caller filters are not authorization. Review this broad access and restrict the profile to intended callers. Statistical release publishers require unrestricted reads of their dataset dependencies"));
            }
            if entity.classification != Classification::Public
                && profile.row_boundaries.is_empty()
                && profile.membership_boundaries.is_empty()
                && !profile.operations.contains(&Operation::List)
                && !caller_is_bounded
            {
                findings.push(Diagnostic::finding("breg.access.profile-unrestricted-rows", format!("{path}.rowBoundaries"),
                    "this profile has no claim-bound row restriction for its granted operations; Review this registry-wide access"));
            }
            let write_operations = [Operation::Create, Operation::Patch, Operation::Import]
                .into_iter()
                .filter(|operation| profile.operations.contains(operation))
                .map(|operation| format!("`{}`", operation_id(operation)))
                .collect::<Vec<_>>();
            if !write_operations.is_empty() && profile.writable_fields.is_empty() {
                findings.push(Diagnostic::finding("breg.access.profile-no-writable-fields", format!("{path}.writableFields"),
                    &format!("this profile grants {} and names no writable field, so every write naming a field is refused and a required field can never be supplied. List the fields this profile may write, or remove the write operations", write_operations.join(", "))));
            }
            // A row boundary compiles to an INSERT `WITH CHECK` pinning its field to
            // the caller's claim, so a permission that creates must keep the field
            // writable. The record id is never a writable field, so a boundary on it
            // is outside that advice.
            let creates = profile.operations.contains(&Operation::Create)
                || profile.operations.contains(&Operation::Import);
            let patches = profile.operations.contains(&Operation::Patch);
            let boundary_fields = profile
                .row_boundaries
                .iter()
                .map(|b| b.field.as_str())
                .filter(|field| *field != "id")
                .collect::<BTreeSet<_>>();
            // Equality binds both the old and new row to one claim value. Only
            // an `in` boundary allows a patch to move between authorized values.
            if patches
                && profile.row_boundaries.iter().any(|b| {
                    b.operator == BoundaryOperator::In && profile.writable_fields.contains(&b.field)
                })
            {
                let advice = if creates {
                    "keep it writable for create, and use a separate patch permission without it if moving records is not intended"
                } else {
                    "remove it from writableFields unless moving records is intended"
                };
                findings.push(Diagnostic::finding("breg.access.profile-writable-row-boundary", format!("{path}.writableFields"),
                    &format!("patch can change an authorization-bound field within the caller's allowed values; {advice}")));
            }
            if creates {
                for field in boundary_fields
                    .iter()
                    .filter(|field| !profile.writable_fields.contains(**field))
                {
                    findings.push(Diagnostic::finding("breg.access.profile-row-boundary-not-writable", format!("{path}.writableFields"),
                        &format!("create is permitted, but row boundary field `{field}` is not writable: a create cannot name it, the row policy pins it to the caller's claim on insert, and every create is refused. Add `{field}` to writableFields, or remove create from this permission")));
                }
            }
            if profile.revision_access && profile.operations.contains(&Operation::Revisions) {
                findings.push(Diagnostic::finding("breg.access.profile-revision-history", format!("{path}.revisionAccess"),
                    "history can disclose previous values of readable fields, including values removed from the current record; review historical disclosure separately"));
            }
            if profile.operations.contains(&Operation::Snapshot) {
                findings.push(Diagnostic::finding("breg.access.profile-snapshot-history", format!("{path}.operations"),
                    "snapshot reads can reproduce retained historical rows under current authorization; review stored-field projection, filters, and row restrictions separately"));
            }
            if profile.allow_data_export {
                findings.push(Diagnostic::finding("breg.access.profile-data-export", format!("{path}.allowDataExport"),
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
                    findings.push(Diagnostic::finding("breg.access.profile-higher-classification", format!("{path}.readableFields[field={field}]"),
                        "this field is more sensitive than its record type's classification; verify the profile's scope and purpose before disclosing it"));
                }
            }
            for permission in &profile.read_paths {
                let Some(read_path) = entity
                    .read_paths
                    .iter()
                    .find(|read_path| read_path.id == permission.path)
                else {
                    continue;
                };
                let direct_grant_covers_fields = entities
                    .get(&read_path.to)
                    .and_then(|target| {
                        target
                            .access_profiles
                            .iter()
                            .find(|target_profile| target_profile.id == profile.id)
                    })
                    .is_some_and(|target_profile| {
                        let reads_directly = target_profile.operations.iter().any(|operation| {
                            matches!(
                                operation,
                                Operation::Get
                                    | Operation::Lookup
                                    | Operation::List
                                    | Operation::Snapshot
                            ) || (*operation == Operation::Revisions
                                && target_profile.revision_access)
                        });
                        // A path applies the root permission's caller and row
                        // gates, never the target permission's. Treat a direct
                        // target grant as covering it only when every root
                        // caller can directly read every target row.
                        reads_directly
                            && target_profile.row_boundaries.is_empty()
                            && target_profile.membership_boundaries.is_empty()
                            && target_profile.require_consent.is_empty()
                            && target_profile
                                .required_scopes
                                .is_subset(&profile.required_scopes)
                            && admits_every_token_of(target_profile.into(), profile.into())
                            && permission
                                .readable_fields
                                .iter()
                                .all(|field| target_profile.readable_fields.contains(field))
                    });
                if direct_grant_covers_fields {
                    continue;
                }
                let fields = permission
                    .readable_fields
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(", ");
                findings.push(Diagnostic::finding(
                    "breg.access.profile-related-disclosure",
                    format!("{path}.readPaths[path={}]", permission.path),
                    &format!(
                        "profile `{}` can read `{}` records linked to `{}` through `{}` on read path `{}`; it sees fields {fields} under its own `{}` row boundaries, and access profiles declared for `{}` do not apply",
                        profile.id,
                        read_path.to,
                        entity.id,
                        read_path.through,
                        read_path.id,
                        entity.id,
                        read_path.to,
                    ),
                ));
            }
        }
    }
    findings
}

/// Findings on target permissions after their types and referenced entities have compiled.
pub(crate) fn compiled_access_findings(
    entities: &BTreeMap<String, CompiledEntity>,
    actions: &CompiledActionInventory,
) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    let mut link_bound = BTreeSet::new();
    for action in &actions.actions {
        for entity in crate::consent::self_bound_targets(action, entities) {
            for grant in &action.permissions {
                link_bound.insert(format!(
                    "actions[id={}].permissions[profile={}].targets[recordType={entity}].rowBoundaries",
                    action.id, grant.profile_id
                ));
            }
        }
    }
    for reach in row_reach(entities, actions) {
        // Ordinary permissions and read-path grants retain their existing
        // finding codes above; a read path reaches related rows under the
        // root profile's own boundaries, which is not a target authority.
        if reach.surface == "record" || reach.surface == "read_path" {
            continue;
        }
        // A `self` consent issuer's subject and record targets are bound
        // through the caller's principal link, not by a row boundary.
        if reach.rows == "all"
            && !link_bound.contains(&reach.source_path)
            && entities
                .get(&reach.entity)
                .is_some_and(|entity| entity.classification != Classification::Public)
        {
            findings.push(Diagnostic::finding("breg.access.target-unrestricted-rows", &reach.source_path,
                "this target permission has no claim-bound row restriction, within its configured operation and field limits. Review this registry-wide target authority"));
        }
    }
    for entity in entities.values() {
        ungated_client_findings(entity, &mut findings);
    }
    findings
}

/// Findings on the access decisions a project writes, read before they are
/// copied onto each entity.
pub(crate) fn project_access_findings(
    project: &RegistryProject,
    entities: &BTreeMap<String, EntitySource>,
) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    for profile in &project.access_profiles {
        let path = format!("project.accessProfiles[id={}]", profile.id);
        if profile.required_scopes.is_empty() {
            let narrower = project
                .access_profiles
                .iter()
                .filter(|other| {
                    other.id != profile.id && admits_every_token_of(profile.into(), (*other).into())
                })
                .map(|other| format!("`{}`", other.id))
                .collect::<Vec<_>>();
            if !narrower.is_empty() {
                findings.push(Diagnostic::finding("breg.access.profile-subsumes-narrower", format!("{path}.requiredScopes"), &format!(
                    "this profile requires no scope and admits every token admitted by {}, so a caller admitted there also reaches what this profile grants by selecting it. Review what this profile grants, or require a scope here",
                    narrower.join(", "))));
            }
        }
        for (member, items) in [
            ("requiredScopes", &profile.required_scopes),
            ("requiredPurposes", &profile.required_purposes),
            ("requesterClients", &profile.requester_clients),
        ] {
            wildcard_spelled_finding(items, format!("{path}.{member}"), &mut findings);
        }
    }
    for entity in entities.values() {
        if let Some(requirements) = &entity.access_requirements {
            let path = format!("recordTypes[id={}].accessRequirements", entity.id);
            for (member, items) in [
                ("requiredScopes", &requirements.required_scopes),
                ("allowedPurposes", &requirements.allowed_purposes),
            ] {
                wildcard_spelled_finding(items, format!("{path}.{member}"), &mut findings);
            }
        }
    }
    findings
}

/// The entity and identifier of every profile a module contributed, read
/// before the project's profiles are copied onto the entities.
pub(crate) fn module_profile_keys(
    entities: &BTreeMap<String, EntitySource>,
) -> BTreeSet<(String, String)> {
    entities
        .values()
        .flat_map(|entity| {
            entity
                .access_profiles
                .iter()
                .map(|profile| (entity.id.clone(), profile.id.clone()))
        })
        .collect()
}

/// The project-profile findings, for the profiles a module contributed.
/// A module profile is compared with every other profile on its entity,
/// whether the module or the project wrote it.
pub(crate) fn module_access_findings(
    entities: &BTreeMap<String, EntitySource>,
    module_profiles: &BTreeSet<(String, String)>,
) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    for entity in entities.values() {
        for profile in &entity.access_profiles {
            if !module_profiles.contains(&(entity.id.clone(), profile.id.clone())) {
                continue;
            }
            let path = profile_path(&entity.id, &profile.id);
            if profile.required_scopes.is_empty() {
                let narrower = entity
                    .access_profiles
                    .iter()
                    .filter(|other| {
                        other.id != profile.id
                            && admits_every_token_of(profile.into(), (*other).into())
                    })
                    .map(|other| format!("`{}`", other.id))
                    .collect::<Vec<_>>();
                if !narrower.is_empty() {
                    findings.push(Diagnostic::finding("breg.access.profile-subsumes-narrower", format!("{path}.requiredScopes"), &format!(
                        "this profile requires no scope and admits every token admitted by {}, so a caller admitted there also reaches what this profile grants by selecting it. Review what this profile grants, or require a scope here",
                        narrower.join(", "))));
                }
            }
            for (member, items) in [
                ("requiredScopes", &profile.required_scopes),
                ("requiredPurposes", &profile.required_purposes),
                ("requesterClients", &profile.requester_clients),
            ] {
                wildcard_spelled_finding(items, format!("{path}.{member}"), &mut findings);
            }
        }
    }
    findings
}

/// The members of a profile that decide which tokens may select it.
struct TokenGates<'a> {
    actor_kind: Option<ActorKindSource>,
    principal_claim: &'a str,
    required_purposes: &'a BTreeSet<String>,
    requester_clients: &'a BTreeSet<String>,
    task_grant: bool,
}

impl<'a> From<&'a ProjectAccessProfileSource> for TokenGates<'a> {
    fn from(profile: &'a ProjectAccessProfileSource) -> Self {
        Self {
            actor_kind: profile.actor_kind,
            principal_claim: &profile.principal_claim,
            required_purposes: &profile.required_purposes,
            requester_clients: &profile.requester_clients,
            task_grant: profile.task_grant.is_some(),
        }
    }
}

impl<'a> From<&'a AccessProfileSource> for TokenGates<'a> {
    fn from(profile: &'a AccessProfileSource) -> Self {
        Self {
            actor_kind: profile.actor_kind,
            principal_claim: &profile.principal_claim,
            required_purposes: &profile.required_purposes,
            requester_clients: &profile.requester_clients,
            task_grant: profile.task_grant.is_some(),
        }
    }
}

/// Whether `open`, a profile that requires no scope, admits every token
/// `narrower` admits, whatever scopes `narrower` requires. It mirrors the
/// request-time profile gates: a member `open` leaves out admits everything,
/// a member it writes must cover what `narrower` writes, and a profile bound
/// to a task grant admits no token another profile admits.
fn admits_every_token_of(open: TokenGates<'_>, narrower: TokenGates<'_>) -> bool {
    let covers = |open: &BTreeSet<String>, narrower: &BTreeSet<String>| {
        open.is_empty() || (!narrower.is_empty() && narrower.is_subset(open))
    };
    // A delegated token is admitted only by an agent profile, and an agent
    // profile admits no other kind.
    let same_actors = open.actor_kind == narrower.actor_kind
        || (open.actor_kind.is_none() && narrower.actor_kind != Some(ActorKindSource::Agent));
    open.principal_claim == narrower.principal_claim
        && covers(open.required_purposes, narrower.required_purposes)
        && covers(open.requester_clients, narrower.requester_clients)
        && same_actors
        && !open.task_grant
        && !narrower.task_grant
}

/// An allow-list item spelled like a wildcard is one name. Nothing here
/// matches by pattern, so it grants and restricts exactly as any other item.
fn wildcard_spelled_finding(
    items: &BTreeSet<String>,
    path: String,
    findings: &mut Vec<Diagnostic>,
) {
    if items
        .iter()
        .any(|item| matches!(item.as_str(), "*" | "unrestricted"))
    {
        findings.push(Diagnostic::finding(
            "breg.access.wildcard-spelled-item",
            path,
            "The item is spelled like a wildcard but names one entry: `*` and `unrestricted` match nothing else in this list.",
        ));
    }
}

/// A client that may read a gated entity through a profile without consent
/// makes the consent gate a choice of profile, not a guarantee.
fn ungated_client_findings(entity: &CompiledEntity, findings: &mut Vec<Diagnostic>) {
    let gated = entity
        .access_profiles
        .values()
        .filter(|profile| !crate::consent::requirements(entity, &profile.id).is_empty())
        .collect::<Vec<_>>();
    if gated.is_empty() {
        return;
    }
    let gated_ids = gated
        .iter()
        .map(|profile| format!("`{}`", profile.id))
        .collect::<Vec<_>>()
        .join(", ");
    for profile in entity.access_profiles.values() {
        // A create answers with the row the caller just wrote, and an action
        // target only lets the action reference a row, so neither reads an
        // existing row without consent.
        let reads_existing_rows = profile
            .operations
            .iter()
            .any(|operation| !matches!(operation, Operation::Create | Operation::Invoke));
        if profile.readable_fields.is_empty()
            || !reads_existing_rows
            || !crate::consent::requirements(entity, &profile.id).is_empty()
        {
            continue;
        }
        let path = format!("{}.requesterClients", profile_path(&entity.id, &profile.id));
        if profile.requester_clients.is_empty() {
            findings.push(Diagnostic::finding("breg.access.consent-ungated-client", path, &format!(
                "this profile admits any client and reads `{}` without consent, so a client of the consent-gated {gated_ids} can read the same rows through it. List requesterClients that no gated profile admits",
                entity.id)));
            continue;
        }
        let shared = gated
            .iter()
            .flat_map(|gated| {
                gated
                    .requester_clients
                    .intersection(&profile.requester_clients)
            })
            .map(|client| format!("`{client}`"))
            .collect::<BTreeSet<_>>();
        if !shared.is_empty() {
            findings.push(Diagnostic::finding("breg.access.consent-ungated-client", path, &format!(
                "{} also select the consent-gated {gated_ids}, and read `{}` without consent through this profile. Give the ungated profile its own client",
                shared.into_iter().collect::<Vec<_>>().join(", "), entity.id)));
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessExplanation {
    /// Authored project profile presentation, including profiles granting nothing.
    pub access_profiles: Vec<crate::model::CompiledAccessProfileDisplay>,
    pub scope_matching: &'static str,
    pub purpose_matching: &'static str,
    pub row_matching: &'static str,
    pub profile_selection: &'static str,
    pub relationship_matching: &'static str,
    pub missing_claims: &'static str,
    pub evaluation: &'static str,
    pub routes: crate::model::CompiledAccessInventory,
    #[serde(rename = "recordTypes")]
    pub entities: Vec<EntityAccessExplanation>,
    pub actions: serde_json::Value,
    /// Autonomous policy, the existing writers that can shape it, and the
    /// exact product-owned Action ceiling it may exercise in the future.
    pub timers: Vec<TimerAccessExplanation>,
    pub row_reach: Vec<RowReachExplanation>,
    pub claim_contract: Option<crate::authority::AuthorityInventory>,
    pub claim_contract_error: Option<crate::authority::AuthorityInventoryError>,
    /// Consent-gated permissions and the recipients they admit; null when the
    /// project declares neither.
    pub consent: Option<ConsentExplanation>,
    /// Who may do what with each statistical dataset; empty when the project
    /// declares none.
    pub statistical_datasets: Vec<StatisticalDatasetAccessExplanation>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimerAccessExplanation {
    #[serde(rename = "recordType")]
    pub entity: String,
    pub timer: String,
    pub source_module: Option<String>,
    pub invoke: String,
    pub control_fields: BTreeSet<String>,
    pub predicate_fields: BTreeSet<String>,
    pub effect_input_fields: BTreeSet<String>,
    pub control_writers: Vec<TimerWriterExplanation>,
    pub predicate_writers: Vec<TimerWriterExplanation>,
    pub effect_input_writers: Vec<TimerWriterExplanation>,
    pub future_effect: TimerFutureEffectExplanation,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimerWriterExplanation {
    pub surface: &'static str,
    pub id: String,
    pub source_path: String,
    pub operations: BTreeSet<Operation>,
    pub fields: BTreeSet<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub access_profiles: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimerFutureEffectExplanation {
    pub authority: &'static str,
    pub record_grant_relationship: &'static str,
    pub system_grant: crate::model::CompiledSystemApplyGrant,
}

/// The access profiles that hold each operation on one statistical dataset.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatisticalDatasetAccessExplanation {
    pub dataset: String,
    pub display: crate::contract::PresentationSource,
    /// Authentication requirements for every dataset profile, including dataset-only readers.
    pub access_profiles: Vec<AccessProfileSource>,
    /// Profiles that read live counts.
    pub read_live: Vec<String>,
    /// The profile that publishes releases; empty when the dataset has none.
    pub publish: Vec<String>,
    /// Every profile that reads published releases.
    pub read_releases: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentExplanation {
    pub condition: &'static str,
    pub unmapped_clients: &'static str,
    pub trust_model: &'static str,
    pub ungating: &'static str,
    pub organizations: Vec<RecipientOrganizationExplanation>,
    pub groups: Vec<RecipientGroupExplanation>,
    pub clients: Vec<ConsentClientExplanation>,
    pub records: Vec<ConsentRecordExplanation>,
    pub permissions: Vec<GatedPermissionExplanation>,
    pub issuers: Vec<ConsentIssuerExplanation>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipientOrganizationExplanation {
    pub id: String,
    pub name: String,
    pub clients: Vec<String>,
    pub groups: Vec<String>,
    /// No client acts for a retired organization; its code stays so earlier
    /// consent rows keep their meaning.
    pub retired: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipientGroupExplanation {
    pub id: String,
    pub name: String,
    pub members: Vec<String>,
    /// Every client of every member organization.
    pub clients: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentClientExplanation {
    pub client: String,
    pub organization: Option<String>,
    /// The organization plus every group containing it; empty fails closed.
    pub recipients: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentRecordExplanation {
    #[serde(rename = "recordType")]
    pub entity: String,
    pub maximum_duration_days: u32,
    pub gives: Vec<String>,
    pub revokes: Vec<String>,
    pub refusals: Vec<String>,
    pub scopes: Vec<String>,
    pub indexes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GatedPermissionExplanation {
    #[serde(rename = "recordType")]
    pub entity: String,
    pub profile: String,
    pub source_path: String,
    pub record: String,
    pub on: String,
    pub condition: String,
    pub purposes: Vec<String>,
    pub scope: String,
    pub maximum_duration_days: u32,
    pub probe_function: String,
    pub indexes: Vec<String>,
    pub readable_fields: Vec<ReadableFieldExplanation>,
    pub clients: Vec<ConsentClientExplanation>,
    pub issuing_actions: Vec<ConsentIssuerExplanation>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadableFieldExplanation {
    pub field: String,
    pub classification: Option<Classification>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentIssuerExplanation {
    pub action: String,
    pub issuer: ConsentIssuerSource,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntityAccessExplanation {
    #[serde(rename = "recordType")]
    pub entity: String,
    pub classification: Classification,
    /// Direct grants remain constrained by the Record type mutation policy.
    pub mutation_policy: serde_json::Value,
    pub requirements: Option<AccessRequirementsSource>,
    pub profiles: Vec<serde_json::Value>,
}

/// Make effective defaults explicit only in author inspection. The compiled
/// profile's serialization remains the package and runtime authority contract.
fn inspect_record_profile(
    entity: &CompiledEntity,
    profile: &AccessProfileSource,
) -> serde_json::Value {
    let mut value = serde_json::to_value(profile).expect("compiled access profile serializes");
    if profile.row_boundaries.is_empty() {
        value["rowBoundaries"] = serde_json::json!("unrestricted");
    }
    value["allowCount"] = serde_json::json!(profile.allow_count);
    for (index, grant) in profile.read_paths.iter().enumerate() {
        let Some(path) = entity.read_paths.get(&grant.path) else {
            continue;
        };
        value["readPaths"][index]["targetRecordType"] = serde_json::json!(path.to);
        value["readPaths"][index]["throughRecordType"] = serde_json::json!(path.through);
        value["readPaths"][index]["route"] = serde_json::json!(path.route);
    }
    value
}

/// Configuration locations identify compiled permissions, not original file line numbers.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RowReachExplanation {
    #[serde(rename = "recordType")]
    pub entity: String,
    pub profile: String,
    pub source_path: String,
    pub surface: &'static str,
    pub rows: &'static str,
    pub row_boundaries: Vec<RowBoundarySource>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub membership_boundaries: Vec<MembershipBoundarySource>,
    pub owner_only: bool,
    /// Action target authority is enforced only while the named Action runs.
    /// It is an additional grant and never becomes ordinary Record CRUD.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_target_authority: Option<ActionTargetAuthorityExplanation>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionTargetAuthorityExplanation {
    pub enforcement: &'static str,
    pub record_grant_relationship: &'static str,
    /// Reports only whether the same profile has any direct Record grant for
    /// this Record type. It does not compare that grant's operations or row
    /// boundaries, or imply that Action authority grants ordinary CRUD.
    pub has_direct_record_grant: bool,
    pub uses: Vec<ActionTargetUseExplanation>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionTargetUseExplanation {
    pub role: &'static str,
    pub operation: Operation,
    pub source: CompiledActionTargetUseSource,
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
                   memberships: &[MembershipBoundarySource],
                   owner,
                   action_target_authority| {
        reach.push(RowReachExplanation {
            entity: entity.to_owned(),
            profile: profile.to_owned(),
            source_path,
            surface,
            rows: match (boundaries.is_empty(), memberships.is_empty()) {
                (true, true) => "all",
                (false, true) => "claim_bound",
                (true, false) => "membership_bound",
                (false, false) => "claim_and_membership_bound",
            },
            row_boundaries: boundaries.to_vec(),
            membership_boundaries: memberships.to_vec(),
            owner_only: owner,
            action_target_authority,
        });
    };
    for entity in entities.values() {
        for profile in entity.access_profiles.values() {
            let path = profile_path(&entity.id, &profile.id);
            add(
                &entity.id,
                &profile.id,
                format!("{path}.rowBoundaries"),
                "record",
                &profile.row_boundaries,
                &profile.membership_boundaries,
                false,
                None,
            );
            for grant in &profile.read_paths {
                let Some(read_path) = entity.read_paths.get(&grant.path) else {
                    continue;
                };
                add(
                    &read_path.to,
                    &profile.id,
                    format!("{path}.readPaths[path={}]", grant.path),
                    "read_path",
                    &profile.row_boundaries,
                    &profile.membership_boundaries,
                    false,
                    None,
                );
            }
        }
    }
    for action in &actions.actions {
        for grant in &action.permissions {
            for target in grant.entity_target_locks() {
                add(
                    &target.entity_id,
                    &grant.profile_id,
                    format!(
                        "actions[id={}].permissions[profile={}].targets[recordType={}].rowBoundaries",
                        action.id, grant.profile_id, target.entity_id
                    ),
                    "action_target",
                    &target.row_boundaries,
                    &[],
                    false,
                    Some(ActionTargetAuthorityExplanation {
                        enforcement: "runtime_enforced",
                        record_grant_relationship: "additional",
                        has_direct_record_grant: entities
                            .get(&target.entity_id)
                            .is_some_and(|entity| {
                                entity.access_profiles.contains_key(&grant.profile_id)
                            }),
                        uses: grant
                            .targets
                            .iter()
                            .filter(|use_| use_.entity_id == target.entity_id)
                            .map(|use_| ActionTargetUseExplanation {
                                role: match use_.operation {
                                    Operation::Create
                                    | Operation::Patch
                                    | Operation::Tombstone
                                    | Operation::Batch
                                    | Operation::Import => "write",
                                    Operation::Get
                                    | Operation::Lookup
                                    | Operation::List
                                    | Operation::Revisions
                                    | Operation::Snapshot
                                    | Operation::Invoke
                                    | Operation::Start => "existing_target",
                                },
                                operation: use_.operation,
                                source: use_.source.clone(),
                            })
                            .collect(),
                    }),
                );
            }
        }
        if let crate::model::CompiledActionExecution::Proposal { proposal } = &action.execution {
            for grant in &proposal.permissions {
                for target in &grant.targets {
                    add(
                        &target.entity_id,
                        &grant.profile_id,
                        format!(
                            "actions[id={}].execution.proposal.permissions[profile={}].targets[recordType={}].rowBoundaries",
                            action.id, grant.profile_id, target.entity_id
                        ),
                        "proposal_target",
                        &target.row_boundaries,
                        &[],
                        grant.ownership == Some(crate::contract::ProposalOwnership::Caller),
                        None,
                    );
                }
            }
        }
    }
    reach
}

fn timer_writer_explanations(
    entity: &CompiledEntity,
    actions: &CompiledActionInventory,
    fields: &BTreeSet<String>,
    include_tombstone: bool,
) -> Vec<TimerWriterExplanation> {
    let write_operations = [
        Operation::Create,
        Operation::Patch,
        Operation::Tombstone,
        Operation::Batch,
        Operation::Import,
    ];
    let mut writers = entity
        .access_profiles
        .values()
        .filter_map(|profile| {
            let affected_fields = profile
                .writable_fields
                .intersection(fields)
                .cloned()
                .collect::<BTreeSet<_>>();
            let operations = write_operations
                .iter()
                .copied()
                .filter(|operation| {
                    profile.operations.contains(operation)
                        && match operation {
                            Operation::Tombstone => include_tombstone,
                            _ => !affected_fields.is_empty(),
                        }
                })
                .collect::<BTreeSet<_>>();
            if operations.is_empty() {
                return None;
            }
            Some(TimerWriterExplanation {
                surface: "record-permission",
                id: profile.id.clone(),
                source_path: profile_path(&entity.id, &profile.id),
                operations,
                fields: affected_fields,
                access_profiles: vec![profile.id.clone()],
            })
        })
        .collect::<Vec<_>>();

    for action in &actions.actions {
        let uses = action
            .target_uses
            .iter()
            .filter(|target| {
                if target.entity_id != entity.id {
                    return false;
                }
                match target.operation {
                    Operation::Create | Operation::Patch => !target.fields.is_disjoint(fields),
                    Operation::Tombstone => include_tombstone,
                    _ => false,
                }
            })
            .collect::<Vec<_>>();
        if uses.is_empty() {
            continue;
        }
        let operations = uses
            .iter()
            .map(|target| target.operation)
            .collect::<BTreeSet<_>>();
        let affected_fields = uses
            .iter()
            .flat_map(|target| target.fields.intersection(fields).cloned())
            .collect::<BTreeSet<_>>();
        let mut access_profiles = action
            .permissions
            .iter()
            .filter(|permission| {
                permission.targets.iter().any(|target| {
                    uses.iter().any(|use_| {
                        target.entity_id == use_.entity_id
                            && target.operation == use_.operation
                            && target.source == use_.source
                    })
                })
            })
            .map(|permission| permission.profile_id.clone())
            .collect::<BTreeSet<_>>();
        if let crate::model::CompiledActionExecution::Proposal { proposal } = &action.execution {
            access_profiles.extend(
                proposal
                    .permissions
                    .iter()
                    .filter(|permission| {
                        permission.operations.iter().any(|operation| {
                            matches!(
                                operation,
                                crate::contract::ProposalOperation::Edit
                                    | crate::contract::ProposalOperation::Submit
                                    | crate::contract::ProposalOperation::Revise
                                    | crate::contract::ProposalOperation::Apply
                                    | crate::contract::ProposalOperation::Rebase
                                    | crate::contract::ProposalOperation::Retry
                            )
                        }) && permission
                            .targets
                            .iter()
                            .any(|target| target.entity_id == entity.id)
                    })
                    .map(|permission| permission.profile_id.clone()),
            );
        }
        writers.push(TimerWriterExplanation {
            surface: "action",
            id: action.id.clone(),
            source_path: format!("actions[id={}]", action.id),
            operations,
            fields: affected_fields,
            access_profiles: access_profiles.into_iter().collect(),
        });
    }
    writers
}

fn explain_timers(registry: &CompiledRegistry) -> Vec<TimerAccessExplanation> {
    registry
        .entities()
        .values()
        .flat_map(|entity| {
            entity.timers.values().map(|timer| TimerAccessExplanation {
                entity: entity.id.clone(),
                timer: timer.id.clone(),
                source_module: timer.source_module.clone(),
                invoke: timer.invoke.clone(),
                control_fields: timer.control_fields.clone(),
                predicate_fields: timer.predicate_fields.clone(),
                effect_input_fields: timer.effect_input_fields.clone(),
                control_writers: timer_writer_explanations(
                    entity,
                    registry.actions(),
                    &timer.control_fields,
                    true,
                ),
                predicate_writers: timer_writer_explanations(
                    entity,
                    registry.actions(),
                    &timer.predicate_fields,
                    false,
                ),
                effect_input_writers: timer_writer_explanations(
                    entity,
                    registry.actions(),
                    &timer.effect_input_fields,
                    false,
                ),
                future_effect: TimerFutureEffectExplanation {
                    authority: "product-owned",
                    record_grant_relationship: "none",
                    system_grant: timer.system_grant.clone(),
                },
            })
        })
        .collect()
}

/// Explain compiled authority without verifying credentials or evaluating records.
pub fn explain_access(registry: &CompiledRegistry) -> AccessExplanation {
    let (claim_contract, claim_contract_error) =
        match crate::authority::authority_inventory(registry) {
            Ok(inventory) => (Some(inventory), None),
            Err(error) => (None, Some(error)),
        };
    AccessExplanation {
        access_profiles: registry.access_profile_displays().to_vec(),
        scope_matching: "all required scopes must be present",
        purpose_matching: "one allowed purpose must match; a profile that names none accepts every purpose",
        row_matching: "all claim-bound and current membership row predicates must hold; rowBoundaries written as unrestricted mean no claim-bound row restriction; Proposal caller ownership additionally limits Proposal operations",
        profile_selection: "one profile per request; selecting its name never grants authority and profiles are not merged",
        relationship_matching: "relationship paths use the root profile row boundaries and the path's target field permissions; target direct profiles do not apply",
        missing_claims: "missing required direct claims cannot satisfy their row boundary or verified-claim lookup; types and scalar/set shape are listed in claimContract",
        evaluation: "configuration inspection only; credentials and record access are not evaluated",
        routes: registry.access().clone(),
        entities: registry
            .entities()
            .values()
            .map(|entity| EntityAccessExplanation {
                entity: entity.id.clone(),
                classification: entity.classification,
                mutation_policy: crate::artifacts::render_mutation_policy(entity),
                requirements: entity.access_requirements.clone(),
                profiles: entity
                    .access_profiles
                    .values()
                    .map(|profile| inspect_record_profile(entity, profile))
                    .collect(),
            })
            .collect(),
        actions: serde_json::json!({
            "actions": registry.actions().actions.iter().map(crate::artifacts::inspect_action).collect::<Vec<_>>(),
            "routes": registry.actions().routes,
            "access": registry.actions().access,
        }),
        timers: explain_timers(registry),
        row_reach: row_reach(registry.entities(), registry.actions()),
        claim_contract,
        claim_contract_error,
        consent: explain_consent(registry),
        statistical_datasets: registry
            .statistical_datasets()
            .values()
            .map(|dataset| {
                let releases = dataset.releases.as_ref();
                StatisticalDatasetAccessExplanation {
                    dataset: dataset.id.clone(),
                    display: dataset.display.clone(),
                    access_profiles: dataset.access_profiles.values().cloned().collect(),
                    read_live: dataset.live_profiles.iter().cloned().collect(),
                    publish: releases
                        .map(|releases| releases.publisher.clone())
                        .into_iter()
                        .collect(),
                    // A live reader and the publisher read releases too, so
                    // the audience is all three sets together.
                    read_releases: releases
                        .map(|releases| {
                            dataset
                                .live_profiles
                                .iter()
                                .chain([&releases.publisher])
                                .chain(&releases.readers)
                                .cloned()
                                .collect::<BTreeSet<_>>()
                        })
                        .unwrap_or_default()
                        .into_iter()
                        .collect(),
                }
            })
            .collect(),
    }
}

fn consent_client(
    recipients: &crate::model::CompiledRecipients,
    client: &str,
) -> ConsentClientExplanation {
    ConsentClientExplanation {
        client: client.to_owned(),
        organization: recipients
            .organizations
            .iter()
            .find(|organization| organization.clients.iter().any(|id| id == client))
            .map(|organization| organization.id.clone()),
        recipients: recipients.recipient_set(client).into_iter().collect(),
    }
}

fn explain_consent(registry: &CompiledRegistry) -> Option<ConsentExplanation> {
    let recipients = registry.recipients();
    let entities = registry.entities();
    if recipients.is_empty()
        && entities
            .values()
            .all(|entity| entity.consent_record.is_none() && entity.consent_requirements.is_empty())
    {
        return None;
    }
    let issuers = registry
        .actions()
        .actions
        .iter()
        .filter_map(|action| {
            Some(ConsentIssuerExplanation {
                action: action.id.clone(),
                issuer: action.consent_issuer?,
            })
        })
        .collect::<Vec<_>>();
    let index_names = |entity: &CompiledEntity| {
        crate::consent::index_statements(entity)
            .into_iter()
            .map(|(_, name, _)| name)
            .collect::<Vec<_>>()
    };
    let records = entities
        .values()
        .filter_map(|entity| {
            let record = entity.consent_record.as_ref()?;
            Some(ConsentRecordExplanation {
                entity: entity.id.clone(),
                maximum_duration_days: record.maximum_duration_days,
                gives: record.gives.iter().cloned().collect(),
                revokes: record.revokes.iter().cloned().collect(),
                refusals: record.refusals.iter().cloned().collect(),
                scopes: entity
                    .fields
                    .values()
                    .find_map(|field| match &field.field_type {
                        FieldTypeSource::VocabularyCode { vocabulary, values }
                            if vocabulary == crate::consent::SCOPES_VOCABULARY =>
                        {
                            Some(values.clone())
                        }
                        _ => None,
                    })
                    .unwrap_or_default(),
                indexes: index_names(entity),
            })
        })
        .collect();
    let mut clients = recipients
        .clients()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let mut permissions = Vec::new();
    for entity in entities.values() {
        for (profile_id, requirements) in &entity.consent_requirements {
            let Some(profile) = entity.access_profiles.get(profile_id) else {
                continue;
            };
            clients.extend(profile.requester_clients.iter().cloned());
            for (index, requirement) in requirements.iter().enumerate() {
                let Some(record_entity) = entities.get(&requirement.record) else {
                    continue;
                };
                let Some(record) = &record_entity.consent_record else {
                    continue;
                };
                let purposes = profile
                    .required_purposes
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>();
                let maximum_duration_days = record.maximum_duration_days;
                let days = if maximum_duration_days == 1 {
                    "day"
                } else {
                    "days"
                };
                permissions.push(GatedPermissionExplanation {
                    entity: entity.id.clone(),
                    profile: profile.id.clone(),
                    source_path: format!(
                        "{}.requireConsent[{index}]",
                        profile_path(&entity.id, &profile.id)
                    ),
                    record: requirement.record.clone(),
                    on: requirement.on.clone(),
                    condition: format!(
                        "each `{}` row is disclosed only while `{}` holds a {} decision whose subject is the row's `{}`, whose recipient is in the caller's recipient set, whose purpose is the request purpose and whose scope is `{}`; the decision must have started, must not have passed its until or {maximum_duration_days} {days} after it was given, and no later revoke for the same subject, recipient, purpose and scope may supersede it",
                        entity.id,
                        requirement.record,
                        record
                            .gives
                            .iter()
                            .map(|code| format!("`{code}`"))
                            .collect::<Vec<_>>()
                            .join(" or "),
                        requirement.on,
                        profile.id
                    ),
                    purposes,
                    scope: profile.id.clone(),
                    maximum_duration_days,
                    probe_function: crate::consent::function_name(&entity.id, &profile.id, index),
                    indexes: index_names(record_entity),
                    readable_fields: profile
                        .readable_fields
                        .iter()
                        .map(|field| ReadableFieldExplanation {
                            field: field.clone(),
                            classification: entity.fields.get(field).map(|f| f.classification),
                        })
                        .collect(),
                    clients: profile
                        .requester_clients
                        .iter()
                        .map(|client| consent_client(recipients, client))
                        .collect(),
                    issuing_actions: registry
                        .actions()
                        .actions
                        .iter()
                        .filter(|action| {
                            action.effects.iter().any(|effect| {
                                effect.operation == Operation::Create
                                    && effect.target.entity_id == requirement.record
                            })
                        })
                        .filter_map(|action| {
                            Some(ConsentIssuerExplanation {
                                action: action.id.clone(),
                                issuer: action.consent_issuer?,
                            })
                        })
                        .collect(),
                });
            }
        }
    }
    Some(ConsentExplanation {
        condition: "a gated profile discloses a row only while every one of its requireConsent checks holds; a check holds while a current, unsuperseded give exists for the row's subject, one of the caller's recipients, the request purpose and the profile id as scope",
        unmapped_clients: "each gated profile's requesterClients map to recipient organizations; a client no organization lists has an empty recipient set, so every consent check it reaches fails closed",
        trust_model: "a consent probe reads the consent table only under its own marker (registry.consent_probe equal to the probe function and registry.access_profile equal to the gated profile), the same processing-only marker model as membership boundaries; registry.recipients is set from the verified requester client, never from a token claim or request header",
        ungating: "the gated profile id is the consent scope; to stop requiring consent, declare a new profile id and list the old one in retiredConsentScopes, never remove requireConsent in place",
        organizations: recipients
            .organizations
            .iter()
            .map(|organization| RecipientOrganizationExplanation {
                id: organization.id.clone(),
                name: organization.name.clone(),
                clients: organization.clients.clone(),
                groups: recipients
                    .groups
                    .iter()
                    .filter(|group| group.members.contains(&organization.id))
                    .map(|group| group.id.clone())
                    .collect(),
                retired: organization.clients.is_empty(),
            })
            .collect(),
        groups: recipients
            .groups
            .iter()
            .map(|group| RecipientGroupExplanation {
                id: group.id.clone(),
                name: group.name.clone(),
                members: group.members.clone(),
                clients: recipients
                    .organizations
                    .iter()
                    .filter(|organization| group.members.contains(&organization.id))
                    .flat_map(|organization| organization.clients.iter().cloned())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            })
            .collect(),
        clients: clients
            .iter()
            .map(|client| consent_client(recipients, client))
            .collect(),
        records,
        permissions,
        issuers,
    })
}
