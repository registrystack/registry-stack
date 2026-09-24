// SPDX-License-Identifier: Apache-2.0
//! Pure, value-free access inspection and compile-time requirements.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::compiler::operation_id;
use crate::contract::{
    AccessProfileSource, AccessRequirementsSource, Classification, ConsentIssuerSource,
    EntitySource, FieldTypeSource, MembershipBoundarySource, Operation, RowBoundarySource,
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
                && profile.membership_boundaries.is_empty()
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
                && profile.membership_boundaries.is_empty()
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
                && profile.membership_boundaries.is_empty()
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
            // A row boundary compiles to an INSERT `WITH CHECK` pinning its field to
            // the caller's claim, so a permission that creates must keep the field
            // writable. The record id is never a writable field, so a boundary on it
            // is outside that advice.
            let creates = profile.operations.contains(&Operation::Create);
            let patches = profile.operations.contains(&Operation::Patch);
            let boundary_fields = profile
                .row_boundaries
                .iter()
                .map(|b| b.field.as_str())
                .filter(|field| *field != "id")
                .collect::<BTreeSet<_>>();
            if creates
                && boundary_fields
                    .iter()
                    .any(|field| profile.writable_fields.contains(*field))
            {
                let patch_review = if patches {
                    ". Review separately that patch can move a record within the caller's allowed values"
                } else {
                    ""
                };
                findings.push(Diagnostic::finding("access.profile.writable_row_boundary", format!("{path}.writableFields"),
                    &format!("create needs this authorization-bound field in writableFields, because the row policy pins it to the caller's claim on insert; keep it writable, and expect a create naming any other value to be refused{patch_review}")));
            } else if patches
                && profile
                    .row_boundaries
                    .iter()
                    .any(|b| profile.writable_fields.contains(&b.field))
            {
                findings.push(Diagnostic::finding("access.profile.writable_row_boundary", format!("{path}.writableFields"),
                    "patch can change an authorization-bound field within the caller's allowed values; remove it from writableFields unless moving records is intended"));
            }
            if creates {
                for field in boundary_fields
                    .iter()
                    .filter(|field| !profile.writable_fields.contains(**field))
                {
                    findings.push(Diagnostic::finding("access.profile.row_boundary_not_writable", format!("{path}.writableFields"),
                        &format!("create is permitted, but row boundary field `{field}` is not writable: a create cannot name it, the row policy pins it to the caller's claim on insert, and every create is refused. Add `{field}` to writableFields, or remove create from this permission")));
                }
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
            for permission in &profile.read_paths {
                findings.push(Diagnostic::finding("access.profile.related_disclosure", format!("{path}.readPaths[path={}]", permission.path),
                    "this permission discloses related records using the root profile, not target direct-access profiles; review its fields and the target/through entity accessRequirements"));
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
                    "actions[id={}].permissions[profile={}].targets[entity={entity}].rowBoundaries",
                    action.id, grant.profile_id
                ));
            }
        }
    }
    for reach in row_reach(entities, actions) {
        // Ordinary permissions retain their existing finding codes above.
        if reach.surface == "entity" {
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
            findings.push(Diagnostic::finding("access.target.unrestricted_rows", &reach.source_path,
                "this target permission has no claim-bound row restriction, within its configured operation and field limits. Review this registry-wide target authority"));
        }
    }
    for entity in entities.values() {
        ungated_client_findings(entity, &mut findings);
    }
    for action in &actions.actions {
        for grant in &action.permissions {
            if !grant.anonymous && grant.required_scopes.is_empty() {
                findings.push(Diagnostic::finding("access.action.no_required_scope",
                    format!("actions[id={}].permissions[profile={}].requiredScopes", action.id, grant.profile_id),
                    "no scope restricts who may select this action profile; any authenticated principal satisfying its purpose and target claims qualifies. Add a required scope unless this is intended"));
            }
        }
    }
    findings
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
        if profile.anonymous || profile.requester_clients.is_empty() {
            findings.push(Diagnostic::finding("access.consent.ungated_client", path, &format!(
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
            findings.push(Diagnostic::finding("access.consent.ungated_client", path, &format!(
                "{} also select the consent-gated {gated_ids}, and read `{}` without consent through this profile. Give the ungated profile its own client",
                shared.into_iter().collect::<Vec<_>>().join(", "), entity.id)));
        }
    }
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
    /// Consent-gated permissions and the recipients they admit; null when the
    /// project declares neither.
    pub consent: Option<ConsentExplanation>,
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
    pub entity: String,
    pub max_duration: String,
    pub gives: Vec<String>,
    pub revokes: Vec<String>,
    pub refusals: Vec<String>,
    pub scopes: Vec<String>,
    pub indexes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GatedPermissionExplanation {
    pub entity: String,
    pub profile: String,
    pub source_path: String,
    pub record: String,
    pub on: String,
    pub condition: String,
    pub purposes: Vec<String>,
    pub scope: String,
    pub max_duration: String,
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
    pub entity: String,
    pub classification: Classification,
    pub requirements: Option<AccessRequirementsSource>,
    pub profiles: Vec<AccessProfileSource>,
}

/// Configuration locations identify compiled permissions, not original file line numbers.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RowReachExplanation {
    pub entity: String,
    pub profile: String,
    pub source_path: String,
    pub surface: &'static str,
    pub rows: &'static str,
    pub row_boundaries: Vec<RowBoundarySource>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub membership_boundaries: Vec<MembershipBoundarySource>,
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
                   memberships: &[MembershipBoundarySource],
                   owner| {
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
                &profile.membership_boundaries,
                profile.request_visibility.is_some(),
            );
            for id in &profile.submitter_targets {
                if let Some(target) = entities
                    .get(id)
                    .and_then(|entity| entity.access_profiles.get(&profile.id))
                {
                    add(
                        id,
                        &profile.id,
                        format!("{path}.submitterTargets[entity={id}]"),
                        "submitter_target",
                        &target.row_boundaries,
                        &[],
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
                    &[],
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
                    &[],
                    false,
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
                        "actions[id={}].permissions[profile={}].targets[entity={}].rowBoundaries",
                        action.id, grant.profile_id, target.entity_id
                    ),
                    "action_target",
                    &target.row_boundaries,
                    &[],
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
        row_matching: "all claim-bound and current membership row predicates must hold; explicit empty rowBoundaries mean no claim-bound row restriction; requestVisibility owner additionally limits request reads",
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
                requirements: entity.access_requirements.clone(),
                profiles: entity.access_profiles.values().cloned().collect(),
            })
            .collect(),
        actions: registry.actions().clone(),
        row_reach: row_reach(registry.entities(), registry.actions()),
        claim_contract,
        claim_contract_error,
        consent: explain_consent(registry),
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
                max_duration: record.max_duration.iso.clone(),
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
                let max_duration = record.max_duration.iso.clone();
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
                        "each `{}` row is disclosed only while `{}` holds a {} decision whose subject is the row's `{}`, whose recipient is in the caller's recipient set, whose purpose is the request purpose and whose scope is `{}`; the decision must have started, must not have passed its until or {max_duration} after it was given, and no later revoke for the same subject, recipient, purpose and scope may supersede it",
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
                    max_duration,
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
