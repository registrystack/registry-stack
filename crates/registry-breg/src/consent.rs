// SPDX-License-Identifier: Apache-2.0
//! Subject-issued consent records and the read permissions that require them.
//!
//! A consent-record entity is an append-only table of decisions keyed by
//! (subject, recipient, purpose, scope). A `requireConsent` permission returns
//! a row only while the caller's recipient set holds a current, unsuperseded
//! give for the row's subject under the request purpose and the profile id.
//! The engine knows the decision sets, the validity bounds and the key; the
//! meaning of any decision code stays in the project.

use std::collections::{BTreeMap, BTreeSet};

use crate::contract::{
    AccessProfileSource, ActionSource, BoundaryOperator, ConsentIssuerSource, EntitySource,
    FieldTypeSource, MutationMode, Operation, ProjectAccessProfileSource, RegistryProject,
    RowBoundarySource,
};
use crate::diagnostics::Diagnostic;
use crate::model::{
    CompiledConsentDuration, CompiledConsentRecord, CompiledConsentRequirement, CompiledEntity,
    CompiledRecipients,
};

/// The synthesized vocabulary of every organization and group id.
pub const RECIPIENTS_VOCABULARY: &str = "registry-recipients";
/// The synthesized vocabulary of every gated profile id plus retired scopes.
pub const SCOPES_VOCABULARY: &str = "registry-consent-scopes";
/// The reserved claim carrying the caller's recipient set. No token supplies it.
pub const RECIPIENTS_CLAIM: &str = "registry:recipients";
/// The reserved claim prefix carrying one consent entity's feed decisions.
pub const DECISIONS_CLAIM_PREFIX: &str = "registry:consent-decisions:";

/// The canonical row identity, bound to `record_id` by the consent probe.
pub(crate) const OWN_ID: &str = "id";

/// Ten years of 365.25 days.
const MAX_DURATION_SECONDS: u64 = 315_576_000;
const SECONDS_PER_YEAR: u64 = 31_557_600;
const SECONDS_PER_MONTH: u64 = 2_629_800;
/// One organization plus its groups stays within the 64-value `in` bound.
const MAX_GROUPS_PER_ORGANIZATION: usize = 63;
const MAX_FEED_DECISIONS: usize = 64;

/// Whether a claim name is filled by the engine and never read from a token.
pub fn is_reserved_claim(claim: &str) -> bool {
    claim == RECIPIENTS_CLAIM || claim.starts_with(DECISIONS_CLAIM_PREFIX)
}

/// The reserved claim carrying one consent entity's feed decision set.
pub fn decisions_claim(entity: &str) -> String {
    format!("{DECISIONS_CLAIM_PREFIX}{entity}")
}

/// The compiler-synthesized vocabularies. Each is present only when it has a
/// value, so a project without consent resolves exactly as before.
pub(crate) fn synthesized_vocabularies(
    project: &RegistryProject,
    entities: &BTreeMap<String, EntitySource>,
) -> Vec<(&'static str, Vec<String>)> {
    let mut vocabularies = Vec::new();
    let recipients = project
        .recipients
        .iter()
        .flat_map(|recipients| {
            recipients
                .organizations
                .iter()
                .map(|organization| organization.id.clone())
                .chain(recipients.groups.iter().map(|group| group.id.clone()))
        })
        .collect::<BTreeSet<_>>();
    if !recipients.is_empty() {
        vocabularies.push((RECIPIENTS_VOCABULARY, recipients.into_iter().collect()));
    }
    let scopes = entities
        .values()
        .flat_map(|entity| &entity.access_profiles)
        .filter(|profile| !profile.require_consent.is_empty())
        .map(|profile| profile.id.clone())
        .chain(project.retired_consent_scopes.iter().cloned())
        .collect::<BTreeSet<_>>();
    if !scopes.is_empty() {
        vocabularies.push((SCOPES_VOCABULARY, scopes.into_iter().collect()));
    }
    vocabularies
}

pub(crate) fn is_reserved_vocabulary(id: &str) -> bool {
    id == RECIPIENTS_VOCABULARY || id == SCOPES_VOCABULARY
}

pub(crate) fn validate(
    project: &RegistryProject,
    entities: &BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    validate_recipients(project, errors);
    validate_retired_scopes(project, entities, errors);
    for entity in entities.values() {
        if let Some(record) = &entity.consent_record {
            validate_record(project, entity, record, entities, errors);
        }
        for profile in &entity.access_profiles {
            if !profile.require_consent.is_empty() {
                validate_requirements(project, entity, profile, entities, errors);
            }
        }
    }
    validate_read_paths(entities, errors);
    validate_submitter_targets(entities, errors);
    validate_reserved_claims(project, entities, errors);
}

fn validate_recipients(project: &RegistryProject, errors: &mut Vec<Diagnostic>) {
    let Some(recipients) = &project.recipients else {
        return;
    };
    let mut ids = BTreeSet::new();
    let organizations = recipients
        .organizations
        .iter()
        .map(|organization| organization.id.as_str())
        .collect::<BTreeSet<_>>();
    for (id, name, contact, path) in recipients
        .organizations
        .iter()
        .map(|organization| {
            (
                &organization.id,
                &organization.name,
                Some(&organization.contact),
                "recipients.organizations[]",
            )
        })
        .chain(
            recipients
                .groups
                .iter()
                .map(|group| (&group.id, &group.name, None, "recipients.groups[]")),
        )
    {
        if !valid_identifier(id) || !ids.insert(id.as_str()) {
            errors.push(Diagnostic::error(
                "recipients.id",
                format!("{path}.id"),
                "organization and group ids share one namespace; each must be unique and use the lowercase identifier grammar",
            ));
        }
        if name.trim().is_empty() || contact.is_some_and(|contact| contact.trim().is_empty()) {
            errors.push(Diagnostic::error(
                "recipients.id",
                path,
                "every recipient declares a name, and every organization a contact, shown in notices",
            ));
        }
    }
    let mut clients = BTreeSet::new();
    for organization in &recipients.organizations {
        for client in &organization.clients {
            if client.trim().is_empty() || !clients.insert(client.as_str()) {
                errors.push(Diagnostic::error(
                    "recipients.client_unique",
                    format!("recipients.organizations[id={}].clients", organization.id),
                    "a client acts for at most one organization; list each non-empty client once",
                ));
            }
        }
    }
    let mut memberships = BTreeMap::<&str, usize>::new();
    for group in &recipients.groups {
        let members = group
            .members
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if members.len() != group.members.len()
            || members.iter().any(|member| !organizations.contains(member))
        {
            errors.push(Diagnostic::error(
                "recipients.group_members",
                format!("recipients.groups[id={}].members", group.id),
                "group members are distinct declared organizations; groups do not nest",
            ));
        }
        for member in members {
            *memberships.entry(member).or_default() += 1;
        }
    }
    for (organization, count) in memberships {
        if count > MAX_GROUPS_PER_ORGANIZATION {
            errors.push(Diagnostic::error(
                "recipients.set_bound",
                format!("recipients.organizations[id={organization}]"),
                "an organization belongs to at most 63 groups, so its recipient set fits one row-boundary value set",
            ));
        }
    }
}

fn validate_retired_scopes(
    project: &RegistryProject,
    entities: &BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    let current = entities
        .values()
        .flat_map(|entity| &entity.access_profiles)
        .map(|profile| profile.id.as_str())
        .chain(
            project
                .access_profiles
                .iter()
                .map(|profile| profile.id.as_str()),
        )
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    for scope in &project.retired_consent_scopes {
        if !valid_identifier(scope) || current.contains(scope.as_str()) || !seen.insert(scope) {
            errors.push(Diagnostic::error(
                "consent.vocabulary.reserved",
                "retiredConsentScopes",
                "a retired consent scope is a unique former profile id that no current profile uses",
            ));
        }
    }
}

fn validate_record(
    project: &RegistryProject,
    entity: &EntitySource,
    record: &crate::contract::ConsentRecordSource,
    entities: &BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    let location = format!("entities[id={}].consentRecord", entity.id);
    if entity.mutation_mode != MutationMode::CreateOnly {
        errors.push(Diagnostic::error(
            "consent.record.mutation_mode",
            format!("entities[id={}].mutationMode", entity.id),
            "a consent-record entity is createOnly; a decision is changed only by a later decision",
        ));
    }
    let field = |id: &str| entity.fields.iter().find(|field| field.id == id);
    let reference_target = |id: &str| match field(id).map(|field| &field.field_type) {
        Some(FieldTypeSource::Reference { target, .. }) => Some(target.clone()),
        _ => None,
    };
    let vocabulary = |id: &str| match field(id).map(|field| &field.field_type) {
        Some(FieldTypeSource::VocabularyCode { vocabulary, values }) => {
            Some((vocabulary.clone(), values.clone()))
        }
        _ => None,
    };
    let timestamp = |id: &str| {
        field(id).is_some_and(|field| matches!(field.field_type, FieldTypeSource::Timestamp))
    };
    let subject_target = reference_target(&record.subject);
    let bound_to = |id: &str, expected: &str| {
        vocabulary(id).is_some_and(|(vocabulary, _)| vocabulary == expected)
    };
    let decision = vocabulary(&record.decision.field);
    let fields_valid = subject_target.is_some()
        && bound_to(&record.recipient, RECIPIENTS_VOCABULARY)
        && bound_to(&record.scope, SCOPES_VOCABULARY)
        && vocabulary(&record.purpose).is_some_and(|(id, _)| !is_reserved_vocabulary(&id))
        && decision
            .as_ref()
            .is_some_and(|(id, _)| !is_reserved_vocabulary(id))
        && timestamp(&record.validity.from)
        && field(&record.validity.from).is_some_and(|field| field.required)
        && record.validity.until.as_deref().is_none_or(timestamp)
        && project.recipients.is_some();
    if !fields_valid {
        errors.push(Diagnostic::error(
            "consent.record.fields",
            &location,
            "subject is a reference; recipient uses registry-recipients (declare project recipients); scope uses registry-consent-scopes; purpose and decision are vocabulary codes; from is a required timestamp and until an optional timestamp",
        ));
    }
    let decisions = &record.decision;
    let codes = decision.map(|(_, values)| values).unwrap_or_default();
    let gives = decisions.gives.iter().collect::<BTreeSet<_>>();
    let revokes = decisions.revokes.iter().collect::<BTreeSet<_>>();
    let refusals = decisions.refusals.iter().collect::<BTreeSet<_>>();
    if gives.is_empty()
        || revokes.is_empty()
        || gives.len() != decisions.gives.len()
        || revokes.len() != decisions.revokes.len()
        || refusals.len() != decisions.refusals.len()
        || !gives.is_disjoint(&revokes)
        || !refusals.is_subset(&revokes)
        || gives.len() + revokes.len() > MAX_FEED_DECISIONS
        || gives
            .iter()
            .chain(&revokes)
            .any(|code| !codes.contains(code))
    {
        errors.push(Diagnostic::error(
            "consent.record.values",
            format!("{location}.decision"),
            "gives and revokes are non-empty, distinct, disjoint codes of the decision vocabulary, at most 64 together, and refusals are a subset of revokes",
        ));
    }
    if parse_duration(&record.validity.max_duration).is_none() {
        errors.push(Diagnostic::error(
            "consent.record.max_duration",
            format!("{location}.validity.maxDuration"),
            "maxDuration is a positive ISO 8601 duration such as P365D, at most ten years",
        ));
    }
    let plaintext = [
        Some(&record.subject),
        Some(&record.recipient),
        Some(&record.purpose),
        Some(&record.scope),
        Some(&record.decision.field),
        Some(&record.validity.from),
        record.validity.until.as_ref(),
    ];
    if plaintext
        .into_iter()
        .flatten()
        .any(|id| field(id).is_some_and(|field| field.encrypted))
    {
        errors.push(Diagnostic::error(
            "consent.record.plaintext",
            &location,
            "consent key and validity fields are plaintext; the consent check compares stored values, so ciphertext could never match",
        ));
    }
    let incoming_read_path = entities.values().any(|candidate| {
        candidate
            .read_paths
            .iter()
            .any(|path| path.through == entity.id || path.to == entity.id)
    });
    let subject_is_record = subject_target
        .as_ref()
        .and_then(|target| entities.get(target))
        .is_some_and(|target| target.consent_record.is_some());
    if entity.change_request.is_some()
        || entity
            .access_profiles
            .iter()
            .any(|profile| !profile.require_consent.is_empty())
        || incoming_read_path
        || subject_is_record
    {
        errors.push(Diagnostic::error(
            "consent.record.leaf",
            &location,
            "a consent-record entity is a leaf: no change request, no requireConsent on its own profiles, no incoming read paths, and its subject is not another consent record",
        ));
    }
    for profile in &entity.access_profiles {
        if profile.operations.contains(&Operation::Create)
            || profile.operations.contains(&Operation::Batch)
        {
            errors.push(Diagnostic::error(
                "consent.record.direct_write",
                format!(
                    "entities[id={}].accessProfiles[id={}].operations",
                    entity.id, profile.id
                ),
                "consent rows are created only by actions that declare consentIssuer; no profile grants create or batch",
            ));
        }
    }
}

fn validate_requirements(
    project: &RegistryProject,
    entity: &EntitySource,
    profile: &AccessProfileSource,
    entities: &BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    let location = format!(
        "entities[id={}].accessProfiles[id={}].requireConsent",
        entity.id, profile.id
    );
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
        || !profile.apply_targets.is_empty()
        || !profile.request_presence.is_empty()
        || profile.request_visibility.is_some()
    {
        errors.push(Diagnostic::error(
            "consent.require.read_only",
            &location,
            "requireConsent supports get, lookup, list, revisions and snapshot only; use a separate profile for writes",
        ));
    }
    if profile.anonymous {
        errors.push(Diagnostic::error(
            "consent.require.anonymous",
            &location,
            "requireConsent needs a verified requester client; anonymous profiles cannot carry it",
        ));
    }
    if profile.spatial_queries.is_some() {
        errors.push(Diagnostic::error(
            "consent.require.spatial_unsupported",
            &location,
            "spatial bbox uses a separate database authority role that cannot evaluate consent; use ordinary consent-checked reads",
        ));
    }
    if profile.allow_data_export {
        errors.push(Diagnostic::error(
            "consent.require.export_unsupported",
            &location,
            "bulk data export is refused on consent-checked permissions",
        ));
    }
    let clients = project
        .recipients
        .iter()
        .flat_map(|recipients| &recipients.organizations)
        .flat_map(|organization| organization.clients.iter().map(String::as_str))
        .collect::<BTreeSet<_>>();
    if profile.requester_clients.is_empty()
        || profile
            .requester_clients
            .iter()
            .any(|client| !clients.contains(client.as_str()))
    {
        errors.push(Diagnostic::error(
            "consent.require.clients",
            &location,
            "requireConsent needs requesterClients (with actorKind), each listed by a declared recipient organization",
        ));
    }
    for (index, requirement) in profile.require_consent.iter().enumerate() {
        let path = format!("{location}[{index}]");
        let Some((record_entity, record)) =
            entities.get(&requirement.record).and_then(|record_entity| {
                record_entity
                    .consent_record
                    .as_ref()
                    .map(|record| (record_entity, record))
            })
        else {
            errors.push(Diagnostic::error(
                "consent.require.key",
                &path,
                "record must name a consent-record entity",
            ));
            continue;
        };
        let subject_target = record_entity
            .fields
            .iter()
            .find(|field| field.id == record.subject)
            .and_then(|field| match &field.field_type {
                FieldTypeSource::Reference { target, .. } => Some(target.as_str()),
                _ => None,
            });
        let key_valid = if requirement.on == OWN_ID {
            subject_target == Some(entity.id.as_str())
        } else {
            entity
                .fields
                .iter()
                .find(|field| field.id == requirement.on)
                .is_some_and(|field| {
                    !field.encrypted
                        && matches!(&field.field_type,
                            FieldTypeSource::Reference { target, .. } if Some(target.as_str()) == subject_target)
                })
        };
        if !key_valid {
            errors.push(Diagnostic::error(
                "consent.require.key",
                &path,
                "on: id needs a consent subject referencing this entity; any other field is a plaintext stored reference to the consent subject's entity",
            ));
        }
        let purposes = record_entity
            .fields
            .iter()
            .find(|field| field.id == record.purpose)
            .and_then(|field| match &field.field_type {
                FieldTypeSource::VocabularyCode { values, .. } => Some(values),
                _ => None,
            });
        if profile.required_purposes.is_empty()
            || purposes.is_some_and(|purposes| {
                profile
                    .required_purposes
                    .iter()
                    .any(|purpose| !purposes.contains(purpose))
            })
        {
            errors.push(Diagnostic::error(
                "consent.require.purpose",
                &path,
                "requireConsent needs requiredPurposes, each a code of the consent record's purpose vocabulary",
            ));
        }
    }
}

/// A read path never inherits a gated target's consent from its root.
fn validate_read_paths(entities: &BTreeMap<String, EntitySource>, errors: &mut Vec<Diagnostic>) {
    let gated = |id: &String| {
        entities.get(id).is_some_and(|target| {
            target
                .access_profiles
                .iter()
                .any(|profile| !profile.require_consent.is_empty())
        })
    };
    for entity in entities.values() {
        for profile in &entity.access_profiles {
            for grant in &profile.read_paths {
                let Some(path) = entity.read_paths.iter().find(|path| path.id == grant.path) else {
                    continue;
                };
                if gated(&path.through) || gated(&path.to) {
                    errors.push(Diagnostic::error(
                        "consent.require.read_path_target",
                        format!(
                            "entities[id={}].accessProfiles[id={}].readPaths",
                            entity.id, profile.id
                        ),
                        "consent on a read path's intermediate or target entity is not inherited from the root; use the gated entity's direct read route",
                    ));
                }
            }
        }
    }
}

/// A gated permission never serves as another permission's same-profile get
/// authority, so a write can never probe a subject the caller cannot read.
fn validate_submitter_targets(
    entities: &BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    for entity in entities.values() {
        for profile in &entity.access_profiles {
            if profile.submitter_targets.iter().any(|target| {
                gated_in(
                    entities.get(target).map(|target| &target.access_profiles),
                    &profile.id,
                )
            }) {
                errors.push(Diagnostic::error(
                    "consent.require.read_only",
                    format!(
                        "entities[id={}].accessProfiles[id={}].submitterTargets",
                        entity.id, profile.id
                    ),
                    "a consent-checked permission cannot authorize a referenced submitter target",
                ));
            }
        }
    }
}

fn gated_in(profiles: Option<&Vec<AccessProfileSource>>, profile: &str) -> bool {
    profiles.is_some_and(|profiles| {
        profiles
            .iter()
            .any(|candidate| candidate.id == profile && !candidate.require_consent.is_empty())
    })
}

/// The recipient claim binds only a consent record's recipient field on a
/// get and list feed. The decision claim is always synthesized.
fn validate_reserved_claims(
    project: &RegistryProject,
    entities: &BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    for entity in entities.values() {
        for profile in &entity.access_profiles {
            let path = format!(
                "entities[id={}].accessProfiles[id={}]",
                entity.id, profile.id
            );
            if profile
                .principal_claim
                .as_deref()
                .is_some_and(is_reserved_claim)
            {
                refuse_claim(&format!("{path}.principalClaim"), errors);
            }
            for boundary in &profile.row_boundaries {
                if !is_reserved_claim(&boundary.claim) {
                    continue;
                }
                let feed = boundary.claim == RECIPIENTS_CLAIM
                    && boundary.operator == BoundaryOperator::In
                    && entity
                        .consent_record
                        .as_ref()
                        .is_some_and(|record| record.recipient == boundary.field)
                    && profile
                        .operations
                        .iter()
                        .all(|operation| matches!(operation, Operation::Get | Operation::List));
                if !feed {
                    refuse_claim(&format!("{path}.rowBoundaries"), errors);
                }
            }
        }
        if entity
            .access_requirements
            .as_ref()
            .is_some_and(|requirements| {
                requirements
                    .row_boundaries
                    .iter()
                    .any(|boundary| is_reserved_claim(&boundary.claim))
            })
        {
            refuse_claim(
                &format!(
                    "entities[id={}].accessRequirements.rowBoundaries",
                    entity.id
                ),
                errors,
            );
        }
    }
    for profile in &project.access_profiles {
        if profile
            .principal_claim
            .as_deref()
            .is_some_and(is_reserved_claim)
        {
            refuse_claim(
                &format!("project.accessProfiles[id={}].principalClaim", profile.id),
                errors,
            );
        }
    }
}

fn refuse_claim(path: &str, errors: &mut Vec<Diagnostic>) {
    errors.push(Diagnostic::error(
        "consent.feed.claim",
        path,
        "registry:recipients binds only an in row boundary on a consent record's recipient field in a get and list permission, and registry:consent-decisions claims are synthesized by the compiler",
    ));
}

/// Resolve consent records and requirements onto compiled entities, add the
/// feed decision bound, and return the declared recipients.
pub(crate) fn compile(
    project: &RegistryProject,
    sources: &BTreeMap<String, EntitySource>,
    entities: &mut BTreeMap<String, CompiledEntity>,
) -> CompiledRecipients {
    for source in sources.values() {
        let entity = entities.get_mut(&source.id).expect("compiled entity");
        if let Some(record) = &source.consent_record {
            let column = |id: &str| entity.fields[id].physical_name.clone();
            let compiled = CompiledConsentRecord {
                subject_column: column(&record.subject),
                recipient_column: column(&record.recipient),
                purpose_column: column(&record.purpose),
                scope_column: column(&record.scope),
                decision_field: record.decision.field.clone(),
                decision_column: column(&record.decision.field),
                from_column: column(&record.validity.from),
                until_column: record.validity.until.as_deref().map(column),
                gives: record.decision.gives.iter().cloned().collect(),
                revokes: record.decision.revokes.iter().cloned().collect(),
                refusals: record.decision.refusals.iter().cloned().collect(),
                max_duration: parse_duration(&record.validity.max_duration)
                    .expect("validated consent maxDuration"),
            };
            let claim = decisions_claim(&entity.id);
            for profile in entity.access_profiles.values_mut() {
                if profile
                    .row_boundaries
                    .iter()
                    .any(|boundary| boundary.claim == RECIPIENTS_CLAIM)
                {
                    profile.row_boundaries.push(RowBoundarySource {
                        field: compiled.decision_field.clone(),
                        claim: claim.clone(),
                        operator: BoundaryOperator::In,
                    });
                }
            }
            entity.consent_record = Some(compiled);
        }
        entity.consent_requirements = source
            .access_profiles
            .iter()
            .filter(|profile| !profile.require_consent.is_empty())
            .map(|profile| {
                let requirements = profile
                    .require_consent
                    .iter()
                    .map(|requirement| CompiledConsentRequirement {
                        record: requirement.record.clone(),
                        on: requirement.on.clone(),
                    })
                    .collect();
                (profile.id.clone(), requirements)
            })
            .collect();
    }
    project
        .recipients
        .as_ref()
        .map(|recipients| CompiledRecipients {
            organizations: recipients.organizations.clone(),
            groups: recipients.groups.clone(),
        })
        .unwrap_or_default()
}

/// The consent checks of one profile over one entity.
pub(crate) fn requirements<'a>(
    entity: &'a CompiledEntity,
    profile: &str,
) -> &'a [CompiledConsentRequirement] {
    entity
        .consent_requirements
        .get(profile)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

/// Action-phase rules for one action: every action creating consent rows
/// declares its issuer, and a self issuer binds the subject through the
/// caller's own principal link.
pub(crate) fn validate_action(
    action: &ActionSource,
    entities: &BTreeMap<String, CompiledEntity>,
    profiles: &[ProjectAccessProfileSource],
    errors: &mut Vec<Diagnostic>,
) {
    let is_record = |entity: Option<&String>| {
        entity
            .and_then(|id| entities.get(id))
            .is_some_and(|entity| entity.consent_record.is_some())
    };
    let creates = action
        .effects
        .iter()
        .filter(|effect| effect.operation == Operation::Create)
        .filter(|effect| is_record(effect.target.entity.as_ref()))
        .collect::<Vec<_>>();
    let handler_creates = action.handler.as_ref().is_some_and(|handler| {
        handler.writes.iter().any(|write| {
            write.operation == Operation::Create && is_record(write.target.entity.as_ref())
        })
    });
    let Some(issuer) = action.consent_issuer else {
        if !creates.is_empty() || handler_creates {
            errors.push(Diagnostic::error(
                "consent.issuer.declared",
                "actions[].consentIssuer",
                "an action creating consent rows declares consentIssuer: self or steward",
            ));
        }
        return;
    };
    if creates.is_empty() && !handler_creates {
        errors.push(Diagnostic::error(
            "consent.issuer.declared",
            "actions[].consentIssuer",
            "consentIssuer is declared only on actions that create consent rows",
        ));
        return;
    }
    if issuer == ConsentIssuerSource::Steward {
        return;
    }
    let bound = action.handler.is_none()
        && creates.iter().all(|effect| {
            let record = entities[effect.target.entity.as_ref().expect("record target")]
                .consent_record
                .as_ref()
                .expect("consent record");
            let subject_field = entities[effect.target.entity.as_ref().expect("record target")]
                .fields
                .iter()
                .find(|(_, field)| field.physical_name == record.subject_column)
                .map(|(id, _)| id.clone());
            let Some(subject_input) = subject_field
                .and_then(|field| effect.set.get(&field))
                .filter(|value| value.from_effect.is_none())
                .and_then(|value| value.from_field.as_deref())
            else {
                return false;
            };
            subject_bound_through_link(action, subject_input, entities, profiles)
        });
    if !bound {
        errors.push(Diagnostic::error(
            "consent.issuer.self_binding",
            "actions[].consentIssuer",
            "a self issuer uses fixed effects, sets the subject from an input S, requires {input: L, field: <link subject>, equalsInput: S} and {input: L, field: <link active>, equals: true}, and every permission bounds L's target to the caller's principal",
        ));
    }
}

/// Whether `subject_input` is tied by `requires` to a link input whose target
/// every permission of the action binds to the verified principal.
fn subject_bound_through_link(
    action: &ActionSource,
    subject_input: &str,
    entities: &BTreeMap<String, CompiledEntity>,
    profiles: &[ProjectAccessProfileSource],
) -> bool {
    action.requires.iter().any(|subject_requirement| {
        if subject_requirement.equals_input.as_deref() != Some(subject_input) {
            return false;
        }
        let link_input = subject_requirement.input.as_str();
        let Some(link) = action
            .inputs
            .iter()
            .find(|input| input.id == link_input)
            .and_then(|input| match &input.field_type {
                FieldTypeSource::Reference { target, .. } => entities.get(target),
                _ => None,
            })
        else {
            return false;
        };
        let reference_field = link
            .fields
            .get(&subject_requirement.field)
            .is_some_and(|field| {
                matches!(field.field_type, FieldTypeSource::Reference { .. })
                    && field.encryption.is_none()
            });
        let active = action.requires.iter().any(|requirement| {
            requirement.input == link_input
                && requirement.equals == Some(serde_json::Value::Bool(true))
                && link
                    .fields
                    .get(&requirement.field)
                    .is_some_and(|field| matches!(field.field_type, FieldTypeSource::Boolean))
        });
        let permissions = profiles
            .iter()
            .flat_map(|profile| {
                profile
                    .permissions
                    .iter()
                    .filter(|grant| grant.action.as_deref() == Some(action.id.as_str()))
                    .map(move |grant| (profile, grant))
            })
            .collect::<Vec<_>>();
        let principal_bound = !permissions.is_empty()
            && permissions.iter().all(|(profile, grant)| {
                let Some(claim) = profile.principal_claim.as_deref() else {
                    return false;
                };
                grant
                    .targets
                    .iter()
                    .filter(|target| target.entity == link.id)
                    .any(|target| {
                        target.row_boundaries.iter().any(|boundary| {
                            boundary.claim == claim
                                && boundary.operator == BoundaryOperator::Equals
                                && link.fields.get(&boundary.field).is_some_and(|field| {
                                    principal_field(field.field_type.clone())
                                        && field.encryption.is_none()
                                })
                        })
                    })
            });
        reference_field && active && principal_bound
    })
}

fn principal_field(field_type: FieldTypeSource) -> bool {
    matches!(
        field_type,
        FieldTypeSource::String { .. } | FieldTypeSource::Text { .. }
    )
}

/// Action-permission rules: a gated profile is read-only, so it holds no
/// consent check on an action and no action reaching a gated entity.
pub(crate) fn validate_action_permission(
    profile: &ProjectAccessProfileSource,
    grant: &crate::contract::AccessPermissionSource,
    entities: &BTreeMap<String, CompiledEntity>,
    errors: &mut Vec<Diagnostic>,
) {
    if !grant.require_consent.is_empty()
        || grant.targets.iter().any(|target| {
            entities
                .get(&target.entity)
                .is_some_and(|entity| !requirements(entity, &profile.id).is_empty())
        })
    {
        errors.push(Diagnostic::error(
            "consent.require.read_only",
            "project.accessProfiles[].permissions[].action",
            "a consent-checked profile is read-only: it cannot carry requireConsent on an action or invoke an action targeting its gated entity",
        ));
    }
    if grant.targets.iter().any(|target| {
        target
            .row_boundaries
            .iter()
            .any(|boundary| is_reserved_claim(&boundary.claim))
    }) {
        refuse_claim(
            "project.accessProfiles[].permissions[].targets[].rowBoundaries",
            errors,
        );
    }
}

/// Parse a positive ISO 8601 duration of at most ten years:
/// `P[nY][nM][nW][nD][T[nH][nM][nS]]` with integer components.
pub(crate) fn parse_duration(text: &str) -> Option<CompiledConsentDuration> {
    let rest = text.strip_prefix('P')?;
    let (date, time) = match rest.split_once('T') {
        Some((date, time)) if !time.is_empty() => (date, Some(time)),
        Some(_) => return None,
        None => (rest, None),
    };
    let date = components(date, &['Y', 'M', 'W', 'D'])?;
    let time = match time {
        Some(time) => components(time, &['H', 'M', 'S'])?,
        None => vec![None; 3],
    };
    if date.iter().chain(&time).all(Option::is_none) {
        return None;
    }
    let value = |part: &Option<u32>| part.unwrap_or(0);
    let duration = CompiledConsentDuration {
        iso: text.to_owned(),
        years: value(&date[0]),
        months: value(&date[1]),
        weeks: value(&date[2]),
        days: value(&date[3]),
        hours: value(&time[0]),
        minutes: value(&time[1]),
        seconds: value(&time[2]),
    };
    let seconds = [
        (duration.years, SECONDS_PER_YEAR),
        (duration.months, SECONDS_PER_MONTH),
        (duration.weeks, 604_800),
        (duration.days, 86_400),
        (duration.hours, 3_600),
        (duration.minutes, 60),
        (duration.seconds, 1),
    ]
    .into_iter()
    .try_fold(0u64, |total, (count, unit)| {
        total.checked_add(u64::from(count).checked_mul(unit)?)
    })?;
    (seconds > 0 && seconds <= MAX_DURATION_SECONDS).then_some(duration)
}

/// Split `1Y2D` into one optional integer per unit, units in order and at
/// most once each.
fn components(text: &str, units: &[char]) -> Option<Vec<Option<u32>>> {
    let mut values = vec![None; units.len()];
    let mut next = 0;
    let mut digits = String::new();
    for character in text.chars() {
        if character.is_ascii_digit() {
            digits.push(character);
            continue;
        }
        let position = units[next..].iter().position(|unit| *unit == character)? + next;
        if digits.is_empty() {
            return None;
        }
        values[position] = Some(digits.parse().ok()?);
        digits.clear();
        next = position + 1;
    }
    digits.is_empty().then_some(values)
}

fn valid_identifier(value: &str) -> bool {
    value.len() <= 64
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{parse_duration, validate};
    use crate::contract::{parse_project_yaml, EntitySource};

    /// The grammar refuses `encrypted` on reference, vocabulary-code and
    /// timestamp fields, so these rules are reached only by a source that
    /// bypassed it. They must still refuse.
    fn codes_with_encrypted(entity: &str, field: &str) -> Vec<String> {
        let project = parse_project_yaml(include_bytes!("../tests/fixtures/consent-access.yaml"))
            .expect("consent fixture parses");
        let mut entities = project
            .entities
            .iter()
            .cloned()
            .map(|entity| (entity.id.clone(), entity))
            .collect::<BTreeMap<String, EntitySource>>();
        entities
            .get_mut(entity)
            .expect("entity")
            .fields
            .iter_mut()
            .find(|candidate| candidate.id == field)
            .expect("field")
            .encrypted = true;
        let mut errors = Vec::new();
        crate::compiler::expand_project_access(&project, &mut entities, &mut errors);
        assert!(errors.is_empty(), "{errors:?}");
        validate(&project, &entities, &mut errors);
        errors.into_iter().map(|error| error.code).collect()
    }

    #[test]
    fn encrypted_consent_fields_are_refused_even_past_the_grammar() {
        for field in [
            "subject",
            "recipient",
            "purpose",
            "scope",
            "decision",
            "effective-at",
            "expires-at",
        ] {
            assert!(
                codes_with_encrypted("consent-decision", field)
                    .contains(&"consent.record.plaintext".to_owned()),
                "{field}"
            );
        }
        assert!(
            codes_with_encrypted("enrolment", "person").contains(&"consent.require.key".to_owned())
        );
        let unrelated = codes_with_encrypted("enrolment", "programme");
        assert!(!unrelated.contains(&"consent.require.key".to_owned()));
        assert!(!unrelated.contains(&"consent.record.plaintext".to_owned()));
    }

    #[test]
    fn durations_parse_integer_components_in_order() {
        let parsed = parse_duration("P1Y2M3W4DT5H6M7S").expect("full duration");
        assert_eq!(
            (
                parsed.years,
                parsed.months,
                parsed.weeks,
                parsed.days,
                parsed.hours,
                parsed.minutes,
                parsed.seconds
            ),
            (1, 2, 3, 4, 5, 6, 7)
        );
        assert!(parse_duration("PT90M").is_some());
        for invalid in ["P1D2Y", "P1DD", "PD", "P1.5D", "P1DT", "P+1D", "p1d", "P1d"] {
            assert!(parse_duration(invalid).is_none(), "{invalid}");
        }
    }
}
