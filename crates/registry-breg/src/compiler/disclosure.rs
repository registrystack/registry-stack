// SPDX-License-Identifier: Apache-2.0

//! Compile-time rules for disclosure conditions and the read-trigger hook.

use std::collections::{BTreeMap, BTreeSet};

use crate::contract::{
    DisclosureConditionSource, DisclosureWhenPredicate, DisclosureWithholdSource, EntitySource,
    EventTrigger, FieldTypeSource, Operation, ProjectAccessProfileSource, UniqueSet,
};
use crate::diagnostics::Diagnostic;
use crate::model::{CompiledDisclosureCondition, CompiledEntity, DisclosureWithhold};

use super::canonical_field_literal;

mod reach;

pub(super) use reach::{validate_derived_reads, validate_external_views, validate_timer_creates};

/// The most conditions one record type declares.
const MAX_CONDITIONS: usize = 8;
/// The most predicates one condition ANDs.
const MAX_PREDICATES: usize = 4;
/// The most literals a `field-in` predicate lists.
const MAX_IN_VALUES: usize = 32;

/// The compiled form of an entity's conditions, in authored order. A condition
/// that fails validation is still compiled, because the compile result is
/// discarded whenever a diagnostic is raised.
pub(super) fn compile_conditions(source: &EntitySource) -> Vec<CompiledDisclosureCondition> {
    source
        .disclosure_conditions
        .iter()
        .map(|condition| CompiledDisclosureCondition {
            id: condition.id.clone(),
            when: condition.when.clone(),
            withhold: match condition.withhold {
                DisclosureWithholdSource::Record => DisclosureWithhold::Record,
                DisclosureWithholdSource::History => DisclosureWithhold::History,
                DisclosureWithholdSource::Fields => {
                    DisclosureWithhold::Fields(condition.fields.iter().cloned().collect())
                }
            },
            exempt_profiles: condition.exempt_profiles.iter().cloned().collect(),
        })
        .collect()
}

/// Why a profile that requires an access reason cannot hold a grant.
const ACCESS_REASON_UNSUPPORTED: &str = "a profile that requires an access reason cannot hold this permission, because its route does not check the Registry-Access-Reason header";
const ACCESS_REASON_CODE: &str = "breg.access-profile.access-reason-operation-unsupported";

/// Whether any operation is one whose route does not check the header.
fn holds_unchecked_operation(operations: &UniqueSet<Operation>) -> bool {
    operations.iter().any(|operation| {
        matches!(
            operation,
            Operation::Import | Operation::Invoke | Operation::Start
        )
    })
}

/// The same refusal for profiles a module contributes to a record type, which
/// carry their grant directly. Runs before project profiles expand onto the
/// entities, so every profile it sees is a module's. Bulk export is refused
/// too: its client sends no reason, so the list route would refuse every page.
pub(super) fn validate_module_access_reason_operations(
    entities: &BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    for entity in entities.values() {
        for profile in entity
            .access_profiles
            .iter()
            .filter(|profile| profile.require_access_reason)
        {
            let root = format!(
                "recordTypes[id={}].accessProfiles[id={}]",
                entity.id, profile.id
            );
            if holds_unchecked_operation(&profile.operations) {
                errors.push(Diagnostic::error(
                    ACCESS_REASON_CODE,
                    format!("{root}.operations"),
                    ACCESS_REASON_UNSUPPORTED,
                ));
            }
            if profile.allow_data_export {
                errors.push(Diagnostic::error(
                    ACCESS_REASON_CODE,
                    format!("{root}.allowDataExport"),
                    ACCESS_REASON_UNSUPPORTED,
                ));
            }
        }
    }
}

/// Refuse a profile that requires an access reason yet holds a permission whose
/// route does not check the header. The reason is enforced on record reads and
/// direct writes only, so every other grant would admit a request with no reason
/// on record.
pub(super) fn validate_access_reason_operations(
    profile: &ProjectAccessProfileSource,
    errors: &mut Vec<Diagnostic>,
) {
    if !profile.require_access_reason {
        return;
    }
    let root = format!("project.accessProfiles[id={}].permissions", profile.id);
    let mut refuse = |path: String| {
        errors.push(Diagnostic::error(
            ACCESS_REASON_CODE,
            path,
            ACCESS_REASON_UNSUPPORTED,
        ));
    };
    let permissions = &profile.permissions;
    for grant in &permissions.entities {
        if holds_unchecked_operation(&grant.operations) {
            refuse(format!(
                "{root}.records[recordType={}].operations",
                grant.entity
            ));
        }
        if grant.allow_data_export {
            refuse(format!(
                "{root}.records[recordType={}].allowDataExport",
                grant.entity
            ));
        }
    }
    for (name, present) in [
        ("actions", !permissions.actions.is_empty()),
        ("proposals", !permissions.proposals.is_empty()),
        ("datasets", !permissions.datasets.is_empty()),
        ("externalViews", !permissions.external_views.is_empty()),
        (
            "refreshExternalProjections",
            !permissions.refresh_external_projections.is_empty(),
        ),
    ] {
        if present {
            refuse(format!("{root}.{name}"));
        }
    }
}

/// Validate one entity's disclosure conditions and read hooks against the
/// access profiles every entity declares.
pub(super) fn validate(
    entity: &EntitySource,
    entities: &BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    let known_profiles: BTreeSet<&str> = entities
        .values()
        .flat_map(|entity| entity.access_profiles.iter())
        .map(|profile| profile.id.as_str())
        .collect();
    validate_read_hooks(entity, &known_profiles, errors);
    if entity.disclosure_conditions.len() > MAX_CONDITIONS {
        errors.push(Diagnostic::error(
            "breg.disclosure.too-many",
            "recordTypes[].disclosureConditions",
            &format!("a record type declares at most {MAX_CONDITIONS} disclosure conditions"),
        ));
    }
    let mut ids = BTreeSet::new();
    for condition in &entity.disclosure_conditions {
        let root = format!("recordTypes[].disclosureConditions[id={}]", condition.id);
        if !ids.insert(condition.id.as_str()) {
            errors.push(Diagnostic::error(
                "breg.disclosure.id-duplicate",
                format!("recordTypes[].disclosureConditions[id={}].id", condition.id),
                "a disclosure condition identifier is duplicated within its record type",
            ));
        }
        validate_when(entity, condition, &root, errors);
        validate_fields(entity, condition, &root, errors);
        validate_exempt_profiles(condition, &known_profiles, &root, errors);
        validate_exposure(entity, condition, &root, errors);
        reach::validate_withholdable(entity, condition, &root, errors);
        reach::validate_spatial_queries(entity, condition, &root, errors);
        reach::validate_boundaries(entity, condition, &root, errors);
        reach::validate_read_paths(entity, condition, entities, &root, errors);
        reach::validate_timers(entity, condition, &root, errors);
    }
}

fn validate_when(
    entity: &EntitySource,
    condition: &DisclosureConditionSource,
    root: &str,
    errors: &mut Vec<Diagnostic>,
) {
    if condition.when.is_empty() || condition.when.len() > MAX_PREDICATES {
        errors.push(Diagnostic::error(
            "breg.disclosure.when-value-invalid",
            format!("{root}.when"),
            &format!("a disclosure condition tests one to {MAX_PREDICATES} predicates"),
        ));
    }
    for (index, predicate) in condition.when.iter().enumerate() {
        let path = format!("{root}.when[{index}]");
        let field = match predicate {
            DisclosureWhenPredicate::FieldEquals { field, .. }
            | DisclosureWhenPredicate::FieldIn { field, .. }
            | DisclosureWhenPredicate::FieldIsNull { field }
            | DisclosureWhenPredicate::FieldIsNotNull { field } => field,
        };
        let Some(source) = entity.fields.iter().find(|source| source.id == *field) else {
            errors.push(Diagnostic::error(
                "breg.disclosure.when-field-invalid",
                format!("{path}.field"),
                "a disclosure predicate names a stored field of its record type",
            ));
            continue;
        };
        if source.encrypted
            || !matches!(
                source.field_type,
                FieldTypeSource::Boolean
                    | FieldTypeSource::String { .. }
                    | FieldTypeSource::Text { .. }
                    | FieldTypeSource::VocabularyCode { .. }
                    | FieldTypeSource::Int64
                    | FieldTypeSource::Date
                    | FieldTypeSource::Uuid
            )
        {
            errors.push(Diagnostic::error(
                "breg.disclosure.when-field-invalid",
                format!("{path}.field"),
                "a disclosure predicate tests an unencrypted boolean, string, text, vocabulary-code, int64, date or uuid field",
            ));
            continue;
        }
        let literals: &[serde_json::Value] = match predicate {
            DisclosureWhenPredicate::FieldEquals { value, .. } => std::slice::from_ref(value),
            DisclosureWhenPredicate::FieldIn { values, .. } => {
                if values.is_empty() || values.len() > MAX_IN_VALUES {
                    errors.push(Diagnostic::error(
                        "breg.disclosure.when-value-invalid",
                        format!("{path}.values"),
                        &format!("a field-in predicate lists one to {MAX_IN_VALUES} values"),
                    ));
                }
                values
            }
            DisclosureWhenPredicate::FieldIsNull { .. }
            | DisclosureWhenPredicate::FieldIsNotNull { .. } => &[],
        };
        for literal in literals {
            if canonical_field_literal(literal, &source.field_type).is_none() {
                errors.push(Diagnostic::error(
                    "breg.disclosure.when-value-invalid",
                    path.clone(),
                    "a disclosure literal must be non-null and canonical for the field type",
                ));
            }
        }
    }
}

fn validate_fields(
    entity: &EntitySource,
    condition: &DisclosureConditionSource,
    root: &str,
    errors: &mut Vec<Diagnostic>,
) {
    let path = format!("{root}.fields");
    if condition.withhold != DisclosureWithholdSource::Fields {
        if !condition.fields.is_empty() {
            errors.push(Diagnostic::error(
                "breg.disclosure.fields-invalid",
                path,
                "only a condition that withholds fields names fields",
            ));
        }
        return;
    }
    if condition.fields.is_empty() {
        errors.push(Diagnostic::error(
            "breg.disclosure.fields-invalid",
            path,
            "a condition that withholds fields names at least one field",
        ));
        return;
    }
    let mut seen = BTreeSet::new();
    for field in &condition.fields {
        let stored = entity.fields.iter().any(|source| source.id == *field);
        if !stored || !seen.insert(field.as_str()) {
            errors.push(Diagnostic::error(
                "breg.disclosure.fields-invalid",
                format!("{path}[field={field}]"),
                "a withheld field is a stored field of its record type and is named once",
            ));
        }
    }
}

fn validate_exempt_profiles(
    condition: &DisclosureConditionSource,
    known_profiles: &BTreeSet<&str>,
    root: &str,
    errors: &mut Vec<Diagnostic>,
) {
    let path = format!("{root}.exemptProfiles");
    if condition.exempt_profiles.is_empty() {
        errors.push(Diagnostic::error(
            "breg.disclosure.exempt-profiles-invalid",
            path,
            "name at least one exempt access profile, so someone can still reach the record",
        ));
        return;
    }
    for profile in condition.exempt_profiles.iter() {
        if !known_profiles.contains(profile.as_str()) {
            errors.push(Diagnostic::error(
                "breg.disclosure.exempt-profiles-invalid",
                format!("{path}[profile={profile}]"),
                "an exempt profile is an access profile some record type declares",
            ));
        }
    }
}

/// A condition that withholds fields is bypassed by any surface that lets a
/// profile it does not exempt filter, sort, look up or export the field, so
/// those surfaces are refused for that profile. A hook event leaves the
/// Registry with no profile, so no hook projects a withheld field, and a
/// record type that withholds records projects nothing at all.
fn validate_exposure(
    entity: &EntitySource,
    condition: &DisclosureConditionSource,
    root: &str,
    errors: &mut Vec<Diagnostic>,
) {
    let mut refuse = |surface: &str, profile: &str, field: &str| {
        errors.push(Diagnostic::error(
            "breg.disclosure.withheld-field-exposed",
            format!("{root}.fields[field={field}]"),
            &format!(
                "access profile `{profile}` is not exempt but reaches withheld field `{field}` through {surface}: remove the field from it, or exempt the profile"
            ),
        ));
    };
    if condition.withhold == DisclosureWithholdSource::Fields {
        for profile in entity
            .access_profiles
            .iter()
            .filter(|profile| !condition.exempt_profiles.contains(&profile.id))
        {
            for field in &condition.fields {
                if profile.filterable_fields.contains(field) {
                    refuse("filterableFields", &profile.id, field);
                }
                if profile.sortable_fields.contains(field) {
                    refuse("sortableFields", &profile.id, field);
                }
                if profile.allow_data_export && profile.readable_fields.contains(field) {
                    refuse("allowDataExport", &profile.id, field);
                }
                for lookup in &profile.lookups {
                    let selects = entity.selector_profiles.iter().any(|selector| {
                        selector.id == lookup.selector && selector.fields.contains(field)
                    });
                    if selects {
                        refuse("a lookup selector", &profile.id, field);
                    }
                }
            }
        }
    }
    for hook in entity
        .hooks
        .iter()
        .filter(|hook| hook.trigger != EventTrigger::Read)
    {
        match condition.withhold {
            DisclosureWithholdSource::Fields => {
                for field in condition
                    .fields
                    .iter()
                    .filter(|f| hook.projection.contains(*f))
                {
                    errors.push(Diagnostic::error(
                        "breg.disclosure.withheld-field-exposed",
                        format!("{root}.fields[field={field}]"),
                        &format!(
                            "hook `{}` projects withheld field `{field}` to destinations that hold no access profile: remove it from the projection",
                            hook.id
                        ),
                    ));
                }
            }
            DisclosureWithholdSource::Record | DisclosureWithholdSource::History => {
                if !hook.projection.is_empty() {
                    errors.push(Diagnostic::error(
                        "breg.disclosure.withheld-field-exposed",
                        root.to_owned(),
                        &format!(
                            "hook `{}` projects record values to destinations that hold no access profile, which a withheld record must not reach: remove the hook or its projection",
                            hook.id
                        ),
                    ));
                }
            }
        }
    }
}

fn validate_read_hooks(
    entity: &EntitySource,
    known_profiles: &BTreeSet<&str>,
    errors: &mut Vec<Diagnostic>,
) {
    for hook in &entity.hooks {
        let path = format!("recordTypes[].hooks[id={}]", hook.id);
        if hook.trigger != EventTrigger::Read {
            if !hook.profiles.is_empty() {
                errors.push(Diagnostic::error(
                    "breg.hook.read-trigger-invalid",
                    format!("{path}.profiles"),
                    "profiles belong to the read trigger only",
                ));
            }
            continue;
        }
        if hook.profiles.is_empty() {
            errors.push(Diagnostic::error(
                "breg.hook.read-trigger-invalid",
                format!("{path}.profiles"),
                "a read hook names at least one access profile",
            ));
        }
        for profile in hook.profiles.iter() {
            if !known_profiles.contains(profile.as_str()) {
                errors.push(Diagnostic::error(
                    "breg.hook.read-trigger-invalid",
                    format!("{path}.profiles[profile={profile}]"),
                    "a read hook names an access profile some record type declares",
                ));
            }
        }
        if !hook.projection.is_empty() {
            errors.push(Diagnostic::error(
                "breg.hook.read-trigger-invalid",
                format!("{path}.projection"),
                "a read event carries no record values: declare projection: []",
            ));
        }
        // The read event is written with the subject access log entry, so
        // without accessLog the alert would never fire.
        if entity.access_log.is_none() {
            errors.push(Diagnostic::error(
                "breg.disclosure.read-hook-access-log-required",
                format!("{path}.trigger"),
                "a read hook raises its event with the subject access log entry, so its record type declares accessLog",
            ));
        }
    }
}

/// What one statistical dataset reads and who may read it.
pub(super) struct DatasetReach<'a> {
    pub dataset_id: &'a str,
    pub entities: &'a BTreeMap<String, CompiledEntity>,
    pub dependency_entities: &'a BTreeSet<String>,
    /// The derived relations of the unit the dataset's fields read.
    pub used_relations: &'a BTreeSet<String>,
    pub unit: &'a CompiledEntity,
    pub referenced_fields: &'a BTreeSet<String>,
    pub publisher: Option<&'a str>,
    /// Every profile that reads the dataset live or exactly, from current records.
    pub live_readers: &'a BTreeSet<String>,
    /// Every profile that reads the dataset live, exactly or as releases.
    pub readers: &'a BTreeSet<String>,
    pub root: &'a str,
}

/// A release must include every subject, so the profile that publishes a
/// dataset is never bound by a `record` condition on a dependency type, and
/// no dataset releases a field a condition withholds from a profile that reads
/// the dataset.
pub(super) fn validate_dataset(reach: &DatasetReach<'_>, errors: &mut Vec<Diagnostic>) {
    let DatasetReach {
        dataset_id,
        entities,
        dependency_entities,
        used_relations: _,
        unit,
        referenced_fields,
        publisher,
        live_readers: _,
        readers,
        root,
    } = *reach;
    if let Some(publisher) = publisher {
        for entity_id in dependency_entities {
            let bound = entities[entity_id]
                .disclosure_conditions
                .iter()
                .any(|condition| {
                    condition.withhold == DisclosureWithhold::Record
                        && !condition.exempt_profiles.contains(publisher)
                });
            if bound {
                errors.push(Diagnostic::error(
                    "breg.disclosure.statistics-publisher-bound",
                    format!("{root}.releases"),
                    &format!(
                        "statistical dataset `{dataset_id}` is published by `{publisher}`, which a record condition on `{entity_id}` withholds records from: exempt the publisher, or release from a profile every record reaches"
                    ),
                ));
            }
        }
    }
    for condition in &unit.disclosure_conditions {
        let DisclosureWithhold::Fields(withheld) = &condition.withhold else {
            continue;
        };
        let reached = publisher
            .into_iter()
            .map(str::to_owned)
            .chain(readers.iter().cloned())
            .find(|profile| !condition.exempt_profiles.contains(profile));
        for field in withheld.intersection(referenced_fields) {
            if let Some(profile) = &reached {
                errors.push(Diagnostic::error(
                    "breg.disclosure.withheld-field-exposed",
                    format!("{root}.dimensions"),
                    &format!(
                        "statistical dataset `{dataset_id}` reads withheld field `{field}` of `{}` for access profile `{profile}`, which the condition does not exempt: remove the field from the dataset, or exempt the profile",
                        unit.id
                    ),
                ));
            }
        }
    }
    reach::validate_dataset_reads(reach, errors);
}
