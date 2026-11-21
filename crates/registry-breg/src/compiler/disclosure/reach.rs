// SPDX-License-Identifier: Apache-2.0

//! Surfaces that read a field a `fields` condition withholds. Each function
//! refuses one surface for the profiles the condition does not exempt, so a
//! withheld field cannot be recovered through geometry queries, boundaries,
//! read paths, Record timers, derived fields, external views or statistics.
//! A Record timer is also refused a created record that carries a record a
//! `record` condition hides.

use std::collections::{BTreeMap, BTreeSet};

use crate::contract::{
    AccessProfileSource, DerivedSource, DisclosureConditionSource, DisclosureWithholdSource,
    EntitySource, Operation, TimerPredicateSource,
};
use crate::diagnostics::Diagnostic;
use crate::external_views::CompiledExternalViews;
use crate::model::{CompiledEntity, DisclosureWithhold};

use super::DatasetReach;

/// The profiles a condition binds on one entity: those it does not exempt.
fn bound<'a>(
    entity: &'a EntitySource,
    condition: &'a DisclosureConditionSource,
) -> impl Iterator<Item = &'a AccessProfileSource> {
    entity
        .access_profiles
        .iter()
        .filter(|profile| !condition.exempt_profiles.contains(&profile.id))
}

fn withheld(condition: &DisclosureConditionSource) -> &BTreeSet<String> {
    static NONE: BTreeSet<String> = BTreeSet::new();
    if condition.withhold == DisclosureWithholdSource::Fields {
        condition.fields.as_set()
    } else {
        &NONE
    }
}

pub(super) fn refuse(
    errors: &mut Vec<Diagnostic>,
    code: &str,
    root: &str,
    field: &str,
    profile: &str,
    surface: &str,
) {
    errors.push(Diagnostic::error(
        code,
        format!("{root}.fields[field={field}]"),
        &format!(
            "access profile `{profile}` is not exempt but {surface} withheld field `{field}`: remove the surface from the profile, or exempt the profile"
        ),
    ));
}

/// A geometry field a condition withholds cannot be searched by a profile the
/// condition binds, since a bounding box narrows the result to where the
/// subject is.
pub(super) fn validate_spatial_queries(
    entity: &EntitySource,
    condition: &DisclosureConditionSource,
    root: &str,
    errors: &mut Vec<Diagnostic>,
) {
    let Some(geometry) = entity
        .geojson
        .as_ref()
        .map(|geojson| &geojson.geometry_field)
    else {
        return;
    };
    if !withheld(condition).contains(geometry) {
        return;
    }
    for profile in bound(entity, condition).filter(|profile| profile.spatial_queries.is_some()) {
        refuse(
            errors,
            "breg.disclosure.spatial-query-withheld-geometry",
            root,
            geometry,
            &profile.id,
            "runs spatialQueries over",
        );
    }
}

/// A withheld field is never a required field or the canonical identifier,
/// which every record carries and every surface may rely on.
pub(super) fn validate_withholdable(
    entity: &EntitySource,
    condition: &DisclosureConditionSource,
    root: &str,
    errors: &mut Vec<Diagnostic>,
) {
    for field in withheld(condition) {
        let required = entity
            .fields
            .iter()
            .any(|source| source.id == *field && source.required);
        if field == "id" || required {
            errors.push(Diagnostic::error(
                "breg.disclosure.fields-invalid",
                format!("{root}.fields[field={field}]"),
                "a withheld field is optional and is not the canonical identifier `id`: a record always carries those",
            ));
        }
    }
}

/// Row, membership and consent boundaries filter on the value of a field, so
/// a profile the condition binds learns it from which rows come back.
pub(super) fn validate_boundaries(
    entity: &EntitySource,
    condition: &DisclosureConditionSource,
    root: &str,
    errors: &mut Vec<Diagnostic>,
) {
    for profile in bound(entity, condition) {
        for field in withheld(condition) {
            if profile
                .row_boundaries
                .iter()
                .any(|boundary| boundary.field == *field)
            {
                refuse(
                    errors,
                    "breg.disclosure.row-boundary-withheld-field",
                    root,
                    field,
                    &profile.id,
                    "scopes rows by a row boundary on",
                );
            }
            if profile
                .membership_boundaries
                .iter()
                .any(|boundary| boundary.field == *field)
            {
                refuse(
                    errors,
                    "breg.disclosure.membership-boundary-withheld-field",
                    root,
                    field,
                    &profile.id,
                    "scopes rows by a membership boundary on",
                );
            }
            if profile
                .require_consent
                .iter()
                .any(|consent| consent.on == *field)
            {
                refuse(
                    errors,
                    "breg.disclosure.consent-boundary-withheld-field",
                    root,
                    field,
                    &profile.id,
                    "scopes rows by a consent requirement on",
                );
            }
        }
    }
}

/// A Record timer runs under the reserved timer profile, which no condition
/// binds. A timer that fires on a withheld time, holds on a withheld value or
/// maps a withheld value into its Action would carry the value, or the moment
/// it fires, into writes a profile the condition binds can read.
pub(super) fn validate_timers(
    entity: &EntitySource,
    condition: &DisclosureConditionSource,
    root: &str,
    errors: &mut Vec<Diagnostic>,
) {
    let withheld: BTreeSet<&String> = withheld(condition).iter().collect();
    if withheld.is_empty() || bound(entity, condition).next().is_none() {
        return;
    }
    for timer in &entity.timers {
        let predicate = timer.when.iter().flat_map(|when| match when {
            TimerPredicateSource::Fields { equals } => equals.keys(),
        });
        let inputs = timer
            .input
            .values()
            .filter_map(|input| input.from_field.as_ref());
        let read = [
            Some(&timer.at),
            timer.not_after.as_ref(),
            timer.rearm_on.as_ref(),
        ]
        .into_iter()
        .flatten()
        .chain(predicate)
        .chain(inputs)
        .filter(|field| withheld.contains(field))
        .collect::<BTreeSet<_>>();
        for field in read {
            errors.push(Diagnostic::error(
                "breg.disclosure.timer-reads-withheld-field",
                format!("{root}.fields[field={field}]"),
                &format!(
                    "Record timer `{}` reads withheld field `{field}`, and it runs without the condition, so its Action can reveal the value to profiles the condition binds: time and map the timer from fields the condition does not withhold, or exempt every profile",
                    timer.id
                ),
            ));
        }
    }
}

/// A Record timer also fires on a record a `record` condition hides. An
/// Action it invokes that creates a record writes the hidden record's id, and
/// any value the timer maps from it, into the created record, so no profile
/// the condition binds may read the created record type.
pub(in crate::compiler) fn validate_timer_creates(
    entity: &EntitySource,
    timer: &str,
    created: &BTreeSet<&str>,
    entities: &BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    for condition in entity
        .disclosure_conditions
        .iter()
        .filter(|condition| condition.withhold == DisclosureWithholdSource::Record)
    {
        for profile in bound(entity, condition) {
            for record_type in created {
                let reads = entities.get(*record_type).is_some_and(|created| {
                    created.access_profiles.iter().any(|reader| {
                        reader.id == profile.id
                            && (reader.allow_data_export
                                || reader.operations.iter().any(|operation| {
                                    matches!(
                                        operation,
                                        Operation::Get
                                            | Operation::Lookup
                                            | Operation::List
                                            | Operation::Revisions
                                            | Operation::Snapshot
                                    )
                                }))
                    })
                });
                if reads {
                    errors.push(Diagnostic::error(
                        "breg.disclosure.timer-creates-readable-record",
                        format!(
                            "recordTypes[id={}].disclosureConditions[id={}]",
                            entity.id, condition.id
                        ),
                        &format!(
                            "Record timer `{timer}` creates a `{record_type}` record that access profile `{}` reads, and the timer runs without the condition, so the created record would reveal a record the condition hides from that profile: have the Action change only its own record, remove the read from the profile, or exempt the profile",
                            profile.id
                        ),
                    ));
                }
            }
        }
    }
}

/// A read path walks the reference fields of its `through` entity, so a
/// profile that reads the path learns which rows the withheld reference joins.
/// The path's grant also filters and sorts its `to` entity before the reader
/// withholds a field, so a bound profile may not filter or sort a field
/// withheld there either.
pub(super) fn validate_read_paths(
    entity: &EntitySource,
    condition: &DisclosureConditionSource,
    entities: &BTreeMap<String, EntitySource>,
    root: &str,
    errors: &mut Vec<Diagnostic>,
) {
    let withheld: BTreeSet<&String> = withheld(condition).iter().collect();
    if withheld.is_empty() {
        return;
    }
    for owner in entities.values() {
        for path in owner
            .read_paths
            .iter()
            .filter(|path| path.through == entity.id)
        {
            let Some((source_ref, target_ref)) =
                super::super::infer_read_path_refs(owner, entity, &path.to)
            else {
                continue;
            };
            for field in [source_ref, target_ref]
                .iter()
                .filter(|field| withheld.contains(field))
            {
                for profile in owner.access_profiles.iter().filter(|profile| {
                    !condition.exempt_profiles.contains(&profile.id)
                        && profile.read_paths.iter().any(|grant| grant.path == path.id)
                }) {
                    refuse(
                        errors,
                        "breg.disclosure.read-path-withheld-field",
                        root,
                        field,
                        &profile.id,
                        &format!("reads path `{}` through", path.id),
                    );
                }
            }
        }
        for path in owner.read_paths.iter().filter(|path| path.to == entity.id) {
            for (profile, grant) in owner
                .access_profiles
                .iter()
                .filter(|profile| !condition.exempt_profiles.contains(&profile.id))
                .flat_map(|profile| {
                    profile
                        .read_paths
                        .iter()
                        .filter(|grant| grant.path == path.id)
                        .map(move |grant| (profile, grant))
                })
            {
                for (surface, granted) in [
                    ("filters", &grant.filterable_fields),
                    ("sorts", &grant.sortable_fields),
                ] {
                    for field in granted.iter().filter(|field| withheld.contains(field)) {
                        refuse(
                            errors,
                            "breg.disclosure.read-path-withheld-field",
                            root,
                            field,
                            &profile.id,
                            &format!("{surface} path `{}` by", path.id),
                        );
                    }
                }
            }
        }
    }
}

/// A derived field is computed from source columns, so a profile that reads,
/// filters or sorts it learns whatever a withheld source field says. The SQL
/// must already have passed validation.
pub(in crate::compiler) fn validate_derived_reads(
    owner: &EntitySource,
    derived: &DerivedSource,
    sql: &[u8],
    source_columns: &BTreeMap<String, BTreeSet<String>>,
    sources: &BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    let read = crate::derived_sql::derived_sql_source_columns(sql, source_columns);
    let derived_ids: BTreeSet<&String> = derived.fields.iter().map(|field| &field.id).collect();
    for source in sources.values() {
        let Some(columns) = read.get(&super::super::canonical_sql_name(&source.id)) else {
            continue;
        };
        for condition in &source.disclosure_conditions {
            let root = format!(
                "recordTypes[id={}].disclosureConditions[id={}]",
                source.id, condition.id
            );
            for field in withheld(condition)
                .iter()
                .filter(|field| columns.contains(&super::super::canonical_sql_name(field)))
            {
                for profile in bound(owner, condition).filter(|profile| {
                    [
                        &profile.readable_fields,
                        &profile.filterable_fields,
                        &profile.sortable_fields,
                    ]
                    .iter()
                    .any(|granted| granted.iter().any(|id| derived_ids.contains(id)))
                }) {
                    refuse(
                        errors,
                        "breg.disclosure.derived-reads-withheld-field",
                        &root,
                        field,
                        &profile.id,
                        &format!(
                            "reads derived relation `{}`, which is computed from",
                            derived.id
                        ),
                    );
                }
            }
        }
    }
}

/// An external view joins from a local field, so a profile that reads the link
/// learns whether a withheld field holds a value, and which one.
pub(in crate::compiler) fn validate_external_views(
    views: &CompiledExternalViews,
    entities: &BTreeMap<String, CompiledEntity>,
    errors: &mut Vec<Diagnostic>,
) {
    for (profile, grants) in &views.grants {
        for (view_id, grant) in grants {
            let Some(view) = views.views.get(view_id) else {
                continue;
            };
            let Some(entity) = entities.get(view.record_type.as_str()) else {
                continue;
            };
            for link in &view.links {
                let granted = grant
                    .links
                    .iter()
                    .any(|permission| permission.link.as_str() == link.id.as_str());
                if !granted {
                    continue;
                }
                for condition in entity.disclosure_conditions.iter().filter(|condition| {
                    !condition.exempt_profiles.contains(profile)
                        && matches!(&condition.withhold,
                            DisclosureWithhold::Fields(fields) if fields.contains(link.from_field.as_str()))
                }) {
                    errors.push(Diagnostic::error(
                        "breg.disclosure.external-view-withheld-field",
                        format!(
                            "recordTypes[id={}].disclosureConditions[id={}].fields[field={}]",
                            entity.id, condition.id, link.from_field
                        ),
                        &format!(
                            "access profile `{profile}` is not exempt but reads link `{}` of view `{view_id}`, which joins from withheld field `{}`: remove the link grant, or exempt the profile",
                            link.id, link.from_field
                        ),
                    ));
                }
            }
        }
    }
}

/// A refresh lists a view's roots under the profile that refreshes it, so a
/// `record` condition that binds that profile leaves the records it matches
/// out of the refresh, and the refresh still succeeds. Keeping protected
/// subjects away from the external source may be intended, so this is a
/// finding, not a refusal. Every refresh worker holds the grant this reads,
/// and a label grant is valid only beside the grant for its link's projection.
pub(in crate::compiler) fn refresh_withheld_root_findings(
    views: &CompiledExternalViews,
    entities: &BTreeMap<String, CompiledEntity>,
) -> Vec<Diagnostic> {
    let mut bound = BTreeSet::new();
    for (profile, projections) in &views.refresh {
        for (view_id, view) in &views.views {
            let Some(entity) = entities.get(view.record_type.as_str()) else {
                continue;
            };
            let lists = entity
                .access_profiles
                .get(profile)
                .is_some_and(|grant| grant.operations.contains(&Operation::List));
            if !lists
                || !view
                    .links
                    .iter()
                    .any(|link| projections.contains(&link.projection))
            {
                continue;
            }
            for condition in entity.disclosure_conditions.iter().filter(|condition| {
                condition.withhold == DisclosureWithhold::Record
                    && !condition.exempt_profiles.contains(profile)
            }) {
                bound.insert((&entity.id, &condition.id, profile, view_id));
            }
        }
    }
    bound
        .into_iter()
        .map(|(entity, condition, profile, view)| {
            Diagnostic::finding(
                "breg.disclosure.external-refresh-withheld-root",
                format!("recordTypes[id={entity}].disclosureConditions[id={condition}]"),
                &format!(
                    "access profile `{profile}` refreshes view `{view}` but this `record` condition binds it, so a refresh leaves out the records the condition matches and still succeeds"
                ),
            )
        })
        .collect()
}

/// A statistical dataset reads what its unit and its derived relations read.
/// A profile that reads it live sees current records, so it is refused where a
/// `record` condition could withhold them, and every profile that reaches the
/// dataset is refused a withheld field a derived relation reads from a
/// dependency entity.
pub(super) fn validate_dataset_reads(reach: &DatasetReach<'_>, errors: &mut Vec<Diagnostic>) {
    let entities = reach.entities;
    for entity_id in reach.dependency_entities {
        for condition in &entities[entity_id].disclosure_conditions {
            if condition.withhold != DisclosureWithhold::Record {
                continue;
            }
            for profile in reach
                .live_readers
                .iter()
                .filter(|profile| !condition.exempt_profiles.contains(*profile))
            {
                errors.push(Diagnostic::error(
                    "breg.disclosure.statistics-live-bound",
                    format!("{}.grants", reach.root),
                    &format!(
                        "access profile `{profile}` reads statistical dataset `{}` live, but record condition `{}` on `{entity_id}` withholds records from it: exempt the profile, or grant read-releases instead",
                        reach.dataset_id, condition.id
                    ),
                ));
            }
        }
    }
    let source_columns: BTreeMap<String, BTreeSet<String>> = entities
        .values()
        .map(|entity| {
            let columns = std::iter::once(entity.canonical_id.sql_name.clone())
                .chain(
                    entity
                        .stored_fields
                        .iter()
                        .filter(|field| {
                            entity
                                .source_relation
                                .stored_fields
                                .contains(&field.logical.id)
                        })
                        .map(|field| field.logical.sql_name.clone()),
                )
                .collect();
            (entity.source_relation.sql_name.clone(), columns)
        })
        .collect();
    let reached: BTreeSet<&str> = reach
        .publisher
        .into_iter()
        .chain(reach.readers.iter().map(String::as_str))
        .collect();
    for relation_id in reach.used_relations {
        let relation = &reach.unit.derived_relations[relation_id];
        let read =
            crate::derived_sql::derived_sql_source_columns(&relation.sql_bytes, &source_columns);
        for (relation_name, columns) in read {
            let Some(entity) = entities
                .values()
                .find(|entity| entity.source_relation.sql_name == relation_name)
            else {
                continue;
            };
            for condition in &entity.disclosure_conditions {
                let DisclosureWithhold::Fields(fields) = &condition.withhold else {
                    continue;
                };
                for field in fields.iter().filter(|field| {
                    entity.stored_fields.iter().any(|stored| {
                        stored.logical.id == **field && columns.contains(&stored.logical.sql_name)
                    })
                }) {
                    for profile in reached
                        .iter()
                        .filter(|profile| !condition.exempt_profiles.contains(**profile))
                    {
                        errors.push(Diagnostic::error(
                            "breg.disclosure.statistics-withheld-field",
                            format!("{}.dimensions", reach.root),
                            &format!(
                                "statistical dataset `{}` reads withheld field `{field}` of `{}` through derived relation `{relation_id}` for access profile `{profile}`, which condition `{}` does not exempt: remove the field from the relation, or exempt the profile",
                                reach.dataset_id, entity.id, condition.id
                            ),
                        ));
                    }
                }
            }
        }
    }
}
