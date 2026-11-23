// SPDX-License-Identifier: Apache-2.0

//! Surfaces that read a field a `fields` condition withholds. Each function
//! refuses one surface for the profiles the condition does not exempt, so a
//! withheld field cannot be recovered through geometry queries, boundaries,
//! read paths, Record timers, derived fields, external views or statistics.
//! A Record timer is also refused a created record that carries a record a
//! `record` condition hides. A derived field is also refused to a profile
//! whose requests cannot see every source row its computation links to.

use std::collections::{BTreeMap, BTreeSet};

use crate::contract::{
    AccessProfileSource, BoundaryOperator, DerivedSource, DisclosureConditionSource,
    DisclosureWithholdSource, EntitySource, Operation, RowBoundarySource, TimerPredicateSource,
    UniqueSet,
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

/// A profile that reads, filters or sorts an owner's derived fields, with the
/// grant whose row boundaries its request runs under: its grant on the owner,
/// or on the root of a read path that ends at the owner.
struct DerivedReader<'a> {
    request_entity: &'a str,
    request_grant: &'a AccessProfileSource,
    fields: BTreeSet<&'a str>,
}

fn derived_fields_named<'a>(
    derived_ids: &BTreeSet<&str>,
    granted: [&'a UniqueSet<String>; 3],
) -> BTreeSet<&'a str> {
    granted
        .into_iter()
        .flat_map(|granted| granted.iter())
        .map(String::as_str)
        .filter(|id| derived_ids.contains(id))
        .collect()
}

/// A derived field is computed from source columns, so a profile that reads,
/// filters or sorts it, directly or through a read path whose `to` is the
/// owner, learns whatever a withheld source field says. The SQL must already
/// have passed validation.
pub(in crate::compiler) fn validate_derived_reads(
    owner: &EntitySource,
    derived: &DerivedSource,
    sql: &[u8],
    source_columns: &BTreeMap<String, BTreeSet<String>>,
    sources: &BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    let read = crate::derived_sql::derived_sql_source_columns(sql, source_columns);
    let derived_ids: BTreeSet<&str> = derived
        .fields
        .iter()
        .map(|field| field.id.as_str())
        .collect();
    let derived_ids = &derived_ids;
    // Each profile that reads the owner's derived fields: its own grant on the
    // owner, then its grants on read paths that end at the owner.
    let direct = owner.access_profiles.iter().map(|profile| DerivedReader {
        request_entity: &owner.id,
        request_grant: profile,
        fields: derived_fields_named(
            derived_ids,
            [
                &profile.readable_fields,
                &profile.filterable_fields,
                &profile.sortable_fields,
            ],
        ),
    });
    let through_paths = sources.values().flat_map(|path_owner| {
        path_owner.access_profiles.iter().flat_map(move |profile| {
            profile
                .read_paths
                .iter()
                .filter(move |grant| {
                    path_owner
                        .read_paths
                        .iter()
                        .any(|path| path.id == grant.path && path.to == owner.id)
                })
                .map(move |grant| DerivedReader {
                    request_entity: &path_owner.id,
                    request_grant: profile,
                    fields: derived_fields_named(
                        derived_ids,
                        [
                            &grant.readable_fields,
                            &grant.filterable_fields,
                            &grant.sortable_fields,
                        ],
                    ),
                })
        })
    });
    let derived_readers: Vec<DerivedReader<'_>> = direct
        .chain(through_paths)
        .filter(|reader| !reader.fields.is_empty())
        .collect();
    let readers: BTreeSet<&str> = derived_readers
        .iter()
        .map(|reader| reader.request_grant.id.as_str())
        .collect();
    validate_derived_source_grants(owner, sql, &derived_readers, sources, errors);
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
                for profile in readers
                    .iter()
                    .filter(|profile| !condition.exempt_profiles.contains(**profile))
                {
                    refuse(
                        errors,
                        "breg.disclosure.derived-reads-withheld-field",
                        &root,
                        field,
                        profile,
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

/// Derived SQL runs in the reader's request, under its row security, so each
/// record type it reads besides the owner contributes only the rows the
/// reader's own grant on that record type sees. A grant that sees fewer rows
/// than are linked to a row the reader sees yields a wrong answer, not an
/// error. So the grant must read rows, carry the row boundaries of the grant
/// the request runs under (a request installs that grant's boundary values,
/// and a grant whose boundaries name other fields or operators sees no row),
/// and add no membership or consent requirement of a kind that grant lacks.
/// A matching boundary still assumes the linked rows hold the same boundary
/// values. Readable fields limit the answer, not this computation, so the
/// grant need not make any field readable.
fn validate_derived_source_grants(
    owner: &EntitySource,
    sql: &[u8],
    readers: &[DerivedReader<'_>],
    sources: &BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    let relations = crate::derived_sql::derived_sql_dependencies(sql).source_relations;
    let mut reported = BTreeSet::new();
    for source in sources.values().filter(|source| {
        source.id != owner.id && relations.contains(&super::super::canonical_sql_name(&source.id))
    }) {
        for reader in readers {
            let Some((code, path, message)) = derived_source_finding(owner, source, reader) else {
                continue;
            };
            if reported.insert((code, path.clone())) {
                errors.push(Diagnostic::error(code, path, &message));
            }
        }
    }
}

fn derived_source_finding(
    owner: &EntitySource,
    source: &EntitySource,
    reader: &DerivedReader<'_>,
) -> Option<(&'static str, String, String)> {
    let request = reader.request_grant;
    let request_entity = reader.request_entity;
    let profile = &request.id;
    let fields = reader
        .fields
        .iter()
        .map(|field| format!("`{field}`"))
        .collect::<Vec<_>>()
        .join(", ");
    let reads = format!(
        "access profile `{profile}` reads derived field {fields} of `{}`, which is computed from `{}` under the profile's row security",
        owner.id, source.id
    );
    let missed = format!("so the computation misses linked `{}` rows", source.id);
    let source_path = |member: &str| {
        format!(
            "recordTypes[id={}].accessProfiles[id={profile}].{member}",
            source.id
        )
    };
    let Some(grant) = source
        .access_profiles
        .iter()
        .find(|grant| grant.id == *profile)
        .filter(|grant| crate::generated_ddl::grant_reads_rows(grant.operations.as_set()))
    else {
        return Some((
            "breg.disclosure.derived-reads-unreadable-source",
            source_path("operations"),
            format!(
                "{reads}, but the profile cannot read `{source}` rows, {missed}: grant it `get` on `{source}`, with only the link fields readable and the row boundaries {boundaries} of its grant on `{request_entity}`",
                source = source.id,
                boundaries = describe_row_boundaries(&request.row_boundaries),
            ),
        ));
    };
    const CODE: &str = "breg.disclosure.derived-reads-source-boundary";
    if request
        .row_boundaries
        .iter()
        .any(|boundary| boundary.field == "id")
    {
        return Some((
            CODE,
            format!("recordTypes[id={request_entity}].accessProfiles[id={profile}].rowBoundaries"),
            format!(
                "{reads}, but its grant on `{request_entity}` is bounded by `id`, which no linked `{source}` row shares, {missed}: bound that grant by a field `{source}` also carries, or do not grant the derived field",
                source = source.id,
            ),
        ));
    }
    if grant.row_boundaries != request.row_boundaries {
        return Some((
            CODE,
            source_path("rowBoundaries"),
            format!(
                "{reads}, but its grant on `{source}` is bounded by {source_rows} and its grant on `{request_entity}` by {request_rows}, {missed}: bound the grant on `{source}` by {request_rows} too, on fields that hold the same values",
                source = source.id,
                source_rows = describe_row_boundaries(&grant.row_boundaries),
                request_rows = describe_row_boundaries(&request.row_boundaries),
            ),
        ));
    }
    if let Some(added) = grant.membership_boundaries.iter().find(|boundary| {
        !request.membership_boundaries.iter().any(|held| {
            (
                &held.membership_entity,
                &held.membership_key_field,
                &held.principal_field,
                &held.active_field,
            ) == (
                &boundary.membership_entity,
                &boundary.membership_key_field,
                &boundary.principal_field,
                &boundary.active_field,
            )
        })
    }) {
        return Some((
            CODE,
            source_path("membershipBoundaries"),
            format!(
                "{reads}, but its grant on `{source}` requires a membership through `{membership}` that its grant on `{request_entity}` does not, {missed}: give the grant on `{request_entity}` the same membership boundary, or remove it from the grant on `{source}`",
                source = source.id,
                membership = added.membership_entity,
            ),
        ));
    }
    if let Some(added) = grant.require_consent.iter().find(|requirement| {
        !request
            .require_consent
            .iter()
            .any(|held| held.record == requirement.record)
    }) {
        return Some((
            CODE,
            source_path("requireConsent"),
            format!(
                "{reads}, but its grant on `{source}` requires consent recorded in `{record}` that its grant on `{request_entity}` does not, {missed}: require the same consent on the grant on `{request_entity}`, or remove it from the grant on `{source}`",
                source = source.id,
                record = added.record,
            ),
        ));
    }
    None
}

fn describe_row_boundaries(boundaries: &[RowBoundarySource]) -> String {
    if boundaries.is_empty() {
        return "`unrestricted`".to_owned();
    }
    boundaries
        .iter()
        .map(|boundary| {
            let operator = match boundary.operator {
                BoundaryOperator::Equals => "equals",
                BoundaryOperator::In => "in",
            };
            format!("`{}` {operator} claim `{}`", boundary.field, boundary.claim)
        })
        .collect::<Vec<_>>()
        .join(" and ")
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
