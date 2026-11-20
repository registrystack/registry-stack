// SPDX-License-Identifier: Apache-2.0

//! Surfaces that read a field a `fields` condition withholds. Each function
//! refuses one surface for the profiles the condition does not exempt, so a
//! withheld field cannot be recovered through geometry queries, boundaries,
//! read paths, derived fields, external views or statistics.

use std::collections::{BTreeMap, BTreeSet};

use crate::contract::{
    AccessProfileSource, DerivedSource, DisclosureConditionSource, DisclosureWithholdSource,
    EntitySource,
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

fn withheld(condition: &DisclosureConditionSource) -> &[String] {
    if condition.withhold == DisclosureWithholdSource::Fields {
        &condition.fields
    } else {
        &[]
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

/// A read path walks the reference fields of its `through` entity, so a
/// profile that reads the path learns which rows the withheld reference joins.
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
