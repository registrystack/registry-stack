// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_canonical_json::canonicalize_json;
use serde::Serialize;
use serde_json::json;

use crate::contract::{
    AccessProfileSource, ActorKindSource, Classification, DatasetOperation, FieldTypeSource,
    Operation, RegistryProject, StatisticalContributorSource, StatisticalDisclosureSource,
    StatisticalMeasureSource, StatisticalPeriodGranularitySource, StatisticalPeriodSource,
    StatisticalValiditySource, MAX_EXACT_JSON_INTEGER,
};
use crate::diagnostics::Diagnostic;
use crate::model::{
    CompiledEntity, CompiledStatisticalDataset, CompiledStatisticalDimension,
    CompiledStatisticalDimensionDomain, CompiledStatisticalExactReads, CompiledStatisticalPeriod,
    CompiledStatisticalReleases, CompiledStatisticalValidity,
};
use crate::query::{ComparisonOp, FilterExpr, FilterPredicate, Literal};
use crate::statistics::{
    maximum_measure_characters, period_for_code, uses_row_cube, Contributor, DisclosureDocument,
    DisclosureMethod, Measure, PeriodGranularity, SumDisclosure,
};

pub const MAX_STATISTICAL_CELLS_PER_PERIOD: usize = 10_000;
/// PostgreSQL accepts at most twelve elements in one `CUBE`, which computes the totals.
pub const MAX_STATISTICAL_DIMENSIONS: usize = 12;
/// A dataset with a non-additive measure (a distinct count or a percentile) or a
/// sum released under minimum-count-and-rounding (see `uses_row_cube`) computes
/// its totals over the records, not the base cells, which is dearer per
/// dimension.
pub const MAX_NON_ADDITIVE_DIMENSIONS: usize = 4;

pub(super) fn compile(
    project: &RegistryProject,
    entities: &BTreeMap<String, CompiledEntity>,
) -> Result<BTreeMap<String, CompiledStatisticalDataset>, Vec<Diagnostic>> {
    let mut errors = Vec::new();
    let mut compiled = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut sum_releases: Vec<SumRelease> = Vec::new();
    validate_permission_datasets(project, &mut errors);
    for source in &project.statistical_datasets {
        let root = format!("statisticalDatasets[id={}]", source.id);
        if !seen.insert(source.id.clone()) {
            errors.push(error(
                "breg.statistical-dataset.id-duplicate",
                &format!("{root}.id"),
                &source.id,
                "use a unique statistical dataset id",
            ));
            continue;
        }
        let Some(unit) = entities.get(&source.unit) else {
            errors.push(error(
                "breg.statistical-dataset.unit-unknown",
                &format!("{root}.unit"),
                &source.id,
                &format!("declare the unit entity `{}`", source.unit),
            ));
            continue;
        };

        let parsed_population = match crate::query::parse_filter(&source.population) {
            Ok(filter) => Some(filter),
            Err(_) => {
                errors.push(error(
                    "breg.statistical-dataset.population-invalid",
                    &format!("{root}.population"),
                    &source.id,
                    "write population with the supported $filter grammar",
                ));
                None
            }
        };
        let (mut referenced_fields, population_field_bindings) =
            validate_population(source, unit, parsed_population.as_ref(), &root, &mut errors);

        let (period, period_fields) = compile_period(source, unit, &root, &mut errors);
        referenced_fields.extend(period_fields);
        let dimensions = compile_dimensions(source, unit, &root, &mut errors);
        referenced_fields.extend(dimensions.iter().map(|dimension| dimension.field.clone()));
        // The fields a live reader must be able to filter on. A measure field is
        // read, never filtered, so it joins the referenced fields only afterwards.
        let filtered_fields = referenced_fields.clone();
        let (measures, measure_fields) = compile_measures(source, unit, &root, &mut errors);
        referenced_fields.extend(measure_fields.iter().cloned());
        validate_referenced_fields(source, unit, &referenced_fields, &root, &mut errors);

        let grants = DatasetGrants::of(project, &source.id);
        for profile in &grants.repeated {
            errors.push(error(
                "breg.statistical-dataset.profile-duplicate",
                &root,
                &source.id,
                &format!(
                    "name the dataset in one permission of access profile `{profile}` and list every operation there"
                ),
            ));
        }
        // Publishing or withdrawing a release commits at once, with no draft
        // for a human to confirm, so a standing agent holds neither. The
        // runtime authorizes both through the unit entity's profile of the
        // same id, which a module contributes when the project profile grants
        // nothing on that entity, so that profile meets the ceiling too.
        for profile in &grants.publish {
            if let Some(path) = standing_agent_path(project, unit, profile, &source.id) {
                errors.push(Diagnostic::error(
                    "breg.access-profile.standing-agent-publish-forbidden",
                    path,
                    "a standing agent profile without a taskGrant cannot publish or withdraw a statistical release; give publish to a profile a person or a service uses directly",
                ));
            }
        }
        for profile in &grants.read_exact {
            if let Some(path) = standing_agent_path(project, unit, profile, &source.id) {
                errors.push(Diagnostic::error(
                    "breg.access-profile.standing-agent-read-exact-forbidden",
                    path,
                    "a standing agent profile without a taskGrant cannot read exact statistics; give read-exact to a profile a person or a service uses directly",
                ));
            }
        }
        // A minimum-count-and-rounding release carries counts, distinct counts
        // and sums; every other measure is read live or released exactly.
        let releasing = grants
            .publish
            .iter()
            .chain(&grants.read_releases)
            .cloned()
            .collect::<BTreeSet<_>>();
        let exact = matches!(
            source.disclosure,
            Some(StatisticalDisclosureSource::ExactPublicValues {})
        );
        if measures
            .iter()
            .any(|measure| !measure.is_count_like() && !measure.is_sum())
            && !releasing.is_empty()
            && !exact
        {
            errors.push(error(
                "breg.statistical-dataset.measure-release-unsupported",
                &root,
                &source.id,
                &format!(
                    "a minimum-count-and-rounding release carries counts, distinct counts and sums; a mean, ratio or percentile is read live: remove publish and read-releases from {}, declare count, distinct-count and sum measures only, or release exact values with disclosure type exact-public-values over a register classified public",
                    quoted(&releasing)
                ),
            ));
        }
        let live_profiles = grants.read_live.clone();
        let mut publishers = grants.publish.iter();
        let releases = match (publishers.next(), publishers.next()) {
            (None, _) => {
                if !grants.read_releases.is_empty() {
                    errors.push(error(
                        "breg.statistical-dataset.publisher-missing",
                        &root,
                        &source.id,
                        &format!(
                            "no access profile publishes it, so there are no releases to read: grant publish to one access profile, or remove read-releases from {}",
                            quoted(&grants.read_releases)
                        ),
                    ));
                }
                None
            }
            (Some(publisher), None) => {
                // The runtime lets a live reader and the publisher read
                // releases, so each says so in its own permission.
                for profile in live_profiles.iter().chain([publisher]) {
                    if !grants.read_releases.contains(profile) {
                        errors.push(error(
                            "breg.statistical-dataset.read-releases-required",
                            &root,
                            &source.id,
                            &format!(
                                "access profile `{profile}` reads its releases because it reads live counts or publishes: add read-releases to the profile's permission on the dataset"
                            ),
                        ));
                    }
                }
                Some(CompiledStatisticalReleases {
                    publisher: publisher.clone(),
                    readers: grants
                        .read_releases
                        .iter()
                        .filter(|profile| {
                            *profile != publisher && !live_profiles.contains(*profile)
                        })
                        .cloned()
                        .collect(),
                })
            }
            (Some(_), Some(_)) => {
                errors.push(error(
                    "breg.statistical-dataset.publisher-multiple",
                    &root,
                    &source.id,
                    &format!(
                        "grant publish to one access profile; {} hold it",
                        quoted(&grants.publish)
                    ),
                ));
                None
            }
        };
        let granted = grants.holders();
        if granted.is_empty() {
            errors.push(error(
                "breg.statistical-dataset.grants-empty",
                &root,
                &source.id,
                "grant read-live, read-exact, publish, or read-releases on the dataset in an access profile's permissions",
            ));
        }

        let access_profiles = granted
            .iter()
            .filter_map(|profile_id| {
                project
                    .access_profiles
                    .iter()
                    .find(|profile| &profile.id == profile_id)
                    .map(|profile| {
                        (
                            profile_id.clone(),
                            authentication_profile(profile, entities),
                        )
                    })
            })
            .collect();
        let exact_reads = compile_exact_reads(
            source,
            project,
            unit,
            &grants.read_exact,
            &filtered_fields,
            &measure_fields,
            &root,
            &mut errors,
        );
        for profile in &live_profiles {
            validate_count_grant(
                source,
                unit,
                profile,
                Holder::Reader,
                &filtered_fields,
                &root,
                &mut errors,
            );
            validate_measure_fields_readable(
                source,
                unit,
                profile,
                Holder::Reader,
                &measure_fields,
                &root,
                &mut errors,
            );
        }
        if let Some(releases) = &releases {
            validate_count_grant(
                source,
                unit,
                &releases.publisher,
                Holder::Reader,
                &filtered_fields,
                &root,
                &mut errors,
            );
            validate_measure_fields_readable(
                source,
                unit,
                &releases.publisher,
                Holder::Reader,
                &measure_fields,
                &root,
                &mut errors,
            );
        }

        let disclosure_source = source.disclosure.as_ref();
        if disclosure_source.is_none() {
            errors.push(error(
                "breg.statistical-dataset.disclosure-missing",
                &format!("{root}.disclosure"),
                &source.id,
                "declare disclosure with type minimum-count-and-rounding (minimumCount and roundingBase) or exact-public-values",
            ));
        }
        let rounding = match disclosure_source {
            Some(StatisticalDisclosureSource::MinimumCountAndRounding {
                minimum_count,
                rounding_base,
                ..
            }) => Some((*minimum_count, *rounding_base)),
            _ => None,
        };
        let declares_sum = measures.iter().any(Measure::is_sum);
        let sum_release = rounding.is_some() && declares_sum && !grants.publish.is_empty();
        let sum_contributor =
            compile_sum_disclosure_rules(source, unit, &grants, sum_release, &root, &mut errors);
        if sum_release {
            if let Some(Contributor::Field { field: contributor }) = &sum_contributor {
                referenced_fields.insert(contributor.clone());
            }
            let sum_fields: BTreeSet<String> = source
                .measures
                .iter()
                .filter_map(|measure| match measure {
                    StatisticalMeasureSource::Sum { field, .. } => Some(field.clone()),
                    _ => None,
                })
                .collect();
            // Any two releases of a sum of one field over one unit share a
            // total, at least the grand total, and the totals rule sees one
            // dataset only: a reader could subtract the published cells of one
            // from that total and recover a cell the other withholds. Every
            // sum of a field over a unit is released by one dataset.
            for earlier in &sum_releases {
                if earlier.unit == source.unit && !earlier.sum_fields.is_disjoint(&sum_fields) {
                    errors.push(error(
                        "breg.statistical-dataset.sum-field-released-twice",
                        &root,
                        &source.id,
                        &format!(
                            "it releases a sum of a field that `{}` also releases over the same unit; release every sum of a field in one dataset, where the totals rule covers every cell",
                            earlier.id
                        ),
                    ));
                }
            }
            sum_releases.push(SumRelease {
                id: source.id.to_string(),
                unit: source.unit.clone(),
                sum_fields,
            });
        }
        if let Some((minimum_count, rounding_base)) = rounding {
            if minimum_count < 2 {
                errors.push(error(
                    "breg.statistical-dataset.disclosure-minimum-count",
                    &format!("{root}.disclosure.minimumCount"),
                    &source.id,
                    "set minimumCount to at least 2",
                ));
            }
            if minimum_count > MAX_EXACT_JSON_INTEGER {
                errors.push(error(
                    "breg.statistical-dataset.disclosure-minimum-count-exceeded",
                    &format!("{root}.disclosure.minimumCount"),
                    &source.id,
                    &format!("set minimumCount to at most {MAX_EXACT_JSON_INTEGER}"),
                ));
            }
            if rounding_base < 2 {
                errors.push(error(
                    "breg.statistical-dataset.disclosure-rounding-base",
                    &format!("{root}.disclosure.roundingBase"),
                    &source.id,
                    "set roundingBase to at least 2",
                ));
            }
            if rounding_base > MAX_EXACT_JSON_INTEGER {
                errors.push(error(
                    "breg.statistical-dataset.disclosure-rounding-base-exceeded",
                    &format!("{root}.disclosure.roundingBase"),
                    &source.id,
                    &format!("set roundingBase to at most {MAX_EXACT_JSON_INTEGER}"),
                ));
            }
        }
        if source.dimensions.len() > MAX_STATISTICAL_DIMENSIONS {
            errors.push(error(
                "breg.statistical-dataset.dimensions-exceeded",
                &format!("{root}.dimensions"),
                &source.id,
                &format!("declare at most {MAX_STATISTICAL_DIMENSIONS} dimensions"),
            ));
        }
        if source.dimensions.len() > MAX_NON_ADDITIVE_DIMENSIONS
            && uses_row_cube(&measures, sum_release)
        {
            errors.push(error(
                "breg.statistical-dataset.non-additive-dimensions",
                &format!("{root}.dimensions"),
                &source.id,
                &format!(
                    "a dataset with a distinct count, a percentile or a released sum declares at most {MAX_NON_ADDITIVE_DIMENSIONS} dimensions, because its totals are computed over the records, not the base cells"
                ),
            ));
        }
        let cell_count = dimensions
            .iter()
            .try_fold(measures.len().max(1), |cells, dimension| {
                cells
                    .checked_mul(dimension.codes.len() + usize::from(dimension.include_unknown) + 1)
            });
        if cell_count.is_none_or(|cells| cells > MAX_STATISTICAL_CELLS_PER_PERIOD) {
            errors.push(error(
                "breg.statistical-dataset.cells-exceeded",
                &format!("{root}.dimensions"),
                &source.id,
                &format!(
                    "reduce dimensions or codes to at most {MAX_STATISTICAL_CELLS_PER_PERIOD} cells per period"
                ),
            ));
        }

        let (dependency_entities, used_relations, evaluation_date_dependent) =
            dependencies(unit, &referenced_fields);
        if let Some(releases) = &releases {
            validate_publisher_independence(
                source,
                entities,
                &dependency_entities,
                &releases.publisher,
                Holder::Publisher,
                &root,
                &mut errors,
            );
        }
        if let Some(exact_reads) = &exact_reads {
            validate_publisher_independence(
                source,
                entities,
                &dependency_entities,
                &exact_reads.access_profile,
                Holder::ExactReads,
                &root,
                &mut errors,
            );
        }
        let exact = matches!(
            disclosure_source,
            Some(StatisticalDisclosureSource::ExactPublicValues {})
        );
        if exact {
            validate_exact_release_is_public(
                source,
                unit,
                entities,
                &dependency_entities,
                &referenced_fields,
                &root,
                &mut errors,
            );
        }
        'compile: {
            let Some(period) = period else {
                break 'compile;
            };
            let disclosure = match disclosure_source {
                Some(StatisticalDisclosureSource::ExactPublicValues {}) => {
                    DisclosureMethod::ExactPublicValues
                }
                _ => match rounding.filter(|(minimum_count, rounding_base)| {
                    (2..=MAX_EXACT_JSON_INTEGER).contains(minimum_count)
                        && (2..=MAX_EXACT_JSON_INTEGER).contains(rounding_base)
                }) {
                    Some((minimum_count, rounding_base)) => {
                        DisclosureMethod::MinimumCountAndRounding {
                            minimum_count,
                            rounding_base,
                        }
                    }
                    None => break 'compile,
                },
            };
            let sum_disclosure = sum_release
                .then(|| {
                    let dominance_percent = match disclosure_source {
                        Some(StatisticalDisclosureSource::MinimumCountAndRounding {
                            dominance_percent,
                            ..
                        }) => *dominance_percent,
                        _ => None,
                    };
                    sum_contributor.clone().zip(dominance_percent).map(
                        |(contributor, dominance_percent)| SumDisclosure {
                            contributor,
                            dominance_percent,
                            integer_sums: measures
                                .iter()
                                .filter(|measure| match measure {
                                    Measure::Sum {
                                        field: field_id, ..
                                    } => matches!(
                                        field(unit, field_id),
                                        Some((FieldTypeSource::Int64, _))
                                    ),
                                    _ => false,
                                })
                                .map(|measure| measure.id().to_owned())
                                .collect(),
                        },
                    )
                })
                .flatten();
            let field_type =
                |field_id: &str| field(unit, field_id).map(|(field_type, _)| field_type.clone());
            let longest_decimal =
                longest_released_decimal(&measures, &field_type, sum_disclosure.as_ref());
            let definition_digest = definition_digest(
                source,
                &period,
                &dimensions,
                &measures,
                &disclosure,
                DefinitionDependencies {
                    sums: sum_disclosure.as_ref(),
                    entities,
                    entity_ids: &dependency_entities,
                    relation_ids: &used_relations,
                    referenced_fields: &referenced_fields,
                    population_field_bindings: &population_field_bindings,
                },
                releases.as_ref().map(|release| release.publisher.as_str()),
            );
            if cell_count.is_some_and(|cells| {
                cells <= MAX_STATISTICAL_CELLS_PER_PERIOD
                    && maximum_release_document_bytes(
                        source,
                        &period,
                        &dimensions,
                        &measures,
                        disclosure,
                        sum_disclosure.as_ref(),
                        &definition_digest,
                        cells,
                        longest_decimal,
                    )
                    .is_none_or(|bytes| bytes > super::MAX_STATISTICAL_RELEASE_DOCUMENT_BYTES)
            }) {
                errors.push(error(
                "breg.statistical-dataset.document-exceeded",
                &format!("{root}.dimensions"),
                &source.id,
                &format!(
                    "reduce dimension names, domain codes, or cells so one release fits within {} bytes",
                    super::MAX_STATISTICAL_RELEASE_DOCUMENT_BYTES
                ),
            ));
                break 'compile;
            }
            compiled.insert(
                source.id.to_string(),
                CompiledStatisticalDataset {
                    id: source.id.to_string(),
                    display: source.display.clone(),
                    unit_entity_id: source.unit.clone(),
                    population: source.population.clone(),
                    period,
                    dimensions,
                    measures,
                    disclosure,
                    sum_disclosure,
                    access_profiles,
                    live_profiles,
                    releases,
                    exact_reads,
                    dependency_entities,
                    referenced_fields,
                    evaluation_date_dependent,
                    definition_digest,
                },
            );
        }
        // Rules of the hold run after every other check, so it is the last
        // diagnostic of the dataset.
        if declares_sum && rounding.is_some() && !releasing.is_empty() {
            errors.push(error(
                "breg.statistical-dataset.sum-release-held",
                &format!("{root}.disclosure"),
                &source.id,
                "a minimum-count-and-rounding release of a sum is held until a statistician has reviewed its disclosure rules; serve sums through read-live, read-exact, or an exact-public-values release",
            ));
        }
    }
    if errors.is_empty() {
        Ok(compiled)
    } else {
        Err(errors)
    }
}

/// The longest decimal text a release can state for any of `measures`. An
/// `int64` sum released under minimum-count-and-rounding is rounded to the
/// base, which can carry into one more digit (99,999 rounded to a base of 10 is
/// 100,000), so its bound is one character wider; a decimal sum is exact.
fn longest_released_decimal(
    measures: &[Measure],
    field_type: &dyn Fn(&str) -> Option<FieldTypeSource>,
    sums: Option<&SumDisclosure>,
) -> Option<usize> {
    measures
        .iter()
        .filter_map(|measure| {
            let exact = maximum_measure_characters(measure, measures, field_type)?;
            let rounded = sums.is_some_and(|sums| sums.integer_sums.contains(measure.id()));
            Some(exact + usize::from(rounded))
        })
        .max()
}

#[allow(clippy::too_many_arguments)]
fn maximum_release_document_bytes(
    source: &crate::contract::StatisticalDatasetSource,
    period: &CompiledStatisticalPeriod,
    dimensions: &[CompiledStatisticalDimension],
    measures: &[Measure],
    disclosure: DisclosureMethod,
    sums: Option<&SumDisclosure>,
    definition_digest: &str,
    cell_count: usize,
    longest_decimal: Option<usize>,
) -> Option<usize> {
    let (period_kind, granularity) = match period {
        CompiledStatisticalPeriod::Flow { granularity, .. } => ("flow", granularity),
        CompiledStatisticalPeriod::Stock { granularity, .. } => ("stock", granularity),
    };
    let digest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let timestamp = "9999-12-31T23:59:59.999999999Z";
    let snapshot = "ffffffff-ffff-ffff-ffff-ffffffffffff";
    let dimension_documents = dimensions
        .iter()
        .map(|dimension| {
            let mut codes = dimension.codes.clone();
            if dimension.include_unknown {
                codes.push(crate::statistics::UNKNOWN_CODE.to_owned());
            }
            codes.push(crate::statistics::TOTAL_CODE.to_owned());
            let vocabulary = match &dimension.domain {
                CompiledStatisticalDimensionDomain::Boolean => "boolean",
                CompiledStatisticalDimensionDomain::Vocabulary { vocabulary } => vocabulary,
            };
            json!({
                "field": dimension.field,
                "vocabulary": vocabulary,
                "codes": codes,
            })
        })
        .collect::<Vec<_>>();
    // Include both optional route envelopes. A response uses at most one, so
    // this remains an upper bound while accounting exactly for authored names,
    // population text, domains, and disclosure parameters.
    let envelope = canonicalize_json(&json!({
        "dataset": {
            "id": source.id,
            "unit": source.unit,
            "measures": measures,
            "periodKind": period_kind,
            "granularity": granularity,
            "population": source.population,
            "definitionDigest": definition_digest,
        },
        "periods": [{
            "code": "9999-12-31",
            "start": "9999-12-31",
            "end": "9999-12-31",
            "referenceDate": "9999-12-31",
            "ended": true,
            "version": {
                "version": MAX_EXACT_JSON_INTEGER,
                "status": "provisional",
                "contentDigest": digest,
                "snapshot": snapshot,
            },
        }],
        "dimensions": dimension_documents,
        "cells": [],
        "release": {
            "period": "9999-12-31",
            "version": MAX_EXACT_JSON_INTEGER,
            "status": "provisional",
            "snapshot": snapshot,
            "computedAt": timestamp,
            "packageDigest": digest,
        },
        "live": {
            "evaluatedAt": timestamp,
            "accessProfile": "x".repeat(64),
        },
        "disclosure": DisclosureDocument::for_release(disclosure, sums),
    }))
    .expect("statistical release size envelope canonicalizes")
    .len();

    let dimension_members = dimensions.iter().try_fold(0_usize, |bytes, dimension| {
        let code_bytes = dimension
            .codes
            .iter()
            .map(|code| canonical_json_string_bytes(code))
            .chain(std::iter::once(canonical_json_string_bytes(
                crate::statistics::TOTAL_CODE,
            )))
            .chain(
                dimension
                    .include_unknown
                    .then(|| canonical_json_string_bytes(crate::statistics::UNKNOWN_CODE)),
            )
            .max()?;
        bytes
            .checked_add(canonical_json_string_bytes(&dimension.field))?
            .checked_add(1)?
            .checked_add(code_bytes)
    })?;
    let dimension_object = 2_usize
        .checked_add(dimension_members)?
        .checked_add(dimensions.len().saturating_sub(1))?;
    let longest_measure_id = measures
        .iter()
        .map(|measure| measure.id().len())
        .max()
        .unwrap_or(0);
    // A count is a JSON integer of at most 16 characters. A sum or mean is a
    // string of at most `longest_decimal` characters, and its cell may state
    // `not-applicable`; the widest of either bounds every cell.
    let (value, status) = match longest_decimal {
        Some(characters) => (json!("9".repeat(characters.max(14))), "not-applicable"),
        None => (json!(MAX_EXACT_JSON_INTEGER), "suppressed"),
    };
    let empty_cell = canonicalize_json(&json!({
        "period": "9999-12-31",
        "dimensions": {},
        "measure": "x".repeat(longest_measure_id),
        "value": value,
        "status": status,
    }))
    .expect("statistical cell size envelope canonicalizes")
    .len();
    let cell_bytes = empty_cell.checked_sub(2)?.checked_add(dimension_object)?;
    let cells_bytes = 2_usize
        .checked_add(cell_count.checked_mul(cell_bytes)?)?
        .checked_add(cell_count.saturating_sub(1))?;
    envelope.checked_sub(2)?.checked_add(cells_bytes)
}

fn canonical_json_string_bytes(value: &str) -> usize {
    canonicalize_json(&json!(value))
        .expect("compiler-validated statistical string canonicalizes")
        .len()
}

fn authentication_profile(
    profile: &crate::contract::ProjectAccessProfileSource,
    entities: &BTreeMap<String, CompiledEntity>,
) -> AccessProfileSource {
    let task_grant = profile.task_grant.as_ref().map(|task_grant| {
        let permissions = profile
            .permissions
            .entities
            .iter()
            .filter_map(|permission| {
                entities.get(&permission.entity).map(|entity| {
                    crate::contract::CompiledTaskGrantPermissionSource {
                        collection: entity.route.clone(),
                        operations: permission.operations.clone(),
                    }
                })
            })
            .collect();
        crate::contract::CompiledTaskGrantSource {
            source_issuer: task_grant.source_issuer.clone(),
            permissions,
        }
    });
    AccessProfileSource {
        id: profile.id.clone(),
        display: profile.display.clone(),
        default: profile.default,
        actor_kind: profile.actor_kind,
        requester_clients: profile.requester_clients.clone(),
        task_grant,
        principal_claim: profile.principal_claim.clone(),
        required_scopes: profile.required_scopes.clone(),
        required_purposes: profile.required_purposes.clone(),
        operations: Default::default(),
        readable_fields: Default::default(),
        writable_fields: Default::default(),
        filterable_fields: Default::default(),
        sortable_fields: Default::default(),
        spatial_queries: None,
        row_boundaries: Vec::new(),
        membership_boundaries: Vec::new(),
        require_consent: Vec::new(),
        lookups: Vec::new(),
        read_paths: Vec::new(),
        allow_count: false,
        revision_access: false,
        provenance_fields: Vec::new(),
        allow_data_export: false,
    }
}

/// Where the profile is an agent without a task grant, declared by the
/// project or contributed to the unit entity by a module: the project profile's
/// dataset permission, or the unit entity's profile.
fn standing_agent_path(
    project: &RegistryProject,
    unit: &CompiledEntity,
    profile: &str,
    dataset: &str,
) -> Option<String> {
    let standing =
        |actor_kind, task_grant: bool| actor_kind == Some(ActorKindSource::Agent) && !task_grant;
    if project.access_profiles.iter().any(|declared| {
        declared.id == profile && standing(declared.actor_kind, declared.task_grant.is_some())
    }) {
        Some(format!(
            "project.accessProfiles[id={profile}].permissions.datasets[dataset={dataset}].operations"
        ))
    } else if unit
        .access_profiles
        .get(profile)
        .is_some_and(|access| standing(access.actor_kind, access.task_grant.is_some()))
    {
        Some(format!(
            "recordTypes[id={}].accessProfiles[id={profile}]",
            unit.id
        ))
    } else {
        None
    }
}

/// Compile `exactReads` and prove its profile can serve every exact read.
/// The profile's caller-independence over the dataset's dependencies is
/// checked with the other dependency rules.
#[allow(clippy::too_many_arguments)]
fn compile_exact_reads(
    source: &crate::contract::StatisticalDatasetSource,
    project: &RegistryProject,
    unit: &CompiledEntity,
    readers: &BTreeSet<String>,
    filtered_fields: &BTreeSet<String>,
    measure_fields: &BTreeSet<String>,
    root: &str,
    errors: &mut Vec<Diagnostic>,
) -> Option<CompiledStatisticalExactReads> {
    let Some(declared) = &source.exact_reads else {
        if !readers.is_empty() {
            errors.push(error(
                "breg.statistical-dataset.exact-reads-missing",
                root,
                &source.id,
                &format!(
                    "{} hold read-exact, which computes under the profile named by exactReads: declare exactReads with an accessProfile, or remove read-exact",
                    quoted(readers)
                ),
            ));
        }
        return None;
    };
    let exact_root = format!("{root}.exactReads");
    if readers.is_empty() {
        errors.push(error(
            "breg.statistical-dataset.exact-reads-unused",
            &exact_root,
            &source.id,
            "no access profile holds read-exact, so nothing reads under exactReads: grant read-exact to an access profile, or remove exactReads",
        ));
        return None;
    }
    let profile = &declared.access_profile;
    let path = Holder::ExactReads.path(root);
    // The runtime resolves the anchor through the unit entity's profile, which
    // a module may contribute, as it does for a publisher.
    let project_profile = project
        .access_profiles
        .iter()
        .find(|candidate| &candidate.id == profile);
    let unit_profile = unit.access_profiles.get(profile);
    if project_profile.is_none() && unit_profile.is_none() {
        errors.push(error(
            "breg.statistical-dataset.exact-reads-profile-unknown",
            &path,
            &source.id,
            &format!(
                "name an access profile the project declares or a module contributes to `{}`; `{profile}` is not one",
                unit.id
            ),
        ));
        return None;
    }
    let task_dependent =
        |actor_kind, task_grant: bool| actor_kind == Some(ActorKindSource::Agent) || task_grant;
    if project_profile
        .is_some_and(|declared| task_dependent(declared.actor_kind, declared.task_grant.is_some()))
        || unit_profile
            .is_some_and(|access| task_dependent(access.actor_kind, access.task_grant.is_some()))
    {
        errors.push(error(
            "breg.statistical-dataset.exact-reads-profile-agent",
            &path,
            &source.id,
            &format!(
                "exactReads profile `{profile}` is an agent or task-grant profile, whose visibility depends on the task: name a profile a person or a service uses directly"
            ),
        ));
    }
    validate_count_grant(
        source,
        unit,
        profile,
        Holder::ExactReads,
        filtered_fields,
        root,
        errors,
    );
    validate_measure_fields_readable(
        source,
        unit,
        profile,
        Holder::ExactReads,
        measure_fields,
        root,
        errors,
    );
    Some(CompiledStatisticalExactReads {
        access_profile: profile.clone(),
        readers: readers.clone(),
    })
}

fn compile_period(
    source: &crate::contract::StatisticalDatasetSource,
    unit: &CompiledEntity,
    root: &str,
    errors: &mut Vec<Diagnostic>,
) -> (Option<CompiledStatisticalPeriod>, BTreeSet<String>) {
    let mut fields = BTreeSet::new();
    let (granularity_source, first_period) = match &source.period {
        StatisticalPeriodSource::Flow {
            field,
            granularity,
            first_period,
        } => {
            fields.insert(field.clone());
            (*granularity, first_period.as_str())
        }
        StatisticalPeriodSource::Stock {
            granularity,
            first_period,
            validity,
        } => {
            match validity {
                StatisticalValiditySource::Temporal(_) => {
                    if let Some(temporal) = &unit.temporal {
                        fields.insert(temporal.start_field.clone());
                        fields.insert(temporal.end_field.clone());
                    } else {
                        errors.push(error(
                            "breg.statistical-dataset.period-temporal-missing",
                            &format!("{root}.period.validity"),
                            &source.id,
                            &format!(
                                "declare temporal validity on unit entity `{}` or name validity fields",
                                unit.id
                            ),
                        ));
                    }
                }
                StatisticalValiditySource::Fields(validity) => {
                    fields.insert(validity.from.clone());
                    if let Some(until) = &validity.until {
                        fields.insert(until.clone());
                    }
                }
            }
            (*granularity, first_period.as_str())
        }
    };
    let granularity = granularity(granularity_source);
    if !valid_period_code(first_period, granularity) {
        errors.push(error(
            "breg.statistical-dataset.period-first-period",
            &format!("{root}.period.firstPeriod"),
            &source.id,
            "use a valid firstPeriod matching the declared granularity",
        ));
    }
    let compiled = match &source.period {
        StatisticalPeriodSource::Flow { field, .. } => CompiledStatisticalPeriod::Flow {
            field: field.clone(),
            granularity,
            first_period: first_period.to_owned(),
        },
        StatisticalPeriodSource::Stock { validity, .. } => {
            let validity = match validity {
                StatisticalValiditySource::Temporal(_) => {
                    unit.temporal
                        .as_ref()
                        .map(|temporal| CompiledStatisticalValidity::Temporal {
                            from: temporal.start_field.clone(),
                            until: temporal.end_field.clone(),
                            last_day: temporal.last_day,
                        })
                }
                StatisticalValiditySource::Fields(validity) => {
                    Some(CompiledStatisticalValidity::Fields {
                        from: validity.from.clone(),
                        until: validity.until.clone(),
                        last_day: unit.temporal.as_ref().is_some_and(|temporal| {
                            temporal.last_day
                                && validity.until.as_ref() == Some(&temporal.end_field)
                        }),
                    })
                }
            };
            let Some(validity) = validity else {
                return (None, fields);
            };
            CompiledStatisticalPeriod::Stock {
                granularity,
                first_period: first_period.to_owned(),
                validity,
            }
        }
    };
    (Some(compiled), fields)
}

/// The declared measures, and the unit fields the sums, means, percentiles and
/// distinct counts read.
fn compile_measures(
    source: &crate::contract::StatisticalDatasetSource,
    unit: &CompiledEntity,
    root: &str,
    errors: &mut Vec<Diagnostic>,
) -> (Vec<Measure>, BTreeSet<String>) {
    let path = format!("{root}.measures");
    let mut measure_fields = BTreeSet::new();
    if source.measures.is_empty() {
        errors.push(error(
            "breg.statistical-dataset.measures-empty",
            &path,
            &source.id,
            "declare at least one measure, or remove `measures` to publish one `count` measure",
        ));
        return (Vec::new(), measure_fields);
    }
    let mut seen = BTreeSet::new();
    let mut counts = 0_usize;
    let mut distinct_fields = BTreeSet::new();
    let mut measures = Vec::new();
    for (index, measure) in source.measures.iter().enumerate() {
        let path = format!("{path}[{index}]");
        let id = measure.id();
        if !seen.insert(id.as_str()) {
            errors.push(error(
                "breg.statistical-dataset.measure-duplicate",
                &format!("{path}.id"),
                &source.id,
                &format!("declare measure `{id}` once"),
            ));
            continue;
        }
        let compiled = match measure {
            StatisticalMeasureSource::Count { .. } => {
                counts += 1;
                if counts > 1 {
                    errors.push(error(
                        "breg.statistical-dataset.measure-count-duplicate",
                        &format!("{path}.type"),
                        &source.id,
                        "declare one count measure; a second would publish the same numbers twice",
                    ));
                    continue;
                }
                Measure::Count { id: id.to_string() }
            }
            StatisticalMeasureSource::Sum {
                field: field_id, ..
            }
            | StatisticalMeasureSource::Mean {
                field: field_id, ..
            } => {
                // An unknown field is refused with every other referenced field.
                measure_fields.insert(field_id.clone());
                let Some((field_type, _)) = field(unit, field_id) else {
                    continue;
                };
                let field_scale = match field_type {
                    FieldTypeSource::Int64 => 0,
                    FieldTypeSource::Decimal { scale, .. } => *scale,
                    _ => {
                        errors.push(error(
                            "breg.statistical-dataset.measure-field-type",
                            &format!("{path}.field"),
                            &source.id,
                            &format!(
                                "measure `{id}` adds or averages field `{field_id}`; use an int64 or decimal field"
                            ),
                        ));
                        continue;
                    }
                };
                match measure {
                    StatisticalMeasureSource::Mean { scale, .. } => Measure::Mean {
                        id: id.to_string(),
                        field: field_id.clone(),
                        scale: *scale,
                    },
                    _ => Measure::Sum {
                        id: id.to_string(),
                        field: field_id.clone(),
                        scale: field_scale,
                    },
                }
            }
            StatisticalMeasureSource::Percentile {
                field: field_id,
                percentile,
                scale,
                ..
            } => {
                measure_fields.insert(field_id.clone());
                let Some((field_type, _)) = field(unit, field_id) else {
                    continue;
                };
                if !matches!(
                    field_type,
                    FieldTypeSource::Int64 | FieldTypeSource::Decimal { .. }
                ) {
                    errors.push(error(
                        "breg.statistical-dataset.measure-field-type",
                        &format!("{path}.field"),
                        &source.id,
                        &format!(
                            "measure `{id}` takes a percentile of field `{field_id}`; use an int64 or decimal field"
                        ),
                    ));
                    continue;
                }
                Measure::Percentile {
                    id: id.to_string(),
                    field: field_id.clone(),
                    percentile: *percentile,
                    scale: *scale,
                }
            }
            StatisticalMeasureSource::Ratio {
                numerator,
                denominator,
                scale,
                ..
            } => {
                let mut operands_valid = true;
                for (member, operand) in [("numerator", numerator), ("denominator", denominator)] {
                    let is_operand = source.measures.iter().any(|candidate| {
                        candidate.id() == operand
                            && matches!(
                                candidate,
                                StatisticalMeasureSource::Count { .. }
                                    | StatisticalMeasureSource::DistinctCount { .. }
                                    | StatisticalMeasureSource::Sum { .. }
                            )
                    });
                    if !is_operand {
                        operands_valid = false;
                        errors.push(error(
                            "breg.statistical-dataset.ratio-operand",
                            &format!("{path}.{member}"),
                            &source.id,
                            &format!(
                                "ratio `{id}` divides measures of this dataset; name a count, distinct-count or sum measure, not `{operand}`"
                            ),
                        ));
                    }
                }
                if numerator == denominator && operands_valid {
                    operands_valid = false;
                    errors.push(error(
                        "breg.statistical-dataset.ratio-operand",
                        &format!("{path}.denominator"),
                        &source.id,
                        &format!(
                            "ratio `{id}` divides `{numerator}` by itself, which is always 1; name two different measures"
                        ),
                    ));
                }
                if !operands_valid {
                    continue;
                }
                Measure::Ratio {
                    id: id.to_string(),
                    numerator: numerator.to_string(),
                    denominator: denominator.to_string(),
                    scale: *scale,
                }
            }
            StatisticalMeasureSource::DistinctCount {
                field: field_id, ..
            } => {
                measure_fields.insert(field_id.clone());
                if !distinct_fields.insert(field_id.as_str()) {
                    errors.push(error(
                        "breg.statistical-dataset.measure-distinct-count-duplicate",
                        &format!("{path}.field"),
                        &source.id,
                        &format!(
                            "declare one distinct count over field `{field_id}`; a second would publish the same numbers twice"
                        ),
                    ));
                    continue;
                }
                let Some((field_type, _)) = field(unit, field_id) else {
                    continue;
                };
                if !matches!(field_type, FieldTypeSource::Reference { .. }) {
                    errors.push(error(
                        "breg.statistical-dataset.measure-field-type",
                        &format!("{path}.field"),
                        &source.id,
                        &format!(
                            "measure `{id}` counts the distinct values of field `{field_id}`; use a reference field"
                        ),
                    ));
                    continue;
                }
                Measure::DistinctCount {
                    id: id.to_string(),
                    field: field_id.clone(),
                }
            }
        };
        measures.push(compiled);
    }
    (measures, measure_fields)
}

/// A live reader gets the sum, mean or percentile of a field it can read, never of one it
/// could not list: a measure field must be readable, though not filterable.
fn validate_measure_fields_readable(
    source: &crate::contract::StatisticalDatasetSource,
    unit: &CompiledEntity,
    profile_id: &str,
    holder: Holder,
    measure_fields: &BTreeSet<String>,
    root: &str,
    errors: &mut Vec<Diagnostic>,
) {
    let subject = holder.subject(profile_id);
    let path = holder.path(root);
    // A missing grant is reported by the count grant check.
    let Some(grant) = unit.access_profiles.get(profile_id) else {
        return;
    };
    for field in measure_fields {
        if !grant.readable_fields.contains(field) {
            errors.push(error(
                &holder.code("measure-field-not-readable"),
                &path,
                &source.id,
                &format!(
                    "add field `{field}` to readableFields for {subject} on `{}`, or remove the sum, mean, percentile or distinct count over it",
                    unit.id
                ),
            ));
        }
    }
}

fn compile_dimensions(
    source: &crate::contract::StatisticalDatasetSource,
    unit: &CompiledEntity,
    root: &str,
    errors: &mut Vec<Diagnostic>,
) -> Vec<CompiledStatisticalDimension> {
    let mut seen = BTreeSet::new();
    let mut dimensions = Vec::new();
    for field_id in &source.dimensions {
        let path = format!("{root}.dimensions[]");
        if !seen.insert(field_id) {
            errors.push(error(
                "breg.statistical-dataset.dimension-duplicate",
                &path,
                &source.id,
                &format!("list dimension `{field_id}` once"),
            ));
            continue;
        }
        if matches!(field_id.as_str(), "period" | "measure" | "value" | "status") {
            errors.push(error(
                "breg.statistical-dataset.dimension-reserved",
                &path,
                &source.id,
                &format!("rename dimension field `{field_id}` because the CSV column is reserved"),
            ));
        }
        let Some((field_type, required)) = field(unit, field_id) else {
            errors.push(error(
                "breg.statistical-dataset.field-unknown",
                &path,
                &source.id,
                &format!(
                    "declare dimension field `{field_id}` on unit entity `{}`",
                    unit.id
                ),
            ));
            continue;
        };
        let (domain, codes) = match field_type {
            FieldTypeSource::Boolean => (
                CompiledStatisticalDimensionDomain::Boolean,
                vec!["false".to_owned(), "true".to_owned()],
            ),
            FieldTypeSource::VocabularyCode { vocabulary, values } => {
                if values.iter().any(|value| value.starts_with('_')) {
                    errors.push(error(
                        "breg.statistical-dataset.dimension-code-reserved",
                        &path,
                        &source.id,
                        &format!(
                            "remove underscore-prefixed codes from dimension vocabulary `{vocabulary}`"
                        ),
                    ));
                }
                (
                    CompiledStatisticalDimensionDomain::Vocabulary {
                        vocabulary: vocabulary.clone(),
                    },
                    values.clone(),
                )
            }
            _ => {
                errors.push(error(
                    "breg.statistical-dataset.dimension-type",
                    &path,
                    &source.id,
                    &format!("make dimension field `{field_id}` boolean or vocabulary-code"),
                ));
                continue;
            }
        };
        dimensions.push(CompiledStatisticalDimension {
            field: field_id.clone(),
            domain,
            codes,
            include_unknown: !required || unit.derived_fields.contains_key(field_id),
        });
    }
    dimensions
}

fn validate_referenced_fields(
    source: &crate::contract::StatisticalDatasetSource,
    unit: &CompiledEntity,
    fields: &BTreeSet<String>,
    root: &str,
    errors: &mut Vec<Diagnostic>,
) {
    for field_id in fields {
        let Some((field_type, _)) = field(unit, field_id) else {
            errors.push(error(
                "breg.statistical-dataset.field-unknown",
                root,
                &source.id,
                &format!(
                    "declare referenced field `{field_id}` on unit entity `{}`",
                    unit.id
                ),
            ));
            continue;
        };
        if unit
            .fields
            .get(field_id)
            .is_some_and(|field| field.encryption.is_some())
        {
            errors.push(error(
                "breg.statistical-dataset.field-encrypted",
                root,
                &source.id,
                &format!("use an unencrypted field instead of `{field_id}`"),
            ));
        }
        let is_period_field = match &source.period {
            StatisticalPeriodSource::Flow { field, .. } => field == field_id,
            StatisticalPeriodSource::Stock { validity, .. } => match validity {
                StatisticalValiditySource::Temporal(_) => unit
                    .temporal
                    .as_ref()
                    .is_some_and(|t| &t.start_field == field_id || &t.end_field == field_id),
                StatisticalValiditySource::Fields(validity) => {
                    &validity.from == field_id || validity.until.as_ref() == Some(field_id)
                }
            },
        };
        if is_period_field && !matches!(field_type, FieldTypeSource::Date) {
            errors.push(error(
                "breg.statistical-dataset.period-field-type",
                root,
                &source.id,
                &format!("make period or validity field `{field_id}` a date"),
            ));
        }
    }
}

fn validate_count_grant(
    source: &crate::contract::StatisticalDatasetSource,
    unit: &CompiledEntity,
    profile_id: &str,
    holder: Holder,
    referenced_fields: &BTreeSet<String>,
    root: &str,
    errors: &mut Vec<Diagnostic>,
) {
    let subject = holder.subject(profile_id);
    let path = holder.path(root);
    let Some(grant) = unit.access_profiles.get(profile_id) else {
        errors.push(error(
            &holder.code("count-grant-missing"),
            &path,
            &source.id,
            &format!("grant {subject} list access to unit entity `{}`", unit.id),
        ));
        return;
    };
    if !grant.operations.contains(&Operation::List) {
        errors.push(error(
            &holder.code("count-grant-list-required"),
            &path,
            &source.id,
            &format!("grant {subject} the list operation on `{}`", unit.id),
        ));
    }
    if !grant.allow_count {
        errors.push(error(
            &holder.code("count-grant-count-required"),
            &path,
            &source.id,
            &format!("set allowCount for {subject} on `{}`", unit.id),
        ));
    }
    if !grant.require_consent.is_empty() {
        errors.push(error(
            &holder.code("count-grant-consent"),
            &path,
            &source.id,
            &format!("remove requireConsent from {subject} for dataset counts"),
        ));
    }
    for field in referenced_fields {
        if !grant.filterable_fields.contains(field) {
            errors.push(error(
                &holder.code("count-grant-field-not-filterable"),
                &path,
                &source.id,
                &format!("add field `{field}` to filterableFields for {subject}"),
            ));
        }
    }
}

/// An exact release publishes every value it computes, so the unit Record type,
/// each field the dataset reads, and each other Record type a derived field
/// reads from must be classified `public`. One diagnostic names each item that
/// is not.
fn validate_exact_release_is_public(
    source: &crate::contract::StatisticalDatasetSource,
    unit: &CompiledEntity,
    entities: &BTreeMap<String, CompiledEntity>,
    dependency_entities: &BTreeSet<String>,
    referenced_fields: &BTreeSet<String>,
    root: &str,
    errors: &mut Vec<Diagnostic>,
) {
    let mut refuse = |kind: &str, item: &str, classification: Classification| {
        errors.push(error(
            "breg.statistical-dataset.exact-release-not-public",
            &format!("{root}.disclosure.type"),
            &source.id,
            &format!(
                "exact-public-values releases every value, but {kind} `{item}` is classified `{}`: reclassify it as public, or use minimum-count-and-rounding",
                classification_name(classification)
            ),
        ));
    };
    if unit.classification != Classification::Public {
        refuse("record type", &unit.id, unit.classification);
    }
    for field_id in referenced_fields {
        let classification = unit
            .fields
            .get(field_id)
            .map(|field| field.classification)
            .or_else(|| {
                unit.derived_fields
                    .get(field_id)
                    .map(|field| field.logical.classification)
            });
        if let Some(classification) = classification.filter(|c| *c != Classification::Public) {
            refuse("field", field_id, classification);
        }
    }
    for entity_id in dependency_entities.iter().filter(|id| **id != unit.id) {
        let classification = entities[entity_id].classification;
        if classification != Classification::Public {
            refuse("record type", entity_id, classification);
        }
    }
}

fn classification_name(classification: Classification) -> &'static str {
    match classification {
        Classification::Public => "public",
        Classification::Internal => "internal",
        Classification::Restricted => "restricted",
    }
}

fn validate_publisher_independence(
    source: &crate::contract::StatisticalDatasetSource,
    entities: &BTreeMap<String, CompiledEntity>,
    dependency_entities: &BTreeSet<String>,
    publisher: &str,
    holder: Holder,
    root: &str,
    errors: &mut Vec<Diagnostic>,
) {
    let subject = holder.independence_subject(publisher);
    let path = holder.path(root);
    let tail = holder.independence_tail();
    for entity_id in dependency_entities {
        let entity = &entities[entity_id];
        if entity
            .access_requirements
            .as_ref()
            .is_some_and(|requirements| !requirements.row_boundaries.is_empty())
        {
            errors.push(error(
                &holder.independence_code("record-type-row-boundary"),
                &path,
                &source.id,
                &format!(
                    "remove accessRequirements.rowBoundaries from dependency entity `{entity_id}` {tail}"
                ),
            ));
        }
        let Some(grant) = entity.access_profiles.get(publisher) else {
            errors.push(error(
                &holder.independence_code("dependency-grant-missing"),
                &path,
                &source.id,
                &format!("grant {subject} access to dependency entity `{entity_id}`"),
            ));
            continue;
        };
        if dependency_select_operations(grant).is_empty() {
            errors.push(error(
                &holder.independence_code("dependency-read-required"),
                &path,
                &source.id,
                &format!(
                    "grant {subject} get, lookup, list, batch, revisions, or snapshot access to dependency entity `{entity_id}`"
                ),
            ));
        }
        let violation = if !grant.row_boundaries.is_empty() {
            Some("rowBoundaries")
        } else if !grant.membership_boundaries.is_empty() {
            Some("membershipBoundaries")
        } else if !grant.required_purposes.is_empty() {
            Some("requiredPurposes")
        } else if !grant.require_consent.is_empty() {
            Some("requireConsent")
        } else {
            None
        };
        if let Some(member) = violation {
            errors.push(error(
                &holder.independence_code("caller-dependent"),
                &path,
                &source.id,
                &format!(
                    "remove `{member}` from {subject} on dependency entity `{entity_id}` {tail}"
                ),
            ));
        }
    }
}

fn dependency_select_operations(profile: &AccessProfileSource) -> BTreeSet<Operation> {
    profile
        .operations
        .iter()
        .copied()
        .filter(|operation| {
            matches!(
                operation,
                Operation::Get
                    | Operation::Lookup
                    | Operation::List
                    | Operation::Batch
                    | Operation::Revisions
                    | Operation::Snapshot
            )
        })
        .collect()
}

fn dependencies(
    unit: &CompiledEntity,
    referenced_fields: &BTreeSet<String>,
) -> (BTreeSet<String>, BTreeSet<String>, bool) {
    let mut entities = BTreeSet::from([unit.id.clone()]);
    let mut relations = BTreeSet::new();
    let mut evaluation_date = false;
    for field in referenced_fields {
        let Some(derived) = unit.derived_fields.get(field) else {
            continue;
        };
        let relation = &unit.derived_relations[&derived.derivation_id];
        relations.insert(relation.id.clone());
        entities.extend(relation.source_entities.iter().cloned());
        evaluation_date |= relation.uses_evaluation_date;
    }
    (entities, relations, evaluation_date)
}

struct DefinitionDependencies<'a> {
    sums: Option<&'a SumDisclosure>,
    entities: &'a BTreeMap<String, CompiledEntity>,
    entity_ids: &'a BTreeSet<String>,
    relation_ids: &'a BTreeSet<String>,
    referenced_fields: &'a BTreeSet<String>,
    population_field_bindings: &'a BTreeMap<String, String>,
}

fn definition_digest(
    source: &crate::contract::StatisticalDatasetSource,
    period: &CompiledStatisticalPeriod,
    dimensions: &[CompiledStatisticalDimension],
    measures: &[Measure],
    disclosure: &DisclosureMethod,
    dependencies: DefinitionDependencies<'_>,
    publisher: Option<&str>,
) -> String {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Visibility<'a> {
        entity: &'a str,
        read_operations: BTreeSet<Operation>,
        row_boundaries: serde_json::Value,
        membership_boundaries: serde_json::Value,
        required_purposes: serde_json::Value,
        require_consent: serde_json::Value,
        access_requirement_row_boundaries: serde_json::Value,
    }
    let unit = &dependencies.entities[&source.unit];
    let source_columns = dependencies
        .entities
        .values()
        .map(|entity| {
            (
                entity.source_relation.sql_name.clone(),
                std::iter::once(entity.canonical_id.sql_name.clone())
                    .chain(entity.source_relation.stored_fields.iter().map(|field_id| {
                        entity
                            .stored_fields
                            .iter()
                            .find(|field| field.logical.id == *field_id)
                            .expect("compiled source relation names only stored fields")
                            .logical
                            .sql_name
                            .clone()
                    }))
                    .collect::<BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let referenced_field_definitions = dependencies
        .referenced_fields
        .iter()
        .filter_map(|field_id| {
            compiled_field_definition(unit, field_id)
                .map(|definition| (field_id.as_str(), definition))
        })
        .collect::<BTreeMap<_, _>>();
    let derived = dependencies
        .relation_ids
        .iter()
        .filter_map(|relation_id| {
            unit.derived_relations.get(relation_id).map(|relation| {
                let source_field_definitions = crate::derived_sql::derived_sql_source_columns(
                    &relation.sql_bytes,
                    &source_columns,
                )
                .into_iter()
                .filter_map(|(relation_name, fields)| {
                    let entity = dependencies
                        .entities
                        .values()
                        .find(|entity| entity.source_relation.sql_name == relation_name)?;
                    let definitions = fields
                        .iter()
                        .filter_map(|sql_name| {
                            source_field_definition(entity, sql_name)
                                .map(|(field_id, definition)| (field_id.to_owned(), definition))
                        })
                        .collect::<BTreeMap<_, _>>();
                    Some((entity.id.clone(), definitions))
                })
                .collect::<BTreeMap<_, _>>();
                json!({
                    "id": relation.id,
                    "keyField": relation.key_field,
                    "execution": relation.execution,
                    "sqlSha256": relation.sql_sha256,
                    "sourceEntities": relation.source_entities,
                    "sourceFieldDefinitions": source_field_definitions,
                    "usesEvaluationDate": relation.uses_evaluation_date,
                })
            })
        })
        .collect::<Vec<_>>();
    let visibility = publisher
        .map(|publisher| {
            dependencies
                .entity_ids
                .iter()
                .filter_map(|entity_id| {
                    let entity = &dependencies.entities[entity_id];
                    let profile = entity.access_profiles.get(publisher)?;
                    Some(Visibility {
                        entity: entity_id,
                        read_operations: dependency_select_operations(profile),
                        row_boundaries: json!(profile.row_boundaries),
                        membership_boundaries: json!(profile.membership_boundaries),
                        required_purposes: json!(profile.required_purposes),
                        require_consent: json!(profile.require_consent),
                        access_requirement_row_boundaries: json!(entity
                            .access_requirements
                            .as_ref()
                            .map(|requirements| &requirements.row_boundaries)),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let period_definition = match period {
        CompiledStatisticalPeriod::Flow {
            field, granularity, ..
        } => json!({"kind": "flow", "field": field, "granularity": granularity}),
        CompiledStatisticalPeriod::Stock {
            granularity,
            validity,
            ..
        } => json!({"kind": "stock", "granularity": granularity, "validity": validity}),
    };
    let mut value = json!({
        "unit": source.unit,
        "population": source.population,
        "populationFieldBindings": dependencies.population_field_bindings,
        "referencedFieldDefinitions": referenced_field_definitions,
        "period": period_definition,
        "dimensions": dimensions,
        "measures": measures,
        "disclosure": disclosure,
        "derived": derived,
        "publisherVisibility": visibility,
    });
    if let Some(contributor) = sum_definition(dependencies.sums) {
        value["contributor"] = contributor;
    }
    let bytes = canonicalize_json(&value).expect("statistical dataset definition canonicalizes");
    super::sha256_hex(&bytes)
}

/// One referenced field as the definition digest hashes it. A published
/// release is stored under that digest and read back by it, so the field type
/// is hashed with each bound under the name it was first hashed with.
fn compiled_field_definition(entity: &CompiledEntity, field_id: &str) -> Option<serde_json::Value> {
    entity
        .stored_fields
        .iter()
        .find(|field| field.logical.id == field_id)
        .map(|field| {
            json!({
                "kind": "stored",
                "sqlName": field.logical.sql_name,
                "type": field.logical.field_type,
                "required": field.required,
                "pattern": entity.fields[&field.logical.id].pattern.as_ref(),
            })
        })
        .or_else(|| {
            entity.derived_fields.get(field_id).map(|field| {
                json!({
                    "kind": "derived",
                    "sqlName": field.logical.sql_name,
                    "type": field.logical.field_type,
                    "derivation": field.derivation_id,
                })
            })
        })
}

fn source_field_definition<'a>(
    entity: &'a CompiledEntity,
    sql_name: &str,
) -> Option<(&'a str, serde_json::Value)> {
    if entity.canonical_id.sql_name == sql_name {
        return Some((
            entity.canonical_id.id.as_str(),
            json!({
                "kind": "canonicalId",
                "sqlName": entity.canonical_id.sql_name,
                "type": entity.canonical_id.field_type,
            }),
        ));
    }
    entity
        .stored_fields
        .iter()
        .find(|field| field.logical.sql_name == sql_name)
        .map(|field| {
            (
                field.logical.id.as_str(),
                json!({
                    "kind": "stored",
                    "sqlName": field.logical.sql_name,
                    "type": field.logical.field_type,
                    "required": field.required,
                    "pattern": entity.fields[&field.logical.id].pattern.as_ref(),
                }),
            )
        })
}

/// The role a profile plays when the compiler checks its access to a
/// statistical dataset's unit and dependencies.
#[derive(Clone, Copy)]
enum Holder {
    /// A live reader or a release publisher, reported against the dataset.
    Reader,
    /// The release publisher, reported against the dataset.
    Publisher,
    /// The `exactReads` profile whose visibility `read-exact` computes under.
    ExactReads,
}

impl Holder {
    fn code(self, base: &str) -> String {
        match self {
            Self::ExactReads => format!("breg.statistical-dataset.exact-reads-{base}"),
            Self::Reader | Self::Publisher => format!("breg.statistical-dataset.{base}"),
        }
    }

    fn independence_code(self, base: &str) -> String {
        match self {
            Self::ExactReads => self.code(base),
            Self::Reader | Self::Publisher => format!("breg.statistical-dataset.publisher-{base}"),
        }
    }

    fn path(self, root: &str) -> String {
        match self {
            Self::ExactReads => format!("{root}.exactReads.accessProfile"),
            Self::Reader | Self::Publisher => root.to_owned(),
        }
    }

    fn subject(self, profile: &str) -> String {
        match self {
            Self::ExactReads => format!("exactReads profile `{profile}`"),
            Self::Reader | Self::Publisher => format!("profile `{profile}`"),
        }
    }

    fn independence_subject(self, profile: &str) -> String {
        match self {
            Self::ExactReads => self.subject(profile),
            Self::Reader | Self::Publisher => format!("publisher `{profile}`"),
        }
    }

    fn independence_tail(self) -> &'static str {
        match self {
            Self::ExactReads => "or remove read-exact from the dataset",
            Self::Reader | Self::Publisher => "or serve the statistical dataset live only",
        }
    }
}

/// Which access profiles hold each operation on one statistical dataset.
#[derive(Default)]
struct DatasetGrants {
    read_live: BTreeSet<String>,
    read_exact: BTreeSet<String>,
    publish: BTreeSet<String>,
    read_releases: BTreeSet<String>,
    /// Profiles that name the dataset in more than one permission.
    repeated: BTreeSet<String>,
}

impl DatasetGrants {
    fn of(project: &RegistryProject, dataset: &str) -> Self {
        let mut grants = Self::default();
        for profile in &project.access_profiles {
            let mut named = false;
            for permission in &profile.permissions.datasets {
                if permission.dataset.as_str() != dataset {
                    continue;
                }
                if named {
                    grants.repeated.insert(profile.id.clone());
                }
                named = true;
                for operation in permission.operations.iter() {
                    match operation {
                        DatasetOperation::ReadLive => &mut grants.read_live,
                        DatasetOperation::ReadExact => &mut grants.read_exact,
                        DatasetOperation::Publish => &mut grants.publish,
                        DatasetOperation::ReadReleases => &mut grants.read_releases,
                    }
                    .insert(profile.id.clone());
                }
            }
        }
        grants
    }

    fn holders(&self) -> BTreeSet<String> {
        self.read_live
            .iter()
            .chain(&self.read_exact)
            .chain(&self.publish)
            .chain(&self.read_releases)
            .cloned()
            .collect()
    }
}

fn quoted(profiles: &BTreeSet<String>) -> String {
    profiles
        .iter()
        .map(|profile| format!("`{profile}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A dataset permission names a dataset the project declares.
fn validate_permission_datasets(project: &RegistryProject, errors: &mut Vec<Diagnostic>) {
    for profile in &project.access_profiles {
        for permission in &profile.permissions.datasets {
            if !project
                .statistical_datasets
                .iter()
                .any(|dataset| dataset.id == permission.dataset)
            {
                errors.push(Diagnostic::error(
                    "breg.access-profile.permission-dataset-unknown",
                    format!(
                        "project.accessProfiles[id={}].permissions.datasets[dataset={}].dataset",
                        profile.id, permission.dataset
                    ),
                    &format!(
                        "access profile `{}` holds a permission on statistical dataset `{}`, which the project does not declare; declare it under statisticalDatasets or remove the permission",
                        profile.id, permission.dataset
                    ),
                ));
            }
        }
    }
}

fn validate_population(
    source: &crate::contract::StatisticalDatasetSource,
    entity: &CompiledEntity,
    filter: Option<&FilterExpr>,
    root: &str,
    errors: &mut Vec<Diagnostic>,
) -> (BTreeSet<String>, BTreeMap<String, String>) {
    let Some(filter) = filter else {
        return (BTreeSet::new(), BTreeMap::new());
    };
    let mut fields = BTreeSet::new();
    let mut field_bindings = BTreeMap::new();
    validate_population_expr(
        source,
        entity,
        filter,
        root,
        &mut fields,
        &mut field_bindings,
        errors,
    );
    (fields, field_bindings)
}

fn validate_population_expr(
    source: &crate::contract::StatisticalDatasetSource,
    entity: &CompiledEntity,
    filter: &FilterExpr,
    root: &str,
    fields: &mut BTreeSet<String>,
    field_bindings: &mut BTreeMap<String, String>,
    errors: &mut Vec<Diagnostic>,
) {
    match filter {
        FilterExpr::Binary { left, right, .. } => {
            validate_population_expr(source, entity, left, root, fields, field_bindings, errors);
            validate_population_expr(source, entity, right, root, fields, field_bindings, errors);
        }
        FilterExpr::Not(filter) | FilterExpr::Group(filter) => {
            validate_population_expr(source, entity, filter, root, fields, field_bindings, errors);
        }
        FilterExpr::Predicate(predicate) => {
            let api_field = match predicate {
                FilterPredicate::Compare { field, .. }
                | FilterPredicate::In { field, .. }
                | FilterPredicate::Function { field, .. } => field.as_str(),
            };
            let Some((field_id, field_type)) = field_by_api_name(entity, api_field) else {
                errors.push(error(
                    "breg.statistical-dataset.population-field-unknown",
                    &format!("{root}.population"),
                    &source.id,
                    &format!(
                        "use a declared API field name instead of `{api_field}` in the population filter"
                    ),
                ));
                return;
            };
            fields.insert(field_id.to_owned());
            field_bindings.insert(api_field.to_owned(), field_id.to_owned());
            if !population_predicate_valid(predicate, field_type) {
                errors.push(error(
                    "breg.statistical-dataset.population-invalid",
                    &format!("{root}.population"),
                    &source.id,
                    &format!(
                        "use an operator and literal supported by population field `{api_field}`"
                    ),
                ));
            }
        }
    }
}

fn field_by_api_name<'a>(
    entity: &'a CompiledEntity,
    api_name: &str,
) -> Option<(&'a str, &'a FieldTypeSource)> {
    entity
        .stored_fields
        .iter()
        .find(|field| field.logical.api_name == api_name)
        .map(|field| (field.logical.id.as_str(), &field.logical.field_type))
        .or_else(|| {
            entity
                .derived_fields
                .values()
                .find(|field| field.logical.api_name == api_name)
                .map(|field| (field.logical.id.as_str(), &field.logical.field_type))
        })
}

fn population_predicate_valid(predicate: &FilterPredicate, field_type: &FieldTypeSource) -> bool {
    match predicate {
        FilterPredicate::Compare { op, literal, .. } => {
            if matches!(literal, Literal::Null) {
                return matches!(op, ComparisonOp::Eq | ComparisonOp::Ne);
            }
            let operator_valid = matches!(op, ComparisonOp::Eq | ComparisonOp::Ne)
                || matches!(
                    field_type,
                    FieldTypeSource::Int64
                        | FieldTypeSource::Decimal { .. }
                        | FieldTypeSource::Date
                        | FieldTypeSource::Timestamp
                );
            operator_valid && population_literal_valid(literal, field_type)
        }
        FilterPredicate::In { values, .. } => {
            // The runtime refuses a list that repeats a value, comparing the
            // text of each literal.
            let unique = values
                .iter()
                .filter_map(population_literal_text)
                .collect::<BTreeSet<_>>();
            !values.is_empty()
                && values
                    .iter()
                    .all(|literal| !matches!(literal, Literal::Null))
                && values
                    .iter()
                    .all(|literal| population_literal_valid(literal, field_type))
                && unique.len() == values.len()
        }
        FilterPredicate::Function { literal, .. } => {
            let Literal::String(value) = literal else {
                return false;
            };
            crate::data::valid_text_search_term(value, field_type)
        }
    }
}

fn population_literal_text(literal: &Literal) -> Option<String> {
    match literal {
        Literal::Boolean(value) => Some(value.to_string()),
        Literal::String(value) | Literal::Integer(value) | Literal::Decimal(value) => {
            Some(value.clone())
        }
        Literal::Null => None,
    }
}

fn population_literal_valid(literal: &Literal, field_type: &FieldTypeSource) -> bool {
    let Some(text) = population_literal_text(literal) else {
        return false;
    };
    let value = match field_type {
        FieldTypeSource::Boolean => match text.as_str() {
            "true" => serde_json::Value::Bool(true),
            "false" => serde_json::Value::Bool(false),
            _ => return false,
        },
        FieldTypeSource::Int64 => match text.parse::<i64>() {
            Ok(value) if value.to_string() == text => serde_json::Value::Number(value.into()),
            _ => return false,
        },
        _ => serde_json::Value::String(text),
    };
    crate::data::validate_field_value(crate::data::FieldValue::Json(&value), field_type)
}

fn field<'a>(entity: &'a CompiledEntity, id: &str) -> Option<(&'a FieldTypeSource, bool)> {
    entity
        .fields
        .get(id)
        .map(|field| (&field.field_type, field.required))
        .or_else(|| {
            entity
                .derived_fields
                .get(id)
                .map(|field| (&field.logical.field_type, false))
        })
}

fn granularity(value: StatisticalPeriodGranularitySource) -> PeriodGranularity {
    match value {
        StatisticalPeriodGranularitySource::Day => PeriodGranularity::Day,
        StatisticalPeriodGranularitySource::Month => PeriodGranularity::Month,
        StatisticalPeriodGranularitySource::Quarter => PeriodGranularity::Quarter,
        StatisticalPeriodGranularitySource::Year => PeriodGranularity::Year,
    }
}

fn valid_period_code(value: &str, granularity: PeriodGranularity) -> bool {
    // Admission must match runtime period bounds, including the exclusive end.
    period_for_code(granularity, value, chrono::NaiveDate::MIN).is_ok()
}

fn error(code: &str, path: &str, dataset: &str, fix: &str) -> Diagnostic {
    Diagnostic::error(
        code,
        path,
        &format!("statistical dataset `{dataset}` is invalid; {fix}"),
    )
}

/// What a released sum adds to the definition digest: who a value belongs to.
/// The dominance percentage is the publisher's secret and stays out, so
/// changing it never re-keys a release.
fn sum_definition(sums: Option<&SumDisclosure>) -> Option<serde_json::Value> {
    sums.map(|sums| json!(sums.contributor))
}

/// A dataset that releases sums: its unit and the fields it sums.
struct SumRelease {
    id: String,
    unit: String,
    sum_fields: BTreeSet<String>,
}

/// The contributor and dominance rules of a dataset that releases sums under
/// minimum-count-and-rounding: members present exactly when it does, a
/// contributor field the publisher reads, sums that cannot go negative, and no
/// day periods. Returns the compiled contributor when one is declared.
fn compile_sum_disclosure_rules(
    source: &crate::contract::StatisticalDatasetSource,
    unit: &CompiledEntity,
    grants: &DatasetGrants,
    sum_release: bool,
    root: &str,
    errors: &mut Vec<Diagnostic>,
) -> Option<Contributor> {
    let Some(StatisticalDisclosureSource::MinimumCountAndRounding {
        contributor,
        dominance_percent,
        ..
    }) = source.disclosure.as_ref()
    else {
        return None;
    };
    let path = format!("{root}.disclosure");
    for (present, member, name) in [
        (contributor.is_some(), "contributor", "contributor"),
        (dominance_percent.is_some(), "dominancePercent", "dominance"),
    ] {
        if sum_release && !present {
            errors.push(error(
                &format!("breg.statistical-dataset.disclosure-{name}-missing"),
                &path,
                &source.id,
                &format!("declare {member}: a release of sums needs it, and it has no default"),
            ));
        } else if !sum_release && present {
            errors.push(error(
                &format!("breg.statistical-dataset.disclosure-{name}-unused"),
                &path,
                &source.id,
                &format!(
                    "remove {member}: it applies to a dataset that declares a sum and has a publisher"
                ),
            ));
        }
    }
    if !sum_release {
        return None;
    }
    let compiled = contributor.as_ref().map(|contributor| match contributor {
        StatisticalContributorSource::Field { field } => Contributor::Field {
            field: field.clone(),
        },
        StatisticalContributorSource::EachRecord {} => Contributor::EachRecord,
    });
    if let Some(Contributor::Field { field: field_id }) = &compiled {
        let field_path = format!("{path}.contributor.field");
        match field(unit, field_id) {
            None => errors.push(error(
                "breg.statistical-dataset.disclosure-contributor-field",
                &field_path,
                &source.id,
                &format!(
                    "contributor field `{field_id}` does not exist on unit record `{}`; name a reference field of it",
                    unit.id
                ),
            )),
            Some((FieldTypeSource::Reference { .. }, _)) => {
                for publisher in &grants.publish {
                    // A publisher with no record grant on the unit is reported
                    // by the count grant check; this rule names only a grant
                    // that leaves the contributor field unreadable.
                    let readable = unit
                        .access_profiles
                        .get(publisher)
                        .is_none_or(|grant| grant.readable_fields.contains(field_id));
                    if !readable {
                        errors.push(error(
                            "breg.statistical-dataset.disclosure-contributor-field",
                            &field_path,
                            &source.id,
                            &format!(
                                "add contributor field `{field_id}` to readableFields for publisher `{publisher}` on `{}`, which counts contributors without exposing them",
                                unit.id
                            ),
                        ));
                    }
                }
            }
            Some(_) => errors.push(error(
                "breg.statistical-dataset.disclosure-contributor-field",
                &field_path,
                &source.id,
                &format!(
                    "contributor field `{field_id}` must be a reference field; name the field that says whose value each record is"
                ),
            )),
        }
    }
    for (index, measure) in source.measures.iter().enumerate() {
        let StatisticalMeasureSource::Sum {
            field: field_id, ..
        } = measure
        else {
            continue;
        };
        if let Some((FieldTypeSource::Decimal { minimum, .. }, _)) = field(unit, field_id) {
            let non_negative = minimum
                .as_deref()
                .is_some_and(|minimum| !minimum.trim_start().starts_with('-'));
            if !non_negative {
                errors.push(error(
                    "breg.statistical-dataset.sum-release-negative-values",
                    &format!("{root}.measures[{index}]"),
                    &source.id,
                    &format!(
                        "declare a minimum of 0 or more on decimal field `{field_id}`: a released sum of values that may be negative can hide a contributor behind an offsetting one"
                    ),
                ));
            }
        }
    }
    let granularity = match &source.period {
        StatisticalPeriodSource::Flow { granularity, .. }
        | StatisticalPeriodSource::Stock { granularity, .. } => *granularity,
    };
    if granularity == StatisticalPeriodGranularitySource::Day {
        errors.push(error(
            "breg.statistical-dataset.sum-release-day-granularity",
            &format!("{root}.period"),
            &source.id,
            "release sums by month, quarter or year: a day holds too few contributors to protect",
        ));
    }
    compiled
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sums(contributor: Contributor, dominance_percent: u8) -> SumDisclosure {
        SumDisclosure {
            contributor,
            dominance_percent,
            integer_sums: BTreeSet::new(),
        }
    }

    fn field(name: &str) -> Contributor {
        Contributor::Field {
            field: name.to_owned(),
        }
    }

    #[test]
    fn the_contributor_joins_the_definition_and_the_dominance_percent_does_not() {
        assert_eq!(sum_definition(None), None);
        let owner = sum_definition(Some(&sums(field("owner"), 15)));
        assert_eq!(owner, sum_definition(Some(&sums(field("owner"), 90))));
        assert_ne!(owner, sum_definition(Some(&sums(field("agent"), 15))));
        assert_ne!(
            owner,
            sum_definition(Some(&sums(Contributor::EachRecord, 15)))
        );
    }

    #[test]
    fn a_rounded_integer_sum_is_bounded_one_digit_wider_than_its_exact_text() {
        // 99,999 rounded to a base of 10 is 100,000: rounding up carries into a
        // new digit, so the longest rounded sum is one character longer.
        assert_eq!(format!("{}", (99_999_u64 + 5) / 10 * 10).len(), 6);
        let measures = vec![
            Measure::Sum {
                id: "units-sum".to_owned(),
                field: "units".to_owned(),
                scale: 0,
            },
            Measure::Sum {
                id: "area-sum".to_owned(),
                field: "area".to_owned(),
                scale: 2,
            },
        ];
        let field_type = |field: &str| match field {
            "units" => Some(FieldTypeSource::Int64),
            "area" => Some(FieldTypeSource::Decimal {
                precision: 10,
                scale: 2,
                minimum: None,
                maximum: None,
            }),
            _ => None,
        };
        let exact = measures
            .iter()
            .filter_map(|measure| maximum_measure_characters(measure, &measures, &field_type))
            .max();
        assert_eq!(
            longest_released_decimal(&measures, &field_type, None),
            exact
        );
        let integer = SumDisclosure {
            contributor: Contributor::EachRecord,
            dominance_percent: 50,
            integer_sums: BTreeSet::from(["units-sum".to_owned()]),
        };
        let units = maximum_measure_characters(&measures[0], &measures, &field_type)
            .expect("an int64 sum is bounded");
        let area = maximum_measure_characters(&measures[1], &measures, &field_type)
            .expect("a decimal sum is bounded");
        assert_eq!(
            longest_released_decimal(&measures, &field_type, Some(&integer)),
            Some((units + 1).max(area)),
            "only the rounded integer sum gains a digit; a decimal sum is exact"
        );
    }
}
