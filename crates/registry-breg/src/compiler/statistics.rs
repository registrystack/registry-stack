// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_canonical_json::canonicalize_json;
use serde::Serialize;
use serde_json::json;

use crate::contract::{
    AccessProfileSource, FieldTypeSource, Operation, RegistryProject,
    StatisticalPeriodGranularitySource, StatisticalPeriodSource, StatisticalValiditySource,
    MAX_EXACT_JSON_INTEGER,
};
use crate::diagnostics::Diagnostic;
use crate::model::{
    CompiledEntity, CompiledStatisticalDataset, CompiledStatisticalDimension,
    CompiledStatisticalDimensionDomain, CompiledStatisticalPeriod, CompiledStatisticalReleases,
    CompiledStatisticalValidity,
};
use crate::query::{ComparisonOp, FilterExpr, FilterPredicate, Literal};
use crate::statistics::{period_for_code, DisclosureParameters, PeriodGranularity};

pub const MAX_STATISTICAL_CELLS_PER_PERIOD: usize = 10_000;

pub(super) fn compile(
    project: &RegistryProject,
    entities: &BTreeMap<String, CompiledEntity>,
) -> Result<BTreeMap<String, CompiledStatisticalDataset>, Vec<Diagnostic>> {
    let mut errors = Vec::new();
    let mut compiled = BTreeMap::new();
    let mut seen = BTreeSet::new();
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
        validate_referenced_fields(source, unit, &referenced_fields, &root, &mut errors);

        let live_profiles = unique_profiles(
            &source.live,
            &format!("{root}.live[]"),
            &source.id,
            "list each live profile once",
            &mut errors,
        );
        let releases = source.releases.as_ref().map(|release| {
            let readers = unique_profiles(
                &release.readers,
                &format!("{root}.releases.readers[]"),
                &source.id,
                "list each release reader once",
                &mut errors,
            );
            if readers.is_empty() {
                errors.push(error(
                    "breg.statistical-dataset.releases-readers-empty",
                    &format!("{root}.releases.readers"),
                    &source.id,
                    "name at least one release reader profile",
                ));
            }
            CompiledStatisticalReleases {
                publisher: release.publisher.clone(),
                readers,
            }
        });
        if live_profiles.is_empty() && releases.is_none() {
            errors.push(error(
                "breg.statistical-dataset.grants-empty",
                &root,
                &source.id,
                "declare live profiles, releases, or both",
            ));
        }

        let mut granted = live_profiles.clone();
        if let Some(releases) = &releases {
            granted.insert(releases.publisher.clone());
            granted.extend(releases.readers.iter().cloned());
        }
        for profile in &granted {
            validate_named_profile(project, profile, &source.id, &root, &mut errors);
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
        for profile in &live_profiles {
            validate_count_grant(
                source,
                unit,
                profile,
                &referenced_fields,
                &root,
                &mut errors,
            );
        }
        if let Some(releases) = &releases {
            validate_count_grant(
                source,
                unit,
                &releases.publisher,
                &referenced_fields,
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
                "declare minimumCount and roundingBase",
            ));
        }
        if disclosure_source.is_none_or(|disclosure| disclosure.minimum_count < 2) {
            errors.push(error(
                "breg.statistical-dataset.disclosure-minimum-count",
                &format!("{root}.disclosure.minimumCount"),
                &source.id,
                "set minimumCount to at least 2",
            ));
        }
        if disclosure_source
            .is_some_and(|disclosure| disclosure.minimum_count > MAX_EXACT_JSON_INTEGER)
        {
            errors.push(error(
                "breg.statistical-dataset.disclosure-minimum-count-exceeded",
                &format!("{root}.disclosure.minimumCount"),
                &source.id,
                &format!("set minimumCount to at most {MAX_EXACT_JSON_INTEGER}"),
            ));
        }
        if disclosure_source.is_none_or(|disclosure| disclosure.rounding_base < 2) {
            errors.push(error(
                "breg.statistical-dataset.disclosure-rounding-base",
                &format!("{root}.disclosure.roundingBase"),
                &source.id,
                "set roundingBase to at least 2",
            ));
        }
        if disclosure_source
            .is_some_and(|disclosure| disclosure.rounding_base > MAX_EXACT_JSON_INTEGER)
        {
            errors.push(error(
                "breg.statistical-dataset.disclosure-rounding-base-exceeded",
                &format!("{root}.disclosure.roundingBase"),
                &source.id,
                &format!("set roundingBase to at most {MAX_EXACT_JSON_INTEGER}"),
            ));
        }
        let cell_count = dimensions.iter().try_fold(1_usize, |cells, dimension| {
            cells.checked_mul(dimension.codes.len() + usize::from(dimension.include_unknown) + 1)
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
                &root,
                &mut errors,
            );
        }
        let Some(period) = period else {
            continue;
        };
        let Some(disclosure_source) = disclosure_source.filter(|disclosure| {
            (2..=MAX_EXACT_JSON_INTEGER).contains(&disclosure.minimum_count)
                && (2..=MAX_EXACT_JSON_INTEGER).contains(&disclosure.rounding_base)
        }) else {
            continue;
        };
        let disclosure = DisclosureParameters {
            minimum_count: disclosure_source.minimum_count,
            rounding_base: disclosure_source.rounding_base,
        };
        let definition_digest = definition_digest(
            source,
            &period,
            &dimensions,
            &disclosure,
            DefinitionDependencies {
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
                    disclosure,
                    &definition_digest,
                    cells,
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
            continue;
        }
        compiled.insert(
            source.id.to_string(),
            CompiledStatisticalDataset {
                id: source.id.to_string(),
                unit_entity_id: source.unit.clone(),
                population: source.population.clone(),
                period,
                dimensions,
                disclosure,
                access_profiles,
                live_profiles,
                releases,
                dependency_entities,
                referenced_fields,
                evaluation_date_dependent,
                definition_digest,
            },
        );
    }
    if errors.is_empty() {
        Ok(compiled)
    } else {
        Err(errors)
    }
}

fn maximum_release_document_bytes(
    source: &crate::contract::StatisticalDatasetSource,
    period: &CompiledStatisticalPeriod,
    dimensions: &[CompiledStatisticalDimension],
    disclosure: DisclosureParameters,
    definition_digest: &str,
    cell_count: usize,
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
            "measure": "count",
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
        "disclosure": {
            "method": "minimum-count-and-rounding",
            "minimumCount": disclosure.minimum_count,
            "roundingBase": disclosure.rounding_base,
            "roundingRule": "nearest-multiple-halves-up",
            "totals": "rounded-independently",
        },
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
    let empty_cell = canonicalize_json(&json!({
        "period": "9999-12-31",
        "dimensions": {},
        "value": MAX_EXACT_JSON_INTEGER,
        "status": "suppressed",
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
            .iter()
            .filter(|permission| !permission.entity.is_empty())
            .filter_map(|permission| {
                entities.get(&permission.entity).map(|entity| {
                    crate::contract::CompiledTaskGrantPermissionSource {
                        collection: entity.route.clone(),
                        operations: permission.operations.clone().into(),
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
        default: profile.default,
        actor_kind: profile.actor_kind,
        requester_clients: profile.requester_clients.clone(),
        task_grant,
        principal_claim: profile.principal_claim.clone(),
        required_scopes: profile.required_scopes.clone(),
        required_purposes: profile.required_purposes.clone(),
        operations: Default::default(),
        readable_fields: Default::default(),
        readable_request_fields: Default::default(),
        writable_fields: Default::default(),
        filterable_fields: Default::default(),
        sortable_fields: Default::default(),
        spatial_queries: None,
        row_boundaries: Vec::new(),
        membership_boundaries: Vec::new(),
        require_consent: Vec::new(),
        request_visibility: None,
        lookups: Vec::new(),
        read_paths: Vec::new(),
        apply_targets: Vec::new(),
        submitter_targets: Default::default(),
        request_presence: Vec::new(),
        allow_count: false,
        revision_access: false,
        provenance_fields: Vec::new(),
        allow_data_export: false,
    }
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
                        })
                }
                StatisticalValiditySource::Fields(validity) => {
                    Some(CompiledStatisticalValidity::Fields {
                        from: validity.from.clone(),
                        until: validity.until.clone(),
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
        if matches!(field_id.as_str(), "period" | "value" | "status") {
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

fn validate_named_profile(
    project: &RegistryProject,
    profile_id: &str,
    dataset: &str,
    root: &str,
    errors: &mut Vec<Diagnostic>,
) {
    if !project
        .access_profiles
        .iter()
        .any(|profile| profile.id == profile_id)
    {
        errors.push(error(
            "breg.statistical-dataset.profile-unknown",
            root,
            dataset,
            &format!("declare access profile `{profile_id}`"),
        ));
    }
}

fn validate_count_grant(
    source: &crate::contract::StatisticalDatasetSource,
    unit: &CompiledEntity,
    profile_id: &str,
    referenced_fields: &BTreeSet<String>,
    root: &str,
    errors: &mut Vec<Diagnostic>,
) {
    let Some(grant) = unit.access_profiles.get(profile_id) else {
        errors.push(error(
            "breg.statistical-dataset.count-grant-missing",
            root,
            &source.id,
            &format!(
                "grant profile `{profile_id}` list access to unit entity `{}`",
                unit.id
            ),
        ));
        return;
    };
    if !grant.operations.contains(&Operation::List) {
        errors.push(error(
            "breg.statistical-dataset.count-grant-list-required",
            root,
            &source.id,
            &format!(
                "grant profile `{profile_id}` the list operation on `{}`",
                unit.id
            ),
        ));
    }
    if !grant.allow_count {
        errors.push(error(
            "breg.statistical-dataset.count-grant-count-required",
            root,
            &source.id,
            &format!("set allowCount for profile `{profile_id}` on `{}`", unit.id),
        ));
    }
    if !grant.require_consent.is_empty() {
        errors.push(error(
            "breg.statistical-dataset.count-grant-consent",
            root,
            &source.id,
            &format!("remove requireConsent from profile `{profile_id}` for dataset counts"),
        ));
    }
    for field in referenced_fields {
        if !grant.filterable_fields.contains(field) {
            errors.push(error(
                "breg.statistical-dataset.count-grant-field-not-filterable",
                root,
                &source.id,
                &format!("add field `{field}` to filterableFields for profile `{profile_id}`"),
            ));
        }
    }
}

fn validate_publisher_independence(
    source: &crate::contract::StatisticalDatasetSource,
    entities: &BTreeMap<String, CompiledEntity>,
    dependency_entities: &BTreeSet<String>,
    publisher: &str,
    root: &str,
    errors: &mut Vec<Diagnostic>,
) {
    for entity_id in dependency_entities {
        let entity = &entities[entity_id];
        if entity
            .access_requirements
            .as_ref()
            .is_some_and(|requirements| !requirements.row_boundaries.is_empty())
        {
            errors.push(error(
                "breg.statistical-dataset.publisher-entity-row-boundary",
                root,
                &source.id,
                &format!(
                    "remove accessRequirements.rowBoundaries from dependency entity `{entity_id}` or serve the statistical dataset live only"
                ),
            ));
        }
        let Some(grant) = entity.access_profiles.get(publisher) else {
            errors.push(error(
                "breg.statistical-dataset.publisher-dependency-grant-missing",
                root,
                &source.id,
                &format!("grant publisher `{publisher}` access to dependency entity `{entity_id}`"),
            ));
            continue;
        };
        if dependency_select_operations(grant).is_empty() {
            errors.push(error(
                "breg.statistical-dataset.publisher-dependency-read-required",
                root,
                &source.id,
                &format!(
                    "grant publisher `{publisher}` get, lookup, list, batch, revisions, or snapshot access to dependency entity `{entity_id}`"
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
        } else if grant.request_visibility.is_some() {
            Some("requestVisibility")
        } else {
            None
        };
        if let Some(member) = violation {
            errors.push(error(
                "breg.statistical-dataset.publisher-caller-dependent",
                root,
                &source.id,
                &format!(
                    "remove `{member}` from publisher `{publisher}` on dependency entity `{entity_id}` or serve the statistical dataset live only"
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
    disclosure: &DisclosureParameters,
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
        request_visibility: serde_json::Value,
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
                        request_visibility: json!(profile.request_visibility),
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
    let value = json!({
        "unit": source.unit,
        "population": source.population,
        "populationFieldBindings": dependencies.population_field_bindings,
        "referencedFieldDefinitions": referenced_field_definitions,
        "period": period_definition,
        "dimensions": dimensions,
        "disclosure": disclosure,
        "derived": derived,
        "publisherVisibility": visibility,
    });
    let bytes = canonicalize_json(&value).expect("statistical dataset definition canonicalizes");
    super::sha256_hex(&bytes)
}

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

fn unique_profiles(
    values: &[String],
    path: &str,
    dataset: &str,
    fix: &str,
    errors: &mut Vec<Diagnostic>,
) -> BTreeSet<String> {
    let profiles = values.iter().cloned().collect::<BTreeSet<_>>();
    if profiles.len() != values.len() {
        errors.push(error(
            "breg.statistical-dataset.profile-duplicate",
            path,
            dataset,
            fix,
        ));
    }
    profiles
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

fn error(code: &'static str, path: &str, dataset: &str, fix: &str) -> Diagnostic {
    Diagnostic::error(
        code,
        path,
        &format!("statistical dataset `{dataset}` is invalid; {fix}"),
    )
}
