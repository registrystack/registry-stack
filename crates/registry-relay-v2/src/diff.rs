// SPDX-License-Identifier: Apache-2.0
//! Authoritative semantic, disclosure, and security change classification.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::contract::Visibility;
use crate::model::{
    CompiledAccess, CompiledOperation, CompiledRegistry, CompiledResource,
    CompiledStatisticalDataset,
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChangeImpactReport {
    pub previous_revision: String,
    pub current_revision: String,
    pub changes: Vec<ContractChange>,
}

impl ChangeImpactReport {
    pub fn has_disclosure_or_access_widening(&self) -> bool {
        self.changes
            .iter()
            .any(|change| change.impact == ChangeImpact::Widening)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ContractChange {
    pub class: ChangeClass,
    pub impact: ChangeImpact,
    pub location: String,
    pub description: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeImpact {
    Informational,
    Narrowing,
    Widening,
    Breaking,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeClass {
    ResourceAdded,
    ResourceRemoved,
    StatisticalDatasetAdded,
    StatisticalDatasetRemoved,
    StatisticalDatasetChanged,
    PropertyAdded,
    PropertyRemoved,
    PropertyMeaningChanged,
    TransformationChanged,
    HandlingRelaxed,
    HandlingTightened,
    OperationAdded,
    OperationRemoved,
    RepresentationAdded,
    RepresentationRemoved,
    DefaultRepresentationChanged,
    DisclosureExpanded,
    DisclosureNarrowed,
    DisclosureProfileChanged,
    FilterAdded,
    FilterRemoved,
    FilterChanged,
    UnfilteredEnabled,
    UnfilteredDisabled,
    SelectorChanged,
    OrderingChanged,
    PaginationExpanded,
    PaginationNarrowed,
    RequestBoundExpanded,
    RequestBoundNarrowed,
    ScopeChanged,
    PurposeExpanded,
    PurposeNarrowed,
    RowBindingRemoved,
    RowBindingAdded,
    RowBindingChanged,
    SourceViewChanged,
    SourceSchemaChanged,
    RecordContextChanged,
    MetadataVisibilityRelaxed,
    MetadataVisibilityTightened,
    SemanticAlignmentChanged,
    ClassificationChanged,
    ClassificationReviewChanged,
    ProcessingChanged,
    GovernedFileChanged,
}

pub fn diff_registries(
    previous: &CompiledRegistry,
    current: &CompiledRegistry,
) -> ChangeImpactReport {
    let mut changes = Vec::new();
    let previous_sources = previous
        .sources
        .iter()
        .map(|source| (source.id.as_str(), source))
        .collect::<BTreeMap<_, _>>();
    let current_sources = current
        .sources
        .iter()
        .map(|source| (source.id.as_str(), source))
        .collect::<BTreeMap<_, _>>();
    for id in previous_sources
        .keys()
        .chain(current_sources.keys())
        .collect::<BTreeSet<_>>()
    {
        match (previous_sources.get(*id), current_sources.get(*id)) {
            (Some(before), Some(after))
                if before.profile != after.profile
                    || before.expected_schema_fingerprint != after.expected_schema_fingerprint =>
            {
                push(
                    &mut changes,
                    ChangeClass::SourceSchemaChanged,
                    ChangeImpact::Breaking,
                    format!("sources.{id}"),
                    "the governed source profile or expected schema fingerprint changed",
                );
            }
            (None, Some(_)) | (Some(_), None) => push(
                &mut changes,
                ChangeClass::SourceSchemaChanged,
                ChangeImpact::Breaking,
                format!("sources.{id}"),
                "a governed source binding was added or removed",
            ),
            _ => {}
        }
    }
    let previous_resources = resource_map(previous);
    let current_resources = resource_map(current);

    for id in previous_resources
        .keys()
        .chain(current_resources.keys())
        .collect::<BTreeSet<_>>()
    {
        match (previous_resources.get(*id), current_resources.get(*id)) {
            (None, Some(_)) => push(
                &mut changes,
                ChangeClass::ResourceAdded,
                ChangeImpact::Widening,
                format!("resources.{id}"),
                "a published resource was added",
            ),
            (Some(_), None) => push(
                &mut changes,
                ChangeClass::ResourceRemoved,
                ChangeImpact::Breaking,
                format!("resources.{id}"),
                "a published resource was removed",
            ),
            (Some(before), Some(after)) => diff_resource(before, after, &mut changes),
            (None, None) => unreachable!(),
        }
    }

    let previous_statistics = statistical_dataset_map(previous);
    let current_statistics = statistical_dataset_map(current);
    for id in previous_statistics
        .keys()
        .chain(current_statistics.keys())
        .collect::<BTreeSet<_>>()
    {
        match (previous_statistics.get(*id), current_statistics.get(*id)) {
            (None, Some(_)) => push(
                &mut changes,
                ChangeClass::StatisticalDatasetAdded,
                ChangeImpact::Widening,
                format!("statisticalDatasets.{id}"),
                "a published statistical dataset was added",
            ),
            (Some(_), None) => push(
                &mut changes,
                ChangeClass::StatisticalDatasetRemoved,
                ChangeImpact::Breaking,
                format!("statisticalDatasets.{id}"),
                "a published statistical dataset was removed",
            ),
            (Some(before), Some(after)) => diff_statistical_dataset(before, after, &mut changes),
            (None, None) => unreachable!(),
        }
    }

    diff_visibility(previous, current, &mut changes);
    if previous.semantic_alignments != current.semantic_alignments {
        push(
            &mut changes,
            ChangeClass::SemanticAlignmentChanged,
            ChangeImpact::Informational,
            "semantics.alignments".into(),
            "the pinned external semantic alignment set changed",
        );
    }
    if previous.classification_review != current.classification_review {
        push(
            &mut changes,
            ChangeClass::ClassificationReviewChanged,
            ChangeImpact::Breaking,
            "classifications.provenanceRef".into(),
            "the reviewed classification binding, inventory digest, method, or identification evidence changed",
        );
    }
    let before_governed = previous
        .governed_files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    let after_governed = current
        .governed_files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    for path in before_governed
        .keys()
        .chain(after_governed.keys())
        .collect::<BTreeSet<_>>()
    {
        if before_governed.get(*path) != after_governed.get(*path) {
            push(
                &mut changes,
                ChangeClass::GovernedFileChanged,
                ChangeImpact::Breaking,
                format!("governedFiles.{path}"),
                "a governed sidecar digest or referenced role changed",
            );
        }
    }
    changes.sort_by(|left, right| {
        left.location
            .cmp(&right.location)
            .then(left.class.cmp(&right.class))
            .then(left.impact.cmp(&right.impact))
    });
    ChangeImpactReport {
        previous_revision: previous.contract_revision.clone(),
        current_revision: current.contract_revision.clone(),
        changes,
    }
}

fn resource_map(registry: &CompiledRegistry) -> BTreeMap<&str, &CompiledResource> {
    registry
        .resources
        .iter()
        .map(|resource| (resource.id.as_str(), resource))
        .collect()
}

fn statistical_dataset_map(
    registry: &CompiledRegistry,
) -> BTreeMap<&str, &CompiledStatisticalDataset> {
    registry
        .statistical_datasets
        .iter()
        .map(|dataset| (dataset.id.as_str(), dataset))
        .collect()
}

fn diff_statistical_dataset(
    previous: &CompiledStatisticalDataset,
    current: &CompiledStatisticalDataset,
    changes: &mut Vec<ContractChange>,
) {
    let root = format!("statisticalDatasets.{}", current.id);
    if previous.source != current.source || previous.view != current.view {
        push(
            changes,
            ChangeClass::SourceViewChanged,
            ChangeImpact::Breaking,
            format!("{root}.source"),
            "the reviewed statistical source or view changed",
        );
    }
    if previous.title != current.title
        || previous.description != current.description
        || previous.release_at != current.release_at
        || previous.sdmx != current.sdmx
        || previous.dimensions != current.dimensions
        || previous.time != current.time
        || previous.measure != current.measure
        || previous.attributes != current.attributes
    {
        push(
            changes,
            ChangeClass::StatisticalDatasetChanged,
            ChangeImpact::Breaking,
            root.clone(),
            "statistical meaning, components, publication facts, or generated binding identity changed",
        );
    }
    if previous.column_accounting != current.column_accounting {
        push(
            changes,
            ChangeClass::ClassificationChanged,
            ChangeImpact::Breaking,
            format!("{root}.sourceColumnClassifications"),
            "effective classifications or uses of reviewed statistical columns changed",
        );
    }
    if previous.processing_descriptions != current.processing_descriptions {
        push(
            changes,
            ChangeClass::ProcessingChanged,
            ChangeImpact::Breaking,
            format!("{root}.processingDescriptions"),
            "the reviewed statistical processing description set changed",
        );
    }
    match (previous.allow_unfiltered, current.allow_unfiltered) {
        (false, true) => push(
            changes,
            ChangeClass::UnfilteredEnabled,
            ChangeImpact::Widening,
            format!("{root}.query.allowUnfiltered"),
            "unfiltered statistical access was enabled",
        ),
        (true, false) => push(
            changes,
            ChangeClass::UnfilteredDisabled,
            ChangeImpact::Narrowing,
            format!("{root}.query.allowUnfiltered"),
            "unfiltered statistical access was disabled",
        ),
        _ => {}
    }
    for (name, before, after) in [
        (
            "maximumObservations",
            previous.maximum_observations,
            current.maximum_observations,
        ),
        (
            "maximumOffset",
            previous.maximum_offset,
            current.maximum_offset,
        ),
    ] {
        if before != after {
            let expanded = after > before;
            push(
                changes,
                if expanded {
                    ChangeClass::RequestBoundExpanded
                } else {
                    ChangeClass::RequestBoundNarrowed
                },
                if expanded {
                    ChangeImpact::Widening
                } else {
                    ChangeImpact::Narrowing
                },
                format!("{root}.query.{name}"),
                "a statistical query bound changed",
            );
        }
    }
    diff_access(&previous.access, &current.access, &root, changes);
}

fn diff_resource(
    previous: &CompiledResource,
    current: &CompiledResource,
    changes: &mut Vec<ContractChange>,
) {
    let root = format!("resources.{}", current.id);
    if previous.source != current.source || previous.view != current.view {
        push(
            changes,
            ChangeClass::SourceViewChanged,
            ChangeImpact::Breaking,
            format!("{root}.source"),
            "the reviewed source or view changed",
        );
    }
    if previous.record_context != current.record_context {
        push(
            changes,
            ChangeClass::RecordContextChanged,
            ChangeImpact::Breaking,
            format!("{root}.recordContext"),
            "a Registry Core binding or reference changed",
        );
    }
    if previous.column_accounting != current.column_accounting {
        push(
            changes,
            ChangeClass::ClassificationChanged,
            ChangeImpact::Breaking,
            format!("{root}.sourceColumnClassifications"),
            "effective classifications or uses of reviewed source columns changed",
        );
    }
    if previous.processing_descriptions != current.processing_descriptions {
        push(
            changes,
            ChangeClass::ProcessingChanged,
            ChangeImpact::Breaking,
            format!("{root}.processingDescriptions"),
            "the reviewed processing description set changed",
        );
    }

    let before_properties = previous
        .properties
        .iter()
        .map(|property| (property.name.as_str(), property))
        .collect::<BTreeMap<_, _>>();
    let after_properties = current
        .properties
        .iter()
        .map(|property| (property.name.as_str(), property))
        .collect::<BTreeMap<_, _>>();
    for name in before_properties
        .keys()
        .chain(after_properties.keys())
        .collect::<BTreeSet<_>>()
    {
        let location = format!("{root}.properties.{name}");
        match (before_properties.get(*name), after_properties.get(*name)) {
            (None, Some(_)) => push(
                changes,
                ChangeClass::PropertyAdded,
                ChangeImpact::Widening,
                location,
                "a publishable property was added",
            ),
            (Some(_), None) => push(
                changes,
                ChangeClass::PropertyRemoved,
                ChangeImpact::Breaking,
                location,
                "a publishable property was removed",
            ),
            (Some(before), Some(after)) => {
                if before.semantic_iri != after.semantic_iri
                    || before.data_type != after.data_type
                    || before.codelist != after.codelist
                    || before.source_column != after.source_column
                    || before.source_required != after.source_required
                {
                    push(
                        changes,
                        ChangeClass::PropertyMeaningChanged,
                        ChangeImpact::Breaking,
                        location.clone(),
                        "a property binding, meaning, datatype, codelist, or requiredness changed",
                    );
                }
                if before.transform != after.transform {
                    push(
                        changes,
                        ChangeClass::TransformationChanged,
                        ChangeImpact::Breaking,
                        format!("{location}.transform"),
                        "the closed transformation kind or parameters changed",
                    );
                }
                let before_handling = before.classification.handling;
                let after_handling = after.classification.handling;
                if after_handling < before_handling {
                    push(
                        changes,
                        ChangeClass::HandlingRelaxed,
                        ChangeImpact::Widening,
                        format!("{location}.classification.handling"),
                        "technical handling became less restrictive",
                    );
                } else if after_handling > before_handling {
                    push(
                        changes,
                        ChangeClass::HandlingTightened,
                        ChangeImpact::Narrowing,
                        format!("{location}.classification.handling"),
                        "technical handling became more restrictive",
                    );
                }
                if classification_context(&before.classification)
                    != classification_context(&after.classification)
                {
                    push(
                        changes,
                        ChangeClass::ClassificationChanged,
                        ChangeImpact::Breaking,
                        format!("{location}.classification"),
                        "privacy, institutional, review, scheme, version, or provenance classification changed",
                    );
                }
            }
            (None, None) => unreachable!(),
        }
    }

    let before_operations = operation_map(previous);
    let after_operations = operation_map(current);
    for id in before_operations
        .keys()
        .chain(after_operations.keys())
        .collect::<BTreeSet<_>>()
    {
        let location = format!("{root}.operations.{id}");
        match (before_operations.get(*id), after_operations.get(*id)) {
            (None, Some(_)) => push(
                changes,
                ChangeClass::OperationAdded,
                ChangeImpact::Widening,
                location,
                "a consultation operation was added",
            ),
            (Some(_), None) => push(
                changes,
                ChangeClass::OperationRemoved,
                ChangeImpact::Breaking,
                location,
                "a consultation operation was removed",
            ),
            (Some(before), Some(after)) => diff_operation(before, after, &location, changes),
            (None, None) => unreachable!(),
        }
    }
}

fn operation_map(resource: &CompiledResource) -> BTreeMap<&str, &CompiledOperation> {
    resource
        .operations
        .iter()
        .map(|operation| (operation.identifier.as_str(), operation))
        .collect()
}

fn diff_operation(
    previous: &CompiledOperation,
    current: &CompiledOperation,
    location: &str,
    changes: &mut Vec<ContractChange>,
) {
    if previous.default_representation != current.default_representation {
        push(
            changes,
            ChangeClass::DefaultRepresentationChanged,
            ChangeImpact::Breaking,
            format!("{location}.defaultRepresentation"),
            "the representation selected when the caller omits an explicit choice changed",
        );
    }
    let before_representations = previous
        .representations
        .iter()
        .map(|representation| (representation.id.as_str(), representation))
        .collect::<BTreeMap<_, _>>();
    let after_representations = current
        .representations
        .iter()
        .map(|representation| (representation.id.as_str(), representation))
        .collect::<BTreeMap<_, _>>();
    for id in before_representations
        .keys()
        .chain(after_representations.keys())
        .collect::<BTreeSet<_>>()
    {
        let representation_location = format!("{location}.representations.{id}");
        match (
            before_representations.get(*id),
            after_representations.get(*id),
        ) {
            (None, Some(_)) => push(
                changes,
                ChangeClass::RepresentationAdded,
                ChangeImpact::Widening,
                representation_location,
                "a callable representation was added to the operation",
            ),
            (Some(_), None) => push(
                changes,
                ChangeClass::RepresentationRemoved,
                ChangeImpact::Breaking,
                representation_location,
                "a callable representation was removed from the operation",
            ),
            (Some(before), Some(after)) => {
                diff_representation(before, after, &representation_location, changes);
            }
            (None, None) => unreachable!(),
        }
    }

    let before_filters = previous
        .query
        .filters
        .iter()
        .map(|filter| (filter.parameter.as_str(), filter))
        .collect::<BTreeMap<_, _>>();
    let after_filters = current
        .query
        .filters
        .iter()
        .map(|filter| (filter.parameter.as_str(), filter))
        .collect::<BTreeMap<_, _>>();
    for name in before_filters
        .keys()
        .chain(after_filters.keys())
        .collect::<BTreeSet<_>>()
    {
        match (before_filters.get(*name), after_filters.get(*name)) {
            (None, Some(_)) => push(
                changes,
                ChangeClass::FilterAdded,
                ChangeImpact::Widening,
                format!("{location}.filters.{name}"),
                "a collection filter was added",
            ),
            (Some(_), None) => push(
                changes,
                ChangeClass::FilterRemoved,
                ChangeImpact::Breaking,
                format!("{location}.filters.{name}"),
                "a collection filter was removed",
            ),
            (Some(before), Some(after)) if before != after => push(
                changes,
                ChangeClass::FilterChanged,
                ChangeImpact::Breaking,
                format!("{location}.filters.{name}"),
                "a filter property, source binding, or datatype changed",
            ),
            _ => {}
        }
    }
    match (
        previous.query.allow_unfiltered,
        current.query.allow_unfiltered,
    ) {
        (false, true) => push(
            changes,
            ChangeClass::UnfilteredEnabled,
            ChangeImpact::Widening,
            format!("{location}.allowUnfiltered"),
            "unfiltered collection access was enabled",
        ),
        (true, false) => push(
            changes,
            ChangeClass::UnfilteredDisabled,
            ChangeImpact::Narrowing,
            format!("{location}.allowUnfiltered"),
            "unfiltered collection access was disabled",
        ),
        _ => {}
    }
    if previous.query.selectors != current.query.selectors {
        push(
            changes,
            ChangeClass::SelectorChanged,
            ChangeImpact::Breaking,
            format!("{location}.selectors"),
            "lookup selector names, bindings, types, bounds, or codelists changed",
        );
    }
    if previous.query.order_by != current.query.order_by {
        push(
            changes,
            ChangeClass::OrderingChanged,
            ChangeImpact::Breaking,
            format!("{location}.orderBy"),
            "the deterministic source ordering changed",
        );
    }
    diff_pagination(
        previous.query.pagination.as_ref(),
        current.query.pagination.as_ref(),
        location,
        changes,
    );
    diff_request_bound(
        previous.query.maximum_request_body_bytes,
        current.query.maximum_request_body_bytes,
        location,
        changes,
    );
}

fn diff_representation(
    previous: &crate::model::CompiledRepresentation,
    current: &crate::model::CompiledRepresentation,
    location: &str,
    changes: &mut Vec<ContractChange>,
) {
    if previous.disclosure_profile != current.disclosure_profile {
        push(
            changes,
            ChangeClass::DisclosureProfileChanged,
            ChangeImpact::Breaking,
            format!("{location}.disclosureProfile"),
            "the named disclosure profile changed and requires review",
        );
    }
    let previous_properties = previous
        .selectable_properties
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let current_properties = current
        .selectable_properties
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if current_properties
        .difference(&previous_properties)
        .next()
        .is_some()
    {
        push(
            changes,
            ChangeClass::DisclosureExpanded,
            ChangeImpact::Widening,
            format!("{location}.disclosureProfile"),
            "the maximum disclosure property set expanded",
        );
    }
    if previous_properties
        .difference(&current_properties)
        .next()
        .is_some()
    {
        push(
            changes,
            ChangeClass::DisclosureNarrowed,
            ChangeImpact::Narrowing,
            format!("{location}.disclosureProfile"),
            "the maximum disclosure property set narrowed",
        );
    }
    if previous.transform_inventory != current.transform_inventory {
        push(
            changes,
            ChangeClass::TransformationChanged,
            ChangeImpact::Breaking,
            format!("{location}.transforms"),
            "the representation transformation inventory changed",
        );
    }
    if previous.processing_handling != current.processing_handling
        || previous.disclosure_handling != current.disclosure_handling
    {
        push(
            changes,
            ChangeClass::ClassificationChanged,
            ChangeImpact::Breaking,
            format!("{location}.handling"),
            "the representation processing or disclosure handling floor changed",
        );
    }
    diff_access(&previous.access, &current.access, location, changes);
}

fn classification_context(
    value: &crate::model::EffectiveClassification,
) -> (
    &str,
    &str,
    &str,
    &str,
    &str,
    &str,
    crate::contract::ReviewStatus,
    &str,
) {
    (
        &value.privacy,
        &value.privacy_scheme,
        &value.privacy_version,
        &value.institutional,
        &value.institutional_scheme,
        &value.institutional_version,
        value.status,
        &value.provenance_ref,
    )
}

fn diff_pagination(
    previous: Option<&crate::model::CompiledPagination>,
    current: Option<&crate::model::CompiledPagination>,
    location: &str,
    changes: &mut Vec<ContractChange>,
) {
    match (previous, current) {
        (Some(before), Some(after)) if before != after => {
            let expanded = after.maximum_page_size > before.maximum_page_size
                || after.default_page_size > before.default_page_size;
            push(
                changes,
                if expanded {
                    ChangeClass::PaginationExpanded
                } else {
                    ChangeClass::PaginationNarrowed
                },
                if expanded {
                    ChangeImpact::Widening
                } else {
                    ChangeImpact::Narrowing
                },
                format!("{location}.pagination"),
                "collection pagination bounds changed",
            );
        }
        (None, Some(_)) => push(
            changes,
            ChangeClass::PaginationExpanded,
            ChangeImpact::Widening,
            format!("{location}.pagination"),
            "pagination was added",
        ),
        (Some(_), None) => push(
            changes,
            ChangeClass::PaginationNarrowed,
            ChangeImpact::Breaking,
            format!("{location}.pagination"),
            "pagination was removed",
        ),
        _ => {}
    }
}

fn diff_request_bound(
    previous: Option<u32>,
    current: Option<u32>,
    location: &str,
    changes: &mut Vec<ContractChange>,
) {
    if previous == current {
        return;
    }
    let expanded = match (previous, current) {
        (Some(before), Some(after)) => after > before,
        (None, Some(_)) => true,
        (Some(_), None) => false,
        (None, None) => return,
    };
    push(
        changes,
        if expanded {
            ChangeClass::RequestBoundExpanded
        } else {
            ChangeClass::RequestBoundNarrowed
        },
        if expanded {
            ChangeImpact::Widening
        } else {
            ChangeImpact::Narrowing
        },
        format!("{location}.requestBody.maximumBytes"),
        "lookup request-body bound changed",
    );
}

fn diff_access(
    previous: &CompiledAccess,
    current: &CompiledAccess,
    location: &str,
    changes: &mut Vec<ContractChange>,
) {
    match (previous, current) {
        (CompiledAccess::Protected { .. }, CompiledAccess::Public) => push(
            changes,
            ChangeClass::ScopeChanged,
            ChangeImpact::Widening,
            format!("{location}.access"),
            "a protected operation became anonymous",
        ),
        (CompiledAccess::Public, CompiledAccess::Protected { .. }) => push(
            changes,
            ChangeClass::ScopeChanged,
            ChangeImpact::Narrowing,
            format!("{location}.access"),
            "an anonymous operation became protected",
        ),
        (
            CompiledAccess::Protected {
                scope: before_scope,
                purpose: before_purpose,
                row_binding: before_binding,
            },
            CompiledAccess::Protected {
                scope: after_scope,
                purpose: after_purpose,
                row_binding: after_binding,
            },
        ) => {
            if before_scope != after_scope {
                push(
                    changes,
                    ChangeClass::ScopeChanged,
                    ChangeImpact::Widening,
                    format!("{location}.access.scope"),
                    "the registered operation scope changed and requires authorization review",
                );
            }
            if before_purpose
                .as_ref()
                .zip(after_purpose.as_ref())
                .is_some_and(|(before, after)| before.claim != after.claim)
            {
                push(
                    changes,
                    ChangeClass::PurposeExpanded,
                    ChangeImpact::Widening,
                    format!("{location}.access.purpose.claim"),
                    "the trusted purpose claim changed and requires authorization review",
                );
            }
            match (before_binding, after_binding) {
                (Some(_), None) => push(
                    changes,
                    ChangeClass::RowBindingRemoved,
                    ChangeImpact::Widening,
                    format!("{location}.access.authorityRowBinding"),
                    "the principal-derived row boundary was removed",
                ),
                (None, Some(_)) => push(
                    changes,
                    ChangeClass::RowBindingAdded,
                    ChangeImpact::Narrowing,
                    format!("{location}.access.authorityRowBinding"),
                    "a principal-derived row boundary was added",
                ),
                (Some(before), Some(after)) if before != after => push(
                    changes,
                    ChangeClass::RowBindingChanged,
                    ChangeImpact::Widening,
                    format!("{location}.access.authorityRowBinding"),
                    "the principal-derived row boundary changed and requires review",
                ),
                _ => {}
            }
            let before_values = before_purpose
                .as_ref()
                .map(|purpose| purpose.allowed.iter().collect::<BTreeSet<_>>())
                .unwrap_or_default();
            let after_values = after_purpose
                .as_ref()
                .map(|purpose| purpose.allowed.iter().collect::<BTreeSet<_>>())
                .unwrap_or_default();
            if after_values.difference(&before_values).next().is_some()
                || (before_purpose.is_some() && after_purpose.is_none())
            {
                push(
                    changes,
                    ChangeClass::PurposeExpanded,
                    ChangeImpact::Widening,
                    format!("{location}.access.purpose"),
                    "the trusted purpose constraint expanded or was removed",
                );
            }
            if before_values.difference(&after_values).next().is_some()
                || (before_purpose.is_none() && after_purpose.is_some())
            {
                push(
                    changes,
                    ChangeClass::PurposeNarrowed,
                    ChangeImpact::Narrowing,
                    format!("{location}.access.purpose"),
                    "the trusted purpose constraint narrowed or was added",
                );
            }
        }
        (CompiledAccess::Public, CompiledAccess::Public) => {}
    }
}

fn diff_visibility(
    previous: &CompiledRegistry,
    current: &CompiledRegistry,
    changes: &mut Vec<ContractChange>,
) {
    let before = &previous.metadata_visibility;
    let after = &current.metadata_visibility;
    for (name, left, right) in [
        ("service", before.service, after.service),
        ("resources", before.resources, after.resources),
        ("semantics", before.semantics, after.semantics),
        (
            "classifications",
            before.classifications,
            after.classifications,
        ),
        ("processing", before.processing, after.processing),
    ] {
        if left == right {
            continue;
        }
        let relaxed = visibility_rank(right) < visibility_rank(left);
        push(
            changes,
            if relaxed {
                ChangeClass::MetadataVisibilityRelaxed
            } else {
                ChangeClass::MetadataVisibilityTightened
            },
            if relaxed {
                ChangeImpact::Widening
            } else {
                ChangeImpact::Narrowing
            },
            format!("metadataVisibility.{name}"),
            if relaxed {
                "metadata became visible to a wider audience"
            } else {
                "metadata became visible to a narrower audience"
            },
        );
    }
}

fn visibility_rank(value: Visibility) -> u8 {
    match value {
        Visibility::Public => 0,
        Visibility::OperationBound => 1,
        Visibility::OperatorOnly => 2,
    }
}

fn push(
    changes: &mut Vec<ContractChange>,
    class: ChangeClass,
    impact: ChangeImpact,
    location: String,
    description: &str,
) {
    changes.push(ContractChange {
        class,
        impact,
        location,
        description: description.into(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::{compile_contract_with_governed_files, tests as compiler_tests};
    use crate::contract::RegistryContract;
    use crate::model::CompileProfile;

    fn compiled() -> CompiledRegistry {
        let contract = RegistryContract::parse_yaml(compiler_tests::valid_contract())
            .expect("contract parses");
        compile_contract_with_governed_files(
            &contract,
            &[compiler_tests::observed_schema()],
            CompileProfile::Production,
            &compiler_tests::governed_files(),
        )
        .expect("contract compiles")
    }

    fn statistical_dataset() -> CompiledStatisticalDataset {
        let classification = crate::model::EffectiveClassification {
            privacy: "non-personal".into(),
            privacy_scheme: "urn:privacy".into(),
            privacy_version: "1".into(),
            institutional: "public".into(),
            institutional_scheme: "urn:institutional".into(),
            institutional_version: "1".into(),
            handling: crate::contract::Handling::Public,
            handling_scheme: "urn:handling".into(),
            handling_version: "1".into(),
            status: crate::contract::ReviewStatus::Reviewed,
            provenance_ref: "governance/review.yaml".into(),
        };
        CompiledStatisticalDataset {
            id: "rates".into(),
            title: "Rates".into(),
            description: "Reviewed rates".into(),
            sdmx: crate::model::CompiledSdmxBinding {
                agency_id: "EXAMPLE".into(),
                dataflow_id: "RATES".into(),
                version: "1.0.0".into(),
                data_structure_id: "RATES_DSD".into(),
                concept_scheme_id: "RATES_CONCEPTS".into(),
            },
            release_at: "2026-08-10T00:00:00Z".into(),
            source: "statistics".into(),
            view: "rates".into(),
            dimensions: vec![crate::model::CompiledStatisticalDimension {
                id: "REF_AREA".into(),
                label: "Reference area".into(),
                description: "Observation geography".into(),
                source_column: "ref_area".into(),
                data_type: crate::contract::StatisticalValueType::String,
                codelist: None,
                semantic_iri: "urn:concept:area".into(),
                classification: classification.clone(),
            }],
            time: crate::model::CompiledStatisticalTimeDimension {
                id: "TIME_PERIOD".into(),
                label: "Time period".into(),
                description: "Observation period".into(),
                source_column: "time_period".into(),
                semantic_iri: "urn:concept:time".into(),
                classification: classification.clone(),
            },
            measure: crate::model::CompiledStatisticalMeasure {
                id: "OBS_VALUE".into(),
                label: "Rate".into(),
                description: "Observation value".into(),
                source_column: "value".into(),
                data_type: crate::contract::StatisticalValueType::Decimal,
                semantic_iri: "urn:concept:rate".into(),
                classification,
            },
            attributes: Vec::new(),
            access: CompiledAccess::Public,
            allow_unfiltered: false,
            maximum_observations: 100,
            maximum_offset: 0,
            processing_handling: crate::contract::Handling::Public,
            disclosure_handling: crate::contract::Handling::Public,
            column_accounting: Vec::new(),
            processing_descriptions: Vec::new(),
        }
    }

    #[test]
    fn visibility_order_is_security_monotonic() {
        assert!(visibility_rank(Visibility::Public) < visibility_rank(Visibility::OperationBound));
        assert!(
            visibility_rank(Visibility::OperationBound) < visibility_rank(Visibility::OperatorOnly)
        );
    }

    #[test]
    fn classification_and_processing_changes_are_reported() {
        let previous = compiled();
        let mut current = previous.clone();
        current.resources[0].properties[0].classification.privacy = "sensitive".into();
        current.resources[0].processing_descriptions[0].purpose = "reviewed-purpose".into();

        let report = diff_registries(&previous, &current);
        assert!(report
            .changes
            .iter()
            .any(|change| change.class == ChangeClass::ClassificationChanged));
        assert!(report
            .changes
            .iter()
            .any(|change| change.class == ChangeClass::ProcessingChanged));
    }

    #[test]
    fn representations_transforms_defaults_and_review_bindings_are_reported() {
        let previous = compiled();
        let mut current = previous.clone();
        let operation = &mut current.resources[0].operations[0];
        operation.representations[0]
            .transform_inventory
            .push("partial-string:suffix:4".into());
        let mut alternate = operation.representations[0].clone();
        alternate.id = "alternate".into();
        operation.representations.push(alternate);
        operation.default_representation = "alternate".into();
        current
            .classification_review
            .as_mut()
            .expect("compiled production review")
            .classification_inventory_digest = format!("sha256:{}", "a".repeat(64));

        let report = diff_registries(&previous, &current);
        for class in [
            ChangeClass::TransformationChanged,
            ChangeClass::RepresentationAdded,
            ChangeClass::DefaultRepresentationChanged,
            ChangeClass::ClassificationReviewChanged,
        ] {
            assert!(
                report.changes.iter().any(|change| change.class == class),
                "missing {class:?}"
            );
        }

        let reverse = diff_registries(&current, &previous);
        assert!(reverse
            .changes
            .iter()
            .any(|change| change.class == ChangeClass::RepresentationRemoved));
    }

    #[test]
    fn governed_sidecar_digest_changes_are_reported() {
        let previous = compiled();
        let mut current = previous.clone();
        current.governed_files[0].sha256 = format!("sha256:{}", "0".repeat(64));

        let report = diff_registries(&previous, &current);
        assert!(report
            .changes
            .iter()
            .any(|change| change.class == ChangeClass::GovernedFileChanged));
    }

    #[test]
    fn source_profile_or_schema_fingerprint_changes_are_reported() {
        let previous = compiled();
        let mut current = previous.clone();
        current.sources[0].expected_schema_fingerprint = format!("sha256:{}", "1".repeat(64));

        let report = diff_registries(&previous, &current);
        assert!(report
            .changes
            .iter()
            .any(|change| change.class == ChangeClass::SourceSchemaChanged));
    }

    #[test]
    fn filter_unfiltered_and_query_shape_changes_are_reported() {
        let mut previous = compiled();
        let operation = &mut previous.resources[0].operations[0];
        operation.query.filters.push(crate::model::CompiledFilter {
            parameter: "name".into(),
            property: "name".into(),
            source_column: "name".into(),
            data_type: crate::contract::DataType::String,
        });
        operation.query.pagination = Some(crate::model::CompiledPagination {
            default_page_size: 1,
            maximum_page_size: 10,
        });
        let mut current = previous.clone();
        let operation = &mut current.resources[0].operations[0];
        operation.query.filters[0].source_column = "replacement".into();
        operation.query.allow_unfiltered = !operation.query.allow_unfiltered;
        operation.query.order_by.push("replacement".into());
        operation.query.pagination = Some(crate::model::CompiledPagination {
            default_page_size: 2,
            maximum_page_size: 20,
        });

        let report = diff_registries(&previous, &current);
        for class in [
            ChangeClass::FilterChanged,
            if previous.resources[0].operations[0].query.allow_unfiltered {
                ChangeClass::UnfilteredDisabled
            } else {
                ChangeClass::UnfilteredEnabled
            },
            ChangeClass::OrderingChanged,
            ChangeClass::PaginationExpanded,
        ] {
            assert!(
                report.changes.iter().any(|change| change.class == class),
                "missing {class:?}"
            );
        }
    }

    #[test]
    fn selector_and_request_bound_changes_are_reported() {
        let mut previous = compiled();
        let operation = &mut previous.resources[0].operations[0];
        operation
            .query
            .selectors
            .push(crate::model::CompiledSelector {
                name: "name".into(),
                source_column: "name".into(),
                data_type: crate::contract::DataType::String,
                minimum_bytes: Some(1),
                maximum_bytes: Some(64),
                codelist: None,
            });
        operation.query.maximum_request_body_bytes = Some(512);
        let mut current = previous.clone();
        let operation = &mut current.resources[0].operations[0];
        operation.query.selectors[0].maximum_bytes = Some(99);
        operation.query.maximum_request_body_bytes = Some(
            operation
                .query
                .maximum_request_body_bytes
                .expect("request bound")
                + 1,
        );

        let report = diff_registries(&previous, &current);
        assert!(report
            .changes
            .iter()
            .any(|change| change.class == ChangeClass::SelectorChanged));
        assert!(report
            .changes
            .iter()
            .any(|change| change.class == ChangeClass::RequestBoundExpanded));
    }

    #[test]
    fn statistical_binding_access_and_bounds_are_reported() {
        let mut previous = compiled();
        previous.statistical_datasets.push(statistical_dataset());
        let mut current = previous.clone();
        let dataset = &mut current.statistical_datasets[0];
        dataset.sdmx.dataflow_id = "RATES_V2".into();
        dataset.allow_unfiltered = true;
        dataset.maximum_observations += 1;
        dataset.access = CompiledAccess::Protected {
            scope: "statistics:read".into(),
            purpose: None,
            row_binding: None,
        };

        let report = diff_registries(&previous, &current);
        for class in [
            ChangeClass::StatisticalDatasetChanged,
            ChangeClass::UnfilteredEnabled,
            ChangeClass::RequestBoundExpanded,
            ChangeClass::ScopeChanged,
        ] {
            assert!(
                report.changes.iter().any(|change| change.class == class),
                "missing {class:?}"
            );
        }

        let mut added = compiled();
        added.statistical_datasets.push(statistical_dataset());
        assert!(diff_registries(&compiled(), &added)
            .changes
            .iter()
            .any(|change| change.class == ChangeClass::StatisticalDatasetAdded));
    }
}
