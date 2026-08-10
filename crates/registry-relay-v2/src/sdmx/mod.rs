// SPDX-License-Identifier: Apache-2.0
//! Pure SDMX query and representation support.
//!
//! This module stops at the logical-row boundary. HTTP routing, authorization,
//! audit, source queries, and cache policy remain owned by their existing Relay
//! layers.

mod query;
mod representation;

use std::collections::BTreeMap;

use crate::contract::{StatisticalTimeGranularity, StatisticalValueType};
use crate::model::CompiledStatisticalDataset;

#[cfg(test)]
pub(crate) use query::ComponentConstraint;
pub(crate) use query::{parse_data_query, DataQuery, DataQueryError, DimensionAtObservation};
#[cfg(test)]
use representation::REST_VERSION;
pub(crate) use representation::{
    serialize_data_csv, serialize_data_json, serialize_structure_json, RepresentationError,
    StructureKind, DATA_CSV_MEDIA_TYPE, DATA_JSON_MEDIA_TYPE, STRUCTURE_JSON_MEDIA_TYPE,
};

/// Maximum decoded byte length for one query or source component value.
pub(crate) const MAXIMUM_COMPONENT_VALUE_BYTES: usize = 1024;

fn valid_sdmx_code_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_COMPONENT_VALUE_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'@' | b'$' | b'-'))
}

/// A normalized statistical value at the boundary between source execution and
/// SDMX representation. Keeping this type independent of the SQLite adapter
/// prevents the SDMX contract from becoming a database contract.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum StatisticalValue {
    Null,
    String(String),
    Integer(i64),
    Decimal(f64),
    Boolean(bool),
}

pub(crate) type StatisticalRow = BTreeMap<String, StatisticalValue>;

/// The small, owned view of a compiled dataset required by the pure SDMX core.
///
/// The compiler remains responsible for identifier syntax, codelist existence,
/// source-column accounting, fixed access, snapshot-only sources, and the
/// binding-version allowlist. Centralizing the adapter here keeps model changes
/// out of the query and representation implementations.
#[derive(Clone, Debug)]
struct DatasetView {
    title: String,
    description: String,
    release_at: String,
    dimensions: Vec<ComponentView>,
    time: TimeComponentView,
    measure: ComponentView,
    attributes: Vec<AttributeView>,
    allow_unfiltered: bool,
    maximum_observations: u32,
    maximum_offset: u32,
    binding: BindingView,
}

#[derive(Clone, Debug)]
struct ComponentView {
    id: String,
    label: String,
    description: String,
    source_column: String,
    value_type: StatisticalValueType,
    coded: bool,
}

#[derive(Clone, Debug)]
struct TimeComponentView {
    id: String,
    label: String,
    description: String,
    source_column: String,
    granularity: StatisticalTimeGranularity,
}

#[derive(Clone, Debug)]
struct AttributeView {
    component: ComponentView,
    required: bool,
}

#[derive(Clone, Debug)]
struct BindingView {
    agency_id: String,
    dataflow_id: String,
    version: String,
    data_structure_id: String,
    concept_scheme_id: String,
    rest_version: String,
    data_json_version: String,
    data_csv_version: String,
    structure_json_version: String,
}

impl DatasetView {
    fn from_compiled(dataset: &CompiledStatisticalDataset) -> Self {
        Self {
            title: dataset.title.clone(),
            description: dataset.description.clone(),
            release_at: dataset.release_at.clone(),
            dimensions: dataset
                .dimensions
                .iter()
                .map(|component| ComponentView {
                    id: component.id.clone(),
                    label: component.label.clone(),
                    description: component.description.clone(),
                    source_column: component.source_column.clone(),
                    value_type: component.data_type,
                    coded: component.codelist.is_some()
                        || component.data_type == StatisticalValueType::Code,
                })
                .collect(),
            time: TimeComponentView {
                id: dataset.time.id.clone(),
                label: dataset.time.label.clone(),
                description: dataset.time.description.clone(),
                source_column: dataset.time.source_column.clone(),
                granularity: dataset.time.granularity,
            },
            measure: ComponentView {
                id: dataset.measure.id.clone(),
                label: dataset.measure.label.clone(),
                description: dataset.measure.description.clone(),
                source_column: dataset.measure.source_column.clone(),
                value_type: dataset.measure.data_type,
                coded: false,
            },
            attributes: dataset
                .attributes
                .iter()
                .map(|attribute| AttributeView {
                    component: ComponentView {
                        id: attribute.id.clone(),
                        label: attribute.label.clone(),
                        description: attribute.description.clone(),
                        source_column: attribute.source_column.clone(),
                        value_type: attribute.data_type,
                        coded: attribute.codelist.is_some()
                            || attribute.data_type == StatisticalValueType::Code,
                    },
                    required: attribute.source_required,
                })
                .collect(),
            allow_unfiltered: dataset.allow_unfiltered,
            maximum_observations: dataset.maximum_observations,
            maximum_offset: dataset.maximum_offset,
            binding: BindingView {
                agency_id: dataset.sdmx.agency_id.clone(),
                dataflow_id: dataset.sdmx.dataflow_id.clone(),
                version: dataset.sdmx.version.clone(),
                data_structure_id: dataset.sdmx.data_structure_id.clone(),
                concept_scheme_id: dataset.sdmx.concept_scheme_id.clone(),
                rest_version: dataset.sdmx.rest_version.clone(),
                data_json_version: dataset.sdmx.data_json_version.clone(),
                data_csv_version: dataset.sdmx.data_csv_version.clone(),
                structure_json_version: dataset.sdmx.structure_json_version.clone(),
            },
        }
    }
}

#[cfg(test)]
fn test_dataset_view() -> DatasetView {
    DatasetView {
        title: "Rates".into(),
        description: "Reviewed rates".into(),
        release_at: "2026-08-10T00:00:00Z".into(),
        dimensions: vec![
            ComponentView {
                id: "REF_AREA".into(),
                label: "Reference area".into(),
                description: "Observation geography".into(),
                source_column: "ref_area".into(),
                value_type: StatisticalValueType::Code,
                coded: true,
            },
            ComponentView {
                id: "SEX".into(),
                label: "Sex".into(),
                description: "Statistical sex".into(),
                source_column: "sex".into(),
                value_type: StatisticalValueType::Code,
                coded: true,
            },
        ],
        time: TimeComponentView {
            id: "TIME_PERIOD".into(),
            label: "Time period".into(),
            description: "Quarterly period".into(),
            source_column: "time_period".into(),
            granularity: StatisticalTimeGranularity::Quarterly,
        },
        measure: ComponentView {
            id: "PARTICIPATION_RATE".into(),
            label: "Participation rate".into(),
            description: "Observation value".into(),
            source_column: "obs_value".into(),
            value_type: StatisticalValueType::Decimal,
            coded: false,
        },
        attributes: vec![AttributeView {
            component: ComponentView {
                id: "UNIT_MEASURE".into(),
                label: "Unit".into(),
                description: "Observation unit".into(),
                source_column: "unit_measure".into(),
                value_type: StatisticalValueType::Code,
                coded: true,
            },
            required: true,
        }],
        allow_unfiltered: true,
        maximum_observations: 100,
        maximum_offset: 1_000,
        binding: BindingView {
            agency_id: "EXAMPLE_STAT".into(),
            dataflow_id: "RATES".into(),
            version: "1.0.0".into(),
            data_structure_id: "RATES_DSD".into(),
            concept_scheme_id: "RATES_CONCEPTS".into(),
            rest_version: REST_VERSION.into(),
            data_json_version: representation::DATA_JSON_VERSION.into(),
            data_csv_version: representation::DATA_CSV_VERSION.into(),
            structure_json_version: representation::STRUCTURE_JSON_VERSION.into(),
        },
    }
}
