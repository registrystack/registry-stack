// SPDX-License-Identifier: Apache-2.0
//! Deterministic SDMX data and structure representations.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use registry_platform_canonical_json::canonicalize_json;
use serde_json::{json, Map, Value};

use super::query::{valid_time_period, DimensionAtObservation};
use super::{
    valid_sdmx_code_value, ComponentView, DatasetView, StatisticalRow, StatisticalValue,
    StatisticalValueType, MAXIMUM_COMPONENT_VALUE_BYTES,
};
use crate::model::CompiledStatisticalDataset;

pub(crate) const REST_VERSION: &str = "2.2.2";
pub(crate) const DATA_JSON_VERSION: &str = "2.1.0";
pub(crate) const DATA_CSV_VERSION: &str = "2.1.0";
pub(crate) const STRUCTURE_JSON_VERSION: &str = "2.1.0";

pub(crate) const DATA_JSON_MEDIA_TYPE: &str = "application/vnd.sdmx.data+json;version=2.1.0";
pub(crate) const DATA_CSV_MEDIA_TYPE: &str = "application/vnd.sdmx.data+csv;version=2.1.0";
pub(crate) const STRUCTURE_JSON_MEDIA_TYPE: &str =
    "application/vnd.sdmx.structure+json;version=2.1.0";

pub(crate) const DATA_JSON_SCHEMA: &str = "https://json.sdmx.org/2.1.0/sdmx-json-data-schema.json";
pub(crate) const STRUCTURE_JSON_SCHEMA: &str =
    "https://json.sdmx.org/2.1.0/sdmx-json-structure-schema.json";

const SENDER_ID: &str = "REGISTRY_RELAY";
pub(crate) const MAXIMUM_SERIALIZED_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StructureKind {
    Dataflow,
    DataStructure,
}

impl StructureKind {
    const fn message_suffix(self) -> &'static str {
        match self {
            Self::Dataflow => "structure_dataflow",
            Self::DataStructure => "structure_datastructure",
        }
    }
}

/// Value-free representation failures. Source values are never included in an
/// error or expected to cross the HTTP refusal boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RepresentationError {
    UnsupportedBinding,
    EmptyRows,
    InvalidRows,
    OutputTooLarge,
    Serialization,
}

impl fmt::Display for RepresentationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedBinding => "the compiled SDMX binding is unsupported",
            Self::EmptyRows => "the statistical result is empty",
            Self::InvalidRows => "the statistical result violates its compiled shape",
            Self::OutputTooLarge => "the statistical representation exceeds its output bound",
            Self::Serialization => "the statistical representation could not be serialized",
        })
    }
}

impl std::error::Error for RepresentationError {}

pub(crate) fn serialize_data_json(
    dataset: &CompiledStatisticalDataset,
    rows: &[StatisticalRow],
    dimension_at_observation: DimensionAtObservation,
) -> Result<Vec<u8>, RepresentationError> {
    serialize_data_json_view(
        &DatasetView::from_compiled(dataset),
        rows,
        dimension_at_observation,
    )
}

pub(crate) fn serialize_data_csv(
    dataset: &CompiledStatisticalDataset,
    rows: &[StatisticalRow],
) -> Result<Vec<u8>, RepresentationError> {
    serialize_data_csv_view(&DatasetView::from_compiled(dataset), rows)
}

pub(crate) fn serialize_structure_json(
    dataset: &CompiledStatisticalDataset,
    kind: StructureKind,
) -> Result<Vec<u8>, RepresentationError> {
    serialize_structure_json_view(&DatasetView::from_compiled(dataset), kind)
}

fn serialize_data_json_view(
    dataset: &DatasetView,
    rows: &[StatisticalRow],
    dimension_at_observation: DimensionAtObservation,
) -> Result<Vec<u8>, RepresentationError> {
    require_current_binding(dataset)?;
    let rows = validate_and_order_rows(dataset, rows)?;
    match dimension_at_observation {
        DimensionAtObservation::TimePeriod => serialize_series_json(dataset, &rows),
        DimensionAtObservation::AllDimensions => serialize_flat_json(dataset, &rows),
    }
}

fn serialize_flat_json(
    dataset: &DatasetView,
    rows: &[&StatisticalRow],
) -> Result<Vec<u8>, RepresentationError> {
    let (dimensions, indexes) = dimension_metadata(dataset, rows)?;
    let attributes = attribute_metadata(dataset, rows)?;
    let mut observations = Map::new();
    for row in rows {
        let key = dataset
            .dimensions
            .iter()
            .map(|dimension| observation_index(row, dimension, &indexes))
            .chain(std::iter::once(time_observation_index(
                row, dataset, &indexes,
            )))
            .collect::<Result<Vec<_>, _>>()?
            .join(":");
        observations.insert(key, observation_values(dataset, row, &attributes)?);
    }

    bounded_json(&json!({
        "$schema": DATA_JSON_SCHEMA,
        "meta": data_message_meta(dataset),
        "data": {
            "dataSets": [{
                "structure": 0,
                "action": "Replace",
                "observations": observations,
            }],
            "structures": [{
                "links": [dataflow_link(dataset, "dataflow")],
                "name": dataset.title,
                "description": dataset.description,
                "dataSets": [0],
                "dimensions": {"observation": dimensions},
                "measures": {"observation": [measure_document(dataset)]},
                "attributes": {
                    "observation": attributes
                        .iter()
                        .map(|attribute| attribute.document.clone())
                        .collect::<Vec<_>>()
                },
            }],
        },
    }))
}

fn serialize_series_json(
    dataset: &DatasetView,
    rows: &[&StatisticalRow],
) -> Result<Vec<u8>, RepresentationError> {
    let (all_dimensions, indexes) = dimension_metadata(dataset, rows)?;
    let dimensions_by_id = all_dimensions
        .into_iter()
        .map(|value| {
            let id = value
                .get("id")
                .and_then(Value::as_str)
                .ok_or(RepresentationError::Serialization)?
                .to_owned();
            Ok((id, value))
        })
        .collect::<Result<BTreeMap<_, _>, RepresentationError>>()?;
    let attributes = attribute_metadata(dataset, rows)?;
    let mut series = Map::new();
    let mut observations = Map::new();

    for row in rows {
        let series_key = dataset
            .dimensions
            .iter()
            .map(|dimension| observation_index(row, dimension, &indexes))
            .collect::<Result<Vec<_>, _>>()?
            .join(":");
        let time_key = time_observation_index(row, dataset, &indexes)?;
        let values = observation_values(dataset, row, &attributes)?;
        if dataset.dimensions.is_empty() {
            observations.insert(time_key, values);
        } else {
            let entry = series
                .entry(series_key)
                .or_insert_with(|| json!({"observations": {}}));
            entry
                .get_mut("observations")
                .and_then(Value::as_object_mut)
                .ok_or(RepresentationError::Serialization)?
                .insert(time_key, values);
        }
    }

    let data_set = if dataset.dimensions.is_empty() {
        json!({"structure": 0, "action": "Replace", "observations": observations})
    } else {
        json!({"structure": 0, "action": "Replace", "series": series})
    };
    let series_dimensions = dataset
        .dimensions
        .iter()
        .map(|dimension| {
            dimensions_by_id
                .get(&dimension.id)
                .cloned()
                .ok_or(RepresentationError::Serialization)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let time_dimension = dimensions_by_id
        .get(&dataset.time.id)
        .cloned()
        .ok_or(RepresentationError::Serialization)?;

    bounded_json(&json!({
        "$schema": DATA_JSON_SCHEMA,
        "meta": data_message_meta(dataset),
        "data": {
            "dataSets": [data_set],
            "structures": [{
                "links": [dataflow_link(dataset, "dataflow")],
                "name": dataset.title,
                "description": dataset.description,
                "dataSets": [0],
                "dimensions": {
                    "series": series_dimensions,
                    "observation": [time_dimension],
                },
                "measures": {"observation": [measure_document(dataset)]},
                "attributes": {
                    "observation": attributes
                        .iter()
                        .map(|attribute| attribute.document.clone())
                        .collect::<Vec<_>>()
                },
            }],
        },
    }))
}

type ValueIndex = BTreeMap<String, usize>;
type ComponentIndexes = BTreeMap<String, ValueIndex>;

struct AttributeMetadata {
    document: Value,
    indexes: Option<ValueIndex>,
}

fn dimension_metadata(
    dataset: &DatasetView,
    rows: &[&StatisticalRow],
) -> Result<(Vec<Value>, ComponentIndexes), RepresentationError> {
    let mut documents = Vec::new();
    let mut indexes = BTreeMap::new();
    for dimension in &dataset.dimensions {
        let values = unique_values(rows, &dimension.source_column)?;
        indexes.insert(dimension.id.clone(), value_index(&values));
        documents.push(dimension_document(dimension, documents.len(), &values)?);
    }

    let time_values = unique_values(rows, &dataset.time.source_column)?;
    indexes.insert(dataset.time.id.clone(), value_index(&time_values));
    documents.push(json!({
        "id": dataset.time.id,
        "name": dataset.time.label,
        "description": dataset.time.description,
        "keyPosition": documents.len(),
        "roles": ["TIME_PERIOD"],
        "format": {"dataType": "ObservationalTimePeriod"},
        "values": time_values
            .iter()
            .map(typed_value_document)
            .collect::<Result<Vec<_>, _>>()?,
    }));
    Ok((documents, indexes))
}

fn dimension_document(
    component: &ComponentView,
    key_position: usize,
    values: &[StatisticalValue],
) -> Result<Value, RepresentationError> {
    let mut document = Map::new();
    document.insert("id".into(), json!(component.id));
    document.insert("name".into(), json!(component.label));
    document.insert("description".into(), json!(component.description));
    document.insert("keyPosition".into(), json!(key_position));
    document.insert("roles".into(), json!([]));
    if !component.coded {
        document.insert(
            "format".into(),
            json!({"dataType": statistical_data_type(component.value_type)}),
        );
    }
    document.insert(
        "values".into(),
        Value::Array(
            values
                .iter()
                .map(|value| component_value_document(component, value))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    );
    Ok(Value::Object(document))
}

fn attribute_metadata(
    dataset: &DatasetView,
    rows: &[&StatisticalRow],
) -> Result<Vec<AttributeMetadata>, RepresentationError> {
    dataset
        .attributes
        .iter()
        .map(|attribute| {
            let values = unique_values(rows, &attribute.component.source_column)?;
            let mut document = json!({
                "id": attribute.component.id,
                "name": attribute.component.label,
                "description": attribute.component.description,
                "isMandatory": attribute.required,
                "relationship": {"observation": {}},
            });
            let indexes = if attribute.component.coded {
                document
                    .as_object_mut()
                    .ok_or(RepresentationError::Serialization)?
                    .insert(
                        "values".into(),
                        Value::Array(
                            values
                                .iter()
                                .map(|value| component_value_document(&attribute.component, value))
                                .collect::<Result<Vec<_>, _>>()?,
                        ),
                    );
                Some(value_index(&values))
            } else {
                document
                    .as_object_mut()
                    .ok_or(RepresentationError::Serialization)?
                    .insert(
                        "format".into(),
                        json!({
                            "dataType": statistical_data_type(attribute.component.value_type)
                        }),
                    );
                None
            };
            Ok(AttributeMetadata { document, indexes })
        })
        .collect()
}

fn observation_values(
    dataset: &DatasetView,
    row: &StatisticalRow,
    attributes: &[AttributeMetadata],
) -> Result<Value, RepresentationError> {
    let mut values = vec![typed_json(row_value(row, &dataset.measure.source_column)?)?];
    for (index, attribute) in dataset.attributes.iter().enumerate() {
        let value = row_value(row, &attribute.component.source_column)?;
        values.push(match value {
            StatisticalValue::Null => Value::Null,
            _ => match &attributes[index].indexes {
                Some(indexes) => Value::from(
                    indexes
                        .get(&stable_value(value))
                        .copied()
                        .ok_or(RepresentationError::Serialization)?,
                ),
                None => typed_json(value)?,
            },
        });
    }
    Ok(Value::Array(values))
}

fn observation_index(
    row: &StatisticalRow,
    component: &ComponentView,
    indexes: &ComponentIndexes,
) -> Result<String, RepresentationError> {
    indexes
        .get(&component.id)
        .and_then(|index| index.get(&stable_value(row.get(&component.source_column)?)))
        .copied()
        .map(|index| index.to_string())
        .ok_or(RepresentationError::Serialization)
}

fn time_observation_index(
    row: &StatisticalRow,
    dataset: &DatasetView,
    indexes: &ComponentIndexes,
) -> Result<String, RepresentationError> {
    indexes
        .get(&dataset.time.id)
        .and_then(|index| index.get(&stable_value(row.get(&dataset.time.source_column)?)))
        .copied()
        .map(|index| index.to_string())
        .ok_or(RepresentationError::Serialization)
}

fn serialize_data_csv_view(
    dataset: &DatasetView,
    rows: &[StatisticalRow],
) -> Result<Vec<u8>, RepresentationError> {
    require_current_binding(dataset)?;
    let rows = validate_and_order_rows(dataset, rows)?;
    let mut bytes = Vec::new();
    let mut header = vec!["STRUCTURE", "STRUCTURE_ID", "ACTION"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    header.extend(
        dataset
            .dimensions
            .iter()
            .map(|component| component.id.clone()),
    );
    header.push(dataset.time.id.clone());
    header.push(dataset.measure.id.clone());
    header.extend(
        dataset
            .attributes
            .iter()
            .map(|attribute| attribute.component.id.clone()),
    );
    write_csv_row(&mut bytes, &header)?;

    for row in rows {
        let mut values = vec![
            "dataflow".to_owned(),
            format!(
                "{}:{}({})",
                dataset.binding.agency_id, dataset.binding.dataflow_id, dataset.binding.version
            ),
            "R".to_owned(),
        ];
        values.extend(
            dataset
                .dimensions
                .iter()
                .map(|component| csv_value(row.get(&component.source_column)))
                .collect::<Result<Vec<_>, _>>()?,
        );
        values.push(csv_value(row.get(&dataset.time.source_column))?);
        values.push(csv_value(row.get(&dataset.measure.source_column))?);
        values.extend(
            dataset
                .attributes
                .iter()
                .map(|attribute| csv_value(row.get(&attribute.component.source_column)))
                .collect::<Result<Vec<_>, _>>()?,
        );
        write_csv_row(&mut bytes, &values)?;
    }
    Ok(bytes)
}

fn write_csv_row(bytes: &mut Vec<u8>, values: &[String]) -> Result<(), RepresentationError> {
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            bytes.push(b',');
        }
        if value.contains([',', '"', '\n', '\r']) {
            bytes.push(b'"');
            bytes.extend_from_slice(value.replace('"', "\"\"").as_bytes());
            bytes.push(b'"');
        } else {
            bytes.extend_from_slice(value.as_bytes());
        }
        ensure_output_bound(bytes.len())?;
    }
    bytes.push(b'\n');
    ensure_output_bound(bytes.len())
}

fn serialize_structure_json_view(
    dataset: &DatasetView,
    kind: StructureKind,
) -> Result<Vec<u8>, RepresentationError> {
    require_current_binding(dataset)?;
    let data = match kind {
        StructureKind::Dataflow => json!({"dataflows": [dataflow_structure(dataset)]}),
        StructureKind::DataStructure => {
            json!({"dataStructures": [data_structure(dataset)]})
        }
    };
    bounded_json(&json!({
        "$schema": STRUCTURE_JSON_SCHEMA,
        "meta": structure_message_meta(dataset, kind),
        "data": data,
    }))
}

fn dataflow_structure(dataset: &DatasetView) -> Value {
    json!({
        "id": dataset.binding.dataflow_id,
        "agencyID": dataset.binding.agency_id,
        "version": dataset.binding.version,
        "name": dataset.title,
        "description": dataset.description,
        "links": [{"urn": dataflow_urn(dataset), "rel": "self"}],
        "structure": data_structure_urn(dataset),
    })
}

fn data_structure(dataset: &DatasetView) -> Value {
    let dimensions = dataset
        .dimensions
        .iter()
        .enumerate()
        .map(|(position, component)| {
            json!({
                "id": component.id,
                "position": position,
                "conceptIdentity": concept_urn(dataset, &component.id),
                "localRepresentation": {
                    "format": {"dataType": statistical_data_type(component.value_type)}
                },
            })
        })
        .collect::<Vec<_>>();
    let time_dimension = json!({
        "id": dataset.time.id,
        "conceptIdentity": concept_urn(dataset, &dataset.time.id),
        "localRepresentation": {"format": {"dataType": "ObservationalTimePeriod"}},
    });

    let mut dimension_list = Map::new();
    dimension_list.insert("id".into(), json!("DimensionDescriptor"));
    if !dimensions.is_empty() {
        dimension_list.insert("dimensions".into(), Value::Array(dimensions));
    }
    dimension_list.insert("timeDimension".into(), time_dimension);

    let mut components = Map::new();
    components.insert("dimensionList".into(), Value::Object(dimension_list));
    components.insert(
        "measureList".into(),
        json!({
            "id": "MeasureDescriptor",
            "measures": [{
                "id": dataset.measure.id,
                "usage": "mandatory",
                "conceptIdentity": concept_urn(dataset, &dataset.measure.id),
                "localRepresentation": {
                    "format": {"dataType": statistical_data_type(dataset.measure.value_type)}
                },
            }],
        }),
    );
    if !dataset.attributes.is_empty() {
        components.insert(
            "attributeList".into(),
            json!({
                "id": "AttributeDescriptor",
                "attributes": dataset.attributes.iter().map(|attribute| json!({
                    "id": attribute.component.id,
                    "usage": if attribute.required {"mandatory"} else {"optional"},
                    "attributeRelationship": {"observation": {}},
                    "conceptIdentity": concept_urn(dataset, &attribute.component.id),
                    "localRepresentation": {
                        "format": {
                            "dataType": statistical_data_type(attribute.component.value_type)
                        }
                    },
                })).collect::<Vec<_>>(),
            }),
        );
    }

    json!({
        "id": dataset.binding.data_structure_id,
        "agencyID": dataset.binding.agency_id,
        "version": dataset.binding.version,
        "name": dataset.title,
        "description": dataset.description,
        "links": [{"urn": data_structure_urn(dataset), "rel": "self"}],
        "dataStructureComponents": Value::Object(components),
    })
}

fn validate_and_order_rows<'a>(
    dataset: &DatasetView,
    rows: &'a [StatisticalRow],
) -> Result<Vec<&'a StatisticalRow>, RepresentationError> {
    if rows.is_empty() {
        return Err(RepresentationError::EmptyRows);
    }
    if rows.len() > dataset.maximum_observations as usize {
        return Err(RepresentationError::InvalidRows);
    }

    let mut keyed_rows = Vec::with_capacity(rows.len());
    let mut keys = BTreeSet::new();
    for row in rows {
        let mut key = Vec::with_capacity(dataset.dimensions.len() + 1);
        for dimension in &dataset.dimensions {
            let value = row_value(row, &dimension.source_column)?;
            if !required_value_matches(value, dimension.value_type, dimension.coded) {
                return Err(RepresentationError::InvalidRows);
            }
            key.push(stable_value(value));
        }
        let time = row_value(row, &dataset.time.source_column)?;
        if !matches!(time, StatisticalValue::String(value)
            if value.len() <= MAXIMUM_COMPONENT_VALUE_BYTES
                && valid_time_period(dataset.time.granularity, value))
        {
            return Err(RepresentationError::InvalidRows);
        }
        key.push(stable_value(time));
        if !keys.insert(key.clone()) {
            return Err(RepresentationError::InvalidRows);
        }

        let measure = row_value(row, &dataset.measure.source_column)?;
        if !required_value_matches(measure, dataset.measure.value_type, false) {
            return Err(RepresentationError::InvalidRows);
        }
        for attribute in &dataset.attributes {
            let value = row_value(row, &attribute.component.source_column)?;
            if matches!(value, StatisticalValue::Null) {
                if attribute.required {
                    return Err(RepresentationError::InvalidRows);
                }
            } else if !required_value_matches(
                value,
                attribute.component.value_type,
                attribute.component.coded,
            ) {
                return Err(RepresentationError::InvalidRows);
            }
        }
        keyed_rows.push((key, row));
    }
    keyed_rows.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(keyed_rows.into_iter().map(|(_, row)| row).collect())
}

fn required_value_matches(
    value: &StatisticalValue,
    value_type: StatisticalValueType,
    coded: bool,
) -> bool {
    match (value_type, value) {
        (StatisticalValueType::Code, StatisticalValue::String(value)) => {
            valid_sdmx_code_value(value)
        }
        (StatisticalValueType::String, StatisticalValue::String(value)) => {
            (!coded || valid_sdmx_code_value(value)) && value.len() <= MAXIMUM_COMPONENT_VALUE_BYTES
        }
        (StatisticalValueType::Integer, StatisticalValue::Integer(_))
        | (StatisticalValueType::Decimal, StatisticalValue::Integer(_))
        | (StatisticalValueType::Boolean, StatisticalValue::Boolean(_)) => true,
        (StatisticalValueType::Decimal, StatisticalValue::Decimal(value)) => value.is_finite(),
        _ => false,
    }
}

fn row_value<'a>(
    row: &'a StatisticalRow,
    column: &str,
) -> Result<&'a StatisticalValue, RepresentationError> {
    row.get(column).ok_or(RepresentationError::InvalidRows)
}

fn unique_values(
    rows: &[&StatisticalRow],
    column: &str,
) -> Result<Vec<StatisticalValue>, RepresentationError> {
    let mut values = BTreeMap::new();
    for row in rows {
        let value = row_value(row, column)?;
        if !matches!(value, StatisticalValue::Null) {
            values
                .entry(stable_value(value))
                .or_insert_with(|| value.clone());
        }
    }
    Ok(values.into_values().collect())
}

fn value_index(values: &[StatisticalValue]) -> ValueIndex {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| (stable_value(value), index))
        .collect()
}

fn stable_value(value: &StatisticalValue) -> String {
    match value {
        StatisticalValue::Null => "null:".to_owned(),
        StatisticalValue::String(value) => format!("s:{value}"),
        StatisticalValue::Integer(value) => format!("i:{value}"),
        StatisticalValue::Decimal(value) => format!("n:{value}"),
        StatisticalValue::Boolean(value) => format!("b:{value}"),
    }
}

fn typed_json(value: &StatisticalValue) -> Result<Value, RepresentationError> {
    match value {
        StatisticalValue::Null => Ok(Value::Null),
        StatisticalValue::String(value) => Ok(Value::String(value.clone())),
        StatisticalValue::Integer(value) => Ok(Value::from(*value)),
        StatisticalValue::Decimal(value) => serde_json::Number::from_f64(*value)
            .map(Value::Number)
            .ok_or(RepresentationError::InvalidRows),
        StatisticalValue::Boolean(value) => Ok(Value::Bool(*value)),
    }
}

fn component_value_document(
    component: &ComponentView,
    value: &StatisticalValue,
) -> Result<Value, RepresentationError> {
    if component.coded {
        let StatisticalValue::String(value) = value else {
            return Err(RepresentationError::InvalidRows);
        };
        Ok(json!({"id": value, "name": value}))
    } else {
        typed_value_document(value)
    }
}

fn typed_value_document(value: &StatisticalValue) -> Result<Value, RepresentationError> {
    Ok(json!({"value": typed_json(value)?}))
}

fn csv_value(value: Option<&StatisticalValue>) -> Result<String, RepresentationError> {
    Ok(match value.ok_or(RepresentationError::InvalidRows)? {
        StatisticalValue::Null => String::new(),
        StatisticalValue::String(value) => value.clone(),
        StatisticalValue::Integer(value) => value.to_string(),
        StatisticalValue::Decimal(value) if value.is_finite() => value.to_string(),
        StatisticalValue::Decimal(_) => return Err(RepresentationError::InvalidRows),
        StatisticalValue::Boolean(value) => value.to_string(),
    })
}

fn measure_document(dataset: &DatasetView) -> Value {
    json!({
        "id": dataset.measure.id,
        "name": dataset.measure.label,
        "description": dataset.measure.description,
        "isMandatory": true,
        "format": {"dataType": statistical_data_type(dataset.measure.value_type)},
    })
}

const fn statistical_data_type(value: StatisticalValueType) -> &'static str {
    match value {
        StatisticalValueType::Code | StatisticalValueType::String => "String",
        StatisticalValueType::Integer => "Integer",
        StatisticalValueType::Decimal => "Decimal",
        StatisticalValueType::Boolean => "Boolean",
    }
}

fn require_current_binding(dataset: &DatasetView) -> Result<(), RepresentationError> {
    let binding = &dataset.binding;
    (binding.rest_version == REST_VERSION
        && binding.data_json_version == DATA_JSON_VERSION
        && binding.data_csv_version == DATA_CSV_VERSION
        && binding.structure_json_version == STRUCTURE_JSON_VERSION)
        .then_some(())
        .ok_or(RepresentationError::UnsupportedBinding)
}

fn data_message_meta(dataset: &DatasetView) -> Value {
    json!({
        "id": message_identifier(dataset, "data"),
        "test": false,
        "prepared": dataset.release_at,
        "sender": {"id": SENDER_ID},
    })
}

fn structure_message_meta(dataset: &DatasetView, kind: StructureKind) -> Value {
    json!({
        "id": message_identifier(dataset, kind.message_suffix()),
        "test": false,
        "prepared": dataset.release_at,
        "sender": {"id": SENDER_ID},
    })
}

fn message_identifier(dataset: &DatasetView, suffix: &str) -> String {
    format!(
        "{}_{}_{}_{}",
        dataset.binding.agency_id.replace('.', "_"),
        dataset.binding.dataflow_id.replace('.', "_"),
        dataset.binding.version.replace('.', "_"),
        suffix,
    )
}

fn dataflow_urn(dataset: &DatasetView) -> String {
    format!(
        "urn:sdmx:org.sdmx.infomodel.datastructure.Dataflow={}:{}({})",
        dataset.binding.agency_id, dataset.binding.dataflow_id, dataset.binding.version
    )
}

fn data_structure_urn(dataset: &DatasetView) -> String {
    format!(
        "urn:sdmx:org.sdmx.infomodel.datastructure.DataStructure={}:{}({})",
        dataset.binding.agency_id, dataset.binding.data_structure_id, dataset.binding.version
    )
}

fn dataflow_link(dataset: &DatasetView, relationship: &str) -> Value {
    json!({"urn": dataflow_urn(dataset), "rel": relationship})
}

fn concept_urn(dataset: &DatasetView, component_id: &str) -> String {
    format!(
        "urn:sdmx:org.sdmx.infomodel.conceptscheme.Concept={}:{}({}).{}",
        dataset.binding.agency_id,
        dataset.binding.concept_scheme_id,
        dataset.binding.version,
        component_id,
    )
}

fn bounded_json(value: &Value) -> Result<Vec<u8>, RepresentationError> {
    let bytes = canonicalize_json(value).map_err(|_| RepresentationError::Serialization)?;
    ensure_output_bound(bytes.len())?;
    Ok(bytes)
}

const fn ensure_output_bound(length: usize) -> Result<(), RepresentationError> {
    if length <= MAXIMUM_SERIALIZED_BYTES {
        Ok(())
    } else {
        Err(RepresentationError::OutputTooLarge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdmx::test_dataset_view;

    fn row(area: &str, sex: &str, period: &str, value: StatisticalValue) -> StatisticalRow {
        BTreeMap::from([
            ("ref_area".into(), StatisticalValue::String(area.into())),
            ("sex".into(), StatisticalValue::String(sex.into())),
            (
                "time_period".into(),
                StatisticalValue::String(period.into()),
            ),
            ("obs_value".into(), value),
            (
                "unit_measure".into(),
                StatisticalValue::String("PERCENT".into()),
            ),
        ])
    }

    #[test]
    fn data_json_is_canonical_and_independent_of_source_row_order() {
        let dataset = test_dataset_view();
        let first = row("TH", "F", "2026-Q1", StatisticalValue::Decimal(61.5));
        let second = row("TH", "M", "2026-Q1", StatisticalValue::Integer(72));
        let forward = serialize_data_json_view(
            &dataset,
            &[first.clone(), second.clone()],
            DimensionAtObservation::TimePeriod,
        )
        .unwrap();
        let reverse = serialize_data_json_view(
            &dataset,
            &[second, first],
            DimensionAtObservation::TimePeriod,
        )
        .unwrap();
        assert_eq!(forward, reverse);

        let document: Value = serde_json::from_slice(&forward).unwrap();
        assert_eq!(document["$schema"], DATA_JSON_SCHEMA);
        assert_eq!(
            document.pointer("/data/structures/0/dimensions/series/0/values/0/id"),
            Some(&json!("TH"))
        );
        assert_eq!(
            document.pointer("/data/structures/0/dimensions/observation/0/values/0/value"),
            Some(&json!("2026-Q1"))
        );
        assert_eq!(
            document.pointer("/data/structures/0/measures/observation/0/format/dataType"),
            Some(&json!("Decimal"))
        );
    }

    #[test]
    fn all_dimensions_moves_every_dimension_to_observation_metadata() {
        let dataset = test_dataset_view();
        let bytes = serialize_data_json_view(
            &dataset,
            &[row("TH", "F", "2026-Q1", StatisticalValue::Decimal(61.5))],
            DimensionAtObservation::AllDimensions,
        )
        .unwrap();
        let document: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            document
                .pointer("/data/structures/0/dimensions/observation")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(3)
        );
        assert!(document
            .pointer("/data/dataSets/0/observations/0:0:0")
            .is_some());
    }

    #[test]
    fn csv_has_fixed_columns_typed_values_and_stable_row_order() {
        let dataset = test_dataset_view();
        let bytes = serialize_data_csv_view(
            &dataset,
            &[
                row("VN", "F", "2026-Q2", StatisticalValue::Decimal(55.25)),
                row("TH", "F", "2026-Q1", StatisticalValue::Integer(61)),
            ],
        )
        .unwrap();
        let csv = String::from_utf8(bytes).unwrap();
        let lines = csv.lines().collect::<Vec<_>>();
        assert_eq!(
            lines[0],
            "STRUCTURE,STRUCTURE_ID,ACTION,REF_AREA,SEX,TIME_PERIOD,PARTICIPATION_RATE,UNIT_MEASURE"
        );
        assert!(lines[1].contains(",TH,F,2026-Q1,61,PERCENT"));
        assert!(lines[2].contains(",VN,F,2026-Q2,55.25,PERCENT"));
    }

    #[test]
    fn csv_quotes_delimiters_and_quotes_without_interpreting_values() {
        let mut bytes = Vec::new();
        write_csv_row(&mut bytes, &["=SUM(1,2)".into(), "quoted\"value".into()]).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "\"=SUM(1,2)\",\"quoted\"\"value\"\n"
        );
    }

    #[test]
    fn structure_artifacts_have_current_root_schema_and_distinct_identity() {
        let dataset = test_dataset_view();
        let dataflow: Value = serde_json::from_slice(
            &serialize_structure_json_view(&dataset, StructureKind::Dataflow).unwrap(),
        )
        .unwrap();
        let dsd: Value = serde_json::from_slice(
            &serialize_structure_json_view(&dataset, StructureKind::DataStructure).unwrap(),
        )
        .unwrap();

        assert_eq!(dataflow["$schema"], STRUCTURE_JSON_SCHEMA);
        assert_eq!(dsd["$schema"], STRUCTURE_JSON_SCHEMA);
        assert_ne!(dataflow["meta"]["id"], dsd["meta"]["id"]);
        assert!(dataflow["meta"].get("schema").is_none());
        assert!(dsd
            .pointer(
                "/data/dataStructures/0/dataStructureComponents/dimensionList/timeDimension/position"
            )
            .is_none());
        assert_eq!(
            dsd.pointer(
                "/data/dataStructures/0/dataStructureComponents/measureList/measures/0/localRepresentation/format/dataType"
            ),
            Some(&json!("Decimal"))
        );
    }

    #[test]
    fn row_validation_rejects_bad_time_duplicates_missing_values_and_nonfinite_numbers() {
        let dataset = test_dataset_view();
        let bad_time = row("TH", "F", "2026-01", StatisticalValue::Decimal(1.0));
        assert_eq!(
            serialize_data_csv_view(&dataset, &[bad_time]),
            Err(RepresentationError::InvalidRows)
        );

        let duplicate = row("TH", "F", "2026-Q1", StatisticalValue::Decimal(1.0));
        assert_eq!(
            serialize_data_csv_view(&dataset, &[duplicate.clone(), duplicate]),
            Err(RepresentationError::InvalidRows)
        );

        let mut missing = row("TH", "F", "2026-Q1", StatisticalValue::Decimal(1.0));
        missing.remove("unit_measure");
        assert_eq!(
            serialize_data_csv_view(&dataset, &[missing]),
            Err(RepresentationError::InvalidRows)
        );

        let nonfinite = row("TH", "F", "2026-Q1", StatisticalValue::Decimal(f64::NAN));
        assert_eq!(
            serialize_data_csv_view(&dataset, &[nonfinite]),
            Err(RepresentationError::InvalidRows)
        );
    }

    #[test]
    fn empty_results_and_non_current_binding_are_explicit() {
        let mut dataset = test_dataset_view();
        assert_eq!(
            serialize_data_json_view(&dataset, &[], DimensionAtObservation::TimePeriod),
            Err(RepresentationError::EmptyRows)
        );
        dataset.binding.structure_json_version = "2.0.0".into();
        assert_eq!(
            serialize_structure_json_view(&dataset, StructureKind::Dataflow),
            Err(RepresentationError::UnsupportedBinding)
        );
    }

    #[test]
    fn output_bound_is_inclusive() {
        assert_eq!(ensure_output_bound(MAXIMUM_SERIALIZED_BYTES), Ok(()));
        assert_eq!(
            ensure_output_bound(MAXIMUM_SERIALIZED_BYTES + 1),
            Err(RepresentationError::OutputTooLarge)
        );
    }
}
