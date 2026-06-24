// SPDX-License-Identifier: Apache-2.0
//! Aggregate discovery and structure response rendering.

use std::collections::{BTreeMap, BTreeSet};

use axum::Extension;
use serde_json::{json, Value};

use crate::auth::Principal;
use crate::config::DatasetConfig;

pub(super) fn aggregate_list_json(item: crate::query::aggregates::AggregateListItem) -> Value {
    json!({
        "aggregate_id": item.aggregate_id,
        "title": item.title,
        "description": item.description,
        "default_group_by": item.default_group_by,
        "dimensions": item.dimensions.into_iter().map(|dimension| json!({
            "id": dimension.id,
            "label": dimension.label,
            "field": dimension.field,
            "codelist": dimension.codelist,
        })).collect::<Vec<_>>(),
        "measures": item.indicators.into_iter().map(|indicator| json!({
            "id": indicator.id,
            "label": indicator.label,
            "aggregation_method": indicator.function,
            "column": indicator.column,
            "unit_measure": indicator.unit_measure,
            "unit_multiplier": indicator.unit_mult,
            "decimals": indicator.decimals,
            "frequency": indicator.frequency,
            "definition_uri": indicator.definition_uri,
        })).collect::<Vec<_>>(),
        "min_cell_size": item.min_cell_size,
        "temporal_field": item.temporal_field,
        "edr_collection_id": item.collection_id,
    })
}

pub(super) fn filter_visible_aggregates(
    principal: Option<&Extension<Principal>>,
    aggregates: Vec<crate::query::aggregates::AggregateListItem>,
) -> Vec<crate::query::aggregates::AggregateListItem> {
    aggregates
        .into_iter()
        .filter(|aggregate| {
            principal_has_scope(principal, &aggregate.metadata_scope)
                && aggregate
                    .source_entity_metadata_scope
                    .as_deref()
                    .is_none_or(|scope| principal_has_scope(principal, scope))
        })
        .collect()
}

pub(super) fn aggregate_structure_json(
    dataset: &DatasetConfig,
    aggregate: &crate::config::AggregateConfig,
) -> Value {
    let item = crate::query::aggregates::AggregateListItem {
        aggregate_id: aggregate.id.to_string(),
        title: aggregate.title.clone(),
        description: aggregate.description.clone(),
        metadata_scope: aggregate
            .access
            .as_ref()
            .and_then(|access| access.metadata_scope.clone())
            .unwrap_or_else(|| format!("{}:metadata", dataset.id)),
        source_entity_metadata_scope: aggregate
            .source_entity
            .as_deref()
            .and_then(|name| dataset.entities.iter().find(|entity| entity.name == name))
            .map(|entity| entity.access.metadata_scope.clone()),
        dimensions: aggregate
            .dimensions
            .iter()
            .map(
                |dimension| crate::query::aggregates::AggregateDimensionItem {
                    id: dimension.id.clone(),
                    label: dimension.label.clone(),
                    field: dimension.field.clone(),
                    codelist: dimension.codelist.clone(),
                },
            )
            .collect(),
        indicators: aggregate
            .indicators
            .iter()
            .map(
                |indicator| crate::query::aggregates::AggregateIndicatorItem {
                    id: indicator.id.clone(),
                    label: indicator.label.clone(),
                    function: match indicator.function {
                        crate::config::AggregateFunction::Count => "count",
                        crate::config::AggregateFunction::Sum => "sum",
                        crate::config::AggregateFunction::Avg => "avg",
                        crate::config::AggregateFunction::Min => "min",
                        crate::config::AggregateFunction::Max => "max",
                        crate::config::AggregateFunction::Median => "median",
                        crate::config::AggregateFunction::CountDistinct => "count_distinct",
                        crate::config::AggregateFunction::Stddev => "stddev",
                    },
                    column: indicator.column.clone(),
                    unit_measure: indicator.unit_measure.clone(),
                    unit_mult: indicator.unit_mult,
                    decimals: indicator.decimals,
                    frequency: indicator.frequency.clone(),
                    definition_uri: indicator.definition_uri.clone(),
                },
            )
            .collect(),
        default_group_by: aggregate.default_group_by.clone(),
        temporal_field: aggregate.temporal_field.clone(),
        min_cell_size: aggregate.disclosure_control.effective_min_cell_size(),
        collection_id: crate::query::aggregates::aggregate_edr_collection_id(dataset, aggregate),
    };
    let mut value = aggregate_list_json(item);
    value["links"] = json!([
        { "rel": "self", "href": format!("/v1/datasets/{}/aggregates/{}/structure", dataset.id, aggregate.id), "type": "application/json" },
        { "rel": "up", "href": format!("/v1/datasets/{}/aggregates/{}", dataset.id, aggregate.id), "type": "application/json" }
    ]);
    value
}

pub(super) fn measure_discovery_items(
    dataset_id: &str,
    aggregates: &[crate::query::aggregates::AggregateListItem],
) -> Vec<Value> {
    let mut items = BTreeMap::<String, MeasureDiscovery>::new();
    for aggregate in aggregates {
        let aggregate_ref = AggregateDiscoveryRef::new(dataset_id, aggregate);
        let queryable_via = aggregate_ref.queryable_via();
        let dimensions = aggregate
            .dimensions
            .iter()
            .map(|dimension| dimension.id.clone())
            .collect::<Vec<_>>();
        for indicator in &aggregate.indicators {
            let item = items
                .entry(indicator.id.clone())
                .or_insert_with(|| MeasureDiscovery::new(indicator));
            item.valid_dimensions.extend(dimensions.iter().cloned());
            item.queryable_via.extend(queryable_via.iter().cloned());
            item.aggregates.push(aggregate_ref.as_json());
        }
    }
    items
        .into_values()
        .map(|item| item.into_json(dataset_id))
        .collect()
}

pub(super) fn dimension_discovery_items(
    dataset_id: &str,
    aggregates: &[crate::query::aggregates::AggregateListItem],
) -> Vec<Value> {
    let mut items = BTreeMap::<String, DimensionDiscovery>::new();
    for aggregate in aggregates {
        let aggregate_ref = AggregateDiscoveryRef::new(dataset_id, aggregate);
        let queryable_via = aggregate_ref.queryable_via();
        for dimension in &aggregate.dimensions {
            let item = items
                .entry(dimension.id.clone())
                .or_insert_with(|| DimensionDiscovery::new(dimension));
            item.queryable_via.extend(queryable_via.iter().cloned());
            item.aggregates.push(aggregate_ref.as_json());
        }
    }
    items
        .into_values()
        .map(|item| item.into_json(dataset_id))
        .collect()
}

fn principal_has_scope(principal: Option<&Extension<Principal>>, required: &str) -> bool {
    principal
        .map(|Extension(principal)| principal.scopes.contains(required))
        .unwrap_or(false)
}

struct MeasureDiscovery {
    id: String,
    label: String,
    function: &'static str,
    column: String,
    unit_measure: String,
    unit_mult: Option<i32>,
    decimals: Option<u32>,
    frequency: Option<String>,
    definition_uri: Option<String>,
    valid_dimensions: BTreeSet<String>,
    queryable_via: BTreeSet<String>,
    aggregates: Vec<Value>,
}

impl MeasureDiscovery {
    fn new(indicator: &crate::query::aggregates::AggregateIndicatorItem) -> Self {
        Self {
            id: indicator.id.clone(),
            label: indicator.label.clone(),
            function: indicator.function,
            column: indicator.column.clone(),
            unit_measure: indicator.unit_measure.clone(),
            unit_mult: indicator.unit_mult,
            decimals: indicator.decimals,
            frequency: indicator.frequency.clone(),
            definition_uri: indicator.definition_uri.clone(),
            valid_dimensions: BTreeSet::new(),
            queryable_via: BTreeSet::new(),
            aggregates: Vec::new(),
        }
    }

    fn into_json(self, dataset_id: &str) -> Value {
        json!({
            "id": self.id,
            "label": self.label,
            "aggregation_method": self.function,
            "column": self.column,
            "unit_measure": self.unit_measure,
            "unit_multiplier": self.unit_mult,
            "decimals": self.decimals,
            "frequency": self.frequency,
            "definition_uri": self.definition_uri,
            "valid_dimensions": self.valid_dimensions.into_iter().collect::<Vec<_>>(),
            "queryable_via": self.queryable_via.into_iter().collect::<Vec<_>>(),
            "aggregates": self.aggregates,
            "links": [
                { "rel": "self", "href": format!("/v1/datasets/{dataset_id}/measures/{}", self.id), "type": "application/json" }
            ]
        })
    }
}

struct DimensionDiscovery {
    id: String,
    label: String,
    field: String,
    codelist: Option<String>,
    queryable_via: BTreeSet<String>,
    aggregates: Vec<Value>,
}

impl DimensionDiscovery {
    fn new(dimension: &crate::query::aggregates::AggregateDimensionItem) -> Self {
        Self {
            id: dimension.id.clone(),
            label: dimension.label.clone(),
            field: dimension.field.clone(),
            codelist: dimension.codelist.clone(),
            queryable_via: BTreeSet::new(),
            aggregates: Vec::new(),
        }
    }

    fn into_json(self, dataset_id: &str) -> Value {
        json!({
            "id": self.id,
            "label": self.label,
            "field": self.field,
            "codelist": self.codelist,
            "queryable_via": self.queryable_via.into_iter().collect::<Vec<_>>(),
            "aggregates": self.aggregates,
            "links": [
                { "rel": "self", "href": format!("/v1/datasets/{dataset_id}/dimensions/{}", self.id), "type": "application/json" }
            ]
        })
    }
}

struct AggregateDiscoveryRef<'a> {
    dataset_id: &'a str,
    aggregate_id: &'a str,
    collection_id: Option<&'a str>,
}

impl<'a> AggregateDiscoveryRef<'a> {
    fn new(
        dataset_id: &'a str,
        aggregate: &'a crate::query::aggregates::AggregateListItem,
    ) -> Self {
        Self {
            dataset_id,
            aggregate_id: &aggregate.aggregate_id,
            collection_id: aggregate.collection_id.as_deref(),
        }
    }

    fn queryable_via(&self) -> Vec<String> {
        let mut values = vec![format!("aggregates:{}", self.aggregate_id)];
        if let Some(collection_id) = self.collection_id {
            values.push(format!("edr:{collection_id}"));
        }
        values
    }

    fn as_json(&self) -> Value {
        let mut value = json!({
            "aggregate_id": self.aggregate_id,
            "href": format!("/v1/datasets/{}/aggregates/{}", self.dataset_id, self.aggregate_id),
        });
        if let Some(collection_id) = self.collection_id {
            value["edr_collection_id"] = json!(collection_id);
            value["edr_area_href"] = json!(format!("/ogc/edr/v1/collections/{collection_id}/area"));
        }
        value
    }
}
