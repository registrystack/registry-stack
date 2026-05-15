// SPDX-License-Identifier: Apache-2.0
//! JSON-LD DCAT-AP and SHACL renderers for entity metadata.

use serde_json::{json, Value};

use crate::config::Config;
use crate::entity::EntityRegistry;

use super::catalog::{
    catalog_document, entity_class_uri, field_property_uri, normalized_base_url, DatasetMetadata,
    EntityMetadata, FieldMetadata,
};

#[must_use]
pub fn dcat_ap_document(config: &Config, registry: &EntityRegistry) -> Value {
    let catalog = catalog_document(config, registry);
    let datasets = catalog
        .datasets
        .iter()
        .map(dcat_dataset)
        .collect::<Vec<_>>();
    let shapes = catalog
        .datasets
        .iter()
        .flat_map(|dataset| {
            dataset
                .entities
                .iter()
                .map(|entity| entity_shape(&catalog.base_url, dataset, entity))
        })
        .collect::<Vec<_>>();

    json!({
        "@context": context(),
        "@id": catalog.links.dcat_ap,
        "@type": "dcat:Catalog",
        "dcterms:title": catalog.title,
        "dcterms:publisher": catalog.publisher,
        "dcat:dataset": datasets,
        "sh:shapesGraph": shapes,
    })
}

#[must_use]
pub fn entity_shape_document(
    config: &Config,
    registry: &EntityRegistry,
    dataset_id: &str,
    entity_name: &str,
) -> Option<Value> {
    let base_url = normalized_base_url(&config.catalog.base_url);
    let catalog = catalog_document(config, registry);
    let dataset = catalog
        .datasets
        .iter()
        .find(|dataset| dataset.dataset_id == dataset_id)?;
    let entity = dataset
        .entities
        .iter()
        .find(|entity| entity.name == entity_name)?;

    Some(json!({
        "@context": context(),
        "schema": entity_schema_object(&base_url, dataset, entity),
        "shape": entity_shape(&base_url, dataset, entity),
    }))
}

fn dcat_dataset(dataset: &DatasetMetadata) -> Value {
    let distributions = dataset
        .entities
        .iter()
        .map(|entity| {
            json!({
                "@id": entity.links.collection,
                "@type": "dcat:Distribution",
                "dcterms:title": entity.title.as_deref().unwrap_or(entity.name.as_str()),
                "dcat:accessURL": entity.links.collection,
                "dcterms:conformsTo": entity.links.schema,
            })
        })
        .collect::<Vec<_>>();

    json!({
        "@id": dataset.links.self_url,
        "@type": "dcat:Dataset",
        "dcterms:identifier": dataset.dataset_id,
        "dcterms:title": dataset.title,
        "dcterms:description": dataset.description,
        "dcterms:publisher": dataset.publisher,
        "dcterms:rightsHolder": dataset.owner,
        "dcterms:accessRights": dataset.access_rights,
        "dcterms:accrualPeriodicity": dataset.update_frequency,
        "dcterms:conformsTo": dataset.conforms_to,
        "dcat:distribution": distributions,
    })
}

fn entity_shape(base_url: &str, dataset: &DatasetMetadata, entity: &EntityMetadata) -> Value {
    let field_properties = entity.fields.iter().map(|field| {
        let mut property = json!({
            "sh:path": field_property_uri(base_url, &dataset.dataset_id, &entity.name, field),
            "sh:name": field.name,
            "data_gate:type": field.r#type,
            "sh:minCount": if field.nullable { 0 } else { 1 },
        });
        insert_optional(
            &mut property,
            "data_gate:codelist",
            field.codelist.as_deref(),
        );
        insert_optional(&mut property, "data_gate:unit", field.unit.as_deref());
        insert_optional(
            &mut property,
            "data_gate:language",
            field.language.as_deref(),
        );
        property
    });
    let relationship_properties = entity.relationships.iter().map(|relationship| {
        let path = relationship.concept_uri.clone().unwrap_or_else(|| {
            format!(
                "{base_url}/datasets/{}/{}/relationships/{}",
                dataset.dataset_id, entity.name, relationship.name
            )
        });
        let target_class = dataset
            .entities
            .iter()
            .find(|candidate| candidate.name == relationship.target)
            .map(|target| entity_class_uri(base_url, &dataset.dataset_id, target))
            .unwrap_or_else(|| {
                format!(
                    "{base_url}/datasets/{}/{}/schema",
                    dataset.dataset_id, relationship.target
                )
            });
        json!({
            "sh:path": path,
            "sh:name": relationship.name,
            "data_gate:relationshipKind": relationship.kind,
            "data_gate:targetEntity": relationship.target,
            "data_gate:foreignKey": relationship.foreign_key,
            "sh:class": target_class,
        })
    });

    json!({
        "@id": entity.links.schema,
        "@type": "sh:NodeShape",
        "sh:targetClass": entity_class_uri(base_url, &dataset.dataset_id, entity),
        "dcterms:isPartOf": dataset.links.self_url,
        "dcterms:identifier": format!("{}:{}", dataset.dataset_id, entity.name),
        "sh:name": entity.name,
        "data_gate:primaryKey": entity.primary_key,
        "sh:property": field_properties.chain(relationship_properties).collect::<Vec<_>>(),
    })
}

fn entity_schema_object(
    base_url: &str,
    dataset: &DatasetMetadata,
    entity: &EntityMetadata,
) -> Value {
    let fields = entity
        .fields
        .iter()
        .map(|field| field_schema_object(base_url, &dataset.dataset_id, &entity.name, field))
        .collect::<Vec<_>>();
    let relationships = entity
        .relationships
        .iter()
        .map(|relationship| {
            json!({
                "name": relationship.name,
                "kind": relationship.kind,
                "target": relationship.target,
                "foreign_key": relationship.foreign_key,
                "concept_uri": relationship.concept_uri,
                "links": relationship.links,
            })
        })
        .collect::<Vec<_>>();

    json!({
        "dataset_id": dataset.dataset_id,
        "entity": entity.name,
        "title": entity.title,
        "description": entity.description,
        "concept_uri": entity.concept_uri,
        "primary_key": entity.primary_key,
        "fields": fields,
        "relationships": relationships,
        "links": entity.links,
    })
}

fn field_schema_object(
    base_url: &str,
    dataset_id: &str,
    entity_name: &str,
    field: &FieldMetadata,
) -> Value {
    json!({
        "name": field.name,
        "type": field.r#type,
        "nullable": field.nullable,
        "concept_uri": field.concept_uri,
        "codelist": field.codelist,
        "unit": field.unit,
        "language": field.language,
        "property_uri": field_property_uri(base_url, dataset_id, entity_name, field),
    })
}

fn insert_optional(target: &mut Value, key: &'static str, value: Option<&str>) {
    if let Some(value) = value {
        target[key] = json!(value);
    }
}

fn context() -> Value {
    json!({
        "dcat": "http://www.w3.org/ns/dcat#",
        "dcterms": "http://purl.org/dc/terms/",
        "sh": "http://www.w3.org/ns/shacl#",
        "data_gate": "https://data-gate.dev/ns#",
    })
}
