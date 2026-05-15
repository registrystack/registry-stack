// SPDX-License-Identifier: Apache-2.0
//! JSON-LD DCAT-AP and SHACL renderers for entity metadata.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use crate::config::Config;
use crate::entity::EntityRegistry;

use super::catalog::{
    catalog_document, catalog_document_for_dataset_ids, catalog_document_for_entity_ids,
    entity_class_uri, field_property_uri, normalized_base_url, DatasetMetadata, EntityMetadata,
    FieldMetadata,
};

#[must_use]
pub fn dcat_ap_document(config: &Config, registry: &EntityRegistry) -> Value {
    let catalog = catalog_document(config, registry);
    dcat_ap_document_from_catalog(catalog)
}

#[must_use]
pub fn dcat_ap_document_for_dataset_ids(
    config: &Config,
    registry: &EntityRegistry,
    dataset_ids: &BTreeSet<String>,
) -> Value {
    let catalog = catalog_document_for_dataset_ids(config, registry, dataset_ids);
    dcat_ap_document_from_catalog(catalog)
}

#[must_use]
pub fn dcat_ap_document_for_entity_ids(
    config: &Config,
    registry: &EntityRegistry,
    entity_ids: &BTreeSet<(String, String)>,
) -> Value {
    let catalog = catalog_document_for_entity_ids(config, registry, entity_ids);
    dcat_ap_document_from_catalog(catalog)
}

fn dcat_ap_document_from_catalog(catalog: super::catalog::CatalogDocument) -> Value {
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
        "dcterms:publisher": publisher_agent(&catalog.publisher),
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

#[must_use]
pub fn entity_schema_document(
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

    Some(entity_schema_object(&base_url, dataset, entity))
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
        "dcterms:publisher": publisher_agent(&dataset.publisher),
        "dcterms:rightsHolder": dataset.owner,
        "dcterms:accessRights": access_rights_uri(dataset.access_rights),
        "dcterms:accrualPeriodicity": frequency_uri(dataset.update_frequency),
        "dcterms:conformsTo": dataset.conforms_to,
        "dcat:distribution": distributions,
    })
}

fn entity_shape(base_url: &str, dataset: &DatasetMetadata, entity: &EntityMetadata) -> Value {
    let field_properties = entity.fields.iter().map(|field| {
        let mut property = json!({
            "@type": "sh:PropertyShape",
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
            "@type": "sh:PropertyShape",
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
        "physical_type": field.r#type,
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

fn publisher_agent(name: &str) -> Value {
    json!({
        "@type": "foaf:Agent",
        "foaf:name": name,
    })
}

fn access_rights_uri(access_rights: &str) -> &'static str {
    match access_rights {
        "public" => "http://publications.europa.eu/resource/authority/access-right/PUBLIC",
        "restricted" => "http://publications.europa.eu/resource/authority/access-right/RESTRICTED",
        "non_public" => "http://publications.europa.eu/resource/authority/access-right/NON_PUBLIC",
        _ => "http://publications.europa.eu/resource/authority/access-right/RESTRICTED",
    }
}

fn frequency_uri(frequency: &str) -> &'static str {
    match frequency {
        "continuous" => "http://publications.europa.eu/resource/authority/frequency/CONT",
        "daily" => "http://publications.europa.eu/resource/authority/frequency/DAILY",
        "weekly" => "http://publications.europa.eu/resource/authority/frequency/WEEKLY",
        "monthly" => "http://publications.europa.eu/resource/authority/frequency/MONTHLY",
        "quarterly" => "http://publications.europa.eu/resource/authority/frequency/QUARTERLY",
        "annual" => "http://publications.europa.eu/resource/authority/frequency/ANNUAL",
        "irregular" => "http://publications.europa.eu/resource/authority/frequency/IRREG",
        "unknown" => "http://publications.europa.eu/resource/authority/frequency/UNKNOWN",
        _ => "http://publications.europa.eu/resource/authority/frequency/UNKNOWN",
    }
}

fn context() -> Value {
    json!({
        "dcat": "http://www.w3.org/ns/dcat#",
        "dcterms": "http://purl.org/dc/terms/",
        "foaf": "http://xmlns.com/foaf/0.1/",
        "sh": "http://www.w3.org/ns/shacl#",
        "data_gate": "https://data-gate.dev/ns#",
        "dcat:accessURL": { "@type": "@id" },
        "dcat:distribution": { "@type": "@id" },
        "dcterms:accessRights": { "@type": "@id" },
        "dcterms:accrualPeriodicity": { "@type": "@id" },
        "dcterms:conformsTo": { "@type": "@id" },
        "dcterms:isPartOf": { "@type": "@id" },
        "sh:class": { "@type": "@id" },
        "sh:path": { "@type": "@id" },
        "sh:targetClass": { "@type": "@id" },
    })
}
