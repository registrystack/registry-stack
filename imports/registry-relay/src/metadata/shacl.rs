// SPDX-License-Identifier: Apache-2.0
//! JSON-LD DCAT-AP and SHACL renderers for entity metadata.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use crate::config::{AdmsStatus, Config};
use crate::entity::EntityRegistry;

use super::catalog::{
    catalog_document, catalog_document_for_dataset_ids, catalog_document_for_entity_ids,
    entity_class_uri, field_property_uri, normalized_base_url, CatalogDocument, DatasetMetadata,
    EntityMetadata, FieldMetadata,
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

fn dcat_ap_document_from_catalog(catalog: CatalogDocument) -> Value {
    let authority_type = catalog.authority_type.as_deref();
    let datasets = catalog
        .datasets
        .iter()
        .map(|dataset| dcat_dataset(dataset, authority_type))
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
        "dspace:participantId": catalog.participant_id,
        "dcterms:title": catalog.title,
        "dcterms:description": format!("DCAT-AP catalog for {}", catalog.title),
        "dcterms:publisher": publisher_agent(&catalog.publisher, authority_type),
        "dcat:landingPage": catalog.links.self_url,
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

fn dcat_dataset(dataset: &DatasetMetadata, authority_type: Option<&str>) -> Value {
    let mut distributions = dataset_standard_distributions(dataset);
    distributions.extend(
        dataset
            .entities
            .iter()
            .flat_map(entity_distributions)
            .collect::<Vec<_>>(),
    );

    // Collect distinct codelist IRIs across all entity fields for dct:references.
    let codelist_iris: Vec<&str> = {
        let mut seen = BTreeSet::new();
        let mut iris = Vec::new();
        for entity in &dataset.entities {
            for field in &entity.fields {
                if let Some(cl) = field.codelist.as_deref() {
                    if seen.insert(cl) {
                        iris.push(cl);
                    }
                }
            }
        }
        iris
    };

    let mut obj = json!({
        "@id": dataset.links.self_url,
        "@type": "dcat:Dataset",
        "dcterms:identifier": dataset.dataset_id,
        "dcterms:title": dataset.title,
        "dcterms:description": dataset.description,
        "dcterms:publisher": publisher_agent(&dataset.publisher, authority_type),
        "dcterms:rightsHolder": dataset.owner,
        "dcterms:accessRights": access_rights_uri(dataset.access_rights),
        "dcterms:accrualPeriodicity": frequency_uri(dataset.update_frequency),
        "dcterms:conformsTo": dataset.conforms_to,
        "adms:status": adms_status_uri(dataset.adms_status),
        "dcat:landingPage": dataset.links.self_url,
        "odrl:hasPolicy": dataset_offer(dataset),
        "dcat:distribution": distributions,
    });

    if let Some(spatial) = dataset.spatial_coverage.as_deref() {
        obj["dcterms:spatial"] = json!(spatial);
    }

    // Project convention: surface distinct codelist IRIs used by this
    // dataset's entity fields as typed `skos:ConceptScheme` nodes under
    // `dcterms:references`, so external tooling can resolve the type
    // without dereferencing the codelist URL. BRegDCAT-AP does not
    // prescribe a property for codelist linkage; `dct:references` on
    // Dataset has range `rdfs:Resource` ("related resource"), and a
    // `skos:ConceptScheme` is an `rdfs:Resource`, so this usage is
    // type-valid even though it is not spec-mandated.
    if !codelist_iris.is_empty() {
        obj["dcterms:references"] = Value::Array(
            codelist_iris
                .iter()
                .map(|iri| json!({ "@id": iri, "@type": "skos:ConceptScheme" }))
                .collect(),
        );
    }

    obj
}

fn dataset_standard_distributions(dataset: &DatasetMetadata) -> Vec<Value> {
    let mut distributions = Vec::new();
    if let Some(ogc) = &dataset.standards.ogc_api_features {
        distributions.push(dataset_ogc_distribution(dataset, ogc));
    }
    if let Some(spdci) = &dataset.standards.spdci {
        distributions.extend(
            spdci
                .registries
                .iter()
                .map(|registry| dataset_spdci_distribution(dataset, registry)),
        );
    }
    distributions
}

fn dataset_ogc_distribution(
    dataset: &DatasetMetadata,
    ogc: &super::catalog::OgcApiFeaturesMetadata,
) -> Value {
    let access_service = format!("{}#ogc-api-features-service", ogc.collections);
    json!({
        "@id": ogc.collections,
        "@type": "dcat:Distribution",
        "dcterms:title": format!("{} OGC API Features service", dataset.title),
        "dcterms:format": {
            "@id": "registry_relay:OGCAPI-Features",
        },
        "dcat:accessURL": ogc.collections,
        "dcat:accessService": {
            "@id": access_service,
            "@type": "dcat:DataService",
            "dcterms:title": format!("{} OGC API Features service", dataset.title),
            "dspace:dataServiceType": "registry_relay:ogc-api-features",
            "dcat:endpointURL": ogc.collections,
            "dcat:endpointDescription": openapi_url(&dataset.links.self_url),
            "dcat:servesDataset": dataset.links.self_url,
            "dcterms:conformsTo": [
                "http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/core",
                "http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/geojson",
            ],
        },
        "dcterms:conformsTo": [
            "http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/core",
            "http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/geojson",
        ],
    })
}

fn dataset_spdci_distribution(
    dataset: &DatasetMetadata,
    registry: &super::catalog::SpdciRegistryMetadata,
) -> Value {
    let access_service = format!("{}#spdci-sync-service", registry.sync_search);
    json!({
        "@id": registry.sync_search,
        "@type": "dcat:Distribution",
        "dcterms:title": format!("{} SP DCI {} sync service", dataset.title, registry.registry),
        "dcterms:format": {
            "@id": "registry_relay:SPDCI-Sync",
        },
        "dcat:accessURL": registry.sync_search,
        "dcat:accessService": {
            "@id": access_service,
            "@type": "dcat:DataService",
            "dcterms:title": format!("{} SP DCI {} sync service", dataset.title, registry.registry),
            "dspace:dataServiceType": "registry_relay:spdci-sync",
            "dcat:endpointURL": registry.sync_search,
            "dcat:endpointDescription": openapi_url(&dataset.links.self_url),
            "dcat:servesDataset": dataset.links.self_url,
            "dcterms:conformsTo": "https://spdci.org/",
            "registry_relay:registryName": registry.registry,
            "registry_relay:recordType": registry.record_type,
        },
        "dcterms:conformsTo": "https://spdci.org/",
    })
}

fn entity_distributions(entity: &EntityMetadata) -> Vec<Value> {
    #[cfg(not(feature = "ogcapi-features"))]
    {
        vec![entity_rest_distribution(entity)]
    }
    #[cfg(feature = "ogcapi-features")]
    {
        let mut distributions = vec![entity_rest_distribution(entity)];
        if let Some(distribution) = entity_ogc_distribution(entity) {
            distributions.push(distribution);
        }
        distributions
    }
}

fn entity_rest_distribution(entity: &EntityMetadata) -> Value {
    let access_service = format!("{}#data-service", entity.links.collection);
    json!({
        "@id": entity.links.collection,
        "@type": "dcat:Distribution",
        "dcterms:title": entity.title.as_deref().unwrap_or(entity.name.as_str()),
        "dcterms:format": {
            "@id": "registry_relay:HttpData-PULL",
        },
        "dcat:accessURL": entity.links.collection,
        "dcat:accessService": {
            "@id": access_service,
            "@type": "dcat:DataService",
            "dcterms:title": format!(
                "{} REST access service",
                entity.title.as_deref().unwrap_or(entity.name.as_str())
            ),
            "dspace:dataServiceType": "registry_relay:entity-rest",
            "dcat:endpointURL": entity.links.collection,
            "dcat:endpointDescription": openapi_url(&entity.links.collection),
            "dcterms:conformsTo": entity.links.schema,
        },
        "dcterms:conformsTo": entity.links.schema,
    })
}

#[cfg(feature = "ogcapi-features")]
fn entity_ogc_distribution(entity: &EntityMetadata) -> Option<Value> {
    let collection = entity.links.ogc_collection.as_ref()?;
    let items = entity.links.ogc_items.as_ref()?;
    let access_service = format!("{collection}#ogc-api-features-service");
    Some(json!({
        "@id": collection,
        "@type": "dcat:Distribution",
        "dcterms:title": format!(
            "{} OGC API Features collection",
            entity.title.as_deref().unwrap_or(entity.name.as_str())
        ),
        "dcterms:format": {
            "@id": "registry_relay:OGCAPI-Features",
        },
        "dcat:accessURL": collection,
        "dcat:downloadURL": items,
        "dcat:accessService": {
            "@id": access_service,
            "@type": "dcat:DataService",
            "dcterms:title": format!(
                "{} OGC API Features service",
                entity.title.as_deref().unwrap_or(entity.name.as_str())
            ),
            "dspace:dataServiceType": "registry_relay:ogc-api-features",
            "dcat:endpointURL": collection,
            "dcat:endpointDescription": openapi_url(collection),
            "dcterms:conformsTo": "http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/core",
        },
        "dcterms:conformsTo": [
            "http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/core",
            "http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/geojson",
        ],
    }))
}

fn dataset_offer(dataset: &DatasetMetadata) -> Value {
    json!({
        "@id": format!("{}#offer", dataset.links.self_url),
        "@type": "odrl:Offer",
        "odrl:permission": [{
            "odrl:action": {
                "@id": "odrl:use",
            },
        }],
    })
}

fn entity_shape(base_url: &str, dataset: &DatasetMetadata, entity: &EntityMetadata) -> Value {
    let field_properties = entity.fields.iter().map(|field| {
        let mut property = json!({
            "@type": "sh:PropertyShape",
            "sh:path": field_property_uri(base_url, &dataset.dataset_id, &entity.name, field),
            "sh:name": field.name,
            "sh:nodeKind": "sh:Literal",
            "sh:datatype": shacl_datatype(field.r#type),
            "registry_relay:type": field.r#type,
            "sh:minCount": if field.nullable { 0 } else { 1 },
            "sh:maxCount": 1,
        });
        insert_optional(
            &mut property,
            "registry_relay:codelist",
            field.codelist.as_deref(),
        );
        // Codelist IRIs surface as typed `skos:ConceptScheme` nodes under
        // `dcterms:references` on the parent dataset (see `dcat_dataset`).
        // We intentionally do NOT put `skos:inScheme` here: `skos:inScheme`
        // applies to `skos:Concept` instances, not to a `sh:PropertyShape`.
        insert_optional(&mut property, "registry_relay:unit", field.unit.as_deref());
        insert_optional(
            &mut property,
            "registry_relay:language",
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
        let mut property = json!({
            "@type": "sh:PropertyShape",
            "sh:path": path,
            "sh:name": relationship.name,
            "sh:nodeKind": "sh:IRI",
            "registry_relay:relationshipKind": relationship.kind,
            "registry_relay:targetEntity": relationship.target,
            "registry_relay:foreignKey": relationship.foreign_key,
            "sh:class": target_class,
        });
        if let Some(max_count) = relationship_max_count(relationship.kind) {
            property["sh:maxCount"] = json!(max_count);
        }
        property
    });

    json!({
        "@id": entity.links.schema,
        "@type": "sh:NodeShape",
        "sh:targetClass": entity_class_uri(base_url, &dataset.dataset_id, entity),
        "dcterms:isPartOf": dataset.links.self_url,
        "dcterms:identifier": format!("{}:{}", dataset.dataset_id, entity.name),
        "sh:name": entity.name,
        "sh:nodeKind": "sh:IRI",
        "registry_relay:primaryKey": entity.primary_key,
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

fn openapi_url(collection_url: &str) -> String {
    let base_url = ["/ogc/v1/", "/datasets/"]
        .iter()
        .find_map(|marker| {
            collection_url
                .find(marker)
                .map(|index| &collection_url[..index])
        })
        .unwrap_or(collection_url);
    format!("{base_url}/openapi.json")
}

fn shacl_datatype(field_type: &str) -> &'static str {
    match field_type {
        "string" => "xsd:string",
        "number" => "xsd:decimal",
        "integer" => "xsd:integer",
        "boolean" => "xsd:boolean",
        "date" => "xsd:date",
        "timestamp" => "xsd:dateTime",
        _ => "xsd:string",
    }
}

fn relationship_max_count(kind: &str) -> Option<u8> {
    match kind {
        "belongs_to" | "has_one" => Some(1),
        _ => None,
    }
}

fn publisher_agent(name: &str, authority_type: Option<&str>) -> Value {
    let mut agent = json!({
        "@type": "foaf:Agent",
        "foaf:name": name,
    });
    if let Some(at) = authority_type {
        agent["dcterms:type"] = json!(at);
    }
    agent
}

fn adms_status_uri(status: AdmsStatus) -> &'static str {
    match status {
        AdmsStatus::UnderDevelopment => "http://purl.org/adms/status/UnderDevelopment",
        AdmsStatus::Completed => "http://purl.org/adms/status/Completed",
        AdmsStatus::Deprecated => "http://purl.org/adms/status/Deprecated",
        AdmsStatus::Withdrawn => "http://purl.org/adms/status/Withdrawn",
    }
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
        "adms": "http://www.w3.org/ns/adms#",
        "dcat": "http://www.w3.org/ns/dcat#",
        "dcterms": "http://purl.org/dc/terms/",
        "dspace": "https://w3id.org/dspace/2025/1/",
        "foaf": "http://xmlns.com/foaf/0.1/",
        "odrl": "http://www.w3.org/ns/odrl/2/",
        "org": "http://www.w3.org/ns/org#",
        "sh": "http://www.w3.org/ns/shacl#",
        "skos": "http://www.w3.org/2004/02/skos/core#",
        "registry_relay": "https://registry-relay.dev/ns#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",
        "adms:status": { "@type": "@id" },
        "dcat:accessURL": { "@type": "@id" },
        "dcat:accessService": { "@type": "@id" },
        "dcat:distribution": { "@type": "@id" },
        "dcat:downloadURL": { "@type": "@id" },
        "dcat:endpointDescription": { "@type": "@id" },
        "dcat:endpointURL": { "@type": "@id" },
        "dcat:landingPage": { "@type": "@id" },
        "dcat:servesDataset": { "@type": "@id" },
        "dcterms:format": { "@type": "@id" },
        "dcterms:accessRights": { "@type": "@id" },
        "dcterms:accrualPeriodicity": { "@type": "@id" },
        "dcterms:conformsTo": { "@type": "@id" },
        "dcterms:isPartOf": { "@type": "@id" },
        "dcterms:spatial": { "@type": "@id" },
        "dcterms:type": { "@type": "@id" },
        "odrl:action": { "@type": "@id" },
        "odrl:hasPolicy": { "@type": "@id" },
        "sh:class": { "@type": "@id" },
        "sh:datatype": { "@type": "@id" },
        "sh:nodeKind": { "@type": "@id" },
        "sh:path": { "@type": "@id" },
        "sh:targetClass": { "@type": "@id" },
    })
}
