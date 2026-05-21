// SPDX-License-Identifier: Apache-2.0
//! JSON-LD DCAT-AP and SHACL renderers for entity metadata.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use crate::config::{AdmsStatus, Config};
use crate::entity::EntityRegistry;

use super::catalog::{
    catalog_document, catalog_document_for_dataset_ids, catalog_document_for_entity_ids,
    entity_class_uri, field_property_uri, normalized_base_url, CatalogDocument, DatasetMetadata,
    EntityMetadata, FieldMetadata, PublicServiceMetadata,
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

pub(crate) fn dcat_ap_document_from_catalog(catalog: CatalogDocument) -> Value {
    let authority_type = catalog.authority_type.as_deref();
    let datasets = catalog
        .datasets
        .iter()
        .map(|dataset| dcat_dataset(dataset, authority_type, &catalog.participant_id))
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
    let public_services = catalog
        .datasets
        .iter()
        .flat_map(|dataset| {
            dataset
                .public_services
                .iter()
                .map(move |service| public_service_node(dataset, service))
        })
        .collect::<Vec<_>>();

    let mut obj = json!({
        "@context": context(),
        "@id": catalog.links.dcat_ap,
        "@type": "dcat:Catalog",
        "dcterms:identifier": slug_identifier(&catalog.title),
        "dcterms:title": catalog.title,
        "dcterms:description": format!("DCAT-AP catalog for {}", catalog.title),
        "dcterms:publisher": publisher_agent(&catalog.publisher, authority_type),
        "dcat:landingPage": catalog.links.self_url,
        "dcat:dataset": datasets,
        "sh:shapesGraph": shapes,
    });
    if !public_services.is_empty() {
        // JSON-LD `@included` carries related CPSV evidence without
        // inventing a Registry Relay source-of-truth predicate.
        obj["@context"] = context_with_public_service_terms();
        append_included_nodes(&mut obj, public_services);
    } else if catalog
        .datasets
        .iter()
        .any(|dataset| !dataset.applicable_legislation.is_empty())
    {
        obj["@context"] = context_with_public_service_terms();
    }
    let mut reference_nodes = standard_reference_nodes(&obj);
    reference_nodes.extend(dcat_range_reference_nodes(&obj));
    append_included_nodes(&mut obj, reference_nodes);

    #[cfg(feature = "ogcapi-records")]
    {
        let mut obj = obj;
        if let Some(service) = catalog_ogc_records_service(&catalog) {
            obj["dcat:service"] = service;
        }
        obj
    }

    #[cfg(not(feature = "ogcapi-records"))]
    obj
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

fn dcat_dataset(
    dataset: &DatasetMetadata,
    authority_type: Option<&str>,
    default_assigner: &str,
) -> Value {
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
        "odrl:hasPolicy": dataset_offer(dataset, default_assigner),
        "dcat:distribution": distributions,
    });

    if let Some(spatial) = dataset.spatial_coverage.as_deref() {
        obj["dcterms:spatial"] = json!(spatial);
    }
    if !dataset.applicable_legislation.is_empty() {
        obj["dcatap:applicableLegislation"] = json!(dataset.applicable_legislation);
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
                .map(|iri| {
                    let label = codelist_label(iri);
                    json!({
                        "@id": iri,
                        "@type": "skos:ConceptScheme",
                        "dcterms:title": label,
                        "skos:prefLabel": label,
                    })
                })
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
    #[cfg(feature = "ogcapi-records")]
    if let Some(records) = &dataset.standards.ogc_api_records {
        distributions.push(dataset_ogc_records_distribution(dataset, records));
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

fn media_type_format(media_type: &str) -> Value {
    json!({
        "@id": format!("https://www.iana.org/assignments/media-types/{media_type}"),
        "@type": ["dcterms:MediaType", "dcterms:MediaTypeOrExtent"],
        "rdfs:label": media_type,
    })
}

fn standard_reference_nodes(document: &Value) -> Vec<Value> {
    // `dcterms:conformsTo` points at standards or profiles in DCAT-AP.
    // We type every configured target accordingly instead of guessing which
    // vocabularies are "known" to Registry Relay.
    let mut iris = BTreeSet::new();
    collect_conforms_to_iris(document, &mut iris);
    iris.into_iter()
        .map(|iri| {
            json!({
                "@id": iri,
                "@type": "dcterms:Standard",
            })
        })
        .collect()
}

fn dcat_range_reference_nodes(document: &Value) -> Vec<Value> {
    let mut typed_iris = BTreeSet::new();
    collect_typed_reference_iris(
        document,
        "dcterms:accessRights",
        "dcterms:RightsStatement",
        &mut typed_iris,
    );
    collect_typed_reference_iris(
        document,
        "dcterms:accrualPeriodicity",
        "dcterms:Frequency",
        &mut typed_iris,
    );
    collect_typed_reference_iris(
        document,
        "dcat:landingPage",
        "foaf:Document",
        &mut typed_iris,
    );
    typed_iris
        .into_iter()
        .map(|(iri, node_type)| {
            json!({
                "@id": iri,
                "@type": node_type,
            })
        })
        .collect()
}

fn collect_typed_reference_iris(
    value: &Value,
    predicate: &str,
    node_type: &str,
    iris: &mut BTreeSet<(String, String)>,
) {
    match value {
        Value::Object(object) => {
            if let Some(reference) = object.get(predicate) {
                let mut values = BTreeSet::new();
                collect_string_values(reference, &mut values);
                iris.extend(
                    values
                        .into_iter()
                        .map(|value| (value, node_type.to_string())),
                );
            }
            for nested in object.values() {
                collect_typed_reference_iris(nested, predicate, node_type, iris);
            }
        }
        Value::Array(values) => {
            for nested in values {
                collect_typed_reference_iris(nested, predicate, node_type, iris);
            }
        }
        _ => {}
    }
}

fn collect_conforms_to_iris(value: &Value, iris: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            if let Some(conforms_to) = object.get("dcterms:conformsTo") {
                collect_string_values(conforms_to, iris);
            }
            for nested in object.values() {
                collect_conforms_to_iris(nested, iris);
            }
        }
        Value::Array(values) => {
            for nested in values {
                collect_conforms_to_iris(nested, iris);
            }
        }
        _ => {}
    }
}

fn collect_string_values(value: &Value, values: &mut BTreeSet<String>) {
    match value {
        Value::String(value) => {
            values.insert(value.clone());
        }
        Value::Array(items) => {
            for item in items {
                collect_string_values(item, values);
            }
        }
        Value::Object(object) => {
            if let Some(id) = object.get("@id").and_then(Value::as_str) {
                values.insert(id.to_string());
            }
        }
        _ => {}
    }
}

fn append_included_nodes(document: &mut Value, nodes: Vec<Value>) {
    if nodes.is_empty() {
        return;
    }
    let mut existing = document
        .get_mut("@included")
        .and_then(Value::as_array_mut)
        .map(std::mem::take)
        .unwrap_or_default();
    let mut seen = existing
        .iter()
        .filter_map(included_node_key)
        .collect::<BTreeSet<_>>();
    for node in nodes {
        if included_node_key(&node).is_some_and(|key| seen.insert(key)) {
            existing.push(node);
        }
    }
    document["@included"] = Value::Array(existing);
}

fn included_node_key(node: &Value) -> Option<(String, String)> {
    let object = node.as_object()?;
    Some((
        object.get("@id")?.as_str()?.to_string(),
        object.get("@type")?.as_str()?.to_string(),
    ))
}

fn codelist_label(iri: &str) -> String {
    let token = iri
        .trim_end_matches('/')
        .rsplit(['/', '#'])
        .next()
        .unwrap_or(iri);
    humanize_token(token)
}

fn slug_identifier(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn humanize_token(value: &str) -> String {
    value
        .split(['_', '-', '/'])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().chain(chars).collect::<String>(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(feature = "ogcapi-records")]
fn dataset_ogc_records_distribution(
    dataset: &DatasetMetadata,
    records: &super::catalog::OgcApiRecordsMetadata,
) -> Value {
    let access_service = format!("{}#ogc-api-records-service", records.collection);
    json!({
        "@id": records.items,
        "@type": "dcat:Distribution",
        "dcterms:title": format!("{} OGC API Records service", dataset.title),
        "dcterms:format": media_type_format("application/geo+json"),
        "dcat:accessURL": records.items,
        "dcat:accessService": {
            "@id": access_service,
            "@type": "dcat:DataService",
            "dcterms:identifier": format!("{}:ogc-api-records", dataset.dataset_id),
            "dcterms:title": format!("{} OGC API Records service", dataset.title),
            "dcat:endpointURL": records.items,
            "dcat:endpointDescription": openapi_url(&dataset.links.self_url),
            "dcat:servesDataset": dataset.links.self_url,
            "dcterms:conformsTo": ogc_records_conformance(),
        },
        "dcterms:conformsTo": ogc_records_conformance(),
    })
}

#[cfg(feature = "ogcapi-records")]
fn catalog_ogc_records_service(catalog: &CatalogDocument) -> Option<Value> {
    let records = catalog
        .datasets
        .iter()
        .find_map(|dataset| dataset.standards.ogc_api_records.as_ref())?;
    Some(json!({
        "@id": format!("{}#ogc-api-records-service", records.landing),
        "@type": "dcat:DataService",
        "dcterms:identifier": "catalog:ogc-api-records",
        "dcterms:title": format!("{} OGC API Records service", catalog.title),
        "dcat:endpointURL": records.landing,
        "dcat:endpointDescription": format!("{}/openapi.json", catalog.base_url),
        "dcat:servesDataset": catalog
            .datasets
            .iter()
            .filter(|dataset| dataset.standards.ogc_api_records.is_some())
            .map(|dataset| dataset.links.self_url.clone())
            .collect::<Vec<_>>(),
        "dcterms:conformsTo": ogc_records_conformance(),
    }))
}

#[cfg(feature = "ogcapi-records")]
fn ogc_records_conformance() -> Value {
    json!([
        "http://www.opengis.net/spec/ogcapi-records-1/1.0/conf/record-core",
        "http://www.opengis.net/spec/ogcapi-records-1/1.0/conf/record-collection",
        "http://www.opengis.net/spec/ogcapi-records-1/1.0/conf/record-api",
        "http://www.opengis.net/spec/ogcapi-records-1/1.0/conf/json",
        "http://www.opengis.net/spec/ogcapi-records-1/1.0/conf/oas30",
    ])
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
        "dcterms:format": media_type_format("application/json"),
        "dcat:accessURL": ogc.collections,
        "dcat:accessService": {
            "@id": access_service,
            "@type": "dcat:DataService",
            "dcterms:identifier": format!("{}:ogc-api-features", dataset.dataset_id),
            "dcterms:title": format!("{} OGC API Features service", dataset.title),
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
        "dcterms:format": media_type_format("application/json"),
        "dcat:accessURL": registry.sync_search,
        "dcat:accessService": {
            "@id": access_service,
            "@type": "dcat:DataService",
            "dcterms:identifier": format!("{}:spdci-sync:{}", dataset.dataset_id, registry.registry),
            "dcterms:title": format!("{} SP DCI {} sync service", dataset.title, registry.registry),
            "dcat:endpointURL": registry.sync_search,
            "dcat:endpointDescription": openapi_url(&dataset.links.self_url),
            "dcat:servesDataset": dataset.links.self_url,
            "dcterms:conformsTo": "https://spdci.org/",
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
        "dcterms:format": media_type_format("application/json"),
        "dcat:accessURL": entity.links.collection,
        "dcat:accessService": {
            "@id": access_service,
            "@type": "dcat:DataService",
            "dcterms:identifier": format!("{}:entity-rest:{}", entity.name, entity.primary_key),
            "dcterms:title": format!(
                "{} REST access service",
                entity.title.as_deref().unwrap_or(entity.name.as_str())
            ),
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
        "dcterms:format": media_type_format("application/geo+json"),
        "dcat:accessURL": collection,
        "dcat:downloadURL": items,
        "dcat:accessService": {
            "@id": access_service,
            "@type": "dcat:DataService",
            "dcterms:identifier": format!("{}:ogc-api-features", entity.name),
            "dcterms:title": format!(
                "{} OGC API Features service",
                entity.title.as_deref().unwrap_or(entity.name.as_str())
            ),
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

fn dataset_offer(dataset: &DatasetMetadata, default_assigner: &str) -> Value {
    if let Some(policy) = dataset.compiled_policy.as_ref() {
        return compiled_dataset_offer(dataset, policy);
    }

    let default_uid = format!("{}#offer", dataset.links.self_url);
    json!({
        "@id": default_uid,
        "@type": "odrl:Offer",
        "odrl:uid": default_uid,
        "odrl:assigner": iri_object(default_assigner),
        "odrl:permission": [default_policy_rule(default_assigner, &dataset.links.self_url)],
    })
}

fn compiled_dataset_offer(
    dataset: &DatasetMetadata,
    policy: &registry_metadata_core::CompiledDatasetPolicy,
) -> Value {
    let uid = legacy_policy_dataset_iri(dataset, &policy.uid);
    let mut offer = json!({
        "@id": uid,
        "@type": "odrl:Offer",
        "odrl:uid": uid,
        "odrl:assigner": iri_object(&policy.assigner),
        "odrl:permission": policy
            .permissions
            .iter()
            .map(|rule| compiled_policy_rule(dataset, rule, &policy.assigner))
            .collect::<Vec<_>>(),
    });
    if !policy.profile.is_empty() {
        offer["odrl:profile"] = json!(policy
            .profile
            .iter()
            .map(|iri| iri_object(iri))
            .collect::<Vec<_>>());
    }
    if !policy.prohibitions.is_empty() {
        offer["odrl:prohibition"] = json!(policy
            .prohibitions
            .iter()
            .map(|rule| compiled_policy_rule(dataset, rule, &policy.assigner))
            .collect::<Vec<_>>());
    }
    offer
}

fn default_policy_rule(assigner: &str, target: &str) -> Value {
    json!({
        "odrl:target": iri_object(target),
        "odrl:assigner": iri_object(assigner),
        "odrl:action": iri_object("odrl:use"),
    })
}

fn compiled_policy_rule(
    dataset: &DatasetMetadata,
    rule: &registry_metadata_core::CompiledPolicyRule,
    assigner: &str,
) -> Value {
    let target = legacy_policy_dataset_iri(dataset, &rule.target);
    let mut value = json!({
        "odrl:target": iri_object(&target),
        "odrl:assigner": iri_object(assigner),
        "odrl:action": iri_object(&rule.action),
    });
    if let Some(assignee) = rule.assignee.as_deref() {
        value["odrl:assignee"] = iri_object(assignee);
    }
    if !rule.constraints.is_empty() {
        value["odrl:constraint"] = json!(rule
            .constraints
            .iter()
            .map(compiled_policy_constraint)
            .collect::<Vec<_>>());
    }
    if !rule.duties.is_empty() {
        value["odrl:duty"] = json!(rule
            .duties
            .iter()
            .map(|duty| compiled_policy_duty(dataset, duty))
            .collect::<Vec<_>>());
    }
    value
}

fn compiled_policy_duty(
    dataset: &DatasetMetadata,
    duty: &registry_metadata_core::CompiledPolicyDuty,
) -> Value {
    let mut value = json!({
        "odrl:action": iri_object(&duty.action),
    });
    if let Some(target) = duty.target.as_deref() {
        let target = legacy_policy_dataset_iri(dataset, target);
        value["odrl:target"] = iri_object(&target);
    }
    if let Some(assignee) = duty.assignee.as_deref() {
        value["odrl:assignee"] = iri_object(assignee);
    }
    if !duty.constraints.is_empty() {
        value["odrl:constraint"] = json!(duty
            .constraints
            .iter()
            .map(compiled_policy_constraint)
            .collect::<Vec<_>>());
    }
    value
}

fn compiled_policy_constraint(
    constraint: &registry_metadata_core::CompiledPolicyConstraint,
) -> Value {
    let mut value = json!({
        "odrl:leftOperand": iri_object(&constraint.left_operand),
        "odrl:operator": iri_object(&constraint.operator),
        "odrl:rightOperand": compiled_policy_operand(&constraint.right_operand, constraint.datatype.as_deref()),
    });
    if let Some(unit) = constraint.unit.as_deref() {
        value["odrl:unit"] = iri_object(unit);
    }
    value
}

fn compiled_policy_operand(
    operand: &registry_metadata_core::CompiledPolicyOperandValue,
    datatype: Option<&str>,
) -> Value {
    match operand {
        registry_metadata_core::CompiledPolicyOperandValue::Iri(iri) => iri_object(iri),
        registry_metadata_core::CompiledPolicyOperandValue::Literal(value) => {
            if let Some(datatype) = datatype {
                json!({
                    "@value": value,
                    "@type": datatype,
                })
            } else {
                json!(value)
            }
        }
    }
}

fn iri_object(iri: &str) -> Value {
    json!({ "@id": iri })
}

fn legacy_policy_dataset_iri(dataset: &DatasetMetadata, iri: &str) -> String {
    if iri == format!("#dataset-{}", dataset.dataset_id) {
        return dataset.links.self_url.clone();
    }
    if iri == format!("#dataset-{}-offer", dataset.dataset_id) {
        return format!("{}#offer", dataset.links.self_url);
    }
    iri.to_string()
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

fn public_service_node(dataset: &DatasetMetadata, service: &PublicServiceMetadata) -> Value {
    json!({
        "@id": service.id,
        "@type": "cpsv:PublicService",
        "dcterms:title": service.title,
        "dcterms:description": service.description,
        "cpsv:produces": dataset.links.self_url,
    })
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
    let mut context = json!({
        "adms": "http://www.w3.org/ns/adms#",
        "dcat": "http://www.w3.org/ns/dcat#",
        "dcterms": "http://purl.org/dc/terms/",
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
        "sh:class": { "@type": "@id" },
        "sh:datatype": { "@type": "@id" },
        "sh:nodeKind": { "@type": "@id" },
        "sh:path": { "@type": "@id" },
        "sh:targetClass": { "@type": "@id" },
    });
    if let Some(object) = context.as_object_mut() {
        for term in [
            "odrl:action",
            "odrl:assignee",
            "odrl:assigner",
            "odrl:hasPolicy",
            "odrl:leftOperand",
            "odrl:operator",
            "odrl:profile",
            "odrl:target",
            "odrl:uid",
            "odrl:unit",
        ] {
            object.insert(term.to_string(), json!({ "@type": "@id" }));
        }
    }
    context
}

fn context_with_public_service_terms() -> Value {
    let mut context = context();
    if let Some(object) = context.as_object_mut() {
        object.insert("cpsv".to_string(), json!("http://purl.org/vocab/cpsv#"));
        object.insert("dcatap".to_string(), json!("http://data.europa.eu/r5r/"));
        object.insert(
            "eli".to_string(),
            json!("http://data.europa.eu/eli/ontology#"),
        );
        object.insert(
            "dcatap:applicableLegislation".to_string(),
            json!({ "@type": "@id" }),
        );
        object.insert("cpsv:produces".to_string(), json!({ "@type": "@id" }));
    }
    context
}
