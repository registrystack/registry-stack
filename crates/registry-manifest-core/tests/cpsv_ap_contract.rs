// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use registry_manifest_core::{compile_manifest, render_cpsv_ap, MetadataManifest};
use serde_json::{json, Value};
use sophia_api::{prelude::QuadParser, quad::Spog, source::QuadSource};
use sophia_jsonld::loader::NoLoader;
use sophia_jsonld::vocabulary::ArcIri;
use sophia_jsonld::{JsonLdOptions, JsonLdParser};
use sophia_term::ArcTerm;

#[test]
fn cpsv_ap_service_first_fixture_satisfies_jsonld_rdf_contract() {
    let manifest: MetadataManifest = serde_yaml_ng::from_str(include_str!(
        "../../../products/manifest/fixtures/cpsv-ap/health-linked-child-support.metadata.yaml"
    ))
    .expect("service-first fixture parses");
    let compiled = compile_manifest(&manifest).expect("service-first fixture compiles");
    let cpsv = render_cpsv_ap(&compiled);

    let quad_count = parse_jsonld_to_rdf(&cpsv).expect("CPSV-AP JSON-LD parses as RDF");
    assert!(quad_count > 0, "CPSV-AP JSON-LD must produce RDF quads");
    validate_cpsv_ap_service_first_contract(&cpsv)
        .unwrap_or_else(|errors| panic!("CPSV-AP contract errors:\n{}", errors.join("\n")));
}

#[test]
fn cpsv_ap_jsonld_parser_rejects_broken_context() {
    let manifest: MetadataManifest = serde_yaml_ng::from_str(include_str!(
        "../../../products/manifest/fixtures/cpsv-ap/health-linked-child-support.metadata.yaml"
    ))
    .expect("service-first fixture parses");
    let compiled = compile_manifest(&manifest).expect("service-first fixture compiles");
    let mut cpsv = render_cpsv_ap(&compiled);
    cpsv["@context"]["dcat:service"] = json!({ "@type": ["@id"] });

    let error = parse_jsonld_to_rdf(&cpsv).expect_err("broken JSON-LD context is rejected");
    assert!(
        error.contains("@type") || error.contains("context"),
        "unexpected JSON-LD parser error: {error}"
    );
}

fn parse_jsonld_to_rdf(document: &Value) -> Result<usize, String> {
    let raw = serde_json::to_string(document).map_err(|error| error.to_string())?;
    let options = JsonLdOptions::new()
        .with_default_document_loader::<NoLoader>()
        .with_base(ArcIri::new_unchecked(Arc::from(
            "https://child-support.example.gov/metadata/cpsv-ap",
        )));
    let parser = JsonLdParser::new_with_options(options);
    let quads: Vec<Spog<ArcTerm>> = parser
        .parse_str(&raw)
        .collect_quads()
        .map_err(|error| error.to_string())?;
    Ok(quads.len())
}

fn validate_cpsv_ap_service_first_contract(document: &Value) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    if contains_object_key(document, "cv:hasInputType") {
        errors.push("CPSV-AP render must not emit cv:hasInputType".to_string());
    }

    let graph = match document.get("@graph").and_then(Value::as_array) {
        Some(graph) => graph,
        None => {
            return Err(vec![
                "CPSV-AP render must include a top-level @graph array".to_string()
            ]);
        }
    };
    let nodes = graph
        .iter()
        .filter_map(|node| node_id(node).map(|id| (id.to_string(), node)))
        .collect::<BTreeMap<_, _>>();

    let catalog_services = references(document.get("dcat:service"));
    if catalog_services.is_empty() {
        errors.push("catalog must publish dcat:service references".to_string());
    }
    for service_id in &catalog_services {
        let Some(node) = nodes.get(*service_id) else {
            errors.push(format!(
                "catalog dcat:service target {service_id} must exist as a graph node"
            ));
            continue;
        };
        if has_type(node, "cpsv:PublicService") {
            errors.push(format!(
                "catalog dcat:service target {service_id} must not be a cpsv:PublicService"
            ));
        }
        if !has_type(node, "dcat:DataService") {
            errors.push(format!(
                "catalog dcat:service target {service_id} must be a dcat:DataService"
            ));
        }
    }

    let catalog_parts = references(document.get("dcterms:hasPart"));
    if catalog_parts.is_empty() {
        errors.push("catalog must link public services with dcterms:hasPart".to_string());
    }
    for service_id in &catalog_parts {
        let Some(node) = nodes.get(*service_id) else {
            errors.push(format!(
                "catalog dcterms:hasPart target {service_id} must exist as a graph node"
            ));
            continue;
        };
        if !has_type(node, "cpsv:PublicService") {
            errors.push(format!(
                "catalog dcterms:hasPart target {service_id} must be a cpsv:PublicService"
            ));
        }
    }

    let dataset_ids = graph
        .iter()
        .filter(|node| has_type(node, "dcat:Dataset"))
        .filter_map(node_id)
        .collect::<BTreeSet<_>>();
    for data_service in graph
        .iter()
        .filter(|node| has_type(node, "dcat:DataService"))
    {
        let data_service_id = node_id(data_service).unwrap_or("<anonymous data service>");
        let served_datasets = references(data_service.get("dcat:servesDataset"));
        if served_datasets.is_empty() {
            errors.push(format!(
                "dcat:DataService {data_service_id} must declare dcat:servesDataset"
            ));
        }
        for dataset_id in served_datasets {
            if !dataset_ids.contains(dataset_id) {
                errors.push(format!(
                    "dcat:DataService {data_service_id} serves missing dataset node {dataset_id}"
                ));
            }
        }
    }

    let requirement_ids = graph
        .iter()
        .filter(|node| has_requirement_type(node))
        .filter_map(node_id)
        .collect::<BTreeSet<_>>();
    for public_service in graph
        .iter()
        .filter(|node| has_type(node, "cpsv:PublicService"))
    {
        let service_id = node_id(public_service).unwrap_or("<anonymous public service>");
        if public_service
            .get("dcterms:description")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .is_empty()
        {
            errors.push(format!(
                "cpsv:PublicService {service_id} must include dcterms:description"
            ));
        }
        let is_registry_service = !references(public_service.get("cpsv:produces")).is_empty()
            && references(public_service.get("registry_manifest:hasForm")).is_empty();
        if references(public_service.get("cv:hasChannel")).is_empty() && !is_registry_service {
            errors.push(format!(
                "cpsv:PublicService {service_id} must include cv:hasChannel"
            ));
        }
        let requirements = references(public_service.get("cv:holdsRequirement"))
            .into_iter()
            .chain(references(public_service.get("cpsv:holdsRequirement")))
            .collect::<BTreeSet<_>>();
        if requirements.is_empty() {
            errors.push(format!(
                "cpsv:PublicService {service_id} must include a requirement reference"
            ));
        }
        for requirement_id in requirements {
            if !requirement_ids.contains(requirement_id) {
                errors.push(format!(
                    "cpsv:PublicService {service_id} references missing requirement {requirement_id}"
                ));
            }
        }
    }

    let evidence_type_ids = graph
        .iter()
        .filter(|node| has_type(node, "cccev:EvidenceType"))
        .filter_map(node_id)
        .collect::<BTreeSet<_>>();
    for requirement in graph.iter().filter(|node| has_requirement_type(node)) {
        let requirement_id = node_id(requirement).unwrap_or("<anonymous requirement>");
        let list_ids = references(requirement.get("cccev:hasEvidenceTypeList"));
        if list_ids.is_empty() {
            errors.push(format!(
                "requirement {requirement_id} must include cccev:hasEvidenceTypeList"
            ));
        }
        for list_id in list_ids {
            let Some(list_node) = nodes.get(list_id) else {
                errors.push(format!(
                    "requirement {requirement_id} evidence type list {list_id} must exist"
                ));
                continue;
            };
            if !has_type(list_node, "cccev:EvidenceTypeList") {
                errors.push(format!(
                    "requirement {requirement_id} evidence type list {list_id} must be cccev:EvidenceTypeList"
                ));
            }
            for evidence_type_id in references(list_node.get("cccev:specifiesEvidenceType")) {
                if !evidence_type_ids.contains(evidence_type_id) {
                    errors.push(format!(
                        "evidence type list {list_id} references missing evidence type {evidence_type_id}"
                    ));
                }
            }
        }
    }

    let concept_ids = graph
        .iter()
        .filter(|node| has_type(node, "cccev:InformationConcept"))
        .filter_map(node_id)
        .collect::<BTreeSet<_>>();
    for form in graph
        .iter()
        .filter(|node| has_type(node, "registry_manifest:FormDefinition"))
    {
        let form_id = node_id(form).unwrap_or("<anonymous form>");
        let service_refs = references(form.get("registry_manifest:forPublicService"));
        if service_refs.is_empty() {
            errors.push(format!(
                "form {form_id} must map to a public service with registry_manifest:forPublicService"
            ));
        }
        let Some(fields) = form
            .get("registry_manifest:hasField")
            .and_then(Value::as_array)
        else {
            errors.push(format!(
                "form {form_id} must include registry_manifest:hasField"
            ));
            continue;
        };
        for field in fields {
            let field_id = node_id(field).unwrap_or("<anonymous form field>");
            let concepts = references(field.get("cccev:hasConcept"));
            if concepts.is_empty() {
                errors.push(format!("form field {field_id} must map to a CCCEV concept"));
            }
            for concept_id in concepts {
                if !concept_ids.contains(concept_id) {
                    errors.push(format!(
                        "form field {field_id} references missing information concept {concept_id}"
                    ));
                }
            }
        }
    }

    for offering in graph
        .iter()
        .filter(|node| has_type(node, "registry_manifest:EvidenceOffering"))
    {
        let offering_id = node_id(offering).unwrap_or("<anonymous evidence offering>");
        let provider = offering
            .get("registry_manifest:issuingAuthority")
            .or_else(|| offering.get("dcterms:publisher"));
        if provider
            .and_then(|provider| provider.get("@id"))
            .and_then(Value::as_str)
            .is_none_or(|id| id.trim().is_empty())
        {
            errors.push(format!(
                "evidence offering {offering_id} must include an evidence provider"
            ));
        }
        let Some(evidence_service) = offering.get("registry_manifest:evidenceService") else {
            errors.push(format!(
                "evidence offering {offering_id} must include registry_manifest:evidenceService"
            ));
            continue;
        };
        if !has_type(evidence_service, "dcat:DataService") {
            errors.push(format!(
                "evidence offering {offering_id} evidence service must be a dcat:DataService"
            ));
        }
        if references(evidence_service.get("dcat:endpointURL")).is_empty() {
            errors.push(format!(
                "evidence offering {offering_id} evidence service must include dcat:endpointURL"
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn contains_object_key(value: &Value, key: &str) -> bool {
    match value {
        Value::Array(values) => values.iter().any(|value| contains_object_key(value, key)),
        Value::Object(object) => {
            object.contains_key(key) || object.values().any(|value| contains_object_key(value, key))
        }
        _ => false,
    }
}

fn node_id(node: &Value) -> Option<&str> {
    node.get("@id").and_then(Value::as_str)
}

fn has_requirement_type(node: &Value) -> bool {
    has_type(node, "cccev:Requirement")
        || has_type(node, "cv:Requirement")
        || has_type(node, "http://data.europa.eu/m8g/Requirement")
}

fn has_type(node: &Value, expected: &str) -> bool {
    match node.get("@type") {
        Some(Value::String(kind)) => kind == expected,
        Some(Value::Array(kinds)) => kinds.iter().any(|kind| kind.as_str() == Some(expected)),
        _ => false,
    }
}

fn references(value: Option<&Value>) -> Vec<&str> {
    let Some(value) = value else {
        return Vec::new();
    };
    match value {
        Value::String(value) => vec![value.as_str()],
        Value::Object(object) => object
            .get("@id")
            .and_then(Value::as_str)
            .into_iter()
            .collect(),
        Value::Array(values) => values
            .iter()
            .flat_map(|value| references(Some(value)))
            .collect(),
        _ => Vec::new(),
    }
}
