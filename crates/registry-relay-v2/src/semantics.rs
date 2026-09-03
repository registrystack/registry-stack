// SPDX-License-Identifier: Apache-2.0
//! Deterministic local semantic and validation artifact construction.

use serde_json::{json, Map, Value};

use crate::contract::DataType;
use crate::model::{CompiledProperty, CompiledPropertyBinding, CompiledRegistry, CompiledResource};

/// Terms owned by the shared Registry Record context. Relay operation contexts
/// compose after that context and must never redefine any of these mappings.
pub const REGISTRY_RECORD_SHARED_CONTEXT_TERMS: &[&str] = &[
    "data",
    "items",
    "pageInfo",
    "meta",
    "domainData",
    "nextCursor",
    "registryIdentifier",
    "datasetIdentifier",
    "entityTypeIdentifier",
    "recordIdentifier",
    "revisionIdentifier",
];

pub fn local_vocabulary(
    registry: &CompiledRegistry,
    resource: &CompiledResource,
    selected: &[String],
) -> Value {
    let mut graph = Vec::new();
    graph.push(json!({
        "@id": resource.semantic_class,
        "@type": "rdfs:Class",
        "rdfs:label": resource.title,
        "rdfs:comment": resource.description,
    }));
    for property in selected_properties(resource, selected) {
        let item = match &property.binding {
            CompiledPropertyBinding::Scalar(binding) => json!({
                "@id": property.semantic_iri,
                "@type": "rdf:Property",
                "rdfs:label": property.label,
                "rdfs:comment": property.description,
                "rdfs:domain": {"@id": resource.semantic_class},
                "rdfs:range": {"@id": datatype_iri(binding.data_type)},
                "https://id.registrystack.org/vocab/sourceRequired": property.source_required,
                "https://id.registrystack.org/vocab/codelist": binding.codelist,
            }),
            CompiledPropertyBinding::Point(binding) => json!({
                "@id": property.semantic_iri,
                "@type": "rdf:Property",
                "rdfs:label": property.label,
                "rdfs:comment": property.description,
                "rdfs:domain": {"@id": resource.semantic_class},
                "rdfs:range": {"@id": "rdf:JSON"},
                "https://id.registrystack.org/vocab/geometryType": "Point",
                "https://id.registrystack.org/vocab/coordinateReferenceSystem": binding.crs,
                "https://id.registrystack.org/vocab/sourceRequired": property.source_required,
            }),
        };
        graph.push(item);
    }
    json!({
        "@context": {
            "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
            "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
            "xsd": "http://www.w3.org/2001/XMLSchema#"
        },
        "@id": registry.local_vocabulary,
        "@graph": graph,
    })
}

pub fn json_ld_context(
    registry: &CompiledRegistry,
    resource: &CompiledResource,
    selected: &[String],
) -> Value {
    let core = "https://id.registrystack.org/vocab/core/";
    let mut context = Map::new();
    context.insert("@version".into(), json!(1.1));
    context.insert("@vocab".into(), json!(registry.local_vocabulary));
    context.insert("xsd".into(), json!("http://www.w3.org/2001/XMLSchema#"));
    for field in [
        "schemaReference",
        "semanticModelReference",
        "authorityIdentifier",
    ] {
        context.insert(
            field.into(),
            json!({"@id": format!("{core}{field}"), "@type": "@id"}),
        );
    }
    context.insert(
        "lifecycleState".into(),
        json!({"@id": format!("{core}lifecycleState"), "@type": "xsd:string"}),
    );
    context.insert(
        "recordedAt".into(),
        json!({"@id": format!("{core}recordedAt"), "@type": "xsd:dateTime"}),
    );
    for property in selected_properties(resource, selected) {
        let data_type = match &property.binding {
            CompiledPropertyBinding::Scalar(binding) => json!(datatype_iri(binding.data_type)),
            CompiledPropertyBinding::Point(_) => json!("@json"),
        };
        context.insert(
            property.name.clone(),
            json!({
                "@id": property.semantic_iri,
                "@type": data_type,
            }),
        );
    }
    json!({"@context": context})
}

pub fn access_profile_schema(
    registry: &CompiledRegistry,
    resource: &CompiledResource,
    selected: &[String],
    schema_reference: &str,
    semantic_model_reference: &str,
) -> Value {
    record_schema(
        registry,
        resource,
        selected,
        false,
        schema_reference,
        semantic_model_reference,
    )
}

pub fn full_record_schema(registry: &CompiledRegistry, resource: &CompiledResource) -> Value {
    let selected = resource
        .properties
        .iter()
        .map(|property| property.name.clone())
        .collect::<Vec<_>>();
    record_schema(
        registry,
        resource,
        &selected,
        true,
        &resource.record_context.schema_reference,
        &resource.record_context.semantic_model_reference,
    )
}

fn record_schema(
    registry: &CompiledRegistry,
    resource: &CompiledResource,
    selected: &[String],
    full: bool,
    schema_reference: &str,
    semantic_model_reference: &str,
) -> Value {
    let lifecycle_values =
        &require_codelist(registry, &resource.record_context.lifecycle_state_codelist).values;
    let lifecycle_schema = json!({"type": "string", "enum": lifecycle_values});
    let mut domain_properties = Map::new();
    let mut domain_required = Vec::new();
    for property in selected_properties(resource, selected) {
        let mut schema = property_schema(registry, property);
        if let Value::Object(map) = &mut schema {
            map.insert("title".into(), json!(property.label));
            map.insert("description".into(), json!(property.description));
        }
        domain_properties.insert(property.name.clone(), schema);
        if full && property.source_required {
            domain_required.push(Value::String(property.name.clone()));
        }
    }
    let mut domain_data = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": domain_properties,
    });
    if full {
        domain_data
            .as_object_mut()
            .expect("object")
            .insert("required".into(), Value::Array(domain_required));
    }
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": schema_reference,
        "title": resource.title,
        "type": "object",
        "additionalProperties": false,
        "required": [
            "recordIdentifier", "revisionIdentifier",
            "lifecycleState", "schemaReference", "semanticModelReference",
            "authorityIdentifier", "recordedAt", "domainData"
        ],
        "properties": {
            "@id": {"type": "string", "format": "uri"},
            "@type": {"const": resource.semantic_class},
            "recordIdentifier": {"type": "string", "minLength": 1},
            "revisionIdentifier": {"type": "string", "minLength": 1},
            "lifecycleState": lifecycle_schema,
            "schemaReference": {"const": schema_reference},
            "semanticModelReference": {"const": semantic_model_reference},
            "authorityIdentifier": {"const": registry.authority_identifier},
            "recordedAt": {"type": "string", "format": "date-time"},
            "domainData": domain_data
        }
    })
}

pub fn access_profile_shacl(
    registry: &CompiledRegistry,
    resource: &CompiledResource,
    selected: &[String],
) -> String {
    shacl(registry, resource, selected, false)
}

pub fn full_record_shacl(registry: &CompiledRegistry, resource: &CompiledResource) -> String {
    let selected = resource
        .properties
        .iter()
        .map(|property| property.name.clone())
        .collect::<Vec<_>>();
    shacl(registry, resource, &selected, true)
}

fn shacl(
    registry: &CompiledRegistry,
    resource: &CompiledResource,
    selected: &[String],
    full: bool,
) -> String {
    let lifecycle_values =
        &require_codelist(registry, &resource.record_context.lifecycle_state_codelist).values;
    let lifecycle_constraint = shacl_in(lifecycle_values);
    let mut output = format!(
        "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n@prefix sh: <http://www.w3.org/ns/shacl#> .\n@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n\n<{}shapes/{}> a sh:NodeShape ;\n  sh:targetClass <{}> ;\n  sh:closed true ;\n  sh:ignoredProperties ( rdf:type )",
        registry.local_vocabulary, resource.id, resource.semantic_class
    );
    for path in [
        "schemaReference",
        "semanticModelReference",
        "authorityIdentifier",
    ] {
        output.push_str(&format!(
            " ;\n  sh:property [ sh:path <https://id.registrystack.org/vocab/core/{path}> ; sh:nodeKind sh:IRI ; sh:minCount 1 ; sh:maxCount 1 ]"
        ));
    }
    for (path, namespace, datatype) in [
        (
            "recordIdentifier",
            "https://id.registrystack.org/vocab/registry-record/",
            "http://www.w3.org/2001/XMLSchema#string",
        ),
        (
            "revisionIdentifier",
            "https://id.registrystack.org/vocab/registry-record/",
            "http://www.w3.org/2001/XMLSchema#string",
        ),
        (
            "lifecycleState",
            "https://id.registrystack.org/vocab/core/",
            "http://www.w3.org/2001/XMLSchema#string",
        ),
        (
            "recordedAt",
            "https://id.registrystack.org/vocab/core/",
            "http://www.w3.org/2001/XMLSchema#dateTime",
        ),
    ] {
        let controlled_values = if path == "lifecycleState" {
            lifecycle_constraint.as_str()
        } else {
            ""
        };
        output.push_str(&format!(
            " ;\n  sh:property [ sh:path <{namespace}{path}> ; sh:datatype <{datatype}>{controlled_values} ; sh:minCount 1 ; sh:maxCount 1 ]"
        ));
    }
    output.push_str(
        " ;\n  sh:property [ sh:path <https://id.registrystack.org/vocab/registry-record/domainData> ; sh:minCount 1 ; sh:maxCount 1 ; sh:node [ sh:closed true",
    );
    for property in selected_properties(resource, selected) {
        match &property.binding {
            CompiledPropertyBinding::Scalar(binding) => {
                let controlled_values = match binding.data_type {
                    DataType::ControlledCode => {
                        let path = binding.codelist.as_deref().unwrap_or_else(|| {
                            panic!(
                                "compiled semantics invariant: controlled property {} has no codelist",
                                property.name
                            )
                        });
                        shacl_in(&require_codelist(registry, path).values)
                    }
                    _ => String::new(),
                };
                output.push_str(&format!(
                    " ;\n    sh:property [ sh:path <{}> ; sh:datatype <{}>{} ; sh:minCount {} ; sh:maxCount 1 ]",
                    property.semantic_iri,
                    datatype_iri(binding.data_type),
                    controlled_values,
                    usize::from(full && property.source_required)
                ));
            }
            CompiledPropertyBinding::Point(_) => output.push_str(&format!(
                " ;\n    sh:property [ sh:path <{}> ; sh:datatype <http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON> ; sh:minCount {} ; sh:maxCount 1 ]",
                property.semantic_iri,
                usize::from(full && property.source_required)
            )),
        }
    }
    output.push_str(" ] ] .\n");
    output
}

fn property_schema(registry: &CompiledRegistry, property: &CompiledProperty) -> Value {
    let CompiledPropertyBinding::Scalar(binding) = &property.binding else {
        let CompiledPropertyBinding::Point(binding) = &property.binding else {
            unreachable!();
        };
        let mut schema = point_geometry_schema();
        schema["x-registry-crs"] = json!(binding.crs);
        return schema;
    };
    match binding.data_type {
        DataType::String => json!({"type": "string"}),
        DataType::ControlledCode => {
            let path = binding.codelist.as_deref().unwrap_or_else(|| {
                panic!(
                    "compiled semantics invariant: controlled property {} has no codelist",
                    property.name
                )
            });
            let values = &require_codelist(registry, path).values;
            json!({"type": "string", "enum": values, "x-registry-codelist": path})
        }
        DataType::Boolean => json!({"type": "boolean"}),
        DataType::Integer => json!({"type": "integer"}),
        DataType::Date => json!({"type": "string", "format": "date"}),
        DataType::DateTime => json!({"type": "string", "format": "date-time"}),
        DataType::Year => json!({
            "type": "string",
            "pattern": "^[0-9]{4}$",
            "x-registry-datatype": "year"
        }),
        DataType::YearMonth => json!({
            "type": "string",
            "pattern": "^[0-9]{4}-(0[1-9]|1[0-2])$",
            "x-registry-datatype": "year-month"
        }),
    }
}

fn point_geometry_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["type", "coordinates"],
        "properties": {
            "type": {"const": "Point"},
            "coordinates": {
                "type": "array",
                "prefixItems": [
                    {"type": "number", "minimum": -180, "maximum": 180},
                    {"type": "number", "minimum": -90, "maximum": 90}
                ],
                "items": false,
                "minItems": 2,
                "maxItems": 2
            }
        }
    })
}

fn require_codelist<'a>(
    registry: &'a CompiledRegistry,
    path: &str,
) -> &'a crate::model::CompiledCodelist {
    registry
        .codelists
        .iter()
        .find(|item| item.path == path)
        .unwrap_or_else(|| {
            panic!("compiled semantics invariant: referenced codelist {path} is missing")
        })
}

fn shacl_in(values: &[String]) -> String {
    format!(
        " ; sh:in ( {} )",
        values
            .iter()
            .map(|value| format!("\"{}\"", turtle_escape(value)))
            .collect::<Vec<_>>()
            .join(" ")
    )
}

fn turtle_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

pub fn datatype_iri(data_type: DataType) -> &'static str {
    match data_type {
        DataType::String | DataType::ControlledCode => "http://www.w3.org/2001/XMLSchema#string",
        DataType::Boolean => "http://www.w3.org/2001/XMLSchema#boolean",
        DataType::Integer => "http://www.w3.org/2001/XMLSchema#integer",
        DataType::Date => "http://www.w3.org/2001/XMLSchema#date",
        DataType::DateTime => "http://www.w3.org/2001/XMLSchema#dateTime",
        DataType::Year => "http://www.w3.org/2001/XMLSchema#gYear",
        DataType::YearMonth => "http://www.w3.org/2001/XMLSchema#gYearMonth",
    }
}

fn selected_properties<'a>(
    resource: &'a CompiledResource,
    selected: &[String],
) -> Vec<&'a CompiledProperty> {
    resource
        .properties
        .iter()
        .filter(|property| selected.contains(&property.name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_context_does_not_redefine_shared_registry_record_terms() {
        let context = json_ld_context(&registry(), &resource(), &["name".into()]);
        let terms = context["@context"].as_object().expect("context terms");
        for field in REGISTRY_RECORD_SHARED_CONTEXT_TERMS {
            assert!(
                !terms.contains_key(*field),
                "operation context must not redefine shared term {field}"
            );
        }
        assert!(context["@context"]["name"].get("@nest").is_none());
        assert_eq!(
            context["@context"]["name"]["@type"],
            "http://www.w3.org/2001/XMLSchema#string"
        );
    }

    #[test]
    #[should_panic(expected = "referenced codelist state.yaml is missing")]
    fn schema_generation_refuses_a_missing_lifecycle_codelist() {
        let _ = full_record_schema(&registry(), &resource());
    }

    #[test]
    #[should_panic(expected = "referenced codelist codes.yaml is missing")]
    fn schema_generation_refuses_a_missing_property_codelist() {
        let mut registry = registry();
        registry.codelists.push(codelist("state.yaml", &["ACTIVE"]));
        let mut resource = resource();
        let crate::model::CompiledPropertyBinding::Scalar(binding) =
            &mut resource.properties[0].binding
        else {
            panic!("fixture property is scalar");
        };
        binding.data_type = DataType::ControlledCode;
        binding.codelist = Some("codes.yaml".into());
        let _ = full_record_schema(&registry, &resource);
    }

    #[test]
    fn schemas_and_shacl_emit_every_compiled_codelist_constraint() {
        let mut registry = registry();
        registry
            .codelists
            .push(codelist("state.yaml", &["ACTIVE", "RETIRED"]));
        registry
            .codelists
            .push(codelist("codes.yaml", &["ONE", "TWO"]));
        let mut resource = resource();
        let crate::model::CompiledPropertyBinding::Scalar(binding) =
            &mut resource.properties[0].binding
        else {
            panic!("fixture property is scalar");
        };
        binding.data_type = DataType::ControlledCode;
        binding.codelist = Some("codes.yaml".into());

        let schema = full_record_schema(&registry, &resource);
        assert_eq!(
            schema["properties"]["lifecycleState"]["enum"],
            json!(["ACTIVE", "RETIRED"])
        );
        assert_eq!(
            schema["properties"]["domainData"]["properties"]["name"]["enum"],
            json!(["ONE", "TWO"])
        );
        assert_eq!(
            schema["properties"]["@id"],
            json!({"type": "string", "format": "uri"})
        );
        assert_eq!(
            schema["properties"]["@type"],
            json!({"const": resource.semantic_class})
        );
        let shacl = full_record_shacl(&registry, &resource);
        assert!(shacl.contains("sh:targetClass <https://example.invalid/vocab/Record>"));
        assert!(shacl.contains("sh:ignoredProperties ( rdf:type )"));
        assert!(shacl.contains("sh:nodeKind sh:IRI"));
        assert!(shacl.contains(
            "sh:path <https://id.registrystack.org/vocab/registry-record/domainData> ; sh:minCount 1 ; sh:maxCount 1 ; sh:node [ sh:closed true"
        ));
        assert!(shacl.contains(
            "sh:node [ sh:closed true ;\n    sh:property [ sh:path <https://example.invalid/vocab/name>"
        ));
        assert!(shacl.contains("sh:in ( \"ACTIVE\" \"RETIRED\" )"));
        assert!(shacl.contains("sh:in ( \"ONE\" \"TWO\" )"));
    }

    #[test]
    fn full_point_artifacts_are_bounded_json_without_carrier_or_geosparql_claims() {
        let mut registry = registry();
        registry
            .codelists
            .push(codelist("state.yaml", &["ACTIVE", "RETIRED"]));
        let mut resource = resource();
        let classification = resource.properties[0].classification.clone();
        resource.properties.push(CompiledProperty {
            name: "location".into(),
            label: "Location".into(),
            description: "Reviewed Point location".into(),
            source_required: true,
            semantic_iri: "https://example.invalid/vocab/location".into(),
            classification,
            binding: CompiledPropertyBinding::Point(crate::model::CompiledPointPropertyBinding {
                crs: "http://www.opengis.net/def/crs/OGC/0/CRS84".into(),
                longitude_column: "private_longitude_carrier".into(),
                latitude_column: "private_latitude_carrier".into(),
            }),
        });
        resource.primary_geometry = Some("location".into());
        let selected = vec!["name".into(), "location".into()];

        let schema = full_record_schema(&registry, &resource);
        let point = &schema["properties"]["domainData"]["properties"]["location"];
        assert_eq!(point["properties"]["type"]["const"], "Point");
        assert_eq!(
            point["properties"]["coordinates"]["prefixItems"][0]["minimum"],
            -180
        );
        assert_eq!(
            point["properties"]["coordinates"]["prefixItems"][1]["maximum"],
            90
        );
        assert_eq!(point["properties"]["coordinates"]["items"], false);
        assert_eq!(
            point["x-registry-crs"],
            "http://www.opengis.net/def/crs/OGC/0/CRS84"
        );
        let context = json_ld_context(&registry, &resource, &selected);
        assert_eq!(context["@context"]["location"]["@type"], "@json");

        let vocabulary = local_vocabulary(&registry, &resource, &selected);
        let vocabulary_property = vocabulary["@graph"]
            .as_array()
            .expect("vocabulary graph")
            .iter()
            .find(|item| item["@id"] == "https://example.invalid/vocab/location")
            .expect("Point vocabulary property");
        assert_eq!(
            vocabulary_property["https://id.registrystack.org/vocab/geometryType"],
            "Point"
        );
        assert_eq!(
            vocabulary_property["https://id.registrystack.org/vocab/coordinateReferenceSystem"],
            "http://www.opengis.net/def/crs/OGC/0/CRS84"
        );
        let shacl = full_record_shacl(&registry, &resource);
        let encoded = format!(
            "{}\n{}\n{}\n{}",
            serde_json::to_string(&schema).expect("schema serializes"),
            serde_json::to_string(&context).expect("context serializes"),
            serde_json::to_string(&vocabulary).expect("vocabulary serializes"),
            shacl
        );
        assert!(encoded.contains("rdf:JSON"));
        assert!(encoded.contains("rdf-syntax-ns#JSON"));
        assert!(encoded.contains("geometryType"));
        assert!(!encoded.to_ascii_lowercase().contains("geosparql"));
        assert!(!encoded.contains("private_longitude_carrier"));
        assert!(!encoded.contains("private_latitude_carrier"));
    }

    fn codelist(path: &str, values: &[&str]) -> crate::model::CompiledCodelist {
        crate::model::CompiledCodelist {
            path: path.into(),
            id: path.into(),
            version: "1".into(),
            values: values.iter().map(|value| (*value).into()).collect(),
        }
    }

    fn resource() -> CompiledResource {
        use crate::contract::{Handling, ReviewStatus};
        use crate::model::*;
        CompiledResource {
            id: "record".into(),
            dataset_identifier: "records".into(),
            entity_type_identifier: "record".into(),
            title: "Record".into(),
            description: "Record".into(),
            semantic_class: "https://example.invalid/vocab/Record".into(),
            source: "db".into(),
            view: "records".into(),
            record_context: CompiledRecordContext {
                record_identifier_column: "id".into(),
                revision_identifier_column: "rev".into(),
                lifecycle_state_column: "state".into(),
                lifecycle_state_codelist: "state.yaml".into(),
                recorded_at_column: "at".into(),
                schema_reference: "https://example.invalid/artifacts/record.schema.json".into(),
                semantic_model_reference:
                    "https://example.invalid/artifacts/record.vocabulary.jsonld".into(),
            },
            properties: vec![CompiledProperty {
                name: "name".into(),
                label: "Name".into(),
                description: "Name".into(),
                source_required: true,
                semantic_iri: "https://example.invalid/vocab/name".into(),
                classification: EffectiveClassification {
                    privacy: "non-personal".into(),
                    privacy_scheme: "urn:p".into(),
                    privacy_version: "1".into(),
                    institutional: "public".into(),
                    institutional_scheme: "urn:i".into(),
                    institutional_version: "1".into(),
                    handling: Handling::Public,
                    handling_scheme: "urn:h".into(),
                    handling_version: "1".into(),
                    status: ReviewStatus::Reviewed,
                    provenance_ref: "review.yaml".into(),
                },
                binding: crate::model::CompiledPropertyBinding::Scalar(
                    crate::model::CompiledScalarPropertyBinding {
                        source_column: "name".into(),
                        transform: None,
                        data_type: DataType::String,
                        codelist: None,
                    },
                ),
            }],
            primary_geometry: None,
            disclosure_profiles: Vec::new(),
            operations: Vec::new(),
            column_accounting: Vec::new(),
            processing_descriptions: Vec::new(),
        }
    }

    fn registry() -> CompiledRegistry {
        use crate::contract::Visibility;
        use crate::model::CompiledMetadataVisibility;
        CompiledRegistry {
            contract_revision: "sha256:test".into(),
            contract_id: "test".into(),
            contract_version: "1".into(),
            registry_identifier: "urn:example:registry".into(),
            registry_name: "Registry".into(),
            authority_identifier: "urn:example:authority".into(),
            authority_name: "Authority".into(),
            operator_identifier: None,
            operator_name: None,
            authoritative_scope: "scope".into(),
            base_uri: "https://example.invalid/".into(),
            identifier_lifecycle_policy_ref: "governance/id.yaml".into(),
            alignment_targets: Vec::new(),
            controller_identifier: "urn:example:authority".into(),
            publisher_identifier: "urn:example:authority".into(),
            audit_owner_identifier: "urn:example:audit".into(),
            publication: None,
            local_vocabulary: "https://example.invalid/vocab/".into(),
            semantic_alignments: Vec::new(),
            governed_files: Vec::new(),
            classification_review: None,
            codelists: Vec::new(),
            sources: Vec::new(),
            resources: Vec::new(),
            statistical_datasets: Vec::new(),
            metadata_visibility: CompiledMetadataVisibility {
                service: Visibility::Public,
                resources: Visibility::Public,
                statistical_datasets: None,
                semantics: Visibility::Public,
                classifications: Visibility::Public,
                processing: Visibility::Public,
            },
        }
    }
}
