// SPDX-License-Identifier: Apache-2.0
//! Deterministic local semantic and validation artifact construction.

use serde_json::{json, Map, Value};

use crate::contract::DataType;
use crate::model::{CompiledProperty, CompiledRegistry, CompiledResource};

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
        graph.push(json!({
            "@id": property.semantic_iri,
            "@type": "rdf:Property",
            "rdfs:label": property.label,
            "rdfs:comment": property.description,
            "rdfs:domain": {"@id": resource.semantic_class},
            "rdfs:range": {"@id": datatype_iri(property.data_type)},
            "https://id.registrystack.org/vocab/sourceRequired": property.source_required,
            "https://id.registrystack.org/vocab/codelist": property.codelist,
        }));
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
    for field in [
        "registryIdentifier",
        "schemaReference",
        "semanticModelReference",
        "authorityIdentifier",
    ] {
        context.insert(
            field.into(),
            json!({"@id": format!("{core}{field}"), "@type": "@id"}),
        );
    }
    for field in [
        "recordIdentifier",
        "revisionIdentifier",
        "lifecycleState",
        "recordedAt",
        "domainData",
    ] {
        context.insert(field.into(), json!(format!("{core}{field}")));
    }
    for property in selected_properties(resource, selected) {
        context.insert(
            property.name.clone(),
            json!({"@id": property.semantic_iri, "@nest": "domainData"}),
        );
    }
    // Transport-only envelope members never acquire semantic meaning.
    for field in ["data", "items", "pageInfo", "nextCursor", "meta"] {
        context.insert(field.into(), Value::Null);
    }
    json!({"@context": context})
}

pub fn representation_schema(
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
    let lifecycle_values = registry
        .codelists
        .iter()
        .find(|item| item.path == resource.record_context.lifecycle_state_codelist)
        .map(|item| item.values.clone())
        .unwrap_or_default();
    let lifecycle_schema = if lifecycle_values.is_empty() {
        json!({"type": "string", "minLength": 1})
    } else {
        json!({"type": "string", "enum": lifecycle_values})
    };
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
            "registryIdentifier", "recordIdentifier", "revisionIdentifier",
            "lifecycleState", "schemaReference", "semanticModelReference",
            "authorityIdentifier", "recordedAt", "domainData"
        ],
        "properties": {
            "registryIdentifier": {"const": registry.registry_identifier},
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

pub fn representation_shacl(
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
    let mut output = format!(
        "@prefix sh: <http://www.w3.org/ns/shacl#> .\n@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n\n<{}shapes/{}> a sh:NodeShape ;\n  sh:targetClass <{}> ;\n  sh:closed true",
        registry.local_vocabulary, resource.id, resource.semantic_class
    );
    for (path, datatype) in [
        (
            "registryIdentifier",
            "http://www.w3.org/2001/XMLSchema#anyURI",
        ),
        (
            "recordIdentifier",
            "http://www.w3.org/2001/XMLSchema#string",
        ),
        (
            "revisionIdentifier",
            "http://www.w3.org/2001/XMLSchema#string",
        ),
        ("lifecycleState", "http://www.w3.org/2001/XMLSchema#string"),
        ("schemaReference", "http://www.w3.org/2001/XMLSchema#anyURI"),
        (
            "semanticModelReference",
            "http://www.w3.org/2001/XMLSchema#anyURI",
        ),
        (
            "authorityIdentifier",
            "http://www.w3.org/2001/XMLSchema#anyURI",
        ),
        ("recordedAt", "http://www.w3.org/2001/XMLSchema#dateTime"),
    ] {
        output.push_str(&format!(
            " ;\n  sh:property [ sh:path <https://id.registrystack.org/vocab/core/{path}> ; sh:datatype <{datatype}> ; sh:minCount 1 ; sh:maxCount 1 ]"
        ));
    }
    for property in selected_properties(resource, selected) {
        let controlled_values = property
            .codelist
            .as_deref()
            .and_then(|path| registry.codelists.iter().find(|item| item.path == path))
            .map(|codelist| {
                format!(
                    " ; sh:in ( {} )",
                    codelist
                        .values
                        .iter()
                        .map(|value| format!("\"{}\"", turtle_escape(value)))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            })
            .unwrap_or_default();
        output.push_str(&format!(
            " ;\n  sh:property [ sh:path <{}> ; sh:datatype <{}>{} ; sh:minCount {} ; sh:maxCount 1 ]",
            property.semantic_iri,
            datatype_iri(property.data_type),
            controlled_values,
            usize::from(full && property.source_required)
        ));
    }
    output.push_str(" .\n");
    output
}

fn property_schema(registry: &CompiledRegistry, property: &CompiledProperty) -> Value {
    match property.data_type {
        DataType::String => json!({"type": "string"}),
        DataType::ControlledCode => {
            let values = property
                .codelist
                .as_deref()
                .and_then(|path| registry.codelists.iter().find(|item| item.path == path))
                .map(|codelist| codelist.values.clone())
                .unwrap_or_default();
            if values.is_empty() {
                json!({"type": "string", "x-registry-codelist": property.codelist})
            } else {
                json!({"type": "string", "enum": values, "x-registry-codelist": property.codelist})
            }
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
    fn transport_envelope_is_null_in_context() {
        let context = json_ld_context(&registry(), &resource(), &["name".into()]);
        assert!(context["@context"]["meta"].is_null());
        assert_eq!(context["@context"]["name"]["@nest"], "domainData");
    }

    fn resource() -> CompiledResource {
        use crate::contract::{Handling, ReviewStatus};
        use crate::model::*;
        CompiledResource {
            id: "record".into(),
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
                source_column: "name".into(),
                transform: None,
                data_type: DataType::String,
                codelist: None,
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
            }],
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
            operator_identifier: None,
            authoritative_scope: "scope".into(),
            base_uri: "https://example.invalid/".into(),
            identifier_lifecycle_policy_ref: "governance/id.yaml".into(),
            alignment_targets: Vec::new(),
            controller_identifier: "urn:example:authority".into(),
            publisher_identifier: "urn:example:authority".into(),
            audit_owner_identifier: "urn:example:audit".into(),
            local_vocabulary: "https://example.invalid/vocab/".into(),
            semantic_alignments: Vec::new(),
            governed_files: Vec::new(),
            classification_review: None,
            codelists: Vec::new(),
            sources: Vec::new(),
            resources: Vec::new(),
            metadata_visibility: CompiledMetadataVisibility {
                service: Visibility::Public,
                resources: Visibility::Public,
                semantics: Visibility::Public,
                classifications: Visibility::Public,
                processing: Visibility::Public,
            },
        }
    }
}
