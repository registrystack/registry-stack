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
    context.insert("xsd".into(), json!("http://www.w3.org/2001/XMLSchema#"));
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
    for field in ["recordIdentifier", "revisionIdentifier", "lifecycleState"] {
        context.insert(
            field.into(),
            json!({"@id": format!("{core}{field}"), "@type": "xsd:string"}),
        );
    }
    context.insert(
        "recordedAt".into(),
        json!({"@id": format!("{core}recordedAt"), "@type": "xsd:dateTime"}),
    );
    context.insert("domainData".into(), json!("@nest"));
    for property in selected_properties(resource, selected) {
        context.insert(
            property.name.clone(),
            json!({
                "@id": property.semantic_iri,
                "@nest": "domainData",
                "@type": datatype_iri(property.data_type),
            }),
        );
    }
    // Record containers contribute their contents to the graph without
    // becoming predicates of their own. Other transport-only members never
    // acquire semantic meaning.
    for field in ["data", "items"] {
        context.insert(field.into(), json!("@graph"));
    }
    for field in ["pageInfo", "nextCursor", "meta"] {
        context.insert(field.into(), Value::Null);
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
            "registryIdentifier", "recordIdentifier", "revisionIdentifier",
            "lifecycleState", "schemaReference", "semanticModelReference",
            "authorityIdentifier", "recordedAt", "domainData"
        ],
        "properties": {
            "@id": {"type": "string", "format": "uri"},
            "@type": {"const": resource.semantic_class},
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
        "registryIdentifier",
        "schemaReference",
        "semanticModelReference",
        "authorityIdentifier",
    ] {
        output.push_str(&format!(
            " ;\n  sh:property [ sh:path <https://id.registrystack.org/vocab/core/{path}> ; sh:nodeKind sh:IRI ; sh:minCount 1 ; sh:maxCount 1 ]"
        ));
    }
    for (path, datatype) in [
        (
            "recordIdentifier",
            "http://www.w3.org/2001/XMLSchema#string",
        ),
        (
            "revisionIdentifier",
            "http://www.w3.org/2001/XMLSchema#string",
        ),
        ("lifecycleState", "http://www.w3.org/2001/XMLSchema#string"),
        ("recordedAt", "http://www.w3.org/2001/XMLSchema#dateTime"),
    ] {
        let controlled_values = if path == "lifecycleState" {
            lifecycle_constraint.as_str()
        } else {
            ""
        };
        output.push_str(&format!(
            " ;\n  sh:property [ sh:path <https://id.registrystack.org/vocab/core/{path}> ; sh:datatype <{datatype}>{controlled_values} ; sh:minCount 1 ; sh:maxCount 1 ]"
        ));
    }
    for property in selected_properties(resource, selected) {
        let controlled_values = match property.data_type {
            DataType::ControlledCode => {
                let path = property.codelist.as_deref().unwrap_or_else(|| {
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
            let path = property.codelist.as_deref().unwrap_or_else(|| {
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
    fn transport_envelope_is_null_in_context() {
        let context = json_ld_context(&registry(), &resource(), &["name".into()]);
        assert!(context["@context"]["meta"].is_null());
        assert_eq!(context["@context"]["data"], "@graph");
        assert_eq!(context["@context"]["items"], "@graph");
        assert_eq!(context["@context"]["domainData"], "@nest");
        assert_eq!(context["@context"]["name"]["@nest"], "domainData");
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
        resource.properties[0].data_type = DataType::ControlledCode;
        resource.properties[0].codelist = Some("codes.yaml".into());
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
        resource.properties[0].data_type = DataType::ControlledCode;
        resource.properties[0].codelist = Some("codes.yaml".into());

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
        assert!(shacl.contains("sh:in ( \"ACTIVE\" \"RETIRED\" )"));
        assert!(shacl.contains("sh:in ( \"ONE\" \"TWO\" )"));
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
