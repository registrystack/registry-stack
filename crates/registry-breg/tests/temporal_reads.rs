// SPDX-License-Identifier: Apache-2.0

//! `:current` and `:as-of` follow the `validAt` rule by interval type and
//! echo the `asOf` they used in collection `meta`.

use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use serde_json::{json, Value};

fn openapi(boundary_type: &str) -> Value {
    let source = json!({
        "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
        "kind": "BRegProject",
        "project": {"id": "licences", "version": "1", "defaultLanguage": "en",
            "canonicalBaseIri": "https://licences.example.test", "timezone": "Asia/Colombo"},
        "datasets": [{"id": "licences"}],
        "recordTypes": [{
            "id": "licence", "primaryDataset": "licences", "route": "licences", "mutationMode": "mutable",
            "fields": [
                {"id": "holder", "type": "string", "maximumLength": 32, "required": true, "classification": "internal"},
                {"id": "valid-from", "type": boundary_type, "required": true, "classification": "internal"},
                {"id": "valid-to", "type": boundary_type, "classification": "internal"}
            ],
            "temporal": {"startField": "valid-from", "endField": "valid-to"}
        }],
        "accessProfiles": [{
            "id": "reader", "default": true, "principalClaim": "principal", "requiredScopes": "unrestricted",
            "permissions": {"records": [{
                "recordType": "licence", "operations": ["list"],
                "readableFields": ["holder", "valid-from", "valid-to"],
                "rowBoundaries": "unrestricted"
            }]}
        }]
    });
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).expect("parses");
    let registry = compile_project(&project, &[], CompileProfile::Authoring).expect("compiles");
    serde_json::from_slice(
        &registry
            .artifacts()
            .get("generated/openapi.json")
            .expect("OpenAPI is generated")
            .bytes,
    )
    .expect("OpenAPI is JSON")
}

fn as_of_parameter(openapi: &Value) -> &Value {
    &openapi["paths"]["/v1/records/licences:as-of"]["get"]["parameters"]
        .as_array()
        .expect("parameters")
        .iter()
        .find(|parameter| parameter["name"] == "asOf")
        .expect("asOf parameter")["schema"]
}

fn meta(openapi: &Value, path: &str) -> Vec<Value> {
    let content = &openapi["paths"][path]["get"]["responses"]["200"]["content"];
    ["application/json", "application/ld+json"]
        .iter()
        .map(|media_type| content[media_type]["schema"]["properties"]["meta"].clone())
        .collect()
}

#[test]
fn as_of_takes_a_calendar_date_on_a_date_interval_and_an_instant_on_a_timestamp_interval() {
    assert_eq!(
        as_of_parameter(&openapi("date")),
        &json!({"type": "string", "format": "date"})
    );
    assert_eq!(
        as_of_parameter(&openapi("timestamp")),
        &json!({"type": "string", "format": "date-time"})
    );
}

#[test]
fn current_and_as_of_responses_echo_the_as_of_they_used_in_meta() {
    for (boundary_type, format) in [("date", "date"), ("timestamp", "date-time")] {
        let openapi = openapi(boundary_type);
        for path in ["/v1/records/licences:current", "/v1/records/licences:as-of"] {
            for meta in meta(&openapi, path) {
                assert_eq!(
                    meta["properties"]["asOf"],
                    json!({"type": "string", "format": format}),
                    "{boundary_type} {path}"
                );
                assert!(
                    meta["required"]
                        .as_array()
                        .expect("required")
                        .contains(&json!("asOf")),
                    "{boundary_type} {path}: {meta}"
                );
            }
        }
        for meta in meta(&openapi, "/v1/records/licences") {
            assert!(
                meta["properties"].get("asOf").is_none(),
                "a plain list has no asOf: {meta}"
            );
        }
    }
}
