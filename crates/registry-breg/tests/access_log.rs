// SPDX-License-Identifier: Apache-2.0

//! Compiler contract for the governed subject-facing access log.

use registry_breg::{compile_project, parse_project_json, CompileFailure, CompileProfile};
use registry_platform_canonical_json::parse_json_strict;
use serde_json::{json, Value};

fn source() -> Value {
    json!({
        "apiVersion": "registry.registrystack.org/v1alpha1",
        "kind": "RegistryProject",
        "registry": {
            "id": "access-log-registry",
            "version": "1",
            "defaultLanguage": "en",
            "canonicalBaseIri": "https://registry.example.test/access-log"
        },
        "entities": [{
            "id": "person",
            "primaryDataset": "people",
            "route": "people",
            "mutationMode": "mutable",
            "classification": "restricted",
            "fields": [
                {
                    "id": "citizen-id",
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 128,
                    "required": true,
                    "classification": "restricted"
                },
                {
                    "id": "display-name",
                    "type": "string",
                    "maxLength": 200,
                    "required": true,
                    "classification": "restricted"
                }
            ],
            "accessLog": {
                "subjectField": "citizen-id",
                "trustedIntermediaries": ["evidence-service"],
                "exemptions": {
                    "investigator": {
                        "reason": "active-investigation",
                        "delayDays": 7
                    }
                }
            }
        }],
        "accessProfiles": [
            {
                "id": "subject",
                "default": true,
                "principalClaim": "registry_principal",
                "permissions": [{
                    "entity": "person",
                    "operations": ["get", "list"],
                    "readableFields": ["citizen-id", "display-name"],
                    "rowBoundaries": []
                }]
            },
            {
                "id": "investigator",
                "principalClaim": "registry_principal",
                "permissions": [{
                    "entity": "person",
                    "operations": ["get"],
                    "readableFields": ["display-name"],
                    "rowBoundaries": []
                }]
            },
            {
                "id": "writer",
                "principalClaim": "registry_principal",
                "permissions": [{
                    "entity": "person",
                    "operations": ["create"],
                    "writableFields": ["citizen-id", "display-name"],
                    "rowBoundaries": []
                }]
            }
        ]
    })
}

fn compile(value: &Value) -> Result<registry_breg::CompiledRegistry, CompileFailure> {
    let project = parse_project_json(&serde_json::to_vec(value).unwrap()).expect("source parses");
    compile_project(&project, &[], CompileProfile::Authoring)
}

fn refusal_codes(value: &Value) -> Vec<String> {
    compile(value)
        .expect_err("source must be refused")
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.clone())
        .collect()
}

fn assert_refused(value: &Value, code: &str) {
    let codes = refusal_codes(value);
    assert!(
        codes.iter().any(|candidate| candidate == code),
        "expected {code}, got {codes:?}"
    );
}

fn add_relationship_reader(value: &mut Value) {
    value["entities"]
        .as_array_mut()
        .unwrap()
        .extend([json!({
            "id": "case",
            "primaryDataset": "people",
            "route": "cases",
            "mutationMode": "mutable",
            "classification": "restricted",
            "fields": [{
                "id": "case-code", "type": "string", "maxLength": 64,
                "required": true, "classification": "restricted"
            }],
            "readPaths": [{
                "id": "people", "through": "case-person", "to": "person", "route": "people"
            }]
        }), json!({
            "id": "case-person",
            "primaryDataset": "people",
            "route": "case-people",
            "mutationMode": "mutable",
            "classification": "restricted",
            "fields": [
                {"id": "case", "type": "reference", "target": "case", "required": true, "classification": "restricted"},
                {"id": "person", "type": "reference", "target": "person", "required": true, "classification": "restricted"}
            ]
        })]);
    let profile = json!({
        "id": "relationship-investigator",
        "principalClaim": "registry_principal",
        "permissions": [{
            "entity": "case",
            "operations": ["get"],
            "readableFields": ["case-code"],
            "rowBoundaries": [],
            "readPaths": [{"path": "people", "readableFields": ["display-name"]}]
        }]
    });
    value["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .push(profile);
}

#[test]
fn access_log_compiles_governed_defaults_and_policy() {
    let compiled = compile(&source()).expect("access-log policy compiles");
    let policy = compiled.entities()["person"]
        .access_log
        .as_ref()
        .expect("compiled entity carries access-log policy");
    assert_eq!(policy.subject_field, "citizen-id");
    assert_eq!(policy.retention_days, 90);
    assert_eq!(
        policy.trusted_intermediaries,
        ["evidence-service".to_owned()].into()
    );
    assert_eq!(policy.exemptions["investigator"].delay_days, 7);

    let effective = serde_json::to_value(&compiled.entities()["person"]).unwrap();
    assert_eq!(effective["accessLog"]["retentionDays"], 90);
    assert_eq!(
        effective["accessLog"]["exemptions"]["investigator"]["reason"],
        "active-investigation"
    );
}

#[test]
fn generated_openapi_publishes_the_subject_owned_bounded_route() {
    let compiled = compile(&source()).expect("access-log policy compiles");
    let artifact = compiled
        .artifacts()
        .get("generated/openapi.json")
        .expect("OpenAPI is generated");
    let openapi = parse_json_strict(&artifact.bytes).expect("OpenAPI is strict JSON");
    let operation = &openapi["paths"]["/v1/records/people/{record_id}/access-log"]["get"];
    assert_eq!(operation["operationId"], "records.person.get.access-log");
    assert_eq!(operation["x-registry-operation"], "access_log");
    assert_eq!(
        operation["x-registry-responseShape"],
        "BRegSubjectAccessLogV1"
    );
    assert_eq!(operation["security"], json!([{"bearerAuth": []}]));
    assert_eq!(
        operation["x-registry-accessProfiles"],
        json!(["investigator", "subject"])
    );
    assert!(operation["description"]
        .as_str()
        .unwrap()
        .contains("subject field must exactly match the verified principal"));
    let parameters = operation["parameters"].as_array().unwrap();
    let limit = parameters
        .iter()
        .find(|parameter| parameter["name"] == "limit")
        .unwrap();
    assert_eq!(
        limit["schema"],
        json!({"type":"integer", "minimum":1, "maximum":100, "default":50})
    );
    let cursor = parameters
        .iter()
        .find(|parameter| parameter["name"] == "cursor")
        .unwrap();
    assert_eq!(cursor["schema"], json!({"type":"string", "format":"uuid"}));
    assert_eq!(
        operation["responses"]["200"]["headers"]["Cache-Control"]["schema"]["const"],
        "no-store"
    );
    assert_eq!(
        operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/SubjectAccessLogPage"
    );
    assert!(operation["responses"]["404"].is_object());
    let schema = &openapi["components"]["schemas"]["SubjectAccessLogPage"];
    assert_eq!(schema["properties"]["events"]["maxItems"], 100);
    assert_eq!(
        schema["properties"]["events"]["items"]["required"],
        json!([
            "id",
            "accessedAt",
            "requester",
            "serviceClient",
            "purpose",
            "operationId",
            "visibleAfter",
            "exemptionReason"
        ])
    );
    assert_eq!(
        schema["properties"]["events"]["items"]["properties"]["purpose"]["type"],
        json!(["string", "null"])
    );
}

#[test]
fn generated_openapi_omits_access_log_route_without_entity_opt_in() {
    let mut value = source();
    value["entities"][0]
        .as_object_mut()
        .unwrap()
        .remove("accessLog");
    let compiled = compile(&value).expect("ordinary entity compiles");
    let artifact = compiled.artifacts().get("generated/openapi.json").unwrap();
    let openapi = parse_json_strict(&artifact.bytes).unwrap();
    assert!(openapi["paths"]
        .get("/v1/records/people/{record_id}/access-log")
        .is_none());
    assert!(openapi["components"]["schemas"]
        .get("SubjectAccessLogPage")
        .is_none());
}

#[test]
fn subject_field_must_be_required_bounded_plaintext_text() {
    let mut unknown = source();
    unknown["entities"][0]["accessLog"]["subjectField"] = json!("unknown");
    assert_refused(&unknown, "breg.access-log.subject-field-invalid");

    let mut optional = source();
    optional["entities"][0]["fields"][0]["required"] = json!(false);
    assert_refused(&optional, "breg.access-log.subject-field-invalid");

    let mut encrypted = source();
    encrypted["entities"][0]["fields"][0]["encrypted"] = json!(true);
    assert_refused(&encrypted, "breg.access-log.subject-field-invalid");

    let mut wrong_type = source();
    wrong_type["entities"][0]["fields"][0] = json!({
        "id": "citizen-id", "type": "int64", "required": true,
        "classification": "restricted"
    });
    assert_refused(&wrong_type, "breg.access-log.subject-field-invalid");

    let mut too_long = source();
    too_long["entities"][0]["fields"][0]["maxLength"] = json!(513);
    assert_refused(&too_long, "breg.access-log.subject-field-invalid");
}

#[test]
fn retention_and_exemption_delays_are_bounded() {
    for invalid in [0, 3_651] {
        let mut value = source();
        value["entities"][0]["accessLog"]["retentionDays"] = json!(invalid);
        assert_refused(&value, "breg.access-log.retention-days-invalid");
    }
    for invalid in [0, 90] {
        let mut value = source();
        value["entities"][0]["accessLog"]["exemptions"]["investigator"]["delayDays"] =
            json!(invalid);
        assert_refused(&value, "breg.access-log.exemption-delay-invalid");
    }
}

#[test]
fn trusted_intermediaries_are_explicit_and_bounded() {
    for invalid in ["", "evidence service", "evidence\nservice"] {
        let mut value = source();
        value["entities"][0]["accessLog"]["trustedIntermediaries"] = json!([invalid]);
        assert_refused(&value, "breg.access-log.trusted-intermediary-invalid");
    }

    let mut too_many = source();
    too_many["entities"][0]["accessLog"]["trustedIntermediaries"] = json!((0..65)
        .map(|index| format!("client-{index}"))
        .collect::<Vec<_>>());
    assert_refused(&too_many, "breg.access-log.trusted-intermediaries-too-many");
}

#[test]
fn exemptions_name_read_profiles_and_bounded_policy_text() {
    let mut unknown = source();
    let exemption = unknown["entities"][0]["accessLog"]["exemptions"]
        .as_object_mut()
        .unwrap()
        .remove("investigator")
        .unwrap();
    unknown["entities"][0]["accessLog"]["exemptions"]["missing"] = exemption;
    assert_refused(&unknown, "breg.access-log.exemption-profile-invalid");

    let mut nonreader = source();
    let exemption = nonreader["entities"][0]["accessLog"]["exemptions"]
        .as_object_mut()
        .unwrap()
        .remove("investigator")
        .unwrap();
    nonreader["entities"][0]["accessLog"]["exemptions"]["writer"] = exemption;
    assert_refused(&nonreader, "breg.access-log.exemption-profile-invalid");

    for invalid in ["", " padded", "line\nbreak"] {
        let mut value = source();
        value["entities"][0]["accessLog"]["exemptions"]["investigator"]["reason"] = json!(invalid);
        assert_refused(&value, "breg.access-log.exemption-reason-invalid");
    }

    let mut too_long = source();
    too_long["entities"][0]["accessLog"]["exemptions"]["investigator"]["reason"] =
        json!("x".repeat(257));
    assert_refused(&too_long, "breg.access-log.exemption-reason-invalid");
}

#[test]
fn relationship_exemptions_bind_the_authority_entity_and_read_path() {
    let mut value = source();
    add_relationship_reader(&mut value);
    value["entities"][0]["accessLog"]["exemptions"]["relationship-investigator"] = json!({
        "sourceEntity": "case",
        "reason": "active-investigation",
        "delayDays": 7
    });
    let compiled = compile(&value).expect("relationship exemption compiles");
    let exemption = &compiled.entities()["person"]
        .access_log
        .as_ref()
        .unwrap()
        .exemptions["relationship-investigator"];
    assert_eq!(exemption.source_entity.as_deref(), Some("case"));

    let mut no_grant = value.clone();
    no_grant["accessProfiles"][3]["permissions"][0]["readPaths"] = json!([]);
    assert_refused(&no_grant, "breg.access-log.exemption-profile-invalid");

    let mut wrong_target = value.clone();
    wrong_target["entities"][1]["readPaths"][0]["to"] = json!("case");
    assert_refused(&wrong_target, "breg.access-log.exemption-profile-invalid");

    let mut unknown_source = value;
    unknown_source["entities"][0]["accessLog"]["exemptions"]["relationship-investigator"]
        ["sourceEntity"] = json!("missing");
    assert_refused(&unknown_source, "breg.access-log.exemption-profile-invalid");
}
