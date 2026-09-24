// SPDX-License-Identifier: Apache-2.0

use registry_breg::{compile_project, parse_project_json, CompileProfile, CompiledRegistry};
use serde_json::{json, Value};

pub const PROJECT: &str = include_str!("../fixtures/consent-access.yaml");
/// The index of the consent-record entity in the fixture.
#[allow(dead_code)]
pub const CONSENT_RECORD: usize = 4;

pub fn source() -> Value {
    let authored = registry_breg::parse_project_yaml(PROJECT.as_bytes()).unwrap();
    serde_json::to_value(authored).unwrap()
}

pub fn compile(value: &Value) -> Result<CompiledRegistry, registry_breg::CompileFailure> {
    compile_project(
        &parse_project_json(&serde_json::to_vec(value).unwrap()).unwrap(),
        &[],
        CompileProfile::Authoring,
    )
}

/// Compile a variant that must fail, and return every diagnostic code.
#[allow(dead_code)]
pub fn refusal_codes(value: &Value) -> Vec<String> {
    compile(value)
        .expect_err("the variant must be refused")
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.clone())
        .collect()
}

/// A self-issued action in the 5.5 principal-link pattern. An action
/// requirement must name a reference input its effects use, so the consent
/// row also records the link that authorized it.
#[allow(dead_code)]
pub fn self_issued_project() -> Value {
    let mut value = source();
    value["entities"][CONSENT_RECORD]["fields"].as_array_mut().unwrap().push(json!(
        {"id": "link", "type": "reference", "target": "consent-subject-link", "classification": "internal"}
    ));
    value["entities"].as_array_mut().unwrap().push(json!({
        "id": "consent-subject-link", "primaryDataset": "consent-dataset", "route": "consent-subject-links",
        "mutationMode": "mutable", "classification": "restricted",
        "fields": [
            {"id": "subject", "type": "reference", "target": "person", "required": true, "classification": "restricted"},
            {"id": "principal", "type": "string", "maxLength": 255, "required": true, "classification": "restricted"},
            {"id": "active", "type": "boolean", "required": true, "classification": "internal"}
        ]
    }));
    value["actions"].as_array_mut().unwrap().push(json!({
        "id": "withdraw-consent",
        "consentIssuer": "self",
        "inputs": [
            {"id": "link", "type": "reference", "target": "consent-subject-link", "required": true, "classification": "internal"},
            {"id": "subject", "type": "reference", "target": "person", "required": true, "classification": "restricted"},
            {"id": "recipient", "type": "vocabulary-code", "vocabulary": "registry-recipients", "required": true, "classification": "internal"},
            {"id": "purpose", "type": "vocabulary-code", "vocabulary": "data-use-purpose", "required": true, "classification": "internal"},
            {"id": "scope", "type": "vocabulary-code", "vocabulary": "registry-consent-scopes", "required": true, "classification": "internal"},
            {"id": "decision", "type": "vocabulary-code", "vocabulary": "consent-decision", "values": ["withdrawn"], "required": true, "classification": "internal"},
            {"id": "effective-at", "type": "timestamp", "required": true, "classification": "internal"}
        ],
        "requires": [
            {"input": "link", "field": "subject", "equalsInput": "subject"},
            {"input": "link", "field": "active", "equals": true}
        ],
        "effects": [{
            "id": "decision", "target": {"entity": "consent-decision"}, "operation": "create",
            "set": {
                "subject": {"fromField": "subject"}, "recipient": {"fromField": "recipient"},
                "purpose": {"fromField": "purpose"}, "scope": {"fromField": "scope"},
                "decision": {"fromField": "decision"}, "effective-at": {"fromField": "effective-at"},
                "link": {"fromField": "link"}
            }
        }]
    }));
    value["accessProfiles"].as_array_mut().unwrap().push(json!({
        "id": "consent-self", "principalClaim": "principal", "requiredScopes": ["consent:self"],
        "permissions": [{
            "action": "withdraw-consent", "operations": ["invoke"],
            "targets": [
                {"entity": "consent-subject-link", "rowBoundaries": [{"field": "principal", "claim": "principal", "operator": "equals"}]},
                {"entity": "person", "rowBoundaries": []},
                {"entity": "consent-decision", "rowBoundaries": []}
            ],
            "results": ["decision"]
        }]
    }));
    value
}
