//! The Evidence payload contract for Version 1.
//!
//! The schema literal here is the single source of the generated
//! `evidence-v1.schema.json` release artifact and of the payload validation
//! every verifier performs, so a response cannot be accepted against a
//! different shape than the one published.

use std::sync::OnceLock;

use jsonschema::{Draft, JSONSchema};
use serde_json::{json, Value};
use thiserror::Error;

pub const SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";
pub const EVIDENCE_SCHEMA_ID: &str =
    "https://registrystack.org/schemas/evidence/assertion-evidence-v1.json";
pub const REQUEST_NONCE_PATTERN: &str = "^[A-Za-z0-9_-]{43}$";

static EVIDENCE_VALIDATOR: OnceLock<Result<JSONSchema, ContractValidationError>> = OnceLock::new();

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("built-in public contract schema failed to initialize")]
pub struct ContractValidationError;

/// Validate a verified JWS payload against the exact generated Version 1 schema.
pub fn evidence_contract_accepts(value: &Value) -> Result<bool, ContractValidationError> {
    match EVIDENCE_VALIDATOR.get_or_init(|| {
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .should_validate_formats(true)
            .compile(&evidence_schema())
            .map_err(|_| ContractValidationError)
    }) {
        Ok(validator) => Ok(validator.is_valid(value)),
        Err(error) => Err(*error),
    }
}

pub fn evidence_schema() -> Value {
    json!({
        "$schema": SCHEMA_DIALECT,
        "$id": EVIDENCE_SCHEMA_ID,
        "title": "Evidence assertion payload Version 1",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema", "assuranceProfile", "subjectBinding", "id", "type", "supportsRequirement", "isConformantTo",
            "issuedBy", "providedBy", "issuedAt", "observedAt", "validUntil",
            "purpose", "configurationRevision", "subjects", "supportedValues"
        ],
        // An audience-scoped assertion carries both members or neither. The
        // implication from `subjectBinding` to those members is enforced in
        // code, because one closed object cannot express it without a branch
        // that carries its own `properties` map.
        "dependentRequired": {
            "audience": ["requestNonce"],
            "requestNonce": ["audience"]
        },
        "properties": {
            "schema": {"const": "registry.assertion-evidence/v1"},
            "assuranceProfile": {"enum": ["local", "production", "evidence-grade"]},
            "subjectBinding": {"enum": ["audience-scoped", "holder-bound"]},
            "requestNonce": {"type": "string", "pattern": REQUEST_NONCE_PATTERN},
            "id": {"type": "string", "format": "uri", "maxLength": 512},
            "type": {"const": "Evidence"},
            "supportsRequirement": {"type": "string", "format": "uri", "maxLength": 512},
            "isConformantTo": {"type": "string", "format": "uri", "maxLength": 512},
            "issuedBy": {"type": "string", "format": "uri", "maxLength": 512},
            "providedBy": {"type": "string", "format": "uri", "maxLength": 512},
            "issuedAt": {"type": "string", "format": "date-time"},
            "observedAt": {"type": "string", "format": "date-time"},
            "validUntil": {"type": "string", "format": "date-time"},
            "purpose": {"type": "string", "pattern": "^[a-z][a-z0-9._:-]{0,127}$"},
            "audience": {"type": "string", "format": "uri", "maxLength": 512},
            "configurationRevision": {"type": "string", "pattern": "^sha256:[a-f0-9]{64}$"},
            "subjects": {
                "type": "array", "minItems": 1, "maxItems": 8,
                "items": {"$ref": "#/$defs/subject-binding"}
            },
            "supportedValues": {
                "type": "array", "minItems": 1, "maxItems": 16,
                "items": {"$ref": "#/$defs/supported-value"}
            }
        },
        "$defs": {
            "subject-binding": {
                "type": "object", "additionalProperties": false,
                "required": ["role", "binding"],
                "properties": {
                    "role": {"type": "string", "pattern": "^[a-z][a-z0-9._-]{0,63}$"},
                    "binding": {"type": "string", "pattern": "^urn:evidence:subject:v[1-9][0-9]*_[A-Za-z0-9_-]{43}$"}
                }
            },
            "supported-value": {
                "type": "object", "additionalProperties": false,
                "required": ["providesValueFor", "value"],
                "properties": {
                    "providesValueFor": {"type": "string", "format": "uri", "maxLength": 512},
                    "value": {"$ref": "#/$defs/value"}
                }
            },
            "value": {
                "anyOf": [
                    {"type": "boolean"},
                    {"type": "integer", "minimum": -9007199254740991_i64, "maximum": 9007199254740991_i64},
                    {"type": "string", "minLength": 1, "maxLength": 1024},
                    {"$ref": "#/$defs/bucket"},
                    {"$ref": "#/$defs/entity-reference"},
                    {"$ref": "#/$defs/structured"},
                    {
                        "type": "array", "minItems": 1, "maxItems": 64,
                        "items": {"anyOf": [
                            {"type": "string", "minLength": 1, "maxLength": 1024},
                            {"$ref": "#/$defs/entity-reference"}
                        ]}
                    }
                ]
            },
            "bucket": {
                "type": "object", "additionalProperties": false,
                "required": ["form", "scheme", "bucket"],
                "properties": {
                    "form": {"enum": ["date-bucket", "time-bucket"]},
                    "scheme": {"type": "string", "format": "uri", "maxLength": 512},
                    "bucket": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"}
                }
            },
            "entity-reference": {
                "type": "object", "additionalProperties": false,
                "required": ["form", "reference"],
                "properties": {
                    "form": {"const": "audience-scoped-entity-reference"},
                    "reference": {"type": "string", "pattern": "^urn:evidence:entity:v[1-9][0-9]*_[A-Za-z0-9_-]{43}$"}
                }
            },
            "structured": {
                "type": "object", "additionalProperties": false,
                "required": ["form", "schema", "fields"],
                "properties": {
                    "form": {"const": "reviewed-structured-value"},
                    "schema": {"type": "string", "format": "uri", "maxLength": 512},
                    "fields": {"type": "object", "minProperties": 1, "maxProperties": 16}
                }
            }
        },
        "$comment": "The selected concept declaration further closes value form, schema, codelist, precision, cardinality, structured fields, and uniqueness. Selector profiles and selector values never appear in Evidence."
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> Value {
        json!({
            "schema": "registry.assertion-evidence/v1",
            "assuranceProfile": "evidence-grade",
            "subjectBinding": "audience-scoped",
            "requestNonce": "A".repeat(43),
            "id": "urn:evidence:assertion:v1_2f0a",
            "type": "Evidence",
            "supportsRequirement": "urn:example:requirement",
            "isConformantTo": "urn:example:evidence-type",
            "issuedBy": "urn:example:issuer",
            "providedBy": "urn:example:provider",
            "issuedAt": "2026-08-02T09:15:00Z",
            "observedAt": "2026-08-02T09:14:59Z",
            "validUntil": "2026-08-02T09:20:00Z",
            "purpose": "age-gated-service",
            "audience": "urn:example:relying-party",
            "configurationRevision": format!("sha256:{}", "0".repeat(64)),
            "subjects": [{"role": "applicant", "binding": format!("urn:evidence:subject:v1_{}", "a".repeat(43))}],
            "supportedValues": [{"providesValueFor": "urn:example:concept", "value": true}]
        })
    }

    /// The contract is one closed object covering both binding modes. It
    /// permits either member set and refuses a half-populated one; the
    /// implication from the declared mode to the members is enforced in code.
    #[test]
    fn the_payload_contract_accepts_both_binding_modes() {
        assert!(evidence_contract_accepts(&payload()).expect("contract compiles"));

        let mut holder_bound = payload();
        let members = holder_bound.as_object_mut().expect("object");
        members.insert(
            "subjectBinding".to_string(),
            Value::String("holder-bound".to_string()),
        );
        members.remove("audience");
        members.remove("requestNonce");
        assert!(evidence_contract_accepts(&holder_bound).expect("contract compiles"));
    }

    #[test]
    fn the_payload_contract_refuses_a_half_populated_audience_scope() {
        for absent in ["audience", "requestNonce"] {
            let mut half = payload();
            half.as_object_mut().expect("object").remove(absent);
            assert!(
                !evidence_contract_accepts(&half).expect("contract compiles"),
                "removing {absent} must not be accepted"
            );
        }
    }

    #[test]
    fn the_payload_contract_requires_a_declared_binding_mode() {
        let mut absent = payload();
        absent
            .as_object_mut()
            .expect("object")
            .remove("subjectBinding");
        assert!(!evidence_contract_accepts(&absent).expect("contract compiles"));

        let mut unknown = payload();
        unknown.as_object_mut().expect("object").insert(
            "subjectBinding".to_string(),
            Value::String("holder_bound".to_string()),
        );
        assert!(!evidence_contract_accepts(&unknown).expect("contract compiles"));
    }
}
