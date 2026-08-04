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
            "schema", "assuranceProfile", "requestNonce", "id", "type", "supportsRequirement", "isConformantTo",
            "issuedBy", "providedBy", "issuedAt", "observedAt", "validUntil",
            "purpose", "audience", "configurationRevision", "subjects", "supportedValues"
        ],
        "properties": {
            "schema": {"const": "registry.assertion-evidence/v1"},
            "assuranceProfile": {"enum": ["local", "production", "evidence-grade"]},
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
