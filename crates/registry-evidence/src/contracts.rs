//! Deterministic public-contract generation for Evidence Version 1.
//!
//! The generated files are release artifacts. This module is their only
//! source and deliberately has no dependency on a deployment bundle.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use jsonschema::{Draft, JSONSchema};
use schemars::JsonSchema;
use serde_json::{json, Value};
use thiserror::Error;

use crate::model::{
    Evidence, EvidenceDefinitions, EvidenceRequest, FlattenedJws, JwksDocument, ProblemBody,
    UnsignedEvidenceEnvelope,
};

pub const OPENAPI_FILE: &str = "registry-evidence.openapi.json";
pub const REQUEST_SCHEMA_FILE: &str = "evidence-request-v1.schema.json";
pub const EVIDENCE_SCHEMA_FILE: &str = "evidence-v1.schema.json";
pub const DEFINITIONS_SCHEMA_FILE: &str = "evidence-definitions-v1.schema.json";
pub const JWS_SCHEMA_FILE: &str = "flattened-jws-v1.schema.json";
pub const UNSIGNED_ENVELOPE_SCHEMA_FILE: &str = "evidence-unsigned-envelope-v1.schema.json";
pub const PROBLEM_SCHEMA_FILE: &str = "problem-v1.schema.json";
pub const JWKS_SCHEMA_FILE: &str = "jwks-v1.schema.json";

const SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";
const REQUEST_SCHEMA_ID: &str = "https://registrystack.org/schemas/evidence/request-v1.json";
const EVIDENCE_SCHEMA_ID: &str =
    "https://registrystack.org/schemas/evidence/assertion-evidence-v1.json";
const DEFINITIONS_SCHEMA_ID: &str =
    "https://registrystack.org/schemas/evidence/definitions-v1.json";
const JWS_SCHEMA_ID: &str = "https://registrystack.org/schemas/evidence/flattened-jws-v1.json";
const UNSIGNED_ENVELOPE_SCHEMA_ID: &str =
    "https://registrystack.org/schemas/evidence/unsigned-envelope-v1.json";
const PROBLEM_SCHEMA_ID: &str = "https://registrystack.org/schemas/evidence/problem-v1.json";
const JWKS_SCHEMA_ID: &str = "https://registrystack.org/schemas/evidence/jwks-v1.json";
const REQUEST_NONCE_PATTERN: &str = "^[A-Za-z0-9_-]{43}$";
const PROBLEM_VARIANTS: [(&str, u16, &str); 9] = [
    ("malformed_request", 400, "Request is not valid"),
    ("invalid_selector", 400, "Request is not valid"),
    ("authentication_failed", 401, "Authentication failed"),
    ("not_authorized", 403, "Request is not authorized"),
    (
        "response_format_not_acceptable",
        406,
        "Requested response format is not acceptable",
    ),
    (
        "evidence_not_available",
        422,
        "Evidence could not be produced",
    ),
    ("rate_limited", 429, "Request rate exceeded"),
    (
        "dependency_unavailable",
        503,
        "Service temporarily unavailable",
    ),
    (
        "service_unavailable",
        503,
        "Service temporarily unavailable",
    ),
];

static SERVED_OPENAPI: OnceLock<Option<String>> = OnceLock::new();
static REQUEST_VALIDATOR: OnceLock<Result<JSONSchema, ContractValidationError>> = OnceLock::new();
static EVIDENCE_VALIDATOR: OnceLock<Result<JSONSchema, ContractValidationError>> = OnceLock::new();
static DEFINITIONS_VALIDATOR: OnceLock<Result<JSONSchema, ContractValidationError>> =
    OnceLock::new();

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("built-in public contract schema failed to initialize")]
pub(crate) struct ContractValidationError;

#[derive(Debug, Error)]
pub enum ContractGenerationError {
    #[error("generated contract serialization failed")]
    Serialization(#[from] serde_json::Error),
    #[error("generated contract output failed at {path}")]
    Output {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("generated contract no longer matches the public Rust wire type {type_name}")]
    ModelDrift { type_name: &'static str },
}

/// Generate every committed public contract, keyed by its stable filename.
pub fn documents() -> Result<BTreeMap<&'static str, String>, ContractGenerationError> {
    let request = request_schema();
    let evidence = evidence_schema();
    let definitions = definitions_schema();
    let jws = jws_schema();
    let unsigned = unsigned_envelope_schema();
    let problem = problem_schema();
    let jwks = jwks_schema();
    assert_model_shape::<EvidenceRequest>("EvidenceRequest", &request, true)?;
    assert_model_shape::<Evidence>("Evidence", &evidence, true)?;
    assert_model_shape::<EvidenceDefinitions>("EvidenceDefinitions", &definitions, true)?;
    assert_model_shape::<FlattenedJws>("FlattenedJws", &jws, false)?;
    assert_model_shape::<UnsignedEvidenceEnvelope>("UnsignedEvidenceEnvelope", &unsigned, false)?;
    assert_model_shape::<ProblemBody>("ProblemBody", &problem, false)?;
    assert_model_shape::<JwksDocument>("JwksDocument", &jwks, false)?;
    let openapi = openapi_document(
        &request,
        &evidence,
        &definitions,
        &jws,
        &unsigned,
        &problem,
        &jwks,
    );

    let values = [
        (REQUEST_SCHEMA_FILE, request),
        (EVIDENCE_SCHEMA_FILE, evidence),
        (DEFINITIONS_SCHEMA_FILE, definitions),
        (JWS_SCHEMA_FILE, jws),
        (UNSIGNED_ENVELOPE_SCHEMA_FILE, unsigned),
        (PROBLEM_SCHEMA_FILE, problem),
        (JWKS_SCHEMA_FILE, jwks),
        (OPENAPI_FILE, openapi),
    ];
    values
        .into_iter()
        .map(|(name, value)| Ok((name, pretty_json(&value)?)))
        .collect()
}

/// Write all generated contracts to an otherwise caller-owned directory.
pub fn write_documents(output: &Path) -> Result<(), ContractGenerationError> {
    fs::create_dir_all(output).map_err(|source| ContractGenerationError::Output {
        path: output.to_path_buf(),
        source,
    })?;
    for (name, contents) in documents()? {
        let path = output.join(name);
        fs::write(&path, contents)
            .map_err(|source| ContractGenerationError::Output { path, source })?;
    }
    Ok(())
}

/// The generated OpenAPI document the running service publishes.
///
/// It is built once from the same generator as [`documents`], so the served
/// description is the committed release artifact and cannot drift from it.
pub(crate) fn served_openapi_document() -> Option<&'static str> {
    SERVED_OPENAPI
        .get_or_init(|| {
            pretty_json(&openapi_document(
                &request_schema(),
                &evidence_schema(),
                &definitions_schema(),
                &jws_schema(),
                &unsigned_envelope_schema(),
                &problem_schema(),
                &jwks_schema(),
            ))
            .ok()
        })
        .as_deref()
}

/// Validate an inbound public request against the exact generated Version 1 schema.
pub(crate) fn request_contract_accepts(value: &Value) -> Result<bool, ContractValidationError> {
    contract_validator(&REQUEST_VALIDATOR, request_schema)
        .map(|validator| validator.is_valid(value))
}

/// Validate a verified JWS payload against the exact generated Version 1 schema.
pub(crate) fn evidence_contract_accepts(value: &Value) -> Result<bool, ContractValidationError> {
    contract_validator(&EVIDENCE_VALIDATOR, evidence_schema)
        .map(|validator| validator.is_valid(value))
}

/// Validate an outbound discovery response against the exact generated
/// Version 1 schema.
pub(crate) fn definitions_contract_accepts(value: &Value) -> Result<bool, ContractValidationError> {
    contract_validator(&DEFINITIONS_VALIDATOR, definitions_schema)
        .map(|validator| validator.is_valid(value))
}

fn contract_validator(
    cell: &'static OnceLock<Result<JSONSchema, ContractValidationError>>,
    schema: fn() -> Value,
) -> Result<&'static JSONSchema, ContractValidationError> {
    match cell.get_or_init(|| {
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .should_validate_formats(true)
            .compile(&schema())
            .map_err(|_| ContractValidationError)
    }) {
        Ok(validator) => Ok(validator),
        Err(error) => Err(*error),
    }
}

fn assert_model_shape<T: JsonSchema>(
    type_name: &'static str,
    contract: &Value,
    compare_nested_properties: bool,
) -> Result<(), ContractGenerationError> {
    let derived = serde_json::to_value(schemars::schema_for!(T))?;
    let matches = if compare_nested_properties {
        property_groups(&derived) == property_groups(contract)
    } else {
        root_properties(&derived) == root_properties(contract)
    };
    if matches {
        Ok(())
    } else {
        Err(ContractGenerationError::ModelDrift { type_name })
    }
}

fn root_properties(value: &Value) -> Vec<String> {
    value
        .get("properties")
        .and_then(Value::as_object)
        .map(|properties| properties.keys().cloned().collect())
        .unwrap_or_default()
}

fn property_groups(value: &Value) -> Vec<Vec<String>> {
    fn visit(value: &Value, groups: &mut Vec<Vec<String>>) {
        match value {
            Value::Array(values) => {
                for value in values {
                    visit(value, groups);
                }
            }
            Value::Object(object) => {
                if let Some(properties) = object.get("properties").and_then(Value::as_object) {
                    groups.push(properties.keys().cloned().collect());
                }
                for value in object.values() {
                    visit(value, groups);
                }
            }
            _ => {}
        }
    }

    let mut groups = Vec::new();
    visit(value, &mut groups);
    groups.sort();
    groups
}

fn pretty_json(value: &Value) -> Result<String, serde_json::Error> {
    let mut rendered = serde_json::to_string_pretty(value)?;
    rendered.push('\n');
    Ok(rendered)
}

fn request_schema() -> Value {
    json!({
        "$schema": SCHEMA_DIALECT,
        "$id": REQUEST_SCHEMA_ID,
        "title": "Evidence request Version 1",
        "type": "object",
        "additionalProperties": false,
        "required": ["requestNonce", "requirement", "purpose", "subjects"],
        "properties": {
            "requestNonce": {"type": "string", "pattern": REQUEST_NONCE_PATTERN},
            "requirement": {"type": "string", "format": "uri", "minLength": 1, "maxLength": 512},
            "purpose": {"type": "string", "pattern": "^[a-z][a-z0-9._:-]{0,127}$"},
            "subjects": {
                "type": "array", "minItems": 1, "maxItems": 8,
                "items": {"$ref": "#/$defs/subject"}
            }
        },
        "$defs": {
            "subject": {
                "type": "object", "additionalProperties": false,
                "required": ["role", "selector"],
                "properties": {
                    "role": {"type": "string", "pattern": "^[a-z][a-z0-9._-]{0,63}$"},
                    "selector": {"$ref": "#/$defs/selector"}
                }
            },
            "selector": {
                "type": "object", "additionalProperties": false,
                "required": ["profile"],
                "properties": {
                    "profile": {"type": "string", "pattern": "^[a-z][a-z0-9._-]{0,127}$"},
                    "values": {
                        "type": "object", "minProperties": 1, "maxProperties": 16,
                        "propertyNames": {"type": "string", "pattern": "^[a-z][a-z0-9._-]{0,63}$"},
                        "additionalProperties": {"$ref": "#/$defs/scalar-selector-value"}
                    }
                }
            },
            "scalar-selector-value": {
                "oneOf": [
                    {"type": "string", "minLength": 1, "maxLength": 512},
                    {"type": "integer", "minimum": -9007199254740991_i64, "maximum": 9007199254740991_i64},
                    {"type": "boolean"}
                ]
            }
        },
        "$comment": "Named selector-profile validation follows this transport schema. The profile closes exact field names, scalar types, bounds, aggregate size, value origin, and source placements. Invalid selector material fails before credential acquisition or source access. requestNonce is the canonical unpadded base64url encoding of exactly 32 independently generated random bytes; a noncanonical final symbol is rejected by the runtime. Callers must not encode identifiers, selectors, secrets, or document digests into it."
    })
}

fn definitions_schema() -> Value {
    json!({
        "$schema": SCHEMA_DIALECT,
        "$id": DEFINITIONS_SCHEMA_ID,
        "title": "Requester-scoped Evidence definitions Version 1",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema", "configurationRevision", "issuedBy", "providedBy", "definitions"
        ],
        "properties": {
            "schema": {"const": "registry.evidence-definitions/v1"},
            "configurationRevision": {"type": "string", "pattern": "^sha256:[a-f0-9]{64}$"},
            "issuedBy": {"type": "string", "format": "uri", "maxLength": 512},
            "providedBy": {"type": "string", "format": "uri", "maxLength": 512},
            "definitions": {
                "type": "array", "maxItems": 16384, "uniqueItems": true,
                "items": {"$ref": "#/$defs/definition"}
            }
        },
        "$defs": {
            "definition": {
                "type": "object", "additionalProperties": false,
                "required": [
                    "requirement", "kind", "evidenceType", "purpose",
                    "referenceFrameworks", "subjects", "concepts"
                ],
                "properties": {
                    "requirement": {"type": "string", "format": "uri", "maxLength": 512},
                    "kind": {"enum": ["criterion", "information-requirement", "constraint"]},
                    "evidenceType": {"type": "string", "format": "uri", "maxLength": 512},
                    "purpose": {"type": "string", "pattern": "^[a-z][a-z0-9._:-]{0,127}$"},
                    "referenceFrameworks": {
                        "type": "array", "minItems": 1, "maxItems": 16, "uniqueItems": true,
                        "items": {"type": "string", "format": "uri", "maxLength": 512}
                    },
                    "subjects": {
                        "type": "array", "minItems": 1, "maxItems": 8, "uniqueItems": true,
                        "items": {"$ref": "#/$defs/subject"}
                    },
                    "concepts": {
                        "type": "array", "minItems": 1, "maxItems": 16, "uniqueItems": true,
                        "items": {"$ref": "#/$defs/concept"}
                    }
                }
            },
            "subject": {
                "type": "object", "additionalProperties": false,
                "required": ["role", "cardinality", "selector"],
                "properties": {
                    "role": {"type": "string", "pattern": "^[a-z][a-z0-9._-]{0,63}$"},
                    "cardinality": {"const": "one"},
                    "selector": {"$ref": "#/$defs/selector"}
                }
            },
            "selector": {
                "type": "object", "additionalProperties": false,
                "required": ["profile", "valueOrigin", "fields"],
                "properties": {
                    "profile": {"type": "string", "pattern": "^[a-z][a-z0-9._-]{0,127}$"},
                    "valueOrigin": {"enum": ["request", "authenticated-context", "authenticated-grant"]},
                    "fields": {
                        "type": "array", "minItems": 1, "maxItems": 16, "uniqueItems": true,
                        "items": {"$ref": "#/$defs/selector-field"}
                    }
                }
            },
            "selector-field": {
                "oneOf": [
                    {
                        "type": "object", "additionalProperties": false,
                        "required": ["type", "name", "minimumBytes", "maximumBytes"],
                        "properties": {
                            "type": {"const": "string"},
                            "name": {"type": "string", "pattern": "^[a-z][a-z0-9._-]{0,63}$"},
                            "minimumBytes": {"type": "integer", "minimum": 1, "maximum": 8192},
                            "maximumBytes": {"type": "integer", "minimum": 1, "maximum": 8192}
                        }
                    },
                    {
                        "type": "object", "additionalProperties": false,
                        "required": ["type", "name"],
                        "properties": {
                            "type": {"const": "date"},
                            "name": {"type": "string", "pattern": "^[a-z][a-z0-9._-]{0,63}$"}
                        }
                    },
                    {
                        "type": "object", "additionalProperties": false,
                        "required": ["type", "name", "minimum", "maximum"],
                        "properties": {
                            "type": {"const": "integer"},
                            "name": {"type": "string", "pattern": "^[a-z][a-z0-9._-]{0,63}$"},
                            "minimum": {"type": "integer", "minimum": -9007199254740991_i64, "maximum": 9007199254740991_i64},
                            "maximum": {"type": "integer", "minimum": -9007199254740991_i64, "maximum": 9007199254740991_i64}
                        }
                    },
                    {
                        "type": "object", "additionalProperties": false,
                        "required": ["type", "name"],
                        "properties": {
                            "type": {"const": "boolean"},
                            "name": {"type": "string", "pattern": "^[a-z][a-z0-9._-]{0,63}$"}
                        }
                    },
                    {
                        "type": "object", "additionalProperties": false,
                        "required": ["type", "name", "scheme", "version", "maximumBytes"],
                        "properties": {
                            "type": {"const": "controlled-code"},
                            "name": {"type": "string", "pattern": "^[a-z][a-z0-9._-]{0,63}$"},
                            "scheme": {"type": "string", "format": "uri", "maxLength": 512},
                            "version": {"type": "string", "minLength": 1, "maxLength": 128},
                            "maximumBytes": {"type": "integer", "minimum": 1, "maximum": 8192}
                        }
                    }
                ]
            },
            "concept": {
                "type": "object", "additionalProperties": false,
                "required": ["id", "form"],
                "properties": {
                    "id": {"type": "string", "format": "uri", "maxLength": 512},
                    "form": {"enum": [
                        "boolean", "controlled-code", "controlled-category", "bounded-integer",
                        "bounded-decimal", "date-bucket", "time-bucket",
                        "audience-scoped-entity-reference", "controlled-code-list",
                        "entity-reference-list", "reviewed-structured-value"
                    ]}
                }
            }
        },
        "$comment": "The authenticated response contains only complete request shapes that match exactly one configured authority path. It never exposes source plans, scripts, credentials, requester tags, authority-profile identifiers, selector values, codelist values, or unrelated definitions."
    })
}

fn evidence_schema() -> Value {
    json!({
        "$schema": SCHEMA_DIALECT,
        "$id": EVIDENCE_SCHEMA_ID,
        "title": "Evidence assertion payload Version 1",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema", "requestNonce", "id", "type", "supportsRequirement", "isConformantTo",
            "issuedBy", "providedBy", "issuedAt", "observedAt", "validUntil",
            "purpose", "audience", "configurationRevision", "subjects", "supportedValues"
        ],
        "properties": {
            "schema": {"const": "registry.assertion-evidence/v1"},
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

fn jws_schema() -> Value {
    json!({
        "$schema": SCHEMA_DIALECT,
        "$id": JWS_SCHEMA_ID,
        "title": "Evidence flattened JWS response Version 1",
        "type": "object",
        "additionalProperties": false,
        "required": ["protected", "payload", "signature"],
        "properties": {
            "protected": {"type": "string", "minLength": 1, "pattern": "^[A-Za-z0-9_-]+$"},
            "payload": {"type": "string", "minLength": 1, "pattern": "^[A-Za-z0-9_-]+$"},
            "signature": {"type": "string", "pattern": "^[A-Za-z0-9_-]{86}$"}
        },
        "$comment": "Flattened JWS JSON Serialization. The protected header has exactly alg=EdDSA, kid, typ=evidence+jws, and cty=application/evidence+json. The payload is the base64url encoding without padding of exact UTF-8 Evidence JSON bytes."
    })
}

fn unsigned_envelope_schema() -> Value {
    json!({
        "$schema": SCHEMA_DIALECT,
        "$id": UNSIGNED_ENVELOPE_SCHEMA_ID,
        "title": "Evidence unsigned response envelope Version 1",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema", "type", "integrityProtection", "warning", "evidence"],
        "properties": {
            "schema": {"const": "registry.unsigned-evidence-envelope/v1"},
            "type": {"const": "UnsignedEvidenceEnvelope"},
            "integrityProtection": {"const": "none"},
            "warning": {"const": "not-cryptographically-verifiable"},
            "evidence": {"$ref": EVIDENCE_SCHEMA_ID}
        },
        "$comment": "Transport-authenticated convenience representation selected only by its exact vendor media type when the immutable bundle and the complete matched grant permit it. Once separated from its HTTPS exchange it provides no issuer-authenticity, integrity, non-repudiation, or later-verification property. The nested evidence is the same closed core object that would be JWS encoded. There is no protected, payload, or signature member, so the strict JWS verifier rejects this representation; tooling that parses it must return an explicitly unverified result."
    })
}

fn problem_schema() -> Value {
    let mut schema = json!({
        "$schema": SCHEMA_DIALECT,
        "$id": PROBLEM_SCHEMA_ID,
        "title": "Evidence public problem Version 1",
        "type": "object",
        "additionalProperties": false,
        "required": ["type", "title", "status", "code", "operation"],
        "properties": {
            "type": {
                "type": "string",
                "enum": [
                    "https://registrystack.org/problems/evidence/malformed_request",
                    "https://registrystack.org/problems/evidence/invalid_selector",
                    "https://registrystack.org/problems/evidence/authentication_failed",
                    "https://registrystack.org/problems/evidence/not_authorized",
                    "https://registrystack.org/problems/evidence/response_format_not_acceptable",
                    "https://registrystack.org/problems/evidence/evidence_not_available",
                    "https://registrystack.org/problems/evidence/rate_limited",
                    "https://registrystack.org/problems/evidence/dependency_unavailable",
                    "https://registrystack.org/problems/evidence/service_unavailable"
                ]
            },
            "title": {"type": "string", "enum": [
                "Request is not valid", "Authentication failed", "Request is not authorized",
                "Requested response format is not acceptable",
                "Evidence could not be produced", "Request rate exceeded", "Service temporarily unavailable"
            ]},
            "status": {"type": "integer", "enum": [400, 401, 403, 406, 422, 429, 503]},
            "code": {"type": "string", "enum": [
                "malformed_request", "invalid_selector", "authentication_failed", "not_authorized",
                "response_format_not_acceptable",
                "evidence_not_available", "rate_limited", "dependency_unavailable", "service_unavailable"
            ]},
            "operation": {"type": "string", "pattern": "^[0-9A-HJKMNP-TV-Z]{26}$"}
        },
        "$comment": "Problem members are a closed safe shape. No request, authority, source, script, supported-value, subject-binding, candidate, or credential detail is returned."
    });
    schema["oneOf"] = Value::Array(
        PROBLEM_VARIANTS
        .into_iter()
        .map(|(code, status, title)| {
            json!({"properties": {
                "type": {"const": format!("https://registrystack.org/problems/evidence/{code}")},
                "title": {"const": title},
                "status": {"const": status},
                "code": {"const": code}
            }})
        })
        .collect(),
    );
    schema
}

fn jwks_schema() -> Value {
    json!({
        "$schema": SCHEMA_DIALECT,
        "$id": JWKS_SCHEMA_ID,
        "title": "Evidence public JWKS Version 1",
        "type": "object",
        "additionalProperties": false,
        "required": ["keys"],
        "properties": {
            "keys": {
                "type": "array", "minItems": 1, "maxItems": 33, "uniqueItems": true,
                "items": {"$ref": "#/$defs/ed25519-public-jwk"}
            }
        },
        "$defs": {
            "ed25519-public-jwk": {
                "type": "object", "additionalProperties": false,
                "required": ["kty", "kid", "alg", "crv", "x"],
                "properties": {
                    "kty": {"const": "OKP"},
                    "kid": {"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]+$"},
                    "alg": {"const": "EdDSA"},
                    "crv": {"const": "Ed25519"},
                    "x": {"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$"}
                }
            }
        },
        "$comment": "Only the active and configured retired public keys are published. Key ids are unique and limited to 256 UTF-8 bytes by the runtime; JSON Schema maxLength is an additional code-point bound. Discovery is not a trust anchor; verifiers pin the governed provider and JWKS location."
    })
}

fn insert_schema_family(
    components: &mut serde_json::Map<String, Value>,
    root_name: &str,
    schema: &Value,
    definition_names: &[(&str, &str)],
) {
    let mut root = schema.clone();
    let definitions = root
        .as_object_mut()
        .and_then(|object| object.remove("$defs"))
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    rewrite_openapi_schema(&mut root, definition_names);
    components.insert(root_name.to_string(), root);

    for (definition_name, component_name) in definition_names {
        let mut definition = definitions
            .get(*definition_name)
            .unwrap_or_else(|| panic!("missing generated schema definition {definition_name}"))
            .clone();
        rewrite_openapi_schema(&mut definition, definition_names);
        components.insert((*component_name).to_string(), definition);
    }
}

fn rewrite_openapi_schema(value: &mut Value, definition_names: &[(&str, &str)]) {
    match value {
        Value::Array(values) => {
            for value in values {
                rewrite_openapi_schema(value, definition_names);
            }
        }
        Value::Object(object) => {
            object.remove("$schema");
            object.remove("$id");
            object.remove("$comment");

            if let Some(reference) = object
                .get("$ref")
                .and_then(Value::as_str)
                .map(str::to_string)
            {
                if let Some(definition_name) = reference.strip_prefix("#/$defs/") {
                    let component_name = definition_names
                        .iter()
                        .find_map(|(definition, component)| {
                            (*definition == definition_name).then_some(*component)
                        })
                        .unwrap_or_else(|| {
                            panic!("unmapped generated schema definition {definition_name}")
                        });
                    object.insert(
                        "$ref".to_string(),
                        Value::String(format!("#/components/schemas/{component_name}")),
                    );
                }
            }

            if let Some(constant) = object.remove("const") {
                let schema_type = match &constant {
                    Value::String(_) => Some("string"),
                    Value::Bool(_) => Some("boolean"),
                    Value::Number(number) if number.is_i64() || number.is_u64() => Some("integer"),
                    Value::Number(_) => Some("number"),
                    Value::Array(_) => Some("array"),
                    Value::Object(_) => Some("object"),
                    Value::Null => None,
                };
                if let Some(schema_type) = schema_type {
                    object
                        .entry("type".to_string())
                        .or_insert_with(|| Value::String(schema_type.to_string()));
                }
                object.insert("enum".to_string(), Value::Array(vec![constant]));
            }
            if !object.contains_key("type") {
                let enum_type = object
                    .get("enum")
                    .and_then(Value::as_array)
                    .and_then(|values| values.first())
                    .and_then(|value| match value {
                        Value::String(_) => Some("string"),
                        Value::Bool(_) => Some("boolean"),
                        Value::Number(number) if number.is_i64() || number.is_u64() => {
                            Some("integer")
                        }
                        Value::Number(_) => Some("number"),
                        _ => None,
                    });
                if let Some(enum_type) = enum_type {
                    object.insert("type".to_string(), Value::String(enum_type.to_string()));
                }
            }

            for value in object.values_mut() {
                rewrite_openapi_schema(value, definition_names);
            }
        }
        _ => {}
    }
}

fn problem_content(codes: &[&str]) -> Value {
    let variants = codes
        .iter()
        .map(|code| {
            let (_, status, title) = PROBLEM_VARIANTS
                .iter()
                .find(|(variant, _, _)| variant == code)
                .unwrap_or_else(|| panic!("unknown public problem code {code}"));
            json!({
                "allOf": [
                    {"$ref": "#/components/schemas/Problem"},
                    {
                        "type": "object",
                        "properties": {
                            "type": {"type": "string", "enum": [format!("https://registrystack.org/problems/evidence/{code}")]},
                            "title": {"type": "string", "enum": [title]},
                            "status": {"type": "integer", "enum": [status]},
                            "code": {"type": "string", "enum": [code]}
                        }
                    }
                ]
            })
        })
        .collect::<Vec<_>>();
    let schema = if variants.len() == 1 {
        variants.into_iter().next().expect("one problem variant")
    } else {
        json!({"oneOf": variants})
    };
    json!({"application/problem+json": {"schema": schema}})
}

fn response_headers(extra: Option<(&str, Value)>) -> Value {
    let mut headers = serde_json::Map::new();
    headers.insert(
        "Cache-Control".to_string(),
        json!({
            "description": "Evidence responses are never cacheable.",
            "schema": {"type": "string", "enum": ["no-store"]}
        }),
    );
    if let Some((name, header)) = extra {
        headers.insert(name.to_string(), header);
    }
    Value::Object(headers)
}

/// Headers for every `/v1/evidence` response, which varies on `Accept`.
fn evidence_response_headers(extra: Option<(&str, Value)>) -> Value {
    let mut headers = response_headers(extra);
    headers
        .as_object_mut()
        .expect("response headers are an object")
        .insert(
            "Vary".to_string(),
            json!({
                "description": "The response format is negotiated through the exact Accept matrix.",
                "schema": {"type": "string", "enum": ["Accept"]}
            }),
        );
    headers
}

#[allow(clippy::too_many_arguments)]
fn openapi_document(
    request: &Value,
    evidence: &Value,
    definitions: &Value,
    jws: &Value,
    unsigned: &Value,
    problem: &Value,
    jwks: &Value,
) -> Value {
    let mut schemas = serde_json::Map::new();
    insert_schema_family(
        &mut schemas,
        "EvidenceRequest",
        request,
        &[
            ("subject", "EvidenceRequestSubject"),
            ("selector", "EvidenceRequestSelector"),
            ("scalar-selector-value", "SelectorValue"),
        ],
    );
    insert_schema_family(
        &mut schemas,
        "Evidence",
        evidence,
        &[
            ("subject-binding", "SubjectBinding"),
            ("supported-value", "SupportedValue"),
            ("value", "PublicValue"),
            ("bucket", "BucketValue"),
            ("entity-reference", "EntityReferenceValue"),
            ("structured", "StructuredValue"),
        ],
    );
    insert_schema_family(
        &mut schemas,
        "EvidenceDefinitions",
        definitions,
        &[
            ("definition", "EvidenceDefinition"),
            ("subject", "EvidenceDefinitionSubject"),
            ("selector", "EvidenceDefinitionSelector"),
            ("selector-field", "EvidenceSelectorField"),
            ("concept", "EvidenceDefinitionConcept"),
        ],
    );
    insert_schema_family(&mut schemas, "FlattenedJws", jws, &[]);
    insert_schema_family(&mut schemas, "UnsignedEvidenceEnvelope", unsigned, &[]);
    if let Some(reference) = schemas
        .get_mut("UnsignedEvidenceEnvelope")
        .and_then(Value::as_object_mut)
        .and_then(|schema| schema.get_mut("properties"))
        .and_then(Value::as_object_mut)
        .and_then(|properties| properties.get_mut("evidence"))
        .and_then(Value::as_object_mut)
    {
        reference.insert(
            "$ref".to_string(),
            Value::String("#/components/schemas/Evidence".to_string()),
        );
    }
    if let Some(properties) = schemas
        .get_mut("FlattenedJws")
        .and_then(Value::as_object_mut)
        .and_then(|schema| schema.get_mut("properties"))
        .and_then(Value::as_object_mut)
    {
        properties["protected"]["x-decoded-schema"] =
            json!({"$ref": "#/components/schemas/EvidenceProtectedHeader"});
        properties["payload"]["x-decoded-schema"] =
            json!({"$ref": "#/components/schemas/Evidence"});
    }
    schemas.insert(
        "EvidenceProtectedHeader".to_string(),
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["alg", "kid", "typ", "cty"],
            "properties": {
                "alg": {"type": "string", "enum": ["EdDSA"]},
                "kid": {"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^[^\\u0000-\\u001F\\u007F]+$"},
                "typ": {"type": "string", "enum": ["evidence+jws"]},
                "cty": {"type": "string", "enum": ["application/evidence+json"]}
            }
        }),
    );
    insert_schema_family(&mut schemas, "Problem", problem, &[]);
    insert_schema_family(
        &mut schemas,
        "JwksDocument",
        jwks,
        &[("ed25519-public-jwk", "Ed25519PublicJwk")],
    );
    schemas.insert(
        "HealthStatus".to_string(),
        json!({
            "type": "object", "additionalProperties": false,
            "required": ["status"],
            "properties": {"status": {"type": "string", "enum": ["ok"]}}
        }),
    );
    schemas.insert(
        "ReadyStatus".to_string(),
        json!({
            "type": "object", "additionalProperties": false,
            "required": ["status"],
            "properties": {"status": {"type": "string", "enum": ["ready"]}}
        }),
    );

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Registry Evidence API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Minimum-disclosure signed assertion service, Version 1."
        },
        "paths": {
            "/v1/evidence": {
                "post": {
                    "operationId": "createEvidence",
                    "summary": "Produce evidence for one authorized fixed requirement",
                    "description": "Missing Accept, */*, and the exact application/jose+json media type select the default signed flattened JWS. Only the exact application/vnd.registrystack.evidence-unsigned+json media type selects the unsigned envelope, and only when the immutable bundle and the complete matched authority grant permit it. Duplicate, combined, parameterized, weighted, or unknown negotiation returns 406 before source access.",
                    "security": [{"bearerAuth": []}],
                    "requestBody": {
                        "required": true,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/EvidenceRequest"}}}
                    },
                    "responses": {
                        "200": {
                            "description": "Signed Evidence as flattened JWS JSON Serialization by default, or the explicitly authorized self-identifying unsigned envelope",
                            "headers": evidence_response_headers(None),
                            "content": {
                                "application/jose+json": {"schema": {"$ref": "#/components/schemas/FlattenedJws"}},
                                "application/vnd.registrystack.evidence-unsigned+json": {"schema": {"$ref": "#/components/schemas/UnsignedEvidenceEnvelope"}}
                            }
                        },
                        "400": {
                            "description": "Malformed request or invalid selector",
                            "headers": evidence_response_headers(None),
                            "content": problem_content(&["malformed_request", "invalid_selector"])
                        },
                        "401": {
                            "description": "Authentication failed",
                            "headers": evidence_response_headers(Some(("WWW-Authenticate", json!({
                                "schema": {"type": "string", "enum": ["Bearer"]}
                            })))),
                            "content": problem_content(&["authentication_failed"])
                        },
                        "403": {
                            "description": "Request is not authorized, including a recognized response format the bundle or matched grant does not permit",
                            "headers": evidence_response_headers(None),
                            "content": problem_content(&["not_authorized"])
                        },
                        "406": {
                            "description": "Media negotiation is outside the closed Accept matrix",
                            "headers": evidence_response_headers(None),
                            "content": problem_content(&["response_format_not_acceptable"])
                        },
                        "422": {
                            "description": "Evidence could not be produced",
                            "headers": evidence_response_headers(None),
                            "content": problem_content(&["evidence_not_available"])
                        },
                        "429": {
                            "description": "Request rate exceeded",
                            "headers": evidence_response_headers(Some(("Retry-After", json!({
                                "schema": {"type": "string", "enum": ["1"]}
                            })))),
                            "content": problem_content(&["rate_limited"])
                        },
                        "503": {
                            "description": "Dependency or service temporarily unavailable",
                            "headers": evidence_response_headers(None),
                            "content": problem_content(&["dependency_unavailable", "service_unavailable"])
                        },
                    }
                }
            },
            "/v1/evidence-definitions": {
                "get": {
                    "operationId": "listEvidenceDefinitions",
                    "summary": "List the complete Evidence request shapes available to the authenticated caller",
                    "security": [{"bearerAuth": []}],
                    "responses": {
                        "200": {
                            "description": "Requester-scoped Evidence definitions",
                            "headers": response_headers(None),
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/EvidenceDefinitions"}}}
                        },
                        "400": {
                            "description": "Malformed discovery request",
                            "headers": response_headers(None),
                            "content": problem_content(&["malformed_request"])
                        },
                        "401": {
                            "description": "Authentication failed",
                            "headers": response_headers(Some(("WWW-Authenticate", json!({
                                "schema": {"type": "string", "enum": ["Bearer"]}
                            })))),
                            "content": problem_content(&["authentication_failed"])
                        },
                        "429": {
                            "description": "Request rate exceeded",
                            "headers": response_headers(Some(("Retry-After", json!({
                                "schema": {"type": "string", "enum": ["1"]}
                            })))),
                            "content": problem_content(&["rate_limited"])
                        },
                        "503": {
                            "description": "Service temporarily unavailable",
                            "headers": response_headers(None),
                            "content": problem_content(&["service_unavailable"])
                        }
                    }
                }
            },
            "/health": {
                "get": {
                    "operationId": "getHealth",
                    "summary": "Report process liveness without dependency access",
                    "responses": {"200": {
                        "description": "Process is live",
                        "headers": response_headers(None),
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/HealthStatus"}}}
                    }}
                }
            },
            "/ready": {
                "get": {
                    "operationId": "getReadiness",
                    "summary": "Report fail-closed runtime readiness",
                    "responses": {
                        "200": {
                            "description": "Runtime is ready",
                            "headers": response_headers(None),
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ReadyStatus"}}}
                        },
                        "503": {
                            "description": "Runtime is not ready",
                            "headers": response_headers(None),
                            "content": problem_content(&["service_unavailable"])
                        }
                    }
                }
            },
            "/openapi.json": {
                "get": {
                    "operationId": "getOpenApi",
                    "summary": "Fetch this OpenAPI document",
                    "description": "The generated public contract for this service. This route is intentionally unauthenticated: the served bytes are the released generated artifact and describe no deployment, definition, or authority.",
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "The generated Version 1 OpenAPI document",
                            "headers": response_headers(None),
                            "content": {"application/openapi+json": {"schema": {"type": "object"}}}
                        },
                        "503": {
                            "description": "The document could not be produced",
                            "headers": response_headers(None),
                            "content": problem_content(&["service_unavailable"])
                        }
                    }
                }
            },
            "/.well-known/evidence/jwks.json": {
                "get": {
                    "operationId": "getEvidenceJwks",
                    "summary": "Publish the active and retained public verification keys",
                    "responses": {"200": {
                        "description": "Evidence public verification keys",
                        "headers": response_headers(None),
                        "content": {"application/jwk-set+json": {"schema": {"$ref": "#/components/schemas/JwksDocument"}}}
                    }}
                }
            }
        },
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                    "description": "Exactly one Authorization header containing one Bearer token is required."
                }
            },
            "schemas": Value::Object(schemas)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_json_schema_is_valid_draft_2020_12() {
        for schema in [
            request_schema(),
            evidence_schema(),
            definitions_schema(),
            jws_schema(),
            problem_schema(),
            jwks_schema(),
        ] {
            JSONSchema::options()
                .with_draft(Draft::Draft202012)
                .should_validate_formats(true)
                .compile(&schema)
                .expect("generated schema compiles");
        }

        // The unsigned envelope references the Evidence payload schema by its
        // canonical identifier, so that document is registered for offline
        // compilation.
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .should_validate_formats(true)
            .with_document(EVIDENCE_SCHEMA_ID.to_string(), evidence_schema())
            .compile(&unsigned_envelope_schema())
            .expect("generated unsigned envelope schema compiles");
    }

    #[test]
    fn openapi_document_is_valid_utoipa_model() {
        let document = openapi_document(
            &request_schema(),
            &evidence_schema(),
            &definitions_schema(),
            &jws_schema(),
            &unsigned_envelope_schema(),
            &problem_schema(),
            &jwks_schema(),
        );
        for (name, schema) in document["components"]["schemas"]
            .as_object()
            .expect("component schemas are an object")
        {
            serde_json::from_value::<utoipa::openapi::RefOr<utoipa::openapi::Schema>>(
                schema.clone(),
            )
            .unwrap_or_else(|error| panic!("component schema {name} is invalid: {error}"));
        }
        serde_json::from_value::<utoipa::openapi::OpenApi>(document)
            .expect("generated OpenAPI parses as OpenAPI 3.1");
    }

    #[test]
    fn openapi_has_only_the_version_one_routes_and_exact_success_media() {
        let document = openapi_document(
            &request_schema(),
            &evidence_schema(),
            &definitions_schema(),
            &jws_schema(),
            &unsigned_envelope_schema(),
            &problem_schema(),
            &jwks_schema(),
        );
        let paths = document["paths"].as_object().expect("paths is an object");
        assert_eq!(
            paths.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "/.well-known/evidence/jwks.json",
                "/health",
                "/openapi.json",
                "/ready",
                "/v1/evidence",
                "/v1/evidence-definitions"
            ]
        );
        assert!(
            document["paths"]["/openapi.json"]["get"]["responses"]["200"]["content"]
                ["application/openapi+json"]
                .is_object()
        );
        assert_eq!(
            document["paths"]["/openapi.json"]["get"]["security"],
            json!([])
        );
        assert!(
            document["paths"]["/v1/evidence"]["post"]["responses"]["200"]["content"]
                ["application/jose+json"]
                .is_object()
        );
        assert!(
            document["paths"]["/v1/evidence"]["post"]["responses"]["200"]["content"]
                ["application/vnd.registrystack.evidence-unsigned+json"]
                .is_object()
        );
        assert_eq!(
            document["paths"]["/v1/evidence"]["post"]["responses"]["406"]["content"]
                ["application/problem+json"]["schema"]["allOf"][1]["properties"]["code"]["enum"],
            json!(["response_format_not_acceptable"])
        );
        for response in document["paths"]["/v1/evidence"]["post"]["responses"]
            .as_object()
            .expect("evidence responses are an object")
            .values()
        {
            assert_eq!(
                response["headers"]["Vary"]["schema"]["enum"],
                json!(["Accept"])
            );
        }
        assert!(
            document["paths"]["/v1/evidence-definitions"]["get"]["responses"]["200"]["content"]
                ["application/json"]
                .is_object()
        );
        assert!(
            document["paths"]["/.well-known/evidence/jwks.json"]["get"]["responses"]["200"]
                ["content"]["application/jwk-set+json"]
                .is_object()
        );
        assert_eq!(
            document["components"]["schemas"]["FlattenedJws"]["properties"]["payload"]
                ["x-decoded-schema"]["$ref"],
            json!("#/components/schemas/Evidence")
        );
        assert_eq!(
            document["components"]["schemas"]["EvidenceProtectedHeader"]["properties"]["alg"]
                ["enum"],
            json!(["EdDSA"])
        );

        for path in paths.values() {
            let operation = path
                .as_object()
                .and_then(|operations| operations.values().next())
                .expect("each Version 1 path has one operation");
            for response in operation["responses"]
                .as_object()
                .expect("responses is an object")
                .values()
            {
                assert_eq!(
                    response["headers"]["Cache-Control"]["schema"]["enum"],
                    json!(["no-store"])
                );
            }
        }

        assert_eq!(
            document["paths"]["/v1/evidence"]["post"]["responses"]["401"]["content"]
                ["application/problem+json"]["schema"]["allOf"][1]["properties"]["code"]["enum"],
            json!(["authentication_failed"])
        );
        assert_eq!(
            document["paths"]["/ready"]["get"]["responses"]["503"]["content"]
                ["application/problem+json"]["schema"]["allOf"][1]["properties"]["code"]["enum"],
            json!(["service_unavailable"])
        );
    }

    #[test]
    fn the_served_openapi_document_is_the_generated_release_artifact() {
        let generated = documents().expect("generated contracts build");
        assert_eq!(
            served_openapi_document().expect("served OpenAPI document builds"),
            generated[OPENAPI_FILE]
        );
    }

    #[test]
    fn jws_and_problem_schemas_are_closed() {
        let jws = jws_schema();
        assert_eq!(jws["additionalProperties"], json!(false));
        assert!(jws["properties"].get("header").is_none());

        let problem = problem_schema();
        assert_eq!(problem["additionalProperties"], json!(false));
        assert_eq!(
            problem["properties"].as_object().map(|value| value.len()),
            Some(5)
        );
    }

    #[test]
    fn schemas_accept_the_exact_public_wire_shapes() {
        let cases = [
            (
                request_schema(),
                json!({
                    "requestNonce": "r1N1mq48U3PpZ5keuZEgmA5KMC2KDrF1hT6640koy6I",
                    "requirement": "urn:example:requirement:v1",
                    "purpose": "casework",
                    "subjects": [{
                        "role": "subject",
                        "selector": {"profile": "opaque-v1", "values": {"opaque": "value"}}
                    }]
                }),
            ),
            (
                evidence_schema(),
                json!({
                    "schema": "registry.assertion-evidence/v1",
                    "requestNonce": "r1N1mq48U3PpZ5keuZEgmA5KMC2KDrF1hT6640koy6I",
                    "id": "urn:ulid:01K1EXAMPLE0000000000000000",
                    "type": "Evidence",
                    "supportsRequirement": "urn:example:requirement:v1",
                    "isConformantTo": "urn:example:evidence-type:v1",
                    "issuedBy": "urn:example:issuer",
                    "providedBy": "urn:example:provider",
                    "issuedAt": "2026-08-02T00:00:00Z",
                    "observedAt": "2026-08-02T00:00:00Z",
                    "validUntil": "2026-08-03T00:00:00Z",
                    "purpose": "casework",
                    "audience": "urn:example:audience",
                    "configurationRevision": format!("sha256:{}", "0".repeat(64)),
                    "subjects": [{
                        "role": "subject",
                        "binding": format!("urn:evidence:subject:v1_{}", "a".repeat(43))
                    }],
                    "supportedValues": [{
                        "providesValueFor": "urn:example:concept",
                        "value": true
                    }]
                }),
            ),
            (
                definitions_schema(),
                json!({
                    "schema": "registry.evidence-definitions/v1",
                    "configurationRevision": format!("sha256:{}", "0".repeat(64)),
                    "issuedBy": "urn:example:issuer",
                    "providedBy": "urn:example:provider",
                    "definitions": [{
                        "requirement": "urn:example:requirement:v1",
                        "kind": "criterion",
                        "evidenceType": "urn:example:evidence-type:v1",
                        "purpose": "casework",
                        "referenceFrameworks": ["urn:example:framework:v1"],
                        "subjects": [{
                            "role": "subject",
                            "cardinality": "one",
                            "selector": {
                                "profile": "person-v1",
                                "valueOrigin": "request",
                                "fields": [{
                                    "type": "string",
                                    "name": "record_reference",
                                    "minimumBytes": 1,
                                    "maximumBytes": 96
                                }]
                            }
                        }],
                        "concepts": [{"id": "urn:example:concept", "form": "boolean"}]
                    }]
                }),
            ),
            (
                jws_schema(),
                json!({
                    "protected": "YWxn",
                    "payload": "ZXZpZGVuY2U",
                    "signature": "a".repeat(86)
                }),
            ),
            (
                problem_schema(),
                json!({
                    "type": "https://registrystack.org/problems/evidence/evidence_not_available",
                    "title": "Evidence could not be produced",
                    "status": 422,
                    "code": "evidence_not_available",
                    "operation": "01ARZ3NDEKTSV4RRFFQ69G5FAV"
                }),
            ),
            (
                jwks_schema(),
                json!({"keys": [{
                    "kty": "OKP", "kid": "evidence-key-1", "alg": "EdDSA",
                    "crv": "Ed25519", "x": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }]}),
            ),
        ];

        for (schema, instance) in cases {
            let compiled = JSONSchema::options()
                .with_draft(Draft::Draft202012)
                .should_validate_formats(true)
                .compile(&schema)
                .expect("generated schema compiles");
            assert!(compiled.is_valid(&instance), "instance: {instance}");
        }
    }

    #[test]
    fn problem_schema_rejects_mismatched_code_status_and_title() {
        let schema = problem_schema();
        let compiled = JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .should_validate_formats(true)
            .compile(&schema)
            .expect("problem schema compiles");
        let mismatched = json!({
            "type": "https://registrystack.org/problems/evidence/dependency_unavailable",
            "title": "Request is not valid",
            "status": 400,
            "code": "dependency_unavailable",
            "operation": "01ARZ3NDEKTSV4RRFFQ69G5FAV"
        });
        assert!(!compiled.is_valid(&mismatched));
    }
}
