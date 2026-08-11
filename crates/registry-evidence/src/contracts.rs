//! Deterministic public-contract generation for Evidence Version 1.
//!
//! The generated files are release artifacts. This module is their source,
//! together with the Evidence payload schema the portable
//! `registry-evidence-verifier` crate owns, and deliberately has no dependency
//! on a deployment bundle.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use jsonschema::{Draft, JSONSchema};
use registry_evidence_verifier::contracts::{
    evidence_schema, ContractValidationError, EVIDENCE_SCHEMA_ID, REQUEST_NONCE_PATTERN,
    SCHEMA_DIALECT,
};
use registry_evidence_verifier::model::EvidenceRequestBatchResponse;
use schemars::JsonSchema;
use serde_json::{json, Value};
use thiserror::Error;

use crate::{
    config::MAXIMUM_HOLDER_BOUND_BATCH_SIZE,
    model::{
        Evidence, EvidenceDefinitions, EvidenceRequest, EvidenceRequestBatch, FlattenedJws,
        JwksDocument, ProblemBody, SdJwtVcBatchEnvelope, UnsignedEvidenceEnvelope,
    },
    EVIDENCE_REQUEST_BATCH_MEDIA_TYPE, EVIDENCE_REQUEST_BATCH_SCHEMA_V1,
    EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE, SD_JWT_VC_BATCH_SCHEMA_V1,
};

/// Evidence payload validation belongs to verification, which the portable
/// crate owns. The runtime exercises it from its own tests.
#[cfg(test)]
pub(crate) use registry_evidence_verifier::contracts::evidence_contract_accepts;

pub const OPENAPI_FILE: &str = "registry-evidence.openapi.json";
pub const REQUEST_SCHEMA_FILE: &str = "evidence-request-v1.schema.json";
pub const REQUEST_BATCH_SCHEMA_FILE: &str = "evidence-request-batch-v1.schema.json";
pub const REQUEST_BATCH_RESPONSE_SCHEMA_FILE: &str =
    "evidence-request-batch-response-v1.schema.json";
pub const EVIDENCE_SCHEMA_FILE: &str = "evidence-v1.schema.json";
pub const DEFINITIONS_SCHEMA_FILE: &str = "evidence-definitions-v1.schema.json";
pub const JWS_SCHEMA_FILE: &str = "flattened-jws-v1.schema.json";
pub const UNSIGNED_ENVELOPE_SCHEMA_FILE: &str = "evidence-unsigned-envelope-v1.schema.json";
pub const SD_JWT_VC_BATCH_SCHEMA_FILE: &str = "sd-jwt-vc-batch-envelope-v1.schema.json";
pub const PROBLEM_SCHEMA_FILE: &str = "problem-v1.schema.json";
pub const JWKS_SCHEMA_FILE: &str = "jwks-v1.schema.json";

const REQUEST_SCHEMA_ID: &str = "https://registrystack.org/schemas/evidence/request-v1.json";
const REQUEST_BATCH_SCHEMA_ID: &str =
    "https://registrystack.org/schemas/evidence/request-batch-v1.json";
const REQUEST_BATCH_RESPONSE_SCHEMA_ID: &str =
    "https://registrystack.org/schemas/evidence/request-batch-response-v1.json";
const DEFINITIONS_SCHEMA_ID: &str =
    "https://registrystack.org/schemas/evidence/definitions-v1.json";
const JWS_SCHEMA_ID: &str = "https://registrystack.org/schemas/evidence/flattened-jws-v1.json";
const UNSIGNED_ENVELOPE_SCHEMA_ID: &str =
    "https://registrystack.org/schemas/evidence/unsigned-envelope-v1.json";
const SD_JWT_VC_BATCH_SCHEMA_ID: &str =
    "https://registrystack.org/schemas/evidence/sd-jwt-vc-batch-envelope-v1.json";
const PROBLEM_SCHEMA_ID: &str = "https://registrystack.org/schemas/evidence/problem-v1.json";
const JWKS_SCHEMA_ID: &str = "https://registrystack.org/schemas/evidence/jwks-v1.json";
/// Shape of the server-minted operation identifier, shared by the response
/// header and the problem member so the two cannot describe different values.
const OPERATION_PATTERN: &str = "^[0-9A-HJKMNP-TV-Z]{26}$";
/// Unpadded base64url encoding of exactly one 32-byte P-256 affine coordinate.
const HOLDER_KEY_COORDINATE_PATTERN: &str = "^[A-Za-z0-9_-]{43}$";
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
static REQUEST_BATCH_VALIDATOR: OnceLock<Result<JSONSchema, ContractValidationError>> =
    OnceLock::new();
static DEFINITIONS_VALIDATOR: OnceLock<Result<JSONSchema, ContractValidationError>> =
    OnceLock::new();

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
    let request_batch = request_batch_schema();
    let request_batch_response = request_batch_response_schema();
    let evidence = evidence_schema();
    let definitions = definitions_schema();
    let jws = jws_schema();
    let unsigned = unsigned_envelope_schema();
    let batch = sd_jwt_vc_batch_envelope_schema();
    let problem = problem_schema();
    let jwks = jwks_schema();
    assert_model_shape::<EvidenceRequest>("EvidenceRequest", &request, true)?;
    assert_model_shape::<EvidenceRequestBatch>("EvidenceRequestBatch", &request_batch, true)?;
    assert_model_shape::<EvidenceRequestBatchResponse>(
        "EvidenceRequestBatchResponse",
        &request_batch_response,
        true,
    )?;
    assert_model_shape::<Evidence>("Evidence", &evidence, true)?;
    assert_model_shape::<EvidenceDefinitions>("EvidenceDefinitions", &definitions, true)?;
    assert_model_shape::<FlattenedJws>("FlattenedJws", &jws, false)?;
    assert_model_shape::<UnsignedEvidenceEnvelope>("UnsignedEvidenceEnvelope", &unsigned, false)?;
    assert_model_shape::<SdJwtVcBatchEnvelope>("SdJwtVcBatchEnvelope", &batch, false)?;
    assert_model_shape::<ProblemBody>("ProblemBody", &problem, false)?;
    assert_model_shape::<JwksDocument>("JwksDocument", &jwks, false)?;
    let openapi = openapi_document(
        &request,
        &request_batch,
        &request_batch_response,
        &evidence,
        &definitions,
        &jws,
        &unsigned,
        &batch,
        &problem,
        &jwks,
    );

    let values = [
        (REQUEST_SCHEMA_FILE, request),
        (REQUEST_BATCH_SCHEMA_FILE, request_batch),
        (REQUEST_BATCH_RESPONSE_SCHEMA_FILE, request_batch_response),
        (EVIDENCE_SCHEMA_FILE, evidence),
        (DEFINITIONS_SCHEMA_FILE, definitions),
        (JWS_SCHEMA_FILE, jws),
        (UNSIGNED_ENVELOPE_SCHEMA_FILE, unsigned),
        (SD_JWT_VC_BATCH_SCHEMA_FILE, batch),
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
                &request_batch_schema(),
                &request_batch_response_schema(),
                &evidence_schema(),
                &definitions_schema(),
                &jws_schema(),
                &unsigned_envelope_schema(),
                &sd_jwt_vc_batch_envelope_schema(),
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

/// Validate an inbound multi-subject request batch against the exact generated
/// Version 1 schema. Named selector-profile and nonce-canonicality checks still
/// follow this structural boundary in the runtime.
pub(crate) fn request_batch_contract_accepts(
    value: &Value,
) -> Result<bool, ContractValidationError> {
    contract_validator(&REQUEST_BATCH_VALIDATOR, request_batch_schema)
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
            },
            "holderKeys": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAXIMUM_HOLDER_BOUND_BATCH_SIZE,
                "items": {"$ref": "#/$defs/holder-key"}
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
            },
            "holder-key": {
                "type": "object", "additionalProperties": false,
                "required": ["kty", "crv", "x", "y"],
                "properties": {
                    "kty": {"type": "string", "enum": ["EC"]},
                    "crv": {"type": "string", "enum": ["P-256"]},
                    "x": {"type": "string", "pattern": HOLDER_KEY_COORDINATE_PATTERN},
                    "y": {"type": "string", "pattern": HOLDER_KEY_COORDINATE_PATTERN},
                    "alg": {"type": "string", "enum": ["ES256"]},
                    "kid": {"type": "string", "minLength": 1, "maxLength": 256}
                }
            }
        },
        "$comment": "Named selector-profile validation follows this transport schema. The profile closes exact field names, scalar types, bounds, aggregate size, value origin, and source placements. Invalid selector material fails before credential acquisition or source access. requestNonce is the canonical unpadded base64url encoding of exactly 32 independently generated random bytes; a noncanonical final symbol is rejected by the runtime. Callers must not encode identifiers, selectors, secrets, or document digests into it. holderKeys is meaningful only to the credential response formats, where each key is echoed into the cnf claim of the credential issued for it; a single-credential request is an array of one. The keys never reach Rhai, source requests, or audit, and a key carrying any private member, a repeated RFC 7638 thumbprint, or a batch above the deployment's declared ceiling is rejected before credential acquisition or source access. Under a holder-bound requirement each key's thumbprint additionally scopes the subject binding of that key's own credential."
    })
}

fn request_batch_schema() -> Value {
    json!({
        "$schema": SCHEMA_DIALECT,
        "$id": REQUEST_BATCH_SCHEMA_ID,
        "title": "Evidence multi-subject request batch Version 1",
        "type": "object",
        "additionalProperties": false,
        "required": ["requirement", "purpose", "items"],
        "properties": {
            "requirement": {"type": "string", "format": "uri", "minLength": 1, "maxLength": 512},
            "purpose": {"type": "string", "pattern": "^[a-z][a-z0-9._:-]{0,127}$"},
            "items": {
                "type": "array",
                "minItems": 1,
                "maxItems": 16,
                "items": {"$ref": "#/$defs/item"}
            }
        },
        "$defs": {
            "item": {
                "type": "object",
                "additionalProperties": false,
                "required": ["requestNonce", "subjects"],
                "properties": {
                    "requestNonce": {"type": "string", "pattern": REQUEST_NONCE_PATTERN},
                    "subjects": {
                        "type": "array", "minItems": 1, "maxItems": 8,
                        "items": {"$ref": "#/$defs/subject"}
                    }
                }
            },
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
        "$comment": "Named selector-profile validation follows independently for every item. Every request nonce is the canonical unpadded base64url encoding of exactly 32 independently generated random bytes, and all nonces in one batch are pairwise distinct. Invalid or repeated nonce and selector material fails the outer request before source access. The authenticated access token supplies the audience common to all items. holderKeys is absent because holder-bound issuance batching remains a separate profile on POST /v1/evidence."
    })
}

fn request_batch_response_schema() -> Value {
    json!({
        "$schema": SCHEMA_DIALECT,
        "$id": REQUEST_BATCH_RESPONSE_SCHEMA_ID,
        "title": "Evidence multi-subject request batch response Version 1",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema", "type", "items"],
        "properties": {
            "schema": {"const": EVIDENCE_REQUEST_BATCH_SCHEMA_V1},
            "type": {"const": "EvidenceRequestBatchResponse"},
            "items": {
                "type": "array", "minItems": 1, "maxItems": 16,
                "items": {
                    "oneOf": [
                        {"$ref": "#/$defs/evidence-result"},
                        {"$ref": "#/$defs/unavailable-result"}
                    ]
                }
            }
        },
        "$defs": {
            "evidence-result": {
                "type": "object", "additionalProperties": false,
                "required": ["result", "evidence"],
                "properties": {
                    "result": {"const": "evidence"},
                    "evidence": {"$ref": "#/$defs/flattened-jws"}
                }
            },
            "unavailable-result": {
                "type": "object", "additionalProperties": false,
                "required": ["result"],
                "properties": {"result": {"const": "evidence_not_available"}}
            },
            "flattened-jws": {
                "type": "object", "additionalProperties": false,
                "required": ["protected", "payload", "signature"],
                "properties": {
                    "protected": {"type": "string", "minLength": 1, "pattern": "^[A-Za-z0-9_-]+$"},
                    "payload": {"type": "string", "minLength": 1, "pattern": "^[A-Za-z0-9_-]+$"},
                    "signature": {"type": "string", "pattern": "^[A-Za-z0-9_-]{86}$"}
                }
            }
        },
        "$comment": "Results are positional and one-for-one with the request. Available members are ordinary signed flattened JWS responses. Singular unavailable conditions become evidence_not_available. Mixed and all-unavailable envelopes return HTTP 200. Every other failure aborts the outer request, and a response above 1048576 serialized bytes is never released."
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
            "schema", "assuranceProfile", "issuedBy", "providedBy",
            "holderBoundBatchMaxSize", "definitions"
        ],
        "properties": {
            "schema": {"const": "registry.evidence-definitions/v1"},
            "assuranceProfile": {"enum": ["local", "production", "evidence-grade"]},
            "issuedBy": {"type": "string", "format": "uri", "maxLength": 512},
            "providedBy": {"type": "string", "format": "uri", "maxLength": 512},
            "holderBoundBatchMaxSize": {
                "description": "The effective deployment ceiling for one holder-bound batch. A protocol adapter may advertise no larger batch than this value.",
                "type": "integer", "minimum": 1, "maximum": MAXIMUM_HOLDER_BOUND_BATCH_SIZE
            },
            "definitions": {
                "type": "array", "maxItems": 16384, "uniqueItems": true,
                "items": {"$ref": "#/$defs/definition"}
            }
        },
        "$defs": {
            "definition": {
                "type": "object", "additionalProperties": false,
                "required": [
                    "requirement", "configurationRevision", "kind", "evidenceType", "purpose",
                    "referenceFrameworks", "subjects", "concepts"
                ],
                "properties": {
                    "requirement": {"type": "string", "format": "uri", "maxLength": 512},
                    "configurationRevision": {"type": "string", "pattern": "^sha256:[a-f0-9]{64}$"},
                    "kind": {"enum": ["criterion", "information-requirement", "constraint"]},
                    "subjectBindingMode": {
                        "description": "What the subject bindings in this requirement's assertions are derived under. The vocabulary is closed and carries no default: absence means audience-scoped, stated here so a relying party reading a definition without the key knows the requirement issues audience-scoped assertions and is not reading an omission it has to resolve elsewhere. A definition that does carry the key states the mode explicitly.",
                        "enum": ["audience-scoped", "holder-bound"]
                    },
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
        "$comment": "Flattened JWS JSON Serialization. The protected header has exactly alg=ES256, an RFC 7638 thumbprint kid, typ=evidence+jws, and cty=application/evidence+json. The payload is the base64url encoding without padding of exact UTF-8 Evidence JSON bytes."
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

fn sd_jwt_vc_batch_envelope_schema() -> Value {
    json!({
        "$schema": SCHEMA_DIALECT,
        "$id": SD_JWT_VC_BATCH_SCHEMA_ID,
        "title": "Evidence SD-JWT VC batch issuance envelope Version 1",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema", "type", "credentials"],
        "properties": {
            "schema": {"const": SD_JWT_VC_BATCH_SCHEMA_V1},
            "type": {"const": "SdJwtVcBatchEnvelope"},
            "credentials": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAXIMUM_HOLDER_BOUND_BATCH_SIZE,
                "items": {"type": "string", "minLength": 1}
            }
        },
        "$comment": "Issuance container selected only by its exact vendor media type, carrying one combined SD-JWT VC issuance serialization per presented holder key in the order the keys were presented. It is issuance-only: nothing consumes it at verification, and each member is verified individually as an ordinary holder-bound credential. Members share an issuance timestamp, purpose, requirement, Evidence Type, configuration revision, and disclosed values, so the container reduces deterministic key-based linkability without making its members unlinkable. A failure on any member releases nothing; there is no partial batch."
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
            "operation": {"type": "string", "pattern": OPERATION_PATTERN}
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
                "items": {"$ref": "#/$defs/p256-public-jwk"}
            }
        },
        "$defs": {
            "p256-public-jwk": {
                "type": "object", "additionalProperties": false,
                "required": ["kty", "kid", "alg", "crv", "x", "y"],
                "properties": {
                    "kty": {"const": "EC"},
                    "kid": {"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$"},
                    "alg": {"const": "ES256"},
                    "crv": {"const": "P-256"},
                    "x": {"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$"},
                    "y": {"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$"}
                }
            }
        },
        "$comment": "Only the governed active and published non-revoked P-256 keys are returned. Each kid is the key's RFC 7638 SHA-256 thumbprint. Discovery is not a trust anchor; verifiers pin the governed provider and JWKS location."
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
    headers.insert(
        "X-Request-Id".to_string(),
        json!({
            "description": "Server-minted operation identifier for this request. It is generated by Evidence, never taken from the caller, and is the identifier a caller quotes to an operator. Problem responses repeat it in the operation member.",
            "schema": {"type": "string", "pattern": OPERATION_PATTERN}
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
    request_batch: &Value,
    request_batch_response: &Value,
    evidence: &Value,
    definitions: &Value,
    jws: &Value,
    unsigned: &Value,
    batch: &Value,
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
            ("holder-key", "HolderPublicKey"),
        ],
    );
    insert_schema_family(
        &mut schemas,
        "EvidenceRequestBatch",
        request_batch,
        &[
            ("item", "EvidenceRequestBatchItem"),
            ("subject", "EvidenceRequestBatchSubject"),
            ("selector", "EvidenceRequestBatchSelector"),
            ("scalar-selector-value", "EvidenceRequestBatchSelectorValue"),
        ],
    );
    insert_schema_family(
        &mut schemas,
        "EvidenceRequestBatchResponse",
        request_batch_response,
        &[
            ("evidence-result", "EvidenceRequestBatchEvidenceResult"),
            (
                "unavailable-result",
                "EvidenceRequestBatchUnavailableResult",
            ),
            ("flattened-jws", "FlattenedJws"),
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
    if let Some(reference) = schemas
        .get_mut("SdJwtVcBatchEnvelope")
        .and_then(Value::as_object_mut)
        .and_then(|schema| schema.get_mut("properties"))
        .and_then(Value::as_object_mut)
        .and_then(|properties| properties.get_mut("credentials"))
        .and_then(Value::as_object_mut)
        .and_then(|credentials| credentials.get_mut("items"))
        .and_then(Value::as_object_mut)
    {
        reference.clear();
        reference.insert(
            "$ref".to_string(),
            Value::String("#/components/schemas/SdJwtVcCredential".to_string()),
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
                "alg": {"type": "string", "enum": ["ES256"]},
                "kid": {"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$"},
                "typ": {"type": "string", "enum": ["evidence+jws"]},
                "cty": {"type": "string", "enum": ["application/evidence+json"]}
            }
        }),
    );
    insert_schema_family(&mut schemas, "SdJwtVcBatchEnvelope", batch, &[]);
    insert_schema_family(&mut schemas, "Problem", problem, &[]);
    insert_schema_family(
        &mut schemas,
        "JwksDocument",
        jwks,
        &[("p256-public-jwk", "P256PublicJwk")],
    );
    schemas.insert(
        "SdJwtVcCredential".to_string(),
        json!({
            "type": "string",
            "description": "Compact SD-JWT VC: the issuer-signed JWT, then the root-value and configured structured-field disclosures, then a trailing tilde marking an absent key-binding JWT. The issuer never appends a key-binding JWT.",
            "pattern": "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+(~[A-Za-z0-9_-]+)*~$"
        }),
    );
    schemas.insert(
        "JwtVcIssuerMetadata".to_string(),
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["issuer", "jwks_uri"],
            "properties": {
                "issuer": {"type": "string", "maxLength": 512},
                "jwks_uri": {"type": "string", "format": "uri", "maxLength": 1024}
            }
        }),
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
                    "description": "Missing Accept, */*, and the exact application/jose+json media type select the default signed flattened JWS. Only the exact application/vnd.registrystack.evidence-unsigned+json media type selects the unsigned envelope, only the exact application/dc+sd-jwt media type selects the SD-JWT VC serialization of the same assertion, and only the exact application/vnd.registrystack.evidence.batch+json media type selects the holder-bound batch issuance envelope carrying one credential per presented holder key; each is released only when the immutable bundle, the complete matched authority grant, and the requirement's subject binding mode all permit it. Duplicate, combined, parameterized, weighted, or unknown negotiation returns 406 before source access.",
                    "security": [{"bearerAuth": []}],
                    "requestBody": {
                        "required": true,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/EvidenceRequest"}}}
                    },
                    "responses": {
                        "200": {
                            "description": "Signed Evidence as flattened JWS JSON Serialization by default, or the explicitly authorized SD-JWT VC serialization, holder-bound batch issuance envelope, or self-identifying unsigned envelope",
                            "headers": evidence_response_headers(None),
                            "content": {
                                "application/jose+json": {"schema": {"$ref": "#/components/schemas/FlattenedJws"}},
                                "application/dc+sd-jwt": {"schema": {"$ref": "#/components/schemas/SdJwtVcCredential"}},
                                EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE: {"schema": {"$ref": "#/components/schemas/SdJwtVcBatchEnvelope"}},
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
            "/v1/evidence/batch": {
                "post": {
                    "operationId": "createEvidenceRequestBatch",
                    "summary": "Produce ordered evidence outcomes for several subjects",
                    "description": "The exact application/vnd.registrystack.evidence.request-batch+json Accept value selects this signed-JWS-only operation. The request carries one common requirement and purpose and between one and sixteen ordered subject items. The authenticated token supplies the common audience. Every item is validated and authorized before source access, and rate admission costs the complete item count atomically. Singular unavailable outcomes appear positionally inside a 200 response. Any other failure aborts the complete request. The serialized response is limited to 1048576 bytes and is released only after one durable terminal audit event.",
                    "security": [{"bearerAuth": []}],
                    "requestBody": {
                        "required": true,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/EvidenceRequestBatch"}}}
                    },
                    "responses": {
                        "200": {
                            "description": "One ordered signed-evidence or evidence-not-available result per request item",
                            "headers": evidence_response_headers(None),
                            "content": {
                                EVIDENCE_REQUEST_BATCH_MEDIA_TYPE: {"schema": {"$ref": "#/components/schemas/EvidenceRequestBatchResponse"}}
                            }
                        },
                        "400": {
                            "description": "Malformed batch request or invalid selector",
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
                            "description": "At least one batch item is not authorized for signed audience-scoped evidence",
                            "headers": evidence_response_headers(None),
                            "content": problem_content(&["not_authorized"])
                        },
                        "406": {
                            "description": "The exact request-batch response media type was not selected",
                            "headers": evidence_response_headers(None),
                            "content": problem_content(&["response_format_not_acceptable"])
                        },
                        "429": {
                            "description": "Atomic item-count rate admission was refused",
                            "headers": evidence_response_headers(Some(("Retry-After", json!({
                                "schema": {"type": "string", "enum": ["1"]}
                            })))),
                            "content": problem_content(&["rate_limited"])
                        },
                        "503": {
                            "description": "A dependency, protocol, signing, serialization, or audit failure aborted the complete request",
                            "headers": evidence_response_headers(None),
                            "content": problem_content(&["dependency_unavailable", "service_unavailable"])
                        }
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
            },
            "/.well-known/jwt-vc-issuer": {
                "get": {
                    "operationId": "getJwtVcIssuerMetadata",
                    "summary": "Publish JWT VC Issuer Metadata for the SD-JWT VC response format",
                    "description": "Discovery is not a trust anchor. The document republishes the same public keys under the provider identity the assertion names, and resolution is meaningful only when that identity is the HTTPS origin of the deployment.",
                    "responses": {"200": {
                        "description": "Provider identity and public verification keys",
                        "headers": response_headers(None),
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/JwtVcIssuerMetadata"}}}
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
            request_batch_schema(),
            request_batch_response_schema(),
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
    fn definitions_v1_intentionally_requires_the_bounded_holder_batch_ceiling() {
        let schema = definitions_schema();
        assert_eq!(schema["$id"], DEFINITIONS_SCHEMA_ID);
        assert!(schema["required"]
            .as_array()
            .expect("definitions required members are an array")
            .iter()
            .any(|member| member == "holderBoundBatchMaxSize"));
        assert_eq!(
            schema["properties"]["holderBoundBatchMaxSize"]["minimum"],
            json!(1)
        );
        assert_eq!(
            schema["properties"]["holderBoundBatchMaxSize"]["maximum"],
            json!(MAXIMUM_HOLDER_BOUND_BATCH_SIZE)
        );

        let compiled = JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .should_validate_formats(true)
            .compile(&schema)
            .expect("definitions schema compiles");
        let mut document = json!({
            "schema": "registry.evidence-definitions/v1",
            "assuranceProfile": "local",
            "issuedBy": "urn:example:issuer",
            "providedBy": "urn:example:provider",
            "holderBoundBatchMaxSize": 1,
            "definitions": []
        });
        assert!(compiled.is_valid(&document));
        document
            .as_object_mut()
            .expect("definitions document is an object")
            .remove("holderBoundBatchMaxSize");
        assert!(
            !compiled.is_valid(&document),
            "the retained v1 identity intentionally has a new required member"
        );
        document["holderBoundBatchMaxSize"] = json!(17);
        assert!(!compiled.is_valid(&document));
    }

    #[test]
    fn openapi_document_is_valid_utoipa_model() {
        let document = openapi_document(
            &request_schema(),
            &request_batch_schema(),
            &request_batch_response_schema(),
            &evidence_schema(),
            &definitions_schema(),
            &jws_schema(),
            &unsigned_envelope_schema(),
            &sd_jwt_vc_batch_envelope_schema(),
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
            &request_batch_schema(),
            &request_batch_response_schema(),
            &evidence_schema(),
            &definitions_schema(),
            &jws_schema(),
            &unsigned_envelope_schema(),
            &sd_jwt_vc_batch_envelope_schema(),
            &problem_schema(),
            &jwks_schema(),
        );
        let paths = document["paths"].as_object().expect("paths is an object");
        assert_eq!(
            paths.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "/.well-known/evidence/jwks.json",
                "/.well-known/jwt-vc-issuer",
                "/health",
                "/openapi.json",
                "/ready",
                "/v1/evidence",
                "/v1/evidence-definitions",
                "/v1/evidence/batch"
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
        assert!(
            document["paths"]["/v1/evidence"]["post"]["responses"]["200"]["content"]
                ["application/dc+sd-jwt"]
                .is_object()
        );
        assert_eq!(
            document["paths"]["/v1/evidence/batch"]["post"]["responses"]
                .as_object()
                .expect("request-batch responses are an object")
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["200", "400", "401", "403", "406", "429", "503"]
        );
        assert!(
            document["paths"]["/v1/evidence/batch"]["post"]["responses"]["200"]["content"]
                [EVIDENCE_REQUEST_BATCH_MEDIA_TYPE]
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
        assert!(
            document["paths"]["/.well-known/jwt-vc-issuer"]["get"]["responses"]["200"]["content"]
                ["application/json"]
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
            json!(["ES256"])
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
                request_batch_schema(),
                json!({
                    "requirement": "urn:example:requirement:v1",
                    "purpose": "casework",
                    "items": [
                        {
                            "requestNonce": "r1N1mq48U3PpZ5keuZEgmA5KMC2KDrF1hT6640koy6I",
                            "subjects": [{
                                "role": "subject",
                                "selector": {"profile": "opaque-v1", "values": {"opaque": "one"}}
                            }]
                        },
                        {
                            "requestNonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                            "subjects": [{
                                "role": "subject",
                                "selector": {"profile": "opaque-v1", "values": {"opaque": "two"}}
                            }]
                        }
                    ]
                }),
            ),
            (
                request_batch_response_schema(),
                json!({
                    "schema": EVIDENCE_REQUEST_BATCH_SCHEMA_V1,
                    "type": "EvidenceRequestBatchResponse",
                    "items": [
                        {
                            "result": "evidence",
                            "evidence": {
                                "protected": "YWxn",
                                "payload": "ZXZpZGVuY2U",
                                "signature": "a".repeat(86)
                            }
                        },
                        {"result": "evidence_not_available"}
                    ]
                }),
            ),
            (
                evidence_schema(),
                json!({
                    "schema": "registry.assertion-evidence/v1",
                    "assuranceProfile": "evidence-grade",
                    "subjectBinding": "audience-scoped",
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
                    "assuranceProfile": "evidence-grade",
                    "issuedBy": "urn:example:issuer",
                    "providedBy": "urn:example:provider",
                    "holderBoundBatchMaxSize": 4,
                    "definitions": [{
                        "requirement": "urn:example:requirement:v1",
                        "configurationRevision": format!("sha256:{}", "0".repeat(64)),
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
                    "kty": "EC", "kid": "_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo", "alg": "ES256",
                    "crv": "P-256", "x": "3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4",
                    "y": "GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU"
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
