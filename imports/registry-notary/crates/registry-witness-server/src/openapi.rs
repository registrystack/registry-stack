// SPDX-License-Identifier: Apache-2.0
//! Registry Witness OpenAPI document generation.

use registry_witness_core::model::{
    BatchEvaluateRequest, CredentialIssueRequest, EvaluateRequest, HolderRequest, RenderRequest,
    SubjectRequest,
};
use serde_json::{json, Value};
use std::sync::OnceLock;
use utoipa::openapi::OpenApi;
use utoipa::PartialSchema;

#[must_use]
pub fn openapi_document() -> OpenApi {
    static DOCUMENT: OnceLock<OpenApi> = OnceLock::new();

    DOCUMENT.get_or_init(build_openapi_document).clone()
}

fn build_openapi_document() -> OpenApi {
    let mut raw_document = json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Registry Witness API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Standalone claim evaluation, rendering, and credential issuance API.",
            "license": {
                "name": env!("CARGO_PKG_LICENSE"),
                "identifier": env!("CARGO_PKG_LICENSE")
            }
        },
        "security": [
            { "apiKeyAuth": [] },
            { "bearerAuth": [] }
        ],
        "paths": {
            "/healthz": {
                "get": {
                    "summary": "Return the liveness probe",
                    "operationId": "getHealthz",
                    "security": [],
                    "responses": {
                        "200": { "description": "Service process is alive" },
                        "4XX": { "description": "Client error" }
                    }
                }
            },
            "/ready": {
                "get": {
                    "summary": "Return the readiness probe",
                    "operationId": "getReady",
                    "security": [],
                    "responses": {
                        "200": { "description": "Evidence runtime is ready" },
                        "4XX": { "description": "Client error" },
                        "503": { "description": "Evidence runtime is not ready" }
                    }
                }
            },
            "/admin/reload": {
                "post": {
                    "summary": "Request a standalone config reload",
                    "operationId": "adminReload",
                    "responses": {
                        "200": { "description": "Standalone router accepted the reload request" },
                        "401": { "description": "Missing or invalid credential" },
                        "403": { "description": "Caller lacks registry_witness:admin scope" }
                    }
                }
            },
            "/openapi.json": {
                "get": {
                    "summary": "Fetch this OpenAPI document",
                    "operationId": "getOpenApi",
                    "responses": {
                        "200": { "description": "OpenAPI document" },
                        "401": { "description": "Missing or invalid credential" }
                    }
                }
            },
            "/.well-known/evidence-service": {
                "get": {
                    "summary": "Discover Registry Witness capabilities",
                    "operationId": "getEvidenceService",
                    "responses": {
                        "200": { "description": "Service document" },
                        "401": { "description": "Missing or invalid credential" }
                    }
                }
            },
            "/.well-known/evidence/jwks.json": {
                "get": {
                    "summary": "Fetch public issuer verification keys",
                    "operationId": "getEvidenceJwks",
                    "responses": {
                        "200": { "description": "Public JWKS" },
                        "401": { "description": "Missing or invalid credential" }
                    }
                }
            },
            "/claims": {
                "get": {
                    "summary": "List claims visible to the caller",
                    "operationId": "listClaims",
                    "responses": {
                        "200": { "description": "Visible claims" },
                        "401": { "description": "Missing or invalid credential" }
                    }
                }
            },
            "/claims/{claim_id}": {
                "get": {
                    "summary": "Get one claim definition",
                    "operationId": "getClaim",
                    "parameters": [
                        {
                            "name": "claim_id",
                            "in": "path",
                            "required": true,
                            "schema": { "type": "string" }
                        }
                    ],
                    "responses": {
                        "200": { "description": "Claim definition" },
                        "401": { "description": "Missing or invalid credential" },
                        "404": { "description": "Claim not found" }
                    }
                }
            },
            "/formats": {
                "get": {
                    "summary": "List supported output formats",
                    "operationId": "listFormats",
                    "responses": {
                        "200": { "description": "Supported formats" },
                        "401": { "description": "Missing or invalid credential" }
                    }
                }
            },
            "/claims/evaluate": {
                "post": {
                    "summary": "Evaluate claims for one subject",
                    "operationId": "evaluateClaims",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/EvaluateRequest" }
                            }
                        }
                    },
                    "responses": {
                        "200": { "description": "Claim evaluation result" },
                        "400": { "description": "Invalid request" },
                        "401": { "description": "Missing or invalid credential" },
                        "403": { "description": "Not authorized for requested claim, purpose, disclosure, or format" }
                    }
                }
            },
            "/claims/batch-evaluate": {
                "post": {
                    "summary": "Evaluate claims for multiple subjects inline",
                    "operationId": "batchEvaluateClaims",
                    "parameters": [
                        {
                            "name": "Idempotency-Key",
                            "in": "header",
                            "required": false,
                            "schema": { "type": "string" }
                        }
                    ],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/BatchEvaluateRequest" }
                            }
                        }
                    },
                    "responses": {
                        "200": { "description": "Per-subject claim evaluation results" },
                        "400": { "description": "Invalid request" },
                        "401": { "description": "Missing or invalid credential" },
                        "403": { "description": "Not authorized for requested claim, purpose, disclosure, or format" }
                    }
                }
            },
            "/evidence/render": {
                "post": {
                    "summary": "Render a stored evaluation",
                    "operationId": "renderEvidence",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/RenderRequest" }
                            }
                        }
                    },
                    "responses": {
                        "200": { "description": "Rendered evidence artifact" },
                        "400": { "description": "Invalid request or disclosure widening attempt" },
                        "401": { "description": "Missing or invalid credential" },
                        "404": { "description": "Evaluation not found" }
                    }
                }
            },
            "/credentials/issue": {
                "post": {
                    "summary": "Issue a credential from a stored evaluation",
                    "operationId": "issueCredential",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/CredentialIssueRequest" }
                            }
                        }
                    },
                    "responses": {
                        "200": { "description": "Issued credential" },
                        "400": { "description": "Invalid request or disclosure widening attempt" },
                        "401": { "description": "Missing or invalid credential" },
                        "404": { "description": "Evaluation not found" }
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "ProblemDetails": problem_details_schema()
            },
            "securitySchemes": {
                "apiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "x-api-key"
                },
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer"
                }
            }
        }
    });
    add_response_examples(&mut raw_document);

    let mut document: OpenApi = serde_json::from_value(raw_document)
        .expect("static Registry Witness OpenAPI document is valid");

    let components = document
        .components
        .get_or_insert_with(utoipa::openapi::Components::new);
    components
        .schemas
        .insert("SubjectRequest".to_string(), SubjectRequest::schema());
    components
        .schemas
        .insert("EvaluateRequest".to_string(), EvaluateRequest::schema());
    components.schemas.insert(
        "BatchEvaluateRequest".to_string(),
        BatchEvaluateRequest::schema(),
    );
    components
        .schemas
        .insert("RenderRequest".to_string(), RenderRequest::schema());
    components.schemas.insert(
        "CredentialIssueRequest".to_string(),
        CredentialIssueRequest::schema(),
    );
    components
        .schemas
        .insert("HolderRequest".to_string(), HolderRequest::schema());

    document
}

fn add_response_examples(document: &mut Value) {
    set_json_response(
        document,
        "/healthz",
        "get",
        "200",
        "Service process is alive",
        json!({
            "status": "ok",
            "checks": {
                "total": 1,
                "ok": 1,
                "failed": 0
            }
        }),
    );
    set_problem_response(
        document,
        "/healthz",
        "get",
        "4XX",
        "Client error",
        problem_example(
            400,
            "request.invalid",
            "Invalid evidence request",
            "the evidence request is invalid",
        ),
    );
    set_json_response(
        document,
        "/ready",
        "get",
        "200",
        "Evidence runtime is ready",
        json!({
            "status": "ready",
            "checks": {
                "total": 1,
                "ok": 1,
                "failed": 0
            }
        }),
    );
    set_problem_response(
        document,
        "/ready",
        "get",
        "4XX",
        "Client error",
        problem_example(
            400,
            "request.invalid",
            "Invalid evidence request",
            "the evidence request is invalid",
        ),
    );
    set_json_response(
        document,
        "/ready",
        "get",
        "503",
        "Evidence runtime is not ready",
        json!({
            "status": "not_ready",
            "checks": {
                "total": 1,
                "ok": 0,
                "failed": 1
            }
        }),
    );
    set_json_response(
        document,
        "/admin/reload",
        "post",
        "200",
        "Standalone router accepted the reload request",
        json!({
            "reloaded": false,
            "status": "noop",
            "detail": "standalone router has no reloadable external config handle"
        }),
    );
    set_problem_response(
        document,
        "/admin/reload",
        "post",
        "401",
        "Missing or invalid credential",
        missing_credential_example(),
    );
    set_problem_response(
        document,
        "/admin/reload",
        "post",
        "403",
        "Caller lacks registry_witness:admin scope",
        problem_example(
            403,
            "auth.scope_denied",
            "Scope denied",
            "missing required scope",
        ),
    );
    set_json_response(
        document,
        "/openapi.json",
        "get",
        "200",
        "OpenAPI document",
        json!({
            "openapi": "3.1.0",
            "info": {
                "title": "Registry Witness API",
                "version": env!("CARGO_PKG_VERSION")
            },
            "paths": {
                "/claims/evaluate": {}
            }
        }),
    );
    set_problem_response(
        document,
        "/openapi.json",
        "get",
        "401",
        "Missing or invalid credential",
        missing_credential_example(),
    );
    set_json_response(
        document,
        "/.well-known/evidence-service",
        "get",
        "200",
        "Service document",
        discovery_example(),
    );
    set_problem_response(
        document,
        "/.well-known/evidence-service",
        "get",
        "401",
        "Missing or invalid credential",
        missing_credential_example(),
    );
    set_json_response(
        document,
        "/.well-known/evidence/jwks.json",
        "get",
        "200",
        "Public JWKS",
        jwks_example(),
    );
    set_problem_response(
        document,
        "/.well-known/evidence/jwks.json",
        "get",
        "401",
        "Missing or invalid credential",
        missing_credential_example(),
    );
    set_json_response(
        document,
        "/claims",
        "get",
        "200",
        "Visible claims",
        claims_list_example(),
    );
    set_problem_response(
        document,
        "/claims",
        "get",
        "401",
        "Missing or invalid credential",
        missing_credential_example(),
    );
    set_json_response(
        document,
        "/claims/{claim_id}",
        "get",
        "200",
        "Claim definition",
        farmer_under_4ha_claim_example(),
    );
    set_problem_response(
        document,
        "/claims/{claim_id}",
        "get",
        "401",
        "Missing or invalid credential",
        missing_credential_example(),
    );
    set_problem_response(
        document,
        "/claims/{claim_id}",
        "get",
        "404",
        "Claim not found",
        problem_example(
            404,
            "claim.not_found",
            "Claim not found",
            "the requested claim is not available",
        ),
    );
    set_json_response(
        document,
        "/formats",
        "get",
        "200",
        "Supported formats",
        formats_example(),
    );
    set_problem_response(
        document,
        "/formats",
        "get",
        "401",
        "Missing or invalid credential",
        missing_credential_example(),
    );
    set_json_response(
        document,
        "/claims/evaluate",
        "post",
        "200",
        "Claim evaluation result",
        evaluate_example(),
    );
    set_problem_response(
        document,
        "/claims/evaluate",
        "post",
        "400",
        "Invalid request",
        problem_example(
            400,
            "request.invalid",
            "Invalid evidence request",
            "the evidence request is invalid",
        ),
    );
    set_problem_response(
        document,
        "/claims/evaluate",
        "post",
        "401",
        "Missing or invalid credential",
        missing_credential_example(),
    );
    set_problem_response(
        document,
        "/claims/evaluate",
        "post",
        "403",
        "Not authorized for requested claim, purpose, disclosure, or format",
        problem_example(
            403,
            "auth.scope_denied",
            "Scope denied",
            "missing required scope",
        ),
    );
    set_json_response(
        document,
        "/claims/batch-evaluate",
        "post",
        "200",
        "Per-subject claim evaluation results",
        batch_evaluate_example(),
    );
    set_problem_response(
        document,
        "/claims/batch-evaluate",
        "post",
        "400",
        "Invalid request",
        problem_example(
            400,
            "request.invalid",
            "Invalid evidence request",
            "the evidence request is invalid",
        ),
    );
    set_problem_response(
        document,
        "/claims/batch-evaluate",
        "post",
        "401",
        "Missing or invalid credential",
        missing_credential_example(),
    );
    set_problem_response(
        document,
        "/claims/batch-evaluate",
        "post",
        "403",
        "Not authorized for requested claim, purpose, disclosure, or format",
        problem_example(
            403,
            "claim.disclosure_not_allowed",
            "Disclosure not allowed",
            "the requested disclosure profile is not allowed",
        ),
    );
    set_json_response(
        document,
        "/evidence/render",
        "post",
        "200",
        "Rendered evidence artifact",
        render_example(),
    );
    set_problem_response(
        document,
        "/evidence/render",
        "post",
        "400",
        "Invalid request or disclosure widening attempt",
        problem_example(
            400,
            "request.invalid",
            "Invalid evidence request",
            "the evidence request is invalid",
        ),
    );
    set_problem_response(
        document,
        "/evidence/render",
        "post",
        "401",
        "Missing or invalid credential",
        missing_credential_example(),
    );
    set_problem_response(
        document,
        "/evidence/render",
        "post",
        "404",
        "Evaluation not found",
        evaluation_not_found_example(),
    );
    set_json_response(
        document,
        "/credentials/issue",
        "post",
        "200",
        "Issued credential",
        credential_issue_example(),
    );
    set_problem_response(
        document,
        "/credentials/issue",
        "post",
        "400",
        "Invalid request or disclosure widening attempt",
        problem_example(
            400,
            "credential.holder_proof_required",
            "Holder proof required",
            "holder proof of possession is required",
        ),
    );
    set_problem_response(
        document,
        "/credentials/issue",
        "post",
        "401",
        "Missing or invalid credential",
        missing_credential_example(),
    );
    set_problem_response(
        document,
        "/credentials/issue",
        "post",
        "404",
        "Evaluation not found",
        evaluation_not_found_example(),
    );
}

fn set_json_response(
    document: &mut Value,
    path: &str,
    method: &str,
    status: &str,
    description: &str,
    example: Value,
) {
    set_response_example(
        document,
        path,
        method,
        status,
        description,
        "application/json",
        example,
    );
}

fn set_problem_response(
    document: &mut Value,
    path: &str,
    method: &str,
    status: &str,
    description: &str,
    example: Value,
) {
    set_response_example(
        document,
        path,
        method,
        status,
        description,
        "application/problem+json",
        example,
    );
}

fn set_response_example(
    document: &mut Value,
    path: &str,
    method: &str,
    status: &str,
    description: &str,
    content_type: &str,
    example: Value,
) {
    let Some(response) = document
        .get_mut("paths")
        .and_then(Value::as_object_mut)
        .and_then(|paths| paths.get_mut(path))
        .and_then(Value::as_object_mut)
        .and_then(|path_item| path_item.get_mut(method))
        .and_then(Value::as_object_mut)
        .and_then(|operation| operation.get_mut("responses"))
        .and_then(Value::as_object_mut)
        .and_then(|responses| responses.get_mut(status))
        .and_then(Value::as_object_mut)
    else {
        return;
    };

    response
        .entry("description")
        .or_insert_with(|| json!(description));
    let content_entry = response.entry("content").or_insert_with(|| json!({}));
    let Some(content) = content_entry.as_object_mut() else {
        return;
    };

    let media_type_entry = if content.is_empty() {
        content
            .entry(content_type.to_string())
            .or_insert_with(|| json!({}))
    } else {
        let Some(media_type) = content.get_mut(content_type) else {
            return;
        };
        media_type
    };
    let Some(media_type) = media_type_entry.as_object_mut() else {
        return;
    };

    if content_type == "application/problem+json" {
        media_type.entry("schema").or_insert_with(|| {
            json!({
                "$ref": "#/components/schemas/ProblemDetails"
            })
        });
    }
    media_type.insert("example".to_string(), example);
}

fn problem_details_schema() -> Value {
    json!({
        "type": "object",
        "required": ["type", "title", "status", "detail", "code"],
        "properties": {
            "type": { "type": "string", "format": "uri" },
            "title": { "type": "string" },
            "status": { "type": "integer", "format": "int32" },
            "detail": { "type": "string" },
            "code": { "type": "string" }
        },
        "additionalProperties": true
    })
}

fn problem_example(status: u16, code: &str, title: &str, detail: &str) -> Value {
    json!({
        "type": format!("https://data.example.gov/problems/{}", code.replace('.', "/")),
        "title": title,
        "status": status,
        "detail": detail,
        "code": code
    })
}

fn missing_credential_example() -> Value {
    problem_example(
        401,
        "auth.missing_credential",
        "Missing credential",
        "missing authentication credential",
    )
}

fn evaluation_not_found_example() -> Value {
    problem_example(
        404,
        "evaluation.not_found",
        "Evaluation not found",
        "the evaluation id is unknown or expired",
    )
}

fn discovery_example() -> Value {
    json!({
        "service_id": "demo.registry-witness",
        "api_version": "2026-05",
        "base_url": "http://127.0.0.1:4255",
        "issuer": {
            "id": "did:web:agriculture.demo.example.gov",
            "name": "demo.registry-witness"
        },
        "auth": {
            "methods": ["api_key", "bearer"],
            "api_key": {
                "header": "x-api-key"
            },
            "bearer": {
                "header": "Authorization",
                "scheme": "bearer",
                "format": "Bearer <token>"
            },
            "audience": "demo.registry-witness"
        },
        "operations": {
            "evaluate": true,
            "batch_evaluate": true,
            "render": true,
            "credential_issue": true
        },
        "claims_url": "/claims",
        "formats_url": "/formats",
        "batch": {
            "max_inline_subjects": 20,
            "idempotency_window": "PT15M"
        },
        "identity": {
            "mapper": "common_subject_id",
            "production_mapper": false
        },
        "formats": formats_value()
    })
}

fn jwks_example() -> Value {
    json!({
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "11qYAYKxCrfVS_3XDbXJC2AgYI57qXzcS7P0W5Y9f4Y",
                "alg": "EdDSA",
                "kid": "did:web:agriculture.demo.example.gov#registry-witness-demo-key-1"
            }
        ]
    })
}

fn claims_list_example() -> Value {
    json!({
        "data": [
            date_of_birth_claim_example(),
            farmer_under_4ha_claim_example()
        ]
    })
}

fn date_of_birth_claim_example() -> Value {
    json!({
        "id": "date-of-birth",
        "title": "Date of birth",
        "version": "2026-05",
        "subject_type": "person",
        "operations": {
            "evaluate": true,
            "batch_evaluate": false
        },
        "formats": [
            "application/vnd.registry-witness.claim-result+json",
            "application/ld+json; profile=\"cccev\""
        ],
        "disclosure": {
            "default": "value",
            "allowed": ["value", "redacted"],
            "downgrade": "deny"
        },
        "cccev": null,
        "oots": null
    })
}

fn farmer_under_4ha_claim_example() -> Value {
    json!({
        "id": "farmer-under-4ha",
        "title": "Farmer under four hectares",
        "version": "2026-05",
        "subject_type": "person",
        "operations": {
            "evaluate": true,
            "batch_evaluate": true
        },
        "formats": [
            "application/vnd.registry-witness.claim-result+json",
            "application/ld+json; profile=\"cccev\"",
            "application/dc+sd-jwt"
        ],
        "disclosure": {
            "default": "predicate",
            "allowed": ["predicate", "redacted"],
            "downgrade": "deny"
        },
        "cccev": {
            "requirement_type": "InformationRequirement"
        },
        "oots": null
    })
}

fn formats_example() -> Value {
    json!({
        "formats": formats_value()
    })
}

fn formats_value() -> Value {
    json!([
        {
            "id": "application/dc+sd-jwt",
            "kind": "credential",
            "status": "enabled"
        },
        {
            "id": "application/ld+json; profile=\"cccev\"",
            "kind": "renderer",
            "status": "enabled"
        },
        {
            "id": "application/vnd.registry-witness.claim-result+json",
            "kind": "claim_result",
            "status": "enabled"
        }
    ])
}

fn evaluate_example() -> Value {
    json!({
        "results": [
            claim_result_example()
        ]
    })
}

fn batch_evaluate_example() -> Value {
    json!({
        "batch_id": "01HX7Y4N6S7ZK0R2T8Q9V1M3PA",
        "status": "completed",
        "claims": ["farmer-under-4ha"],
        "items": [
            {
                "input_index": 0,
                "subject_ref": "person-1",
                "evaluation_id": "01HX7Y5F2WAJ7ZP0Q4M5K9E8NC",
                "status": "succeeded",
                "claim_results": [
                    {
                        "result_id": "01HX7Y5F31M8BZWQ2HY7P6J9FA",
                        "claim_id": "farmer-under-4ha",
                        "claim_version": "2026-05",
                        "value_type": "boolean",
                        "value": true,
                        "satisfied": true,
                        "disclosure": "predicate",
                        "provenance": provenance_example()
                    }
                ],
                "errors": []
            }
        ],
        "summary": {
            "succeeded": 1,
            "failed": 0
        }
    })
}

fn render_example() -> Value {
    json!({
        "results": [
            claim_result_example()
        ]
    })
}

fn claim_result_example() -> Value {
    json!({
        "evaluation_id": "01HX7Y5F2WAJ7ZP0Q4M5K9E8NC",
        "claim_id": "farmer-under-4ha",
        "claim_version": "2026-05",
        "subject_type": "person",
        "subject_ref": "person-1",
        "value": true,
        "satisfied": true,
        "disclosure": "predicate",
        "format": "application/vnd.registry-witness.claim-result+json",
        "issued_at": "2026-05-24T12:00:00Z",
        "expires_at": "2026-05-25T12:00:00Z",
        "provenance": provenance_example()
    })
}

fn provenance_example() -> Value {
    json!({
        "source_count": 1,
        "source_versions": {},
        "computed_by": "demo.registry-witness"
    })
}

fn credential_issue_example() -> Value {
    json!({
        "credential_id": "urn:registry-witness:credential:01HX7Y5F2WAJ7ZP0Q4M5K9E8NC",
        "format": "application/dc+sd-jwt",
        "issuer": "did:web:agriculture.demo.example.gov",
        "expires_at": "2026-05-25T12:00:00Z",
        "credential": "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWI6YWdyaWN1bHR1cmUuZGVtby5leGFtcGxlLmdvdiNyZWdpc3RyeS13aXRuZXNzLWRlbW8ta2V5LTEifQ.eyJpc3MiOiJkaWQ6d2ViOmFncmljdWx0dXJlLmRlbW8uZXhhbXBsZS5nb3YifQ.c2lnbmF0dXJl~ZGlzY2xvc3VyZQ~",
        "issuer_signed_jwt": "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWI6YWdyaWN1bHR1cmUuZGVtby5leGFtcGxlLmdvdiNyZWdpc3RyeS13aXRuZXNzLWRlbW8ta2V5LTEifQ.eyJpc3MiOiJkaWQ6d2ViOmFncmljdWx0dXJlLmRlbW8uZXhhbXBsZS5nb3YifQ.c2lnbmF0dXJl",
        "disclosures": ["ZGlzY2xvc3VyZQ"]
    })
}

#[cfg(test)]
mod tests {
    use super::{openapi_document, set_response_example};
    use serde_json::json;

    #[test]
    fn documents_split_registry_witness_routes() {
        let doc = openapi_document();
        let paths = doc.paths.paths;
        for route in [
            "/healthz",
            "/ready",
            "/admin/reload",
            "/openapi.json",
            "/.well-known/evidence-service",
            "/.well-known/evidence/jwks.json",
            "/claims",
            "/claims/{claim_id}",
            "/formats",
            "/claims/evaluate",
            "/claims/batch-evaluate",
            "/evidence/render",
            "/credentials/issue",
        ] {
            assert!(paths.contains_key(route), "missing {route}");
        }
    }

    #[test]
    fn document_info_tracks_crate_metadata() {
        let doc = serde_json::to_value(openapi_document()).expect("document serializes");
        assert_eq!(doc["info"]["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(doc["info"]["license"]["name"], env!("CARGO_PKG_LICENSE"));
        assert_eq!(
            doc["info"]["license"]["identifier"],
            env!("CARGO_PKG_LICENSE")
        );
    }

    #[test]
    fn public_probe_routes_do_not_require_security() {
        let doc = serde_json::to_value(openapi_document()).expect("document serializes");
        assert_eq!(doc["paths"]["/healthz"]["get"]["security"], json!([]));
        assert_eq!(doc["paths"]["/ready"]["get"]["security"], json!([]));
        assert_eq!(
            doc["paths"]["/healthz"]["get"]["responses"]["4XX"]["description"],
            "Client error"
        );
        assert_eq!(
            doc["paths"]["/ready"]["get"]["responses"]["4XX"]["description"],
            "Client error"
        );
    }

    #[test]
    fn high_value_routes_have_redoc_response_examples() {
        let doc = serde_json::to_value(openapi_document()).expect("document serializes");
        for (path, method, status) in [
            ("/healthz", "get", "200"),
            ("/ready", "get", "200"),
            ("/ready", "get", "503"),
            ("/admin/reload", "post", "200"),
            ("/openapi.json", "get", "200"),
            ("/.well-known/evidence-service", "get", "200"),
            ("/.well-known/evidence/jwks.json", "get", "200"),
            ("/claims", "get", "200"),
            ("/claims/{claim_id}", "get", "200"),
            ("/formats", "get", "200"),
            ("/claims/evaluate", "post", "200"),
            ("/claims/batch-evaluate", "post", "200"),
            ("/evidence/render", "post", "200"),
            ("/credentials/issue", "post", "200"),
        ] {
            assert_json_example(&doc, path, method, status);
        }

        assert_eq!(
            doc["paths"]["/.well-known/evidence-service"]["get"]["responses"]["200"]["content"]
                ["application/json"]["example"]["service_id"],
            json!("demo.registry-witness")
        );
        assert_eq!(
            doc["paths"]["/claims/evaluate"]["post"]["responses"]["200"]["content"]
                ["application/json"]["example"]["results"][0]["claim_id"],
            json!("farmer-under-4ha")
        );
        assert_eq!(
            doc["paths"]["/credentials/issue"]["post"]["responses"]["200"]["content"]
                ["application/json"]["example"]["format"],
            json!("application/dc+sd-jwt")
        );
    }

    #[test]
    fn common_error_responses_have_problem_detail_examples() {
        let doc = serde_json::to_value(openapi_document()).expect("document serializes");
        for (path, method, status) in [
            ("/admin/reload", "post", "401"),
            ("/admin/reload", "post", "403"),
            ("/.well-known/evidence-service", "get", "401"),
            ("/.well-known/evidence/jwks.json", "get", "401"),
            ("/claims", "get", "401"),
            ("/claims/{claim_id}", "get", "401"),
            ("/claims/{claim_id}", "get", "404"),
            ("/formats", "get", "401"),
            ("/claims/evaluate", "post", "400"),
            ("/claims/evaluate", "post", "401"),
            ("/claims/evaluate", "post", "403"),
            ("/claims/batch-evaluate", "post", "400"),
            ("/claims/batch-evaluate", "post", "401"),
            ("/claims/batch-evaluate", "post", "403"),
            ("/evidence/render", "post", "400"),
            ("/evidence/render", "post", "401"),
            ("/evidence/render", "post", "404"),
            ("/credentials/issue", "post", "400"),
            ("/credentials/issue", "post", "401"),
            ("/credentials/issue", "post", "404"),
        ] {
            assert_problem_example(&doc, path, method, status);
        }

        assert_eq!(
            doc["paths"]["/claims/{claim_id}"]["get"]["responses"]["404"]["content"]
                ["application/problem+json"]["example"]["code"],
            json!("claim.not_found")
        );
        assert_eq!(
            doc["paths"]["/evidence/render"]["post"]["responses"]["404"]["content"]
                ["application/problem+json"]["example"]["code"],
            json!("evaluation.not_found")
        );
    }

    #[test]
    fn problem_responses_reference_shared_problem_details_schema() {
        let doc = serde_json::to_value(openapi_document()).expect("document serializes");
        assert!(doc["components"]["schemas"]["ProblemDetails"].is_object());

        for (path, method, status) in [
            ("/claims/evaluate", "post", "400"),
            ("/claims/evaluate", "post", "401"),
            ("/claims/evaluate", "post", "403"),
            ("/credentials/issue", "post", "404"),
        ] {
            assert_eq!(
                doc["paths"][path][method]["responses"][status]["content"]
                    ["application/problem+json"]["schema"]["$ref"],
                json!("#/components/schemas/ProblemDetails"),
                "problem response schema must reference the shared component for {method} {path} {status}"
            );
        }
    }

    #[test]
    fn response_example_patcher_noops_when_target_shape_is_missing() {
        let mut doc = json!({
            "paths": {
                "/demo": {
                    "get": {
                        "responses": {
                            "200": {
                                "description": "plain response",
                                "content": {
                                    "text/plain": {}
                                }
                            },
                            "400": {
                                "description": "problem response",
                                "content": {
                                    "application/problem+json": "not an object"
                                }
                            }
                        }
                    }
                }
            }
        });

        set_response_example(
            &mut doc,
            "/missing",
            "get",
            "200",
            "Missing path",
            "application/json",
            json!({ "ignored": true }),
        );
        set_response_example(
            &mut doc,
            "/demo",
            "get",
            "200",
            "JSON response",
            "application/json",
            json!({ "ignored": true }),
        );
        set_response_example(
            &mut doc,
            "/demo",
            "get",
            "400",
            "Problem response",
            "application/problem+json",
            json!({ "ignored": true }),
        );

        assert!(
            doc["paths"]["/demo"]["get"]["responses"]["200"]["content"]["application/json"]
                .is_null()
        );
        assert_eq!(
            doc["paths"]["/demo"]["get"]["responses"]["400"]["content"]["application/problem+json"],
            json!("not an object")
        );
    }

    fn assert_json_example(doc: &serde_json::Value, path: &str, method: &str, status: &str) {
        assert!(
            doc["paths"][path][method]["responses"][status]["content"]["application/json"]
                ["example"]
                .is_object(),
            "missing JSON example for {method} {path} {status}"
        );
    }

    fn assert_problem_example(doc: &serde_json::Value, path: &str, method: &str, status: &str) {
        let example = &doc["paths"][path][method]["responses"][status]["content"]
            ["application/problem+json"]["example"];
        assert!(
            example.is_object(),
            "missing problem example for {method} {path} {status}"
        );
        assert!(
            example["type"]
                .as_str()
                .is_some_and(|value| value.starts_with("https://data.example.gov/problems/")),
            "problem example must include a Registry Witness problem type for {method} {path} {status}"
        );
        assert!(
            example["code"].is_string(),
            "problem example must include a code for {method} {path} {status}"
        );
    }
}
