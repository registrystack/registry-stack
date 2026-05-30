// SPDX-License-Identifier: Apache-2.0
//! Registry Notary OpenAPI document generation.

use registry_notary_core::model::{
    BatchEvaluateRequest, BatchSubjectRequest, ClaimRef, CredentialIssueRequest, EvaluateRequest,
    HolderRequest, RenderEvaluationRequest, SubjectRequest, FORMAT_SD_JWT_VC,
    SD_JWT_VC_HOLDER_BINDING_METHOD, SD_JWT_VC_ISSUER_KEY_TYPE, SD_JWT_VC_JWT_TYP,
    SD_JWT_VC_SIGNING_ALG,
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
            "title": "Registry Notary API",
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
            "/admin/v1/reload": {
                "post": {
                    "summary": "Request a standalone config reload",
                    "operationId": "adminReload",
                    "responses": {
                        "200": { "description": "Standalone router accepted the reload request" },
                        "401": { "description": "Missing or invalid credential" },
                        "403": { "description": "Caller lacks registry_notary:admin scope" }
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
                    "summary": "Discover Registry Notary capabilities",
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
            "/.well-known/openid-credential-issuer": {
                "get": {
                    "summary": "Discover OpenID4VCI credential issuer metadata",
                    "operationId": "getOpenidCredentialIssuer",
                    "description": "Returns the OpenID4VCI issuer metadata for Registry Notary' dc+sd-jwt issuance profile.",
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "OpenID4VCI credential issuer metadata",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/CredentialIssuerMetadata" }
                                }
                            }
                        },
                        "404": { "description": "OpenID4VCI issuer is disabled" },
                        "500": {
                            "description": "OpenID4VCI issuer failed",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/Oid4vciError" }
                                }
                            }
                        }
                    }
                }
            },
            "/oid4vci/credential-offer": {
                "get": {
                    "summary": "Create an OpenID4VCI credential offer",
                    "operationId": "getOid4vciCredentialOffer",
                    "description": "Returns an authorization-code credential offer. Error responses use the OpenID4VCI error envelope, not RFC 7807 Problem Details.",
                    "security": [],
                    "parameters": [
                        {
                            "name": "credential_configuration_id",
                            "in": "query",
                            "required": false,
                            "schema": { "type": "string" }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Credential offer",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/CredentialOffer" }
                                }
                            }
                        },
                        "400": {
                            "description": "Invalid credential offer request",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/Oid4vciError" }
                                }
                            }
                        },
                        "404": { "description": "OpenID4VCI issuer is disabled" },
                        "500": {
                            "description": "OpenID4VCI issuer failed",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/Oid4vciError" }
                                }
                            }
                        }
                    }
                }
            },
            "/oid4vci/nonce": {
                "post": {
                    "summary": "Create an OpenID4VCI credential nonce",
                    "operationId": "createOid4vciNonce",
                    "description": "Returns a c_nonce for proof-of-possession. Error responses use the OpenID4VCI error envelope, not RFC 7807 Problem Details.",
                    "security": [],
                    "requestBody": {
                        "required": false,
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/NonceRequest" }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Nonce response",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/NonceResponse" }
                                }
                            }
                        },
                        "400": {
                            "description": "Invalid nonce request",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/Oid4vciError" }
                                }
                            }
                        },
                        "404": { "description": "OpenID4VCI nonce endpoint is disabled" },
                        "429": {
                            "description": "Nonce store is rate limited",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/Oid4vciError" }
                                }
                            }
                        },
                        "500": {
                            "description": "OpenID4VCI issuer failed",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/Oid4vciError" }
                                }
                            }
                        }
                    }
                }
            },
            "/oid4vci/credential": {
                "post": {
                    "summary": "Issue a credential through OpenID4VCI",
                    "operationId": "issueOid4vciCredential",
                    "description": "Issues a dc+sd-jwt credential for an authenticated self-attestation principal. Error responses use the OpenID4VCI error envelope, not RFC 7807 Problem Details.",
                    "security": [
                        { "bearerAuth": [] }
                    ],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/CredentialRequest" }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Credential response",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/CredentialResponse" }
                                }
                            }
                        },
                        "400": {
                            "description": "Invalid credential request, proof, or type",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/Oid4vciError" }
                                }
                            }
                        },
                        "401": {
                            "description": "Invalid credential access token",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/Oid4vciError" }
                                }
                            }
                        },
                        "403": {
                            "description": "Credential request is denied",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/Oid4vciError" }
                                }
                            }
                        },
                        "429": {
                            "description": "Credential request is rate limited",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/Oid4vciError" }
                                }
                            }
                        },
                        "500": {
                            "description": "OpenID4VCI issuer failed",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/Oid4vciError" }
                                }
                            }
                        }
                    }
                }
            },
            "/v1/claims": {
                "get": {
                    "summary": "List claims visible to the caller",
                    "operationId": "listClaims",
                    "responses": {
                        "200": { "description": "Visible claims" },
                        "401": { "description": "Missing or invalid credential" }
                    }
                }
            },
            "/v1/claims/{claim_id}": {
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
            "/v1/formats": {
                "get": {
                    "summary": "List supported output formats",
                    "operationId": "listFormats",
                    "responses": {
                        "200": { "description": "Supported formats" },
                        "401": { "description": "Missing or invalid credential" }
                    }
                }
            },
            "/v1/evaluations": {
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
                        "403": { "description": "Not authorized for requested claim, purpose, disclosure, or format" },
                        "406": { "description": "Requested format is not acceptable" },
                        "413": { "description": "Request body or batch is too large" },
                        "429": { "description": "Self-attestation request is rate limited" },
                        "503": { "description": "Source service is unavailable" }
                    }
                }
            },
            "/federation/v1/evaluations": {
                "post": {
                    "summary": "Evaluate one configured federation profile for a trusted peer",
                    "operationId": "federatedEvaluate",
                    "description": "Accepts a compact JWS request with typ registry-notary-request+jwt. This route is mounted only when federation is enabled and uses body-JWT authentication instead of API key or bearer authentication.",
                    "security": [],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/jwt": {
                                "schema": {
                                    "type": "string",
                                    "description": "Compact JWS signed federation evaluation request"
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Compact JWS signed federation evaluation response",
                            "content": {
                                "application/jwt": {
                                    "schema": {
                                        "type": "string",
                                        "description": "Compact JWS with typ registry-notary-response+jwt"
                                    }
                                }
                            }
                        },
                        "400": { "description": "Invalid federation request" },
                        "401": { "description": "Invalid federation token" },
                        "403": { "description": "Peer, profile, purpose, or subject id type is not allowed" },
                        "409": { "description": "Request replay detected" },
                        "413": { "description": "Request body is too large" },
                        "415": { "description": "Content type is not application/jwt" },
                        "503": { "description": "Source service or peer key service is unavailable" }
                    }
                }
            },
            "/v1/batch-evaluations": {
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
                        "403": { "description": "Not authorized for requested claim, purpose, disclosure, or format" },
                        "406": { "description": "Requested format is not acceptable" },
                        "409": { "description": "Idempotency key conflicts with another request body" },
                        "413": { "description": "Request body or batch is too large" },
                        "429": { "description": "Self-attestation request is rate limited" },
                        "503": { "description": "Source service is unavailable" }
                    }
                }
            },
            "/v1/evaluations/{evaluation_id}/render": {
                "post": {
                    "summary": "Render a stored evaluation",
                    "operationId": "renderEvidence",
                    "parameters": [
                        {
                            "name": "evaluation_id",
                            "in": "path",
                            "required": true,
                            "schema": { "type": "string" }
                        }
                    ],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/RenderEvaluationRequest" }
                            }
                        }
                    },
                    "responses": {
                        "200": { "description": "Rendered evidence artifact" },
                        "400": { "description": "Invalid request or disclosure widening attempt" },
                        "401": { "description": "Missing or invalid credential" },
                        "404": { "description": "Evaluation not found" },
                        "406": { "description": "Requested format is not acceptable" },
                        "413": { "description": "Request body is too large" },
                        "429": { "description": "Self-attestation request is rate limited" },
                        "503": { "description": "Source service is unavailable" }
                    }
                }
            },
            "/v1/credentials": {
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
                        "404": { "description": "Evaluation not found" },
                        "406": { "description": "Requested format is not acceptable" },
                        "409": { "description": "Holder proof replay or source ambiguity conflict" },
                        "413": { "description": "Request body is too large" },
                        "429": { "description": "Self-attestation request is rate limited" },
                        "503": { "description": "Source service is unavailable" }
                    }
                }
            },
            "/v1/credentials/{credential_id}/status": {
                "get": {
                    "summary": "Fetch credential lifecycle status",
                    "operationId": "getCredentialStatus",
                    "security": [],
                    "parameters": [
                        {
                            "name": "credential_id",
                            "in": "path",
                            "required": true,
                            "schema": { "type": "string" }
                        }
                    ],
                    "responses": {
                        "200": { "description": "Credential status record" },
                        "404": { "description": "Credential status is disabled or not found" },
                        "503": { "description": "Credential status store is unavailable" }
                    }
                }
            },
            "/admin/v1/credentials/{credential_id}/status": {
                "post": {
                    "summary": "Update credential lifecycle status",
                    "operationId": "updateCredentialStatus",
                    "parameters": [
                        {
                            "name": "credential_id",
                            "in": "path",
                            "required": true,
                            "schema": { "type": "string" }
                        }
                    ],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/CredentialStatusUpdateRequest" }
                            }
                        }
                    },
                    "responses": {
                        "200": { "description": "Updated credential status record" },
                        "400": { "description": "Invalid status value" },
                        "401": { "description": "Missing or invalid credential" },
                        "403": { "description": "Caller lacks registry_notary:admin scope" },
                        "404": { "description": "Credential status is disabled or not found" },
                        "503": { "description": "Credential status store is unavailable" }
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "ProblemDetails": problem_details_schema(),
                "CredentialStatus": credential_status_schema(),
                "CredentialStatusUpdateRequest": credential_status_update_request_schema(),
                "CredentialIssuerMetadata": credential_issuer_metadata_schema(),
                "CredentialConfigurationMetadata": credential_configuration_metadata_schema(),
                "CredentialOffer": credential_offer_schema(),
                "NonceRequest": nonce_request_schema(),
                "NonceResponse": nonce_response_schema(),
                "CredentialRequest": credential_request_schema(),
                "CredentialResponse": credential_response_schema(),
                "Oid4vciError": oid4vci_error_schema()
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
        .expect("static Registry Notary OpenAPI document is valid");

    let components = document
        .components
        .get_or_insert_with(utoipa::openapi::Components::new);
    components
        .schemas
        .insert("SubjectRequest".to_string(), SubjectRequest::schema());
    components.schemas.insert(
        "BatchSubjectRequest".to_string(),
        BatchSubjectRequest::schema(),
    );
    components
        .schemas
        .insert("ClaimRef".to_string(), ClaimRef::schema());
    components
        .schemas
        .insert("EvaluateRequest".to_string(), EvaluateRequest::schema());
    components.schemas.insert(
        "BatchEvaluateRequest".to_string(),
        BatchEvaluateRequest::schema(),
    );
    components.schemas.insert(
        "RenderEvaluationRequest".to_string(),
        RenderEvaluationRequest::schema(),
    );
    components.schemas.insert(
        "CredentialIssueRequest".to_string(),
        CredentialIssueRequest::schema(),
    );
    components
        .schemas
        .insert("HolderRequest".to_string(), HolderRequest::schema());

    let mut document_value =
        serde_json::to_value(&document).expect("Registry Notary OpenAPI document serializes");
    document_value["components"]["schemas"]["ClaimRef"] = claim_ref_schema();
    serde_json::from_value(document_value)
        .expect("Registry Notary OpenAPI ClaimRef schema is valid")
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
        "/admin/v1/reload",
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
        "/admin/v1/reload",
        "post",
        "401",
        "Missing or invalid credential",
        missing_credential_example(),
    );
    set_problem_response(
        document,
        "/admin/v1/reload",
        "post",
        "403",
        "Caller lacks registry_notary:admin scope",
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
                "title": "Registry Notary API",
                "version": env!("CARGO_PKG_VERSION")
            },
            "paths": {
                "/v1/evaluations": {}
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
        "/.well-known/openid-credential-issuer",
        "get",
        "200",
        "OpenID4VCI credential issuer metadata",
        oid4vci_issuer_metadata_example(),
    );
    set_oid4vci_error_response(
        document,
        "/.well-known/openid-credential-issuer",
        "get",
        "500",
        "OpenID4VCI issuer failed",
        oid4vci_error_example("server_error", "credential issuer failed"),
    );
    set_json_response(
        document,
        "/oid4vci/credential-offer",
        "get",
        "200",
        "Credential offer",
        oid4vci_credential_offer_example(),
    );
    for (status, code, description) in [
        ("400", "invalid_request", "credential request is invalid"),
        ("500", "server_error", "credential issuer failed"),
    ] {
        set_oid4vci_error_response(
            document,
            "/oid4vci/credential-offer",
            "get",
            status,
            if status == "400" {
                "Invalid credential offer request"
            } else {
                "OpenID4VCI issuer failed"
            },
            oid4vci_error_example(code, description),
        );
    }
    set_json_response(
        document,
        "/oid4vci/nonce",
        "post",
        "200",
        "Nonce response",
        oid4vci_nonce_example(),
    );
    for (status, code, description) in [
        ("400", "invalid_request", "credential request is invalid"),
        (
            "429",
            "temporarily_unavailable",
            "credential request is rate limited",
        ),
        ("500", "server_error", "credential issuer failed"),
    ] {
        set_oid4vci_error_response(
            document,
            "/oid4vci/nonce",
            "post",
            status,
            match status {
                "400" => "Invalid nonce request",
                "429" => "Nonce store is rate limited",
                _ => "OpenID4VCI issuer failed",
            },
            oid4vci_error_example(code, description),
        );
    }
    set_json_response(
        document,
        "/oid4vci/credential",
        "post",
        "200",
        "Credential response",
        oid4vci_credential_response_example(),
    );
    for (status, code, description) in [
        ("400", "invalid_proof", "credential proof is invalid"),
        ("401", "invalid_token", "credential access token is invalid"),
        ("403", "access_denied", "credential request is denied"),
        (
            "429",
            "temporarily_unavailable",
            "credential request is rate limited",
        ),
        ("500", "server_error", "credential issuer failed"),
    ] {
        set_oid4vci_error_response(
            document,
            "/oid4vci/credential",
            "post",
            status,
            match status {
                "400" => "Invalid credential request, proof, or type",
                "401" => "Invalid credential access token",
                "403" => "Credential request is denied",
                "429" => "Credential request is rate limited",
                _ => "OpenID4VCI issuer failed",
            },
            oid4vci_error_example(code, description),
        );
    }
    set_json_response(
        document,
        "/v1/claims",
        "get",
        "200",
        "Visible claims",
        claims_list_example(),
    );
    set_problem_response(
        document,
        "/v1/claims",
        "get",
        "401",
        "Missing or invalid credential",
        missing_credential_example(),
    );
    set_json_response(
        document,
        "/v1/claims/{claim_id}",
        "get",
        "200",
        "Claim definition",
        farmer_under_4ha_claim_example(),
    );
    set_problem_response(
        document,
        "/v1/claims/{claim_id}",
        "get",
        "401",
        "Missing or invalid credential",
        missing_credential_example(),
    );
    set_problem_response(
        document,
        "/v1/claims/{claim_id}",
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
        "/v1/formats",
        "get",
        "200",
        "Supported formats",
        formats_example(),
    );
    set_problem_response(
        document,
        "/v1/formats",
        "get",
        "401",
        "Missing or invalid credential",
        missing_credential_example(),
    );
    set_json_response(
        document,
        "/v1/evaluations",
        "post",
        "200",
        "Claim evaluation result",
        evaluate_example(),
    );
    set_problem_response(
        document,
        "/v1/evaluations",
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
        "/v1/evaluations",
        "post",
        "401",
        "Missing or invalid credential",
        missing_credential_example(),
    );
    set_problem_response(
        document,
        "/v1/evaluations",
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
    add_runtime_problem_responses(
        document,
        "/v1/evaluations",
        "post",
        &["406", "413", "429", "503"],
    );
    set_json_response(
        document,
        "/v1/batch-evaluations",
        "post",
        "200",
        "Per-subject claim evaluation results",
        batch_evaluate_example(),
    );
    set_problem_response(
        document,
        "/v1/batch-evaluations",
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
        "/v1/batch-evaluations",
        "post",
        "401",
        "Missing or invalid credential",
        missing_credential_example(),
    );
    set_problem_response(
        document,
        "/v1/batch-evaluations",
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
    add_runtime_problem_responses(
        document,
        "/v1/batch-evaluations",
        "post",
        &["406", "409", "413", "429", "503"],
    );
    set_json_response(
        document,
        "/v1/evaluations/{evaluation_id}/render",
        "post",
        "200",
        "Rendered evidence artifact",
        render_example(),
    );
    set_problem_response(
        document,
        "/v1/evaluations/{evaluation_id}/render",
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
        "/v1/evaluations/{evaluation_id}/render",
        "post",
        "401",
        "Missing or invalid credential",
        missing_credential_example(),
    );
    set_problem_response(
        document,
        "/v1/evaluations/{evaluation_id}/render",
        "post",
        "404",
        "Evaluation not found",
        evaluation_not_found_example(),
    );
    add_runtime_problem_responses(
        document,
        "/v1/evaluations/{evaluation_id}/render",
        "post",
        &["406", "413", "429", "503"],
    );
    set_json_response(
        document,
        "/v1/credentials",
        "post",
        "200",
        "Issued credential",
        credential_issue_example(),
    );
    set_problem_response(
        document,
        "/v1/credentials",
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
        "/v1/credentials",
        "post",
        "401",
        "Missing or invalid credential",
        missing_credential_example(),
    );
    set_problem_response(
        document,
        "/v1/credentials",
        "post",
        "404",
        "Evaluation not found",
        evaluation_not_found_example(),
    );
    add_runtime_problem_responses(
        document,
        "/v1/credentials",
        "post",
        &["406", "409", "413", "429", "503"],
    );
    set_json_response(
        document,
        "/v1/credentials/{credential_id}/status",
        "get",
        "200",
        "Credential status record",
        credential_status_example("valid"),
    );
    set_problem_response(
        document,
        "/v1/credentials/{credential_id}/status",
        "get",
        "404",
        "Credential status is disabled or not found",
        credential_status_problem_example(404, "credential_status.not_found"),
    );
    set_problem_response(
        document,
        "/v1/credentials/{credential_id}/status",
        "get",
        "503",
        "Credential status store is unavailable",
        credential_status_problem_example(503, "credential_status.unavailable"),
    );
    set_json_response(
        document,
        "/admin/v1/credentials/{credential_id}/status",
        "post",
        "200",
        "Updated credential status record",
        credential_status_example("revoked"),
    );
    set_problem_response(
        document,
        "/admin/v1/credentials/{credential_id}/status",
        "post",
        "400",
        "Invalid status value",
        credential_status_problem_example(400, "credential_status.invalid_status"),
    );
    set_problem_response(
        document,
        "/admin/v1/credentials/{credential_id}/status",
        "post",
        "401",
        "Missing or invalid credential",
        missing_credential_example(),
    );
    set_problem_response(
        document,
        "/admin/v1/credentials/{credential_id}/status",
        "post",
        "403",
        "Caller lacks registry_notary:admin scope",
        problem_example(
            403,
            "auth.scope_denied",
            "Scope denied",
            "missing required scope",
        ),
    );
    set_problem_response(
        document,
        "/admin/v1/credentials/{credential_id}/status",
        "post",
        "404",
        "Credential status is disabled or not found",
        credential_status_problem_example(404, "credential_status.not_found"),
    );
    set_problem_response(
        document,
        "/admin/v1/credentials/{credential_id}/status",
        "post",
        "503",
        "Credential status store is unavailable",
        credential_status_problem_example(503, "credential_status.unavailable"),
    );
}

fn claim_ref_schema() -> Value {
    json!({
        "oneOf": [
            { "type": "string" },
            {
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": { "type": "string" },
                    "version": { "type": "string" }
                },
                "additionalProperties": false
            }
        ]
    })
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

fn set_oid4vci_error_response(
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

fn add_runtime_problem_responses(
    document: &mut Value,
    path: &str,
    method: &str,
    statuses: &[&str],
) {
    for status in statuses {
        let (status_code, code, title, detail) = match *status {
            "406" => (
                406,
                "format.unsupported",
                "Claim format not supported",
                "the requested claim format is not supported",
            ),
            "409" => (
                409,
                "request.conflict",
                "Request conflict",
                "the request conflicts with existing state",
            ),
            "413" => (
                413,
                "request.too_large",
                "Request too large",
                "the request body or batch is too large",
            ),
            "429" => (
                429,
                "self_attestation.rate_limited",
                "Self-attestation rate limited",
                "self-attestation request is rate limited",
            ),
            "503" => (
                503,
                "source.unavailable",
                "Source unavailable",
                "the evidence source is unavailable",
            ),
            _ => continue,
        };
        set_problem_response(
            document,
            path,
            method,
            status,
            title,
            problem_example(status_code, code, title, detail),
        );
    }
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

fn credential_status_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "credential_id",
            "issuer",
            "credential_profile",
            "status",
            "issued_at",
            "expires_at",
            "updated_at"
        ],
        "properties": {
            "credential_id": { "type": "string" },
            "issuer": { "type": "string" },
            "credential_profile": { "type": "string" },
            "status": {
                "type": "string",
                "enum": ["valid", "suspended", "revoked", "expired"]
            },
            "issued_at": { "type": "string", "format": "date-time" },
            "expires_at": { "type": "string", "format": "date-time" },
            "updated_at": { "type": "string", "format": "date-time" }
        }
    })
}

fn credential_status_update_request_schema() -> Value {
    json!({
        "type": "object",
        "required": ["status"],
        "properties": {
            "status": {
                "type": "string",
                "enum": ["valid", "suspended", "revoked"]
            }
        },
        "additionalProperties": false
    })
}

fn credential_issuer_metadata_schema() -> Value {
    json!({
        "type": "object",
        "required": ["credential_issuer", "credential_endpoint", "credential_configurations_supported"],
        "properties": {
            "credential_issuer": { "type": "string", "format": "uri" },
            "credential_endpoint": { "type": "string", "format": "uri" },
            "nonce_endpoint": { "type": "string", "format": "uri" },
            "authorization_servers": { "type": "array", "items": { "type": "string", "format": "uri" } },
            "credential_configurations_supported": {
                "type": "object",
                "additionalProperties": { "$ref": "#/components/schemas/CredentialConfigurationMetadata" }
            }
        }
    })
}

fn credential_offer_schema() -> Value {
    json!({
        "type": "object",
        "required": ["credential_issuer", "credential_configuration_ids"],
        "properties": {
            "credential_issuer": { "type": "string", "format": "uri" },
            "credential_configuration_ids": { "type": "array", "items": { "type": "string" } },
            "grants": { "type": "object", "additionalProperties": true }
        }
    })
}

fn credential_configuration_metadata_schema() -> Value {
    json!({
        "type": "object",
        "required": ["format"],
        "properties": {
            "format": { "type": "string" },
            "scope": { "type": "string" },
            "cryptographic_binding_methods_supported": { "type": "array", "items": { "type": "string" } },
            "credential_signing_alg_values_supported": { "type": "array", "items": { "type": "string" } },
            "proof_types_supported": { "type": "object", "additionalProperties": true },
            "display": { "type": "array", "items": { "type": "object", "additionalProperties": true } },
            "vct": { "type": "string", "format": "uri" }
        }
    })
}

fn nonce_request_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "credential_configuration_id": { "type": "string" }
        },
        "additionalProperties": false
    })
}

fn nonce_response_schema() -> Value {
    json!({
        "type": "object",
        "required": ["c_nonce", "c_nonce_expires_in"],
        "properties": {
            "c_nonce": { "type": "string" },
            "c_nonce_expires_in": { "type": "integer", "format": "uint64" }
        }
    })
}

fn credential_request_schema() -> Value {
    json!({
        "type": "object",
        "required": ["format", "proof"],
        "properties": {
            "format": { "type": "string", "example": "dc+sd-jwt" },
            "credential_identifier": { "type": "string" },
            "credential_configuration_id": { "type": "string" },
            "vct": { "type": "string", "format": "uri" },
            "proof": {
                "type": "object",
                "required": ["proof_type", "jwt"],
                "properties": {
                    "proof_type": { "type": "string", "example": "jwt" },
                    "jwt": { "type": "string" }
                },
                "additionalProperties": false
            }
        },
        "additionalProperties": false
    })
}

fn credential_response_schema() -> Value {
    json!({
        "type": "object",
        "required": ["credential"],
        "properties": {
            "credential": { "type": "string" },
            "credential_profile": { "type": "string" },
            "format": { "type": "string" },
            "c_nonce": { "type": "string" },
            "c_nonce_expires_in": { "type": "integer", "format": "uint64" }
        }
    })
}

fn oid4vci_error_schema() -> Value {
    json!({
        "type": "object",
        "required": ["error"],
        "properties": {
            "error": { "type": "string" },
            "error_description": { "type": "string" }
        }
    })
}

fn problem_example(status: u16, code: &str, title: &str, detail: &str) -> Value {
    json!({
        "type": format!("{}/{}", crate::PROBLEM_TYPE_BASE_URL, code.replace('.', "/")),
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

fn credential_status_example(status: &str) -> Value {
    json!({
        "credential_id": "urn:ulid:01HX7Y5F2WAJ7ZP0Q4M5K9E8NC",
        "issuer": "did:web:issuer.example",
        "credential_profile": "civil_status_sd_jwt",
        "status": status,
        "issued_at": "2026-05-25T12:00:00Z",
        "expires_at": "2026-05-25T12:10:00Z",
        "updated_at": "2026-05-25T12:00:00Z"
    })
}

fn credential_status_problem_example(status: u16, code: &str) -> Value {
    let (title, detail) = match code {
        "credential_status.invalid_status" => (
            "Invalid credential status",
            "status must be valid, suspended, or revoked",
        ),
        "credential_status.unavailable" => (
            "Credential status unavailable",
            "credential status store is unavailable",
        ),
        _ => (
            "Credential status not found",
            "credential status record was not found",
        ),
    };
    problem_example(status, code, title, detail)
}

fn discovery_example() -> Value {
    json!({
        "service_id": "demo.registry-notary",
        "api_version": "2026-05",
        "base_url": "http://127.0.0.1:4255",
        "issuer": {
            "id": "did:web:agriculture.demo.example.gov",
            "name": "demo.registry-notary"
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
            "audience": "demo.registry-notary"
        },
        "operations": {
            "evaluate": true,
            "batch_evaluate": true,
            "render": true,
            "credential_issue": true
        },
        "claims_url": "/v1/claims",
        "formats_url": "/v1/formats",
        "credential_capabilities": {
            "formats": [FORMAT_SD_JWT_VC],
            "sd_jwt_vc": {
                "media_type": FORMAT_SD_JWT_VC,
                "jwt_typ": SD_JWT_VC_JWT_TYP,
                "signing_algs": [SD_JWT_VC_SIGNING_ALG],
                "issuer_key_types": [SD_JWT_VC_ISSUER_KEY_TYPE],
                "holder_binding_methods": [SD_JWT_VC_HOLDER_BINDING_METHOD],
                "status_methods": [],
                "credential_profiles": [
                    {
                        "id": "smallholder_sd_jwt",
                        "format": FORMAT_SD_JWT_VC,
                        "issuer": "did:web:agriculture.demo.example.gov",
                        "vct": "https://demo.example.gov/credentials/smallholder-farmer/v1",
                        "validity_seconds": 86400,
                        "holder_binding": {
                            "mode": "did",
                            "proof_of_possession": "required",
                            "allowed_did_methods": [SD_JWT_VC_HOLDER_BINDING_METHOD]
                        },
                        "allowed_claims": ["farmer-under-4ha"],
                        "disclosure": {
                            "allowed": ["predicate"]
                        }
                    }
                ],
                "openid4vci": {
                    "support": "not_full_issuer"
                }
            },
            "unsupported_features": [
                "application/vc+sd-jwt",
                "json_ld_vc_issuance",
                "data_integrity_proofs",
                "credential_status",
                "mso_mdoc",
                "openid4vci_full_issuer"
            ]
        },
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
                "kid": "did:web:agriculture.demo.example.gov#registry-notary-demo-key-1"
            }
        ]
    })
}

fn oid4vci_issuer_metadata_example() -> Value {
    json!({
        "credential_issuer": "https://issuer.example.gov",
        "credential_endpoint": "https://issuer.example.gov/oid4vci/credential",
        "nonce_endpoint": "https://issuer.example.gov/oid4vci/nonce",
        "authorization_servers": ["https://id.example.gov"],
        "credential_configurations_supported": {
            "person_is_alive_sd_jwt": {
                "format": "dc+sd-jwt",
                "scope": "person_is_alive",
                "cryptographic_binding_methods_supported": ["did:jwk"],
                "credential_signing_alg_values_supported": ["EdDSA"],
                "proof_types_supported": {
                    "jwt": {
                        "proof_signing_alg_values_supported": ["EdDSA"]
                    }
                },
                "display": [
                    { "name": "Person is alive" }
                ],
                "vct": "https://issuer.example.gov/credentials/person-is-alive"
            }
        }
    })
}

fn oid4vci_credential_offer_example() -> Value {
    json!({
        "credential_issuer": "https://issuer.example.gov",
        "credential_configuration_ids": ["person_is_alive_sd_jwt"],
        "grants": {
            "authorization_code": {
                "issuer_state": "issuer-state",
                "authorization_server": "https://id.example.gov"
            }
        }
    })
}

fn oid4vci_nonce_example() -> Value {
    json!({
        "c_nonce": "b64url-nonce",
        "c_nonce_expires_in": 300
    })
}

fn oid4vci_credential_response_example() -> Value {
    json!({
        "credential": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRjK3NkLWp3dCJ9.payload.signature~disclosure~",
        "format": "dc+sd-jwt",
        "c_nonce": "next-b64url-nonce",
        "c_nonce_expires_in": 300
    })
}

fn oid4vci_error_example(code: &str, description: &str) -> Value {
    json!({
        "error": code,
        "error_description": description
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
            "application/vnd.registry-notary.claim-result+json",
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
        "evidence_type": "smallholder_farmer_evidence",
        "evidence_type_iri": "https://demo.example.gov/evidence-types/smallholder-farmer",
        "operations": {
            "evaluate": true,
            "batch_evaluate": true
        },
        "formats": [
            "application/vnd.registry-notary.claim-result+json",
            "application/ld+json; profile=\"cccev\"",
            "application/dc+sd-jwt"
        ],
        "disclosure": {
            "default": "predicate",
            "allowed": ["predicate", "redacted"],
            "downgrade": "deny"
        },
        "cccev": {
            "requirement_type": "InformationRequirement",
            "evidence_type": "smallholder_farmer_evidence",
            "evidence_type_iri": "https://demo.example.gov/evidence-types/smallholder-farmer"
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
            "id": "application/vnd.registry-notary.claim-result+json",
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
                "subject_ref": subject_ref_example(),
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
        "subject_ref": subject_ref_example(),
        "value": true,
        "satisfied": true,
        "disclosure": "predicate",
        "format": "application/vnd.registry-notary.claim-result+json",
        "issued_at": "2026-05-24T12:00:00Z",
        "expires_at": "2026-05-25T12:00:00Z",
        "provenance": provenance_example()
    })
}

fn subject_ref_example() -> Value {
    json!({
        "hash": "hmac-sha256:example-subject-ref-hash",
        "id_type": "national_id"
    })
}

fn provenance_example() -> Value {
    json!({
        "source_count": 1,
        "source_versions": {},
        "computed_by": "demo.registry-notary"
    })
}

fn credential_issue_example() -> Value {
    json!({
        "credential_id": "urn:registry-notary:credential:01HX7Y5F2WAJ7ZP0Q4M5K9E8NC",
        "credential_profile": "climate_smart_input_voucher_sd_jwt",
        "format": "application/dc+sd-jwt",
        "issuer": "did:web:agriculture.demo.example.gov",
        "expires_at": "2026-05-25T12:00:00Z",
        "credential": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRjK3NkLWp3dCIsImtpZCI6ImRpZDp3ZWI6YWdyaWN1bHR1cmUuZGVtby5leGFtcGxlLmdvdiNyZWdpc3RyeS13aXRuZXNzLWRlbW8ta2V5LTEifQ.eyJpc3MiOiJkaWQ6d2ViOmFncmljdWx0dXJlLmRlbW8uZXhhbXBsZS5nb3YiLCJzdWIiOiJkaWQ6andrOmV5SnJkSGtpT2lKUFMxQWlMQ0pqY25ZaU9pSkZaREkxTlRFNUlpd2llQ0k2SWpFeGNWbEJXVXQ0UTNKbVZsTmZNMWhFWWxoS1F6SkJaMWxKTlRkeFdIcGpVemRRTUZjMVdUbG1ORmtpZlEiLCJpYXQiOjE3Nzk2MjQwMDAsImV4cCI6MTc3OTcxMDQwMCwidmN0IjoiaHR0cHM6Ly9kZW1vLmV4YW1wbGUuZ292L2NyZWRlbnRpYWxzL3NtYWxsaG9sZGVyLWZhcm1lci92MSIsImp0aSI6InVybjpyZWdpc3RyeS13aXRuZXNzOmNyZWRlbnRpYWw6MDFIWDdZNUYyV0FKN1pQMFE0TTVLOUU4TkMiLCJpZCI6InVybjpyZWdpc3RyeS13aXRuZXNzOmNyZWRlbnRpYWw6MDFIWDdZNUYyV0FKN1pQMFE0TTVLOUU4TkMiLCJfc2QiOlsia0ZxYXpKcDdleVhjS1ZIX0tiMzNnQ1lwMGM3dzFDLWd0WjVORkJxbDdYcyJdLCJjbmYiOnsia2lkIjoiZGlkOmp3azpleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNklqRXhjVmxCV1V0NFEzSm1WbE5mTTFoRVlsaEtRekpCWjFsSk5UZHhXSHBqVXpkUU1GYzFXVGxtTkZraWZRIiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiMTFxWUFZS3hDcmZWU18zWERiWEpDMkFnWUk1N3FYemNTN1AwVzVZOWY0WSJ9fX0.c2lnbmF0dXJl~ZGlzY2xvc3VyZQ~",
        "issuer_signed_jwt": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRjK3NkLWp3dCIsImtpZCI6ImRpZDp3ZWI6YWdyaWN1bHR1cmUuZGVtby5leGFtcGxlLmdvdiNyZWdpc3RyeS13aXRuZXNzLWRlbW8ta2V5LTEifQ.eyJpc3MiOiJkaWQ6d2ViOmFncmljdWx0dXJlLmRlbW8uZXhhbXBsZS5nb3YiLCJzdWIiOiJkaWQ6andrOmV5SnJkSGtpT2lKUFMxQWlMQ0pqY25ZaU9pSkZaREkxTlRFNUlpd2llQ0k2SWpFeGNWbEJXVXQ0UTNKbVZsTmZNMWhFWWxoS1F6SkJaMWxKTlRkeFdIcGpVemRRTUZjMVdUbG1ORmtpZlEiLCJpYXQiOjE3Nzk2MjQwMDAsImV4cCI6MTc3OTcxMDQwMCwidmN0IjoiaHR0cHM6Ly9kZW1vLmV4YW1wbGUuZ292L2NyZWRlbnRpYWxzL3NtYWxsaG9sZGVyLWZhcm1lci92MSIsImp0aSI6InVybjpyZWdpc3RyeS13aXRuZXNzOmNyZWRlbnRpYWw6MDFIWDdZNUYyV0FKN1pQMFE0TTVLOUU4TkMiLCJpZCI6InVybjpyZWdpc3RyeS13aXRuZXNzOmNyZWRlbnRpYWw6MDFIWDdZNUYyV0FKN1pQMFE0TTVLOUU4TkMiLCJfc2QiOlsia0ZxYXpKcDdleVhjS1ZIX0tiMzNnQ1lwMGM3dzFDLWd0WjVORkJxbDdYcyJdLCJjbmYiOnsia2lkIjoiZGlkOmp3azpleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNklqRXhjVmxCV1V0NFEzSm1WbE5mTTFoRVlsaEtRekpCWjFsSk5UZHhXSHBqVXpkUU1GYzFXVGxtTkZraWZRIiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiMTFxWUFZS3hDcmZWU18zWERiWEpDMkFnWUk1N3FYemNTN1AwVzVZOWY0WSJ9fX0.c2lnbmF0dXJl",
        "disclosures": ["ZGlzY2xvc3VyZQ"]
    })
}

#[cfg(test)]
mod tests {
    use super::{openapi_document, set_response_example};
    use serde_json::json;

    #[test]
    fn documents_split_registry_notary_routes() {
        let doc = openapi_document();
        let paths = doc.paths.paths;
        for route in [
            "/healthz",
            "/ready",
            "/admin/v1/reload",
            "/openapi.json",
            "/.well-known/evidence-service",
            "/.well-known/evidence/jwks.json",
            "/.well-known/openid-credential-issuer",
            "/oid4vci/credential-offer",
            "/oid4vci/nonce",
            "/oid4vci/credential",
            "/v1/claims",
            "/v1/claims/{claim_id}",
            "/v1/formats",
            "/v1/evaluations",
            "/federation/v1/evaluations",
            "/v1/batch-evaluations",
            "/v1/evaluations/{evaluation_id}/render",
            "/v1/credentials",
            "/v1/credentials/{credential_id}/status",
            "/admin/v1/credentials/{credential_id}/status",
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
            doc["paths"]["/.well-known/openid-credential-issuer"]["get"]["security"],
            json!([])
        );
        assert_eq!(
            doc["paths"]["/oid4vci/credential-offer"]["get"]["security"],
            json!([])
        );
        assert_eq!(
            doc["paths"]["/oid4vci/nonce"]["post"]["security"],
            json!([])
        );
        assert_eq!(
            doc["paths"]["/federation/v1/evaluations"]["post"]["security"],
            json!([])
        );
        assert_eq!(
            doc["paths"]["/v1/credentials/{credential_id}/status"]["get"]["security"],
            json!([])
        );
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
            ("/admin/v1/reload", "post", "200"),
            ("/openapi.json", "get", "200"),
            ("/.well-known/evidence-service", "get", "200"),
            ("/.well-known/evidence/jwks.json", "get", "200"),
            ("/.well-known/openid-credential-issuer", "get", "200"),
            ("/oid4vci/credential-offer", "get", "200"),
            ("/oid4vci/nonce", "post", "200"),
            ("/oid4vci/credential", "post", "200"),
            ("/v1/claims", "get", "200"),
            ("/v1/claims/{claim_id}", "get", "200"),
            ("/v1/formats", "get", "200"),
            ("/v1/evaluations", "post", "200"),
            ("/v1/batch-evaluations", "post", "200"),
            ("/v1/evaluations/{evaluation_id}/render", "post", "200"),
            ("/v1/credentials", "post", "200"),
            ("/v1/credentials/{credential_id}/status", "get", "200"),
            (
                "/admin/v1/credentials/{credential_id}/status",
                "post",
                "200",
            ),
        ] {
            assert_json_example(&doc, path, method, status);
        }

        assert_eq!(
            doc["paths"]["/.well-known/evidence-service"]["get"]["responses"]["200"]["content"]
                ["application/json"]["example"]["service_id"],
            json!("demo.registry-notary")
        );
        assert_eq!(
            doc["paths"]["/v1/evaluations"]["post"]["responses"]["200"]["content"]
                ["application/json"]["example"]["results"][0]["claim_id"],
            json!("farmer-under-4ha")
        );
        assert_eq!(
            doc["paths"]["/v1/credentials"]["post"]["responses"]["200"]["content"]
                ["application/json"]["example"]["format"],
            json!("application/dc+sd-jwt")
        );
    }

    #[test]
    fn common_error_responses_have_problem_detail_examples() {
        let doc = serde_json::to_value(openapi_document()).expect("document serializes");
        for (path, method, status) in [
            ("/admin/v1/reload", "post", "401"),
            ("/admin/v1/reload", "post", "403"),
            ("/.well-known/evidence-service", "get", "401"),
            ("/.well-known/evidence/jwks.json", "get", "401"),
            ("/v1/claims", "get", "401"),
            ("/v1/claims/{claim_id}", "get", "401"),
            ("/v1/claims/{claim_id}", "get", "404"),
            ("/v1/formats", "get", "401"),
            ("/v1/evaluations", "post", "400"),
            ("/v1/evaluations", "post", "401"),
            ("/v1/evaluations", "post", "403"),
            ("/v1/evaluations", "post", "406"),
            ("/v1/evaluations", "post", "413"),
            ("/v1/evaluations", "post", "429"),
            ("/v1/evaluations", "post", "503"),
            ("/v1/batch-evaluations", "post", "400"),
            ("/v1/batch-evaluations", "post", "401"),
            ("/v1/batch-evaluations", "post", "403"),
            ("/v1/batch-evaluations", "post", "406"),
            ("/v1/batch-evaluations", "post", "409"),
            ("/v1/batch-evaluations", "post", "413"),
            ("/v1/batch-evaluations", "post", "429"),
            ("/v1/batch-evaluations", "post", "503"),
            ("/v1/evaluations/{evaluation_id}/render", "post", "400"),
            ("/v1/evaluations/{evaluation_id}/render", "post", "401"),
            ("/v1/evaluations/{evaluation_id}/render", "post", "404"),
            ("/v1/evaluations/{evaluation_id}/render", "post", "406"),
            ("/v1/evaluations/{evaluation_id}/render", "post", "413"),
            ("/v1/evaluations/{evaluation_id}/render", "post", "429"),
            ("/v1/evaluations/{evaluation_id}/render", "post", "503"),
            ("/v1/credentials", "post", "400"),
            ("/v1/credentials", "post", "401"),
            ("/v1/credentials", "post", "404"),
            ("/v1/credentials", "post", "406"),
            ("/v1/credentials", "post", "409"),
            ("/v1/credentials", "post", "413"),
            ("/v1/credentials", "post", "429"),
            ("/v1/credentials", "post", "503"),
            ("/v1/credentials/{credential_id}/status", "get", "404"),
            ("/v1/credentials/{credential_id}/status", "get", "503"),
            (
                "/admin/v1/credentials/{credential_id}/status",
                "post",
                "400",
            ),
            (
                "/admin/v1/credentials/{credential_id}/status",
                "post",
                "401",
            ),
            (
                "/admin/v1/credentials/{credential_id}/status",
                "post",
                "403",
            ),
            (
                "/admin/v1/credentials/{credential_id}/status",
                "post",
                "404",
            ),
            (
                "/admin/v1/credentials/{credential_id}/status",
                "post",
                "503",
            ),
        ] {
            assert_problem_example(&doc, path, method, status);
        }

        assert_eq!(
            doc["paths"]["/v1/claims/{claim_id}"]["get"]["responses"]["404"]["content"]
                ["application/problem+json"]["example"]["code"],
            json!("claim.not_found")
        );
        assert_eq!(
            doc["paths"]["/v1/evaluations/{evaluation_id}/render"]["post"]["responses"]["404"]
                ["content"]["application/problem+json"]["example"]["code"],
            json!("evaluation.not_found")
        );
    }

    #[test]
    fn oid4vci_routes_document_json_error_envelope() {
        let doc = serde_json::to_value(openapi_document()).expect("document serializes");
        assert_eq!(
            doc["components"]["schemas"]["CredentialIssuerMetadata"]["type"],
            json!("object")
        );
        assert_eq!(
            doc["components"]["schemas"]["CredentialRequest"]["type"],
            json!("object")
        );
        assert_eq!(
            doc["components"]["schemas"]["CredentialResponse"]["type"],
            json!("object")
        );
        assert_eq!(
            doc["paths"]["/oid4vci/credential"]["post"]["responses"]["400"]["content"]
                ["application/json"]["schema"]["$ref"],
            json!("#/components/schemas/Oid4vciError")
        );
        assert_eq!(
            doc["paths"]["/oid4vci/credential"]["post"]["description"],
            json!("Issues a dc+sd-jwt credential for an authenticated self-attestation principal. Error responses use the OpenID4VCI error envelope, not RFC 7807 Problem Details.")
        );
    }

    #[test]
    fn problem_responses_reference_shared_problem_details_schema() {
        let doc = serde_json::to_value(openapi_document()).expect("document serializes");
        assert!(doc["components"]["schemas"]["ProblemDetails"].is_object());

        for (path, method, status) in [
            ("/v1/evaluations", "post", "400"),
            ("/v1/evaluations", "post", "401"),
            ("/v1/evaluations", "post", "403"),
            ("/v1/credentials", "post", "404"),
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
                .is_some_and(|value| {
                    value.starts_with("https://docs.registry-notary.dev/problems/")
                }),
            "problem example must include a Registry Notary problem type for {method} {path} {status}"
        );
        assert!(
            example["code"].is_string(),
            "problem example must include a code for {method} {path} {status}"
        );
    }
}
