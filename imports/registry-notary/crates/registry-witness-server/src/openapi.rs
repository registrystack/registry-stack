// SPDX-License-Identifier: Apache-2.0
//! Registry Witness OpenAPI document generation.

use registry_witness_core::model::{
    BatchEvaluateRequest, CredentialIssueRequest, EvaluateRequest, HolderRequest, RenderRequest,
    SubjectRequest,
};
use serde_json::json;
use utoipa::openapi::OpenApi;
use utoipa::PartialSchema;

#[must_use]
pub fn openapi_document() -> OpenApi {
    let mut document: OpenApi = serde_json::from_value(json!({
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
    }))
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

#[cfg(test)]
mod tests {
    use super::openapi_document;
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
}
