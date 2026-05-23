// SPDX-License-Identifier: Apache-2.0
//! Registry Witness OpenAPI document generation.

use serde_json::json;
use utoipa::openapi::OpenApi;

#[must_use]
pub fn openapi_document() -> OpenApi {
    serde_json::from_value(json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Registry Witness API",
            "version": "0.1.0",
            "description": "Standalone claim evaluation, rendering, and credential issuance API."
        },
        "security": [
            { "apiKeyAuth": [] },
            { "bearerAuth": [] }
        ],
        "paths": {
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
            },
            "schemas": {
                "SubjectRequest": {
                    "type": "object",
                    "required": ["id"],
                    "additionalProperties": false,
                    "properties": {
                        "id": { "type": "string" },
                        "id_type": { "type": "string" }
                    }
                },
                "EvaluateRequest": {
                    "type": "object",
                    "required": ["subject", "claims"],
                    "additionalProperties": false,
                    "properties": {
                        "subject": { "$ref": "#/components/schemas/SubjectRequest" },
                        "claims": {
                            "type": "array",
                            "items": { "type": "string" }
                        },
                        "disclosure": { "type": "string" },
                        "format": { "type": "string" },
                        "purpose": { "type": "string" }
                    }
                },
                "BatchEvaluateRequest": {
                    "type": "object",
                    "required": ["subjects", "claims"],
                    "additionalProperties": false,
                    "properties": {
                        "subjects": {
                            "type": "array",
                            "items": { "$ref": "#/components/schemas/SubjectRequest" }
                        },
                        "claims": {
                            "type": "array",
                            "items": { "type": "string" }
                        },
                        "disclosure": { "type": "string" },
                        "format": { "type": "string" },
                        "purpose": { "type": "string" },
                        "prefer": { "type": "string" }
                    }
                },
                "RenderRequest": {
                    "type": "object",
                    "required": ["evaluation_id", "format"],
                    "additionalProperties": false,
                    "properties": {
                        "evaluation_id": { "type": "string" },
                        "format": { "type": "string" },
                        "disclosure": { "type": "string" },
                        "claims": {
                            "type": "array",
                            "items": { "type": "string" }
                        },
                        "purpose": { "type": "string" }
                    }
                },
                "CredentialIssueRequest": {
                    "type": "object",
                    "required": ["evaluation_id"],
                    "additionalProperties": false,
                    "properties": {
                        "evaluation_id": { "type": "string" },
                        "credential_profile": { "type": "string" },
                        "format": { "type": "string" },
                        "claims": {
                            "type": "array",
                            "items": { "type": "string" }
                        },
                        "disclosure": { "type": "string" },
                        "holder": {
                            "type": "object",
                            "additionalProperties": false,
                            "properties": {
                                "binding": { "type": "string" },
                                "id": { "type": "string" },
                                "proof": { "type": "string" }
                            }
                        }
                    }
                }
            }
        }
    }))
    .expect("static Registry Witness OpenAPI document is valid")
}

#[cfg(test)]
mod tests {
    use super::openapi_document;

    #[test]
    fn documents_split_registry_witness_routes() {
        let doc = openapi_document();
        let paths = doc.paths.paths;
        for route in [
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
}
