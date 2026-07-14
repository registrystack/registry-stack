// SPDX-License-Identifier: Apache-2.0
//! Registry Notary OpenAPI document generation.

use registry_notary_core::model::{
    ClaimRef, CredentialIssueRequest, HolderRequest, RenderEvaluationRequest, FORMAT_SD_JWT_VC,
    SD_JWT_VC_HOLDER_BINDING_METHOD, SD_JWT_VC_ISSUER_KEY_TYPE, SD_JWT_VC_JWT_TYP,
    SD_JWT_VC_SIGNING_ALG,
};
use serde_json::{json, Value};
use std::sync::OnceLock;
use utoipa::openapi::OpenApi;
use utoipa::PartialSchema;

const INFO_SUMMARY: &str =
    "Standalone evidence evaluation, rendering, and credential issuance service.";
const CONTACT_NAME: &str = "Registry Notary owning team";

#[must_use]
pub fn openapi_document() -> &'static Value {
    static DOCUMENT: OnceLock<Value> = OnceLock::new();

    DOCUMENT.get_or_init(build_openapi_document)
}

fn build_openapi_document() -> Value {
    let mut raw_document = json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Registry Notary API",
            "summary": INFO_SUMMARY,
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Standalone claim evaluation, rendering, and credential issuance API.",
            "contact": {
                "name": CONTACT_NAME
            },
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
                        "503": { "description": "Evidence runtime is not ready or is degraded" }
                    }
                }
            },
            "/admin/v1/reload": {
                "post": {
                    "summary": "Report unsupported runtime reload",
                    "description": "Standalone mode does not support runtime configuration reload. Operators should call /admin/v1/capabilities before invoking product-specific reload operations.",
                    "operationId": "adminReload",
                    "security": [
                        { "apiKeyAuth": [] },
                        { "bearerAuth": [] }
                    ],
                    "responses": {
                        "501": { "description": "Runtime configuration reload is not supported" },
                        "401": { "description": "Missing or invalid credential" },
                        "403": { "description": "Caller lacks registry_notary:admin scope" }
                    }
                }
            },
            "/admin/v1/capabilities": {
                "get": {
                    "summary": "Discover authenticated admin capabilities",
                    "description": "Returns redacted product capability metadata for posture and supported admin operations.",
                    "operationId": "adminCapabilities",
                    "security": [
                        { "apiKeyAuth": [] },
                        { "bearerAuth": [] }
                    ],
                    "responses": {
                        "200": { "description": "Admin capabilities for this product runtime" },
                        "401": { "description": "Missing or invalid credential" },
                        "403": { "description": "Caller lacks registry_notary:ops_read scope" }
                    }
                }
            },
            "/admin/v1/posture": {
                "get": {
                    "summary": "Read redacted runtime posture",
                    "description": "Returns redacted runtime posture for the requested tier. The response body is a registry.ops.posture.v1 document describing instance, configuration, notary, deployment, and audit posture.",
                    "operationId": "adminPosture",
                    "security": [
                        { "apiKeyAuth": [] },
                        { "bearerAuth": [] }
                    ],
                    "parameters": [
                        {
                            "name": "tier",
                            "in": "query",
                            "required": false,
                            "description": "Redaction tier for the posture document. Defaults to default.",
                            "schema": { "type": "string", "enum": ["default", "restricted"] }
                        }
                    ],
                    "responses": {
                        "200": { "description": "Redacted posture for the requested tier" },
                        "400": { "description": "Posture tier is invalid" },
                        "401": { "description": "Missing or invalid credential" },
                        "403": { "description": "Caller lacks registry_notary:ops_read scope" },
                        "500": { "description": "Posture could not be filtered for the requested tier" },
                        "503": { "description": "Posture state is unavailable" }
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
                    "description": "Returns public issuer verification keys for wallet and verifier discovery. This well-known route is intentionally unauthenticated; it only exposes public JWK members.",
                    "security": [],
                    "responses": {
                        "200": { "description": "Public JWKS" }
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
            "/credentials/{vct_path}": {
                "x-registry-notary-catch-all": true,
                "get": {
                    "summary": "Fetch SD-JWT VC Type Metadata",
                    "operationId": "getSdJwtVcTypeMetadata",
                    "description": "Returns public SD-JWT VC Type Metadata for a configured OID4VCI credential configuration whose vct exactly matches the requested absolute URL. The path key uses the OpenAPI single-segment form {vct_path} for standard tooling compatibility, but the route is a multi-segment catch-all: vct_path captures the full path remainder after /credentials/ (slashes included, not percent-encoded) and may span multiple segments. This route is intentionally unversioned and must remain at /credentials/{vct_path} (without a /v1/ prefix): per SD-JWT VC type-metadata dereference, a client resolves the credential type by dereferencing the vct claim directly (for example, https://{host}/credentials/{vct_path}), so the server path must match the vct URL path component exactly. Adding a /v1/ prefix would break dereference for any credential whose vct does not include that prefix. This route serves type metadata only and is unrelated to POST /v1/credentials (credential issuance).",
                    "security": [],
                    "parameters": [
                        {
                            "name": "vct_path",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string",
                                "pattern": "^[^/]+(/[^/]+)*$"
                            },
                            "description": "Full path remainder after /credentials/ captured as a multi-segment catch-all. The value is the unencoded path suffix of the VCT URL (slashes not percent-encoded) and may contain one or more segments."
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "SD-JWT VC Type Metadata",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/SdJwtVcTypeMetadata" }
                                }
                            }
                        },
                        "404": { "description": "OpenID4VCI issuer is disabled or no configured vct matches the requested URL" }
                    }
                }
            },
            "/.well-known/vct/{vct_path}": {
                "x-registry-notary-catch-all": true,
                "get": {
                    "summary": "Fetch SD-JWT VC Type Metadata at the well-known location",
                    "operationId": "getWellKnownSdJwtVcTypeMetadata",
                    "description": "Returns public SD-JWT VC Type Metadata at the SD-JWT VC well-known location. Consumers dereference an HTTPS vct by inserting /.well-known/vct between the host and the path; the server strips that prefix and matches the reconstructed vct (https://{host}/{vct_path}) against a configured OID4VCI credential configuration. The path key uses the OpenAPI single-segment form {vct_path} for standard tooling compatibility, but the route is a multi-segment catch-all: vct_path captures the full path remainder (slashes included, not percent-encoded) and may span multiple segments. This route is intentionally unversioned and must remain at /.well-known/vct/{vct_path}: per RFC 8615 well-known URI semantics, the path prefix is determined by the protocol and cannot be changed. Adding a /v1/ prefix would violate the well-known URI convention. This route serves type metadata only and is unrelated to POST /v1/credentials (credential issuance).",
                    "security": [],
                    "parameters": [
                        {
                            "name": "vct_path",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string",
                                "pattern": "^[^/]+(/[^/]+)*$"
                            },
                            "description": "Full path remainder after /.well-known/vct/ captured as a multi-segment catch-all. The value is the unencoded path suffix of the VCT URL (slashes not percent-encoded) and may contain one or more segments."
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "SD-JWT VC Type Metadata",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/SdJwtVcTypeMetadata" }
                                }
                            }
                        },
                        "404": { "description": "OpenID4VCI issuer is disabled or no configured vct matches the reconstructed URL" }
                    }
                }
            },
            "/oid4vci/credential-offer": {
                "get": {
                    "summary": "Create an OpenID4VCI credential offer",
                    "operationId": "getOid4vciCredentialOffer",
                    "description": "Returns an authorization-code credential offer. Error responses use the OpenID4VCI error envelope, not RFC 9457 Problem Details.",
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
                    "description": "Returns a c_nonce for proof-of-possession. Error responses use the OpenID4VCI error envelope, not RFC 9457 Problem Details.",
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
                    "description": "Issues a dc+sd-jwt credential for an authenticated self-attestation principal. Error responses use the OpenID4VCI error envelope, not RFC 9457 Problem Details.",
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
            "/oid4vci/offer/start": {
                "get": {
                    "summary": "Begin an authenticated pre-authorized-code offer",
                    "operationId": "startOid4vciOffer",
                    "description": "Public and unauthenticated. Begins the eSignet authorization-code login as the confidential RP and 302-redirects the browser to eSignet. Mints no pre-authorized_code or credential material. Returns 404 when the pre-authorized-code flow is disabled. Error responses use the OpenID4VCI error envelope, not RFC 9457 Problem Details.",
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
                        "303": { "description": "Redirect to the eSignet authorization endpoint" },
                        "400": {
                            "description": "Invalid or unknown credential configuration",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/Oid4vciError" }
                                }
                            }
                        },
                        "404": { "description": "Pre-authorized-code flow is disabled" },
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
            "/oid4vci/offer/callback": {
                "get": {
                    "summary": "Complete eSignet login and render a pre-authorized-code offer",
                    "operationId": "completeOid4vciOffer",
                    "description": "Public and unauthenticated. Consumes the login state, exchanges the eSignet code with private_key_jwt, validates the id_token, and mints one single-use pre-authorized_code. When configured, the offer also includes one numeric tx_code (PIN) shown out-of-band from the QR. Returns 404 when the pre-authorized-code flow is disabled.",
                    "security": [],
                    "parameters": [
                        {
                            "name": "code",
                            "in": "query",
                            "required": true,
                            "schema": { "type": "string" }
                        },
                        {
                            "name": "state",
                            "in": "query",
                            "required": true,
                            "schema": { "type": "string" }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Offer page with the credential offer URI and optional tx_code PIN",
                            "content": {
                                "text/html": {
                                    "schema": { "type": "string" }
                                }
                            }
                        },
                        "400": {
                            "description": "Login state, eSignet code, or id_token is invalid",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/Oid4vciError" }
                                }
                            }
                        },
                        "404": { "description": "Pre-authorized-code flow is disabled" },
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
            "/oid4vci/token": {
                "post": {
                    "summary": "Redeem a pre-authorized-code for an access token",
                    "operationId": "redeemOid4vciToken",
                    "description": "Public and unauthenticated OID4VCI token endpoint for the pre-authorized-code grant. Accepts only grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code with a valid, unexpired, single-use pre-authorized_code. A matching tx_code is required when the credential offer includes a tx_code object. Mints a short-TTL Notary-signed access token plus a c_nonce. Returns 404 when the pre-authorized-code flow is disabled. Error responses use the OpenID4VCI error envelope, not RFC 9457 Problem Details.",
                    "security": [],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/x-www-form-urlencoded": {
                                "schema": { "$ref": "#/components/schemas/TokenRequest" }
                            },
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/TokenRequest" }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Token response",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/TokenResponse" }
                                }
                            }
                        },
                        "400": {
                            "description": "Invalid request, grant, or tx_code",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/Oid4vciError" }
                                }
                            }
                        },
                        "404": { "description": "Pre-authorized-code flow is disabled" },
                        "429": {
                            "description": "Too many token attempts (wrong-PIN lockout or random-code flood)",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/Oid4vciError" }
                                }
                            }
                        },
                        "500": {
                            "description": "Token issuance failed",
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
                    "summary": "Evaluate claims for one target",
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
                        "429": { "description": "Self-attestation request is rate limited, or the machine evaluation quota was exceeded" },
                        "503": { "description": "Required Relay consultation or operational dependency is unavailable" }
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
                        "403": { "description": "Peer, profile, purpose, or requester/target identity path is not allowed" },
                        "409": { "description": "Request replay detected" },
                        "413": { "description": "Request body is too large" },
                        "415": { "description": "Content type is not application/jwt" },
                        "503": { "description": "An operational dependency required for a fail-closed response is unavailable" }
                    }
                }
            },
            "/v1/batch-evaluations": {
                "post": {
                    "summary": "Evaluate claims for multiple request items inline",
                    "operationId": "batchEvaluateClaims",
                    "parameters": [
                        {
                            "name": "Idempotency-Key",
                            "in": "header",
                            "required": false,
                            "description": "Required for every registry-backed batch. The value is caller-bound and may contain 1 to 256 bytes.",
                            "schema": { "type": "string", "minLength": 1, "maxLength": 256 }
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
                        "200": { "description": "Per-item claim evaluation results" },
                        "400": { "description": "Invalid request, including a registry-backed batch without a valid Idempotency-Key or an item that fails whole-batch preflight" },
                        "401": { "description": "Missing or invalid credential" },
                        "403": { "description": "Not authorized for requested claim, purpose, disclosure, or format" },
                        "406": { "description": "Requested format is not acceptable" },
                        "409": { "description": "Idempotency key conflicts with another request body" },
                        "413": { "description": "Request body or batch is too large" },
                        "429": { "description": "Self-attestation request is rate limited, or the machine evaluation quota was exceeded" },
                        "503": { "description": "Required Relay consultation or operational dependency is unavailable" }
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
                        "503": { "description": "Required Relay consultation or operational dependency is unavailable" }
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
                        "409": { "description": "Holder proof replay or Relay ambiguity conflict" },
                        "413": { "description": "Request body is too large" },
                        "429": { "description": "Self-attestation request is rate limited" },
                        "503": { "description": "Required Relay consultation or operational dependency is unavailable" }
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
                    "security": [
                        { "apiKeyAuth": [] },
                        { "bearerAuth": [] }
                    ],
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
                "SdJwtVcTypeMetadata": sd_jwt_vc_type_metadata_schema(),
                "CredentialOffer": credential_offer_schema(),
                "NonceRequest": nonce_request_schema(),
                "NonceResponse": nonce_response_schema(),
                "CredentialRequest": credential_request_schema(),
                "CredentialResponse": credential_response_schema(),
                "TokenRequest": token_request_schema(),
                "TokenResponse": token_response_schema(),
                "Oid4vciError": oid4vci_error_schema()
            },
            "securitySchemes": {
                "apiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-Api-Key"
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
        .insert("ClaimRef".to_string(), ClaimRef::schema());
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
    let schema_overrides = [
        ("ClaimRef", claim_ref_schema()),
        ("EvaluateRequest", evaluate_request_schema()),
        ("BatchEvaluateRequest", batch_evaluate_request_schema()),
        (
            "BatchEvaluateItemRequest",
            batch_evaluate_item_request_schema(),
        ),
        ("EvidenceEntity", evidence_entity_schema()),
        ("EvidenceIdentifier", evidence_identifier_schema()),
        ("EvidenceAssurance", evidence_assurance_schema()),
        ("EvidenceRelationship", evidence_relationship_schema()),
        ("EvidenceOnBehalfOf", evidence_on_behalf_of_schema()),
        ("EvidenceActor", evidence_actor_schema()),
        ("ReadinessResponse", readiness_response_schema()),
        ("ReadinessChecks", readiness_checks_schema()),
        (
            "SigningProviderReadinessChecks",
            signing_provider_readiness_checks_schema(),
        ),
        ("SignerCustodyChecks", signer_custody_checks_schema()),
        ("SignerCustodySurfaces", signer_custody_surfaces_schema()),
        ("SignerSurfaceChecks", signer_surface_checks_schema()),
        (
            "EnabledSignerSurfaceChecks",
            enabled_signer_surface_checks_schema(),
        ),
        ("ReadinessProblem", readiness_problem_schema()),
        ("ListClaimsResponse", list_claims_response_schema()),
        ("ClaimSummary", claim_summary_schema()),
        ("ClaimSemantics", claim_semantics_schema()),
        ("ClaimTargetInputMethod", claim_target_input_method_schema()),
        ("ClaimTargetInputGroup", claim_target_input_group_schema()),
        ("ClaimTargetInput", claim_target_input_schema()),
        ("EvaluationResponse", evaluation_response_schema()),
        ("ClaimResultView", claim_result_view_schema()),
        ("BatchEvaluateResponse", batch_evaluate_response_schema()),
        ("BatchItemResponse", batch_item_response_schema()),
        ("BatchClaimResultView", batch_claim_result_view_schema()),
        ("BatchItemError", batch_item_error_schema()),
        ("BatchSummary", batch_summary_schema()),
        ("ClaimProvenance", claim_provenance_schema()),
        ("ProvenanceGeneratedBy", provenance_generated_by_schema()),
        ("ProvenanceUsed", provenance_used_schema()),
        ("TargetRefView", target_ref_view_schema()),
        ("EvidenceEntityRef", evidence_entity_ref_schema()),
    ];
    for (name, schema) in schema_overrides.iter() {
        document_value["components"]["schemas"][*name] = schema.clone();
    }
    set_json_response_schema(
        &mut document_value,
        "/ready",
        "get",
        "200",
        "#/components/schemas/ReadinessResponse",
    );
    set_problem_response_schema(
        &mut document_value,
        "/ready",
        "get",
        "503",
        "#/components/schemas/ReadinessProblem",
    );
    set_json_response_schema(
        &mut document_value,
        "/v1/claims",
        "get",
        "200",
        "#/components/schemas/ListClaimsResponse",
    );
    set_json_response_schema(
        &mut document_value,
        "/v1/claims/{claim_id}",
        "get",
        "200",
        "#/components/schemas/ClaimSummary",
    );
    set_json_response_schema(
        &mut document_value,
        "/v1/evaluations",
        "post",
        "200",
        "#/components/schemas/EvaluationResponse",
    );
    set_json_response_schema(
        &mut document_value,
        "/v1/batch-evaluations",
        "post",
        "200",
        "#/components/schemas/BatchEvaluateResponse",
    );
    set_json_response_schema(
        &mut document_value,
        "/v1/evaluations/{evaluation_id}/render",
        "post",
        "200",
        "#/components/schemas/EvaluationResponse",
    );
    document_value["info"]["summary"] = json!(INFO_SUMMARY);
    document_value["info"]["contact"] = json!({ "name": CONTACT_NAME });
    serde_json::from_value::<OpenApi>(document_value.clone()).unwrap_or_else(|err| {
        let base_document_value =
            serde_json::to_value(&document).expect("Registry Notary OpenAPI document serializes");
        for (name, schema) in schema_overrides {
            let mut probe = base_document_value.clone();
            probe["components"]["schemas"][name] = schema;
            if let Err(schema_err) = serde_json::from_value::<OpenApi>(probe) {
                panic!("Registry Notary OpenAPI {name} schema is valid: {schema_err}");
            }
        }
        panic!("Registry Notary OpenAPI schema overrides are valid: {err}");
    });
    document_value
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
                "degraded": 0,
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
                "total": 3,
                "ok": 3,
                "degraded": 0,
                "failed": 0,
                "signing_providers": {
                    "total": 1,
                    "ok": 1,
                    "failed": 0,
                    "custody": {
                        "active_provider_counts": {
                            "pkcs11": 1
                        },
                        "signing_provider_count": 1,
                        "local_software_signing_provider_count": 0,
                        "custody_approval_required": true,
                        "custody_approved": true,
                        "unapproved_signing_provider_count": 0,
                        "surfaces": {
                            "credential_issuance": {
                                "signing_provider_count": 1,
                                "local_software_signing_provider_count": 0,
                                "unapproved_signing_provider_count": 0
                            },
                            "access_token_issuance": {
                                "enabled": false,
                                "signing_provider_count": 0,
                                "local_software_signing_provider_count": 0,
                                "unapproved_signing_provider_count": 0
                            },
                            "federation": {
                                "enabled": false,
                                "signing_provider_count": 0,
                                "local_software_signing_provider_count": 0,
                                "unapproved_signing_provider_count": 0
                            }
                        }
                    }
                },
                "relay": {
                    "total": 1,
                    "ok": 1,
                    "failed": 0
                }
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
    set_problem_response(
        document,
        "/ready",
        "get",
        "503",
        "Evidence runtime is not ready or is degraded",
        json!({
            "type": format!("{}/readiness/not-ready", crate::PROBLEM_TYPE_BASE_URL),
            "title": "Evidence runtime is not ready",
            "status": 503,
            "detail": "one or more readiness checks are not ready",
            "code": "readiness.not_ready",
            "request_id": "01J00000000000000000000000",
            "readiness_status": "not_ready",
            "checks": {
                "total": 3,
                "ok": 1,
                "degraded": 1,
                "failed": 1,
                "signing_providers": {
                    "total": 1,
                    "ok": 1,
                    "failed": 0,
                    "custody": {
                        "active_provider_counts": {
                            "local_jwk_env": 1
                        },
                        "signing_provider_count": 1,
                        "local_software_signing_provider_count": 1,
                        "custody_approval_required": true,
                        "custody_approved": false,
                        "unapproved_signing_provider_count": 1,
                        "surfaces": {
                            "credential_issuance": {
                                "signing_provider_count": 1,
                                "local_software_signing_provider_count": 1,
                                "unapproved_signing_provider_count": 1
                            },
                            "access_token_issuance": {
                                "enabled": false,
                                "signing_provider_count": 0,
                                "local_software_signing_provider_count": 0,
                                "unapproved_signing_provider_count": 0
                            },
                            "federation": {
                                "enabled": false,
                                "signing_provider_count": 0,
                                "local_software_signing_provider_count": 0,
                                "unapproved_signing_provider_count": 0
                            }
                        }
                    }
                },
                "relay": {
                    "total": 1,
                    "ok": 0,
                    "failed": 1
                }
            }
        }),
    );
    set_problem_response(
        document,
        "/admin/v1/reload",
        "post",
        "501",
        "Runtime configuration reload is not supported",
        admin_error_example(
            501,
            "registry.admin.capability.not_supported",
            "Admin capability not supported",
            "registry-notary standalone runtime does not support reload",
        ),
    );
    set_json_response(
        document,
        "/admin/v1/capabilities",
        "get",
        "200",
        "Admin capabilities for this product runtime",
        json!({
            "schema": "registry.admin.capabilities.v1",
            "product": "registry-notary",
            "admin_api_version": "v1",
            "supported_posture_tiers": ["default", "restricted"],
            "config": {
                "verify": {
                    "supported": false,
                    "currently_available": false
                },
                "dry_run": {
                    "supported": false,
                    "currently_available": false
                },
                "apply": {
                    "supported": false,
                    "currently_available": false,
                    "supported_sources": [],
                    "requires_signed_input": true
                }
            },
            "break_glass": {
                "supported": false,
                "currently_available": false,
                "rate_limit_scope": "none"
            },
            "listeners": {
                "admin": {
                    "mode": "shared_with_public",
                    "public_admin_routes": true
                },
                "metrics": {
                    "mode": "shared_with_public",
                    "requires_admin_scope": false,
                    "required_scope": "registry_notary:metrics_read"
                }
            },
            "root_transition": {
                "supported": false,
                "currently_available": false
            },
            "hot_swap": {
                "supported": false,
                "currently_available": false,
                "components": []
            },
            "reload": {
                "resource_reload": {
                    "supported": false,
                    "currently_available": false
                },
                "table_reload": {
                    "supported": false,
                    "currently_available": false
                },
                "config_reload": {
                    "supported": false,
                    "currently_available": false
                }
            }
        }),
    );
    set_problem_response(
        document,
        "/admin/v1/capabilities",
        "get",
        "401",
        "Missing or invalid credential",
        missing_credential_example(),
    );
    set_problem_response(
        document,
        "/admin/v1/capabilities",
        "get",
        "403",
        "Caller lacks registry_notary:ops_read scope",
        problem_example(
            403,
            "auth.scope_denied",
            "Scope denied",
            "missing required scope",
        ),
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
        "/admin/v1/posture",
        "get",
        "200",
        "Redacted posture for the requested tier",
        serde_json::from_str(registry_platform_ops::NOTARY_POSTURE_EXAMPLE_V1)
            .expect("notary posture example is valid JSON"),
    );
    set_problem_response(
        document,
        "/admin/v1/posture",
        "get",
        "400",
        "Posture tier is invalid",
        admin_error_example(
            400,
            "registry.admin.posture.invalid_tier",
            "Admin posture tier invalid",
            "posture tier must be default or restricted",
        ),
    );
    set_problem_response(
        document,
        "/admin/v1/posture",
        "get",
        "401",
        "Missing or invalid credential",
        missing_credential_example(),
    );
    set_problem_response(
        document,
        "/admin/v1/posture",
        "get",
        "403",
        "Caller lacks registry_notary:ops_read scope",
        problem_example(
            403,
            "auth.scope_denied",
            "Scope denied",
            "missing required scope",
        ),
    );
    set_problem_response(
        document,
        "/admin/v1/posture",
        "get",
        "500",
        "Posture could not be filtered for the requested tier",
        problem_example(
            500,
            "posture.filter_failed",
            "Admin posture unavailable",
            "admin posture could not be filtered for the requested tier",
        ),
    );
    set_problem_response(
        document,
        "/admin/v1/posture",
        "get",
        "503",
        "Posture state is unavailable",
        admin_error_example(
            503,
            "posture.unavailable",
            "Admin posture unavailable",
            "posture state is unavailable",
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
        "/credentials/{vct_path}",
        "get",
        "200",
        "SD-JWT VC Type Metadata",
        sd_jwt_vc_type_metadata_example(),
    );
    set_json_response(
        document,
        "/.well-known/vct/{vct_path}",
        "get",
        "200",
        "SD-JWT VC Type Metadata",
        sd_jwt_vc_type_metadata_example(),
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
        "/oid4vci/token",
        "post",
        "200",
        "Token response",
        oid4vci_token_response_example(),
    );
    for (status, code, description) in [
        (
            "400",
            "invalid_grant",
            "pre-authorized code or tx_code is invalid",
        ),
        ("429", "slow_down", "too many token requests"),
        ("500", "server_error", "token issuance failed"),
    ] {
        set_oid4vci_error_response(
            document,
            "/oid4vci/token",
            "post",
            status,
            match status {
                "400" => "Invalid request, grant, or tx_code",
                "429" => "Too many token attempts (wrong-PIN lockout or random-code flood)",
                _ => "Token issuance failed",
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
        "Per-item claim evaluation results",
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
        "type": "object",
        "description": "Claim reference. Wire requests may also use a plain string claim id.",
        "required": ["id"],
        "properties": {
            "id": { "type": "string" },
            "version": { "type": "string" }
        },
        "additionalProperties": false
    })
}

fn evaluate_request_schema() -> Value {
    json!({
        "type": "object",
        "required": ["claims"],
        "properties": {
            "requester": { "$ref": "#/components/schemas/EvidenceEntity" },
            "target": { "$ref": "#/components/schemas/EvidenceEntity" },
            "relationship": { "$ref": "#/components/schemas/EvidenceRelationship" },
            "on_behalf_of": { "$ref": "#/components/schemas/EvidenceOnBehalfOf" },
            "variables": {
                "type": "object",
                "maxProperties": 16,
                "propertyNames": {
                    "type": "string",
                    "maxLength": 96,
                    "pattern": "^[a-z][a-z0-9_]{0,95}$"
                },
                "additionalProperties": {
                    "type": "string",
                    "format": "date",
                    "minLength": 10,
                    "maxLength": 10
                }
            },
            "claims": {
                "type": "array",
                "items": { "$ref": "#/components/schemas/ClaimRef" }
            },
            "disclosure": { "type": "string" },
            "format": { "type": "string" },
            "purpose": { "type": "string" }
        },
        "additionalProperties": false
    })
}

fn batch_evaluate_request_schema() -> Value {
    json!({
        "type": "object",
        "required": ["items", "claims"],
        "properties": {
            "items": {
                "type": "array",
                "items": { "$ref": "#/components/schemas/BatchEvaluateItemRequest" }
            },
            "claims": {
                "type": "array",
                "items": { "$ref": "#/components/schemas/ClaimRef" }
            },
            "disclosure": { "type": "string" },
            "format": { "type": "string" },
            "purpose": { "type": "string" }
        },
        "additionalProperties": false
    })
}

fn batch_evaluate_item_request_schema() -> Value {
    json!({
        "type": "object",
        "required": ["target"],
        "properties": {
            "requester": { "$ref": "#/components/schemas/EvidenceEntity" },
            "target": { "$ref": "#/components/schemas/EvidenceEntity" },
            "relationship": { "$ref": "#/components/schemas/EvidenceRelationship" },
            "on_behalf_of": { "$ref": "#/components/schemas/EvidenceOnBehalfOf" },
            "purpose": { "type": "string" }
        },
        "additionalProperties": false
    })
}

fn evidence_entity_schema() -> Value {
    json!({
        "type": "object",
        "required": ["type"],
        "properties": {
            "type": { "type": "string" },
            "id": { "type": "string" },
            "identifiers": {
                "type": "array",
                "items": { "$ref": "#/components/schemas/EvidenceIdentifier" }
            },
            "attributes": {
                "type": "object",
                "additionalProperties": true
            },
            "assurance": { "$ref": "#/components/schemas/EvidenceAssurance" },
            "profile": { "type": "string" }
        },
        "additionalProperties": false
    })
}

fn evidence_identifier_schema() -> Value {
    json!({
        "type": "object",
        "required": ["scheme", "value"],
        "properties": {
            "scheme": { "type": "string" },
            "value": { "type": "string" },
            "issuer": { "type": "string" },
            "country": { "type": "string" }
        },
        "additionalProperties": false
    })
}

fn evidence_assurance_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "method": { "type": "string" },
            "level_scheme": { "type": "string" },
            "level": { "type": "string" },
            "verified_at": { "type": "string", "format": "date-time" },
            "issuer": { "type": "string" },
            "evidence": {
                "type": "array",
                "items": { "type": "object", "additionalProperties": true }
            }
        },
        "additionalProperties": false
    })
}

fn evidence_relationship_schema() -> Value {
    json!({
        "type": "object",
        "required": ["type"],
        "properties": {
            "type": { "type": "string" },
            "attributes": {
                "type": "object",
                "additionalProperties": true
            }
        },
        "additionalProperties": false
    })
}

fn evidence_on_behalf_of_schema() -> Value {
    json!({
        "type": "object",
        "description": "Frozen minimal actor/delegation envelope. Replaces the previous free-form object; free-form payloads are rejected. Simple deployments omit on_behalf_of entirely. Production-grade delegation (OAuth token exchange / RAR / CIBA) arrives post-1.0 as an additive profile that maps the actor onto OAuth act-claim semantics via the opaque delegation_ref; the shape does not bake in a single-actor assumption.",
        "required": ["actor"],
        "properties": {
            "actor": { "$ref": "#/components/schemas/EvidenceActor" },
            "delegation_ref": {
                "type": "string",
                "description": "Opaque reference to an out-of-band delegation record. Not interpreted by the envelope; the indirection point through which a later OAuth profile resolves an actor chain."
            }
        },
        "additionalProperties": false
    })
}

fn evidence_actor_schema() -> Value {
    json!({
        "type": "object",
        "required": ["type", "id_hash"],
        "properties": {
            "type": { "type": "string" },
            "id_hash": {
                "type": "string",
                "description": "Keyed-hash identifier of the actor in hmac-sha256:<hex> format. Never a raw principal value."
            },
            "assurance": {
                "type": "string",
                "description": "Optional assurance level of the actor (for example an acr value)."
            }
        },
        "additionalProperties": false
    })
}

fn list_claims_response_schema() -> Value {
    json!({
        "type": "object",
        "required": ["data"],
        "properties": {
            "data": {
                "type": "array",
                "items": { "$ref": "#/components/schemas/ClaimSummary" }
            }
        },
        "additionalProperties": false
    })
}

fn claim_summary_schema() -> Value {
    json!({
        "type": "object",
        "required": ["id", "title", "version", "subject_type", "operations", "formats", "disclosure"],
        "properties": {
            "id": { "type": "string" },
            "title": { "type": "string" },
            "version": { "type": "string" },
            "subject_type": { "type": "string" },
            "evidence_type": { "type": "string" },
            "evidence_type_iri": { "type": "string", "format": "uri" },
            "semantics": { "$ref": "#/components/schemas/ClaimSemantics" },
            "operations": {
                "type": "object",
                "required": ["evaluate", "batch_evaluate"],
                "properties": {
                    "evaluate": { "type": "boolean" },
                    "batch_evaluate": { "type": "boolean" }
                },
                "additionalProperties": false
            },
            "formats": {
                "type": "array",
                "items": { "type": "string" }
            },
            "disclosure": {
                "type": "object",
                "required": ["default", "allowed", "downgrade"],
                "properties": {
                    "default": { "type": "string" },
                    "allowed": {
                        "type": "array",
                        "items": { "type": "string" }
                    },
                    "downgrade": { "type": "string" }
                },
                "additionalProperties": false
            },
            "target_inputs": {
                "type": "array",
                "description": "Safe request-input metadata for building evaluation targets. It exposes target-side paths and matching method labels, never upstream connection, dataset, entity, or field details.",
                "items": { "$ref": "#/components/schemas/ClaimTargetInputMethod" }
            },
            "cccev": {
                "oneOf": [
                    { "type": "null" },
                    { "type": "object", "additionalProperties": true }
                ]
            },
            "oots": {
                "oneOf": [
                    { "type": "null" },
                    { "type": "object", "additionalProperties": true }
                ]
            }
        },
        "additionalProperties": true
    })
}

fn claim_semantics_schema() -> Value {
    json!({
        "type": "object",
        "description": "Optional semantic binding for a Notary claim. These fields label the claim output or predicate with external vocabulary terms such as PublicSchema URIs; they do not change the Notary result shape or by themselves prove privacy minimization.",
        "properties": {
            "concept": {
                "type": "string",
                "description": "External concept URI, for example https://publicschema.org/Person."
            },
            "property": {
                "type": "string",
                "description": "External property URI for raw value claims, for example https://publicschema.org/date_of_birth."
            },
            "vocabulary": {
                "type": "string",
                "description": "External vocabulary or value-set URI used by the claim value."
            },
            "predicate": {
                "type": "string",
                "description": "External or local predicate URI/URN for derived boolean claims."
            },
            "derived_from": {
                "type": "array",
                "items": { "type": "string" },
                "description": "External property URIs the predicate or derived value depends on."
            },
            "value_mapping": {
                "type": "string",
                "description": "Operator label for the value mapping/canonicalization applied before returning the claim."
            }
        },
        "additionalProperties": false
    })
}

fn claim_target_input_method_schema() -> Value {
    json!({
        "type": "object",
        "required": ["target_type", "method", "confidence", "groups"],
        "properties": {
            "policy_id": {
                "type": "string",
                "description": "Stable target-matching policy identifier when configured."
            },
            "target_type": { "type": "string" },
            "method": {
                "type": "string",
                "description": "Configured target-matching method label."
            },
            "confidence": {
                "type": "string",
                "description": "Policy-asserted confidence label for this target-input method."
            },
            "groups": {
                "type": "array",
                "description": "OR-of-AND input groups. A request needs to satisfy one group.",
                "items": { "$ref": "#/components/schemas/ClaimTargetInputGroup" }
            }
        },
        "additionalProperties": false
    })
}

fn claim_target_input_group_schema() -> Value {
    json!({
        "type": "object",
        "required": ["inputs"],
        "properties": {
            "inputs": {
                "type": "array",
                "items": { "$ref": "#/components/schemas/ClaimTargetInput" }
            }
        },
        "additionalProperties": false
    })
}

fn claim_target_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["path", "kind", "name", "label"],
        "properties": {
            "path": {
                "type": "string",
                "description": "Target-side request path, for example target.identifiers.national_id or target.attributes.birthdate."
            },
            "kind": {
                "type": "string",
                "enum": ["id", "identifier", "attribute"]
            },
            "name": { "type": "string" },
            "label": { "type": "string" }
        },
        "additionalProperties": false
    })
}

fn evaluation_response_schema() -> Value {
    json!({
        "type": "object",
        "required": ["results"],
        "properties": {
            "results": {
                "type": "array",
                "items": { "$ref": "#/components/schemas/ClaimResultView" }
            }
        },
        "additionalProperties": false
    })
}

fn claim_result_view_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "evaluation_id",
            "claim_id",
            "claim_version",
            "subject_type",
            "target_ref",
            "value",
            "satisfied",
            "disclosure",
            "format",
            "issued_at",
            "expires_at",
            "provenance"
        ],
        "properties": {
            "evaluation_id": { "type": "string" },
            "claim_id": { "type": "string" },
            "claim_version": { "type": "string" },
            "subject_type": { "type": "string" },
            "requester_ref": { "$ref": "#/components/schemas/EvidenceEntityRef" },
            "target_ref": { "$ref": "#/components/schemas/TargetRefView" },
            "value": {
                "type": ["object", "array", "string", "number", "integer", "boolean", "null"],
                "description": "Claim value. The runtime may return any JSON value."
            },
            "satisfied": { "type": ["boolean", "null"] },
            "disclosure": { "type": "string" },
            "format": { "type": "string" },
            "issued_at": { "type": "string", "format": "date-time" },
            "expires_at": { "type": ["string", "null"], "format": "date-time" },
            "provenance": { "$ref": "#/components/schemas/ClaimProvenance" }
        },
        "additionalProperties": false
    })
}

fn batch_evaluate_response_schema() -> Value {
    json!({
        "type": "object",
        "required": ["batch_id", "status", "claims", "items", "summary"],
        "properties": {
            "batch_id": { "type": "string" },
            "status": { "type": "string", "enum": ["completed"] },
            "claims": {
                "type": "array",
                "items": { "type": "string" }
            },
            "items": {
                "type": "array",
                "items": { "$ref": "#/components/schemas/BatchItemResponse" }
            },
            "summary": { "$ref": "#/components/schemas/BatchSummary" }
        },
        "additionalProperties": false
    })
}

fn batch_item_response_schema() -> Value {
    json!({
        "type": "object",
        "required": ["input_index", "target_ref", "status", "claim_results", "errors"],
        "properties": {
            "input_index": { "type": "integer", "minimum": 0 },
            "target_ref": { "$ref": "#/components/schemas/TargetRefView" },
            "requester_ref": { "$ref": "#/components/schemas/EvidenceEntityRef" },
            "evaluation_id": { "type": "string" },
            "status": { "type": "string", "enum": ["succeeded", "failed"] },
            "claim_results": {
                "type": "array",
                "items": { "$ref": "#/components/schemas/BatchClaimResultView" }
            },
            "errors": {
                "type": "array",
                "items": { "$ref": "#/components/schemas/BatchItemError" }
            }
        },
        "additionalProperties": false
    })
}

fn batch_claim_result_view_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "result_id",
            "claim_id",
            "claim_version",
            "value_type",
            "value",
            "disclosure",
            "provenance"
        ],
        "properties": {
            "result_id": { "type": "string" },
            "claim_id": { "type": "string" },
            "claim_version": { "type": "string" },
            "value_type": { "type": "string" },
            "value": {
                "type": ["object", "array", "string", "number", "integer", "boolean", "null"],
                "description": "Claim value. The runtime may return any JSON value."
            },
            "satisfied": { "type": ["boolean", "null"] },
            "disclosure": { "type": "string" },
            "provenance": { "$ref": "#/components/schemas/ClaimProvenance" }
        },
        "additionalProperties": false
    })
}

fn batch_item_error_schema() -> Value {
    json!({
        "type": "object",
        "required": ["code", "title", "retryable"],
        "properties": {
            "code": { "type": "string" },
            "title": { "type": "string" },
            "retryable": { "type": "boolean" }
        },
        "additionalProperties": false
    })
}

fn batch_summary_schema() -> Value {
    json!({
        "type": "object",
        "required": ["succeeded", "failed"],
        "properties": {
            "succeeded": { "type": "integer", "minimum": 0 },
            "failed": { "type": "integer", "minimum": 0 }
        },
        "additionalProperties": false
    })
}

fn claim_provenance_schema() -> Value {
    json!({
        "type": "object",
        "description": "Versioned claim provenance (registry-notary-claim-provenance/v2). PROV-mappable but not PROV-O. Requester-side identity (client, actor, subject) is deliberately absent; it lives in restricted audit only.",
        "required": ["schema_version", "generated_by", "used", "derived_from"],
        "properties": {
            "schema_version": {
                "type": "string",
                "enum": ["registry-notary-claim-provenance/v2"]
            },
            "generated_by": { "$ref": "#/components/schemas/ProvenanceGeneratedBy" },
            "used": { "$ref": "#/components/schemas/ProvenanceUsed" },
            "derived_from": {
                "type": "array",
                "description": "Upstream provenance records this result was derived from. Always empty in v1; reserved for additive cross-evaluation linking.",
                "items": { "type": "object" }
            }
        },
        "additionalProperties": false
    })
}

fn provenance_generated_by_schema() -> Value {
    json!({
        "type": "object",
        "required": ["type", "service_id", "evaluation_id", "claim_id", "claim_version"],
        "properties": {
            "type": {
                "type": "string",
                "enum": ["claim_evaluation"]
            },
            "service_id": {
                "type": "string",
                "description": "Identifier of the service that produced the result. Replaces the dropped computed_by field; the CCCEV renderer maps its provider agent from here."
            },
            "evaluation_id": { "type": "string" },
            "claim_id": { "type": "string" },
            "claim_version": { "type": "string" },
            "policy_id": {
                "type": "string",
                "description": "Evaluation policy identifier under which this result was produced. Present for flows evaluated under a named policy, such as self-attestation, and omitted for machine-client flows with no evaluation policy."
            },
            "policy_version": { "type": "string" },
            "policy_hash": {
                "type": "string",
                "description": "sha256:<hex> digest of the evaluation policy. Public in v1: a hash revealing no policy content, used to correlate the result with a policy evidence-pack."
            }
        },
        "additionalProperties": false
    })
}

fn provenance_used_schema() -> Value {
    json!({
        "type": "object",
        "required": ["relay_consultation_count"],
        "properties": {
            "relay_consultation_count": { "type": "integer", "minimum": 0 }
        },
        "additionalProperties": false
    })
}

fn target_ref_view_schema() -> Value {
    json!({
        "type": "object",
        "required": ["handle"],
        "properties": {
            "type": { "type": "string" },
            "handle": { "type": "string" },
            "identifier_schemes": {
                "type": "array",
                "items": { "type": "string" }
            },
            "profile": { "type": "string" }
        },
        "additionalProperties": false
    })
}

fn evidence_entity_ref_schema() -> Value {
    json!({
        "type": "object",
        "required": ["type", "handle"],
        "properties": {
            "type": { "type": "string" },
            "handle": { "type": "string" },
            "identifier_schemes": {
                "type": "array",
                "items": { "type": "string" }
            },
            "profile": { "type": "string" }
        },
        "additionalProperties": false
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

fn set_json_response_schema(
    document: &mut Value,
    path: &str,
    method: &str,
    status: &str,
    schema_ref: &str,
) {
    set_response_schema(
        document,
        path,
        method,
        status,
        "application/json",
        schema_ref,
    );
}

fn set_problem_response_schema(
    document: &mut Value,
    path: &str,
    method: &str,
    status: &str,
    schema_ref: &str,
) {
    set_response_schema(
        document,
        path,
        method,
        status,
        "application/problem+json",
        schema_ref,
    );
}

fn set_response_schema(
    document: &mut Value,
    path: &str,
    method: &str,
    status: &str,
    content_type: &str,
    schema_ref: &str,
) {
    let Some(media_type) = document
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
        .and_then(|response| response.get_mut("content"))
        .and_then(Value::as_object_mut)
        .and_then(|content| content.get_mut(content_type))
        .and_then(Value::as_object_mut)
    else {
        return;
    };

    media_type.insert(
        "schema".to_string(),
        json!({
            "$ref": schema_ref
        }),
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
                "evidence.not_available",
                "Evidence not available",
                "the required evidence or operational dependency is unavailable",
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

fn readiness_response_schema() -> Value {
    json!({
        "type": "object",
        "required": ["status", "checks"],
        "properties": {
            "status": { "type": "string", "enum": ["ready"] },
            "checks": { "$ref": "#/components/schemas/ReadinessChecks" }
        },
        "additionalProperties": false
    })
}

fn readiness_checks_schema() -> Value {
    json!({
        "type": "object",
        "required": ["total", "ok", "degraded", "failed", "signing_providers", "relay"],
        "properties": {
            "total": non_negative_count_schema(),
            "ok": non_negative_count_schema(),
            "degraded": non_negative_count_schema(),
            "failed": non_negative_count_schema(),
            "signing_providers": {
                "$ref": "#/components/schemas/SigningProviderReadinessChecks"
            },
            "relay": {
                "type": "object",
                "required": ["total", "ok", "failed"],
                "properties": {
                    "total": non_negative_count_schema(),
                    "ok": non_negative_count_schema(),
                    "failed": non_negative_count_schema()
                },
                "additionalProperties": false
            }
        },
        "additionalProperties": false
    })
}

fn signing_provider_readiness_checks_schema() -> Value {
    json!({
        "type": "object",
        "required": ["total", "ok", "failed", "custody"],
        "properties": {
            "total": non_negative_count_schema(),
            "ok": non_negative_count_schema(),
            "failed": non_negative_count_schema(),
            "custody": { "$ref": "#/components/schemas/SignerCustodyChecks" }
        },
        "additionalProperties": false
    })
}

fn signer_custody_checks_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "active_provider_counts",
            "signing_provider_count",
            "local_software_signing_provider_count",
            "custody_approval_required",
            "custody_approved",
            "unapproved_signing_provider_count",
            "surfaces"
        ],
        "properties": {
            "active_provider_counts": {
                "type": "object",
                "description": "Counts by configured provider kind. PKCS#11 identifies an interface, not whether custody is hardware- or software-backed.",
                "additionalProperties": non_negative_count_schema()
            },
            "signing_provider_count": non_negative_count_schema(),
            "local_software_signing_provider_count": non_negative_count_schema(),
            "custody_approval_required": { "type": "boolean" },
            "custody_approved": { "type": "boolean" },
            "unapproved_signing_provider_count": non_negative_count_schema(),
            "surfaces": { "$ref": "#/components/schemas/SignerCustodySurfaces" }
        },
        "additionalProperties": false
    })
}

fn signer_custody_surfaces_schema() -> Value {
    json!({
        "type": "object",
        "required": ["credential_issuance", "access_token_issuance", "federation"],
        "properties": {
            "credential_issuance": { "$ref": "#/components/schemas/SignerSurfaceChecks" },
            "access_token_issuance": {
                "$ref": "#/components/schemas/EnabledSignerSurfaceChecks"
            },
            "federation": { "$ref": "#/components/schemas/EnabledSignerSurfaceChecks" }
        },
        "additionalProperties": false
    })
}

fn signer_surface_checks_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "signing_provider_count",
            "local_software_signing_provider_count",
            "unapproved_signing_provider_count"
        ],
        "properties": {
            "signing_provider_count": non_negative_count_schema(),
            "local_software_signing_provider_count": non_negative_count_schema(),
            "unapproved_signing_provider_count": non_negative_count_schema()
        },
        "additionalProperties": false
    })
}

fn enabled_signer_surface_checks_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "enabled",
            "signing_provider_count",
            "local_software_signing_provider_count",
            "unapproved_signing_provider_count"
        ],
        "properties": {
            "enabled": { "type": "boolean" },
            "signing_provider_count": non_negative_count_schema(),
            "local_software_signing_provider_count": non_negative_count_schema(),
            "unapproved_signing_provider_count": non_negative_count_schema()
        },
        "additionalProperties": false
    })
}

fn readiness_problem_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "type",
            "title",
            "status",
            "detail",
            "code",
            "request_id",
            "readiness_status",
            "checks"
        ],
        "properties": {
            "type": { "type": "string", "format": "uri" },
            "title": { "type": "string" },
            "status": { "type": "integer", "format": "int32" },
            "detail": { "type": "string" },
            "code": { "type": "string" },
            "request_id": { "type": "string" },
            "readiness_status": {
                "type": "string",
                "enum": ["degraded", "not_ready"]
            },
            "checks": { "$ref": "#/components/schemas/ReadinessChecks" }
        },
        "additionalProperties": false
    })
}

fn non_negative_count_schema() -> Value {
    json!({ "type": "integer", "minimum": 0 })
}

fn problem_details_schema() -> Value {
    json!({
        "type": "object",
        "required": ["type", "title", "status", "detail", "code", "request_id"],
        "properties": {
            "type": { "type": "string", "format": "uri" },
            "title": { "type": "string" },
            "status": { "type": "integer", "format": "int32" },
            "detail": { "type": "string" },
            "code": { "type": "string" },
            "request_id": { "type": "string" }
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
            "token_endpoint": { "type": "string", "format": "uri" },
            "nonce_endpoint": { "type": "string", "format": "uri" },
            "authorization_servers": { "type": "array", "items": { "type": "string", "format": "uri" } },
            "display": { "type": "array", "items": { "type": "object", "additionalProperties": true } },
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

fn sd_jwt_vc_type_metadata_schema() -> Value {
    json!({
        "type": "object",
        "required": ["vct", "name", "display", "claims"],
        "properties": {
            "vct": { "type": "string", "format": "uri" },
            "name": { "type": "string" },
            "description": { "type": "string" },
            "display": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["locale", "name"],
                    "properties": {
                        "locale": { "type": "string" },
                        "name": { "type": "string" }
                    },
                    "additionalProperties": true
                }
            },
            "claims": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["path", "display", "sd", "mandatory"],
                    "properties": {
                        "path": {
                            "type": "array",
                            "items": { "type": "string" }
                        },
                        "display": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["locale", "label"],
                                "properties": {
                                    "locale": { "type": "string" },
                                    "label": { "type": "string" }
                                },
                                "additionalProperties": true
                            }
                        },
                        "sd": {
                            "type": "string",
                            "enum": ["always"]
                        },
                        "mandatory": { "type": "boolean" },
                        "registry_notary_semantics": {
                            "$ref": "#/components/schemas/ClaimSemantics"
                        }
                    },
                    "additionalProperties": true
                }
            }
        },
        "additionalProperties": true
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
        "oneOf": [
            { "required": ["proof"] },
            { "required": ["proofs"] }
        ],
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
            },
            "proofs": {
                "type": "object",
                "properties": {
                    "jwt": {
                        "type": "array",
                        "items": { "type": "string" },
                        "minItems": 1
                    }
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
            "credentials": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["credential"],
                    "properties": {
                        "credential": { "type": "string" }
                    },
                    "additionalProperties": true
                }
            },
            "credential_profile": { "type": "string" },
            "format": { "type": "string" },
            "c_nonce": { "type": "string" },
            "c_nonce_expires_in": { "type": "integer", "format": "uint64" }
        }
    })
}

fn token_request_schema() -> Value {
    json!({
        "type": "object",
        "required": ["grant_type", "pre-authorized_code"],
        "properties": {
            "grant_type": {
                "type": "string",
                "example": "urn:ietf:params:oauth:grant-type:pre-authorized_code"
            },
            "pre-authorized_code": { "type": "string" },
            "tx_code": {
                "type": "string",
                "description": "The numeric PIN shown on the offer page. Required when the credential offer includes a tx_code object."
            }
        }
    })
}

fn token_response_schema() -> Value {
    json!({
        "type": "object",
        "required": ["access_token", "token_type"],
        "properties": {
            "access_token": { "type": "string" },
            "token_type": { "type": "string", "example": "Bearer" },
            "expires_in": { "type": "integer", "format": "uint64" },
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
        "code": code,
        "request_id": "01J00000000000000000000000"
    })
}

fn admin_error_example(status: u16, code: &str, title: &str, detail: &str) -> Value {
    json!({
        "schema": "registry.admin.error.v1",
        "type": format!("{}/{}", crate::PROBLEM_TYPE_BASE_URL, code.replace('.', "/")),
        "title": title,
        "status": status,
        "detail": detail,
        "message": detail,
        "code": code,
        "request_id": "01J00000000000000000000000"
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
                "header": "X-Api-Key"
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
        "display": [
            {
                "name": "Civil Registry Notary",
                "locale": "en-US"
            }
        ],
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
                    {
                        "name": "Person is alive",
                        "locale": "en-US",
                        "description": "Proof that the civil registry currently records this person as alive.",
                        "background_color": "#0057B8",
                        "text_color": "#FFFFFF"
                    }
                ],
                "vct": "https://issuer.example.gov/credentials/person-is-alive"
            }
        }
    })
}

fn sd_jwt_vc_type_metadata_example() -> Value {
    json!({
        "vct": "https://issuer.example.gov/credentials/person-is-alive",
        "name": "Person is alive",
        "display": [
            {
                "locale": "en-US",
                "name": "Person is alive",
                "description": "Proof that the civil registry currently records this person as alive.",
                "background_color": "#0057B8",
                "text_color": "#FFFFFF"
            }
        ],
        "claims": [
            {
                "path": ["person-is-alive"],
                "display": [
                    {
                        "locale": "en-US",
                        "label": "Person is alive"
                    }
                ],
                "sd": "always",
                "mandatory": true,
                "registry_notary_semantics": {
                    "concept": "https://publicschema.org/Person",
                    "predicate": "urn:registry-notary:predicate:person-is-alive",
                    "derived_from": ["https://publicschema.org/date_of_death"]
                }
            }
        ]
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

fn oid4vci_token_response_example() -> Value {
    json!({
        "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6InJlZ2lzdHJ5LW5vdGFyeS1hY2Nlc3MrancifQ.payload.signature",
        "token_type": "Bearer",
        "expires_in": 300,
        "c_nonce": "b64url-nonce",
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
        "semantics": {
            "concept": "https://publicschema.org/Person",
            "property": "https://publicschema.org/date_of_birth",
            "value_mapping": "publicschema"
        },
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
        "target_inputs": [
            {
                "policy_id": "smallholder-demographic-v1",
                "target_type": "Person",
                "method": "exact_name_birthdate",
                "confidence": "high",
                "groups": [
                    {
                        "inputs": [
                            {
                                "path": "target.identifiers.farmer_id",
                                "kind": "identifier",
                                "name": "farmer_id",
                                "label": "Farmer id"
                            }
                        ]
                    },
                    {
                        "inputs": [
                            {
                                "path": "target.attributes.given_name",
                                "kind": "attribute",
                                "name": "given_name",
                                "label": "Given name"
                            },
                            {
                                "path": "target.attributes.family_name",
                                "kind": "attribute",
                                "name": "family_name",
                                "label": "Family name"
                            },
                            {
                                "path": "target.attributes.birthdate",
                                "kind": "attribute",
                                "name": "birthdate",
                                "label": "Birthdate"
                            }
                        ]
                    }
                ]
            }
        ],
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
                "target_ref": target_ref_example("Person"),
                "requester_ref": requester_ref_example(),
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
        "requester_ref": requester_ref_example(),
        "target_ref": target_ref_example("Person"),
        "value": true,
        "satisfied": true,
        "disclosure": "predicate",
        "format": "application/vnd.registry-notary.claim-result+json",
        "issued_at": "2026-05-24T12:00:00Z",
        "expires_at": "2026-05-25T12:00:00Z",
        "provenance": provenance_example()
    })
}

fn target_ref_example(entity_type: &str) -> Value {
    json!({
        "type": entity_type,
        "handle": "rnref:v1:example-target-ref",
        "identifier_schemes": ["national_id"],
        "profile": "resident"
    })
}

fn requester_ref_example() -> Value {
    json!({
        "type": "Agency",
        "handle": "rnref:v1:example-requester-ref",
        "identifier_schemes": ["agency_id"],
        "profile": "benefits"
    })
}

fn provenance_example() -> Value {
    json!({
        "schema_version": "registry-notary-claim-provenance/v2",
        "generated_by": {
            "type": "claim_evaluation",
            "service_id": "demo.registry-notary",
            "evaluation_id": "01HX7Y5F2WAJ7ZP0Q4M5K9E8NC",
            "claim_id": "person_is_alive",
            "claim_version": "1",
            "policy_id": "self-attestation",
            "policy_version": "v1",
            "policy_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        },
        "used": {
            "relay_consultation_count": 1
        },
        "derived_from": []
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
    fn claim_provenance_schema_is_v2_relay_consultation_contract() {
        let doc = openapi_document();
        let schemas = &doc["components"]["schemas"];

        let provenance = &schemas["ClaimProvenance"];
        let required: Vec<&str> = provenance["required"]
            .as_array()
            .expect("required array")
            .iter()
            .map(|value| value.as_str().expect("required entry is string"))
            .collect();
        assert_eq!(
            required,
            vec!["schema_version", "generated_by", "used", "derived_from"]
        );
        assert_eq!(provenance["additionalProperties"], json!(false));
        assert_eq!(
            provenance["properties"]["schema_version"]["enum"],
            json!(["registry-notary-claim-provenance/v2"])
        );

        let generated_by = &schemas["ProvenanceGeneratedBy"];
        assert_eq!(generated_by["additionalProperties"], json!(false));
        // computed_by is dropped entirely; service_id replaces it.
        assert!(generated_by["properties"].get("computed_by").is_none());
        assert!(generated_by["properties"]["service_id"].is_object());
        assert_eq!(
            generated_by["properties"]["type"]["enum"],
            json!(["claim_evaluation"])
        );

        let used = &schemas["ProvenanceUsed"];
        assert_eq!(used["additionalProperties"], json!(false));
        let used_required: Vec<&str> = used["required"]
            .as_array()
            .expect("required array")
            .iter()
            .map(|value| value.as_str().expect("string"))
            .collect();
        assert_eq!(used_required, vec!["relay_consultation_count"]);
    }

    #[test]
    fn provenance_policy_id_description_names_evaluation_policy() {
        let doc = openapi_document();
        let schemas = &doc["components"]["schemas"];

        let generated_by_policy = schemas["ProvenanceGeneratedBy"]["properties"]["policy_id"]
            ["description"]
            .as_str()
            .expect("generated_by.policy_id has a description");
        assert!(
            generated_by_policy.contains("Evaluation policy"),
            "generated_by.policy_id must name the evaluation policy: {generated_by_policy}"
        );
    }

    #[test]
    fn on_behalf_of_schema_is_frozen_envelope_rejecting_free_form() {
        let doc = openapi_document();
        let schemas = &doc["components"]["schemas"];

        let envelope = &schemas["EvidenceOnBehalfOf"];
        assert_eq!(
            envelope["additionalProperties"],
            json!(false),
            "envelope must reject free-form payloads"
        );
        assert_eq!(envelope["required"], json!(["actor"]));
        assert_eq!(
            envelope["properties"]["actor"]["$ref"],
            json!("#/components/schemas/EvidenceActor")
        );
        assert!(envelope["properties"]["delegation_ref"].is_object());

        let actor = &schemas["EvidenceActor"];
        assert_eq!(actor["additionalProperties"], json!(false));
        let actor_required: Vec<&str> = actor["required"]
            .as_array()
            .expect("required array")
            .iter()
            .map(|value| value.as_str().expect("string"))
            .collect();
        assert_eq!(actor_required, vec!["type", "id_hash"]);
        assert!(actor["properties"]["id_hash"]["description"]
            .as_str()
            .expect("id_hash description")
            .contains("hmac-sha256"));
    }

    #[test]
    fn documents_split_registry_notary_routes() {
        let doc = openapi_document();
        let paths = doc["paths"].as_object().expect("paths object");
        for route in [
            "/healthz",
            "/ready",
            "/admin/v1/reload",
            "/admin/v1/capabilities",
            "/admin/v1/posture",
            "/openapi.json",
            "/.well-known/evidence-service",
            "/.well-known/evidence/jwks.json",
            "/.well-known/openid-credential-issuer",
            "/credentials/{vct_path}",
            "/.well-known/vct/{vct_path}",
            "/oid4vci/credential-offer",
            "/oid4vci/nonce",
            "/oid4vci/credential",
            "/oid4vci/offer/start",
            "/oid4vci/offer/callback",
            "/oid4vci/token",
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
        for route in [
            "/admin/v1/config/verify",
            "/admin/v1/config/dry-run",
            "/admin/v1/config/apply",
        ] {
            assert!(
                !paths.contains_key(route),
                "removed admin config route is still documented: {route}"
            );
        }
    }

    #[test]
    fn documents_admin_posture_query_and_response_contract() {
        let doc = openapi_document();
        let posture = &doc["paths"]["/admin/v1/posture"]["get"];
        assert!(posture.is_object(), "admin posture GET is documented");
        // Authenticated read: posture must not be exposed as a public route.
        assert_eq!(
            posture["security"],
            json!([{ "apiKeyAuth": [] }, { "bearerAuth": [] }])
        );
        // The tier query parameter is constrained to the runtime-accepted values.
        let tier = &posture["parameters"][0];
        assert_eq!(tier["name"], json!("tier"));
        assert_eq!(tier["in"], json!("query"));
        assert_eq!(tier["schema"]["enum"], json!(["default", "restricted"]));
        // Every response the handler can return is documented.
        for status in ["200", "400", "401", "403", "500", "503"] {
            assert!(
                posture["responses"][status].is_object(),
                "posture documents the {status} response"
            );
        }
        // The 200 body is documented with the real posture document shape.
        assert_eq!(
            posture["responses"]["200"]["content"]["application/json"]["example"]["schema"],
            json!("registry.ops.posture.v1")
        );
    }

    #[test]
    fn document_info_tracks_crate_metadata() {
        let doc = serde_json::to_value(openapi_document()).expect("document serializes");
        assert_eq!(
            doc["info"]["summary"],
            "Standalone evidence evaluation, rendering, and credential issuance service."
        );
        assert_eq!(
            doc["info"]["contact"]["name"],
            "Registry Notary owning team"
        );
        assert_eq!(doc["info"]["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(doc["info"]["license"]["name"], env!("CARGO_PKG_LICENSE"));
        assert_eq!(
            doc["info"]["license"]["identifier"],
            env!("CARGO_PKG_LICENSE")
        );
    }

    #[test]
    fn document_security_contract_uses_default_security_and_canonical_api_key_header() {
        let doc = serde_json::to_value(openapi_document()).expect("document serializes");
        assert_eq!(
            doc["security"],
            json!([{ "apiKeyAuth": [] }, { "bearerAuth": [] }])
        );
        assert_eq!(
            doc["components"]["securitySchemes"]["apiKeyAuth"]["name"],
            "X-Api-Key"
        );
    }

    #[test]
    fn deleted_config_admin_operations_are_not_documented() {
        let doc = serde_json::to_value(openapi_document()).expect("document serializes");
        for path in [
            "/admin/v1/config/verify",
            "/admin/v1/config/dry-run",
            "/admin/v1/config/apply",
        ] {
            assert!(
                doc["paths"].get(path).is_none(),
                "{path} must not be documented"
            );
        }
        for schema in [
            "ConfigApplyRequest",
            "ConfigApplyResponse",
            "TufConfigTargetRequest",
            "LocalTufConfigTargetRequest",
            "RemoteTufConfigTargetRequest",
            "BreakGlassApproval",
            "BreakGlassRateLimit",
        ] {
            assert!(
                doc["components"]["schemas"].get(schema).is_none(),
                "retired schema is still documented: {schema}"
            );
        }
    }

    #[test]
    fn public_probe_routes_do_not_require_security() {
        let doc = serde_json::to_value(openapi_document()).expect("document serializes");
        assert_eq!(doc["paths"]["/healthz"]["get"]["security"], json!([]));
        assert_eq!(doc["paths"]["/ready"]["get"]["security"], json!([]));
        assert_eq!(
            doc["paths"]["/.well-known/evidence/jwks.json"]["get"]["security"],
            json!([])
        );
        assert_eq!(
            doc["paths"]["/.well-known/openid-credential-issuer"]["get"]["security"],
            json!([])
        );
        assert_eq!(
            doc["paths"]["/credentials/{vct_path}"]["get"]["security"],
            json!([])
        );
        assert_eq!(
            doc["paths"]["/.well-known/vct/{vct_path}"]["get"]["security"],
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
            doc["paths"]["/oid4vci/offer/start"]["get"]["security"],
            json!([])
        );
        assert_eq!(
            doc["paths"]["/oid4vci/offer/callback"]["get"]["security"],
            json!([])
        );
        assert_eq!(
            doc["paths"]["/oid4vci/token"]["post"]["security"],
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
    fn documents_typed_readiness_custody_contract() {
        let doc = openapi_document();
        let ready = &doc["paths"]["/ready"]["get"]["responses"];
        assert_eq!(
            ready["200"]["content"]["application/json"]["schema"]["$ref"],
            json!("#/components/schemas/ReadinessResponse")
        );
        assert_eq!(
            ready["503"]["content"]["application/problem+json"]["schema"]["$ref"],
            json!("#/components/schemas/ReadinessProblem")
        );
        assert!(doc["components"]["schemas"]["ReadinessProblem"]["required"]
            .as_array()
            .expect("required array")
            .iter()
            .any(|field| field == "request_id"));

        let custody = &doc["components"]["schemas"]["SignerCustodyChecks"];
        let required = custody["required"].as_array().expect("required array");
        for field in [
            "active_provider_counts",
            "custody_approval_required",
            "custody_approved",
            "unapproved_signing_provider_count",
            "surfaces",
        ] {
            assert!(required.iter().any(|entry| entry == field));
        }

        for status in ["200", "503"] {
            let content_type = if status == "200" {
                "application/json"
            } else {
                "application/problem+json"
            };
            let checks = &ready[status]["content"][content_type]["example"]["checks"];
            assert!(checks.get("deployment").is_none());
            assert!(checks["relay"].get("total").is_some());
            assert!(checks["signing_providers"]["custody"]["surfaces"]
                .get("access_token_issuance")
                .is_some());
        }
    }

    #[test]
    fn high_value_routes_have_redoc_response_examples() {
        let doc = serde_json::to_value(openapi_document()).expect("document serializes");
        for (path, method, status) in [
            ("/healthz", "get", "200"),
            ("/ready", "get", "200"),
            ("/admin/v1/capabilities", "get", "200"),
            ("/admin/v1/posture", "get", "200"),
            ("/openapi.json", "get", "200"),
            ("/.well-known/evidence-service", "get", "200"),
            ("/.well-known/evidence/jwks.json", "get", "200"),
            ("/.well-known/openid-credential-issuer", "get", "200"),
            ("/credentials/{vct_path}", "get", "200"),
            ("/.well-known/vct/{vct_path}", "get", "200"),
            ("/oid4vci/credential-offer", "get", "200"),
            ("/oid4vci/nonce", "post", "200"),
            ("/oid4vci/credential", "post", "200"),
            ("/oid4vci/token", "post", "200"),
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
    fn evaluation_response_schemas_use_target_and_requester_refs() {
        let doc = serde_json::to_value(openapi_document()).expect("document serializes");

        assert_eq!(
            doc["paths"]["/v1/evaluations"]["post"]["responses"]["200"]["content"]
                ["application/json"]["schema"]["$ref"],
            json!("#/components/schemas/EvaluationResponse")
        );
        assert_eq!(
            doc["paths"]["/v1/batch-evaluations"]["post"]["responses"]["200"]["content"]
                ["application/json"]["schema"]["$ref"],
            json!("#/components/schemas/BatchEvaluateResponse")
        );
        assert_eq!(
            doc["components"]["schemas"]["ClaimResultView"]["properties"]["target_ref"]["$ref"],
            json!("#/components/schemas/TargetRefView")
        );
        assert_eq!(
            doc["components"]["schemas"]["ClaimResultView"]["properties"]["requester_ref"]["$ref"],
            json!("#/components/schemas/EvidenceEntityRef")
        );
        let evaluate_example = &doc["paths"]["/v1/evaluations"]["post"]["responses"]["200"]
            ["content"]["application/json"]["example"]["results"][0];
        assert!(evaluate_example.get("subject_ref").is_none());
        assert!(evaluate_example.get("target_ref").is_some());
        assert!(evaluate_example.get("requester_ref").is_some());
        assert!(evaluate_example.get("matching").is_none());
        assert!(evaluate_example["value"].is_boolean());

        let batch_item_example = &doc["paths"]["/v1/batch-evaluations"]["post"]["responses"]["200"]
            ["content"]["application/json"]["example"]["items"][0];
        assert!(batch_item_example.get("subject_ref").is_none());
        assert!(batch_item_example.get("target_ref").is_some());
        assert!(batch_item_example.get("requester_ref").is_some());
        assert!(batch_item_example.get("matching").is_none());
        assert!(batch_item_example["claim_results"][0]["value"].is_boolean());
        assert_eq!(
            doc["components"]["schemas"]["ClaimResultView"]["properties"]["value"]["type"],
            json!(["object", "array", "string", "number", "integer", "boolean", "null"])
        );
        assert_eq!(
            doc["components"]["schemas"]["BatchClaimResultView"]["properties"]["value"]["type"],
            json!(["object", "array", "string", "number", "integer", "boolean", "null"])
        );

        let evaluate_request = &doc["components"]["schemas"]["EvaluateRequest"]["properties"];
        assert!(evaluate_request.get("subject").is_none());
        assert!(evaluate_request.get("id_type").is_none());
        assert!(evaluate_request.get("target").is_some());
        assert_eq!(evaluate_request["variables"]["maxProperties"], json!(16));
        assert_eq!(
            evaluate_request["variables"]["additionalProperties"]["format"],
            json!("date")
        );
        assert_eq!(
            doc["components"]["schemas"]["EvaluateRequest"]["required"],
            json!(["claims"])
        );

        let batch_request = &doc["components"]["schemas"]["BatchEvaluateRequest"]["properties"];
        assert!(batch_request.get("subjects").is_none());
        assert!(batch_request.get("items").is_some());
    }

    #[test]
    fn common_error_responses_have_problem_detail_examples() {
        let doc = serde_json::to_value(openapi_document()).expect("document serializes");
        for (path, method, status) in [
            ("/admin/v1/reload", "post", "401"),
            ("/admin/v1/reload", "post", "403"),
            ("/admin/v1/posture", "get", "400"),
            ("/admin/v1/posture", "get", "401"),
            ("/admin/v1/posture", "get", "403"),
            ("/admin/v1/posture", "get", "500"),
            ("/admin/v1/posture", "get", "503"),
            ("/.well-known/evidence-service", "get", "401"),
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
            ("/ready", "get", "503"),
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
    fn every_problem_example_carries_the_required_request_id() {
        let doc = serde_json::to_value(openapi_document()).expect("document serializes");
        for (path, path_item) in doc["paths"].as_object().expect("paths are an object") {
            for (method, operation) in path_item.as_object().expect("path item is an object") {
                let Some(responses) = operation
                    .get("responses")
                    .and_then(serde_json::Value::as_object)
                else {
                    continue;
                };
                for (status, response) in responses {
                    let Some(example) = response
                        .pointer("/content/application~1problem+json/example")
                        .filter(|example| example.is_object())
                    else {
                        continue;
                    };
                    assert!(
                        example["request_id"]
                            .as_str()
                            .is_some_and(|value| !value.is_empty()),
                        "problem example must include request_id for {method} {path} {status}"
                    );
                }
            }
        }
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
            json!("Issues a dc+sd-jwt credential for an authenticated self-attestation principal. Error responses use the OpenID4VCI error envelope, not RFC 9457 Problem Details.")
        );
        assert_eq!(
            doc["components"]["schemas"]["TokenRequest"]["type"],
            json!("object")
        );
        assert_eq!(
            doc["components"]["schemas"]["TokenResponse"]["type"],
            json!("object")
        );
        assert_eq!(
            doc["paths"]["/oid4vci/token"]["post"]["requestBody"]["content"]
                ["application/x-www-form-urlencoded"]["schema"]["$ref"],
            json!("#/components/schemas/TokenRequest")
        );
        assert_eq!(
            doc["paths"]["/oid4vci/token"]["post"]["responses"]["200"]["content"]
                ["application/json"]["schema"]["$ref"],
            json!("#/components/schemas/TokenResponse")
        );
        assert_eq!(
            doc["paths"]["/oid4vci/token"]["post"]["responses"]["400"]["content"]
                ["application/json"]["schema"]["$ref"],
            json!("#/components/schemas/Oid4vciError")
        );
        // The token endpoint documents its grant, the conditional tx_code, and the
        // public/unauthenticated nature.
        let token_description = doc["paths"]["/oid4vci/token"]["post"]["description"]
            .as_str()
            .expect("token endpoint has a description");
        assert!(
            token_description.contains("urn:ietf:params:oauth:grant-type:pre-authorized_code"),
            "token endpoint documents the pre-authorized-code grant"
        );
        assert!(
            token_description.contains("tx_code") && token_description.contains("offer includes"),
            "token endpoint documents when tx_code is required"
        );
        assert!(
            token_description.contains("unauthenticated"),
            "token endpoint documents that it is unauthenticated"
        );
        assert!(
            token_description.contains("404") && token_description.contains("disabled"),
            "token endpoint documents the disabled 404 behavior"
        );
        assert_eq!(
            doc["components"]["schemas"]["SdJwtVcTypeMetadata"]["properties"]["claims"]["items"]
                ["properties"]["sd"]["enum"],
            json!(["always"])
        );
        assert_eq!(
            doc["paths"]["/credentials/{vct_path}"]["get"]["responses"]["200"]["content"]
                ["application/json"]["schema"]["$ref"],
            json!("#/components/schemas/SdJwtVcTypeMetadata")
        );
        assert_eq!(
            doc["paths"]["/credentials/{vct_path}"]["get"]["responses"]["200"]["content"]
                ["application/json"]["example"]["claims"][0]["path"],
            json!(["person-is-alive"])
        );
        assert!(
            doc["paths"]["/credentials/{vct_path}"]["get"]["description"]
                .as_str()
                .is_some_and(|description| description.contains("multi-segment catch-all")),
            "Type Metadata route must document that vct_path is a multi-segment catch-all"
        );
        // x-registry-notary-catch-all lives on the path item, not the operation.
        assert_eq!(
            doc["paths"]["/credentials/{vct_path}"]["x-registry-notary-catch-all"],
            json!(true)
        );
        assert_eq!(
            doc["paths"]["/credentials/{vct_path}"]["get"]["parameters"][0]["schema"]["pattern"],
            json!("^[^/]+(/[^/]+)*$"),
            "vct_path parameter schema must carry a pattern permitting slash-separated segments"
        );
        assert_eq!(
            doc["paths"]["/.well-known/vct/{vct_path}"]["get"]["responses"]["200"]["content"]
                ["application/json"]["schema"]["$ref"],
            json!("#/components/schemas/SdJwtVcTypeMetadata")
        );
        assert_eq!(
            doc["paths"]["/.well-known/vct/{vct_path}"]["get"]["responses"]["200"]["content"]
                ["application/json"]["example"]["claims"][0]["path"],
            json!(["person-is-alive"])
        );
        assert!(
            doc["paths"]["/.well-known/vct/{vct_path}"]["get"]["description"]
                .as_str()
                .is_some_and(|description| description.contains("/.well-known/vct")
                    && description.contains("multi-segment catch-all")),
            "well-known Type Metadata route must document the well-known prefix and catch-all semantics"
        );
        // x-registry-notary-catch-all lives on the path item, not the operation.
        assert_eq!(
            doc["paths"]["/.well-known/vct/{vct_path}"]["x-registry-notary-catch-all"],
            json!(true)
        );
        assert_eq!(
            doc["paths"]["/.well-known/vct/{vct_path}"]["get"]["parameters"][0]["schema"]
                ["pattern"],
            json!("^[^/]+(/[^/]+)*$"),
            "well-known vct_path parameter schema must carry a pattern permitting slash-separated segments"
        );
    }

    #[test]
    fn problem_responses_reference_shared_problem_details_schema() {
        let doc = serde_json::to_value(openapi_document()).expect("document serializes");
        assert!(doc["components"]["schemas"]["ProblemDetails"].is_object());

        for (path, method, status) in [
            ("/admin/v1/reload", "post", "501"),
            ("/admin/v1/capabilities", "get", "401"),
            ("/admin/v1/capabilities", "get", "403"),
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

    #[test]
    fn admin_routes_carry_explicit_per_route_security() {
        // Admin routes must declare security explicitly so OpenAPI consumers do not
        // treat them as equivalent to data routes that merely inherit the doc-level
        // default. The declared schemes must match what the runtime enforces: an API
        // key (X-Api-Key header) or an OIDC bearer token.
        let doc = serde_json::to_value(openapi_document()).expect("document serializes");
        let expected = json!([{ "apiKeyAuth": [] }, { "bearerAuth": [] }]);
        for (path, method) in [
            ("/admin/v1/reload", "post"),
            ("/admin/v1/capabilities", "get"),
            ("/admin/v1/credentials/{credential_id}/status", "post"),
        ] {
            assert_eq!(
                doc["paths"][path][method]["security"], expected,
                "admin route {method} {path} must carry explicit per-route security"
            );
        }
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
                    value.starts_with("https://id.registrystack.org/problems/registry-notary/")
                }),
            "problem example must include a Registry Notary problem type for {method} {path} {status}"
        );
        assert!(
            example["code"].is_string(),
            "problem example must include a code for {method} {path} {status}"
        );
    }
}
