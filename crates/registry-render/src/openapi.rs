//! The static OpenAPI document. Two endpoints do not justify a generator;
//! this file is the contract, and the serve tests pin its routes.
//!
//! The document describes every route, the seal route included. A
//! deployment without a `signing` block does not mount `/v1/seal/{type}`,
//! so it serves the document without that path ([`served`]).

use std::sync::OnceLock;

/// The seal route, present only in a deployment that declares seals.
pub const SEAL_PATH: &str = "/v1/seal/{type}";

/// The OpenAPI document a deployment serves: the whole contract when it
/// seals, and the contract without the seal route when it does not.
pub fn served(sealing: bool) -> &'static str {
    static WITHOUT_SEALING: OnceLock<String> = OnceLock::new();
    if sealing {
        return OPENAPI_JSON;
    }
    WITHOUT_SEALING.get_or_init(|| {
        let mut document: serde_json::Value =
            serde_json::from_str(OPENAPI_JSON).expect("the OpenAPI document is JSON");
        document["paths"]
            .as_object_mut()
            .expect("the OpenAPI document has paths")
            .remove(SEAL_PATH);
        serde_json::to_string_pretty(&document).expect("the OpenAPI document serializes")
    })
}

pub const OPENAPI_JSON: &str = r#"{
  "openapi": "3.1.0",
  "info": {
    "title": "Registry Render",
    "version": "1.0.0",
    "description": "Governed, byte-stable PDF documents from registry data. Deterministic rendering: the same bundle, data, and issuedAt produce the same bytes, so retries are always safe."
  },
  "paths": {
    "/health": {
      "get": {
        "summary": "Liveness (value-free: status, bundle version and hash, renderer version, Typst pin)",
        "responses": { "200": { "description": "ok" } }
      }
    },
    "/ready": {
      "get": {
        "summary": "Readiness (issuer keys and audit destination included)",
        "responses": {
          "200": { "description": "ready. A deployment that seals adds a signing member, one entry per seal: {status: ready} or {status: unavailable, reason: certificate-expired | certificate-not-yet-valid | provider-not-ready}. A seal never changes the status code; readiness never requests a timestamp." },
          "503": { "description": "not ready" }
        }
      }
    },
    "/v1/documents": {
      "get": {
        "summary": "List document types in the verified package",
        "security": [{ "bearerAuth": [] }],
        "responses": { "200": { "description": "document inventory" } }
      }
    },
    "/v1/render/{type}": {
      "post": {
        "summary": "Render one document",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          {
            "name": "Idempotency-Key",
            "in": "header",
            "description": "Opaque correlation id; echoed and audited. Never used for dedupe — rendering is deterministic.",
            "schema": { "type": "string", "maxLength": 128 }
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["issuedAt", "data"],
                "properties": {
                  "locale": { "type": "string" },
                  "issuedAt": { "type": "string", "format": "date-time" },
                  "data": { "type": "object" },
                  "assets": {
                    "type": "object",
                    "additionalProperties": { "type": "string", "contentEncoding": "base64" }
                  }
                }
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Rendered PDF. Default representation is application/pdf with X-Registry-Pdf-Sha256, X-Registry-Data-Sha256, X-Registry-Document-Version and X-Registry-Warning-Count headers. A nonzero warning count means the host should inspect the JSON warnings before releasing the document. With Accept: application/json, the body is {pdfBase64, pdfSha256, dataSha256, documentVersion, warnings}.",
            "headers": {
              "X-Registry-Warning-Count": {
                "description": "Number of rendering warnings, including zero. Present on PDF responses; warning text is available in the JSON representation.",
                "schema": { "type": "integer", "minimum": 0 }
              }
            },
            "content": {
              "application/pdf": { "schema": { "type": "string", "format": "binary" } },
              "application/json": { "schema": { "type": "object" } }
            }
          },
          "400": { "description": "Invalid request, data, or assets (problem+json with JSON pointers)" },
          "401": { "description": "Missing or invalid bearer credential; Bearer challenge" },
          "403": { "description": "Verified credential lacks render:render scope" },
          "422": { "description": "Compile failure, strict warnings, or oversized output" },
          "413": { "description": "Request body over the configured limit (problem+json; audited, after authentication)" },
          "500": { "description": "Render panicked" },
          "503": { "description": "Audit failure or credential verifier unavailable without usable cached keys" },
          "504": { "description": "Render timeout" }
        }
      }
    },
    "/v1/seal/{type}": {
      "post": {
        "summary": "Render one document and seal it (PAdES). Present only when the deployment declares seals.",
        "description": "The render route's request body. The document type must name a seal in the bundle manifest; the payload the template reads carries a signing member {mode: seal, signerName, testOnly}. Requires the render:seal scope, which render:render does not imply, from a client the seal's allowedClients names; the legacy API key never seals. The signing time is the server's clock, truncated to seconds.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          {
            "name": "Idempotency-Key",
            "in": "header",
            "description": "Opaque correlation id; echoed and audited. A sealed file carries the signing time, so two seals of one request differ in their signed bytes; their first revision does not.",
            "schema": { "type": "string", "maxLength": 128 }
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["issuedAt", "data"],
                "properties": {
                  "locale": { "type": "string" },
                  "issuedAt": { "type": "string", "format": "date-time" },
                  "data": { "type": "object" },
                  "assets": {
                    "type": "object",
                    "additionalProperties": { "type": "string", "contentEncoding": "base64" }
                  }
                }
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Sealed PDF. Default representation is application/pdf with X-Registry-Document-Sha256 (the first revision, Render's rendered document), X-Registry-Signed-File-Sha256 (the whole signed file), X-Registry-Data-Sha256, X-Registry-Document-Version, X-Registry-Warning-Count, X-Registry-Seal-Id, X-Registry-Seal-Level (b-t or b-b), X-Registry-Certificate-Sha256 and, for b-t, X-Registry-Timestamp-Time. With Accept: application/json, the body is {pdfBase64, documentSha256, signedFileSha256, dataSha256, documentVersion, warnings, seal: {id, level, certificateSha256, timestampTime}}; timestampTime is present for b-t only. There is no pdfSha256.",
            "content": {
              "application/pdf": { "schema": { "type": "string", "format": "binary" } },
              "application/json": { "schema": { "type": "object" } }
            }
          },
          "400": { "description": "Invalid request, data, or assets; or document-not-sealable, a document type that names no seal" },
          "401": { "description": "Missing or invalid bearer credential; Bearer challenge" },
          "403": { "description": "forbidden: the credential lacks the render:seal scope, or is the legacy API key; seal-client-not-allowed: the verified client is not in the seal's allowedClients" },
          "413": { "description": "Request body over the configured limit (problem+json; audited, after authentication)" },
          "422": { "description": "Compile failure, strict warnings, or oversized output" },
          "500": { "description": "Render panicked, or the prepared file was refused" },
          "502": { "description": "timestamp-failed: the timestamp authority could not be reached, refused, returned an invalid token, or answered too large; one attempt, never retried, never sealed without the timestamp" },
          "503": { "description": "signing-unavailable or seal-certificate-invalid (the seal cannot sign now, plain rendering unaffected); audit failure; or credential verifier unavailable" },
          "504": { "description": "Render timeout" }
        }
      }
    }
  },
  "components": {
    "securitySchemes": {
      "bearerAuth": { "type": "http", "scheme": "bearer", "description": "Resource-bound OIDC access token with the route's scope: render:render for documents and rendering, render:seal for sealing. Or the configured legacy API key, which never seals." }
    }
  }
}
"#;
