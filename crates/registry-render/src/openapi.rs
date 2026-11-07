//! The static OpenAPI document. A handful of routes do not justify a
//! generator; this file is the contract, and the serve tests pin its routes.
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

pub const OPENAPI_JSON: &str = r##"{
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
          "200": { "description": "ready. A deployment that seals adds a signing member, one entry per seal: {status: ready} or {status: not-ready, reason: certificate-expired | certificate-not-yet-valid | signer-not-ready}, with testOnly: true for a seal the runtime declares assuranceProfile: local. A seal never changes the status code; readiness never requests a timestamp." },
          "503": { "description": "not ready" }
        }
      }
    },
    "/v1/documents": {
      "get": {
        "summary": "List document types in the verified package",
        "security": [{ "bearerAuth": [] }],
        "responses": { "200": { "description": "document inventory; a document type the seal route takes carries its seal id as seal" } }
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
            "description": "Rendered PDF. The default representation is application/pdf with the headers below. A nonzero warning count means the host should inspect the JSON warnings before releasing the document. With Accept: application/json, the body carries the same values and the warning text, and the headers are not sent. pdfSha256 and dataSha256, and their headers, are deprecated: they are pdfDigest and dataDigest without the sha256: label.",
            "headers": {
              "X-Registry-Pdf-Digest": {
                "description": "SHA-256 over the PDF.",
                "schema": { "$ref": "#/components/schemas/Digest" }
              },
              "X-Registry-Data-Digest": {
                "description": "SHA-256 over the canonical request envelope the template read.",
                "schema": { "$ref": "#/components/schemas/Digest" }
              },
              "X-Registry-Pdf-Sha256": {
                "description": "Deprecated: X-Registry-Pdf-Digest without its sha256: label.",
                "deprecated": true,
                "schema": { "$ref": "#/components/schemas/Sha256Hex" }
              },
              "X-Registry-Data-Sha256": {
                "description": "Deprecated: X-Registry-Data-Digest without its sha256: label.",
                "deprecated": true,
                "schema": { "$ref": "#/components/schemas/Sha256Hex" }
              },
              "X-Registry-Document-Version": {
                "description": "The document type and its version, as <id> v<version>.",
                "schema": { "type": "string" }
              },
              "X-Registry-Warning-Count": {
                "description": "Number of rendering warnings, including zero. Present on PDF responses; warning text is available in the JSON representation.",
                "schema": { "type": "integer", "minimum": 0 }
              }
            },
            "content": {
              "application/pdf": { "schema": { "type": "string", "format": "binary" } },
              "application/json": {
                "schema": {
                  "type": "object",
                  "required": ["pdfBase64", "pdfDigest", "dataDigest", "pdfSha256", "dataSha256", "documentVersion", "warnings"],
                  "properties": {
                    "pdfBase64": { "type": "string", "contentEncoding": "base64" },
                    "pdfDigest": { "$ref": "#/components/schemas/Digest" },
                    "dataDigest": { "$ref": "#/components/schemas/Digest" },
                    "pdfSha256": {
                      "description": "Deprecated: pdfDigest without its sha256: label.",
                      "deprecated": true,
                      "$ref": "#/components/schemas/Sha256Hex"
                    },
                    "dataSha256": {
                      "description": "Deprecated: dataDigest without its sha256: label.",
                      "deprecated": true,
                      "$ref": "#/components/schemas/Sha256Hex"
                    },
                    "documentVersion": { "type": "string" },
                    "warnings": { "type": "array", "items": { "type": "string" } }
                  }
                }
              }
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
            "description": "Sealed PDF. The default representation is application/pdf with the headers below. With Accept: application/json, the body carries the same values and the warning text, and the headers are not sent. A sealed file has two digests: documentDigest over the first revision, Render's rendered document, and signedFileDigest over the whole signed file; there is no pdfDigest.",
            "headers": {
              "X-Registry-Document-Digest": {
                "description": "SHA-256 over the first revision, Render's rendered document.",
                "schema": { "$ref": "#/components/schemas/Digest" }
              },
              "X-Registry-Signed-File-Digest": {
                "description": "SHA-256 over the whole signed file.",
                "schema": { "$ref": "#/components/schemas/Digest" }
              },
              "X-Registry-Data-Digest": {
                "description": "SHA-256 over the canonical request envelope the template read, its signing member included.",
                "schema": { "$ref": "#/components/schemas/Digest" }
              },
              "X-Registry-Document-Version": {
                "description": "The document type and its version, as <id> v<version>.",
                "schema": { "type": "string" }
              },
              "X-Registry-Package-Digest": {
                "description": "The served package's digest, in the form package.expectedDigest takes.",
                "schema": { "$ref": "#/components/schemas/Digest" }
              },
              "X-Registry-Warning-Count": {
                "description": "Number of rendering warnings, including zero.",
                "schema": { "type": "integer", "minimum": 0 }
              },
              "X-Registry-Seal-Id": {
                "description": "The runtime seal id.",
                "schema": { "type": "string" }
              },
              "X-Registry-Seal-Level": {
                "description": "The PAdES baseline level, by its ETSI EN 319 142-1 name.",
                "schema": { "type": "string", "enum": ["B-T", "B-B"] }
              },
              "X-Registry-Certificate-Digest": {
                "description": "SHA-256 over the seal certificate's DER.",
                "schema": { "$ref": "#/components/schemas/Digest" }
              },
              "X-Registry-Timestamped-At": {
                "description": "B-T only: the timestamp authority's genTime, RFC 3339 in UTC at the precision the authority gave (fractional seconds only when genTime has them).",
                "schema": { "type": "string", "format": "date-time" }
              },
              "X-Registry-Seal-Test-Only": {
                "description": "true, for a seal the runtime declares assuranceProfile: local; absent otherwise.",
                "schema": { "type": "string", "enum": ["true"] }
              }
            },
            "content": {
              "application/pdf": { "schema": { "type": "string", "format": "binary" } },
              "application/json": {
                "schema": {
                  "type": "object",
                  "required": ["pdfBase64", "documentDigest", "signedFileDigest", "dataDigest", "documentVersion", "packageDigest", "warnings", "seal"],
                  "properties": {
                    "pdfBase64": { "type": "string", "contentEncoding": "base64" },
                    "documentDigest": { "$ref": "#/components/schemas/Digest" },
                    "signedFileDigest": { "$ref": "#/components/schemas/Digest" },
                    "dataDigest": { "$ref": "#/components/schemas/Digest" },
                    "documentVersion": { "type": "string" },
                    "packageDigest": { "$ref": "#/components/schemas/Digest" },
                    "warnings": { "type": "array", "items": { "type": "string" } },
                    "seal": {
                      "type": "object",
                      "required": ["id", "level", "certificateDigest"],
                      "properties": {
                        "id": { "type": "string" },
                        "level": { "type": "string", "enum": ["B-T", "B-B"] },
                        "certificateDigest": { "$ref": "#/components/schemas/Digest" },
                        "timestampedAt": {
                          "description": "B-T only, as X-Registry-Timestamped-At.",
                          "type": "string",
                          "format": "date-time"
                        },
                        "testOnly": {
                          "description": "Always true when present, for a seal the runtime declares assuranceProfile: local.",
                          "type": "boolean",
                          "const": true
                        }
                      }
                    }
                  }
                }
              }
            }
          },
          "400": { "description": "Invalid request, data, or assets; or document-not-sealable, a document type that names no seal" },
          "401": { "description": "Missing or invalid bearer credential; Bearer challenge" },
          "403": { "description": "forbidden: the credential lacks the render:seal scope, or is the legacy API key; seal-client-not-allowed: the verified client is not in the seal's allowedClients" },
          "413": { "description": "Request body over the configured limit (problem+json; audited, after authentication)" },
          "422": { "description": "Compile failure, strict warnings, or oversized output" },
          "429": { "description": "rate-limited: as many seals as render slots are already in flight; refused, not queued; retry later" },
          "500": { "description": "Render panicked, or the prepared file was refused" },
          "502": { "description": "timestamp-failed: the timestamp authority could not be reached, refused, returned an invalid token, or answered too large; one attempt, never retried, never sealed without the timestamp" },
          "503": { "description": "signing-unavailable or seal-certificate-invalid (the seal cannot sign now, plain rendering unaffected); audit failure; or credential verifier unavailable" },
          "504": { "description": "Render timeout" }
        }
      }
    }
  },
  "components": {
    "schemas": {
      "Digest": {
        "description": "A labelled SHA-256 digest: sha256: and 64 lowercase hex digits.",
        "type": "string",
        "pattern": "^sha256:[0-9a-f]{64}$"
      },
      "Sha256Hex": {
        "description": "A bare SHA-256: 64 lowercase hex digits.",
        "type": "string",
        "pattern": "^[0-9a-f]{64}$"
      }
    },
    "securitySchemes": {
      "bearerAuth": { "type": "http", "scheme": "bearer", "description": "Resource-bound OIDC access token with the route's scope: render:render for documents and rendering, render:seal for sealing. Or the configured legacy API key, which never seals." }
    }
  }
}
"##;
