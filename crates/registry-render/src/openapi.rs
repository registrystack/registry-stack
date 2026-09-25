//! The static OpenAPI document. Two endpoints do not justify a generator;
//! this file is the contract, and the serve tests pin its routes.

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
        "summary": "Readiness (audit destination included)",
        "responses": {
          "200": { "description": "ready" },
          "503": { "description": "not ready" }
        }
      }
    },
    "/v1/documents": {
      "get": {
        "summary": "List document types in the sealed bundle",
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
            "description": "Rendered PDF. Default representation is application/pdf with X-Registry-Pdf-Sha256, X-Registry-Data-Sha256, X-Registry-Document-Version headers. With Accept: application/json, the body is {pdfBase64, pdfSha256, dataSha256, documentVersion, warnings}.",
            "content": {
              "application/pdf": { "schema": { "type": "string", "format": "binary" } },
              "application/json": { "schema": { "type": "object" } }
            }
          },
          "400": { "description": "Invalid request, data, or assets (problem+json with JSON pointers)" },
          "401": { "description": "Missing or wrong API key" },
          "422": { "description": "Compile failure, strict warnings, or oversized output" },
          "413": { "description": "Request body over the configured limit (problem+json; audited, after authentication)" },
          "500": { "description": "Render panicked" },
          "503": { "description": "Audit failure (fail closed) or not ready" },
          "504": { "description": "Render timeout" }
        }
      }
    }
  },
  "components": {
    "securitySchemes": {
      "bearerAuth": { "type": "http", "scheme": "bearer" }
    }
  }
}
"#;
