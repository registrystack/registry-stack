//! Deterministic OpenAPI contract for the complete public delivery listener.

use serde_json::{json, Value};

use crate::{
    service::{
        AUTHORIZATION_SERVER_METADATA_PATH, CREDENTIAL_PATH, HEALTH_PATH, ISSUER_METADATA_PATH,
        NONCE_PATH, OFFERS_PATH, READY_PATH, TOKEN_PATH,
    },
    CREDENTIAL_FORMAT, PRE_AUTHORIZED_CODE_GRANT_TYPE,
};

#[cfg(test)]
use crate::service::PUBLIC_ROUTES;

/// Generate the committed public HTTP contract from the same route constants
/// and closed profile vocabulary used by the runtime.
#[must_use]
pub fn openapi_document() -> Value {
    let mut paths = serde_json::Map::new();
    paths.insert(
        HEALTH_PATH.to_owned(),
        json!({"get": probe_operation("health", "Liveness probe")}),
    );
    paths.insert(
        READY_PATH.to_owned(),
        json!({"get": probe_operation("readiness", "Process readiness probe")}),
    );
    paths.insert(
        ISSUER_METADATA_PATH.to_owned(),
        json!({
            "get": {
                "operationId": "getCredentialIssuerMetadata",
                "summary": "Discover the frozen wallet-delivery profile",
                "responses": {
                    "200": json_response("Credential issuer metadata", "CredentialIssuerMetadata"),
                    "408": problem_response("The configured request deadline elapsed"),
                    "503": problem_response("Backing Evidence discovery is unavailable")
                }
            }
        }),
    );
    paths.insert(
        AUTHORIZATION_SERVER_METADATA_PATH.to_owned(),
        json!({
            "get": {
                "operationId": "getAuthorizationServerMetadata",
                "summary": "Discover the anonymous pre-authorized token endpoint",
                "responses": {
                    "200": json_response("Authorization server metadata", "AuthorizationServerMetadata"),
                    "408": problem_response("The configured request deadline elapsed")
                }
            }
        }),
    );
    paths.insert(
        OFFERS_PATH.to_owned(),
        json!({
            "post": {
                "operationId": "createCredentialOffer",
                "summary": "Create one adopter-authorized credential offer",
                "security": [{"offerBearer": []}],
                "requestBody": required_json_body("OfferRequest"),
                "responses": {
                    "201": json_response("Credential offer", "OfferResponse"),
                    "400": problem_response("The offer request is outside the published catalog"),
                    "401": bearer_problem_response("The offer bearer token is missing or refused"),
                    "408": problem_response("The configured request deadline elapsed"),
                    "413": framework_response("The request body exceeds the configured byte limit"),
                    "503": problem_response("Authorization, Evidence discovery, or bounded state is unavailable")
                }
            }
        }),
    );
    paths.insert(
        TOKEN_PATH.to_owned(),
        json!({
            "post": {
                "operationId": "redeemPreAuthorizedCode",
                "summary": "Redeem one pre-authorized code anonymously",
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/x-www-form-urlencoded": {
                            "schema": {"$ref": "#/components/schemas/TokenRequest"}
                        }
                    }
                },
                "responses": {
                    "200": json_response("Single-use access token", "TokenResponse"),
                    "400": problem_response("The grant or code was refused"),
                    "408": problem_response("The configured request deadline elapsed"),
                    "413": framework_response("The request body exceeds the configured byte limit"),
                    "415": framework_response("The request is not form encoded"),
                    "422": framework_response("The form body cannot be decoded"),
                    "503": problem_response("The bounded state store is unavailable")
                }
            }
        }),
    );
    paths.insert(
        NONCE_PATH.to_owned(),
        json!({
            "post": {
                "operationId": "createCredentialNonce",
                "summary": "Mint one stateless proof nonce",
                "requestBody": {
                    "required": false,
                    "content": {"application/json": {"schema": {"type": "object", "maxProperties": 0}}}
                },
                "responses": {
                    "200": json_response("Stateless nonce", "NonceResponse"),
                    "400": problem_response("The nonce request was not empty"),
                    "408": problem_response("The configured request deadline elapsed"),
                    "413": framework_response("The request body exceeds the configured byte limit")
                }
            }
        }),
    );
    paths.insert(
        CREDENTIAL_PATH.to_owned(),
        json!({
            "post": {
                "operationId": "issueHolderBoundCredentials",
                "summary": "Exchange one claimed token and plural proofs for plural credentials",
                "security": [{"credentialBearer": []}],
                "requestBody": required_json_body("CredentialRequest"),
                "responses": {
                    "200": json_response("Evidence credentials, byte-for-byte", "CredentialResponse"),
                    "400": problem_response("The configuration, nonce, or proof was refused after token claim"),
                    "401": bearer_problem_response("The access token is missing, unknown, expired, or already claimed"),
                    "403": problem_response("Evidence refused the request"),
                    "408": problem_response("The configured request deadline elapsed"),
                    "413": framework_response("The request body exceeds the configured byte limit"),
                    "503": problem_response("Evidence or bounded state is unavailable")
                }
            }
        }),
    );

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Registry Evidence OID4VCI delivery API",
            "version": "1",
            "description": "Narrow OID4VCI 1.0 Final delivery profile. The normative source is products/evidence/contracts/oid4vci-profile.yaml. This contract does not claim full issuer certification or conformance."
        },
        "paths": Value::Object(paths),
        "components": {
            "securitySchemes": {
                "offerBearer": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
                "credentialBearer": {"type": "http", "scheme": "bearer"}
            },
            "schemas": schemas()
        },
        "x-unsupported-capabilities": [
            "authorization-code", "par", "dpop", "remote-did-resolution",
            "additional-credential-formats", "deferred-issuance", "notifications",
            "credential-status-or-lifecycle", "multi-replica-state", "plugin-extensibility",
            "draft-13"
        ]
    })
}

fn probe_operation(operation: &str, summary: &str) -> Value {
    json!({
        "operationId": operation,
        "summary": summary,
        "responses": {
            "200": json_response("Process status", "ProbeResponse"),
            "408": problem_response("The configured request deadline elapsed")
        }
    })
}

fn required_json_body(schema: &str) -> Value {
    json!({
        "required": true,
        "content": {"application/json": {"schema": {"$ref": format!("#/components/schemas/{schema}")}}}
    })
}

fn json_response(description: &str, schema: &str) -> Value {
    json!({
        "description": description,
        "headers": {
            "Cache-Control": {"schema": {"type": "string", "const": "no-store"}},
            "Pragma": {"schema": {"type": "string", "const": "no-cache"}}
        },
        "content": {"application/json": {"schema": {"$ref": format!("#/components/schemas/{schema}")}}}
    })
}

fn problem_response(description: &str) -> Value {
    json!({
        "description": description,
        "headers": {
            "Cache-Control": {"schema": {"type": "string", "const": "no-store"}},
            "Pragma": {"schema": {"type": "string", "const": "no-cache"}}
        },
        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Problem"}}}
    })
}

fn bearer_problem_response(description: &str) -> Value {
    let mut response = problem_response(description);
    response["headers"]["WWW-Authenticate"] =
        json!({"schema": {"type": "string", "const": "Bearer"}});
    response
}

fn framework_response(description: &str) -> Value {
    json!({
        "description": description,
        "headers": {
            "Cache-Control": {"schema": {"type": "string", "const": "no-store"}},
            "Pragma": {"schema": {"type": "string", "const": "no-cache"}}
        },
        "content": {"text/plain; charset=utf-8": {"schema": {"type": "string"}}}
    })
}

fn schemas() -> Value {
    json!({
        "ProbeResponse": {
            "type": "object", "additionalProperties": false, "required": ["status"],
            "properties": {"status": {"enum": ["ok", "ready"]}}
        },
        "Problem": {
            "type": "object", "additionalProperties": false,
            "required": ["error", "error_description"],
            "properties": {
                "error": {"enum": [
                    "invalid_request", "invalid_token", "unsupported_grant_type", "invalid_grant",
                    "invalid_credential_request", "invalid_proof", "invalid_nonce",
                    "temporarily_unavailable", "server_error"
                ]},
                "error_description": {"type": "string"}
            }
        },
        "CredentialIssuerMetadata": {
            "type": "object", "additionalProperties": false,
            "required": [
                "credential_issuer", "credential_endpoint", "nonce_endpoint",
                "authorization_servers", "batch_credential_issuance",
                "credential_configurations_supported"
            ],
            "properties": {
                "credential_issuer": {"type": "string", "format": "uri"},
                "credential_endpoint": {"type": "string", "format": "uri"},
                "nonce_endpoint": {"type": "string", "format": "uri"},
                "authorization_servers": {
                    "type": "array", "minItems": 1, "maxItems": 1,
                    "items": {"type": "string", "format": "uri"}
                },
                "batch_credential_issuance": {
                    "type": "object", "additionalProperties": false, "required": ["batch_size"],
                    "properties": {"batch_size": {"type": "integer", "minimum": 1, "maximum": 16}}
                },
                "credential_configurations_supported": {
                    "type": "object", "additionalProperties": {"$ref": "#/components/schemas/CredentialConfiguration"}
                }
            }
        },
        "CredentialConfiguration": {
            "type": "object", "additionalProperties": false,
            "required": [
                "format", "vct", "cryptographic_binding_methods_supported",
                "credential_signing_alg_values_supported", "proof_types_supported"
            ],
            "properties": {
                "format": {"const": CREDENTIAL_FORMAT},
                "vct": {"type": "string", "format": "uri"},
                "cryptographic_binding_methods_supported": {
                    "type": "array", "prefixItems": [{"const": "jwk"}, {"const": "did:jwk"}],
                    "minItems": 2, "maxItems": 2
                },
                "credential_signing_alg_values_supported": {
                    "type": "array", "prefixItems": [{"const": "ES256"}], "minItems": 1, "maxItems": 1
                },
                "proof_types_supported": {
                    "type": "object", "additionalProperties": false, "required": ["jwt"],
                    "properties": {"jwt": {
                        "type": "object", "additionalProperties": false,
                        "required": ["proof_signing_alg_values_supported"],
                        "properties": {"proof_signing_alg_values_supported": {
                            "type": "array", "prefixItems": [{"const": "ES256"}], "minItems": 1, "maxItems": 1
                        }}
                    }}
                }
            }
        },
        "AuthorizationServerMetadata": {
            "type": "object", "additionalProperties": false,
            "required": [
                "issuer", "token_endpoint", "grant_types_supported", "response_types_supported",
                "token_endpoint_auth_methods_supported", "pre-authorized_grant_anonymous_access_supported"
            ],
            "properties": {
                "issuer": {"type": "string", "format": "uri"},
                "token_endpoint": {"type": "string", "format": "uri"},
                "grant_types_supported": {
                    "type": "array", "prefixItems": [{"const": PRE_AUTHORIZED_CODE_GRANT_TYPE}],
                    "minItems": 1, "maxItems": 1
                },
                "response_types_supported": {"type": "array", "maxItems": 0},
                "token_endpoint_auth_methods_supported": {
                    "type": "array", "prefixItems": [{"const": "none"}], "minItems": 1, "maxItems": 1
                },
                "pre-authorized_grant_anonymous_access_supported": {"const": true}
            }
        },
        "RequestedSubject": {
            "type": "object", "additionalProperties": false, "required": ["role"],
            "properties": {
                "role": {"type": "string", "pattern": "^[a-z][a-z0-9._-]{0,63}$"},
                "selectorValues": {
                    "type": "object", "maxProperties": 16,
                    "additionalProperties": {"type": ["string", "integer", "boolean"]}
                }
            }
        },
        "OfferRequest": {
            "type": "object", "additionalProperties": false,
            "required": ["credentialConfigurationId", "subjects"],
            "properties": {
                "credentialConfigurationId": {"type": "string"},
                "subjects": {"type": "array", "minItems": 1, "maxItems": 8, "items": {"$ref": "#/components/schemas/RequestedSubject"}},
                "transactionCode": {"type": "boolean", "default": false}
            }
        },
        "OfferResponse": {
            "type": "object", "additionalProperties": false,
            "required": ["credentialOffer", "credentialOfferUri", "expiresIn"],
            "properties": {
                "credentialOffer": {"$ref": "#/components/schemas/CredentialOffer"},
                "credentialOfferUri": {"type": "string", "format": "uri"},
                "expiresIn": {"type": "integer", "minimum": 60, "maximum": 900},
                "transactionCode": {"type": "string", "pattern": "^[0-9]{6}$"}
            }
        },
        "CredentialOffer": {
            "type": "object", "additionalProperties": false,
            "required": ["credential_issuer", "credential_configuration_ids", "grants"],
            "properties": {
                "credential_issuer": {"type": "string", "format": "uri"},
                "credential_configuration_ids": {
                    "type": "array", "minItems": 1, "maxItems": 1,
                    "items": {"type": "string"}
                },
                "grants": {
                    "type": "object", "additionalProperties": false,
                    "required": [PRE_AUTHORIZED_CODE_GRANT_TYPE],
                    "properties": {
                        PRE_AUTHORIZED_CODE_GRANT_TYPE: {
                            "$ref": "#/components/schemas/PreAuthorizedCodeGrant"
                        }
                    }
                }
            }
        },
        "PreAuthorizedCodeGrant": {
            "type": "object", "additionalProperties": false,
            "required": ["pre-authorized_code"],
            "properties": {
                "pre-authorized_code": {"type": "string"},
                "tx_code": {"$ref": "#/components/schemas/TransactionCodeDescription"}
            }
        },
        "TransactionCodeDescription": {
            "type": "object", "additionalProperties": false,
            "required": ["input_mode", "length"],
            "properties": {
                "input_mode": {"const": "numeric"},
                "length": {"const": 6}
            }
        },
        "TokenRequest": {
            "type": "object", "additionalProperties": false,
            "required": ["grant_type", "pre-authorized_code"],
            "properties": {
                "grant_type": {"const": PRE_AUTHORIZED_CODE_GRANT_TYPE},
                "pre-authorized_code": {"type": "string"},
                "tx_code": {"type": "string", "pattern": "^[0-9]{6}$"}
            }
        },
        "TokenResponse": {
            "type": "object", "additionalProperties": false,
            "required": ["access_token", "token_type", "expires_in"],
            "properties": {
                "access_token": {"type": "string"},
                "token_type": {"const": "Bearer"},
                "expires_in": {"type": "integer", "minimum": 60, "maximum": 900}
            }
        },
        "NonceResponse": {
            "type": "object", "additionalProperties": false, "required": ["c_nonce"],
            "properties": {"c_nonce": {"type": "string"}}
        },
        "CredentialRequest": {
            "type": "object", "additionalProperties": false,
            "required": ["credential_configuration_id", "proofs"],
            "properties": {
                "credential_configuration_id": {"type": "string"},
                "proofs": {
                    "type": "object", "additionalProperties": false, "required": ["jwt"],
                    "properties": {"jwt": {
                        "type": "array", "minItems": 1, "maxItems": 16,
                        "items": {"type": "string", "maxLength": 8192}
                    }}
                }
            }
        },
        "CredentialResponse": {
            "type": "object", "additionalProperties": false, "required": ["credentials"],
            "properties": {"credentials": {
                "type": "array", "minItems": 1, "maxItems": 16,
                "items": {
                    "type": "object", "additionalProperties": false, "required": ["credential"],
                    "properties": {"credential": {"type": "string"}}
                }
            }}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn the_openapi_contract_covers_exactly_the_public_route_table() {
        let document = openapi_document();
        let actual = document["paths"]
            .as_object()
            .expect("paths are an object")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let expected = PUBLIC_ROUTES
            .into_iter()
            .map(|route| route.path())
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, expected);
    }

    #[test]
    fn the_contract_includes_middleware_and_extractor_refusals() {
        let document = openapi_document();
        for path in PUBLIC_ROUTES.map(|route| route.path()) {
            let operation = document["paths"][path]
                .as_object()
                .expect("a route publishes an operation")
                .values()
                .next()
                .expect("a route has one operation");
            assert!(operation["responses"].get("408").is_some(), "{path}");
        }
        for path in [OFFERS_PATH, TOKEN_PATH, NONCE_PATH, CREDENTIAL_PATH] {
            assert!(
                document["paths"][path]["post"]["responses"]
                    .get("413")
                    .is_some(),
                "{path}"
            );
        }
        assert!(document["paths"][TOKEN_PATH]["post"]["responses"]
            .get("415")
            .is_some());
        assert!(document["paths"][TOKEN_PATH]["post"]["responses"]
            .get("422")
            .is_some());
        for path in [OFFERS_PATH, CREDENTIAL_PATH] {
            assert_eq!(
                document["paths"][path]["post"]["responses"]["401"]["headers"]["WWW-Authenticate"]
                    ["schema"]["const"],
                "Bearer",
                "{path}"
            );
        }
    }

    #[test]
    fn the_contract_pins_only_the_frozen_profile() {
        let document = openapi_document();
        let rendered = document.to_string();
        for required in [
            CREDENTIAL_FORMAT,
            PRE_AUTHORIZED_CODE_GRANT_TYPE,
            "pre-authorized_grant_anonymous_access_supported",
            "did:jwk",
            "ES256",
        ] {
            assert!(rendered.contains(required), "contract omitted {required}");
        }
        for unsupported in [
            "authorization-code",
            "dpop",
            "remote-did-resolution",
            "draft-13",
        ] {
            assert!(document["x-unsupported-capabilities"]
                .as_array()
                .expect("unsupported list")
                .iter()
                .any(|entry| entry == unsupported));
        }
    }
}
