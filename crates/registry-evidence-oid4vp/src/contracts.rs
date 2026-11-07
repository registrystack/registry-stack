//! Deterministic OpenAPI contract for the verifier listener.

use serde_json::{json, Value};

use crate::service::{
    DID_DOCUMENT_PATH, HEALTH_PATH, JWKS_PATH, READY_PATH, READ_PATH, REQUEST_PATH, RESPONSE_PATH,
    SESSIONS_PATH, SESSION_PATH,
};

/// Every route the listener can serve. The two identity documents are served
/// only when a client identifier needs them.
pub const ROUTES: [&str; 9] = [
    HEALTH_PATH,
    READY_PATH,
    SESSIONS_PATH,
    SESSION_PATH,
    REQUEST_PATH,
    RESPONSE_PATH,
    READ_PATH,
    DID_DOCUMENT_PATH,
    JWKS_PATH,
];

const FAILURE_CATEGORIES: [&str; 6] = [
    "access_denied",
    "invalid_request",
    "invalid_client",
    "vp_formats_not_supported",
    "wallet_unavailable",
    "other",
];

/// Generate the committed HTTP contract from the same route constants the
/// runtime registers.
#[must_use]
pub fn openapi_document() -> Value {
    let mut paths = serde_json::Map::new();
    paths.insert(
        HEALTH_PATH.to_owned(),
        json!({"get": probe_operation("health", "Liveness probe", "HealthResponse")}),
    );
    paths.insert(READY_PATH.to_owned(), json!({"get": readiness_operation()}));
    paths.insert(
        SESSIONS_PATH.to_owned(),
        json!({
            "post": {
                "operationId": "createPresentationSession",
                "summary": "Start one presentation exchange for the authenticated applicant",
                "security": [{"applicantBearer": []}],
                "requestBody": required_json_body("CreateSessionRequest"),
                "responses": {
                    "201": json_response("Session created", "CreateSessionResponse"),
                    "400": problem_response("The body is not a JSON object with one policy member"),
                    "401": bearer_problem_response("The applicant token is missing or refused"),
                    "408": problem_response("The configured request deadline elapsed"),
                    "413": problem_response("The request body exceeds the configured byte limit"),
                    "415": problem_response("The request is not application/json"),
                    "422": problem_response("No presentation policy has this identifier"),
                    "429": retry_response("The applicant is creating sessions too quickly"),
                    "500": problem_response("Session secrets or the request identity could not be produced"),
                    "503": retry_response("The session store is full, the audit destination is stopped, or the token issuer is unavailable")
                }
            }
        }),
    );
    paths.insert(
        SESSION_PATH.to_owned(),
        json!({
            "get": {
                "operationId": "readSessionStatus",
                "summary": "Read the state of a session the applicant created",
                "security": [{"applicantBearer": []}],
                "parameters": [{
                    "name": "reference", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": json_response("Session status, never the presented content", "SessionStatus"),
                    "401": bearer_problem_response("The applicant token is missing or refused"),
                    "404": problem_response("Unknown, expired, or created by another applicant"),
                    "408": problem_response("The configured request deadline elapsed"),
                    "503": retry_response("The token issuer is unavailable")
                }
            }
        }),
    );
    paths.insert(
        REQUEST_PATH.to_owned(),
        json!({
            "get": {
                "operationId": "fetchRequestObject",
                "summary": "Serve the signed OpenID4VP request object to the wallet",
                "description": "Anonymous; the request identifier is a bearer capability. The object is a JWT signed under the policy's client identifier.",
                "parameters": [{
                    "name": "request_id", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {
                        "description": "Signed request object (RFC 9101)",
                        "headers": {"Cache-Control": {"schema": {"type": "string", "const": "no-store"}}},
                        "content": {"application/oauth-authz-req+jwt": {"schema": {"type": "string"}}}
                    },
                    "404": problem_response("Unknown, expired, or no longer pending"),
                    "408": problem_response("The configured request deadline elapsed"),
                    "429": retry_response("Requests are arriving too quickly"),
                    "500": problem_response("The request object could not be signed"),
                    "503": retry_response("The audit destination is stopped")
                }
            }
        }),
    );
    paths.insert(
        RESPONSE_PATH.to_owned(),
        json!({
            "post": {
                "operationId": "receiveWalletResponse",
                "summary": "Receive the wallet's direct_post.jwt response",
                "description": "Anonymous; the request identifier is a bearer capability. The form carries one encrypted `response` JWE, or a plain OAuth `error`. Answers use the OAuth error shape and never carry a description.",
                "parameters": [{
                    "name": "request_id", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/x-www-form-urlencoded": {
                            "schema": {"$ref": "#/components/schemas/WalletForm"}
                        }
                    }
                },
                "responses": {
                    "200": json_response("The response was accepted; an empty object", "Empty"),
                    "400": oauth_error_response("The response was refused"),
                    "408": problem_response("The configured request deadline elapsed"),
                    "413": problem_response("The body exceeds the response size limit"),
                    "429": oauth_retry_response("Responses are arriving too quickly"),
                    "503": oauth_retry_response("The audit destination is stopped, the response is being recorded, or holding the presentation would pass the held-presentation byte budget")
                }
            }
        }),
    );
    paths.insert(
        READ_PATH.to_owned(),
        json!({
            "post": {
                "operationId": "readPresentation",
                "summary": "Release the presentation a wallet returned, to Evidence",
                "security": [{"evidenceBearer": []}],
                "requestBody": required_json_body("ReadRequest"),
                "responses": {
                    "200": json_response("The presentation and the session context; the first successful read consumes the result", "ReadResponse"),
                    "400": problem_response("The body does not name a reference and the applicant principal"),
                    "401": bearer_problem_response("The Evidence service credential is missing or refused"),
                    "404": problem_response("Unknown, expired, already read, or created by another principal"),
                    "408": problem_response("The configured request deadline elapsed"),
                    "409": problem_response("The wallet has not presented yet"),
                    "413": problem_response("The request body exceeds the configured byte limit"),
                    "415": problem_response("The request is not application/json"),
                    "422": json!({
                        "description": "The wallet reported an error instead of presenting; the first read consumes the result",
                        "headers": no_store_headers(),
                        "content": {"application/problem+json": {"schema": {
                            "allOf": [
                                {"$ref": "#/components/schemas/Problem"},
                                {
                                    "type": "object", "required": ["category"],
                                    "properties": {"category": {"enum": FAILURE_CATEGORIES}}
                                }
                            ]
                        }}}
                    }),
                    "429": retry_response("Reads are arriving too quickly"),
                    "503": retry_response("The audit destination is stopped or the token issuer is unavailable")
                }
            }
        }),
    );
    paths.insert(
        DID_DOCUMENT_PATH.to_owned(),
        json!({
            "get": {
                "operationId": "getDidDocument",
                "summary": "The DID document of the did:web client identifier",
                "description": "Served only when a decentralized-identifier client identifier is configured.",
                "responses": {
                    "200": identity_document_response("DID document", "DidDocument"),
                    "404": problem_response("No did:web client identifier is configured"),
                    "408": problem_response("The configured request deadline elapsed")
                }
            }
        }),
    );
    paths.insert(
        JWKS_PATH.to_owned(),
        json!({
            "get": {
                "operationId": "getVerifierKeys",
                "summary": "The public keys of the EdDSA client identifiers",
                "description": "Served only when a pre-registered or decentralized-identifier client identifier is configured.",
                "responses": {
                    "200": identity_document_response("JSON Web Key Set", "Jwks"),
                    "404": problem_response("No EdDSA client identifier is configured"),
                    "408": problem_response("The configured request deadline elapsed")
                }
            }
        }),
    );

    publish_trace_header(&mut paths);

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Registry Evidence OpenID4VP verifier API",
            "version": "1",
            "description": "OpenID4VP 1.0 verifier front end for Evidence. The normative source is products/evidence/contracts/oid4vp-profile.yaml. This contract does not claim verifier certification or HAIP conformance."
        },
        "paths": Value::Object(paths),
        "components": {
            "securitySchemes": {
                "applicantBearer": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
                "evidenceBearer": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
            },
            "schemas": schemas()
        }
    })
}

/// Every response of every operation carries exactly one canonical W3C
/// `traceparent` (version 0), whether it is a success, a problem or a wallet
/// answer. Evidence refuses an upstream response without it.
fn publish_trace_header(paths: &mut serde_json::Map<String, Value>) {
    let header = json!({
        "description": "The W3C Trace Context version 0 field of the request, or a server-created one when the request carried none or an invalid or repeated one. `tracestate` is never answered.",
        "schema": {"type": "string", "pattern": "^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$"}
    });
    for operations in paths.values_mut().filter_map(Value::as_object_mut) {
        for operation in operations.values_mut() {
            let Some(responses) = operation["responses"].as_object_mut() else {
                continue;
            };
            for response in responses.values_mut() {
                response["headers"]["Traceparent"] = header.clone();
            }
        }
    }
}

fn no_store_headers() -> Value {
    json!({"Cache-Control": {"schema": {"type": "string", "const": "no-store"}}})
}

fn probe_operation(operation: &str, summary: &str, schema: &str) -> Value {
    json!({
        "operationId": operation,
        "summary": summary,
        "responses": {
            "200": json_response("Process status", schema),
            "408": problem_response("The configured request deadline elapsed")
        }
    })
}

fn readiness_operation() -> Value {
    let mut operation =
        probe_operation("readiness", "Process readiness probe", "ReadinessResponse");
    operation["responses"]["503"] = json_response(
        "The required local audit destination is stopped or stalled, or a client identifier certificate has expired",
        "ReadinessResponse",
    );
    operation
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
        "headers": no_store_headers(),
        "content": {"application/json": {"schema": {"$ref": format!("#/components/schemas/{schema}")}}}
    })
}

fn identity_document_response(description: &str, schema: &str) -> Value {
    json!({
        "description": description,
        "headers": {"Cache-Control": {"schema": {"type": "string", "const": "public, max-age=300"}}},
        "content": {"application/json": {"schema": {"$ref": format!("#/components/schemas/{schema}")}}}
    })
}

fn problem_response(description: &str) -> Value {
    json!({
        "description": description,
        "headers": no_store_headers(),
        "content": {"application/problem+json": {"schema": {"$ref": "#/components/schemas/Problem"}}}
    })
}

fn retry_response(description: &str) -> Value {
    let mut response = problem_response(description);
    response["headers"]["Retry-After"] = json!({"schema": {"type": "integer", "minimum": 1}});
    response
}

fn bearer_problem_response(description: &str) -> Value {
    let mut response = problem_response(description);
    response["headers"]["WWW-Authenticate"] =
        json!({"schema": {"type": "string", "const": "Bearer"}});
    response
}

fn oauth_error_response(description: &str) -> Value {
    json!({
        "description": description,
        "headers": no_store_headers(),
        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/OAuthError"}}}
    })
}

fn oauth_retry_response(description: &str) -> Value {
    let mut response = oauth_error_response(description);
    response["headers"]["Retry-After"] = json!({"schema": {"type": "integer", "minimum": 1}});
    response
}

fn schemas() -> Value {
    json!({
        "HealthResponse": {
            "type": "object", "additionalProperties": false, "required": ["status"],
            "properties": {"status": {"const": "ok"}}
        },
        "ReadinessResponse": {
            "type": "object", "additionalProperties": false, "required": ["status"],
            "properties": {"status": {"enum": ["ready", "not_ready"]}}
        },
        "Empty": {"type": "object", "additionalProperties": false},
        "Problem": {
            "type": "object", "required": ["type", "title", "status"],
            "properties": {
                "type": {"type": "string", "format": "uri"},
                "title": {"type": "string"},
                "status": {"type": "integer"},
                "detail": {"type": "string"}
            }
        },
        "OAuthError": {
            "type": "object", "additionalProperties": false, "required": ["error"],
            "properties": {"error": {"enum": ["invalid_request", "temporarily_unavailable"]}}
        },
        "CreateSessionRequest": {
            "type": "object", "additionalProperties": false, "required": ["policy"],
            "properties": {"policy": {"type": "string"}}
        },
        "CreateSessionResponse": {
            "type": "object", "additionalProperties": false,
            "required": ["reference", "requestUri", "walletInvocation", "expiresAt"],
            "properties": {
                "reference": {"type": "string"},
                "requestUri": {"type": "string", "format": "uri"},
                "walletInvocation": {
                    "type": "string",
                    "description": "openid4vp://authorize?client_id=...&request_uri=..."
                },
                "expiresAt": {"type": "string", "format": "date-time"}
            }
        },
        "SessionStatus": {
            "type": "object", "additionalProperties": false,
            "required": ["status", "policy", "expiresAt"],
            "properties": {
                "status": {"enum": ["pending", "received", "failed"]},
                "policy": {"type": "string"},
                "expiresAt": {"type": "string", "format": "date-time"},
                "failureCategory": {
                    "enum": FAILURE_CATEGORIES,
                    "description": "Present only when the session failed on a wallet error."
                }
            }
        },
        "WalletForm": {
            "type": "object", "additionalProperties": false,
            "properties": {
                "response": {"type": "string", "description": "Compact JWE (ECDH-ES; A128GCM or A256GCM)."},
                "error": {"type": "string"},
                "state": {"type": "string"}
            }
        },
        "Principal": {
            "type": "object", "additionalProperties": false, "required": ["issuer", "subject"],
            "properties": {"issuer": {"type": "string"}, "subject": {"type": "string"}}
        },
        "ReadRequest": {
            "type": "object", "additionalProperties": false, "required": ["reference", "principal"],
            "properties": {
                "reference": {"type": "string"},
                "principal": {"$ref": "#/components/schemas/Principal"}
            }
        },
        "ReadResponse": {
            "type": "object", "additionalProperties": false, "required": ["presentation", "context"],
            "properties": {
                "presentation": {
                    "type": "object",
                    "description": "DCQL credential query id to the presented credentials, as received.",
                    "additionalProperties": {"type": "array", "items": {"type": "string"}}
                },
                "context": {
                    "type": "object", "additionalProperties": false,
                    "required": [
                        "nonce", "clientId", "responseUri", "responseKeyThumbprint",
                        "policyId", "createdBy", "receivedAt"
                    ],
                    "properties": {
                        "nonce": {"type": "string"},
                        "clientId": {"type": "string"},
                        "responseUri": {"type": "string", "format": "uri"},
                        "responseKeyThumbprint": {"type": "string"},
                        "policyId": {"type": "string"},
                        "createdBy": {"$ref": "#/components/schemas/Principal"},
                        "receivedAt": {"type": "string", "format": "date-time"}
                    }
                }
            }
        },
        "DidDocument": {
            "type": "object", "additionalProperties": false,
            "required": ["@context", "id", "verificationMethod", "authentication", "assertionMethod"],
            "properties": {
                "@context": {"type": "array", "items": {"type": "string"}},
                "id": {"type": "string", "pattern": "^did:web:"},
                "verificationMethod": {
                    "type": "array", "minItems": 1, "maxItems": 1,
                    "items": {
                        "type": "object", "additionalProperties": false,
                        "required": ["id", "type", "controller", "publicKeyMultibase"],
                        "properties": {
                            "id": {"type": "string"},
                            "type": {"const": "Ed25519VerificationKey2020"},
                            "controller": {"type": "string"},
                            "publicKeyMultibase": {"type": "string", "pattern": "^z"}
                        }
                    }
                },
                "authentication": {"type": "array", "items": {"type": "string"}},
                "assertionMethod": {"type": "array", "items": {"type": "string"}}
            }
        },
        "Jwks": {
            "type": "object", "additionalProperties": false, "required": ["keys"],
            "properties": {"keys": {
                "type": "array", "minItems": 1,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["kty", "crv", "x", "kid", "use", "alg"],
                    "properties": {
                        "kty": {"const": "OKP"},
                        "crv": {"const": "Ed25519"},
                        "x": {"type": "string"},
                        "kid": {"type": "string"},
                        "use": {"const": "sig"},
                        "alg": {"const": "EdDSA"}
                    }
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
    fn the_openapi_contract_covers_exactly_the_route_table() {
        let document = openapi_document();
        let actual = document["paths"]
            .as_object()
            .expect("paths are an object")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, ROUTES.into_iter().collect::<BTreeSet<_>>());
    }

    #[test]
    fn every_route_publishes_one_operation_with_the_deadline_refusal() {
        let document = openapi_document();
        for path in ROUTES {
            let operations = document["paths"][path].as_object().expect("a route");
            assert_eq!(operations.len(), 1, "{path}");
            let operation = operations.values().next().unwrap();
            assert!(operation["responses"].get("408").is_some(), "{path}");
        }
    }

    #[test]
    fn every_response_publishes_the_traceparent_header() {
        let document = openapi_document();
        for path in ROUTES {
            let operation = document["paths"][path]
                .as_object()
                .expect("a route")
                .values()
                .next()
                .unwrap();
            for (status, response) in operation["responses"].as_object().unwrap() {
                let schema = &response["headers"]["Traceparent"]["schema"];
                assert_eq!(schema["type"], "string", "{path} {status}");
                assert!(
                    schema["pattern"].as_str().unwrap().starts_with("^00-"),
                    "{path} {status}"
                );
            }
        }
    }

    #[test]
    fn authenticated_routes_publish_the_bearer_challenge() {
        let document = openapi_document();
        for (path, method) in [
            (SESSIONS_PATH, "post"),
            (SESSION_PATH, "get"),
            (READ_PATH, "post"),
        ] {
            assert_eq!(
                document["paths"][path][method]["responses"]["401"]["headers"]["WWW-Authenticate"]
                    ["schema"]["const"],
                "Bearer",
                "{path}"
            );
        }
    }

    #[test]
    fn body_taking_routes_publish_their_size_and_media_refusals() {
        let document = openapi_document();
        for path in [SESSIONS_PATH, READ_PATH, RESPONSE_PATH] {
            assert!(
                document["paths"][path]["post"]["responses"]
                    .get("413")
                    .is_some(),
                "{path}"
            );
        }
        for path in [SESSIONS_PATH, READ_PATH] {
            assert!(
                document["paths"][path]["post"]["responses"]
                    .get("415")
                    .is_some(),
                "{path}"
            );
        }
    }

    #[test]
    fn the_failure_categories_are_the_closed_set_on_both_surfaces() {
        let document = openapi_document();
        let status = &document["components"]["schemas"]["SessionStatus"]["properties"]
            ["failureCategory"]["enum"];
        let read = &document["paths"][READ_PATH]["post"]["responses"]["422"]["content"]
            ["application/problem+json"]["schema"]["allOf"][1]["properties"]["category"]["enum"];
        assert_eq!(status, &json!(FAILURE_CATEGORIES));
        assert_eq!(read, &json!(FAILURE_CATEGORIES));
    }

    #[test]
    fn the_budget_refusal_is_published_on_the_wallet_route() {
        let document = openapi_document();
        assert!(
            document["paths"][RESPONSE_PATH]["post"]["responses"]["503"]["description"]
                .as_str()
                .unwrap()
                .contains("byte budget")
        );
    }
}
