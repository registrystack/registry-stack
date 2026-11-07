//! The OpenID4VCI Draft 13 compatibility profile.
//!
//! One wallet family, the France Identite Partenaires test wallet, accepts
//! third-party issuance only over Draft 13. This profile lets it receive the
//! same `dc+sd-jwt` credentials Evidence signs for the 1.0 Final profile. It
//! is a separate profile with its own issuer identifier and path prefix, off
//! unless `draft13Profile: {}` is configured, and removable as one unit: this
//! module, `service/draft13.rs`, the `draft13_profile` configuration member,
//! and the single route registration in `service::build_app`.
//!
//! The wire differences from the 1.0 Final profile, and where each comes from
//! (the Draft 13 text, or the Partenaires guide at
//! `https://playground.france-identite.gouv.fr/marketplace/wallets/fin_oid4vci_draft13/`):
//!
//! - the issuer identifier is the 1.0 identifier followed by [`PATH_PREFIX`],
//!   and the metadata document is that identifier followed by
//!   `/.well-known/openid-credential-issuer` (guide, section 1);
//! - the metadata is plain JSON that carries `token_endpoint`,
//!   `grant_types_supported` and the singular `token_endpoint_auth_method`, and
//!   carries no `authorization_servers`, no `nonce_endpoint`, and no batch
//!   member (guide, section 2);
//! - every configuration advertises `cose_key` as its only binding method (the
//!   Android 1.3.5078 workaround, guide, section 11); the credential still
//!   binds the holder key in `cnf.jwk`;
//! - the token response carries lowercase `bearer`, `c_nonce` and
//!   `c_nonce_expires_in` (Draft 13, section 6.2; guide, section 5);
//! - the credential request names `format` and `vct` and carries a singular
//!   `proof` (Draft 13, section 7.2; guide, section 7), and the response is one
//!   `credential` (guide, section 8);
//! - the offer is the Draft 13 offer object, with `user_pin_required: false`
//!   when no transaction code is wanted, because the guide's tested shape
//!   carries it (guide, section 4).
//!
//! None of this changes what is delivered. The service signs nothing here
//! either: the credential is the one Evidence signed, byte for byte.

use serde_json::{json, Map, Value};

use crate::{
    config::DeliveryConfig,
    contracts::{
        bearer_problem_response, catalog_refusal_response, framework_response, json_response,
        problem_response, retry_response,
    },
    metadata::{CredentialCatalog, ES256},
    CREDENTIAL_FORMAT, PRE_AUTHORIZED_CODE_GRANT_TYPE, TRANSACTION_CODE_INPUT_MODE,
    TRANSACTION_CODE_LENGTH,
};

/// The path every route of this profile lives under.
pub const PATH_PREFIX: &str = "/protocol/oid4vci/draft-13";
pub const ISSUER_METADATA_PATH: &str =
    "/protocol/oid4vci/draft-13/.well-known/openid-credential-issuer";
pub const OFFERS_PATH: &str = "/protocol/oid4vci/draft-13/offers";
pub const TOKEN_PATH: &str = "/protocol/oid4vci/draft-13/token";
pub const CREDENTIAL_PATH: &str = "/protocol/oid4vci/draft-13/credential";

/// The routes of this profile, shared with the contract drift test.
#[cfg(test)]
pub(crate) const ROUTES: [&str; 4] = [
    ISSUER_METADATA_PATH,
    OFFERS_PATH,
    TOKEN_PATH,
    CREDENTIAL_PATH,
];

/// The binding method the Partenaires Android 1.3.5078 build requires every
/// configuration to advertise.
pub const COSE_KEY_BINDING: &str = "cose_key";

/// The label that separates this profile's offer and token state from the 1.0
/// profile's, inside the shared store.
pub(crate) const GENERATION_LABEL: &str = "draft-13";

/// The proof JWT header type. Draft 13 and 1.0 Final name the same value.
pub const PROOF_TYPE_HEADER: &str = "openid4vci-proof+jwt";

/// The `credential_issuer` of this profile, which is also the `aud` its proofs
/// must carry.
#[must_use]
pub fn credential_issuer(config: &DeliveryConfig) -> String {
    format!("{}{PATH_PREFIX}", config.credential_issuer)
}

/// The plain JSON issuer metadata document.
///
/// Every configuration is the catalog's, derived from authenticated Evidence
/// discovery, described in the Draft 13 shape.
#[must_use]
pub fn issuer_metadata(catalog: &CredentialCatalog, config: &DeliveryConfig) -> Value {
    let issuer = credential_issuer(config);
    let mut supported = Map::new();
    for configuration in catalog.configurations() {
        supported.insert(
            configuration.id.clone(),
            json!({
                "format": CREDENTIAL_FORMAT,
                "vct": configuration.vct,
                "cryptographic_binding_methods_supported": [COSE_KEY_BINDING],
                "credential_signing_alg_values_supported": [ES256],
                "proof_types_supported": {
                    "jwt": {"proof_signing_alg_values_supported": [ES256]},
                },
            }),
        );
    }
    json!({
        "credential_issuer": issuer,
        "credential_endpoint": format!("{issuer}/credential"),
        "token_endpoint": format!("{issuer}/token"),
        "grant_types_supported": [PRE_AUTHORIZED_CODE_GRANT_TYPE],
        "token_endpoint_auth_method": ["none"],
        "credential_configurations_supported": Value::Object(supported),
    })
}

/// The Draft 13 credential offer object a wallet reads.
#[must_use]
pub fn credential_offer(
    credential_issuer: &str,
    configuration_id: &str,
    pre_authorized_code: &str,
    with_transaction_code: bool,
) -> Value {
    let mut grant = json!({"pre-authorized_code": pre_authorized_code});
    if with_transaction_code {
        grant["tx_code"] = json!({
            "input_mode": TRANSACTION_CODE_INPUT_MODE,
            "length": TRANSACTION_CODE_LENGTH,
        });
    } else {
        grant["user_pin_required"] = json!(false);
    }
    json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": [configuration_id],
        "grants": {PRE_AUTHORIZED_CODE_GRANT_TYPE: grant},
    })
}

/// The OpenAPI path items this profile adds to the service contract.
pub(crate) fn openapi_paths() -> Vec<(&'static str, Value)> {
    vec![
        (
            ISSUER_METADATA_PATH,
            json!({"get": {
                "operationId": "getDraft13CredentialIssuerMetadata",
                "summary": "Discover the Draft 13 compatibility profile",
                "responses": {
                    "200": json_response("Draft 13 credential issuer metadata", "Draft13IssuerMetadata"),
                    "403": catalog_refusal_response(),
                    "408": problem_response("The configured request deadline elapsed"),
                    "503": problem_response("Backing Evidence discovery is unavailable")
                }
            }}),
        ),
        (
            OFFERS_PATH,
            json!({"post": {
                "operationId": "createDraft13CredentialOffer",
                "summary": "Create one adopter-authorized credential offer for the Draft 13 profile",
                "security": [{"offerBearer": []}],
                "requestBody": {
                    "required": true,
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/OfferRequest"}}}
                },
                "responses": {
                    "201": json_response("Draft 13 credential offer", "Draft13OfferResponse"),
                    "400": problem_response("The offer request is outside the published catalog"),
                    "401": bearer_problem_response("The offer bearer token is missing or refused"),
                    "403": catalog_refusal_response(),
                    "408": problem_response("The configured request deadline elapsed"),
                    "429": retry_response("The request budget is spent; retry after the interval in Retry-After"),
                    "413": framework_response("The request body exceeds the configured byte limit"),
                    "503": problem_response("Authorization, Evidence discovery, or bounded state is unavailable")
                }
            }}),
        ),
        (
            TOKEN_PATH,
            json!({"post": {
                "operationId": "redeemDraft13PreAuthorizedCode",
                "summary": "Redeem one Draft 13 pre-authorized code anonymously",
                "requestBody": {
                    "required": true,
                    "content": {"application/x-www-form-urlencoded": {
                        "schema": {"$ref": "#/components/schemas/TokenRequest"}
                    }}
                },
                "responses": {
                    "200": json_response("Single-use access token and c_nonce", "Draft13TokenResponse"),
                    "400": problem_response("The form cannot be decoded, or the grant or code was refused"),
                    "408": problem_response("The configured request deadline elapsed"),
                    "429": retry_response("The request budget is spent; retry after the interval in Retry-After"),
                    "413": framework_response("The request body exceeds the configured byte limit"),
                    "415": framework_response("The request is not form encoded"),
                    "503": problem_response("The bounded state store is unavailable")
                }
            }}),
        ),
        (
            CREDENTIAL_PATH,
            json!({"post": {
                "operationId": "issueDraft13HolderBoundCredential",
                "summary": "Exchange one claimed token and one proof for one credential",
                "security": [{"credentialBearer": []}],
                "requestBody": {
                    "required": true,
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Draft13CredentialRequest"}}}
                },
                "responses": {
                    "200": json_response("The Evidence credential, byte-for-byte", "Draft13CredentialResponse"),
                    "400": credential_bad_request(),
                    "401": bearer_problem_response("The access token is missing, unknown, expired, or already claimed"),
                    "408": problem_response("The configured request deadline elapsed"),
                    "429": retry_response("The request budget is spent; retry after the interval in Retry-After"),
                    "413": framework_response("The request body exceeds the configured byte limit"),
                    "503": problem_response("Bounded state is unavailable before the access token can be claimed")
                }
            }}),
        ),
    ]
}

fn credential_bad_request() -> Value {
    let mut response = problem_response(
        "The request shape, format, type, nonce, proof, or post-claim credential request was terminally refused",
    );
    response["content"]["application/json"]["schema"] = json!({
        "allOf": [
            {"$ref": "#/components/schemas/Draft13Problem"},
            {
                "type": "object",
                "properties": {
                    "error": {"enum": [
                        "invalid_credential_request", "unsupported_credential_format",
                        "unsupported_credential_type", "invalid_proof",
                        "credential_request_denied"
                    ]}
                }
            }
        ]
    });
    response
}

/// The OpenAPI component schemas this profile adds to the service contract.
pub(crate) fn openapi_schemas() -> Value {
    json!({
        "Draft13Problem": {
            "type": "object", "additionalProperties": false,
            "required": ["error", "error_description"],
            "properties": {
                "error": {"enum": [
                    "invalid_request", "invalid_token", "unsupported_grant_type", "invalid_grant",
                    "invalid_credential_request", "unsupported_credential_format",
                    "unsupported_credential_type", "invalid_proof",
                    "credential_request_denied", "temporarily_unavailable", "server_error"
                ]},
                "error_description": {"type": "string"}
            }
        },
        "Draft13IssuerMetadata": {
            "type": "object", "additionalProperties": false,
            "required": [
                "credential_issuer", "credential_endpoint", "token_endpoint",
                "grant_types_supported", "token_endpoint_auth_method",
                "credential_configurations_supported"
            ],
            "properties": {
                "credential_issuer": {"type": "string", "format": "uri"},
                "credential_endpoint": {"type": "string", "format": "uri"},
                "token_endpoint": {"type": "string", "format": "uri"},
                "grant_types_supported": {
                    "type": "array", "prefixItems": [{"const": PRE_AUTHORIZED_CODE_GRANT_TYPE}],
                    "minItems": 1, "maxItems": 1
                },
                "token_endpoint_auth_method": {
                    "type": "array", "prefixItems": [{"const": "none"}], "minItems": 1, "maxItems": 1
                },
                "credential_configurations_supported": {
                    "type": "object",
                    "additionalProperties": {"$ref": "#/components/schemas/Draft13CredentialConfiguration"}
                }
            }
        },
        "Draft13CredentialConfiguration": {
            "type": "object", "additionalProperties": false,
            "required": [
                "format", "vct", "cryptographic_binding_methods_supported",
                "credential_signing_alg_values_supported", "proof_types_supported"
            ],
            "properties": {
                "format": {"const": CREDENTIAL_FORMAT},
                "vct": {"type": "string", "format": "uri"},
                "cryptographic_binding_methods_supported": {
                    "type": "array", "prefixItems": [{"const": COSE_KEY_BINDING}],
                    "minItems": 1, "maxItems": 1
                },
                "credential_signing_alg_values_supported": {
                    "type": "array", "prefixItems": [{"const": ES256}], "minItems": 1, "maxItems": 1
                },
                "proof_types_supported": {
                    "type": "object", "additionalProperties": false, "required": ["jwt"],
                    "properties": {"jwt": {
                        "type": "object", "additionalProperties": false,
                        "required": ["proof_signing_alg_values_supported"],
                        "properties": {"proof_signing_alg_values_supported": {
                            "type": "array", "prefixItems": [{"const": ES256}], "minItems": 1, "maxItems": 1
                        }}
                    }}
                }
            }
        },
        "Draft13OfferResponse": {
            "type": "object", "additionalProperties": false,
            "required": ["credentialOffer", "credentialOfferUri", "expiresIn"],
            "properties": {
                "credentialOffer": {"$ref": "#/components/schemas/Draft13CredentialOffer"},
                "credentialOfferUri": {"type": "string", "format": "uri"},
                "expiresIn": {"type": "integer", "minimum": 60, "maximum": 900},
                "transactionCode": {"type": "string", "pattern": "^[0-9]{6}$"}
            }
        },
        "Draft13CredentialOffer": {
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
                            "$ref": "#/components/schemas/Draft13PreAuthorizedCodeGrant"
                        }
                    }
                }
            }
        },
        "Draft13PreAuthorizedCodeGrant": {
            "type": "object", "additionalProperties": false,
            "required": ["pre-authorized_code"],
            "properties": {
                "pre-authorized_code": {"type": "string"},
                "tx_code": {"$ref": "#/components/schemas/TransactionCodeDescription"},
                "user_pin_required": {"const": false}
            }
        },
        "Draft13TokenResponse": {
            "type": "object", "additionalProperties": false,
            "required": ["access_token", "token_type", "expires_in", "c_nonce", "c_nonce_expires_in"],
            "properties": {
                "access_token": {"type": "string"},
                "token_type": {"const": "bearer"},
                "expires_in": {"type": "integer", "minimum": 60, "maximum": 900},
                "c_nonce": {"type": "string"},
                "c_nonce_expires_in": {"type": "integer", "minimum": 30, "maximum": 900}
            }
        },
        "Draft13CredentialRequest": {
            "type": "object", "additionalProperties": false,
            "required": ["format", "vct", "proof"],
            "properties": {
                "format": {"const": CREDENTIAL_FORMAT},
                "vct": {"type": "string"},
                "proof": {
                    "type": "object", "additionalProperties": false,
                    "required": ["proof_type", "jwt"],
                    "properties": {
                        "proof_type": {"const": "jwt"},
                        "jwt": {"type": "string", "maxLength": 8192}
                    }
                }
            }
        },
        "Draft13CredentialResponse": {
            "type": "object", "additionalProperties": false, "required": ["credential"],
            "properties": {"credential": {"type": "string"}}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_route_lives_under_the_profile_prefix() {
        for route in ROUTES {
            assert!(route.starts_with(&format!("{PATH_PREFIX}/")), "{route}");
        }
    }
}
