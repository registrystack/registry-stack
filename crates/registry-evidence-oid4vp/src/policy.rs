//! What a presentation policy asks a wallet for, rendered as the OpenID4VP
//! request parameters that carry it.

use serde_json::{json, Map, Value};

use crate::config::PolicyConfig;

/// The credential format the service requests, the Digital Credentials
/// SD-JWT VC format identifier (OpenID4VP 1.0 Appendix B.3).
pub const CREDENTIAL_FORMAT: &str = "dc+sd-jwt";

/// The signature algorithms accepted for the SD-JWT and the key binding JWT
/// of a presented credential.
pub const SD_JWT_ALGORITHMS: [&str; 2] = ["ES256", "EdDSA"];

/// The DCQL query for `policy` (OpenID4VP 1.0 section 6, `dcql_query` in
/// section 5.1).
///
/// A policy's `trusted_authorities` apply to every credential query as `aki`
/// entries (section 6.1.1.1); with none configured the member is omitted,
/// which a wallet reads as no restriction (section 6.1: the member is
/// optional). A credential query with no claims omits `claims`.
#[must_use]
pub fn dcql_query(policy: &PolicyConfig) -> Value {
    let credentials: Vec<Value> = policy
        .credentials
        .iter()
        .map(|credential| {
            let claims: Vec<Value> = credential
                .claims
                .iter()
                .map(|claim| json!({ "path": claim.path }))
                .collect();
            let mut query = Map::new();
            query.insert("id".to_owned(), json!(credential.id));
            query.insert("format".to_owned(), json!(CREDENTIAL_FORMAT));
            query.insert(
                "meta".to_owned(),
                json!({ "vct_values": credential.vct_values }),
            );
            // `claims` is omitted, never empty, when none is requested
            // (section 6.1: non-empty when present; section 6.4.1: absent
            // requests no selectively disclosable claim).
            if !claims.is_empty() {
                query.insert("claims".to_owned(), Value::Array(claims));
            }
            if !policy.trusted_authorities.is_empty() {
                let authorities: Vec<Value> = policy
                    .trusted_authorities
                    .iter()
                    .map(|authority| json!({ "type": "aki", "values": authority.values }))
                    .collect();
                query.insert("trusted_authorities".to_owned(), Value::Array(authorities));
            }
            Value::Object(query)
        })
        .collect();
    json!({ "credentials": credentials })
}

/// The verifier metadata the request carries (`client_metadata`, section 5.1).
///
/// `jwks` holds the per-session encryption key a wallet encrypts its
/// `direct_post.jwt` response to (section 8.3), with
/// `encrypted_response_enc_values_supported` naming the `enc` values accepted
/// (section 5.1; 8.3.1). `vp_formats_supported` is defined in section 11.1.
#[must_use]
pub fn client_metadata(policy: &PolicyConfig, encryption_jwk: Map<String, Value>) -> Value {
    let enc: Vec<&str> = policy
        .accepted_response_encryption
        .iter()
        .map(|enc| enc.jwa_name())
        .collect();
    json!({
        "jwks": { "keys": [Value::Object(encryption_jwk)] },
        "encrypted_response_enc_values_supported": enc,
        "vp_formats_supported": {
            CREDENTIAL_FORMAT: {
                "sd-jwt_alg_values": SD_JWT_ALGORITHMS,
                "kb-jwt_alg_values": SD_JWT_ALGORITHMS,
            }
        },
    })
}
