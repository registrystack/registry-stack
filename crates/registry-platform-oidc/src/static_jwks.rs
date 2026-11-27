//! Public-key rule for operator-pinned JSON Web Key Sets.
//!
//! One rule for every product that loads a static key set. Members this
//! module does not name are ignored, as RFC 7517 sections 4 and 5 require.
//! A refusal names the position of the key and the rule it broke, never a
//! `kid` or a member value.

use std::collections::BTreeSet;

use registry_platform_crypto::{parse_json_strict, PRIVATE_JWK_MEMBERS};
use serde_json::Value;

/// Why a static key set was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StaticJwksError {
    #[error("the document is not JSON, or repeats a member name")]
    NotJson,
    #[error("the document is not a JSON Web Key Set: it needs a top-level \"keys\" array")]
    NotAKeySet,
    #[error("the key set holds no keys")]
    Empty,
    #[error("key {key} is not a JSON object")]
    KeyNotAnObject { key: usize },
    #[error(
        "key {key} is a symmetric key (\"kty\": \"oct\"); a static key set holds public keys only"
    )]
    SymmetricKey { key: usize },
    #[error("key {key} has no \"kty\", or a key type that is not RSA, EC or OKP")]
    UnsupportedKeyType { key: usize },
    #[error("key {key} carries the private-key member \"{member}\"; a static key set holds public keys only, so export the public key and replace this document")]
    PrivateKeyMember { key: usize, member: &'static str },
    #[error("key {key} has no \"kid\"; give every key a non-empty \"kid\"")]
    MissingKeyId { key: usize },
    #[error("key {key} repeats the \"kid\" of an earlier key; give every key its own \"kid\"")]
    RepeatedKeyId { key: usize },
}

/// Check that `bytes` is a JSON Web Key Set that holds public keys only.
/// Returns the parsed document. Members this function does not name are not
/// inspected. The caller bounds the size of `bytes`.
pub fn public_jwks_document(bytes: &[u8]) -> Result<Value, StaticJwksError> {
    let document = parse_json_strict(bytes).map_err(|_| StaticJwksError::NotJson)?;
    let keys = document
        .get("keys")
        .and_then(Value::as_array)
        .ok_or(StaticJwksError::NotAKeySet)?;
    if keys.is_empty() {
        return Err(StaticJwksError::Empty);
    }
    let mut key_ids = BTreeSet::new();
    for (key, member) in keys.iter().enumerate() {
        let member = member
            .as_object()
            .ok_or(StaticJwksError::KeyNotAnObject { key })?;
        match member.get("kty").and_then(Value::as_str) {
            Some("oct") => return Err(StaticJwksError::SymmetricKey { key }),
            Some("RSA" | "EC" | "OKP") => {}
            _ => return Err(StaticJwksError::UnsupportedKeyType { key }),
        }
        if let Some(private) = PRIVATE_JWK_MEMBERS
            .iter()
            .find(|name| member.contains_key(**name))
        {
            return Err(StaticJwksError::PrivateKeyMember {
                key,
                member: private,
            });
        }
        let kid = member
            .get("kid")
            .and_then(Value::as_str)
            .filter(|kid| !kid.is_empty())
            .ok_or(StaticJwksError::MissingKeyId { key })?;
        if !key_ids.insert(kid) {
            return Err(StaticJwksError::RepeatedKeyId { key });
        }
    }
    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_crypto::PRIVATE_JWK_MEMBERS;
    use serde_json::json;

    const RSA: &str = r#"{"kty":"RSA","kid":"one","n":"AQAB","e":"AQAB"}"#;

    fn set(keys: &str) -> Vec<u8> {
        format!(r#"{{"keys":[{keys}]}}"#).into_bytes()
    }

    fn refusal(bytes: &[u8]) -> StaticJwksError {
        public_jwks_document(bytes).expect_err("document must be refused")
    }

    #[test]
    fn unknown_members_on_keys_and_on_the_set_are_ignored() {
        let key = r#"{"kty":"RSA","kid":"one","n":"AQAB","e":"AQAB","ext":true,"x5c":["AA"],"x5t":"a","x5t#S256":"b","x5u":"https://x.example/c","use":"sig","key_ops":["verify"],"future":{"a":1}}"#;
        let bytes = format!(r#"{{"issuer":"x","keys":[{key}]}}"#);
        let document = public_jwks_document(bytes.as_bytes()).expect("loads");
        assert_eq!(document["keys"].as_array().expect("keys").len(), 1);
    }

    #[test]
    fn a_keycloak_shaped_set_loads() {
        let sig = r#"{"kid":"sig","kty":"RSA","alg":"RS256","use":"sig","n":"AQAB","e":"AQAB","x5c":["MIIC"],"x5t":"aa","x5t#S256":"bb"}"#;
        let enc = r#"{"kid":"enc","kty":"RSA","alg":"RSA-OAEP","use":"enc","n":"AQAB","e":"AQAB","x5c":["MIIC"],"x5t":"aa","x5t#S256":"bb"}"#;
        public_jwks_document(&set(&format!("{sig},{enc}"))).expect("loads");
    }

    #[test]
    fn every_private_member_is_refused_on_every_key_type() {
        let shapes = [
            r#""kty":"RSA","n":"AQAB","e":"AQAB""#,
            r#""kty":"EC","crv":"P-256","x":"AQAB","y":"AQAB""#,
            r#""kty":"OKP","crv":"Ed25519","x":"AQAB""#,
        ];
        for shape in shapes {
            for member in PRIVATE_JWK_MEMBERS {
                let bytes = set(&format!(r#"{{{shape},"kid":"one","{member}":"canary"}}"#));
                let error = refusal(&bytes);
                assert_eq!(
                    error,
                    StaticJwksError::PrivateKeyMember { key: 0, member },
                    "{shape} {member}"
                );
            }
        }
    }

    #[test]
    fn the_first_private_member_in_list_order_is_reported() {
        let bytes = set(r#"{"kty":"RSA","kid":"one","n":"AQAB","e":"AQAB","dq":"x","d":"y"}"#);
        assert_eq!(
            refusal(&bytes),
            StaticJwksError::PrivateKeyMember {
                key: 0,
                member: "d"
            }
        );
    }

    #[test]
    fn symmetric_and_unsupported_key_types_are_refused() {
        assert_eq!(
            refusal(&set(r#"{"kty":"oct","kid":"one","k":"AA"}"#)),
            StaticJwksError::SymmetricKey { key: 0 }
        );
        for key in [
            r#"{"kty":"DSA","kid":"one"}"#,
            r#"{"kid":"one"}"#,
            r#"{"kty":5,"kid":"one"}"#,
        ] {
            assert_eq!(
                refusal(&set(key)),
                StaticJwksError::UnsupportedKeyType { key: 0 },
                "{key}"
            );
        }
    }

    #[test]
    fn structural_refusals() {
        assert_eq!(refusal(b"not-json"), StaticJwksError::NotJson);
        assert_eq!(
            refusal(br#"{"keys":[],"keys":[]}"#),
            StaticJwksError::NotJson
        );
        assert_eq!(
            refusal(br#"{"keys":[{"kty":"RSA","kty":"RSA","kid":"one"}]}"#),
            StaticJwksError::NotJson
        );
        assert_eq!(refusal(b"{}"), StaticJwksError::NotAKeySet);
        assert_eq!(refusal(b"[]"), StaticJwksError::NotAKeySet);
        assert_eq!(refusal(br#"{"keys":{}}"#), StaticJwksError::NotAKeySet);
        assert_eq!(refusal(br#"{"keys":[]}"#), StaticJwksError::Empty);
        assert_eq!(
            refusal(&set(&format!("{RSA},3"))),
            StaticJwksError::KeyNotAnObject { key: 1 }
        );
    }

    #[test]
    fn key_id_rules() {
        assert_eq!(
            refusal(&set(r#"{"kty":"RSA","n":"AQAB","e":"AQAB"}"#)),
            StaticJwksError::MissingKeyId { key: 0 }
        );
        assert_eq!(
            refusal(&set(r#"{"kty":"RSA","kid":"","n":"AQAB","e":"AQAB"}"#)),
            StaticJwksError::MissingKeyId { key: 0 }
        );
        assert_eq!(
            refusal(&set(r#"{"kty":"RSA","kid":7,"n":"AQAB","e":"AQAB"}"#)),
            StaticJwksError::MissingKeyId { key: 0 }
        );
        assert_eq!(
            refusal(&set(&format!("{RSA},{RSA}"))),
            StaticJwksError::RepeatedKeyId { key: 1 }
        );
    }

    #[test]
    fn refusal_text_carries_no_key_material_or_kid() {
        let canary = "canary-secret-value";
        let documents = [
            json!({"keys":[{"kty":"RSA","kid":canary,"n":"AQAB","e":"AQAB","d":canary}]}),
            json!({"keys":[{"kty":"oct","kid":canary,"k":canary}]}),
            json!({"keys":[{"kty":canary,"kid":canary}]}),
            json!({"keys":[{"kty":"RSA","kid":canary},{"kty":"RSA","kid":canary}]}),
        ];
        for document in documents {
            let text = refusal(document.to_string().as_bytes()).to_string();
            assert!(!text.contains(canary), "{text}");
        }
    }
}
