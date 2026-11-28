//! Public-key rule for operator-pinned JSON Web Key Sets.
//!
//! One rule for every product that loads a static key set. Members this
//! module does not name are ignored, as RFC 7517 sections 4 and 5 require,
//! apart from the strict JSON rule that applies to the whole document: no
//! repeated member name, and no integer a binary64 number cannot hold
//! exactly. A refusal names the position of the key and the rule it broke,
//! never a member value. The one refusal that also names a key's `kid` and
//! `crv` is [`StaticJwksError::OctetKeyPair`], for a key the verifier would
//! otherwise load: both are public labels, quoted and bounded.

use std::collections::BTreeSet;

use registry_platform_crypto::{parse_json_strict, PRIVATE_JWK_MEMBERS};
use serde_json::Value;

/// Why a static key set was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StaticJwksError {
    #[error("the document is not JSON, repeats a member name, or holds an integer that a 64-bit floating-point number cannot represent exactly")]
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
    #[error("key {key}{} is an OKP key (\"kty\": \"OKP\"), which the token verifier does not load; use an RSA or EC key", okp_labels(.kid, .crv))]
    OctetKeyPair {
        key: usize,
        kid: Option<String>,
        crv: Option<String>,
    },
    #[error(
        "key {key} is not a valid JSON Web Key: a member it needs is missing or has the wrong type"
    )]
    KeyShape { key: usize },
}

/// The longest `kid` or `crv` an OKP refusal repeats.
const MAX_LABEL_CHARS: usize = 64;

/// ` (kid "...", crv "...")` for the labels a key has, quoted and cut to
/// [`MAX_LABEL_CHARS`], or nothing when it has neither.
fn okp_labels(kid: &Option<String>, crv: &Option<String>) -> String {
    let labels: Vec<String> = [("kid", kid), ("crv", crv)]
        .into_iter()
        .filter_map(|(name, value)| {
            let value = value.as_deref()?;
            let bounded: String = value.chars().take(MAX_LABEL_CHARS).collect();
            Some(format!("{name} {bounded:?}"))
        })
        .collect();
    if labels.is_empty() {
        String::new()
    } else {
        format!(" ({})", labels.join(", "))
    }
}

/// Check that `bytes` is a JSON Web Key Set that holds public keys only.
/// Returns the parsed document. Apart from the strict JSON rule (no repeated
/// member name, no integer a binary64 number cannot hold exactly, anywhere in
/// the document), members this function does not name are not inspected. An
/// OKP key passes here; [`crate::parse_static_jwks`] refuses it for the token
/// verifier. The caller bounds the size of `bytes`.
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
pub(crate) mod tests {
    use super::*;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine;
    use jsonwebtoken::jwk::{KeyAlgorithm, PublicKeyUse};
    use registry_platform_crypto::PRIVATE_JWK_MEMBERS;
    use serde_json::json;

    const RSA: &str = r#"{"kty":"RSA","kid":"one","n":"AQAB","e":"AQAB"}"#;

    /// The `kid` of the RS256 signing key in [`keycloak_realm_jwks`].
    pub(crate) const KEYCLOAK_SIG_KID: &str = "kXbJ0QJ3Yx3qhJpU0rT9d8nqk1Z6m2Vw4sFhL7cE5aA";
    /// The `kid` of the RSA-OAEP encryption key in [`keycloak_realm_jwks`].
    pub(crate) const KEYCLOAK_ENC_KID: &str = "Rz8tYp4WmQ1nV6bH2cL9xK3fJ7sD0gA5eU8iO2wN4qM";

    /// A key set in the shape a Keycloak realm publishes at
    /// `/realms/<realm>/protocol/openid-connect/certs`: an RSA-OAEP `enc` key
    /// listed before the RS256 `sig` key, each with a 2048-bit modulus, a
    /// one-certificate `x5c` chain of a self-signed realm certificate's length,
    /// `x5t` and `x5t#S256`. Every value is synthetic: the moduli are not real
    /// keys and the certificates are filler bytes behind a DER sequence header.
    pub(crate) fn keycloak_realm_jwks() -> Vec<u8> {
        fn filler(seed: u8, len: usize) -> Vec<u8> {
            (0..len)
                .map(|index| (index as u8).wrapping_mul(167).wrapping_add(seed))
                .collect()
        }
        fn modulus(seed: u8) -> String {
            let mut bytes = filler(seed, 256);
            bytes[0] |= 0x80;
            bytes[255] |= 0x01;
            URL_SAFE_NO_PAD.encode(bytes)
        }
        fn certificate(seed: u8) -> String {
            let mut der = vec![0x30, 0x82, 0x02, 0xa9];
            der.extend(filler(seed, 0x02a9));
            STANDARD.encode(der)
        }
        fn key(kid: &str, alg: &str, key_use: &str, seed: u8) -> Value {
            json!({
                "kid": kid,
                "kty": "RSA",
                "alg": alg,
                "use": key_use,
                "n": modulus(seed),
                "e": "AQAB",
                "x5c": [certificate(seed)],
                "x5t": URL_SAFE_NO_PAD.encode(filler(seed, 20)),
                "x5t#S256": URL_SAFE_NO_PAD.encode(filler(seed, 32)),
            })
        }
        json!({"keys": [
            key(KEYCLOAK_ENC_KID, "RSA-OAEP", "enc", 0x5a),
            key(KEYCLOAK_SIG_KID, "RS256", "sig", 0xa5),
        ]})
        .to_string()
        .into_bytes()
    }

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
    fn a_keycloak_realm_set_loads_through_the_verifier_parser() {
        let bytes = keycloak_realm_jwks();
        let keys = crate::parse_static_jwks(&bytes).expect("a realm key set loads");
        assert_eq!(keys.keys.len(), 2);
        let sig = keys.find(KEYCLOAK_SIG_KID).expect("the signing key loads");
        assert_eq!(sig.common.public_key_use, Some(PublicKeyUse::Signature));
        assert_eq!(sig.common.key_algorithm, Some(KeyAlgorithm::RS256));
        let chain = sig.common.x509_chain.as_deref().expect("x5c is kept");
        assert!(chain[0].len() > 900, "the certificate has a realm length");
        let enc = keys
            .find(KEYCLOAK_ENC_KID)
            .expect("the encryption key loads");
        assert_eq!(enc.common.public_key_use, Some(PublicKeyUse::Encryption));
        assert_eq!(enc.common.key_algorithm, Some(KeyAlgorithm::RSA_OAEP));
    }

    #[test]
    fn an_inexact_integer_anywhere_is_refused_and_the_text_says_so() {
        let bytes = format!(r#"{{"keys":[{RSA}],"serial":9007199254740993}}"#);
        let error = refusal(bytes.as_bytes());
        assert_eq!(error, StaticJwksError::NotJson);
        assert!(error.to_string().contains("integer"), "{error}");
        public_jwks_document(format!(r#"{{"keys":[{RSA}],"serial":9007199254740992}}"#).as_bytes())
            .expect("an integer binary64 holds exactly is kept");
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
