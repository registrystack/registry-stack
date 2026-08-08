//! Key material and wallet proofs for this crate's own tests.
//!
//! Every key here is generated in the test process and used nowhere else. No
//! key, and no value derived from one, is written to a tracked file.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
use registry_platform_crypto::{sign, PrivateJwk};
use serde_json::{json, Value};

/// A freshly generated P-256 private JWK, as JSON text.
pub(crate) fn private_jwk(key_id: &str) -> String {
    let key = SigningKey::random(&mut OsRng);
    let point = key.verifying_key().to_encoded_point(false);
    json!({
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "kid": key_id,
        "x": URL_SAFE_NO_PAD.encode(point.x().expect("an uncompressed P-256 point has x")),
        "y": URL_SAFE_NO_PAD.encode(point.y().expect("an uncompressed P-256 point has y")),
        "d": URL_SAFE_NO_PAD.encode(key.to_bytes()),
    })
    .to_string()
}

/// The public half of a private JWK, as a JSON object.
pub(crate) fn public_jwk(private_key: &str) -> Value {
    let key = PrivateJwk::parse(private_key).expect("the test key parses");
    serde_json::to_value(key.public()).expect("the public key serializes")
}

/// A signed OpenID4VCI proof JWT presenting the key that signed it.
pub(crate) fn proof_jwt(private_key: &str, audience: &str, nonce: &str, iat: i64) -> String {
    proof_jwt_with(
        private_key,
        json!({"aud": audience, "iat": iat, "nonce": nonce}),
    )
}

/// A signed proof JWT over an arbitrary payload, for the refusal cases.
pub(crate) fn proof_jwt_with(private_key: &str, payload: Value) -> String {
    let header = json!({
        "alg": "ES256",
        "typ": "openid4vci-proof+jwt",
        "jwk": public_jwk(private_key),
    });
    proof_jwt_with_header(private_key, header, payload)
}

/// A correctly signed proof JWT over an arbitrary header and payload.
///
/// The signature is real, so a test built on this proves that a refusal came
/// from the header or the claims rather than from a broken signature.
pub(crate) fn proof_jwt_with_header(private_key: &str, header: Value, payload: Value) -> String {
    proof_jwt_over_payload_text(private_key, header, &payload.to_string())
}

/// A correctly signed proof JWT over payload text written by the caller.
///
/// `serde_json` will not emit an object carrying the same member twice, so a
/// payload that carries one is written as text and signed over exactly those
/// bytes. The signature is real, for the same reason it is above.
pub(crate) fn proof_jwt_over_payload_text(
    private_key: &str,
    header: Value,
    payload: &str,
) -> String {
    let key = PrivateJwk::parse(private_key).expect("the test key parses");
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let signature = sign(signing_input.as_bytes(), &key).expect("the proof is signed");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

/// A proof JWT carrying no signature, as `alg: none` is serialized: the two
/// segments a signed proof carries and an empty third.
pub(crate) fn unsigned_proof_jwt(header: Value, payload: Value) -> String {
    format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(payload.to_string())
    )
}
