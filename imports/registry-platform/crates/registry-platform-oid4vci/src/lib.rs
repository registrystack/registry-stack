// SPDX-License-Identifier: Apache-2.0
//! OpenID4VCI facade helpers shared by Registry Platform consumers.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use registry_platform_crypto::{did_jwk_from_public_jwk, parse_did_jwk, verify, PublicJwk};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Duration;
use thiserror::Error;

pub const PROOF_JWT_TYPE: &str = "openid4vci-proof+jwt";
pub const PROOF_TYPE_JWT: &str = "jwt";
pub const SD_JWT_VC_FORMAT: &str = "dc+sd-jwt";
pub const CREDENTIAL_SIGNING_ALG_EDDSA: &str = "EdDSA";
pub const CRYPTOGRAPHIC_BINDING_METHOD_DID_JWK: &str = "did:jwk";
pub const AUTHORIZATION_CODE_GRANT_TYPE: &str = "authorization_code";
pub const PKCE_METHOD_S256: &str = "S256";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialIssuerMetadata {
    pub credential_issuer: String,
    pub credential_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorization_servers: Vec<String>,
    pub credential_configurations_supported: BTreeMap<String, CredentialConfigurationMetadata>,
}

impl CredentialIssuerMetadata {
    pub fn new(
        credential_issuer: impl Into<String>,
        credential_endpoint: impl Into<String>,
        nonce_endpoint: Option<String>,
        authorization_servers: Vec<String>,
        credential_configurations_supported: BTreeMap<String, CredentialConfigurationMetadata>,
    ) -> Self {
        Self {
            credential_issuer: credential_issuer.into(),
            credential_endpoint: credential_endpoint.into(),
            nonce_endpoint,
            authorization_servers,
            credential_configurations_supported,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialConfigurationMetadata {
    pub format: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cryptographic_binding_methods_supported: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_signing_alg_values_supported: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proof_types_supported: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub display: Vec<DisplayMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vct: Option<String>,
}

impl CredentialConfigurationMetadata {
    pub fn sd_jwt_vc(
        scope: impl Into<String>,
        cryptographic_binding_methods_supported: Vec<String>,
        display_name: impl Into<String>,
        vct: impl Into<String>,
    ) -> Self {
        Self {
            format: SD_JWT_VC_FORMAT.to_string(),
            scope: vec![scope.into()],
            cryptographic_binding_methods_supported,
            credential_signing_alg_values_supported: vec![CREDENTIAL_SIGNING_ALG_EDDSA.to_string()],
            proof_types_supported: vec![PROOF_TYPE_JWT.to_string()],
            display: vec![DisplayMetadata {
                name: display_name.into(),
                locale: None,
            }],
            vct: Some(vct.into()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisplayMetadata {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialOffer {
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub grants: BTreeMap<String, Value>,
}

impl CredentialOffer {
    pub fn authorization_code(
        credential_issuer: impl Into<String>,
        credential_configuration_ids: Vec<String>,
        issuer_state: impl Into<String>,
        authorization_server: Option<String>,
    ) -> Self {
        let issuer_state = issuer_state.into();
        Self {
            credential_issuer: credential_issuer.into(),
            credential_configuration_ids,
            grants: BTreeMap::from([(
                AUTHORIZATION_CODE_GRANT_TYPE.to_string(),
                serde_json::json!({
                    "issuer_state": issuer_state,
                    "authorization_server": authorization_server,
                }),
            )]),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonceRequest {
    #[serde(default)]
    pub credential_configuration_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceResponse {
    pub c_nonce: String,
    pub c_nonce_expires_in: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRequest {
    pub format: String,
    #[serde(default)]
    pub credential_identifier: Option<String>,
    #[serde(default)]
    pub credential_configuration_id: Option<String>,
    #[serde(default)]
    pub vct: Option<String>,
    pub proof: CredentialRequestProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRequestProof {
    #[serde(rename = "proof_type")]
    pub proof_type: String,
    pub jwt: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialResponse {
    pub credential: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub c_nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub c_nonce_expires_in: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireError {
    pub error: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

impl WireError {
    pub fn new(error: impl Into<String>, error_description: Option<String>) -> Self {
        Self {
            error: error.into(),
            error_description,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProofValidationPolicy<'a> {
    pub audience: &'a str,
    pub expected_nonce: Option<&'a str>,
    pub max_lifetime: Duration,
    pub future_skew: Duration,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedProof {
    pub holder_jwk: PublicJwk,
    pub holder_id: String,
    pub kid: Option<String>,
    pub nonce: Option<String>,
    pub iat: i64,
    pub exp: Option<i64>,
    pub raw_claims: Value,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProofError {
    #[error("proof must be a compact JWT")]
    MalformedJwt,
    #[error("proof header is invalid")]
    InvalidHeader,
    #[error("proof claims are invalid")]
    InvalidClaims,
    #[error("proof uses an unsupported key reference")]
    UnsupportedKeyReference,
    #[error("proof signature is invalid")]
    InvalidSignature,
    #[error("proof nonce is invalid")]
    InvalidNonce,
    #[error("proof audience is invalid")]
    InvalidAudience,
    #[error("proof time bounds are invalid")]
    InvalidTime,
}

pub fn validate_proof_jwt(
    proof_jwt: &str,
    policy: &ProofValidationPolicy<'_>,
    now: i64,
) -> Result<ValidatedProof, ProofError> {
    let (header_b64, payload_b64, signature_b64) = split_compact_jwt(proof_jwt)?;
    let header = decode_json(header_b64).map_err(|_| ProofError::InvalidHeader)?;
    reject_header(&header)?;
    let holder_jwk = holder_jwk_from_header(&header)?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| ProofError::MalformedJwt)?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    verify(signing_input.as_bytes(), &signature, &holder_jwk)
        .map_err(|_| ProofError::InvalidSignature)?;

    let claims = decode_json(payload_b64).map_err(|_| ProofError::InvalidClaims)?;
    let aud = claims.get("aud").ok_or(ProofError::InvalidAudience)?;
    if !audience_contains(aud, policy.audience) {
        return Err(ProofError::InvalidAudience);
    }
    let nonce = claims
        .get("nonce")
        .and_then(Value::as_str)
        .map(str::to_string);
    if let Some(expected) = policy.expected_nonce {
        if nonce.as_deref() != Some(expected) {
            return Err(ProofError::InvalidNonce);
        }
    }
    let iat = required_i64(&claims, "iat")?;
    let exp = optional_i64(&claims, "exp")?;
    validate_time(iat, exp, policy, now)?;
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .map(str::to_string);
    let holder_id = match kid
        .as_deref()
        .filter(|kid| kid.starts_with(CRYPTOGRAPHIC_BINDING_METHOD_DID_JWK))
    {
        Some(kid) => {
            let did = strip_fragment(kid)?;
            let kid_jwk = parse_did_jwk(did).map_err(|_| ProofError::UnsupportedKeyReference)?;
            if kid_jwk != holder_jwk {
                return Err(ProofError::UnsupportedKeyReference);
            }
            did.to_string()
        }
        None => did_jwk_from_public_jwk(&holder_jwk).expect("public jwk encodes"),
    };

    Ok(ValidatedProof {
        holder_jwk,
        holder_id,
        kid,
        nonce,
        iat,
        exp,
        raw_claims: claims,
    })
}

fn reject_header(header: &Value) -> Result<(), ProofError> {
    if header.get("alg").and_then(Value::as_str) != Some(CREDENTIAL_SIGNING_ALG_EDDSA) {
        return Err(ProofError::InvalidHeader);
    }
    if header.get("typ").and_then(Value::as_str) != Some(PROOF_JWT_TYPE) {
        return Err(ProofError::InvalidHeader);
    }
    for forbidden in ["jku", "x5u", "x5c"] {
        if header.get(forbidden).is_some() {
            return Err(ProofError::UnsupportedKeyReference);
        }
    }
    if header.get("crit").is_some() {
        return Err(ProofError::InvalidHeader);
    }
    Ok(())
}

fn holder_jwk_from_header(header: &Value) -> Result<PublicJwk, ProofError> {
    if let Some(jwk) = header.get("jwk") {
        return PublicJwk::parse(&jwk.to_string()).map_err(|_| ProofError::UnsupportedKeyReference);
    }
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or(ProofError::UnsupportedKeyReference)?;
    if !kid.starts_with(CRYPTOGRAPHIC_BINDING_METHOD_DID_JWK) {
        return Err(ProofError::UnsupportedKeyReference);
    }
    parse_did_jwk(kid).map_err(|_| ProofError::UnsupportedKeyReference)
}

fn strip_fragment(kid: &str) -> Result<&str, ProofError> {
    Ok(kid.split_once('#').map_or(kid, |(did, _)| did))
}

fn validate_time(
    iat: i64,
    exp: Option<i64>,
    policy: &ProofValidationPolicy<'_>,
    now: i64,
) -> Result<(), ProofError> {
    let max_lifetime = i64::try_from(policy.max_lifetime.as_secs()).unwrap_or(i64::MAX);
    let future_skew = i64::try_from(policy.future_skew.as_secs()).unwrap_or(i64::MAX);
    if iat > now + future_skew || iat < now - max_lifetime {
        return Err(ProofError::InvalidTime);
    }
    if let Some(exp) = exp {
        if exp <= iat || exp > iat + max_lifetime || exp <= now {
            return Err(ProofError::InvalidTime);
        }
    }
    Ok(())
}

fn audience_contains(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(aud) => aud == expected,
        Value::Array(items) => items.iter().any(|item| item.as_str() == Some(expected)),
        _ => false,
    }
}

fn required_i64(value: &Value, name: &'static str) -> Result<i64, ProofError> {
    value
        .get(name)
        .and_then(Value::as_i64)
        .ok_or(ProofError::InvalidClaims)
}

fn optional_i64(value: &Value, name: &'static str) -> Result<Option<i64>, ProofError> {
    match value.get(name) {
        Some(value) => value.as_i64().map(Some).ok_or(ProofError::InvalidClaims),
        None => Ok(None),
    }
}

fn split_compact_jwt(jwt: &str) -> Result<(&str, &str, &str), ProofError> {
    let mut parts = jwt.split('.');
    let header = parts.next().ok_or(ProofError::MalformedJwt)?;
    let payload = parts.next().ok_or(ProofError::MalformedJwt)?;
    let signature = parts.next().ok_or(ProofError::MalformedJwt)?;
    if parts.next().is_some() || header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(ProofError::MalformedJwt);
    }
    Ok((header, payload, signature))
}

fn decode_json(segment: &str) -> Result<Value, ProofError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| ProofError::MalformedJwt)?;
    serde_json::from_slice(&bytes).map_err(|_| ProofError::MalformedJwt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_crypto::{did_jwk_from_public_jwk, sign, PrivateJwk};
    use serde_json::json;

    const RAW_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;

    #[test]
    fn validates_public_jwk_proof() {
        let key = PrivateJwk::parse(RAW_JWK).expect("key parses");
        let proof = sign_proof(
            json!({"alg":"EdDSA","typ":PROOF_JWT_TYPE,"jwk": key.public()}),
            json!({"aud":"https://issuer.example","iat":1000,"exp":1060,"nonce":"n-1"}),
            &key,
        );
        let validated = validate_proof_jwt(
            &proof,
            &ProofValidationPolicy {
                audience: "https://issuer.example",
                expected_nonce: Some("n-1"),
                max_lifetime: Duration::from_secs(300),
                future_skew: Duration::from_secs(30),
            },
            1001,
        )
        .expect("proof validates");

        assert_eq!(validated.holder_jwk, key.public());
        assert!(validated.holder_id.starts_with("did:jwk:"));
    }

    #[test]
    fn validates_did_jwk_kid_proof() {
        let key = PrivateJwk::parse(RAW_JWK).expect("key parses");
        let did = did_jwk_from_public_jwk(&key.public()).expect("did:jwk encodes");
        let proof = sign_proof(
            json!({"alg":"EdDSA","typ":PROOF_JWT_TYPE,"kid": format!("{did}#key-1")}),
            json!({"aud":["https://other.example","https://issuer.example"],"iat":1000}),
            &key,
        );

        let validated = validate_proof_jwt(
            &proof,
            &ProofValidationPolicy {
                audience: "https://issuer.example",
                expected_nonce: None,
                max_lifetime: Duration::from_secs(300),
                future_skew: Duration::from_secs(30),
            },
            1001,
        )
        .expect("proof validates");

        assert_eq!(validated.holder_id, did);
    }

    #[test]
    fn rejects_wrong_type_remote_key_and_wrong_nonce() {
        let key = PrivateJwk::parse(RAW_JWK).expect("key parses");
        let wrong_typ = sign_proof(
            json!({"alg":"EdDSA","typ":"jwt","jwk": key.public()}),
            json!({"aud":"https://issuer.example","iat":1000,"nonce":"n-1"}),
            &key,
        );
        assert_eq!(
            validate_proof_jwt(&wrong_typ, &policy(Some("n-1")), 1001),
            Err(ProofError::InvalidHeader)
        );

        let remote = sign_proof(
            json!({"alg":"EdDSA","typ":PROOF_JWT_TYPE,"jku":"https://keys.example/jwks.json","jwk": key.public()}),
            json!({"aud":"https://issuer.example","iat":1000,"nonce":"n-1"}),
            &key,
        );
        assert_eq!(
            validate_proof_jwt(&remote, &policy(Some("n-1")), 1001),
            Err(ProofError::UnsupportedKeyReference)
        );

        assert_eq!(
            validate_proof_jwt(&valid_proof(&key, "n-2"), &policy(Some("n-1")), 1001),
            Err(ProofError::InvalidNonce)
        );
    }

    #[test]
    fn rejects_conflicting_public_jwk_and_did_jwk_kid() {
        let signing_key = PrivateJwk::parse(RAW_JWK).expect("key parses");
        let other_key = PrivateJwk::parse(
            r#"{"crv":"Ed25519","d":"f4QIxnAyRWzhuBOmNRgvBTE56mWePdsPL0mvCtl8Gys","x":"pv4e_hXHBLN27rcs6VDFV1ED0TiU8M3xy9vsuWFEsec","kty":"OKP","alg":"EdDSA"}"#,
        )
        .expect("other key parses");
        let other_did = did_jwk_from_public_jwk(&other_key.public()).expect("did:jwk encodes");
        let proof = sign_proof(
            json!({
                "alg": "EdDSA",
                "typ": PROOF_JWT_TYPE,
                "jwk": signing_key.public(),
                "kid": format!("{other_did}#key-1")
            }),
            json!({"aud":"https://issuer.example","iat":1000,"nonce":"n-1"}),
            &signing_key,
        );

        assert_eq!(
            validate_proof_jwt(&proof, &policy(Some("n-1")), 1001),
            Err(ProofError::UnsupportedKeyReference)
        );
    }

    #[test]
    fn rejects_stale_or_future_proofs() {
        let key = PrivateJwk::parse(RAW_JWK).expect("key parses");
        assert_eq!(
            validate_proof_jwt(&valid_proof(&key, "n-1"), &policy(Some("n-1")), 1400),
            Err(ProofError::InvalidTime)
        );
        assert_eq!(
            validate_proof_jwt(&valid_proof(&key, "n-1"), &policy(Some("n-1")), 900),
            Err(ProofError::InvalidTime)
        );
    }

    #[test]
    fn credential_request_rejects_unknown_fields() {
        let request = json!({
            "format": SD_JWT_VC_FORMAT,
            "credential_configuration_id": "person_is_alive_sd_jwt",
            "subject": {"id": "NID-1002"},
            "proof": {"proof_type": PROOF_TYPE_JWT, "jwt": "a.b.c"}
        });
        assert!(serde_json::from_value::<CredentialRequest>(request).is_err());

        let request = json!({
            "format": SD_JWT_VC_FORMAT,
            "credential_configuration_id": "person_is_alive_sd_jwt",
            "proof": {"proof_type": PROOF_TYPE_JWT, "jwt": "a.b.c", "subject": "NID-1002"}
        });
        assert!(serde_json::from_value::<CredentialRequest>(request).is_err());
    }

    #[test]
    fn nonce_request_rejects_unknown_fields() {
        assert!(serde_json::from_value::<NonceRequest>(
            json!({"credential_configuration_id":"person_is_alive_sd_jwt"})
        )
        .is_ok());
        assert!(serde_json::from_value::<NonceRequest>(
            json!({"credential_configuration_id":"person_is_alive_sd_jwt","subject":"NID-1002"})
        )
        .is_err());
    }

    fn policy(expected_nonce: Option<&str>) -> ProofValidationPolicy<'_> {
        ProofValidationPolicy {
            audience: "https://issuer.example",
            expected_nonce,
            max_lifetime: Duration::from_secs(300),
            future_skew: Duration::from_secs(30),
        }
    }

    fn valid_proof(key: &PrivateJwk, nonce: &str) -> String {
        sign_proof(
            json!({"alg":"EdDSA","typ":PROOF_JWT_TYPE,"jwk": key.public()}),
            json!({"aud":"https://issuer.example","iat":1000,"exp":1060,"nonce": nonce}),
            key,
        )
    }

    fn sign_proof(header: Value, payload: Value, key: &PrivateJwk) -> String {
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header"));
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload"));
        let signing_input = format!("{header}.{payload}");
        let signature = URL_SAFE_NO_PAD.encode(sign(signing_input.as_bytes(), key).expect("sign"));
        format!("{signing_input}.{signature}")
    }
}
