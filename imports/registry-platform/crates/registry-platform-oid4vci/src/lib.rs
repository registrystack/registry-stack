// SPDX-License-Identifier: Apache-2.0
//! OpenID4VCI facade helpers shared by Registry Platform consumers.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use registry_platform_crypto::{did_jwk_from_public_jwk, parse_did_jwk, verify, PublicJwk};
use registry_platform_replay::{
    require_consume_once, ConsumableNonceStore, ReplayKey, ReplayScope,
};
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
pub const PRE_AUTHORIZED_CODE_GRANT_TYPE: &str =
    "urn:ietf:params:oauth:grant-type:pre-authorized_code";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialIssuerMetadata {
    pub credential_issuer: String,
    pub credential_endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
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
            token_endpoint: None,
            nonce_endpoint,
            authorization_servers,
            credential_configurations_supported,
        }
    }

    #[must_use]
    pub fn with_token_endpoint(mut self, token_endpoint: impl Into<String>) -> Self {
        self.token_endpoint = Some(token_endpoint.into());
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialConfigurationMetadata {
    pub format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cryptographic_binding_methods_supported: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_signing_alg_values_supported: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub proof_types_supported: BTreeMap<String, ProofTypeMetadata>,
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
            scope: Some(scope.into()),
            cryptographic_binding_methods_supported,
            credential_signing_alg_values_supported: vec![CREDENTIAL_SIGNING_ALG_EDDSA.to_string()],
            proof_types_supported: BTreeMap::from([(
                PROOF_TYPE_JWT.to_string(),
                ProofTypeMetadata {
                    proof_signing_alg_values_supported: vec![
                        CREDENTIAL_SIGNING_ALG_EDDSA.to_string()
                    ],
                },
            )]),
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
pub struct ProofTypeMetadata {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proof_signing_alg_values_supported: Vec<String>,
}

/// Expected character set of a transaction code, per OID4VCI: `numeric` (digits
/// only, the default) or `text` (any characters).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TxCodeInputMode {
    #[default]
    Numeric,
    Text,
}

/// Transaction code parameters carried inside a pre-authorized-code grant.
///
/// See the OID4VCI pre-authorized code flow: `input_mode` is the expected
/// character set (`numeric` by default), `length` is the number of characters,
/// and `description` is optional guidance shown to the holder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxCode {
    #[serde(default)]
    pub input_mode: TxCodeInputMode,
    pub length: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl TxCode {
    pub fn new(length: u64, description: Option<String>) -> Self {
        Self {
            input_mode: TxCodeInputMode::Numeric,
            length,
            description,
        }
    }
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
        let mut grant = serde_json::Map::new();
        grant.insert("issuer_state".to_string(), Value::String(issuer_state));
        if let Some(authorization_server) = authorization_server {
            grant.insert(
                "authorization_server".to_string(),
                Value::String(authorization_server),
            );
        }
        Self {
            credential_issuer: credential_issuer.into(),
            credential_configuration_ids,
            grants: BTreeMap::from([(
                AUTHORIZATION_CODE_GRANT_TYPE.to_string(),
                Value::Object(grant),
            )]),
        }
    }

    pub fn pre_authorized_code(
        credential_issuer: impl Into<String>,
        credential_configuration_ids: Vec<String>,
        pre_authorized_code: impl Into<String>,
        tx_code: Option<TxCode>,
    ) -> Self {
        let mut grant = serde_json::Map::new();
        grant.insert(
            "pre-authorized_code".to_string(),
            Value::String(pre_authorized_code.into()),
        );
        if let Some(tx_code) = tx_code {
            grant.insert(
                "tx_code".to_string(),
                serde_json::to_value(tx_code).expect("tx_code serializes"),
            );
        }
        Self {
            credential_issuer: credential_issuer.into(),
            credential_configuration_ids,
            grants: BTreeMap::from([(
                PRE_AUTHORIZED_CODE_GRANT_TYPE.to_string(),
                Value::Object(grant),
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
pub struct TokenRequest {
    pub grant_type: String,
    #[serde(
        rename = "pre-authorized_code",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub pre_authorized_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
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
    pub forbidden_holder_keys: &'a [PublicJwk],
}

impl<'a> ProofValidationPolicy<'a> {
    #[must_use]
    pub fn credential_endpoint(
        audience: &'a str,
        expected_nonce: Option<&'a str>,
        max_lifetime: Duration,
        future_skew: Duration,
    ) -> Self {
        Self {
            audience,
            expected_nonce,
            max_lifetime,
            future_skew,
            forbidden_holder_keys: &[],
        }
    }

    #[must_use]
    pub fn with_forbidden_holder_keys(mut self, forbidden_holder_keys: &'a [PublicJwk]) -> Self {
        self.forbidden_holder_keys = forbidden_holder_keys;
        self
    }
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
#[non_exhaustive]
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

/// Validate an OID4VCI proof JWT presented at the credential endpoint.
///
/// Validates structure, `typ` (`openid4vci-proof+jwt`), EdDSA signature,
/// audience, optional nonce, optional issuer claim shape, time bounds, and
/// holder binding (`did:jwk` or inline `jwk` header). Returns the verified
/// holder JWK, holder DID, and raw claims on success.
///
/// **Nonce replay is a caller responsibility.** This function validates that the
/// nonce in the proof matches `policy.expected_nonce`, but it does NOT track
/// nonce usage across calls. Callers must persist and reject already-used nonces.
/// The `ValidatedProof::nonce` field carries the nonce back for this purpose.
pub fn validate_proof_jwt(
    proof_jwt: &str,
    policy: &ProofValidationPolicy<'_>,
    now: i64,
) -> Result<ValidatedProof, ProofError> {
    let (header_b64, payload_b64, signature_b64) = split_compact_jwt(proof_jwt)?;
    let header = decode_json(header_b64).map_err(|_| ProofError::InvalidHeader)?;
    reject_header(&header)?;
    let holder_jwk = holder_jwk_from_header(&header)?;
    if policy
        .forbidden_holder_keys
        .iter()
        .any(|forbidden| same_public_key_material(forbidden, &holder_jwk))
    {
        return Err(ProofError::UnsupportedKeyReference);
    }
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
            if !same_public_key_material(&kid_jwk, &holder_jwk) {
                return Err(ProofError::UnsupportedKeyReference);
            }
            did.to_string()
        }
        None => did_jwk_from_public_jwk(&holder_jwk).expect("public jwk encodes"),
    };
    if claims.get("iss").is_some_and(|issuer| !issuer.is_string()) {
        return Err(ProofError::InvalidClaims);
    }

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

/// Validate a production credential-endpoint proof with a reserved, single-use
/// challenge nonce.
///
/// The nonce must be present in `policy.expected_nonce`, the proof must carry
/// exactly that nonce, and `nonce_store` must consume the nonce in `nonce_scope`
/// exactly once. Missing, already-used, or store-failed nonces all fail closed
/// as `ProofError::InvalidNonce`.
pub async fn validate_challenged_proof_jwt(
    proof_jwt: &str,
    policy: &ProofValidationPolicy<'_>,
    now: i64,
    nonce_store: &dyn ConsumableNonceStore,
    nonce_scope: &ReplayScope,
) -> Result<ValidatedProof, ProofError> {
    let expected_nonce = policy.expected_nonce.ok_or(ProofError::InvalidNonce)?;
    let proof = validate_proof_jwt(proof_jwt, policy, now)?;
    if proof.nonce.as_deref() != Some(expected_nonce) {
        return Err(ProofError::InvalidNonce);
    }
    let nonce_key = ReplayKey::new(expected_nonce).map_err(|_| ProofError::InvalidNonce)?;
    require_consume_once(nonce_store, nonce_scope, &nonce_key)
        .await
        .map_err(|_| ProofError::InvalidNonce)?;
    Ok(proof)
}

/// Consume the nonce from an already validated credential-endpoint proof.
///
/// This helper supports consumers that derive their replay key from deployment
/// context instead of using the raw nonce string as the replay key.
pub async fn consume_validated_proof_nonce_once(
    proof: &ValidatedProof,
    expected_nonce: &str,
    nonce_store: &dyn ConsumableNonceStore,
    nonce_scope: &ReplayScope,
    nonce_key: &ReplayKey,
) -> Result<(), ProofError> {
    if proof.nonce.as_deref() != Some(expected_nonce) {
        return Err(ProofError::InvalidNonce);
    }
    require_consume_once(nonce_store, nonce_scope, nonce_key)
        .await
        .map_err(|_| ProofError::InvalidNonce)?;
    Ok(())
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

fn same_public_key_material(left: &PublicJwk, right: &PublicJwk) -> bool {
    left.kty == right.kty
        && left.crv == right.crv
        && left.x == right.x
        && left.y == right.y
        && left.n == right.n
        && left.e == right.e
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
    use registry_platform_replay::{InMemoryConsumableNonceStore, ReplayKey, ReplayScope};
    use serde_json::json;
    use time::OffsetDateTime;

    const RAW_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;

    #[test]
    fn validates_public_jwk_proof() {
        let key = PrivateJwk::parse(RAW_JWK).expect("key parses");
        let holder_id = did_jwk_from_public_jwk(&key.public()).expect("did:jwk encodes");
        let proof = sign_proof(
            json!({"alg":"EdDSA","typ":PROOF_JWT_TYPE,"jwk": key.public()}),
            json!({"iss":holder_id,"aud":"https://issuer.example","iat":1000,"exp":1060,"nonce":"n-1"}),
            &key,
        );
        let validated = validate_proof_jwt(
            &proof,
            &ProofValidationPolicy {
                audience: "https://issuer.example",
                expected_nonce: Some("n-1"),
                max_lifetime: Duration::from_secs(300),
                future_skew: Duration::from_secs(30),
                forbidden_holder_keys: &[],
            },
            1001,
        )
        .expect("proof validates");

        assert_eq!(validated.holder_jwk, key.public());
        assert!(validated.holder_id.starts_with("did:jwk:"));
    }

    #[test]
    fn validates_pyjwt_public_jwk_proof_without_iss() {
        let proof = concat!(
            "eyJhbGciOiJFZERTQSIsImp3ayI6eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MT",
            "kiLCJrdHkiOiJPS1AiLCJ4IjoiMWFqX3JMSnNHRmd3LTV2OTI1RU1tZVpqNUp",
            "xUDQ0eGVnYWZFS2ZaYmR4YyJ9LCJ0eXAiOiJvcGVuaWQ0dmNpLXByb29",
            "mK2p3dCJ9.eyJhdWQiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiaWF",
            "0IjoxMDAwLCJub25jZSI6Im4tMSJ9.fIyoaSjcCVbtOuSql0Wj5WfmdKBzY",
            "jIDyU26kCixkwXM2QcKiNJicQMp4yBO5mNEsSp3qiDn09Bqbrx0EhMFBg"
        );

        validate_proof_jwt(proof, &policy(Some("n-1")), 1001)
            .expect("PyJWT EdDSA proof without iss validates");
    }

    #[test]
    fn validates_did_jwk_kid_proof() {
        let key = PrivateJwk::parse(RAW_JWK).expect("key parses");
        let did = did_jwk_from_public_jwk(&key.public()).expect("did:jwk encodes");
        let proof = sign_proof(
            json!({"alg":"EdDSA","typ":PROOF_JWT_TYPE,"kid": format!("{did}#key-1")}),
            json!({"iss":did,"aud":["https://other.example","https://issuer.example"],"iat":1000}),
            &key,
        );

        let validated = validate_proof_jwt(
            &proof,
            &ProofValidationPolicy {
                audience: "https://issuer.example",
                expected_nonce: None,
                max_lifetime: Duration::from_secs(300),
                future_skew: Duration::from_secs(30),
                forbidden_holder_keys: &[],
            },
            1001,
        )
        .expect("proof validates");

        assert_eq!(validated.holder_id, did);
    }

    #[test]
    fn validates_did_jwk_kid_proof_with_wallet_public_metadata() {
        let key = PrivateJwk::parse(RAW_JWK).expect("key parses");
        let did = format!(
            "did:jwk:{}",
            URL_SAFE_NO_PAD.encode(
                br#"{"x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","kty":"OKP","crv":"Ed25519","alg":"EdDSA","kid":"wallet-key-1"}"#
            )
        );
        let proof = sign_proof(
            json!({"alg":"EdDSA","typ":PROOF_JWT_TYPE,"kid": format!("{did}#0")}),
            json!({"aud":"https://issuer.example","iat":1000,"nonce":"n-1"}),
            &key,
        );

        let validated = validate_proof_jwt(&proof, &policy(Some("n-1")), 1001)
            .expect("wallet did:jwk proof validates");

        assert_eq!(validated.holder_id, did);
    }

    #[test]
    fn rejects_wrong_type_remote_key_and_wrong_nonce() {
        let key = PrivateJwk::parse(RAW_JWK).expect("key parses");
        let holder_id = did_jwk_from_public_jwk(&key.public()).expect("did:jwk encodes");
        let wrong_typ = sign_proof(
            json!({"alg":"EdDSA","typ":"jwt","jwk": key.public()}),
            json!({"iss":holder_id,"aud":"https://issuer.example","iat":1000,"nonce":"n-1"}),
            &key,
        );
        assert_eq!(
            validate_proof_jwt(&wrong_typ, &policy(Some("n-1")), 1001),
            Err(ProofError::InvalidHeader)
        );

        let remote = sign_proof(
            json!({"alg":"EdDSA","typ":PROOF_JWT_TYPE,"jku":"https://keys.example/jwks.json","jwk": key.public()}),
            json!({"iss":holder_id,"aud":"https://issuer.example","iat":1000,"nonce":"n-1"}),
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
        let signing_did = did_jwk_from_public_jwk(&signing_key.public()).expect("did:jwk encodes");
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
            json!({"iss":signing_did,"aud":"https://issuer.example","iat":1000,"nonce":"n-1"}),
            &signing_key,
        );

        assert_eq!(
            validate_proof_jwt(&proof, &policy(Some("n-1")), 1001),
            Err(ProofError::UnsupportedKeyReference)
        );
    }

    #[test]
    fn rejects_forbidden_holder_key() {
        let key = PrivateJwk::parse(RAW_JWK).expect("key parses");
        let mut p = policy(Some("n-1"));
        let forbidden = [key.public()];
        p.forbidden_holder_keys = &forbidden;

        assert_eq!(
            validate_proof_jwt(&valid_proof(&key, "n-1"), &p, 1001),
            Err(ProofError::UnsupportedKeyReference)
        );
    }

    #[test]
    fn rejects_forbidden_holder_key_with_different_metadata() {
        let key = PrivateJwk::parse(RAW_JWK).expect("key parses");
        let mut forbidden_key = key.public();
        forbidden_key.alg = None;
        forbidden_key.kid = Some("did:web:issuer.test#rotated".to_string());
        let forbidden = [forbidden_key];
        let mut p = policy(Some("n-1"));
        p.forbidden_holder_keys = &forbidden;

        assert_eq!(
            validate_proof_jwt(&valid_proof(&key, "n-1"), &p, 1001),
            Err(ProofError::UnsupportedKeyReference)
        );
    }

    #[test]
    fn accepts_optional_proof_issuer_and_rejects_invalid_shape() {
        let key = PrivateJwk::parse(RAW_JWK).expect("key parses");
        let missing_iss = sign_proof(
            json!({"alg":"EdDSA","typ":PROOF_JWT_TYPE,"jwk": key.public()}),
            json!({"aud":"https://issuer.example","iat":1000,"nonce":"n-1"}),
            &key,
        );
        validate_proof_jwt(&missing_iss, &policy(Some("n-1")), 1001)
            .expect("anonymous pre-authorized-code proof accepts omitted iss");

        let client_iss = sign_proof(
            json!({"alg":"EdDSA","typ":PROOF_JWT_TYPE,"jwk": key.public()}),
            json!({"iss":"wallet-client-1","aud":"https://issuer.example","iat":1000,"nonce":"n-1"}),
            &key,
        );
        validate_proof_jwt(&client_iss, &policy(Some("n-1")), 1001)
            .expect("proof issuer is an optional client identifier");

        let invalid_iss = sign_proof(
            json!({"alg":"EdDSA","typ":PROOF_JWT_TYPE,"jwk": key.public()}),
            json!({"iss":{"id":"wallet-client-1"},"aud":"https://issuer.example","iat":1000,"nonce":"n-1"}),
            &key,
        );
        assert_eq!(
            validate_proof_jwt(&invalid_iss, &policy(Some("n-1")), 1001),
            Err(ProofError::InvalidClaims)
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
    fn credential_request_ignores_unknown_fields() {
        let request = json!({
            "format": SD_JWT_VC_FORMAT,
            "credential_configuration_id": "person_is_alive_sd_jwt",
            "subject": {"id": "NID-1002"},
            "proof": {"proof_type": PROOF_TYPE_JWT, "jwt": "a.b.c"}
        });
        let parsed = serde_json::from_value::<CredentialRequest>(request).expect("request parses");
        assert_eq!(
            parsed.credential_configuration_id.as_deref(),
            Some("person_is_alive_sd_jwt")
        );

        let request = json!({
            "format": SD_JWT_VC_FORMAT,
            "credential_configuration_id": "person_is_alive_sd_jwt",
            "proof": {"proof_type": PROOF_TYPE_JWT, "jwt": "a.b.c", "subject": "NID-1002"}
        });
        let parsed = serde_json::from_value::<CredentialRequest>(request).expect("request parses");
        assert_eq!(parsed.proof.jwt, "a.b.c");
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

    #[test]
    fn validate_proof_jwt_does_not_track_nonce_reuse_across_calls() {
        let key = PrivateJwk::parse(RAW_JWK).expect("key parses");
        let proof = valid_proof(&key, "n-replay");
        let p = policy(Some("n-replay"));

        let first = validate_proof_jwt(&proof, &p, 1001).expect("first call accepts the proof");
        let second =
            validate_proof_jwt(&proof, &p, 1001).expect("second call also accepts the proof");

        assert_eq!(first.nonce, Some("n-replay".to_string()));
        assert_eq!(second.nonce, Some("n-replay".to_string()));
        // Both calls succeed because replay prevention is the caller's responsibility;
        // the caller must record `ValidatedProof::nonce` and reject it if seen before.
    }

    #[tokio::test]
    async fn challenged_proof_consumes_reserved_nonce_once() {
        let key = PrivateJwk::parse(RAW_JWK).expect("key parses");
        let store = InMemoryConsumableNonceStore::new();
        let scope = ReplayScope::oid4vci_nonce("tenant-a", "issuer-a", "profile-a").expect("scope");
        let nonce = ReplayKey::new("n-replay").expect("nonce key");
        store
            .reserve_nonce(
                &scope,
                &nonce,
                OffsetDateTime::now_utc() + time::Duration::seconds(60),
            )
            .await
            .expect("nonce reserves");
        let proof = valid_proof(&key, "n-replay");
        let p = policy(Some("n-replay"));

        validate_challenged_proof_jwt(&proof, &p, 1001, &store, &scope)
            .await
            .expect("reserved nonce validates once");
        assert_eq!(
            validate_challenged_proof_jwt(&proof, &p, 1001, &store, &scope).await,
            Err(ProofError::InvalidNonce)
        );
    }

    #[tokio::test]
    async fn challenged_proof_requires_expected_nonce() {
        let key = PrivateJwk::parse(RAW_JWK).expect("key parses");
        let store = InMemoryConsumableNonceStore::new();
        let scope = ReplayScope::oid4vci_nonce("tenant-a", "issuer-a", "profile-a").expect("scope");
        let p = policy(None);

        assert_eq!(
            validate_challenged_proof_jwt(
                &valid_proof(&key, "n-replay"),
                &p,
                1001,
                &store,
                &scope,
            )
            .await,
            Err(ProofError::InvalidNonce)
        );
    }

    #[tokio::test]
    async fn credential_endpoint_policy_and_nonce_helper_consume_once() {
        let key = PrivateJwk::parse(RAW_JWK).expect("key parses");
        let store = InMemoryConsumableNonceStore::new();
        let scope = ReplayScope::oid4vci_nonce("tenant-a", "issuer-a", "profile-a").expect("scope");
        let nonce_key = ReplayKey::new("hashed-n-replay").expect("nonce key");
        store
            .reserve_nonce(
                &scope,
                &nonce_key,
                OffsetDateTime::now_utc() + time::Duration::seconds(60),
            )
            .await
            .expect("nonce reserves");
        let policy = ProofValidationPolicy::credential_endpoint(
            "https://issuer.example",
            Some("n-replay"),
            Duration::from_secs(300),
            Duration::from_secs(30),
        );
        let proof = validate_proof_jwt(&valid_proof(&key, "n-replay"), &policy, 1001)
            .expect("proof validates");

        consume_validated_proof_nonce_once(&proof, "n-replay", &store, &scope, &nonce_key)
            .await
            .expect("reserved nonce consumes once");
        assert_eq!(
            consume_validated_proof_nonce_once(&proof, "n-replay", &store, &scope, &nonce_key)
                .await,
            Err(ProofError::InvalidNonce)
        );
    }

    #[test]
    fn credential_configuration_metadata_sd_jwt_vc_serialises_to_spec_shape() {
        let metadata = CredentialConfigurationMetadata::sd_jwt_vc(
            "identity_vc",
            vec![CRYPTOGRAPHIC_BINDING_METHOD_DID_JWK.to_string()],
            "Identity Credential",
            "https://vct.example/identity",
        );
        let value = serde_json::to_value(&metadata).expect("serializes");

        assert_eq!(value["format"], SD_JWT_VC_FORMAT);
        assert_eq!(value["scope"], "identity_vc");
        assert_eq!(
            value["proof_types_supported"][PROOF_TYPE_JWT]["proof_signing_alg_values_supported"][0],
            CREDENTIAL_SIGNING_ALG_EDDSA
        );
        assert_eq!(
            value["credential_signing_alg_values_supported"][0],
            CREDENTIAL_SIGNING_ALG_EDDSA
        );
        assert_eq!(value["vct"], "https://vct.example/identity");

        let round_tripped: CredentialConfigurationMetadata =
            serde_json::from_value(value).expect("round-trip deserializes");
        assert_eq!(round_tripped.format, SD_JWT_VC_FORMAT);
        assert_eq!(
            round_tripped.vct.as_deref(),
            Some("https://vct.example/identity")
        );
        assert!(round_tripped
            .proof_types_supported
            .contains_key(PROOF_TYPE_JWT));
    }

    #[test]
    fn credential_offer_authorization_code_serialises_to_spec_shape() {
        let offer = CredentialOffer::authorization_code(
            "https://issuer.example",
            vec!["identity_vc".to_string()],
            "state-xyz",
            Some("https://as.example".to_string()),
        );
        let value = serde_json::to_value(&offer).expect("serializes");

        assert_eq!(value["credential_issuer"], "https://issuer.example");
        assert_eq!(value["credential_configuration_ids"][0], "identity_vc");
        assert_eq!(
            value["grants"][AUTHORIZATION_CODE_GRANT_TYPE]["issuer_state"],
            "state-xyz"
        );
        assert_eq!(
            value["grants"][AUTHORIZATION_CODE_GRANT_TYPE]["authorization_server"],
            "https://as.example"
        );

        let round_tripped: CredentialOffer =
            serde_json::from_value(value).expect("round-trip deserializes");
        assert_eq!(round_tripped.credential_issuer, "https://issuer.example");
        assert!(round_tripped
            .grants
            .contains_key(AUTHORIZATION_CODE_GRANT_TYPE));
    }

    #[test]
    fn credential_offer_authorization_code_grant_has_no_pre_authorized_fields() {
        let offer = CredentialOffer::authorization_code(
            "https://issuer.example",
            vec!["identity_vc".to_string()],
            "state-xyz",
            Some("https://as.example".to_string()),
        );
        let value = serde_json::to_value(&offer).expect("serializes");

        assert!(value["grants"]
            .get(PRE_AUTHORIZED_CODE_GRANT_TYPE)
            .is_none());
        let grant = &value["grants"][AUTHORIZATION_CODE_GRANT_TYPE];
        assert!(grant.get("pre-authorized_code").is_none());
        assert!(grant.get("tx_code").is_none());
    }

    #[test]
    fn credential_offer_pre_authorized_code_serialises_to_spec_shape() {
        let offer = CredentialOffer::pre_authorized_code(
            "https://issuer.example",
            vec!["identity_vc".to_string()],
            "pre-auth-code-123",
            Some(TxCode::new(
                6,
                Some("Enter the code from the letter".to_string()),
            )),
        );
        let value = serde_json::to_value(&offer).expect("serializes");

        assert_eq!(value["credential_issuer"], "https://issuer.example");
        assert_eq!(value["credential_configuration_ids"][0], "identity_vc");
        let grant = &value["grants"][PRE_AUTHORIZED_CODE_GRANT_TYPE];
        assert_eq!(grant["pre-authorized_code"], "pre-auth-code-123");
        assert_eq!(grant["tx_code"]["input_mode"], "numeric");
        assert_eq!(grant["tx_code"]["length"], 6);
        assert_eq!(
            grant["tx_code"]["description"],
            "Enter the code from the letter"
        );

        let round_tripped: CredentialOffer =
            serde_json::from_value(value).expect("round-trip deserializes");
        assert!(round_tripped
            .grants
            .contains_key(PRE_AUTHORIZED_CODE_GRANT_TYPE));
    }

    #[test]
    fn credential_offer_pre_authorized_code_omits_tx_code_when_absent() {
        let offer = CredentialOffer::pre_authorized_code(
            "https://issuer.example",
            vec!["identity_vc".to_string()],
            "pre-auth-code-123",
            None,
        );
        let value = serde_json::to_value(&offer).expect("serializes");

        let grant = &value["grants"][PRE_AUTHORIZED_CODE_GRANT_TYPE];
        assert_eq!(grant["pre-authorized_code"], "pre-auth-code-123");
        assert!(grant.get("tx_code").is_none());
    }

    #[test]
    fn tx_code_defaults_input_mode_and_omits_description() {
        let tx_code = TxCode::new(4, None);
        let value = serde_json::to_value(&tx_code).expect("serializes");

        assert_eq!(value["input_mode"], "numeric");
        assert_eq!(value["length"], 4);
        assert!(value.get("description").is_none());

        let from_minimal: TxCode =
            serde_json::from_value(json!({"length": 8})).expect("deserializes minimal tx_code");
        assert_eq!(from_minimal.input_mode, TxCodeInputMode::Numeric);
        assert_eq!(from_minimal.length, 8);
        assert_eq!(from_minimal.description, None);
    }

    #[test]
    fn token_request_deserialises_from_form_payload() {
        let form = "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code\
            &pre-authorized_code=pre-auth-code-123&tx_code=123456";
        let request: TokenRequest =
            serde_urlencoded::from_str(form).expect("form decodes into TokenRequest");

        assert_eq!(request.grant_type, PRE_AUTHORIZED_CODE_GRANT_TYPE);
        assert_eq!(
            request.pre_authorized_code.as_deref(),
            Some("pre-auth-code-123")
        );
        assert_eq!(request.tx_code.as_deref(), Some("123456"));

        let request: TokenRequest = serde_json::from_value(json!({
            "grant_type": PRE_AUTHORIZED_CODE_GRANT_TYPE,
            "pre-authorized_code": "pre-auth-code-123"
        }))
        .expect("json decodes into TokenRequest");
        assert_eq!(
            request.pre_authorized_code.as_deref(),
            Some("pre-auth-code-123")
        );
        assert_eq!(request.tx_code, None);
    }

    #[test]
    fn token_response_serialises_access_token_and_c_nonce() {
        let response = TokenResponse {
            access_token: "access-token-abc".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(300),
            c_nonce: Some("c-nonce-xyz".to_string()),
            c_nonce_expires_in: Some(120),
        };
        let value = serde_json::to_value(&response).expect("serializes");

        assert_eq!(value["access_token"], "access-token-abc");
        assert_eq!(value["token_type"], "Bearer");
        assert_eq!(value["expires_in"], 300);
        assert_eq!(value["c_nonce"], "c-nonce-xyz");
        assert_eq!(value["c_nonce_expires_in"], 120);

        let round_tripped: TokenResponse =
            serde_json::from_value(value).expect("round-trip deserializes");
        assert_eq!(round_tripped.access_token, "access-token-abc");
        assert_eq!(round_tripped.c_nonce.as_deref(), Some("c-nonce-xyz"));
    }

    #[test]
    fn token_response_omits_c_nonce_expires_in_when_absent() {
        let response = TokenResponse {
            access_token: "access-token-abc".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(300),
            c_nonce: Some("c-nonce-xyz".to_string()),
            c_nonce_expires_in: None,
        };
        let value = serde_json::to_value(&response).expect("serializes");

        assert!(value.get("c_nonce_expires_in").is_none());
    }

    #[test]
    fn credential_issuer_metadata_token_endpoint_serialisation() {
        let metadata = CredentialIssuerMetadata::new(
            "https://issuer.example",
            "https://issuer.example/credential",
            None,
            Vec::new(),
            BTreeMap::new(),
        );
        let value = serde_json::to_value(&metadata).expect("serializes");
        assert!(value.get("token_endpoint").is_none());

        let metadata = metadata.with_token_endpoint("https://issuer.example/token".to_string());
        let value = serde_json::to_value(&metadata).expect("serializes");
        assert_eq!(value["token_endpoint"], "https://issuer.example/token");

        let round_tripped: CredentialIssuerMetadata =
            serde_json::from_value(value).expect("round-trip deserializes");
        assert_eq!(
            round_tripped.token_endpoint.as_deref(),
            Some("https://issuer.example/token")
        );
    }

    fn policy(expected_nonce: Option<&str>) -> ProofValidationPolicy<'_> {
        ProofValidationPolicy {
            audience: "https://issuer.example",
            expected_nonce,
            max_lifetime: Duration::from_secs(300),
            future_skew: Duration::from_secs(30),
            forbidden_holder_keys: &[],
        }
    }

    fn valid_proof(key: &PrivateJwk, nonce: &str) -> String {
        let holder_id = did_jwk_from_public_jwk(&key.public()).expect("did:jwk encodes");
        sign_proof(
            json!({"alg":"EdDSA","typ":PROOF_JWT_TYPE,"jwk": key.public()}),
            json!({"iss":holder_id,"aud":"https://issuer.example","iat":1000,"exp":1060,"nonce": nonce}),
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
