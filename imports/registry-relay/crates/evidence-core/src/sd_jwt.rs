// SPDX-License-Identifier: Apache-2.0
//! Minimal SD-JWT VC issuer for Evidence Server claim views.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use getrandom::fill;
use jsonwebtoken::{Algorithm, EncodingKey};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::config::CredentialProfileConfig;
use crate::error::EvidenceError;
use crate::model::ClaimResultView;

#[derive(Debug, Clone)]
pub struct SignedSdJwtVc {
    pub credential_id: String,
    pub issuer: String,
    pub expires_at: String,
    pub compact: String,
}

#[derive(Debug, Clone)]
pub struct EvidenceIssuer {
    verification_method_id: String,
    encoding_key: EncodingKey,
    public_jwk: Value,
}

impl EvidenceIssuer {
    pub fn from_profile(profile: &CredentialProfileConfig) -> Result<Self, EvidenceError> {
        let verification_method_id = profile
            .issuer_kid
            .clone()
            .unwrap_or_else(|| format!("{}#evidence-issuer", profile.issuer));
        let raw = std::env::var(&profile.issuer_key_env)
            .map_err(|_| EvidenceError::CredentialIssuerNotConfigured)?;
        let raw = Zeroizing::new(raw);
        Self::from_jwk_str(&raw, verification_method_id)
    }

    pub fn from_jwk_str(raw: &str, verification_method_id: String) -> Result<Self, EvidenceError> {
        let jwk: PrivateJwk =
            serde_json::from_str(raw).map_err(|_| EvidenceError::CredentialIssuanceFailed)?;
        if jwk.kty != "OKP" || jwk.crv.as_deref() != Some("Ed25519") {
            return Err(EvidenceError::CredentialIssuanceFailed);
        }
        if let Some(jwk_alg) = jwk.alg.as_deref() {
            if jwk_alg != "EdDSA" {
                return Err(EvidenceError::CredentialIssuanceFailed);
            }
        }
        let d = jwk
            .d
            .as_deref()
            .ok_or(EvidenceError::CredentialIssuanceFailed)?;
        let x = jwk
            .x
            .as_deref()
            .ok_or(EvidenceError::CredentialIssuanceFailed)?;
        let d_bytes = URL_SAFE_NO_PAD
            .decode(d)
            .map_err(|_| EvidenceError::CredentialIssuanceFailed)?;
        if d_bytes.len() != 32 {
            return Err(EvidenceError::CredentialIssuanceFailed);
        }
        let x_bytes = URL_SAFE_NO_PAD
            .decode(x)
            .map_err(|_| EvidenceError::CredentialIssuanceFailed)?;
        if x_bytes.len() != 32 {
            return Err(EvidenceError::CredentialIssuanceFailed);
        }
        let encoding_key = EncodingKey::from_ed_der(&ed25519_pkcs8_seed(&d_bytes));
        let public_jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x,
            "alg": "EdDSA",
            "kid": verification_method_id.clone(),
        });
        Ok(Self {
            verification_method_id,
            encoding_key,
            public_jwk,
        })
    }

    #[must_use]
    pub fn public_jwk(&self) -> Value {
        self.public_jwk.clone()
    }

    fn sign(&self, header: Value, payload: Value) -> Result<String, EvidenceError> {
        let header_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&header).map_err(|_| EvidenceError::CredentialIssuanceFailed)?,
        );
        let payload_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&payload).map_err(|_| EvidenceError::CredentialIssuanceFailed)?,
        );
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = jsonwebtoken::crypto::sign(
            signing_input.as_bytes(),
            &self.encoding_key,
            Algorithm::EdDSA,
        )
        .map_err(|_| EvidenceError::CredentialIssuanceFailed)?;
        Ok(format!("{signing_input}.{signature}"))
    }
}

pub fn issue(
    profile: &CredentialProfileConfig,
    issuer: &EvidenceIssuer,
    results: &[ClaimResultView],
    holder_id: Option<&str>,
) -> Result<SignedSdJwtVc, EvidenceError> {
    if profile.holder_binding.mode != "none" && holder_id.is_none() {
        return Err(EvidenceError::HolderProofRequired);
    }
    let now = OffsetDateTime::now_utc();
    let expires_at = now + time::Duration::seconds(profile.validity_seconds);
    let credential_id = format!("urn:ulid:{}", Ulid::new());
    let mut payload = Map::new();
    payload.insert("iss".to_string(), Value::String(profile.issuer.clone()));
    payload.insert(
        "iat".to_string(),
        Value::Number(now.unix_timestamp().into()),
    );
    payload.insert(
        "exp".to_string(),
        Value::Number(expires_at.unix_timestamp().into()),
    );
    payload.insert("vct".to_string(), Value::String(profile.vct.clone()));
    payload.insert("id".to_string(), Value::String(credential_id.clone()));
    payload.insert("_sd_alg".to_string(), Value::String("sha-256".to_string()));
    if let Some(holder_id) = holder_id {
        payload.insert("cnf".to_string(), json!({ "kid": holder_id }));
    }

    let mut sd = Vec::new();
    let mut disclosures = Vec::new();
    for result in results {
        let claim_value = json!({
            "claim_id": result.claim_id,
            "version": result.claim_version,
            "value": result.value,
            "satisfied": result.satisfied,
            "subject_type": result.subject_type,
            "issued_at": result.issued_at,
        });
        let disclosure = disclosure(&result.claim_id, claim_value)?;
        sd.push(Value::String(disclosure.digest));
        disclosures.push(disclosure.encoded);
    }
    payload.insert("_sd".to_string(), Value::Array(sd));

    let header = json!({
        "alg": "EdDSA",
        "typ": "dc+sd-jwt",
        "kid": issuer.verification_method_id,
    });
    let compact = issuer.sign(header, Value::Object(payload))?;
    Ok(SignedSdJwtVc {
        credential_id,
        issuer: profile.issuer.clone(),
        expires_at: format_time(expires_at),
        compact: format!("{}~{}~", compact, disclosures.join("~")),
    })
}

struct Disclosure {
    encoded: String,
    digest: String,
}

fn disclosure(name: &str, value: Value) -> Result<Disclosure, EvidenceError> {
    let mut salt = [0u8; 16];
    fill(&mut salt).map_err(|_| EvidenceError::CredentialIssuanceFailed)?;
    let salt = URL_SAFE_NO_PAD.encode(salt);
    let encoded = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!([salt, name, value]))
            .map_err(|_| EvidenceError::CredentialIssuanceFailed)?,
    );
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(encoded.as_bytes()));
    Ok(Disclosure { encoded, digest })
}

#[derive(Debug, Deserialize)]
struct PrivateJwk {
    kty: String,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    d: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    alg: Option<String>,
}

fn ed25519_pkcs8_seed(seed: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(48);
    out.extend_from_slice(&[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ]);
    out.extend_from_slice(seed);
    out
}

fn format_time(value: OffsetDateTime) -> String {
    value
        .format(&Rfc3339)
        .expect("OffsetDateTime within supported RFC3339 range")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disclosure_digest_is_over_encoded_disclosure() {
        let d = disclosure("x", json!(1)).expect("disclosure");
        assert_eq!(
            d.digest,
            URL_SAFE_NO_PAD.encode(Sha256::digest(d.encoded.as_bytes()))
        );
    }

    #[test]
    fn signing_algorithm_header_value_is_stable() {
        let raw_jwk = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;
        let issuer = EvidenceIssuer::from_jwk_str(raw_jwk, "did:web:issuer.test#key-1".to_string())
            .expect("test issuer builds");
        let compact = issuer
            .sign(
                json!({
                    "alg": "EdDSA",
                    "typ": "dc+sd-jwt",
                    "kid": "did:web:issuer.test#key-1",
                }),
                json!({ "iss": "did:web:issuer.test" }),
            )
            .expect("test jwt signs");
        let header = compact.split('.').next().expect("compact jwt has header");
        let header: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(header)
                .expect("header decodes as base64url"),
        )
        .expect("header decodes as JSON");
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["typ"], "dc+sd-jwt");
    }
}
