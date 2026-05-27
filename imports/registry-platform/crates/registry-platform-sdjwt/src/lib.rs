// SPDX-License-Identifier: Apache-2.0
//! SD-JWT VC issuance and holder-proof validation helpers.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use registry_platform_crypto::{
    verify, JwkError, LocalJwkSigner, PrivateJwk, PublicJwk, SigningAlgorithm, SigningError,
    SigningProvider,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use ulid::Ulid;

#[derive(Clone)]
pub struct SdJwtIssuer {
    signer: Arc<dyn SigningProvider>,
}

impl fmt::Debug for SdJwtIssuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SdJwtIssuer")
            .field("alg", &self.signer.algorithm())
            .field("kid", &self.signer.key_id())
            .finish_non_exhaustive()
    }
}

impl SdJwtIssuer {
    pub fn from_jwk(jwk: PrivateJwk) -> Result<Self, SdJwtError> {
        let signer = LocalJwkSigner::new(jwk).map_err(map_signing_error)?;
        Ok(Self::from_signing_provider(Arc::new(signer)))
    }

    #[must_use]
    pub fn from_signing_provider(signer: Arc<dyn SigningProvider>) -> Self {
        Self { signer }
    }

    pub async fn issue(&self, input: SdJwtIssuanceInput) -> Result<SignedSdJwt, SdJwtError> {
        input.validate()?;
        if self.signer.key_id().trim().is_empty() {
            return Err(SdJwtError::Signing(SigningError::MissingKeyId));
        }
        let credential_id = format!("urn:ulid:{}", Ulid::new());

        let mut payload = Map::new();
        payload.insert("iss".to_string(), Value::String(input.iss));
        payload.insert("sub".to_string(), Value::String(input.sub_ref));
        payload.insert("iat".to_string(), Value::Number(input.iat.into()));
        payload.insert("exp".to_string(), Value::Number(input.exp.into()));
        payload.insert("vct".to_string(), Value::String(input.vct));
        payload.insert("id".to_string(), Value::String(credential_id.clone()));
        payload.insert("jti".to_string(), Value::String(credential_id.clone()));
        payload.insert("_sd_alg".to_string(), Value::String("sha-256".to_string()));

        if let Some(cnf) = input.cnf {
            let mut cnf_value = Map::new();
            cnf_value.insert("jwk".to_string(), serde_json::to_value(cnf.jwk)?);
            if let Some(kid) = cnf.kid {
                cnf_value.insert("kid".to_string(), Value::String(kid));
            }
            payload.insert("cnf".to_string(), Value::Object(cnf_value));
        }

        let mut digests = Vec::with_capacity(input.disclosures.len());
        let mut disclosures = Vec::with_capacity(input.disclosures.len());
        for disclosure in input.disclosures {
            let issued = issue_disclosure(&disclosure.name, disclosure.value)?;
            digests.push(issued.digest);
            disclosures.push(issued.encoded);
        }
        sort_sd_digests(&mut digests);
        payload.insert(
            "_sd".to_string(),
            Value::Array(digests.into_iter().map(Value::String).collect()),
        );

        let header = json!({
            "alg": signing_algorithm_jwa(self.signer.algorithm()),
            "typ": "dc+sd-jwt",
            "kid": self.signer.key_id(),
        });
        let jwt = sign_jwt(header, Value::Object(payload), self.signer.as_ref()).await?;
        Ok(SignedSdJwt {
            credential_id: credential_id.clone(),
            jti: credential_id,
            jwt: format!("{}~{}~", jwt, disclosures.join("~")),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HolderConfirmation {
    pub jwk: PublicJwk,
    pub kid: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Disclosure {
    pub name: String,
    pub value: Value,
}

#[derive(Clone, Debug)]
pub struct SdJwtIssuanceInput {
    pub iss: String,
    pub sub_ref: String,
    pub iat: i64,
    pub exp: i64,
    pub vct: String,
    pub cnf: Option<HolderConfirmation>,
    pub disclosures: Vec<Disclosure>,
}

impl SdJwtIssuanceInput {
    fn validate(&self) -> Result<(), SdJwtError> {
        if self.iss.is_empty()
            || self.sub_ref.is_empty()
            || self.vct.is_empty()
            || self.exp <= self.iat
        {
            return Err(SdJwtError::InvalidInput);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedSdJwt {
    pub credential_id: String,
    pub jti: String,
    pub jwt: String,
}

#[allow(clippy::ptr_arg)]
pub fn sort_sd_digests(digests: &mut Vec<String>) {
    digests.sort_unstable();
}

#[derive(Clone, Debug)]
pub struct HolderProofPolicy {
    pub audience: String,
    pub max_lifetime: Duration,
}

#[derive(Clone, Debug)]
pub struct HolderProofBindings<'a> {
    pub expected_sub: &'a str,
    pub evaluation_id: &'a str,
    pub credential_profile: &'a str,
    pub disclosure_hash: &'a [u8],
    pub claim_set: &'a [String],
}

#[derive(Clone, Debug, PartialEq)]
pub struct HolderProofClaims {
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub raw: Value,
}

pub fn validate_holder_proof(
    proof_jwt: &str,
    holder_jwk: &PublicJwk,
    bindings: &HolderProofBindings<'_>,
    policy: &HolderProofPolicy,
    now: i64,
) -> Result<HolderProofClaims, SdJwtError> {
    let (header_b64, payload_b64, signature_b64) = split_compact_jwt(proof_jwt)?;
    let header = decode_json(header_b64)?;
    if header.get("alg").and_then(Value::as_str) != Some("EdDSA") {
        return Err(SdJwtError::HolderProofInvalid);
    }
    if header.get("typ").and_then(Value::as_str) != Some("kb+jwt") {
        return Err(SdJwtError::HolderProofInvalid);
    }
    for forbidden in ["crit", "jku", "jwk", "x5u", "x5c"] {
        if header.get(forbidden).is_some() {
            return Err(SdJwtError::HolderProofInvalid);
        }
    }
    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| SdJwtError::HolderProofInvalid)?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    verify(signing_input.as_bytes(), &signature, holder_jwk)
        .map_err(|_| SdJwtError::HolderProofInvalid)?;

    let raw = decode_json(payload_b64)?;
    let sub = required_string(&raw, "sub")?;
    let aud = required_audience(&raw, &policy.audience)?;
    let iat = required_i64(&raw, "iat")?;
    let exp = required_i64(&raw, "exp")?;
    let jti = required_string(&raw, "jti")?;
    if jti.is_empty() || jti.starts_with("urn:ulid:") {
        return Err(SdJwtError::HolderProofInvalid);
    }
    if sub != bindings.expected_sub {
        return Err(SdJwtError::HolderProofInvalid);
    }
    if raw.get("evaluation_id").and_then(Value::as_str) != Some(bindings.evaluation_id) {
        return Err(SdJwtError::HolderProofInvalid);
    }
    if raw.get("credential_profile").and_then(Value::as_str) != Some(bindings.credential_profile) {
        return Err(SdJwtError::HolderProofInvalid);
    }
    let expected_disclosure = URL_SAFE_NO_PAD.encode(bindings.disclosure_hash);
    if raw.get("disclosure").and_then(Value::as_str) != Some(expected_disclosure.as_str()) {
        return Err(SdJwtError::HolderProofInvalid);
    }
    if raw.get("claims") != Some(&json!(bindings.claim_set)) {
        return Err(SdJwtError::HolderProofInvalid);
    }
    let max_lifetime = i64::try_from(policy.max_lifetime.as_secs()).unwrap_or(i64::MAX);
    if iat < now - 120 || iat > now + 30 || exp <= iat || exp > iat + max_lifetime || exp <= now {
        return Err(SdJwtError::HolderProofInvalid);
    }

    Ok(HolderProofClaims {
        sub: sub.to_string(),
        aud,
        iat,
        exp,
        jti: jti.to_string(),
        raw,
    })
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SdJwtError {
    #[error("invalid SD-JWT input")]
    InvalidInput,
    #[error("unsupported signing algorithm")]
    UnsupportedAlgorithm,
    #[error("invalid signing key: {0}")]
    InvalidKey(#[from] JwkError),
    #[error("cryptographic operation failed: {0}")]
    Crypto(#[from] registry_platform_crypto::CryptoError),
    #[error("signing operation failed: {0}")]
    Signing(#[from] SigningError),
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("randomness failed: {0}")]
    Random(#[from] getrandom::Error),
    #[error("holder proof is invalid")]
    HolderProofInvalid,
}

fn map_signing_error(err: SigningError) -> SdJwtError {
    match err {
        SigningError::InvalidKey(JwkError::UnsupportedAlgorithm) => {
            SdJwtError::UnsupportedAlgorithm
        }
        SigningError::InvalidKey(err) => SdJwtError::InvalidKey(err),
        err => SdJwtError::Signing(err),
    }
}

fn signing_algorithm_jwa(algorithm: SigningAlgorithm) -> &'static str {
    match algorithm {
        SigningAlgorithm::EdDsa => "EdDSA",
    }
}

struct IssuedDisclosure {
    encoded: String,
    digest: String,
}

fn issue_disclosure(name: &str, value: Value) -> Result<IssuedDisclosure, SdJwtError> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt)?;
    let salt = URL_SAFE_NO_PAD.encode(salt);
    let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!([salt, name, value]))?);
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(encoded.as_bytes()));
    Ok(IssuedDisclosure { encoded, digest })
}

/// Internal JWS serialiser. Local Ed25519 sign cost is inherited from
/// `registry_platform_crypto::sign` (~15 µs/op on Apple M5 Max; see its doc
/// comment for details), while external providers may add network latency.
async fn sign_jwt(
    header: Value,
    payload: Value,
    signer: &dyn SigningProvider,
) -> Result<String, SdJwtError> {
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let public_jwk = signer.public_jwk();
    if public_jwk.kid.as_deref() != Some(signer.key_id()) {
        return Err(SdJwtError::Signing(SigningError::KeyIdMismatch));
    }
    let signature = signer.sign(signing_input.as_bytes()).await?;
    verify(signing_input.as_bytes(), &signature, &public_jwk)
        .map_err(|err| SdJwtError::Signing(SigningError::Crypto(err)))?;
    Ok(format!(
        "{}.{}",
        signing_input,
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

fn split_compact_jwt(jwt: &str) -> Result<(&str, &str, &str), SdJwtError> {
    let mut parts = jwt.split('.');
    let header = parts.next().ok_or(SdJwtError::HolderProofInvalid)?;
    let payload = parts.next().ok_or(SdJwtError::HolderProofInvalid)?;
    let signature = parts.next().ok_or(SdJwtError::HolderProofInvalid)?;
    if parts.next().is_some() || header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(SdJwtError::HolderProofInvalid);
    }
    Ok((header, payload, signature))
}

fn decode_json(segment: &str) -> Result<Value, SdJwtError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| SdJwtError::HolderProofInvalid)?;
    serde_json::from_slice(&bytes).map_err(|_| SdJwtError::HolderProofInvalid)
}

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, SdJwtError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(SdJwtError::HolderProofInvalid)
}

fn required_i64(value: &Value, field: &str) -> Result<i64, SdJwtError> {
    value
        .get(field)
        .and_then(Value::as_i64)
        .ok_or(SdJwtError::HolderProofInvalid)
}

fn required_audience(value: &Value, expected: &str) -> Result<String, SdJwtError> {
    match value.get("aud") {
        Some(Value::String(aud)) if aud == expected => Ok(aud.clone()),
        Some(Value::Array(values)) => {
            let matched = values
                .iter()
                .filter_map(Value::as_str)
                .find(|aud| *aud == expected)
                .ok_or(SdJwtError::HolderProofInvalid)?;
            Ok(matched.to_string())
        }
        _ => Err(SdJwtError::HolderProofInvalid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use registry_platform_crypto::{
        sign as sign_with_private_jwk, LocalJwkSigner, SigningAlgorithm, SigningError,
        SigningProvider,
    };
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const RAW_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.test#key-1"}"#;
    const HOLDER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:jwk:holder#key-1"}"#;

    #[test]
    fn sd_jwt_issuer_debug_never_exposes_private_scalar() {
        let issuer =
            SdJwtIssuer::from_jwk(PrivateJwk::parse(RAW_JWK).expect("jwk")).expect("issuer builds");

        let debug = format!("{issuer:?}");

        assert!(
            !debug.contains("2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw"),
            "debug must not expose the private scalar"
        );
        assert!(debug.contains("SdJwtIssuer"));
    }

    #[tokio::test]
    async fn sd_jwt_issuance_writes_vct_cnf_jwk_cnf_kid_and_provider_header_kid() {
        let issuer =
            SdJwtIssuer::from_jwk(PrivateJwk::parse(RAW_JWK).expect("jwk")).expect("issuer builds");
        let holder = PrivateJwk::parse(HOLDER_JWK).expect("holder");
        let signed = issuer
            .issue(SdJwtIssuanceInput {
                iss: "did:web:issuer.test".to_string(),
                sub_ref: "did:example:subject".to_string(),
                iat: 1_700_000_000,
                exp: 1_700_000_600,
                vct: "https://vct.example/test".to_string(),
                cnf: Some(HolderConfirmation {
                    jwk: holder.public(),
                    kid: Some("did:jwk:holder#key-1".to_string()),
                }),
                disclosures: vec![Disclosure {
                    name: "claim-a".to_string(),
                    value: json!({"ok": true}),
                }],
            })
            .await
            .expect("issues");

        assert_eq!(signed.credential_id, signed.jti);
        let header = jwt_header(&signed.jwt);
        let payload = jwt_payload(&signed.jwt);
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["typ"], "dc+sd-jwt");
        assert_eq!(header["kid"], "did:web:issuer.test#key-1");
        assert_eq!(payload["vct"], "https://vct.example/test");
        assert_eq!(payload["jti"], signed.credential_id);
        assert_eq!(payload["id"], signed.credential_id);
        assert_eq!(payload["cnf"]["kid"], "did:jwk:holder#key-1");
        assert_eq!(
            payload["cnf"]["jwk"]["x"],
            "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc"
        );
        assert!(payload["cnf"]["jwk"].get("d").is_none());
    }

    #[tokio::test]
    async fn sd_jwt_issuance_omits_cnf_when_unbound() {
        let issuer =
            SdJwtIssuer::from_jwk(PrivateJwk::parse(RAW_JWK).expect("jwk")).expect("issuer builds");
        let signed = issuer.issue(issue_input(None)).await.expect("issues");

        assert!(jwt_payload(&signed.jwt).get("cnf").is_none());
    }

    #[tokio::test]
    async fn issued_sd_digests_are_sorted_by_digest() {
        let issuer =
            SdJwtIssuer::from_jwk(PrivateJwk::parse(RAW_JWK).expect("jwk")).expect("issuer builds");
        let signed = issuer
            .issue(SdJwtIssuanceInput {
                disclosures: vec![
                    Disclosure {
                        name: "third".to_string(),
                        value: json!(3),
                    },
                    Disclosure {
                        name: "first".to_string(),
                        value: json!(1),
                    },
                    Disclosure {
                        name: "second".to_string(),
                        value: json!(2),
                    },
                ],
                ..issue_input(None)
            })
            .await
            .expect("issues");
        let payload = jwt_payload(&signed.jwt);
        let sd = payload["_sd"]
            .as_array()
            .expect("_sd array")
            .iter()
            .map(|value| value.as_str().expect("digest").to_string())
            .collect::<Vec<_>>();
        let mut disclosure_digests = signed
            .jwt
            .split('~')
            .skip(1)
            .filter(|disclosure| !disclosure.is_empty())
            .map(|disclosure| URL_SAFE_NO_PAD.encode(Sha256::digest(disclosure.as_bytes())))
            .collect::<Vec<_>>();
        disclosure_digests.sort_unstable();

        assert_eq!(sd, disclosure_digests);
    }

    #[tokio::test]
    async fn sd_jwt_issuer_accepts_provider_without_private_jwk_at_call_site() {
        let private = PrivateJwk::parse(RAW_JWK).expect("jwk");
        let provider = Arc::new(CountingProvider {
            signer: LocalJwkSigner::new(private).expect("local signer builds"),
            calls: AtomicUsize::new(0),
        });
        let issuer = SdJwtIssuer::from_signing_provider(provider.clone());

        let signed = issuer.issue(issue_input(None)).await.expect("issues");
        let header = jwt_header(&signed.jwt);

        assert_eq!(header["kid"], provider.key_id());
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn sd_jwt_issuer_maps_provider_signing_failures_without_payload_leakage() {
        let issuer = SdJwtIssuer::from_signing_provider(Arc::new(FailingProvider));

        let err = issuer
            .issue(SdJwtIssuanceInput {
                sub_ref: "sensitive-subject".to_string(),
                ..issue_input(None)
            })
            .await
            .expect_err("provider failure propagates");
        let rendered = err.to_string();

        assert!(matches!(err, SdJwtError::Signing(_)));
        assert!(!rendered.contains("sensitive-subject"));
        assert!(!rendered.contains("signature"));
    }

    #[tokio::test]
    async fn sd_jwt_issuer_rejects_provider_with_empty_key_id() {
        let issuer = SdJwtIssuer::from_signing_provider(Arc::new(EmptyKidProvider));

        let err = issuer
            .issue(issue_input(None))
            .await
            .expect_err("empty provider kid rejects");

        assert!(matches!(
            err,
            SdJwtError::Signing(SigningError::MissingKeyId)
        ));
    }

    #[tokio::test]
    async fn sd_jwt_issuer_rejects_provider_signature_that_does_not_verify() {
        let issuer = SdJwtIssuer::from_signing_provider(Arc::new(BadSignatureProvider));

        let err = issuer
            .issue(issue_input(None))
            .await
            .expect_err("bad provider signature rejects");

        assert!(matches!(
            err,
            SdJwtError::Signing(SigningError::Crypto(
                registry_platform_crypto::CryptoError::InvalidSignature
            ))
        ));
    }

    #[tokio::test]
    async fn sd_jwt_issuer_rejects_provider_public_jwk_kid_mismatch() {
        let issuer = SdJwtIssuer::from_signing_provider(Arc::new(MismatchedPublicKidProvider));

        let err = issuer
            .issue(issue_input(None))
            .await
            .expect_err("public jwk kid mismatch rejects");

        assert!(matches!(
            err,
            SdJwtError::Signing(SigningError::KeyIdMismatch)
        ));
    }

    #[test]
    fn holder_proof_returns_jti_for_caller_replay_detection() {
        let holder = PrivateJwk::parse(HOLDER_JWK).expect("holder");
        let now = 1_700_000_000;
        let proof = sign_holder_proof(&holder, proof_payload(now, "proof-jti-1"));

        let claim_set = claim_set();
        let bindings = bindings(&claim_set);
        let claims = validate_holder_proof(&proof, &holder.public(), &bindings, &policy(), now)
            .expect("proof validates");

        assert_eq!(claims.jti, "proof-jti-1");
    }

    #[test]
    fn holder_proof_rejects_when_credential_id_substituted_for_proof_jti() {
        let holder = PrivateJwk::parse(HOLDER_JWK).expect("holder");
        let now = 1_700_000_000;
        let proof = sign_holder_proof(
            &holder,
            proof_payload(now, "urn:ulid:01HX0000000000000000000000"),
        );

        let claim_set = claim_set();
        let bindings = bindings(&claim_set);
        validate_holder_proof(&proof, &holder.public(), &bindings, &policy(), now)
            .expect_err("credential id must not be accepted as holder-proof jti");
    }

    #[test]
    fn holder_proof_enforces_audience_lifetime_and_bindings() {
        let holder = PrivateJwk::parse(HOLDER_JWK).expect("holder");
        let now = 1_700_000_000;

        let claim_set = claim_set();
        let bindings = bindings(&claim_set);
        validate_holder_proof(
            &sign_holder_proof(&holder, proof_payload(now, "proof-jti-1")),
            &holder.public(),
            &bindings,
            &policy(),
            now,
        )
        .expect("baseline proof validates");

        let mut wrong_aud_payload = proof_payload(now, "proof-jti-2");
        wrong_aud_payload["aud"] = json!("wrong");
        let wrong_aud = sign_holder_proof(&holder, wrong_aud_payload);
        validate_holder_proof(&wrong_aud, &holder.public(), &bindings, &policy(), now)
            .expect_err("audience mismatch rejects");

        let mut exp_equal_iat_payload = proof_payload(now, "proof-jti-3");
        exp_equal_iat_payload["exp"] = json!(now);
        let exp_equal_iat = sign_holder_proof(&holder, exp_equal_iat_payload);
        validate_holder_proof(&exp_equal_iat, &holder.public(), &bindings, &policy(), now)
            .expect_err("exp == iat rejects");

        let mut over_ceiling_payload = proof_payload(now, "proof-jti-4");
        over_ceiling_payload["exp"] = json!(now + 301);
        let over_ceiling = sign_holder_proof(&holder, over_ceiling_payload);
        validate_holder_proof(&over_ceiling, &holder.public(), &bindings, &policy(), now)
            .expect_err("over max lifetime rejects");

        let mut wrong_bindings = proof_bindings(&claim_set);
        wrong_bindings.credential_profile = "profile-b";
        validate_holder_proof(
            &sign_holder_proof(&holder, proof_payload(now, "proof-jti-5")),
            &holder.public(),
            &wrong_bindings,
            &policy(),
            now,
        )
        .expect_err("binding mismatch rejects");
    }

    #[test]
    fn validate_holder_proof_rejects_structurally_malformed_compact_jwt() {
        let holder = PrivateJwk::parse(HOLDER_JWK).expect("holder");
        let claim_set = claim_set();
        let bindings = bindings(&claim_set);
        let now = 1_700_000_000;

        for malformed in ["notajwt", "a.b", "a.b.c.d", "!!.!!.!!"] {
            assert!(
                matches!(
                    validate_holder_proof(malformed, &holder.public(), &bindings, &policy(), now),
                    Err(SdJwtError::HolderProofInvalid)
                ),
                "input {:?} must return HolderProofInvalid",
                malformed
            );
        }
    }

    #[test]
    fn holder_proof_rejects_wrong_type_and_dangerous_headers() {
        let holder = PrivateJwk::parse(HOLDER_JWK).expect("holder");
        let now = 1_700_000_000;
        let claim_set = claim_set();
        let bindings = bindings(&claim_set);

        let wrong_typ = sign_jwt_with_private(
            json!({"alg": "EdDSA", "typ": "JWT", "kid": "did:jwk:holder#key-1"}),
            proof_payload(now, "proof-jti-6"),
            &holder,
        )
        .expect("proof signs");
        validate_holder_proof(&wrong_typ, &holder.public(), &bindings, &policy(), now)
            .expect_err("holder proof typ must be kb+jwt");

        for forbidden in ["crit", "jku", "jwk", "x5u", "x5c"] {
            let mut header = json!({
                "alg": "EdDSA",
                "typ": "kb+jwt",
                "kid": "did:jwk:holder#key-1"
            });
            header[forbidden] = json!("forbidden");
            let proof = sign_jwt_with_private(header, proof_payload(now, "proof-jti-7"), &holder)
                .expect("proof signs");
            validate_holder_proof(&proof, &holder.public(), &bindings, &policy(), now)
                .expect_err("dangerous holder-proof header is rejected");
        }
    }

    fn issue_input(cnf: Option<HolderConfirmation>) -> SdJwtIssuanceInput {
        SdJwtIssuanceInput {
            iss: "did:web:issuer.test".to_string(),
            sub_ref: "did:example:subject".to_string(),
            iat: 1_700_000_000,
            exp: 1_700_000_600,
            vct: "https://vct.example/test".to_string(),
            cnf,
            disclosures: Vec::new(),
        }
    }

    #[derive(Debug)]
    struct CountingProvider {
        signer: LocalJwkSigner,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl SigningProvider for CountingProvider {
        fn algorithm(&self) -> SigningAlgorithm {
            self.signer.algorithm()
        }

        fn key_id(&self) -> &str {
            self.signer.key_id()
        }

        fn public_jwk(&self) -> PublicJwk {
            self.signer.public_jwk()
        }

        async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SigningError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.signer.sign(payload).await
        }
    }

    #[derive(Debug)]
    struct FailingProvider;

    #[async_trait]
    impl SigningProvider for FailingProvider {
        fn algorithm(&self) -> SigningAlgorithm {
            SigningAlgorithm::EdDsa
        }

        fn key_id(&self) -> &str {
            "did:web:issuer.test#failing"
        }

        fn public_jwk(&self) -> PublicJwk {
            let mut public = PrivateJwk::parse(RAW_JWK).expect("jwk").public();
            public.kid = Some(self.key_id().to_string());
            public
        }

        async fn sign(&self, _payload: &[u8]) -> Result<Vec<u8>, SigningError> {
            Err(SigningError::external(
                "external signer unavailable; payload redacted",
            ))
        }
    }

    #[derive(Debug)]
    struct EmptyKidProvider;

    #[async_trait]
    impl SigningProvider for EmptyKidProvider {
        fn algorithm(&self) -> SigningAlgorithm {
            SigningAlgorithm::EdDsa
        }

        fn key_id(&self) -> &str {
            " "
        }

        fn public_jwk(&self) -> PublicJwk {
            let mut public = PrivateJwk::parse(RAW_JWK).expect("jwk").public();
            public.kid = Some(self.key_id().to_string());
            public
        }

        async fn sign(&self, _payload: &[u8]) -> Result<Vec<u8>, SigningError> {
            Ok(vec![0; 64])
        }
    }

    #[derive(Debug)]
    struct BadSignatureProvider;

    #[async_trait]
    impl SigningProvider for BadSignatureProvider {
        fn algorithm(&self) -> SigningAlgorithm {
            SigningAlgorithm::EdDsa
        }

        fn key_id(&self) -> &str {
            "did:web:issuer.test#bad-signature"
        }

        fn public_jwk(&self) -> PublicJwk {
            let mut public = PrivateJwk::parse(RAW_JWK).expect("jwk").public();
            public.kid = Some(self.key_id().to_string());
            public
        }

        async fn sign(&self, _payload: &[u8]) -> Result<Vec<u8>, SigningError> {
            Ok(vec![0; 64])
        }
    }

    #[derive(Debug)]
    struct MismatchedPublicKidProvider;

    #[async_trait]
    impl SigningProvider for MismatchedPublicKidProvider {
        fn algorithm(&self) -> SigningAlgorithm {
            SigningAlgorithm::EdDsa
        }

        fn key_id(&self) -> &str {
            "did:web:issuer.test#key-1"
        }

        fn public_jwk(&self) -> PublicJwk {
            let mut public = PrivateJwk::parse(RAW_JWK).expect("jwk").public();
            public.kid = Some("did:web:issuer.test#old".to_string());
            public
        }

        async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SigningError> {
            LocalJwkSigner::new(PrivateJwk::parse(RAW_JWK).expect("jwk"))
                .expect("signer")
                .sign(payload)
                .await
        }
    }

    fn claim_set() -> Vec<String> {
        vec!["claim-a".to_string()]
    }

    fn bindings<'a>(claim_set: &'a [String]) -> HolderProofBindings<'a> {
        proof_bindings(claim_set)
    }

    fn proof_bindings<'a>(claim_set: &'a [String]) -> HolderProofBindings<'a> {
        HolderProofBindings {
            expected_sub: "did:jwk:holder",
            evaluation_id: "eval-1",
            credential_profile: "profile-a",
            disclosure_hash: b"redacted-disclosure-hash",
            claim_set,
        }
    }

    fn policy() -> HolderProofPolicy {
        HolderProofPolicy {
            audience: "registry-witness".to_string(),
            max_lifetime: Duration::from_secs(300),
        }
    }

    fn proof_payload(now: i64, jti: &str) -> Value {
        json!({
            "sub": "did:jwk:holder",
            "aud": "registry-witness",
            "iat": now,
            "exp": now + 60,
            "jti": jti,
            "evaluation_id": "eval-1",
            "credential_profile": "profile-a",
            "disclosure": URL_SAFE_NO_PAD.encode(b"redacted-disclosure-hash"),
            "claims": ["claim-a"],
        })
    }

    fn sign_holder_proof(holder: &PrivateJwk, payload: Value) -> String {
        sign_jwt_with_private(
            json!({"alg": "EdDSA", "typ": "kb+jwt", "kid": "did:jwk:holder#key-1"}),
            payload,
            holder,
        )
        .expect("proof signs")
    }

    fn sign_jwt_with_private(
        header: Value,
        payload: Value,
        jwk: &PrivateJwk,
    ) -> Result<String, SdJwtError> {
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = sign_with_private_jwk(signing_input.as_bytes(), jwk)?;
        Ok(format!(
            "{}.{}",
            signing_input,
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }

    fn jwt_header(sd_jwt: &str) -> Value {
        jwt_part(sd_jwt, 0)
    }

    fn jwt_payload(sd_jwt: &str) -> Value {
        jwt_part(sd_jwt, 1)
    }

    fn jwt_part(sd_jwt: &str, index: usize) -> Value {
        let compact = sd_jwt.split('~').next().expect("compact jwt");
        let segment = compact.split('.').nth(index).expect("jwt segment");
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segment).expect("base64url")).expect("json")
    }
}
