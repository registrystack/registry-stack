// SPDX-License-Identifier: Apache-2.0
//! SD-JWT VC issuance and holder-proof validation helpers.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use registry_platform_crypto::{sign, verify, JwkError, PrivateJwk, PublicJwk};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use ulid::Ulid;

#[derive(Clone)]
pub struct SdJwtIssuer {
    jwk: Arc<PrivateJwk>,
}

impl fmt::Debug for SdJwtIssuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SdJwtIssuer")
            .field("alg", &"EdDSA")
            .field("kid", &self.jwk.kid)
            .finish_non_exhaustive()
    }
}

impl SdJwtIssuer {
    pub fn from_jwk(jwk: PrivateJwk) -> Result<Self, SdJwtError> {
        jwk.algorithm().map_err(map_jwk_algorithm_error)?;
        Ok(Self { jwk: Arc::new(jwk) })
    }

    pub fn issue(&self, input: SdJwtIssuanceInput) -> Result<SignedSdJwt, SdJwtError> {
        input.validate()?;
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
            "alg": "EdDSA",
            "typ": "dc+sd-jwt",
            "kid": input.signing_kid,
        });
        let jwt = sign_jwt(header, Value::Object(payload), &self.jwk)?;
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
    pub signing_kid: String,
    pub cnf: Option<HolderConfirmation>,
    pub disclosures: Vec<Disclosure>,
}

impl SdJwtIssuanceInput {
    fn validate(&self) -> Result<(), SdJwtError> {
        if self.iss.is_empty()
            || self.sub_ref.is_empty()
            || self.vct.is_empty()
            || self.signing_kid.is_empty()
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
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("randomness failed: {0}")]
    Random(#[from] getrandom::Error),
    #[error("holder proof is invalid")]
    HolderProofInvalid,
}

fn map_jwk_algorithm_error(err: JwkError) -> SdJwtError {
    match err {
        JwkError::UnsupportedAlgorithm => SdJwtError::UnsupportedAlgorithm,
        err => SdJwtError::InvalidKey(err),
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

/// Internal JWS serialiser. Runs synchronously on the calling thread; the
/// Ed25519 sign cost is inherited from `registry_platform_crypto::sign`
/// (~15 µs/op on Apple M5 Max; see its doc comment for details).
fn sign_jwt(header: Value, payload: Value, jwk: &PrivateJwk) -> Result<String, SdJwtError> {
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = sign(signing_input.as_bytes(), jwk)?;
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
    use serde_json::json;

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

    #[test]
    fn sd_jwt_issuance_writes_vct_cnf_jwk_cnf_kid_and_header_kid() {
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
                signing_kid: "did:web:issuer.test#key-1".to_string(),
                cnf: Some(HolderConfirmation {
                    jwk: holder.public(),
                    kid: Some("did:jwk:holder#key-1".to_string()),
                }),
                disclosures: vec![Disclosure {
                    name: "claim-a".to_string(),
                    value: json!({"ok": true}),
                }],
            })
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

    #[test]
    fn sd_jwt_issuance_omits_cnf_when_unbound() {
        let issuer =
            SdJwtIssuer::from_jwk(PrivateJwk::parse(RAW_JWK).expect("jwk")).expect("issuer builds");
        let signed = issuer.issue(issue_input(None)).expect("issues");

        assert!(jwt_payload(&signed.jwt).get("cnf").is_none());
    }

    #[test]
    fn issued_sd_digests_are_sorted_by_digest() {
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

        let wrong_typ = sign_jwt(
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
            let proof =
                sign_jwt(header, proof_payload(now, "proof-jti-7"), &holder).expect("proof signs");
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
            signing_kid: "did:web:issuer.test#key-1".to_string(),
            cnf,
            disclosures: Vec::new(),
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
        sign_jwt(
            json!({"alg": "EdDSA", "typ": "kb+jwt", "kid": "did:jwk:holder#key-1"}),
            payload,
            holder,
        )
        .expect("proof signs")
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
