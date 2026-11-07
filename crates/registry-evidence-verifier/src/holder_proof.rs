//! The proof of possession for Evidence's holder-bound SD-JWT VC profile.
//!
//! A holder proves it controls the key an issued credential confirms by signing
//! a short-lived EdDSA JWT that names the subject, the evaluation, the
//! credential profile, the disclosed claim set and a hash of the disclosure.
//! The proof is checked against the holder key the issuer signed into the
//! credential's `cnf`, never against a key the proof itself carries.
//!
//! This is Evidence's own profile, not the RFC 9901 key-binding JWT. The
//! generic key-binding check lives in `registry-platform-sdjwt`.

use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_crypto::jws::{parse_compact_jws, CompactJws, JwsLimits};
use registry_platform_crypto::{PublicJwk, SigningAlgorithm};
use registry_platform_sdjwt::HolderConfirmation;
use serde_json::{json, Value};
use thiserror::Error;

const HOLDER_PROOF_ALLOWED_ALGORITHM: SigningAlgorithm = SigningAlgorithm::EdDsa;
const HOLDER_PROOF_TYP: &str = "kb+jwt";

/// Header parameters through which a token nominates its own verification key
/// or its own processing rules. A holder proof never honours one.
const SELF_NOMINATING_HEADER_PARAMETERS: [&str; 5] = ["crit", "jku", "jwk", "x5u", "x5c"];

/// Seconds an `iat` may lie before the verification instant.
const MAXIMUM_PROOF_AGE_SECONDS: i64 = 120;
/// Seconds an `iat` may lie after the verification instant.
const MAXIMUM_PROOF_FUTURE_SKEW_SECONDS: i64 = 30;

/// Why a holder proof was refused. It never carries the proof, a claim, or a
/// key, so it is safe to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum HolderProofError {
    #[error("holder proof is invalid")]
    Invalid,
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

/// Validate a holder proof against a holder key.
pub fn validate_holder_proof(
    proof_jwt: &str,
    holder_jwk: &PublicJwk,
    bindings: &HolderProofBindings<'_>,
    policy: &HolderProofPolicy,
    now: i64,
) -> Result<HolderProofClaims, HolderProofError> {
    let jws = parse_proof(proof_jwt)?;
    validate_parsed_proof(&jws, holder_jwk, bindings, policy, now)
}

/// Validate a holder proof against the holder confirmation embedded in the
/// issuer-signed credential.
///
/// This is the preferred entry point for SD-JWT VC presentations. It prevents
/// callers from accidentally trusting a holder key that did not come from the
/// credential's `cnf.jwk`, and when `cnf.kid` is present it requires the holder
/// proof header to carry that exact `kid`.
pub fn validate_holder_proof_for_confirmation(
    proof_jwt: &str,
    confirmation: &HolderConfirmation,
    bindings: &HolderProofBindings<'_>,
    policy: &HolderProofPolicy,
    now: i64,
) -> Result<HolderProofClaims, HolderProofError> {
    let jws = parse_proof(proof_jwt)?;
    if let Some(expected_kid) = confirmation.kid.as_deref() {
        if jws.header().get("kid").and_then(Value::as_str) != Some(expected_kid) {
            return Err(HolderProofError::Invalid);
        }
    }
    validate_parsed_proof(&jws, &confirmation.jwk, bindings, policy, now)
}

fn parse_proof(proof_jwt: &str) -> Result<CompactJws<'_>, HolderProofError> {
    parse_compact_jws(proof_jwt, &JwsLimits::default()).map_err(|_| HolderProofError::Invalid)
}

fn validate_parsed_proof(
    jws: &CompactJws<'_>,
    holder_jwk: &PublicJwk,
    bindings: &HolderProofBindings<'_>,
    policy: &HolderProofPolicy,
    now: i64,
) -> Result<HolderProofClaims, HolderProofError> {
    let header = jws.header();
    if header.get("typ").and_then(Value::as_str) != Some(HOLDER_PROOF_TYP) {
        return Err(HolderProofError::Invalid);
    }
    for forbidden in SELF_NOMINATING_HEADER_PARAMETERS {
        if header.contains_key(forbidden) {
            return Err(HolderProofError::Invalid);
        }
    }
    // `verify` requires the header algorithm to be EdDSA and to equal the
    // algorithm of the holder key.
    let payload = jws
        .verify(holder_jwk, &[HOLDER_PROOF_ALLOWED_ALGORITHM])
        .map_err(|_| HolderProofError::Invalid)?;

    let raw: Value = serde_json::from_slice(payload).map_err(|_| HolderProofError::Invalid)?;
    let sub = required_string(&raw, "sub")?;
    let aud = required_audience(&raw, &policy.audience)?;
    let iat = required_i64(&raw, "iat")?;
    let exp = required_i64(&raw, "exp")?;
    let jti = required_string(&raw, "jti")?;
    if jti.is_empty() || jti.starts_with("urn:ulid:") {
        return Err(HolderProofError::Invalid);
    }
    if sub != bindings.expected_sub {
        return Err(HolderProofError::Invalid);
    }
    if raw.get("evaluation_id").and_then(Value::as_str) != Some(bindings.evaluation_id) {
        return Err(HolderProofError::Invalid);
    }
    if raw.get("credential_profile").and_then(Value::as_str) != Some(bindings.credential_profile) {
        return Err(HolderProofError::Invalid);
    }
    let expected_disclosure = URL_SAFE_NO_PAD.encode(bindings.disclosure_hash);
    if raw.get("disclosure").and_then(Value::as_str) != Some(expected_disclosure.as_str()) {
        return Err(HolderProofError::Invalid);
    }
    if raw.get("claims") != Some(&json!(bindings.claim_set)) {
        return Err(HolderProofError::Invalid);
    }
    let max_lifetime = i64::try_from(policy.max_lifetime.as_secs()).unwrap_or(i64::MAX);
    if iat < now - MAXIMUM_PROOF_AGE_SECONDS
        || iat > now + MAXIMUM_PROOF_FUTURE_SKEW_SECONDS
        || exp <= iat
        || exp > iat + max_lifetime
        || exp <= now
    {
        return Err(HolderProofError::Invalid);
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

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, HolderProofError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(HolderProofError::Invalid)
}

fn required_i64(value: &Value, field: &str) -> Result<i64, HolderProofError> {
    value
        .get(field)
        .and_then(Value::as_i64)
        .ok_or(HolderProofError::Invalid)
}

fn required_audience(value: &Value, expected: &str) -> Result<String, HolderProofError> {
    match value.get("aud") {
        Some(Value::String(aud)) if aud == expected => Ok(aud.clone()),
        Some(Value::Array(values)) => {
            let matched = values
                .iter()
                .filter_map(Value::as_str)
                .find(|aud| *aud == expected)
                .ok_or(HolderProofError::Invalid)?;
            Ok(matched.to_string())
        }
        _ => Err(HolderProofError::Invalid),
    }
}

#[cfg(test)]
mod tests {
    use registry_platform_crypto::{sign, PrivateJwk};

    use super::*;

    const HOLDER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:jwk:holder#key-1"}"#;
    const P256_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"did:web:issuer.test#p256-key-1"}"#;

    fn claim_set() -> Vec<String> {
        vec!["claim-a".to_string()]
    }

    fn bindings(claim_set: &[String]) -> HolderProofBindings<'_> {
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
            audience: "registry-notary".to_string(),
            max_lifetime: Duration::from_secs(300),
        }
    }

    fn proof_payload(now: i64, jti: &str) -> Value {
        json!({
            "sub": "did:jwk:holder",
            "aud": "registry-notary",
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
    }

    fn sign_jwt_with_private(header: Value, payload: Value, jwk: &PrivateJwk) -> String {
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header"));
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload"));
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = sign(signing_input.as_bytes(), jwk).expect("proof signs");
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
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

        let mut wrong_bindings = bindings.clone();
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
    fn holder_proof_for_confirmation_enforces_cnf_jwk_and_kid() {
        let holder = PrivateJwk::parse(HOLDER_JWK).expect("holder");
        let other_holder = PrivateJwk::parse(
            r#"{"crv":"Ed25519","d":"f4QIxnAyRWzhuBOmNRgvBTE56mWePdsPL0mvCtl8Gys","x":"pv4e_hXHBLN27rcs6VDFV1ED0TiU8M3xy9vsuWFEsec","kty":"OKP","alg":"EdDSA","kid":"did:jwk:other#key-1"}"#,
        )
        .expect("other holder");
        let now = 1_700_000_000;
        let claim_set = claim_set();
        let bindings = bindings(&claim_set);
        let proof = sign_holder_proof(&holder, proof_payload(now, "proof-jti-confirmed"));
        let confirmation = HolderConfirmation {
            jwk: holder.public(),
            kid: Some("did:jwk:holder#key-1".to_string()),
        };

        validate_holder_proof_for_confirmation(&proof, &confirmation, &bindings, &policy(), now)
            .expect("cnf-bound proof validates");

        let wrong_confirmation = HolderConfirmation {
            jwk: other_holder.public(),
            kid: Some("did:jwk:holder#key-1".to_string()),
        };
        validate_holder_proof_for_confirmation(
            &proof,
            &wrong_confirmation,
            &bindings,
            &policy(),
            now,
        )
        .expect_err("wrong cnf.jwk rejects");

        let wrong_kid_confirmation = HolderConfirmation {
            jwk: holder.public(),
            kid: Some("did:jwk:holder#other".to_string()),
        };
        validate_holder_proof_for_confirmation(
            &proof,
            &wrong_kid_confirmation,
            &bindings,
            &policy(),
            now,
        )
        .expect_err("wrong cnf.kid rejects");
    }

    #[test]
    fn holder_proof_rejects_header_alg_that_does_not_match_resolved_key() {
        let holder = PrivateJwk::parse(P256_JWK).expect("p256 holder");
        let now = 1_700_000_000;
        let claim_set = claim_set();
        let bindings = bindings(&claim_set);
        let proof = sign_jwt_with_private(
            json!({"alg": "EdDSA", "typ": "kb+jwt", "kid": "did:jwk:holder#p256-key-1"}),
            proof_payload(now, "proof-jti-alg-confusion"),
            &holder,
        );
        let confirmation = HolderConfirmation {
            jwk: holder.public(),
            kid: Some("did:jwk:holder#p256-key-1".to_string()),
        };

        validate_holder_proof_for_confirmation(&proof, &confirmation, &bindings, &policy(), now)
            .expect_err("EdDSA header must not verify with an ES256 cnf key");
        validate_holder_proof(&proof, &holder.public(), &bindings, &policy(), now)
            .expect_err("EdDSA header must not verify with an ES256 resolved key");
    }

    #[test]
    fn holder_proof_rejects_correctly_signed_non_eddsa_proof_because_the_holder_proof_pin_is_eddsa_only(
    ) {
        let holder = PrivateJwk::parse(P256_JWK).expect("p256 holder");
        let now = 1_700_000_000;
        let claim_set = claim_set();
        let bindings = bindings(&claim_set);
        let proof = sign_jwt_with_private(
            json!({"alg": "ES256", "typ": "kb+jwt", "kid": "did:web:issuer.test#p256-key-1"}),
            proof_payload(now, "proof-jti-es256"),
            &holder,
        );

        validate_holder_proof(&proof, &holder.public(), &bindings, &policy(), now).expect_err(
            "HOLDER_PROOF_ALLOWED_ALGORITHM pins holder proofs to EdDSA even for a \
             correctly self-signed ES256 proof",
        );
    }

    #[test]
    fn validate_holder_proof_rejects_structurally_malformed_compact_jwt() {
        let holder = PrivateJwk::parse(HOLDER_JWK).expect("holder");
        let claim_set = claim_set();
        let bindings = bindings(&claim_set);
        let now = 1_700_000_000;

        for malformed in ["notajwt", "a.b", "a.b.c.d", "!!.!!.!!"] {
            assert_eq!(
                validate_holder_proof(malformed, &holder.public(), &bindings, &policy(), now),
                Err(HolderProofError::Invalid),
                "input {malformed:?} must return Invalid"
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
        );
        validate_holder_proof(&wrong_typ, &holder.public(), &bindings, &policy(), now)
            .expect_err("holder proof typ must be kb+jwt");

        for forbidden in ["crit", "jku", "jwk", "x5u", "x5c"] {
            let mut header = json!({
                "alg": "EdDSA",
                "typ": "kb+jwt",
                "kid": "did:jwk:holder#key-1"
            });
            header[forbidden] = json!("forbidden");
            let proof = sign_jwt_with_private(header, proof_payload(now, "proof-jti-7"), &holder);
            validate_holder_proof(&proof, &holder.public(), &bindings, &policy(), now)
                .expect_err("dangerous holder-proof header is rejected");
        }
    }
}
