// SPDX-License-Identifier: Apache-2.0
//! Explicit SD-JWT VC verification helpers.

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use registry_notary_core::SD_JWT_VC_JWT_TYP;
use registry_platform_crypto::{verify, PublicJwk, SigningAlgorithm};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;

/// Caller-owned policy for explicit SD-JWT VC verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyOptions {
    /// Issuer identifier expected in the `iss` claim.
    pub expected_issuer: String,
    /// Accepted JWS algorithms. Defaults to `EdDSA`.
    pub accepted_algorithms: BTreeSet<String>,
    /// Expected SD-JWT VC `vct`, when the caller wants a concrete profile.
    pub expected_vct: Option<String>,
    /// Allowed skew for `exp`, `nbf`, and future `iat` checks.
    pub clock_skew: Duration,
    /// Holder-binding policy for the embedded `cnf` confirmation.
    pub holder_binding: HolderBindingPolicy,
    /// Expected key-binding JWT audience for verifier-controlled challenges.
    pub expected_key_binding_audience: Option<String>,
    /// Expected key-binding JWT nonce for verifier-controlled challenges.
    pub expected_key_binding_nonce: Option<String>,
    /// Test hook for deterministic time checks. Production callers should leave
    /// this unset.
    pub now: Option<OffsetDateTime>,
}

impl VerifyOptions {
    #[must_use]
    pub fn new(expected_issuer: impl Into<String>) -> Self {
        Self {
            expected_issuer: expected_issuer.into(),
            accepted_algorithms: BTreeSet::from(["EdDSA".to_string()]),
            expected_vct: None,
            clock_skew: Duration::from_secs(60),
            holder_binding: HolderBindingPolicy::NotRequired,
            expected_key_binding_audience: None,
            expected_key_binding_nonce: None,
            now: None,
        }
    }

    #[must_use]
    pub fn expected_vct(mut self, expected_vct: impl Into<String>) -> Self {
        self.expected_vct = Some(expected_vct.into());
        self
    }

    #[must_use]
    pub fn accepted_algorithms(
        mut self,
        algorithms: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.accepted_algorithms = algorithms.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn clock_skew(mut self, clock_skew: Duration) -> Self {
        self.clock_skew = clock_skew;
        self
    }

    #[must_use]
    pub fn holder_binding(mut self, holder_binding: HolderBindingPolicy) -> Self {
        self.holder_binding = holder_binding;
        self
    }

    #[must_use]
    pub fn key_binding_challenge(
        mut self,
        expected_audience: impl Into<String>,
        expected_nonce: impl Into<String>,
    ) -> Self {
        self.expected_key_binding_audience = Some(expected_audience.into());
        self.expected_key_binding_nonce = Some(expected_nonce.into());
        self
    }

    #[must_use]
    pub fn now(mut self, now: OffsetDateTime) -> Self {
        self.now = Some(now);
        self
    }
}

/// Holder-binding expectation for the credential confirmation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HolderBindingPolicy {
    /// Do not require a holder confirmation.
    NotRequired,
    /// Require `cnf.jwk`, and validate that it is a public JWK.
    Required,
    /// Require `cnf.jwk` and this exact `cnf.kid`.
    RequiredKid(String),
}

/// Verified credential metadata returned after successful verification.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedCredential {
    pub issuer: String,
    pub subject: Option<String>,
    pub credential_id: Option<String>,
    pub vct: String,
    pub key_id: String,
    pub algorithm: String,
    pub expires_at: i64,
    pub not_before: Option<i64>,
    pub issued_at: i64,
    pub disclosure_count: usize,
    pub holder_key_id: Option<String>,
}

impl fmt::Debug for VerifiedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedCredential")
            .field("issuer", &self.issuer)
            .field("subject", &self.subject.as_ref().map(|_| "<redacted>"))
            .field("credential_id", &self.credential_id)
            .field("vct", &self.vct)
            .field("key_id", &self.key_id)
            .field("algorithm", &self.algorithm)
            .field("expires_at", &self.expires_at)
            .field("not_before", &self.not_before)
            .field("issued_at", &self.issued_at)
            .field("disclosure_count", &self.disclosure_count)
            .field("holder_key_id", &self.holder_key_id)
            .finish()
    }
}

/// Redacted verifier error with a stable policy code.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerificationError {
    #[error("SD-JWT VC is malformed")]
    Malformed { code: &'static str },
    #[error("SD-JWT VC header uses an unsupported type")]
    HeaderType { code: &'static str },
    #[error("SD-JWT VC header contains an untrusted key reference")]
    UntrustedKeyReference { code: &'static str },
    #[error("SD-JWT VC algorithm is not accepted")]
    AlgorithmDisallowed { code: &'static str },
    #[error("SD-JWT VC signing key metadata does not match the header")]
    AlgorithmKeyMismatch { code: &'static str },
    #[error("SD-JWT VC signing key is missing")]
    MissingKeyId { code: &'static str },
    #[error("SD-JWT VC signing key is unknown")]
    UnknownKey { code: &'static str },
    #[error("SD-JWT VC signature is invalid")]
    InvalidSignature { code: &'static str },
    #[error("SD-JWT VC issuer does not match policy")]
    IssuerMismatch { code: &'static str },
    #[error("SD-JWT VC credential profile does not match policy")]
    VctMismatch { code: &'static str },
    #[error("SD-JWT VC time claim is invalid")]
    TimeClaim { code: &'static str },
    #[error("SD-JWT VC disclosure digest does not match")]
    DisclosureDigestMismatch { code: &'static str },
    #[error("SD-JWT VC holder binding does not match policy")]
    HolderBinding { code: &'static str },
    #[error("issuer JWKS could not be loaded")]
    JwksUnavailable { code: &'static str },
}

impl VerificationError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Malformed { code }
            | Self::HeaderType { code }
            | Self::UntrustedKeyReference { code }
            | Self::AlgorithmDisallowed { code }
            | Self::AlgorithmKeyMismatch { code }
            | Self::MissingKeyId { code }
            | Self::UnknownKey { code }
            | Self::InvalidSignature { code }
            | Self::IssuerMismatch { code }
            | Self::VctMismatch { code }
            | Self::TimeClaim { code }
            | Self::DisclosureDigestMismatch { code }
            | Self::HolderBinding { code }
            | Self::JwksUnavailable { code } => code,
        }
    }

    #[must_use]
    pub const fn is_unknown_key(&self) -> bool {
        matches!(self, Self::UnknownKey { .. })
    }

    pub(crate) const fn jwks_unavailable() -> Self {
        Self::JwksUnavailable {
            code: "jwks.unavailable",
        }
    }
}

/// Verify one SD-JWT VC compact credential against caller-supplied trusted JWKS.
pub fn verify_sd_jwt_vc(
    compact: &str,
    jwks: &Value,
    options: &VerifyOptions,
) -> Result<VerifiedCredential, VerificationError> {
    let parsed = ParsedSdJwt::parse(compact)?;
    let header = decode_segment(parsed.header_b64)?;
    let payload = decode_segment(parsed.payload_b64)?;

    reject_untrusted_header_references(&header)?;
    let alg = required_string(&header, "alg")?;
    if !options.accepted_algorithms.contains(alg) {
        return Err(VerificationError::AlgorithmDisallowed {
            code: "algorithm.disallowed",
        });
    }
    if header.get("typ").and_then(Value::as_str) != Some(SD_JWT_VC_JWT_TYP) {
        return Err(VerificationError::HeaderType {
            code: "header.typ_mismatch",
        });
    }
    let kid = required_string(&header, "kid").map_err(|_| VerificationError::MissingKeyId {
        code: "key.missing",
    })?;
    let jwk = find_jwk(jwks, kid)?;
    if jwk_alg(&jwk) != Some(alg) || jwk.alg.as_deref().is_some_and(|jwk_alg| jwk_alg != alg) {
        return Err(VerificationError::AlgorithmKeyMismatch {
            code: "algorithm.key_mismatch",
        });
    }
    let signature =
        URL_SAFE_NO_PAD
            .decode(parsed.signature_b64)
            .map_err(|_| VerificationError::Malformed {
                code: "token.malformed",
            })?;
    verify(parsed.signing_input().as_bytes(), &signature, &jwk).map_err(|_| {
        VerificationError::InvalidSignature {
            code: "signature.invalid",
        }
    })?;

    verify_claims(&payload, &parsed, options, alg, kid)
}

fn verify_claims(
    payload: &Value,
    parsed: &ParsedSdJwt<'_>,
    options: &VerifyOptions,
    alg: &str,
    kid: &str,
) -> Result<VerifiedCredential, VerificationError> {
    let issuer = required_string(payload, "iss")?;
    if issuer != options.expected_issuer {
        return Err(VerificationError::IssuerMismatch {
            code: "claim.issuer_mismatch",
        });
    }
    let vct = required_string(payload, "vct")?;
    if options
        .expected_vct
        .as_deref()
        .is_some_and(|expected| expected != vct)
    {
        return Err(VerificationError::VctMismatch {
            code: "claim.vct_mismatch",
        });
    }

    let now = options
        .now
        .unwrap_or_else(OffsetDateTime::now_utc)
        .unix_timestamp();
    let skew = i64::try_from(options.clock_skew.as_secs()).unwrap_or(i64::MAX);
    let exp = required_i64(payload, "exp")?;
    let iat = required_i64(payload, "iat")?;
    let nbf = optional_i64(payload, "nbf")?;
    if exp <= now.saturating_sub(skew) || iat > now.saturating_add(skew) {
        return Err(VerificationError::TimeClaim {
            code: "claim.time_invalid",
        });
    }
    if let Some(nbf) = nbf {
        if nbf > now.saturating_add(skew) {
            return Err(VerificationError::TimeClaim {
                code: "claim.time_invalid",
            });
        }
    }

    verify_disclosures(payload, &parsed.disclosures)?;
    let holder_key_id = verify_holder_binding(HolderBindingContext {
        payload,
        policy: &options.holder_binding,
        key_binding_jwt: parsed.key_binding_jwt,
        sd_hash_input: parsed.sd_hash_input,
        expected_audience: options.expected_key_binding_audience.as_deref(),
        expected_nonce: options.expected_key_binding_nonce.as_deref(),
        now,
        skew,
    })?;
    Ok(VerifiedCredential {
        issuer: issuer.to_string(),
        subject: payload
            .get("sub")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        credential_id: payload
            .get("jti")
            .or_else(|| payload.get("id"))
            .and_then(Value::as_str)
            .map(ToString::to_string),
        vct: vct.to_string(),
        key_id: kid.to_string(),
        algorithm: alg.to_string(),
        expires_at: exp,
        not_before: nbf,
        issued_at: iat,
        disclosure_count: parsed.disclosures.len(),
        holder_key_id,
    })
}

fn verify_disclosures(payload: &Value, disclosures: &[&str]) -> Result<(), VerificationError> {
    if disclosures.is_empty() && payload.get("_sd").is_none() {
        return Ok(());
    }
    if payload.get("_sd_alg").and_then(Value::as_str) != Some("sha-256") {
        return Err(VerificationError::DisclosureDigestMismatch {
            code: "disclosure.digest_mismatch",
        });
    }
    let expected = payload
        .get("_sd")
        .and_then(Value::as_array)
        .ok_or(VerificationError::DisclosureDigestMismatch {
            code: "disclosure.digest_mismatch",
        })?
        .iter()
        .map(|digest| {
            digest.as_str().map(ToString::to_string).ok_or(
                VerificationError::DisclosureDigestMismatch {
                    code: "disclosure.digest_mismatch",
                },
            )
        })
        .collect::<Result<BTreeSet<_>, _>>()?;

    let mut actual = BTreeSet::new();
    for disclosure in disclosures {
        let decoded = URL_SAFE_NO_PAD.decode(disclosure).map_err(|_| {
            VerificationError::DisclosureDigestMismatch {
                code: "disclosure.digest_mismatch",
            }
        })?;
        let value: Value = serde_json::from_slice(&decoded).map_err(|_| {
            VerificationError::DisclosureDigestMismatch {
                code: "disclosure.digest_mismatch",
            }
        })?;
        if value.as_array().is_none_or(|items| items.len() < 3) {
            return Err(VerificationError::DisclosureDigestMismatch {
                code: "disclosure.digest_mismatch",
            });
        }
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(disclosure.as_bytes()));
        if !expected.contains(&digest) || !actual.insert(digest) {
            return Err(VerificationError::DisclosureDigestMismatch {
                code: "disclosure.digest_mismatch",
            });
        }
    }
    Ok(())
}

struct HolderBindingContext<'a> {
    payload: &'a Value,
    policy: &'a HolderBindingPolicy,
    key_binding_jwt: Option<&'a str>,
    sd_hash_input: &'a str,
    expected_audience: Option<&'a str>,
    expected_nonce: Option<&'a str>,
    now: i64,
    skew: i64,
}

fn verify_holder_binding(
    context: HolderBindingContext<'_>,
) -> Result<Option<String>, VerificationError> {
    if matches!(context.policy, HolderBindingPolicy::NotRequired)
        && (context.key_binding_jwt.is_none()
            || context.expected_audience.is_none()
            || context.expected_nonce.is_none())
    {
        return Ok(context
            .payload
            .get("cnf")
            .and_then(|cnf| cnf.get("kid"))
            .and_then(Value::as_str)
            .map(ToString::to_string));
    }
    let cnf = context
        .payload
        .get("cnf")
        .ok_or(VerificationError::HolderBinding {
            code: "holder_binding.required",
        })?;
    let jwk_value = cnf.get("jwk").ok_or(VerificationError::HolderBinding {
        code: "holder_binding.required",
    })?;
    let jwk_json =
        serde_json::to_string(jwk_value).map_err(|_| VerificationError::HolderBinding {
            code: "holder_binding.invalid",
        })?;
    let holder_jwk = PublicJwk::parse(&jwk_json).map_err(|_| VerificationError::HolderBinding {
        code: "holder_binding.invalid",
    })?;
    let actual_kid = cnf
        .get("kid")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    if let HolderBindingPolicy::RequiredKid(expected) = context.policy {
        if actual_kid.as_deref() != Some(expected.as_str()) {
            return Err(VerificationError::HolderBinding {
                code: "holder_binding.kid_mismatch",
            });
        }
    }
    if let Some(key_binding_jwt) = context.key_binding_jwt {
        verify_key_binding_jwt(
            key_binding_jwt,
            context.sd_hash_input,
            &holder_jwk,
            context.expected_audience,
            context.expected_nonce,
            context.now,
            context.skew,
        )?;
    }
    Ok(actual_kid)
}

fn verify_key_binding_jwt(
    compact: &str,
    sd_hash_input: &str,
    holder_jwk: &PublicJwk,
    expected_audience: Option<&str>,
    expected_nonce: Option<&str>,
    now: i64,
    skew: i64,
) -> Result<(), VerificationError> {
    let mut parts = compact.split('.');
    let header_b64 = parts.next().ok_or(VerificationError::HolderBinding {
        code: "holder_binding.proof_invalid",
    })?;
    let payload_b64 = parts.next().ok_or(VerificationError::HolderBinding {
        code: "holder_binding.proof_invalid",
    })?;
    let signature_b64 = parts.next().ok_or(VerificationError::HolderBinding {
        code: "holder_binding.proof_invalid",
    })?;
    if parts.next().is_some()
        || header_b64.is_empty()
        || payload_b64.is_empty()
        || signature_b64.is_empty()
    {
        return Err(VerificationError::HolderBinding {
            code: "holder_binding.proof_invalid",
        });
    }
    let header = decode_segment(header_b64).map_err(|_| VerificationError::HolderBinding {
        code: "holder_binding.proof_invalid",
    })?;
    reject_untrusted_header_references(&header)?;
    if header.get("alg").and_then(Value::as_str) != Some("EdDSA")
        || header.get("typ").and_then(Value::as_str) != Some("kb+jwt")
    {
        return Err(VerificationError::HolderBinding {
            code: "holder_binding.proof_invalid",
        });
    }
    let signature =
        URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|_| VerificationError::HolderBinding {
                code: "holder_binding.proof_invalid",
            })?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    verify(signing_input.as_bytes(), &signature, holder_jwk).map_err(|_| {
        VerificationError::HolderBinding {
            code: "holder_binding.proof_invalid",
        }
    })?;
    let payload = decode_segment(payload_b64).map_err(|_| VerificationError::HolderBinding {
        code: "holder_binding.proof_invalid",
    })?;
    let iat =
        payload
            .get("iat")
            .and_then(Value::as_i64)
            .ok_or(VerificationError::HolderBinding {
                code: "holder_binding.proof_invalid",
            })?;
    if iat > now.saturating_add(skew) {
        return Err(VerificationError::HolderBinding {
            code: "holder_binding.proof_invalid",
        });
    }
    let exp =
        payload
            .get("exp")
            .and_then(Value::as_i64)
            .ok_or(VerificationError::HolderBinding {
                code: "holder_binding.proof_invalid",
            })?;
    if exp <= now.saturating_sub(skew) {
        return Err(VerificationError::HolderBinding {
            code: "holder_binding.proof_invalid",
        });
    }
    if payload
        .get("nbf")
        .and_then(Value::as_i64)
        .is_some_and(|nbf| nbf > now.saturating_add(skew))
    {
        return Err(VerificationError::HolderBinding {
            code: "holder_binding.proof_invalid",
        });
    }
    let expected_sd_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(sd_hash_input.as_bytes()));
    if payload.get("sd_hash").and_then(Value::as_str) != Some(expected_sd_hash.as_str()) {
        return Err(VerificationError::HolderBinding {
            code: "holder_binding.proof_invalid",
        });
    }
    let (Some(expected_audience), Some(expected_nonce)) = (expected_audience, expected_nonce)
    else {
        return Err(VerificationError::HolderBinding {
            code: "holder_binding.challenge_required",
        });
    };
    if !audience_matches(&payload, expected_audience) {
        return Err(VerificationError::HolderBinding {
            code: "holder_binding.proof_invalid",
        });
    }
    if payload.get("nonce").and_then(Value::as_str) != Some(expected_nonce) {
        return Err(VerificationError::HolderBinding {
            code: "holder_binding.proof_invalid",
        });
    }
    Ok(())
}

fn audience_matches(payload: &Value, expected_audience: &str) -> bool {
    match payload.get("aud") {
        Some(Value::String(audience)) => audience == expected_audience,
        Some(Value::Array(audiences)) => audiences
            .iter()
            .any(|audience| audience.as_str() == Some(expected_audience)),
        _ => false,
    }
}

fn reject_untrusted_header_references(header: &Value) -> Result<(), VerificationError> {
    for forbidden in ["crit", "jku", "jwk", "x5u", "x5c"] {
        if header.get(forbidden).is_some() {
            return Err(VerificationError::UntrustedKeyReference {
                code: "header.untrusted_key_reference",
            });
        }
    }
    Ok(())
}

fn find_jwk(jwks: &Value, kid: &str) -> Result<PublicJwk, VerificationError> {
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or(VerificationError::UnknownKey {
            code: "key.unknown",
        })?;
    for key in keys {
        if key.get("kid").and_then(Value::as_str) == Some(kid) {
            let json = serde_json::to_string(key).map_err(|_| VerificationError::UnknownKey {
                code: "key.unknown",
            })?;
            return PublicJwk::parse(&json).map_err(|_| VerificationError::UnknownKey {
                code: "key.unknown",
            });
        }
    }
    Err(VerificationError::UnknownKey {
        code: "key.unknown",
    })
}

fn jwk_alg(jwk: &PublicJwk) -> Option<&'static str> {
    match jwk.algorithm().ok()? {
        SigningAlgorithm::EdDsa => Some("EdDSA"),
        SigningAlgorithm::Rs256 => Some("RS256"),
    }
}

fn decode_segment(segment: &str) -> Result<Value, VerificationError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| VerificationError::Malformed {
            code: "token.malformed",
        })?;
    serde_json::from_slice(&decoded).map_err(|_| VerificationError::Malformed {
        code: "token.malformed",
    })
}

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, VerificationError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or(VerificationError::Malformed {
            code: "token.malformed",
        })
}

fn required_i64(value: &Value, field: &str) -> Result<i64, VerificationError> {
    value
        .get(field)
        .and_then(Value::as_i64)
        .ok_or(VerificationError::TimeClaim {
            code: "claim.time_invalid",
        })
}

fn optional_i64(value: &Value, field: &str) -> Result<Option<i64>, VerificationError> {
    value
        .get(field)
        .map(|raw| {
            raw.as_i64().ok_or(VerificationError::TimeClaim {
                code: "claim.time_invalid",
            })
        })
        .transpose()
}

struct ParsedSdJwt<'a> {
    header_b64: &'a str,
    payload_b64: &'a str,
    signature_b64: &'a str,
    disclosures: Vec<&'a str>,
    key_binding_jwt: Option<&'a str>,
    sd_hash_input: &'a str,
}

impl<'a> ParsedSdJwt<'a> {
    fn parse(compact: &'a str) -> Result<Self, VerificationError> {
        let mut parts = compact.split('~');
        let issuer_jwt =
            parts
                .next()
                .filter(|part| !part.is_empty())
                .ok_or(VerificationError::Malformed {
                    code: "token.malformed",
                })?;
        let mut presentation_parts = parts.filter(|part| !part.is_empty()).collect::<Vec<_>>();
        let key_binding_jwt = presentation_parts
            .last()
            .copied()
            .filter(|part| is_compact_jws(part));
        if key_binding_jwt.is_some() {
            presentation_parts.pop();
        }
        if presentation_parts.iter().any(|part| is_compact_jws(part)) {
            return Err(VerificationError::Malformed {
                code: "token.malformed",
            });
        }
        let sd_hash_input = if let Some(key_binding_jwt) = key_binding_jwt {
            compact
                .strip_suffix(key_binding_jwt)
                .ok_or(VerificationError::Malformed {
                    code: "token.malformed",
                })?
                .strip_suffix('~')
                .ok_or(VerificationError::Malformed {
                    code: "token.malformed",
                })?
        } else {
            compact
        };
        let mut jwt_parts = issuer_jwt.split('.');
        let header_b64 = jwt_parts.next().ok_or(VerificationError::Malformed {
            code: "token.malformed",
        })?;
        let payload_b64 = jwt_parts.next().ok_or(VerificationError::Malformed {
            code: "token.malformed",
        })?;
        let signature_b64 = jwt_parts.next().ok_or(VerificationError::Malformed {
            code: "token.malformed",
        })?;
        if jwt_parts.next().is_some()
            || header_b64.is_empty()
            || payload_b64.is_empty()
            || signature_b64.is_empty()
        {
            return Err(VerificationError::Malformed {
                code: "token.malformed",
            });
        }
        Ok(Self {
            header_b64,
            payload_b64,
            signature_b64,
            disclosures: presentation_parts,
            key_binding_jwt,
            sd_hash_input,
        })
    }

    fn signing_input(&self) -> String {
        format!("{}.{}", self.header_b64, self.payload_b64)
    }
}

fn is_compact_jws(value: &str) -> bool {
    let mut parts = value.split('.');
    let Some(header) = parts.next() else {
        return false;
    };
    let Some(payload) = parts.next() else {
        return false;
    };
    let Some(signature) = parts.next() else {
        return false;
    };
    parts.next().is_none() && !header.is_empty() && !payload.is_empty() && !signature.is_empty()
}
