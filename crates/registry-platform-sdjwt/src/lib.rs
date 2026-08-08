// SPDX-License-Identifier: Apache-2.0
//! SD-JWT VC issuance and holder-proof validation helpers.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use registry_platform_crypto::{
    parse_json_strict, verify, JwkError, LocalJwkSigner, PrivateJwk, PublicJwk, SigningAlgorithm,
    SigningError, SigningProvider,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;
use thiserror::Error;
use ulid::Ulid;

const HOLDER_PROOF_ALLOWED_ALGORITHM: SigningAlgorithm = SigningAlgorithm::EdDsa;
const KEY_BINDING_ALLOWED_ALGORITHM: SigningAlgorithm = SigningAlgorithm::Es256;
const OID4VCI_PROOF_ALLOWED_ALGORITHM: SigningAlgorithm = SigningAlgorithm::Es256;

const KEY_BINDING_TYP: &str = "kb+jwt";

/// The bare subtype OpenID4VCI 1.0 puts in the proof header. The registered
/// media type is `application/openid4vci-proof+jwt`; the header value drops the
/// prefix, and a header that keeps it is a different value.
const OID4VCI_PROOF_TYP: &str = "openid4vci-proof+jwt";

/// Header parameters through which a token nominates its own verification key
/// or its own processing rules. Honouring one lets the presenter choose what it
/// is checked against, so a validator must name every one it accepts.
const SELF_NOMINATING_HEADER_PARAMETERS: [&str; 5] = ["crit", "jku", "jwk", "x5u", "x5c"];

/// Header parameters a key-binding JWT may carry. `kid` is optional and is only
/// ever compared against the confirmation the issuer already signed, so no
/// self-nominating parameter appears here.
const KEY_BINDING_HEADER_PARAMETERS: [&str; 3] = ["alg", "typ", "kid"];

/// Header parameters an OpenID4VCI proof JWT may carry. `jwk` is the one
/// self-nominating parameter this crate honours, and only because the proof's
/// whole purpose is to present a key the issuer has not seen before.
const OID4VCI_PROOF_HEADER_PARAMETERS: [&str; 3] = ["alg", "typ", "jwk"];

/// The complete claim set RFC 9901 section 4.3 permits in a key-binding JWT.
const KEY_BINDING_PAYLOAD_CLAIMS: [&str; 4] = ["nonce", "aud", "iat", "sd_hash"];

/// The complete claim set this crate permits in an OpenID4VCI proof JWT.
const OID4VCI_PROOF_PAYLOAD_CLAIMS: [&str; 3] = ["aud", "iat", "nonce"];

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
        let credential_id = input.credential_id.unwrap_or_else(new_credential_id);

        let mut payload = Map::new();
        payload.insert("iss".to_string(), Value::String(input.iss));
        payload.insert("sub".to_string(), Value::String(input.sub_ref));
        payload.insert("iat".to_string(), Value::Number(input.iat.into()));
        payload.insert("exp".to_string(), Value::Number(input.exp.into()));
        payload.insert("vct".to_string(), Value::String(input.vct));
        payload.insert("id".to_string(), Value::String(credential_id.clone()));
        payload.insert("jti".to_string(), Value::String(credential_id.clone()));
        payload.insert("_sd_alg".to_string(), Value::String("sha-256".to_string()));
        if let Some(status) = input.status {
            payload.insert("status".to_string(), status);
        }
        for (name, value) in input.public_claims {
            payload.insert(name, value);
        }

        if let Some(cnf) = input.cnf {
            let mut cnf_value = Map::new();
            cnf_value.insert("jwk".to_string(), serde_json::to_value(cnf.jwk)?);
            if let Some(kid) = cnf.kid {
                cnf_value.insert("kid".to_string(), Value::String(kid));
            }
            payload.insert("cnf".to_string(), Value::Object(cnf_value));
        }

        let mut digests = Vec::with_capacity(input.disclosures.len());
        let nested_count = input
            .object_disclosures
            .iter()
            .map(|object| object.fields.len())
            .sum::<usize>();
        let mut disclosures = Vec::with_capacity(input.disclosures.len() + nested_count);
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
        for object in input.object_disclosures {
            let mut object_digests = Vec::with_capacity(object.fields.len());
            for disclosure in object.fields {
                let issued = issue_disclosure(&disclosure.name, disclosure.value)?;
                object_digests.push(issued.digest);
                disclosures.push(issued.encoded);
            }
            sort_sd_digests(&mut object_digests);
            payload.insert(
                object.name,
                json!({
                    "_sd": object_digests,
                }),
            );
        }

        let header = json!({
            "alg": self.signer.algorithm().jwa_name(),
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

    pub async fn sign_compact_jwt(&self, typ: &str, payload: Value) -> Result<String, SdJwtError> {
        if typ.trim().is_empty() || self.signer.key_id().trim().is_empty() {
            return Err(SdJwtError::Signing(SigningError::MissingKeyId));
        }
        let header = json!({
            "alg": self.signer.algorithm().jwa_name(),
            "typ": typ,
            "kid": self.signer.key_id(),
        });
        sign_jwt(header, payload, self.signer.as_ref()).await
    }
}

#[must_use]
pub fn new_credential_id() -> String {
    format!("urn:ulid:{}", Ulid::new())
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

/// One always-visible object container whose direct properties are separately
/// disclosable. Nested property values remain atomic; recursive disclosure is
/// deliberately outside this bounded helper.
#[derive(Clone, Debug)]
pub struct ObjectDisclosure {
    pub name: String,
    pub fields: Vec<Disclosure>,
}

#[derive(Clone, Debug)]
pub struct SdJwtIssuanceInput {
    pub iss: String,
    pub sub_ref: String,
    pub credential_id: Option<String>,
    pub iat: i64,
    pub exp: i64,
    pub vct: String,
    pub status: Option<Value>,
    pub public_claims: BTreeMap<String, Value>,
    pub cnf: Option<HolderConfirmation>,
    pub disclosures: Vec<Disclosure>,
    pub object_disclosures: Vec<ObjectDisclosure>,
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
        if self
            .credential_id
            .as_deref()
            .is_some_and(invalid_credential_id)
        {
            return Err(SdJwtError::InvalidInput);
        }
        for name in self.public_claims.keys() {
            if invalid_public_claim_name(name) {
                return Err(SdJwtError::InvalidInput);
            }
        }
        let mut names = BTreeSet::new();
        for disclosure in &self.disclosures {
            if invalid_disclosure_name(&disclosure.name)
                || self.public_claims.contains_key(&disclosure.name)
                || !names.insert(disclosure.name.as_str())
            {
                return Err(SdJwtError::InvalidInput);
            }
        }
        for object in &self.object_disclosures {
            if invalid_disclosure_name(&object.name)
                || self.public_claims.contains_key(&object.name)
                || !names.insert(object.name.as_str())
                || object.fields.is_empty()
                || object.fields.len() > 64
            {
                return Err(SdJwtError::InvalidInput);
            }
            let mut fields = BTreeSet::new();
            for disclosure in &object.fields {
                if invalid_object_property_name(&disclosure.name)
                    || !fields.insert(disclosure.name.as_str())
                {
                    return Err(SdJwtError::InvalidInput);
                }
            }
        }
        Ok(())
    }
}

fn invalid_credential_id(value: &str) -> bool {
    value.trim().is_empty() || value.chars().any(|ch| ch.is_ascii_control())
}

fn invalid_disclosure_name(value: &str) -> bool {
    const PROTECTED_NAMES: [&str; 13] = [
        "iss", "sub", "aud", "iat", "nbf", "exp", "vct", "id", "jti", "_sd", "_sd_alg", "cnf",
        "status",
    ];
    value.trim().is_empty()
        || value.chars().any(|ch| ch.is_ascii_control())
        || PROTECTED_NAMES.contains(&value)
}

fn invalid_public_claim_name(value: &str) -> bool {
    invalid_disclosure_name(value)
}

fn invalid_object_property_name(value: &str) -> bool {
    value.is_empty()
        || value.len() > 128
        || value == "_sd"
        || value == "..."
        || value.chars().any(char::is_control)
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
    require_holder_proof_algorithm(&header, holder_jwk, HOLDER_PROOF_ALLOWED_ALGORITHM)?;
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

/// Validate a holder proof against the holder confirmation embedded in the
/// issuer-signed credential.
///
/// This is the preferred verifier entry point for SD-JWT VC presentations. It
/// prevents callers from accidentally trusting a holder key that did not come
/// from the credential's `cnf.jwk`, and when `cnf.kid` is present it requires
/// the holder proof header to carry that exact `kid`.
pub fn validate_holder_proof_for_confirmation(
    proof_jwt: &str,
    confirmation: &HolderConfirmation,
    bindings: &HolderProofBindings<'_>,
    policy: &HolderProofPolicy,
    now: i64,
) -> Result<HolderProofClaims, SdJwtError> {
    if let Some(expected_kid) = confirmation.kid.as_deref() {
        let actual_kid = holder_proof_header_kid(proof_jwt)?;
        if actual_kid.as_deref() != Some(expected_kid) {
            return Err(SdJwtError::HolderProofInvalid);
        }
    }
    validate_holder_proof(proof_jwt, &confirmation.jwk, bindings, policy, now)
}

/// Compute the platform-owned disclosure binding hash for a presentation.
#[must_use]
pub fn presentation_disclosure_hash(presentation: &str) -> [u8; 32] {
    let digest = Sha256::digest(presentation.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Policy a verifier states before it will accept a key-binding JWT.
///
/// `nonce` is the challenge the verifier issued for this presentation.
/// Comparing it here is an equality check, not a consumption: RFC 9901
/// section 7.3 leaves the challenge lifecycle, single use included, to the
/// surrounding protocol.
#[derive(Clone)]
pub struct KeyBindingPolicy {
    pub audience: String,
    pub nonce: String,
    pub max_age: Duration,
    pub max_future_skew: Duration,
}

impl fmt::Debug for KeyBindingPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyBindingPolicy")
            .field("audience", &self.audience)
            .field("max_age", &self.max_age)
            .field("max_future_skew", &self.max_future_skew)
            .finish_non_exhaustive()
    }
}

/// The four claims RFC 9901 section 4.3 permits in a key-binding JWT, returned
/// only after every check has passed.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyBindingClaims {
    pub nonce: String,
    pub aud: String,
    pub iat: i64,
    pub sd_hash: String,
}

impl fmt::Debug for KeyBindingClaims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyBindingClaims")
            .field("aud", &self.aud)
            .field("iat", &self.iat)
            .field("sd_hash", &self.sd_hash)
            .finish_non_exhaustive()
    }
}

/// Policy a credential issuer states before it will accept an OpenID4VCI proof
/// JWT. `nonce` is the `c_nonce` the issuer handed out.
#[derive(Clone)]
pub struct Oid4vciProofPolicy {
    pub audience: String,
    pub nonce: String,
    pub max_age: Duration,
    pub max_future_skew: Duration,
}

impl fmt::Debug for Oid4vciProofPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Oid4vciProofPolicy")
            .field("audience", &self.audience)
            .field("max_age", &self.max_age)
            .field("max_future_skew", &self.max_future_skew)
            .finish_non_exhaustive()
    }
}

/// A validated OpenID4VCI proof. `holder_jwk` is the single public key the
/// proof authenticated, which is what a caller binds the credential to.
#[derive(Clone, PartialEq, Eq)]
pub struct Oid4vciProofClaims {
    pub holder_jwk: PublicJwk,
    pub aud: String,
    pub iat: i64,
    pub nonce: String,
}

impl fmt::Debug for Oid4vciProofClaims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Oid4vciProofClaims")
            .field("holder_jwk", &self.holder_jwk)
            .field("aud", &self.aud)
            .field("iat", &self.iat)
            .finish_non_exhaustive()
    }
}

/// Validate a key-binding JWT against RFC 9901 section 4.3.
///
/// The checks run in a fixed order and the order is part of the contract:
///
/// 1. split the compact serialization and decode the header;
/// 2. require `typ`, require the algorithm, and close the header allowlist;
/// 3. verify the signature against the credential's confirmed holder key,
///    before any claim is parsed, so no decision is ever taken from an
///    unverified token;
/// 4. require exactly the four permitted claims, rejecting duplicate JSON
///    members outright rather than resolving them;
/// 5. compare the challenge in constant time, then the audience, then bound
///    `iat` with checked arithmetic;
/// 6. recompute `sd_hash` over `sd_hash_input` and compare.
///
/// `sd_hash_input` is the presentation up to and including the last tilde, per
/// section 4.3.1. It is hashed, never parsed.
///
/// The confirmed key arrives as a `registry_platform_crypto::PublicJwk`, which
/// already applied that crate's point check when it was parsed. That is the
/// same acceptance rule `parse_oid4vci_proof_jwk` applies and the same one
/// `PublicJwk::jkt` thumbprints, so no key can be acceptable to one of these
/// validators and not the other.
///
/// This does not consume the challenge. Single use belongs to the caller's
/// challenge store.
pub fn validate_key_binding_jwt(
    kb_jwt: &str,
    confirmation: &HolderConfirmation,
    sd_hash_input: &str,
    policy: &KeyBindingPolicy,
    now: i64,
) -> Result<KeyBindingClaims, SdJwtError> {
    let (header_b64, payload_b64, signature_b64) =
        split_compact_jwt(kb_jwt).map_err(|_| SdJwtError::KeyBindingInvalid)?;
    let header = decode_strict_json(header_b64).map_err(|_| SdJwtError::KeyBindingInvalid)?;
    require_key_binding_header(&header, confirmation)?;

    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| SdJwtError::KeyBindingInvalid)?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    verify(signing_input.as_bytes(), &signature, &confirmation.jwk)
        .map_err(|_| SdJwtError::KeyBindingInvalid)?;

    let payload = decode_strict_json(payload_b64).map_err(|_| SdJwtError::KeyBindingInvalid)?;
    let members = closed_payload(&payload, &KEY_BINDING_PAYLOAD_CLAIMS)
        .ok_or(SdJwtError::KeyBindingInvalid)?;

    let nonce = required_member_str(members, "nonce").ok_or(SdJwtError::KeyBindingInvalid)?;
    if !constant_time_eq(nonce.as_bytes(), policy.nonce.as_bytes()) {
        return Err(SdJwtError::KeyBindingInvalid);
    }
    let aud =
        single_valued_audience(members, &policy.audience).ok_or(SdJwtError::KeyBindingInvalid)?;
    let iat = members
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or(SdJwtError::KeyBindingInvalid)?;
    if !iat_within_window(iat, now, policy.max_age, policy.max_future_skew)? {
        return Err(SdJwtError::KeyBindingInvalid);
    }

    let sd_hash = required_member_str(members, "sd_hash").ok_or(SdJwtError::KeyBindingInvalid)?;
    let expected_sd_hash = URL_SAFE_NO_PAD.encode(presentation_disclosure_hash(sd_hash_input));
    if !constant_time_eq(sd_hash.as_bytes(), expected_sd_hash.as_bytes()) {
        return Err(SdJwtError::KeyBindingInvalid);
    }

    Ok(KeyBindingClaims {
        nonce: nonce.to_string(),
        aud,
        iat,
        sd_hash: sd_hash.to_string(),
    })
}

/// Validate an OpenID for Verifiable Credential Issuance 1.0 proof JWT and
/// return the public key it authenticated.
///
/// The checks run in the same fixed order as `validate_key_binding_jwt`. Four
/// rules differ from a key-binding JWT:
///
/// - `typ` is the bare subtype `openid4vci-proof+jwt`. The registered media
///   type carries an `application/` prefix; the header value does not;
/// - the header may nominate exactly one of `kid`, `jwk`, or `x5c`, and this
///   validator honours `jwk` only, so the key is verified from the token and
///   returned to the caller;
/// - `aud` is the credential issuer identifier, and `iat` and `nonce` are both
///   required;
/// - `iss` must be absent. A present `iss` is a rejection, not a claim to
///   ignore.
pub fn validate_oid4vci_proof_jwt(
    proof_jwt: &str,
    policy: &Oid4vciProofPolicy,
    now: i64,
) -> Result<Oid4vciProofClaims, SdJwtError> {
    let (header_b64, payload_b64, signature_b64) =
        split_compact_jwt(proof_jwt).map_err(|_| SdJwtError::Oid4vciProofInvalid)?;
    let header = decode_strict_json(header_b64).map_err(|_| SdJwtError::Oid4vciProofInvalid)?;
    let holder_jwk = require_oid4vci_proof_header(&header)?;

    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| SdJwtError::Oid4vciProofInvalid)?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    verify(signing_input.as_bytes(), &signature, &holder_jwk)
        .map_err(|_| SdJwtError::Oid4vciProofInvalid)?;

    let payload = decode_strict_json(payload_b64).map_err(|_| SdJwtError::Oid4vciProofInvalid)?;
    let members = payload.as_object().ok_or(SdJwtError::Oid4vciProofInvalid)?;
    // OpenID4VCI 1.0 sends `iss` only from a wallet that authenticated as an
    // OAuth client. A pre-authorized code flow has no such client, so `iss`
    // asserts an identity this validator has nothing to check it against.
    if members.contains_key("iss") {
        return Err(SdJwtError::Oid4vciProofIssuerPresent);
    }
    let members = closed_payload(&payload, &OID4VCI_PROOF_PAYLOAD_CLAIMS)
        .ok_or(SdJwtError::Oid4vciProofInvalid)?;

    let nonce = required_member_str(members, "nonce").ok_or(SdJwtError::Oid4vciProofInvalid)?;
    if !constant_time_eq(nonce.as_bytes(), policy.nonce.as_bytes()) {
        return Err(SdJwtError::Oid4vciProofInvalid);
    }
    let aud =
        single_valued_audience(members, &policy.audience).ok_or(SdJwtError::Oid4vciProofInvalid)?;
    let iat = members
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or(SdJwtError::Oid4vciProofInvalid)?;
    if !iat_within_window(iat, now, policy.max_age, policy.max_future_skew)? {
        return Err(SdJwtError::Oid4vciProofInvalid);
    }

    Ok(Oid4vciProofClaims {
        holder_jwk,
        aud,
        iat,
        nonce: nonce.to_string(),
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
    #[error("key-binding JWT is invalid")]
    KeyBindingInvalid,
    #[error("OpenID4VCI proof JWT is invalid")]
    Oid4vciProofInvalid,
    #[error(
        "OpenID4VCI proof JWT must nominate its key with `jwk`: `kid` needs a key registered \
         before the request, which a pre-authorized code flow does not have, and `x5c` needs a \
         certificate trust anchor this crate does not hold"
    )]
    Oid4vciProofKeyReferenceUnsupported,
    #[error("OpenID4VCI proof JWT carries `iss` but no authenticated client identity backs it")]
    Oid4vciProofIssuerPresent,
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

// This parser recognizes EdDSA, ES256, and RS256, a narrower set than
// `SdJwtIssuer::issue` can emit through `self.signer.algorithm().jwa_name()`,
// which also covers ES384 and RS384. The gap is unreachable: this parser's only
// caller is `require_holder_proof_algorithm`, which is pinned to
// `HOLDER_PROOF_ALLOWED_ALGORITHM = SigningAlgorithm::EdDsa`, so a header naming
// an algorithm this function does not recognize is rejected here, and a header
// naming any algorithm other than EdDSA is rejected by the pin regardless of
// whether this function would have parsed it. Widening the holder-proof pin to
// accept another algorithm must add the matching arm here first.
fn signing_algorithm_from_jwa(alg: &str) -> Option<SigningAlgorithm> {
    match alg {
        "EdDSA" => Some(SigningAlgorithm::EdDsa),
        "ES256" => Some(SigningAlgorithm::Es256),
        "RS256" => Some(SigningAlgorithm::Rs256),
        _ => None,
    }
}

fn require_holder_proof_algorithm(
    header: &Value,
    holder_jwk: &PublicJwk,
    allowed_algorithm: SigningAlgorithm,
) -> Result<(), SdJwtError> {
    let header_algorithm = header
        .get("alg")
        .and_then(Value::as_str)
        .and_then(signing_algorithm_from_jwa)
        .ok_or(SdJwtError::HolderProofInvalid)?;
    let jwk_algorithm = holder_jwk
        .algorithm()
        .map_err(|_| SdJwtError::HolderProofInvalid)?;

    if header_algorithm != allowed_algorithm || jwk_algorithm != header_algorithm {
        return Err(SdJwtError::HolderProofInvalid);
    }
    Ok(())
}

/// Check the header of a key-binding JWT, in the order `typ`, algorithm,
/// closed allowlist, then the issuer-stated `kid`.
fn require_key_binding_header(
    header: &Value,
    confirmation: &HolderConfirmation,
) -> Result<(), SdJwtError> {
    if header.get("typ").and_then(Value::as_str) != Some(KEY_BINDING_TYP) {
        return Err(SdJwtError::KeyBindingInvalid);
    }
    require_holder_proof_algorithm(header, &confirmation.jwk, KEY_BINDING_ALLOWED_ALGORITHM)
        .map_err(|_| SdJwtError::KeyBindingInvalid)?;
    if !header_parameters_are_reviewed(header, &KEY_BINDING_HEADER_PARAMETERS, &[]) {
        return Err(SdJwtError::KeyBindingInvalid);
    }
    // When the issuer named a `cnf.kid`, the presenter has to repeat it, so a
    // holder with several confirmed keys cannot silently swap between them.
    if let Some(expected_kid) = confirmation.kid.as_deref() {
        if header.get("kid").and_then(Value::as_str) != Some(expected_kid) {
            return Err(SdJwtError::KeyBindingInvalid);
        }
    }
    Ok(())
}

/// Check the header of an OpenID4VCI proof JWT and return the key it
/// nominated, in the order `typ`, key nomination, algorithm, closed allowlist.
/// The key nomination is checked before the allowlist so an unresolvable
/// reference reports why, instead of a generic rejection.
fn require_oid4vci_proof_header(header: &Value) -> Result<PublicJwk, SdJwtError> {
    if header.get("typ").and_then(Value::as_str) != Some(OID4VCI_PROOF_TYP) {
        return Err(SdJwtError::Oid4vciProofInvalid);
    }
    let holder_jwk = oid4vci_proof_key(header)?;
    require_holder_proof_algorithm(header, &holder_jwk, OID4VCI_PROOF_ALLOWED_ALGORITHM)
        .map_err(|_| SdJwtError::Oid4vciProofInvalid)?;
    if !header_parameters_are_reviewed(header, &OID4VCI_PROOF_HEADER_PARAMETERS, &["jwk"]) {
        return Err(SdJwtError::Oid4vciProofInvalid);
    }
    Ok(holder_jwk)
}

/// Select the one key an OpenID4VCI proof may nominate.
///
/// OpenID4VCI 1.0 permits exactly one of `kid`, `jwk`, or `x5c`. Only `jwk` is
/// honoured, and the other two are refused with their own error so a deployment
/// reads the reason rather than a generic parse failure.
fn oid4vci_proof_key(header: &Value) -> Result<PublicJwk, SdJwtError> {
    let nominated: Vec<&str> = ["kid", "jwk", "x5c"]
        .into_iter()
        .filter(|name| header.get(*name).is_some())
        .collect();
    match nominated.as_slice() {
        ["jwk"] => {}
        [] => return Err(SdJwtError::Oid4vciProofInvalid),
        _ => return Err(SdJwtError::Oid4vciProofKeyReferenceUnsupported),
    }
    let jwk = header.get("jwk").ok_or(SdJwtError::Oid4vciProofInvalid)?;
    parse_oid4vci_proof_jwk(jwk)
}

/// Parse a nominated proof key through `registry_platform_crypto::PublicJwk`.
///
/// That parser is this crate's single acceptance rule for a holder public key:
/// it rejects private members, rejects duplicate JSON members, and checks the
/// P-256 point. Both validators here and `PublicJwk::jkt` therefore agree on
/// which keys exist at all, rather than each carrying its own point check.
///
/// RFC 7517 makes `alg` optional and wallets routinely omit it, while
/// `PublicJwk` requires it for an EC key. The header has already pinned ES256
/// by this point, so an EC key that states no `alg` has that pinned value
/// restated onto it. A key that states a different `alg` is left exactly as
/// sent and fails the algorithm agreement check that follows.
///
/// The underlying `JwkError` is deliberately not carried into the returned
/// error: its `Json` variant can quote the offending input, and the input here
/// may be key material.
fn parse_oid4vci_proof_jwk(jwk: &Value) -> Result<PublicJwk, SdJwtError> {
    let mut members = jwk
        .as_object()
        .ok_or(SdJwtError::Oid4vciProofInvalid)?
        .clone();
    if members.get("kty").and_then(Value::as_str) == Some("EC") && !members.contains_key("alg") {
        members.insert(
            "alg".to_string(),
            json!(OID4VCI_PROOF_ALLOWED_ALGORITHM.jwa_name()),
        );
    }
    let serialized = serde_json::to_string(&Value::Object(members))
        .map_err(|_| SdJwtError::Oid4vciProofInvalid)?;
    PublicJwk::parse(&serialized).map_err(|_| SdJwtError::Oid4vciProofInvalid)
}

/// Enforce a closed header allowlist.
///
/// Rejecting everything the validator has not reviewed already subsumes the
/// `crit`, `jku`, `jwk`, `x5u`, and `x5c` denylist that `validate_holder_proof`
/// applies. Those five are still named, so widening an allowlist to include one
/// of them has to be a deliberate entry in `honoured_self_nominating` and can
/// never be an oversight.
fn header_parameters_are_reviewed(
    header: &Value,
    allowed: &[&str],
    honoured_self_nominating: &[&str],
) -> bool {
    let Some(members) = header.as_object() else {
        return false;
    };
    members.keys().all(|name| {
        let name = name.as_str();
        if SELF_NOMINATING_HEADER_PARAMETERS.contains(&name)
            && !honoured_self_nominating.contains(&name)
        {
            return false;
        }
        allowed.contains(&name)
    })
}

/// Require a payload that carries exactly `claims` and nothing else.
fn closed_payload<'a>(payload: &'a Value, claims: &[&str]) -> Option<&'a Map<String, Value>> {
    let members = payload.as_object()?;
    if members.len() != claims.len() || !claims.iter().all(|claim| members.contains_key(*claim)) {
        return None;
    }
    Some(members)
}

fn required_member_str<'a>(members: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    members.get(name).and_then(Value::as_str)
}

/// Match a single-valued `aud`. Both of these profiles address one verifier, so
/// the array form RFC 7519 also permits is not accepted here: it would let a
/// token addressed to several parties satisfy any one of them.
fn single_valued_audience(members: &Map<String, Value>, expected: &str) -> Option<String> {
    match members.get("aud") {
        Some(Value::String(aud)) if aud == expected => Some(aud.clone()),
        _ => None,
    }
}

/// Compare a challenge without leaking how far a candidate matched, so a caller
/// cannot be walked toward the expected value one byte at a time. Length is
/// compared first and is not treated as secret.
fn constant_time_eq(actual: &[u8], expected: &[u8]) -> bool {
    actual.len() == expected.len() && bool::from(actual.ct_eq(expected))
}

/// Bound `iat` to the policy window with checked arithmetic, so neither a
/// hostile `iat` nor an unusable policy duration can wrap a comparison into
/// acceptance. A bound that cannot be represented is a deployment fault rather
/// than a token fault, so it is reported as `InvalidInput` and never silently
/// clamped.
fn iat_within_window(
    iat: i64,
    now: i64,
    max_age: Duration,
    max_future_skew: Duration,
) -> Result<bool, SdJwtError> {
    let max_age = i64::try_from(max_age.as_secs()).map_err(|_| SdJwtError::InvalidInput)?;
    let max_future_skew =
        i64::try_from(max_future_skew.as_secs()).map_err(|_| SdJwtError::InvalidInput)?;
    let earliest = now.checked_sub(max_age).ok_or(SdJwtError::InvalidInput)?;
    let latest = now
        .checked_add(max_future_skew)
        .ok_or(SdJwtError::InvalidInput)?;
    Ok(iat >= earliest && iat <= latest)
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

/// Decode a base64url segment into JSON that rejects duplicate members.
///
/// `serde_json` keeps the last of two members sharing a name. A validator that
/// reads such a member once would then check one value while another reader of
/// the same bytes sees the other, so every closed header and payload in this
/// module is decoded here. Callers map the failure onto their own error, which
/// is why this returns the neutral `InvalidInput`.
fn decode_strict_json(segment: &str) -> Result<Value, SdJwtError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| SdJwtError::InvalidInput)?;
    parse_json_strict(&bytes).map_err(|_| SdJwtError::InvalidInput)
}

fn holder_proof_header_kid(proof_jwt: &str) -> Result<Option<String>, SdJwtError> {
    let (header_b64, _, _) = split_compact_jwt(proof_jwt)?;
    let header = decode_json(header_b64)?;
    Ok(header
        .get("kid")
        .and_then(Value::as_str)
        .map(str::to_string))
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
    const P256_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"did:web:issuer.test#p256-key-1"}"#;
    const HOLDER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:jwk:holder#key-1"}"#;
    const HOLDER_P256_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"did:jwk:holder#p256-key-1"}"#;
    const OTHER_HOLDER_P256_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"M1bGIfUqjBuVWN85Q3qxTW1HUYYNnM-bR9alZAB-KtQ","x":"1vBja0WEJgw_GjigW1Er6WdhpAmnKHsTGPIov3lQ5Ak","y":"wrAAc7K8b9KkjqvrL51AXvmFeYfiio4yNDEIiM-2jyE","alg":"ES256","kid":"did:jwk:holder#p256-key-2"}"#;

    /// RFC 9901, November 2025, section 5.2 "Presentation": the complete
    /// SD-JWT+KB exactly as the specification prints it, with only the
    /// specification's own line wrapping removed. Each `concat!` line is one
    /// line of the RFC, so the bytes can be diffed against the source document.
    /// The element after the last tilde is the key-binding JWT; everything
    /// before it, including that tilde, is the `sd_hash` input of section
    /// 4.3.1.
    const RFC_9901_PRESENTATION: &str = concat!(
        "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJfc2QiOiBb",
        "IkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZ",
        "akg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBL",
        "dVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1",
        "SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tB",
        "TmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2",
        "Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFr",
        "b2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpn",
        "bGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vaXNzdWVyLmV4YW1wbGUu",
        "Y29tIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjog",
        "InVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15",
        "VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1",
        "ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjog",
        "InNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0y",
        "NTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VH",
        "ZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlG",
        "MkhaUSJ9fX0.MczwjBFGtzf-6WMT-hIvYbkb11NrV1WMO-jTijpMPNbswNzZ87wY2uHz",
        "-CXo6R04b7jYrpj9mNRAvVssXou1iw~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgI",
        "mZhbWlseV9uYW1lIiwgIkRvZSJd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFk",
        "ZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5",
        "IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMi",
        "fV0~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd",
        "~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0~eyJhbGciOiAiRVMyNTYiLCA",
        "idHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodH",
        "RwczovL3ZlcmlmaWVyLmV4YW1wbGUub3JnIiwgImlhdCI6IDE3NDg1MzcyNDQsICJzZF",
        "9oYXNoIjogIjBfQWYtMkItRWhMV1g1eWRoX3cyeHp3bU82aU02NkJfMlFDRWFuSTRmVV",
        "kifQ.T3SIus2OidNl41nmVkTZVCKKhOAX97aOldMyHFiYjHm261eLiJ1YiuONFiMN8Ql",
        "CmYzDlBLAdPvrXh52KaLgUQ",
    );

    /// The holder key from the `cnf` claim of the same RFC 9901 example. The
    /// RFC prints it without an `alg` member, which `PublicJwk` requires for an
    /// EC key. `alg` is not an RFC 7638 thumbprint member, so stating it names
    /// the same key; the existing external vector fixture states it the same
    /// way for the RFC's issuer key.
    const RFC_9901_HOLDER_JWK: &str = r#"{"kty":"EC","crv":"P-256","alg":"ES256","x":"TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc","y":"ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"}"#;

    /// A stand-in for the SD-JWT part of a presentation. Only its bytes matter:
    /// `sd_hash` is a digest over them, never a parse of them.
    const SD_HASH_INPUT: &str = "issuer.jwt~disclosure-a~disclosure-b~";

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
                credential_id: None,
                iat: 1_700_000_000,
                exp: 1_700_000_600,
                vct: "https://vct.example/test".to_string(),
                status: None,
                public_claims: BTreeMap::new(),
                cnf: Some(HolderConfirmation {
                    jwk: holder.public(),
                    kid: Some("did:jwk:holder#key-1".to_string()),
                }),
                disclosures: vec![Disclosure {
                    name: "claim-a".to_string(),
                    value: json!({"ok": true}),
                }],
                object_disclosures: Vec::new(),
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
    async fn issuer_can_sign_profiled_compact_jwt() {
        let issuer =
            SdJwtIssuer::from_jwk(PrivateJwk::parse(RAW_JWK).expect("jwk")).expect("issuer builds");

        let compact = issuer
            .sign_compact_jwt(
                "statuslist+jwt",
                json!({
                    "sub": "https://issuer.example/status/1",
                    "iat": 1_700_000_000,
                    "status_list": {
                        "bits": 2,
                        "lst": "eNoDAAAAAAE"
                    }
                }),
            )
            .await
            .expect("signs");

        let header = jwt_header(&compact);
        let payload = jwt_payload(&compact);
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["typ"], "statuslist+jwt");
        assert_eq!(header["kid"], "did:web:issuer.test#key-1");
        assert_eq!(payload["status_list"]["bits"], 2);
    }

    #[tokio::test]
    async fn sd_jwt_issuance_omits_cnf_when_unbound() {
        let issuer =
            SdJwtIssuer::from_jwk(PrivateJwk::parse(RAW_JWK).expect("jwk")).expect("issuer builds");
        let signed = issuer.issue(issue_input(None)).await.expect("issues");

        assert!(jwt_payload(&signed.jwt).get("cnf").is_none());
    }

    #[tokio::test]
    async fn sd_jwt_issuance_maps_es256_signing_algorithm() {
        let issuer = SdJwtIssuer::from_jwk(PrivateJwk::parse(P256_JWK).expect("jwk"))
            .expect("issuer builds");
        let signed = issuer.issue(issue_input(None)).await.expect("issues");
        let header = jwt_header(&signed.jwt);

        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "did:web:issuer.test#p256-key-1");
    }

    #[tokio::test]
    async fn sd_jwt_issuance_accepts_caller_credential_id_and_status_claim() {
        let issuer =
            SdJwtIssuer::from_jwk(PrivateJwk::parse(RAW_JWK).expect("jwk")).expect("issuer builds");
        let credential_id = "urn:ulid:01HX7Y5F2WAJ7ZP0Q4M5K9E8NC".to_string();
        let status = json!({
            "status_list": {
                "idx": 0,
                "uri": "https://issuer.example/credentials/status/01HX7Y5F2WAJ7ZP0Q4M5K9E8NC"
            }
        });

        let signed = issuer
            .issue(SdJwtIssuanceInput {
                credential_id: Some(credential_id.clone()),
                status: Some(status.clone()),
                ..issue_input(None)
            })
            .await
            .expect("issues");
        let payload = jwt_payload(&signed.jwt);

        assert_eq!(signed.credential_id, credential_id);
        assert_eq!(signed.jti, credential_id);
        assert_eq!(payload["id"], credential_id);
        assert_eq!(payload["jti"], credential_id);
        assert_eq!(payload["status"], status);
    }

    #[tokio::test]
    async fn sd_jwt_issuance_accepts_public_compatibility_claims() {
        let issuer =
            SdJwtIssuer::from_jwk(PrivateJwk::parse(RAW_JWK).expect("jwk")).expect("issuer builds");

        let signed = issuer
            .issue(SdJwtIssuanceInput {
                public_claims: BTreeMap::from([
                    ("issuanceDate".to_string(), json!("2023-11-14T22:13:20Z")),
                    ("expirationDate".to_string(), json!("2023-11-14T22:23:20Z")),
                ]),
                ..issue_input(None)
            })
            .await
            .expect("issues");
        let payload = jwt_payload(&signed.jwt);

        assert_eq!(payload["issuanceDate"], "2023-11-14T22:13:20Z");
        assert_eq!(payload["expirationDate"], "2023-11-14T22:23:20Z");
    }

    #[tokio::test]
    async fn sd_jwt_issuance_rejects_public_claims_that_override_registered_claims() {
        let issuer =
            SdJwtIssuer::from_jwk(PrivateJwk::parse(RAW_JWK).expect("jwk")).expect("issuer builds");

        let err = issuer
            .issue(SdJwtIssuanceInput {
                public_claims: BTreeMap::from([("exp".to_string(), json!("shadow"))]),
                ..issue_input(None)
            })
            .await
            .expect_err("registered claim names reject");

        assert!(matches!(err, SdJwtError::InvalidInput));
    }

    #[tokio::test]
    async fn sd_jwt_issuance_rejects_blank_caller_credential_id() {
        let issuer =
            SdJwtIssuer::from_jwk(PrivateJwk::parse(RAW_JWK).expect("jwk")).expect("issuer builds");

        let err = issuer
            .issue(SdJwtIssuanceInput {
                credential_id: Some(" \t".to_string()),
                ..issue_input(None)
            })
            .await
            .expect_err("blank credential id rejects");

        assert!(matches!(err, SdJwtError::InvalidInput));
    }

    #[tokio::test]
    async fn sd_jwt_issuance_rejects_protected_or_duplicate_disclosure_names() {
        let issuer =
            SdJwtIssuer::from_jwk(PrivateJwk::parse(RAW_JWK).expect("jwk")).expect("issuer builds");

        for name in ["iss", "aud", "nbf", "status"] {
            let protected = issuer
                .issue(SdJwtIssuanceInput {
                    disclosures: vec![Disclosure {
                        name: name.to_string(),
                        value: json!("attacker"),
                    }],
                    ..issue_input(None)
                })
                .await
                .expect_err("protected disclosure name rejects");
            assert!(matches!(protected, SdJwtError::InvalidInput));
        }

        let duplicate = issuer
            .issue(SdJwtIssuanceInput {
                disclosures: vec![
                    Disclosure {
                        name: "claim-a".to_string(),
                        value: json!(1),
                    },
                    Disclosure {
                        name: "claim-a".to_string(),
                        value: json!(2),
                    },
                ],
                ..issue_input(None)
            })
            .await
            .expect_err("duplicate disclosure name rejects");
        assert!(matches!(duplicate, SdJwtError::InvalidInput));
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
    async fn object_properties_are_independent_nested_disclosures() {
        let issuer =
            SdJwtIssuer::from_jwk(PrivateJwk::parse(RAW_JWK).expect("jwk")).expect("issuer builds");
        let signed = issuer
            .issue(SdJwtIssuanceInput {
                object_disclosures: vec![ObjectDisclosure {
                    name: "birthCertificate".to_string(),
                    fields: vec![
                        Disclosure {
                            name: "givenName".to_string(),
                            value: json!("John"),
                        },
                        Disclosure {
                            name: "placeOfBirth".to_string(),
                            value: json!({"city": "Dusseldorf", "country": "DE"}),
                        },
                    ],
                }],
                ..issue_input(None)
            })
            .await
            .expect("issues");

        let payload = jwt_payload(&signed.jwt);
        assert_eq!(payload["_sd"], json!([]));
        let nested = payload["birthCertificate"]["_sd"]
            .as_array()
            .expect("nested digest array");
        assert_eq!(nested.len(), 2);
        let names = signed
            .jwt
            .split('~')
            .skip(1)
            .filter(|segment| !segment.is_empty())
            .map(|segment| {
                let decoded = URL_SAFE_NO_PAD.decode(segment).expect("disclosure decodes");
                let disclosure: Value = serde_json::from_slice(&decoded).expect("disclosure JSON");
                disclosure[1].as_str().expect("claim name").to_owned()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            names,
            BTreeSet::from(["givenName".to_string(), "placeOfBirth".to_string()])
        );
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
        )
        .expect("proof signs with resolved ES256 key");
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
        )
        .expect("proof signs with its own ES256 key");

        validate_holder_proof(&proof, &holder.public(), &bindings, &policy(), now).expect_err(
            "HOLDER_PROOF_ALLOWED_ALGORITHM pins holder proofs to EdDSA even for a \
             correctly self-signed ES256 proof",
        );
    }

    #[test]
    fn presentation_disclosure_hash_is_platform_computed() {
        let hash = presentation_disclosure_hash("issuer.jwt~disclosure~holder.jwt");
        let manual = Sha256::digest(b"issuer.jwt~disclosure~holder.jwt");

        assert_eq!(hash.as_slice(), manual.as_slice());
        assert_ne!(hash, [0u8; 32]);
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

    #[test]
    fn key_binding_jwt_validates_the_rfc_9901_presentation_vector() {
        let (sd_hash_input, kb_jwt) = split_rfc_9901_presentation();
        let confirmation = HolderConfirmation {
            jwk: PublicJwk::parse(RFC_9901_HOLDER_JWK).expect("rfc holder key parses"),
            kid: None,
        };
        let policy = KeyBindingPolicy {
            audience: "https://verifier.example.org".to_string(),
            nonce: "1234567890".to_string(),
            max_age: Duration::from_secs(300),
            max_future_skew: Duration::from_secs(30),
        };

        let claims =
            validate_key_binding_jwt(kb_jwt, &confirmation, sd_hash_input, &policy, 1_748_537_244)
                .expect("rfc 9901 key-binding jwt validates");

        assert_eq!(claims.aud, "https://verifier.example.org");
        assert_eq!(claims.nonce, "1234567890");
        assert_eq!(claims.iat, 1_748_537_244);
        assert_eq!(
            claims.sd_hash,
            "0_Af-2B-EhLWX5ydh_w2xzwmO6iM66B_2QCEanI4fUY"
        );
    }

    #[test]
    fn key_binding_jwt_rejects_the_rfc_vector_against_a_different_presentation() {
        let (sd_hash_input, kb_jwt) = split_rfc_9901_presentation();
        let confirmation = HolderConfirmation {
            jwk: PublicJwk::parse(RFC_9901_HOLDER_JWK).expect("rfc holder key parses"),
            kid: None,
        };
        let policy = KeyBindingPolicy {
            audience: "https://verifier.example.org".to_string(),
            nonce: "1234567890".to_string(),
            max_age: Duration::from_secs(300),
            max_future_skew: Duration::from_secs(30),
        };
        let dropped_disclosure = sd_hash_input
            .rsplit_once('~')
            .and_then(|(head, _)| head.rsplit_once('~'))
            .map(|(head, _)| format!("{head}~"))
            .expect("presentation carries disclosures");

        let err = validate_key_binding_jwt(
            kb_jwt,
            &confirmation,
            &dropped_disclosure,
            &policy,
            1_748_537_244,
        )
        .expect_err("a key-binding jwt must not travel to another presentation");

        assert!(matches!(err, SdJwtError::KeyBindingInvalid));
    }

    #[test]
    fn key_binding_jwt_rejects_wrong_type_and_algorithm() {
        let holder = PrivateJwk::parse(HOLDER_P256_JWK).expect("holder");
        let ed25519_holder = PrivateJwk::parse(HOLDER_JWK).expect("ed25519 holder");
        let now = 1_700_000_000;

        for typ in [
            "JWT",
            "kb+JWT",
            "application/kb+jwt",
            "openid4vci-proof+jwt",
        ] {
            let mut header = key_binding_header();
            header["typ"] = json!(typ);
            let kb_jwt = sign_compact(&holder, header, &key_binding_payload(now));
            validate_key_binding_jwt(
                &kb_jwt,
                &key_binding_confirmation(&holder),
                SD_HASH_INPUT,
                &key_binding_policy(),
                now,
            )
            .expect_err("key-binding typ must be exactly kb+jwt");
        }

        let ed25519 = sign_compact(
            &ed25519_holder,
            json!({"alg": "EdDSA", "typ": "kb+jwt"}),
            &key_binding_payload(now),
        );
        validate_key_binding_jwt(
            &ed25519,
            &key_binding_confirmation(&ed25519_holder),
            SD_HASH_INPUT,
            &key_binding_policy(),
            now,
        )
        .expect_err("key binding is ES256 only");
    }

    #[test]
    fn key_binding_jwt_rejects_header_parameters_outside_the_allowlist() {
        let holder = PrivateJwk::parse(HOLDER_P256_JWK).expect("holder");
        let now = 1_700_000_000;

        for parameter in ["crit", "jku", "jwk", "x5u", "x5c", "cty", "b64"] {
            let mut header = key_binding_header();
            header[parameter] = json!("attacker-controlled");
            let kb_jwt = sign_compact(&holder, header, &key_binding_payload(now));

            let err = validate_key_binding_jwt(
                &kb_jwt,
                &key_binding_confirmation(&holder),
                SD_HASH_INPUT,
                &key_binding_policy(),
                now,
            )
            .expect_err("header parameter outside the allowlist is rejected");

            assert!(
                matches!(err, SdJwtError::KeyBindingInvalid),
                "header parameter {parameter} must be rejected"
            );
        }
    }

    #[test]
    fn key_binding_jwt_rejects_a_policy_satisfying_payload_signed_by_another_key() {
        let holder = PrivateJwk::parse(HOLDER_P256_JWK).expect("holder");
        let other = PrivateJwk::parse(OTHER_HOLDER_P256_JWK).expect("other holder");
        let now = 1_700_000_000;
        let kb_jwt = sign_compact(&other, key_binding_header(), &key_binding_payload(now));

        let err = validate_key_binding_jwt(
            &kb_jwt,
            &key_binding_confirmation(&holder),
            SD_HASH_INPUT,
            &key_binding_policy(),
            now,
        )
        .expect_err("a payload cannot buy acceptance without the confirmed key's signature");

        assert!(matches!(err, SdJwtError::KeyBindingInvalid));
    }

    #[test]
    fn key_binding_jwt_rejects_a_duplicate_payload_member() {
        let holder = PrivateJwk::parse(HOLDER_P256_JWK).expect("holder");
        let now = 1_700_000_000;
        let sd_hash = URL_SAFE_NO_PAD.encode(presentation_disclosure_hash(SD_HASH_INPUT));
        let shadowed = format!(
            r#"{{"nonce":"attacker-challenge","nonce":"verifier-challenge","aud":"https://verifier.example/rp","iat":{now},"sd_hash":"{sd_hash}"}}"#
        );
        let kb_jwt = sign_raw_compact(&holder, key_binding_header(), &shadowed);

        let err = validate_key_binding_jwt(
            &kb_jwt,
            &key_binding_confirmation(&holder),
            SD_HASH_INPUT,
            &key_binding_policy(),
            now,
        )
        .expect_err("a duplicate JSON member must not shadow the member a check reads");

        assert!(matches!(err, SdJwtError::KeyBindingInvalid));
    }

    #[test]
    fn key_binding_jwt_requires_exactly_the_four_closed_payload_claims() {
        let holder = PrivateJwk::parse(HOLDER_P256_JWK).expect("holder");
        let now = 1_700_000_000;

        let mut extended = key_binding_payload(now);
        extended["iss"] = json!("https://holder.example");
        let extra = sign_compact(&holder, key_binding_header(), &extended);
        validate_key_binding_jwt(
            &extra,
            &key_binding_confirmation(&holder),
            SD_HASH_INPUT,
            &key_binding_policy(),
            now,
        )
        .expect_err("an unreviewed extra claim is rejected");

        for claim in ["nonce", "aud", "iat", "sd_hash"] {
            let mut payload = key_binding_payload(now);
            payload
                .as_object_mut()
                .expect("payload object")
                .remove(claim);
            let kb_jwt = sign_compact(&holder, key_binding_header(), &payload);

            validate_key_binding_jwt(
                &kb_jwt,
                &key_binding_confirmation(&holder),
                SD_HASH_INPUT,
                &key_binding_policy(),
                now,
            )
            .unwrap_err();
        }
    }

    #[test]
    fn key_binding_jwt_compares_nonce_audience_and_presentation_hash() {
        let holder = PrivateJwk::parse(HOLDER_P256_JWK).expect("holder");
        let now = 1_700_000_000;

        let mut wrong_nonce = key_binding_payload(now);
        wrong_nonce["nonce"] = json!("another-challenge");
        let kb_jwt = sign_compact(&holder, key_binding_header(), &wrong_nonce);
        validate_key_binding_jwt(
            &kb_jwt,
            &key_binding_confirmation(&holder),
            SD_HASH_INPUT,
            &key_binding_policy(),
            now,
        )
        .expect_err("nonce mismatch rejects");

        let mut wrong_aud = key_binding_payload(now);
        wrong_aud["aud"] = json!("https://other-verifier.example/rp");
        let kb_jwt = sign_compact(&holder, key_binding_header(), &wrong_aud);
        validate_key_binding_jwt(
            &kb_jwt,
            &key_binding_confirmation(&holder),
            SD_HASH_INPUT,
            &key_binding_policy(),
            now,
        )
        .expect_err("audience mismatch rejects");

        let mut array_aud = key_binding_payload(now);
        array_aud["aud"] = json!(["https://verifier.example/rp"]);
        let kb_jwt = sign_compact(&holder, key_binding_header(), &array_aud);
        validate_key_binding_jwt(
            &kb_jwt,
            &key_binding_confirmation(&holder),
            SD_HASH_INPUT,
            &key_binding_policy(),
            now,
        )
        .expect_err("this profile requires the single-valued audience form");

        let mut wrong_hash = key_binding_payload(now);
        wrong_hash["sd_hash"] =
            json!(URL_SAFE_NO_PAD.encode(presentation_disclosure_hash("other")));
        let kb_jwt = sign_compact(&holder, key_binding_header(), &wrong_hash);
        validate_key_binding_jwt(
            &kb_jwt,
            &key_binding_confirmation(&holder),
            SD_HASH_INPUT,
            &key_binding_policy(),
            now,
        )
        .expect_err("presentation hash mismatch rejects");
    }

    #[test]
    fn key_binding_jwt_bounds_iat_with_checked_arithmetic() {
        let holder = PrivateJwk::parse(HOLDER_P256_JWK).expect("holder");
        let now = 1_700_000_000;
        let confirmation = key_binding_confirmation(&holder);

        let stale = sign_compact(
            &holder,
            key_binding_header(),
            &key_binding_payload(now - 301),
        );
        validate_key_binding_jwt(
            &stale,
            &confirmation,
            SD_HASH_INPUT,
            &key_binding_policy(),
            now,
        )
        .expect_err("iat older than max_age rejects");

        let future = sign_compact(
            &holder,
            key_binding_header(),
            &key_binding_payload(now + 31),
        );
        validate_key_binding_jwt(
            &future,
            &confirmation,
            SD_HASH_INPUT,
            &key_binding_policy(),
            now,
        )
        .expect_err("iat beyond max_future_skew rejects");

        let baseline = sign_compact(&holder, key_binding_header(), &key_binding_payload(0));
        for (label, now, policy) in [
            ("now at the lower limit", i64::MIN, key_binding_policy()),
            ("now at the upper limit", i64::MAX, key_binding_policy()),
            (
                "an unrepresentable max_age",
                1_700_000_000,
                KeyBindingPolicy {
                    max_age: Duration::from_secs(u64::MAX),
                    ..key_binding_policy()
                },
            ),
            (
                "an unrepresentable max_future_skew",
                1_700_000_000,
                KeyBindingPolicy {
                    max_future_skew: Duration::from_secs(u64::MAX),
                    ..key_binding_policy()
                },
            ),
        ] {
            let err =
                validate_key_binding_jwt(&baseline, &confirmation, SD_HASH_INPUT, &policy, now)
                    .expect_err("time arithmetic must fail visibly");

            assert!(
                matches!(err, SdJwtError::InvalidInput),
                "{label} must report unusable policy bounds"
            );
        }
    }

    #[test]
    fn key_binding_jwt_requires_the_confirmation_kid_when_it_names_one() {
        let holder = PrivateJwk::parse(HOLDER_P256_JWK).expect("holder");
        let now = 1_700_000_000;
        let mut header = key_binding_header();
        header["kid"] = json!("did:jwk:holder#p256-key-1");
        let kb_jwt = sign_compact(&holder, header, &key_binding_payload(now));
        let confirmation = HolderConfirmation {
            jwk: holder.public(),
            kid: Some("did:jwk:holder#p256-key-1".to_string()),
        };

        validate_key_binding_jwt(
            &kb_jwt,
            &confirmation,
            SD_HASH_INPUT,
            &key_binding_policy(),
            now,
        )
        .expect("matching kid validates");

        let wrong_kid = HolderConfirmation {
            jwk: holder.public(),
            kid: Some("did:jwk:holder#other".to_string()),
        };
        validate_key_binding_jwt(
            &kb_jwt,
            &wrong_kid,
            SD_HASH_INPUT,
            &key_binding_policy(),
            now,
        )
        .expect_err("confirmation kid mismatch rejects");

        let no_header_kid = sign_compact(&holder, key_binding_header(), &key_binding_payload(now));
        validate_key_binding_jwt(
            &no_header_kid,
            &confirmation,
            SD_HASH_INPUT,
            &key_binding_policy(),
            now,
        )
        .expect_err("a confirmation kid must be repeated in the header");
    }

    #[test]
    fn key_binding_jwt_rejects_structurally_malformed_compact_input() {
        let holder = PrivateJwk::parse(HOLDER_P256_JWK).expect("holder");
        let confirmation = key_binding_confirmation(&holder);

        for malformed in ["", "notajwt", "a.b", "a.b.c.d", "!!.!!.!!", ".."] {
            let err = validate_key_binding_jwt(
                malformed,
                &confirmation,
                SD_HASH_INPUT,
                &key_binding_policy(),
                1_700_000_000,
            )
            .expect_err("malformed compact input rejects");

            assert!(
                matches!(err, SdJwtError::KeyBindingInvalid),
                "input {malformed:?} must return KeyBindingInvalid"
            );
        }
    }

    #[test]
    fn key_binding_debug_never_exposes_the_verifier_challenge() {
        let holder = PrivateJwk::parse(HOLDER_P256_JWK).expect("holder");
        let now = 1_700_000_000;
        let kb_jwt = sign_compact(&holder, key_binding_header(), &key_binding_payload(now));
        let claims = validate_key_binding_jwt(
            &kb_jwt,
            &key_binding_confirmation(&holder),
            SD_HASH_INPUT,
            &key_binding_policy(),
            now,
        )
        .expect("validates");

        let policy_debug = format!("{:?}", key_binding_policy());
        let claims_debug = format!("{claims:?}");

        assert!(!policy_debug.contains("verifier-challenge"));
        assert!(!claims_debug.contains("verifier-challenge"));
        assert!(policy_debug.contains("KeyBindingPolicy"));
        assert!(claims_debug.contains("KeyBindingClaims"));
    }

    #[test]
    fn oid4vci_proof_jwt_returns_the_holder_key_it_authenticated() {
        let holder = PrivateJwk::parse(HOLDER_P256_JWK).expect("holder");
        let now = 1_700_000_000;
        let proof = sign_compact(
            &holder,
            oid4vci_proof_header(&holder),
            &oid4vci_proof_payload(now),
        );

        let claims = validate_oid4vci_proof_jwt(&proof, &oid4vci_proof_policy(), now)
            .expect("wallet proof validates");

        assert_eq!(claims.holder_jwk, holder.public());
        assert_eq!(claims.aud, "https://issuer.example/credentials");
        assert_eq!(claims.nonce, "c-nonce-value");
        assert_eq!(claims.iat, now);
    }

    #[test]
    fn oid4vci_proof_jwt_requires_the_bare_typ_without_the_media_type_prefix() {
        let holder = PrivateJwk::parse(HOLDER_P256_JWK).expect("holder");
        let now = 1_700_000_000;

        for typ in [
            "application/openid4vci-proof+jwt",
            "openid4vci-proof+JWT",
            "kb+jwt",
            "JWT",
        ] {
            let mut header = oid4vci_proof_header(&holder);
            header["typ"] = json!(typ);
            let proof = sign_compact(&holder, header, &oid4vci_proof_payload(now));

            let err = validate_oid4vci_proof_jwt(&proof, &oid4vci_proof_policy(), now)
                .expect_err("proof typ must be the bare subtype");

            assert!(
                matches!(err, SdJwtError::Oid4vciProofInvalid),
                "typ {typ:?} must be rejected"
            );
        }
    }

    #[test]
    fn oid4vci_proof_jwt_rejects_key_references_it_cannot_resolve() {
        let holder = PrivateJwk::parse(HOLDER_P256_JWK).expect("holder");
        let now = 1_700_000_000;

        for reference in ["kid", "x5c"] {
            let mut header = oid4vci_proof_header(&holder);
            header.as_object_mut().expect("header object").remove("jwk");
            header[reference] = json!("did:jwk:holder#p256-key-1");
            let proof = sign_compact(&holder, header, &oid4vci_proof_payload(now));

            let err = validate_oid4vci_proof_jwt(&proof, &oid4vci_proof_policy(), now)
                .expect_err("an unresolvable key reference is rejected");

            assert!(
                matches!(err, SdJwtError::Oid4vciProofKeyReferenceUnsupported),
                "header {reference} must report why it cannot be resolved"
            );
        }

        let mut both = oid4vci_proof_header(&holder);
        both["kid"] = json!("did:jwk:holder#p256-key-1");
        let proof = sign_compact(&holder, both, &oid4vci_proof_payload(now));
        assert!(matches!(
            validate_oid4vci_proof_jwt(&proof, &oid4vci_proof_policy(), now)
                .expect_err("exactly one key reference is permitted"),
            SdJwtError::Oid4vciProofKeyReferenceUnsupported
        ));

        let mut none = oid4vci_proof_header(&holder);
        none.as_object_mut().expect("header object").remove("jwk");
        let proof = sign_compact(&holder, none, &oid4vci_proof_payload(now));
        assert!(matches!(
            validate_oid4vci_proof_jwt(&proof, &oid4vci_proof_policy(), now)
                .expect_err("a proof must carry a key reference"),
            SdJwtError::Oid4vciProofInvalid
        ));
    }

    #[test]
    fn oid4vci_proof_jwt_rejects_a_present_issuer_claim() {
        let holder = PrivateJwk::parse(HOLDER_P256_JWK).expect("holder");
        let now = 1_700_000_000;
        let mut payload = oid4vci_proof_payload(now);
        payload["iss"] = json!("wallet-client-id");
        let proof = sign_compact(&holder, oid4vci_proof_header(&holder), &payload);

        let err = validate_oid4vci_proof_jwt(&proof, &oid4vci_proof_policy(), now)
            .expect_err("iss must be omitted in the pre-authorized code flow");

        assert!(matches!(err, SdJwtError::Oid4vciProofIssuerPresent));
    }

    #[test]
    fn oid4vci_proof_jwt_requires_exactly_the_three_closed_payload_claims() {
        let holder = PrivateJwk::parse(HOLDER_P256_JWK).expect("holder");
        let now = 1_700_000_000;

        for claim in ["aud", "iat", "nonce"] {
            let mut payload = oid4vci_proof_payload(now);
            payload
                .as_object_mut()
                .expect("payload object")
                .remove(claim);
            let proof = sign_compact(&holder, oid4vci_proof_header(&holder), &payload);

            let err = validate_oid4vci_proof_jwt(&proof, &oid4vci_proof_policy(), now)
                .expect_err("every proof claim is required");

            assert!(
                matches!(err, SdJwtError::Oid4vciProofInvalid),
                "claim {claim} must be required"
            );
        }

        let mut extended = oid4vci_proof_payload(now);
        extended["jti"] = json!("wallet-chosen");
        let proof = sign_compact(&holder, oid4vci_proof_header(&holder), &extended);
        validate_oid4vci_proof_jwt(&proof, &oid4vci_proof_policy(), now)
            .expect_err("an unreviewed extra claim is rejected");
    }

    #[test]
    fn oid4vci_proof_jwt_rejects_a_proof_signed_by_a_key_other_than_its_header_jwk() {
        let holder = PrivateJwk::parse(HOLDER_P256_JWK).expect("holder");
        let other = PrivateJwk::parse(OTHER_HOLDER_P256_JWK).expect("other holder");
        let now = 1_700_000_000;
        let proof = sign_compact(
            &other,
            oid4vci_proof_header(&holder),
            &oid4vci_proof_payload(now),
        );

        let err = validate_oid4vci_proof_jwt(&proof, &oid4vci_proof_policy(), now)
            .expect_err("the nominated key must be the signing key");

        assert!(matches!(err, SdJwtError::Oid4vciProofInvalid));
    }

    #[test]
    fn oid4vci_proof_jwt_rejects_a_duplicate_payload_member() {
        let holder = PrivateJwk::parse(HOLDER_P256_JWK).expect("holder");
        let now = 1_700_000_000;
        let shadowed = format!(
            r#"{{"nonce":"attacker-nonce","nonce":"c-nonce-value","aud":"https://issuer.example/credentials","iat":{now}}}"#
        );
        let proof = sign_raw_compact(&holder, oid4vci_proof_header(&holder), &shadowed);

        let err = validate_oid4vci_proof_jwt(&proof, &oid4vci_proof_policy(), now)
            .expect_err("a duplicate JSON member must not shadow the member a check reads");

        assert!(matches!(err, SdJwtError::Oid4vciProofInvalid));
    }

    #[test]
    fn oid4vci_proof_jwt_rejects_a_non_es256_algorithm() {
        let ed25519_holder = PrivateJwk::parse(HOLDER_JWK).expect("ed25519 holder");
        let now = 1_700_000_000;
        let proof = sign_compact(
            &ed25519_holder,
            json!({
                "alg": "EdDSA",
                "typ": "openid4vci-proof+jwt",
                "jwk": ed25519_holder.public(),
            }),
            &oid4vci_proof_payload(now),
        );

        let err = validate_oid4vci_proof_jwt(&proof, &oid4vci_proof_policy(), now)
            .expect_err("proofs are ES256 only");

        assert!(matches!(err, SdJwtError::Oid4vciProofInvalid));
    }

    #[test]
    fn oid4vci_proof_jwt_completes_an_absent_jwk_alg_from_the_pinned_header() {
        let holder = PrivateJwk::parse(HOLDER_P256_JWK).expect("holder");
        let now = 1_700_000_000;
        let mut header = oid4vci_proof_header(&holder);
        let jwk = header["jwk"].as_object_mut().expect("jwk object");
        jwk.remove("alg");
        jwk.remove("kid");
        let proof = sign_compact(&holder, header, &oid4vci_proof_payload(now));

        let claims = validate_oid4vci_proof_jwt(&proof, &oid4vci_proof_policy(), now)
            .expect("a wallet key without alg is accepted under the pinned header");

        assert_eq!(claims.holder_jwk.x, holder.public().x);
        assert_eq!(claims.holder_jwk.alg.as_deref(), Some("ES256"));
    }

    #[test]
    fn oid4vci_proof_jwt_rejects_private_key_material_in_the_header_jwk() {
        let holder = PrivateJwk::parse(HOLDER_P256_JWK).expect("holder");
        let now = 1_700_000_000;
        let mut header = oid4vci_proof_header(&holder);
        header["jwk"]["d"] = json!("MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4");
        let proof = sign_compact(&holder, header, &oid4vci_proof_payload(now));

        let err = validate_oid4vci_proof_jwt(&proof, &oid4vci_proof_policy(), now)
            .expect_err("a proof key must not carry private material");
        let rendered = err.to_string();

        assert!(matches!(err, SdJwtError::Oid4vciProofInvalid));
        assert!(!rendered.contains("MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4"));
    }

    #[test]
    fn oid4vci_proof_jwt_rejects_header_parameters_outside_the_allowlist() {
        let holder = PrivateJwk::parse(HOLDER_P256_JWK).expect("holder");
        let now = 1_700_000_000;

        for parameter in ["crit", "jku", "x5u", "cty"] {
            let mut header = oid4vci_proof_header(&holder);
            header[parameter] = json!("attacker-controlled");
            let proof = sign_compact(&holder, header, &oid4vci_proof_payload(now));

            let err = validate_oid4vci_proof_jwt(&proof, &oid4vci_proof_policy(), now)
                .expect_err("header parameter outside the allowlist is rejected");

            assert!(
                matches!(err, SdJwtError::Oid4vciProofInvalid),
                "header parameter {parameter} must be rejected"
            );
        }
    }

    #[test]
    fn oid4vci_proof_jwt_compares_nonce_and_audience_and_bounds_iat() {
        let holder = PrivateJwk::parse(HOLDER_P256_JWK).expect("holder");
        let now = 1_700_000_000;

        let mut wrong_nonce = oid4vci_proof_payload(now);
        wrong_nonce["nonce"] = json!("stale-c-nonce");
        let proof = sign_compact(&holder, oid4vci_proof_header(&holder), &wrong_nonce);
        validate_oid4vci_proof_jwt(&proof, &oid4vci_proof_policy(), now)
            .expect_err("nonce mismatch rejects");

        let mut wrong_aud = oid4vci_proof_payload(now);
        wrong_aud["aud"] = json!("https://other-issuer.example/credentials");
        let proof = sign_compact(&holder, oid4vci_proof_header(&holder), &wrong_aud);
        validate_oid4vci_proof_jwt(&proof, &oid4vci_proof_policy(), now)
            .expect_err("audience mismatch rejects");

        let stale = sign_compact(
            &holder,
            oid4vci_proof_header(&holder),
            &oid4vci_proof_payload(now - 301),
        );
        validate_oid4vci_proof_jwt(&stale, &oid4vci_proof_policy(), now)
            .expect_err("iat older than max_age rejects");

        let baseline = sign_compact(
            &holder,
            oid4vci_proof_header(&holder),
            &oid4vci_proof_payload(0),
        );
        let err = validate_oid4vci_proof_jwt(&baseline, &oid4vci_proof_policy(), i64::MIN)
            .expect_err("time arithmetic must fail visibly");
        assert!(matches!(err, SdJwtError::InvalidInput));
    }

    #[test]
    fn oid4vci_proof_debug_never_exposes_the_issuer_challenge() {
        let holder = PrivateJwk::parse(HOLDER_P256_JWK).expect("holder");
        let now = 1_700_000_000;
        let proof = sign_compact(
            &holder,
            oid4vci_proof_header(&holder),
            &oid4vci_proof_payload(now),
        );
        let claims =
            validate_oid4vci_proof_jwt(&proof, &oid4vci_proof_policy(), now).expect("validates");

        let policy_debug = format!("{:?}", oid4vci_proof_policy());
        let claims_debug = format!("{claims:?}");

        assert!(!policy_debug.contains("c-nonce-value"));
        assert!(!claims_debug.contains("c-nonce-value"));
        assert!(policy_debug.contains("Oid4vciProofPolicy"));
        assert!(claims_debug.contains("Oid4vciProofClaims"));
    }

    fn split_rfc_9901_presentation() -> (&'static str, &'static str) {
        let boundary = RFC_9901_PRESENTATION
            .rfind('~')
            .expect("presentation carries a key-binding jwt");
        (
            &RFC_9901_PRESENTATION[..=boundary],
            &RFC_9901_PRESENTATION[boundary + 1..],
        )
    }

    fn key_binding_header() -> Value {
        json!({"alg": "ES256", "typ": "kb+jwt"})
    }

    fn key_binding_payload(iat: i64) -> Value {
        json!({
            "nonce": "verifier-challenge",
            "aud": "https://verifier.example/rp",
            "iat": iat,
            "sd_hash": URL_SAFE_NO_PAD.encode(presentation_disclosure_hash(SD_HASH_INPUT)),
        })
    }

    fn key_binding_policy() -> KeyBindingPolicy {
        KeyBindingPolicy {
            audience: "https://verifier.example/rp".to_string(),
            nonce: "verifier-challenge".to_string(),
            max_age: Duration::from_secs(300),
            max_future_skew: Duration::from_secs(30),
        }
    }

    fn key_binding_confirmation(holder: &PrivateJwk) -> HolderConfirmation {
        HolderConfirmation {
            jwk: holder.public(),
            kid: None,
        }
    }

    fn oid4vci_proof_header(holder: &PrivateJwk) -> Value {
        json!({
            "alg": "ES256",
            "typ": "openid4vci-proof+jwt",
            "jwk": holder.public(),
        })
    }

    fn oid4vci_proof_payload(iat: i64) -> Value {
        json!({
            "aud": "https://issuer.example/credentials",
            "iat": iat,
            "nonce": "c-nonce-value",
        })
    }

    fn oid4vci_proof_policy() -> Oid4vciProofPolicy {
        Oid4vciProofPolicy {
            audience: "https://issuer.example/credentials".to_string(),
            nonce: "c-nonce-value".to_string(),
            max_age: Duration::from_secs(300),
            max_future_skew: Duration::from_secs(30),
        }
    }

    fn sign_compact(jwk: &PrivateJwk, header: Value, payload: &Value) -> String {
        sign_jwt_with_private(header, payload.clone(), jwk).expect("compact jwt signs")
    }

    fn sign_raw_compact(jwk: &PrivateJwk, header: Value, payload_json: &str) -> String {
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header json"));
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = sign_with_private_jwk(signing_input.as_bytes(), jwk).expect("signs");
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    fn issue_input(cnf: Option<HolderConfirmation>) -> SdJwtIssuanceInput {
        SdJwtIssuanceInput {
            iss: "did:web:issuer.test".to_string(),
            sub_ref: "did:example:subject".to_string(),
            credential_id: None,
            iat: 1_700_000_000,
            exp: 1_700_000_600,
            vct: "https://vct.example/test".to_string(),
            status: None,
            public_claims: BTreeMap::new(),
            cnf,
            disclosures: Vec::new(),
            object_disclosures: Vec::new(),
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
