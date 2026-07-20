// SPDX-License-Identifier: Apache-2.0
//! Notary-issued JWT primitives for the pre-authorized-code OID4VCI flow.
//!
//! Two token classes are minted with the dedicated access-token signing key
//! (never the SD-JWT VC credential-signing key):
//!
//! - The `pre-authorized_code`: a short-TTL JWT carrying a `jti` for single-use
//!   tracking and the eSignet-verified subject claims, handed to the wallet
//!   inside the credential offer.
//! - The Notary access token: redeemed at the token endpoint and accepted by
//!   the existing credential-endpoint consumers unchanged. Its `iss`/`aud`/`typ`
//!   and alg pin the second verifier's trust anchor; its claim set reproduces
//!   what an eSignet token would carry so subject binding, audience, and
//!   subject-access classification pass identically.
//!
//! The verify helpers here are sufficient for unit-testing the mint/verify
//! round-trip. PR3 wires the real middleware verification via the platform
//! `TokenVerifier`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use registry_platform_crypto::{verify as verify_signature, PublicJwk, SigningProvider};
use serde_json::{Map, Value};
use std::fmt;

use crate::error::EvidenceError;

/// JWT `alg` (and signing-key alg) for Notary-issued tokens.
pub const NOTARY_TOKEN_SIGNING_ALG: &str = "EdDSA";

/// Default header `typ` for the `pre-authorized_code` JWT.
pub const PRE_AUTHORIZED_CODE_JWT_TYP: &str = "registry-notary-preauth-code+jwt";

/// Default header `typ` for the Notary access token.
pub const NOTARY_ACCESS_TOKEN_JWT_TYP: &str = "registry-notary-access+jwt";

/// Header `typ` for Notary transaction tokens minted by the platform STS.
pub const NOTARY_TRANSACTION_TOKEN_JWT_TYP: &str = "at+jwt";
pub const NOTARY_AUTHORIZATION_DETAILS_TYPE: &str = "registry_notary_evidence_transaction";
pub const NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION: &str =
    "registry-notary-authorization-details/v1";

/// The eSignet-verified subject the Notary binds a pre-authorized code and the
/// resulting access token to. Captured at the offer callback.
///
/// `subject_binding_value` (the civil ID identified by `subject_binding_claim`)
/// is load-bearing: the credential endpoint attests the claim for this subject.
#[derive(Clone)]
pub struct BoundSubject {
    /// Token `sub`.
    pub subject: String,
    /// Claim name holding the civil ID (e.g.
    /// `subject_access.subject_binding.token_claim`).
    pub subject_binding_claim: String,
    /// The civil ID value, reproduced exactly from the eSignet id_token.
    pub subject_binding_value: String,
    /// Citizen `client_id` mapped to an allowed citizen client.
    pub client_id: String,
    /// OAuth scopes; must include the subject-access required scopes.
    pub scopes: Vec<String>,
    /// Assurance level (`acr`), if present.
    pub acr: Option<String>,
    /// Authentication time (`auth_time`), if present.
    pub auth_time: Option<i64>,
}

impl fmt::Debug for BoundSubject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundSubject")
            .field("subject", &"[redacted]")
            .field("subject_binding_claim", &self.subject_binding_claim)
            .field("subject_binding_value", &"[redacted]")
            .field("client_id", &self.client_id)
            .field("scopes", &self.scopes)
            .field("acr", &self.acr)
            .field("auth_time", &self.auth_time)
            .finish()
    }
}

/// Inputs for minting a `pre-authorized_code` JWT.
#[derive(Clone, Debug)]
pub struct PreAuthorizedCodeClaims {
    /// Notary token issuer (`iss`).
    pub issuer: String,
    /// Single-use identifier tracked in the replay store by PR3 (`jti`).
    pub jti: String,
    /// Selected credential configuration the code is bound to.
    pub credential_configuration_id: String,
    /// Opaque identifier of the immutable registry-backed issuance transaction.
    pub issuance_transaction_id: String,
    /// Versioned commitment over the authority-bearing transaction fields.
    pub issuance_transaction_commitment: String,
    /// Whether this individual code requires the holder-presented transaction
    /// code advertised with its credential offer.
    pub tx_code_required: bool,
    /// eSignet-verified subject claims carried into the code.
    pub subject: BoundSubject,
    /// Issued-at (unix seconds).
    pub iat: i64,
    /// Expiry (unix seconds).
    pub exp: i64,
}

/// Inputs for minting a Notary access token.
#[derive(Clone, Debug)]
pub struct AccessTokenClaims {
    /// Notary token issuer (`iss`); must equal the second verifier's pinned
    /// issuer.
    pub issuer: String,
    /// Optional JWT id (`jti`) for transaction-token replay protection.
    pub jti: Option<String>,
    /// Accepted audiences (`aud`); must satisfy
    /// `oid4vci.accepted_token_audiences` and
    /// `subject_access.citizen_clients.allowed_audiences`.
    pub audiences: Vec<String>,
    /// Token-type claim surfaced to the credential endpoint.
    pub token_type: String,
    /// Credential configuration the token is scoped to.
    pub credential_configuration_id: String,
    /// Opaque identifier of the immutable registry-backed issuance transaction.
    pub issuance_transaction_id: String,
    /// Versioned commitment copied from the pre-authorized code transaction.
    pub issuance_transaction_commitment: String,
    /// eSignet-verified subject claims.
    pub subject: BoundSubject,
    /// OAuth 2.0 Rich Authorization Requests-shaped authorization details.
    pub authorization_details: Vec<Value>,
    /// Sender constraint confirmation (`cnf`) copied from the verified subject
    /// token when the deployment profile requires sender-constrained tokens.
    pub confirmation: Option<Value>,
    /// Verified assisted-access actor envelope. Public responses must not copy
    /// this wholesale; it is for restricted audit/evaluation records.
    pub actor: Option<Value>,
    /// Issued-at (unix seconds).
    pub iat: i64,
    /// Expiry (unix seconds).
    pub exp: i64,
}

/// A minted, signed Notary JWT. The compact form is a secret (it is a bearer
/// token), so its `Debug` redacts it.
#[derive(Clone)]
pub struct SignedNotaryToken {
    /// Header `typ`.
    pub typ: String,
    /// `jti` for the pre-authorized code; `None` for access tokens.
    pub jti: Option<String>,
    /// Compact `header.payload.signature` JWT.
    pub compact: String,
}

impl fmt::Debug for SignedNotaryToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedNotaryToken")
            .field("typ", &self.typ)
            .field("jti", &self.jti)
            .field("compact", &"[redacted]")
            .finish()
    }
}

/// Mint a signed `pre-authorized_code` JWT with the access-token signing key.
pub async fn mint_pre_authorized_code(
    signer: &dyn SigningProvider,
    typ: &str,
    claims: &PreAuthorizedCodeClaims,
) -> Result<SignedNotaryToken, EvidenceError> {
    let mut payload = Map::new();
    payload.insert("iss".to_string(), Value::String(claims.issuer.clone()));
    payload.insert("jti".to_string(), Value::String(claims.jti.clone()));
    payload.insert(
        "credential_configuration_id".to_string(),
        Value::String(claims.credential_configuration_id.clone()),
    );
    payload.insert(
        "issuance_transaction_id".to_string(),
        Value::String(claims.issuance_transaction_id.clone()),
    );
    payload.insert(
        "issuance_transaction_commitment".to_string(),
        Value::String(claims.issuance_transaction_commitment.clone()),
    );
    payload.insert(
        "tx_code_required".to_string(),
        Value::Bool(claims.tx_code_required),
    );
    payload.insert("iat".to_string(), Value::from(claims.iat));
    payload.insert("nbf".to_string(), Value::from(claims.iat));
    payload.insert("exp".to_string(), Value::from(claims.exp));
    insert_subject_claims(&mut payload, &claims.subject)?;
    let compact = sign_compact_jwt(signer, typ, Value::Object(payload)).await?;
    Ok(SignedNotaryToken {
        typ: typ.to_string(),
        jti: Some(claims.jti.clone()),
        compact,
    })
}

/// Mint a signed Notary access token with the access-token signing key.
///
/// The claim set is the security-critical contract consumed unchanged by the
/// credential endpoint: `iss`, `aud`, `sub`, `client_id`, `token_type`,
/// `scope`, the subject-binding claim, `acr`/`auth_time`, and `iat`/`nbf`/`exp`.
pub async fn mint_access_token(
    signer: &dyn SigningProvider,
    typ: &str,
    claims: &AccessTokenClaims,
) -> Result<SignedNotaryToken, EvidenceError> {
    let mut payload = Map::new();
    payload.insert("iss".to_string(), Value::String(claims.issuer.clone()));
    if let Some(jti) = &claims.jti {
        payload.insert("jti".to_string(), Value::String(jti.clone()));
    }
    payload.insert("aud".to_string(), audience_value(&claims.audiences));
    payload.insert(
        "token_type".to_string(),
        Value::String(claims.token_type.clone()),
    );
    payload.insert(
        "credential_configuration_id".to_string(),
        Value::String(claims.credential_configuration_id.clone()),
    );
    payload.insert(
        "issuance_transaction_id".to_string(),
        Value::String(claims.issuance_transaction_id.clone()),
    );
    payload.insert(
        "issuance_transaction_commitment".to_string(),
        Value::String(claims.issuance_transaction_commitment.clone()),
    );
    payload.insert("iat".to_string(), Value::from(claims.iat));
    payload.insert("nbf".to_string(), Value::from(claims.iat));
    payload.insert("exp".to_string(), Value::from(claims.exp));
    if !claims.authorization_details.is_empty() {
        payload.insert(
            "authorization_details".to_string(),
            Value::Array(claims.authorization_details.clone()),
        );
    }
    if let Some(cnf) = &claims.confirmation {
        payload.insert("cnf".to_string(), cnf.clone());
    }
    if let Some(actor) = &claims.actor {
        payload.insert("act".to_string(), actor.clone());
    }
    insert_subject_claims(&mut payload, &claims.subject)?;
    let compact = sign_compact_jwt(signer, typ, Value::Object(payload)).await?;
    Ok(SignedNotaryToken {
        typ: typ.to_string(),
        jti: None,
        compact,
    })
}

/// The decoded header and payload of a verified Notary token, exposed so unit
/// tests can assert on the exact claim set.
#[derive(Clone, Debug)]
pub struct VerifiedNotaryToken {
    pub header: Value,
    pub payload: Value,
}

impl VerifiedNotaryToken {
    #[must_use]
    pub fn claim_str(&self, name: &str) -> Option<&str> {
        self.payload.get(name).and_then(Value::as_str)
    }

    #[must_use]
    pub fn claim_i64(&self, name: &str) -> Option<i64> {
        self.payload.get(name).and_then(Value::as_i64)
    }

    /// Space-separated `scope` claim split into individual scopes. Empty
    /// segments (from leading, trailing, or repeated spaces) are dropped.
    #[must_use]
    pub fn scopes(&self) -> Vec<String> {
        self.claim_str("scope")
            .map(|scope| {
                scope
                    .split(' ')
                    .filter(|segment| !segment.is_empty())
                    .map(ToString::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Verify a Notary token against the access-token signing key's public JWK.
///
/// Enforces: header alg in the allow-list, the expected `typ`, signature,
/// `iss` exactly equal, `aud` membership (when expected audiences are given),
/// and `exp`/`nbf` against `now`. This mirrors what PR3's middleware verifier
/// pins and is sufficient for the unit-test round-trip. Every failure collapses
/// to `EvidenceError::MissingCredential`, matching the middleware's no-info-leak
/// failure mapping.
pub fn verify_notary_token(
    compact: &str,
    public_jwk: &PublicJwk,
    expected_typ: &str,
    expected_issuer: &str,
    expected_audiences: &[String],
    now: i64,
) -> Result<VerifiedNotaryToken, EvidenceError> {
    let (header_b64, payload_b64, signature_b64) = split_compact(compact)?;
    // Verify the signature over the raw segments BEFORE decoding any JSON, so a
    // malformed or hostile header/payload never reaches the JSON parser on an
    // unauthenticated token. The expected key is supplied by the caller, so the
    // header is not needed to locate it; the key fixes the algorithm.
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| EvidenceError::MissingCredential)?;
    verify_signature(signing_input.as_bytes(), &signature, public_jwk)
        .map_err(|_| EvidenceError::MissingCredential)?;
    let header = decode_segment_json(header_b64)?;
    if header.get("alg").and_then(Value::as_str) != Some(NOTARY_TOKEN_SIGNING_ALG) {
        return Err(EvidenceError::MissingCredential);
    }
    if header.get("typ").and_then(Value::as_str) != Some(expected_typ) {
        return Err(EvidenceError::MissingCredential);
    }
    if expected_typ == NOTARY_TRANSACTION_TOKEN_JWT_TYP
        && header
            .get("kid")
            .and_then(Value::as_str)
            .map(str::is_empty)
            .unwrap_or(true)
    {
        return Err(EvidenceError::MissingCredential);
    }
    let payload = decode_segment_json(payload_b64)?;
    if expected_typ == NOTARY_TRANSACTION_TOKEN_JWT_TYP {
        require_nonempty_claim(&payload, "jti")?;
        require_nonempty_claim(&payload, "sub")?;
        require_nonempty_claim(&payload, "scope")?;
        require_authorization_details(&payload)?;
        if payload.get("cnf").is_some() {
            return Err(EvidenceError::MissingCredential);
        }
    }
    if payload.get("iss").and_then(Value::as_str) != Some(expected_issuer) {
        return Err(EvidenceError::MissingCredential);
    }
    if !expected_audiences.is_empty() && !audience_matches(&payload, expected_audiences) {
        return Err(EvidenceError::MissingCredential);
    }
    let exp = payload
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(EvidenceError::MissingCredential)?;
    if now >= exp {
        return Err(EvidenceError::MissingCredential);
    }
    if let Some(nbf) = payload.get("nbf").and_then(Value::as_i64) {
        if now < nbf {
            return Err(EvidenceError::MissingCredential);
        }
    }
    Ok(VerifiedNotaryToken { header, payload })
}

/// Claim names the Notary tokens already populate. A configured
/// `subject_binding_claim` must not collide with any of these, or inserting it
/// would overwrite a standard or required claim (`iss`/`aud`/`exp`/...).
const RESERVED_TOKEN_CLAIMS: &[&str] = &[
    "iss",
    "sub",
    "aud",
    "exp",
    "nbf",
    "iat",
    "jti",
    "authorization_details",
    "cnf",
    "act",
    "scope",
    "client_id",
    "token_type",
    "credential_configuration_id",
    "issuance_transaction_id",
    "issuance_transaction_commitment",
    "tx_code_required",
    "acr",
    "auth_time",
];

fn insert_subject_claims(
    payload: &mut Map<String, Value>,
    subject: &BoundSubject,
) -> Result<(), EvidenceError> {
    // A subject-binding claim configured to a reserved/emitted claim name would
    // overwrite it (e.g. clobbering `aud` with the civil ID). Refuse to mint
    // rather than emit a malformed token.
    if RESERVED_TOKEN_CLAIMS.contains(&subject.subject_binding_claim.as_str()) {
        return Err(EvidenceError::CredentialIssuanceFailed);
    }
    payload.insert("sub".to_string(), Value::String(subject.subject.clone()));
    payload.insert(
        "client_id".to_string(),
        Value::String(subject.client_id.clone()),
    );
    payload.insert("scope".to_string(), Value::String(subject.scopes.join(" ")));
    // The subject-binding claim (the civil ID) is load-bearing: the credential
    // endpoint reads it to identify whose status is attested.
    payload.insert(
        subject.subject_binding_claim.clone(),
        Value::String(subject.subject_binding_value.clone()),
    );
    if let Some(acr) = &subject.acr {
        payload.insert("acr".to_string(), Value::String(acr.clone()));
    }
    if let Some(auth_time) = subject.auth_time {
        payload.insert("auth_time".to_string(), Value::from(auth_time));
    }
    Ok(())
}

fn require_nonempty_claim(payload: &Value, name: &str) -> Result<(), EvidenceError> {
    if payload
        .get(name)
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
    {
        return Ok(());
    }
    Err(EvidenceError::MissingCredential)
}

fn require_authorization_details(payload: &Value) -> Result<(), EvidenceError> {
    let Some(details) = payload
        .get("authorization_details")
        .and_then(Value::as_array)
    else {
        return Err(EvidenceError::MissingCredential);
    };
    let has_matching_detail = details.iter().filter_map(Value::as_object).any(|detail| {
        detail.get("type").and_then(Value::as_str) == Some(NOTARY_AUTHORIZATION_DETAILS_TYPE)
            && detail.get("schema_version").and_then(Value::as_str)
                == Some(NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION)
    });
    if !has_matching_detail {
        return Err(EvidenceError::MissingCredential);
    }
    Ok(())
}

fn audience_value(audiences: &[String]) -> Value {
    if audiences.len() == 1 {
        Value::String(audiences[0].clone())
    } else {
        Value::Array(audiences.iter().cloned().map(Value::String).collect())
    }
}

fn audience_matches(payload: &Value, expected: &[String]) -> bool {
    match payload.get("aud") {
        Some(Value::String(aud)) => expected.iter().any(|candidate| candidate == aud),
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .any(|aud| expected.iter().any(|candidate| candidate.as_str() == aud)),
        _ => false,
    }
}

async fn sign_compact_jwt(
    signer: &dyn SigningProvider,
    typ: &str,
    payload: Value,
) -> Result<String, EvidenceError> {
    let public_jwk = signer.public_jwk();
    let kid = public_jwk
        .kid
        .clone()
        .filter(|kid| kid == signer.key_id())
        .ok_or(EvidenceError::CredentialIssuanceFailed)?;
    let header = serde_json::json!({
        "alg": NOTARY_TOKEN_SIGNING_ALG,
        "typ": typ,
        "kid": kid,
    });
    let header_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).map_err(|_| EvidenceError::CredentialIssuanceFailed)?);
    let payload_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&payload).map_err(|_| EvidenceError::CredentialIssuanceFailed)?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signer
        .sign(signing_input.as_bytes())
        .await
        .map_err(|_| EvidenceError::CredentialIssuanceFailed)?;
    // Self-check so a misbehaving signer cannot emit an unverifiable token.
    verify_signature(signing_input.as_bytes(), &signature, &public_jwk)
        .map_err(|_| EvidenceError::CredentialIssuanceFailed)?;
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

fn split_compact(compact: &str) -> Result<(&str, &str, &str), EvidenceError> {
    let mut parts = compact.split('.');
    let header = parts.next().ok_or(EvidenceError::MissingCredential)?;
    let payload = parts.next().ok_or(EvidenceError::MissingCredential)?;
    let signature = parts.next().ok_or(EvidenceError::MissingCredential)?;
    if parts.next().is_some() || header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(EvidenceError::MissingCredential);
    }
    Ok((header, payload, signature))
}

fn decode_segment_json(segment: &str) -> Result<Value, EvidenceError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| EvidenceError::MissingCredential)?;
    serde_json::from_slice(&bytes).map_err(|_| EvidenceError::MissingCredential)
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_crypto::{LocalJwkSigner, PrivateJwk};

    // Stands in for the dedicated access-token signing key.
    const ACCESS_TOKEN_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;
    // Stands in for the SD-JWT VC credential-signing key (a different key).
    const CREDENTIAL_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"f4QIxnAyRWzhuBOmNRgvBTE56mWePdsPL0mvCtl8Gys","x":"pv4e_hXHBLN27rcs6VDFV1ED0TiU8M3xy9vsuWFEsec","alg":"EdDSA"}"#;

    const ISSUER: &str = "http://127.0.0.1:4325";
    const AUDIENCE: &str = "http://127.0.0.1:4325";
    const SUBJECT_BINDING_CLAIM: &str = "https://id.example.gov/claims/national_id";
    const CIVIL_ID: &str = "NAT-123456";
    const NOW: i64 = 1_700_000_000;

    fn signer(raw: &str, kid: &str) -> LocalJwkSigner {
        let mut jwk = PrivateJwk::parse(raw).expect("test JWK parses");
        jwk.kid = Some(kid.to_string());
        jwk.alg = Some(NOTARY_TOKEN_SIGNING_ALG.to_string());
        LocalJwkSigner::new(jwk).expect("local signer builds")
    }

    fn access_token_signer() -> LocalJwkSigner {
        signer(ACCESS_TOKEN_JWK, "did:web:issuer.example#access-token-key")
    }

    fn credential_signer() -> LocalJwkSigner {
        signer(CREDENTIAL_JWK, "did:web:issuer.example#credential-key")
    }

    fn bound_subject() -> BoundSubject {
        BoundSubject {
            subject: "citizen-subject-1".to_string(),
            subject_binding_claim: SUBJECT_BINDING_CLAIM.to_string(),
            subject_binding_value: CIVIL_ID.to_string(),
            client_id: "registry-lab-live-client".to_string(),
            scopes: vec!["openid".to_string(), "subject_access".to_string()],
            acr: Some("urn:example:loa:substantial".to_string()),
            auth_time: Some(NOW - 30),
        }
    }

    fn access_token_claims() -> AccessTokenClaims {
        AccessTokenClaims {
            issuer: ISSUER.to_string(),
            jti: None,
            audiences: vec![AUDIENCE.to_string()],
            token_type: "Bearer".to_string(),
            credential_configuration_id: "date_of_birth_sd_jwt".to_string(),
            issuance_transaction_id: "transaction-123".to_string(),
            issuance_transaction_commitment: "sha256:transaction".to_string(),
            subject: bound_subject(),
            authorization_details: Vec::new(),
            confirmation: None,
            actor: None,
            iat: NOW,
            exp: NOW + 300,
        }
    }

    fn transaction_token_claims() -> AccessTokenClaims {
        AccessTokenClaims {
            issuer: ISSUER.to_string(),
            jti: Some("01J0000000000000000000TXN1".to_string()),
            audiences: vec![AUDIENCE.to_string()],
            token_type: "Bearer".to_string(),
            credential_configuration_id: "date_of_birth_sd_jwt".to_string(),
            issuance_transaction_id: "transaction-123".to_string(),
            issuance_transaction_commitment: "sha256:transaction".to_string(),
            subject: bound_subject(),
            authorization_details: vec![serde_json::json!({
                "type": NOTARY_AUTHORIZATION_DETAILS_TYPE,
                "schema_version": NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION,
                "actions": ["evaluate"],
                "locations": [AUDIENCE],
            })],
            confirmation: None,
            actor: Some(serde_json::json!({
                "actor_id_hash": "hmac-sha256:actor",
                "assurance": "workforce-login",
                "delegation_ref": "delegation-123",
            })),
            iat: NOW,
            exp: NOW + 300,
        }
    }

    fn pre_authorized_code_claims() -> PreAuthorizedCodeClaims {
        PreAuthorizedCodeClaims {
            issuer: ISSUER.to_string(),
            jti: "01J0000000000000000000PREAU".to_string(),
            credential_configuration_id: "date_of_birth_sd_jwt".to_string(),
            issuance_transaction_id: "01J0000000000000000000PREAU".to_string(),
            issuance_transaction_commitment: "sha256:transaction".to_string(),
            tx_code_required: true,
            subject: bound_subject(),
            iat: NOW,
            exp: NOW + 120,
        }
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds")
            .block_on(future)
    }

    #[test]
    fn access_token_round_trip_carries_full_required_claim_set() {
        let signer = access_token_signer();
        let token = block_on(mint_access_token(
            &signer,
            NOTARY_ACCESS_TOKEN_JWT_TYP,
            &access_token_claims(),
        ))
        .expect("access token mints");
        assert!(token.jti.is_none());

        let verified = verify_notary_token(
            &token.compact,
            &signer.public_jwk(),
            NOTARY_ACCESS_TOKEN_JWT_TYP,
            ISSUER,
            &[AUDIENCE.to_string()],
            NOW + 1,
        )
        .expect("access token verifies");

        // Header: alg + the distinct access-token typ + the access-token kid.
        assert_eq!(verified.header["alg"], NOTARY_TOKEN_SIGNING_ALG);
        assert_eq!(verified.header["typ"], NOTARY_ACCESS_TOKEN_JWT_TYP);
        assert_eq!(
            verified.header["kid"],
            "did:web:issuer.example#access-token-key"
        );

        // iss: pinned by the second verifier (standalone.rs authenticate_oidc).
        assert_eq!(verified.claim_str("iss"), Some(ISSUER));
        // aud: require_oid4vci_token_audience (api.rs:2296) + citizen audience.
        assert_eq!(verified.payload["aud"], AUDIENCE);
        // sub + subject_binding claim: oid4vci_bound_subject (api.rs:2317) and
        // bounded_verified_claims_from_oidc (standalone.rs:2437).
        assert_eq!(verified.claim_str("sub"), Some("citizen-subject-1"));
        assert_eq!(verified.claim_str(SUBJECT_BINDING_CLAIM), Some(CIVIL_ID));
        // client_id + scope: classify_subject_access_principal (api.rs:2585).
        assert_eq!(
            verified.claim_str("client_id"),
            Some("registry-lab-live-client")
        );
        assert_eq!(
            verified.scopes(),
            vec!["openid".to_string(), "subject_access".to_string()]
        );
        // token_type, acr, auth_time, exp, iat, nbf: BoundedVerifiedClaims.
        assert_eq!(verified.claim_str("token_type"), Some("Bearer"));
        assert_eq!(
            verified.claim_str("acr"),
            Some("urn:example:loa:substantial")
        );
        assert_eq!(verified.claim_i64("auth_time"), Some(NOW - 30));
        assert_eq!(verified.claim_i64("iat"), Some(NOW));
        assert_eq!(verified.claim_i64("nbf"), Some(NOW));
        assert_eq!(verified.claim_i64("exp"), Some(NOW + 300));
        assert_eq!(
            verified.claim_str("credential_configuration_id"),
            Some("date_of_birth_sd_jwt")
        );
    }

    #[test]
    fn pre_authorized_code_round_trip_carries_jti_subject_and_tx_code_requirement() {
        let signer = access_token_signer();
        let claims = pre_authorized_code_claims();
        let token = block_on(mint_pre_authorized_code(
            &signer,
            PRE_AUTHORIZED_CODE_JWT_TYP,
            &claims,
        ))
        .expect("pre-authorized code mints");
        assert_eq!(token.jti.as_deref(), Some(claims.jti.as_str()));

        let verified = verify_notary_token(
            &token.compact,
            &signer.public_jwk(),
            PRE_AUTHORIZED_CODE_JWT_TYP,
            ISSUER,
            &[],
            NOW + 1,
        )
        .expect("pre-authorized code verifies");

        assert_eq!(verified.header["typ"], PRE_AUTHORIZED_CODE_JWT_TYP);
        assert_eq!(verified.claim_str("jti"), Some(claims.jti.as_str()));
        assert_eq!(verified.claim_str("sub"), Some("citizen-subject-1"));
        assert_eq!(verified.claim_str(SUBJECT_BINDING_CLAIM), Some(CIVIL_ID));
        assert_eq!(
            verified.claim_str("credential_configuration_id"),
            Some("date_of_birth_sd_jwt")
        );
        assert_eq!(verified.payload["tx_code_required"], true);
    }

    #[test]
    fn transaction_token_round_trip_requires_jti_authz_details_and_actor() {
        let signer = access_token_signer();
        let claims = transaction_token_claims();
        let token = block_on(mint_access_token(
            &signer,
            NOTARY_TRANSACTION_TOKEN_JWT_TYP,
            &claims,
        ))
        .expect("transaction token mints");

        let verified = verify_notary_token(
            &token.compact,
            &signer.public_jwk(),
            NOTARY_TRANSACTION_TOKEN_JWT_TYP,
            ISSUER,
            &[AUDIENCE.to_string()],
            NOW + 1,
        )
        .expect("transaction token verifies");

        assert_eq!(verified.header["typ"], NOTARY_TRANSACTION_TOKEN_JWT_TYP);
        assert_eq!(
            verified.header["kid"],
            "did:web:issuer.example#access-token-key"
        );
        assert_eq!(
            verified.claim_str("jti"),
            Some("01J0000000000000000000TXN1")
        );
        assert!(verified.payload.get("cnf").is_none());
        assert_eq!(
            verified.payload["authorization_details"][0]["type"],
            NOTARY_AUTHORIZATION_DETAILS_TYPE
        );
        assert_eq!(
            verified.payload["authorization_details"][0]["schema_version"],
            NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION
        );
        assert_eq!(
            verified.payload["act"]["actor_id_hash"],
            "hmac-sha256:actor"
        );
        assert_eq!(verified.payload["act"]["delegation_ref"], "delegation-123");
    }

    #[test]
    fn transaction_token_accepts_matching_authorization_details_after_other_entries() {
        let signer = access_token_signer();
        let mut claims = transaction_token_claims();
        claims.authorization_details.insert(
            0,
            serde_json::json!({
                "type": "unrelated_authorization_detail",
                "schema_version": "example/v1",
            }),
        );
        let token = block_on(mint_access_token(
            &signer,
            NOTARY_TRANSACTION_TOKEN_JWT_TYP,
            &claims,
        ))
        .expect("transaction token mints");

        verify_notary_token(
            &token.compact,
            &signer.public_jwk(),
            NOTARY_TRANSACTION_TOKEN_JWT_TYP,
            ISSUER,
            &[AUDIENCE.to_string()],
            NOW + 1,
        )
        .expect("matching authorization_details need not be first");
    }

    #[test]
    fn transaction_token_verify_rejects_unvalidated_sender_constraint() {
        let signer = access_token_signer();
        let claims = AccessTokenClaims {
            confirmation: Some(serde_json::json!({"jkt": "sender-key-thumbprint"})),
            ..transaction_token_claims()
        };
        let token = block_on(mint_access_token(
            &signer,
            NOTARY_TRANSACTION_TOKEN_JWT_TYP,
            &claims,
        ))
        .expect("transaction token mints");

        let error = verify_notary_token(
            &token.compact,
            &signer.public_jwk(),
            NOTARY_TRANSACTION_TOKEN_JWT_TYP,
            ISSUER,
            &[AUDIENCE.to_string()],
            NOW + 1,
        )
        .expect_err("cnf without proof validation must be rejected");

        assert!(matches!(error, EvidenceError::MissingCredential));
    }

    #[test]
    fn transaction_token_verify_rejects_missing_authorization_details() {
        let signer = access_token_signer();
        let claims = AccessTokenClaims {
            authorization_details: Vec::new(),
            ..transaction_token_claims()
        };
        let token = block_on(mint_access_token(
            &signer,
            NOTARY_TRANSACTION_TOKEN_JWT_TYP,
            &claims,
        ))
        .expect("transaction token mints");

        let error = verify_notary_token(
            &token.compact,
            &signer.public_jwk(),
            NOTARY_TRANSACTION_TOKEN_JWT_TYP,
            ISSUER,
            &[AUDIENCE.to_string()],
            NOW + 1,
        )
        .expect_err("missing authorization_details must be rejected");

        assert!(matches!(error, EvidenceError::MissingCredential));
    }

    #[test]
    fn transaction_token_verify_rejects_wrong_authorization_details_type() {
        let signer = access_token_signer();
        let claims = AccessTokenClaims {
            authorization_details: vec![serde_json::json!({
                "type": "registry_notary_subject_access",
                "schema_version": NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION,
            })],
            ..transaction_token_claims()
        };
        let token = block_on(mint_access_token(
            &signer,
            NOTARY_TRANSACTION_TOKEN_JWT_TYP,
            &claims,
        ))
        .expect("transaction token mints");

        let error = verify_notary_token(
            &token.compact,
            &signer.public_jwk(),
            NOTARY_TRANSACTION_TOKEN_JWT_TYP,
            ISSUER,
            &[AUDIENCE.to_string()],
            NOW + 1,
        )
        .expect_err("wrong authorization_details type must be rejected");

        assert!(matches!(error, EvidenceError::MissingCredential));
    }

    #[test]
    fn verify_rejects_token_signed_by_a_different_key() {
        let access = access_token_signer();
        let credential = credential_signer();
        // Sign with the access-token key, then verify against the credential
        // key's public JWK.
        let token = block_on(mint_access_token(
            &access,
            NOTARY_ACCESS_TOKEN_JWT_TYP,
            &access_token_claims(),
        ))
        .expect("access token mints");

        let error = verify_notary_token(
            &token.compact,
            &credential.public_jwk(),
            NOTARY_ACCESS_TOKEN_JWT_TYP,
            ISSUER,
            &[AUDIENCE.to_string()],
            NOW + 1,
        )
        .expect_err("a token signed by a different key must be rejected");
        assert!(matches!(error, EvidenceError::MissingCredential));
    }

    #[test]
    fn verify_rejects_token_signed_by_the_credential_key() {
        // A token claiming the Notary issuer/typ but signed by the credential
        // key must not verify against the access-token public key.
        let credential = credential_signer();
        let access = access_token_signer();
        let token = block_on(mint_access_token(
            &credential,
            NOTARY_ACCESS_TOKEN_JWT_TYP,
            &access_token_claims(),
        ))
        .expect("token mints with the credential key");

        let error = verify_notary_token(
            &token.compact,
            &access.public_jwk(),
            NOTARY_ACCESS_TOKEN_JWT_TYP,
            ISSUER,
            &[AUDIENCE.to_string()],
            NOW + 1,
        )
        .expect_err("a credential-key-signed token must be rejected");
        assert!(matches!(error, EvidenceError::MissingCredential));
    }

    #[test]
    fn verify_rejects_wrong_typ() {
        let signer = access_token_signer();
        let token = block_on(mint_access_token(
            &signer,
            NOTARY_ACCESS_TOKEN_JWT_TYP,
            &access_token_claims(),
        ))
        .expect("access token mints");

        let error = verify_notary_token(
            &token.compact,
            &signer.public_jwk(),
            PRE_AUTHORIZED_CODE_JWT_TYP,
            ISSUER,
            &[AUDIENCE.to_string()],
            NOW + 1,
        )
        .expect_err("a token with the wrong typ must be rejected");
        assert!(matches!(error, EvidenceError::MissingCredential));
    }

    #[test]
    fn verify_rejects_wrong_issuer() {
        let signer = access_token_signer();
        let token = block_on(mint_access_token(
            &signer,
            NOTARY_ACCESS_TOKEN_JWT_TYP,
            &access_token_claims(),
        ))
        .expect("access token mints");

        let error = verify_notary_token(
            &token.compact,
            &signer.public_jwk(),
            NOTARY_ACCESS_TOKEN_JWT_TYP,
            "https://attacker.example",
            &[AUDIENCE.to_string()],
            NOW + 1,
        )
        .expect_err("a token with the wrong issuer must be rejected");
        assert!(matches!(error, EvidenceError::MissingCredential));
    }

    #[test]
    fn verify_rejects_wrong_audience() {
        let signer = access_token_signer();
        let token = block_on(mint_access_token(
            &signer,
            NOTARY_ACCESS_TOKEN_JWT_TYP,
            &access_token_claims(),
        ))
        .expect("access token mints");

        let error = verify_notary_token(
            &token.compact,
            &signer.public_jwk(),
            NOTARY_ACCESS_TOKEN_JWT_TYP,
            ISSUER,
            &["https://other.example".to_string()],
            NOW + 1,
        )
        .expect_err("a token with no accepted audience must be rejected");
        assert!(matches!(error, EvidenceError::MissingCredential));
    }

    #[test]
    fn verify_rejects_expired_token() {
        let signer = access_token_signer();
        let token = block_on(mint_access_token(
            &signer,
            NOTARY_ACCESS_TOKEN_JWT_TYP,
            &access_token_claims(),
        ))
        .expect("access token mints");

        let error = verify_notary_token(
            &token.compact,
            &signer.public_jwk(),
            NOTARY_ACCESS_TOKEN_JWT_TYP,
            ISSUER,
            &[AUDIENCE.to_string()],
            NOW + 301,
        )
        .expect_err("an expired token must be rejected");
        assert!(matches!(error, EvidenceError::MissingCredential));
    }

    #[test]
    fn signed_token_debug_redacts_compact() {
        let signer = access_token_signer();
        let token = block_on(mint_access_token(
            &signer,
            NOTARY_ACCESS_TOKEN_JWT_TYP,
            &access_token_claims(),
        ))
        .expect("access token mints");
        let debug = format!("{token:?}");

        assert!(debug.contains("SignedNotaryToken"));
        assert!(debug.contains(NOTARY_ACCESS_TOKEN_JWT_TYP));
        assert!(!debug.contains(&token.compact));
    }

    #[test]
    fn bound_subject_debug_redacts_subject_and_civil_id() {
        let subject = bound_subject();
        let debug = format!("{subject:?}");

        assert!(debug.contains("BoundSubject"));
        assert!(debug.contains(SUBJECT_BINDING_CLAIM));
        assert!(!debug.contains("citizen-subject-1"));
        assert!(!debug.contains(CIVIL_ID));
    }

    #[test]
    fn pre_authorized_code_claims_debug_does_not_render_civil_id() {
        let claims = pre_authorized_code_claims();
        let debug = format!("{claims:?}");

        // The derived Debug recurses into BoundSubject's redacting Debug.
        assert!(!debug.contains("citizen-subject-1"));
        assert!(!debug.contains(CIVIL_ID));
    }

    #[test]
    fn mint_rejects_subject_binding_claim_colliding_with_a_reserved_claim() {
        // A subject_binding_claim configured to a reserved/emitted claim name
        // would overwrite that claim; minting must fail loudly instead.
        for &reserved in RESERVED_TOKEN_CLAIMS {
            let mut subject = bound_subject();
            subject.subject_binding_claim = reserved.to_string();
            let claims = AccessTokenClaims {
                subject,
                ..access_token_claims()
            };
            let error = block_on(mint_access_token(
                &access_token_signer(),
                NOTARY_ACCESS_TOKEN_JWT_TYP,
                &claims,
            ))
            .expect_err("a reserved subject-binding claim must be rejected");
            assert!(matches!(error, EvidenceError::CredentialIssuanceFailed));
        }
    }
}
