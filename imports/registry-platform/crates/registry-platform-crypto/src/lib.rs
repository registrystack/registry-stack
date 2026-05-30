// SPDX-License-Identifier: Apache-2.0
//! Crypto primitives shared by Registry Platform consumers.

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use thiserror::Error;
use url::{Host, Url};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// Ed25519 EdDSA signatures using OKP/Ed25519 JWKs.
    ///
    /// This crate currently supports only EdDSA for signing and verification.
    /// ES256, RS256, and PS256 JWKs are rejected as unsupported at parse time.
    EdDsa,
}

#[derive(Clone, Deserialize)]
pub struct PrivateJwk {
    pub kty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
}

impl fmt::Debug for PrivateJwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateJwk")
            .field("kty", &self.kty)
            .field("kid", &self.kid)
            .field("alg", &self.alg)
            .field("crv", &self.crv)
            .field("d", &self.d.as_ref().map(|_| "[redacted]"))
            .field("x", &self.x)
            .field("y", &self.y)
            .field("n", &self.n.as_ref().map(|_| "[redacted]"))
            .field("e", &self.e)
            .finish()
    }
}

impl Serialize for PrivateJwk {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.public().serialize(serializer)
    }
}

impl Drop for PrivateJwk {
    fn drop(&mut self) {
        self.d.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PublicJwk {
    pub kty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
}

/// A key-backed signer that can produce detached signatures and publish
/// verification metadata without exposing private key material.
#[async_trait]
pub trait SigningProvider: Send + Sync {
    /// Signing algorithm advertised by this provider.
    fn algorithm(&self) -> SigningAlgorithm;
    /// Stable key identifier to publish in JWT/JWS headers.
    fn key_id(&self) -> &str;
    /// Public verification JWK for this provider.
    fn public_jwk(&self) -> PublicJwk;
    /// Sign the exact bytes supplied by the caller.
    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SigningError>;
}

/// Local `PrivateJwk`-backed signer for tests, demos, and mounted secret files.
#[derive(Clone)]
pub struct LocalJwkSigner {
    jwk: Arc<PrivateJwk>,
    key_id: String,
    public_jwk: PublicJwk,
}

impl LocalJwkSigner {
    /// Build a local signer from an Ed25519 private JWK with a non-empty `kid`.
    pub fn new(jwk: PrivateJwk) -> Result<Self, SigningError> {
        jwk.validate_private().map_err(SigningError::InvalidKey)?;
        let key_id = jwk
            .kid
            .as_deref()
            .filter(|kid| !kid.trim().is_empty())
            .ok_or(SigningError::MissingKeyId)?
            .to_string();
        let public_jwk = jwk.public();
        Ok(Self {
            jwk: Arc::new(jwk),
            key_id,
            public_jwk,
        })
    }
}

impl fmt::Debug for LocalJwkSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalJwkSigner")
            .field("alg", &self.algorithm())
            .field("kid", &self.key_id)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SigningProvider for LocalJwkSigner {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::EdDsa
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn public_jwk(&self) -> PublicJwk {
        self.public_jwk.clone()
    }

    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SigningError> {
        sign(payload, self.jwk.as_ref()).map_err(SigningError::Crypto)
    }
}

impl PrivateJwk {
    pub fn parse(json: &str) -> Result<Self, JwkError> {
        let value: Value = serde_json::from_str(json).map_err(JwkError::Json)?;
        let jwk: Self = serde_json::from_value(value).map_err(JwkError::Json)?;
        jwk.validate_private()?;
        Ok(jwk)
    }

    #[must_use]
    pub fn public(&self) -> PublicJwk {
        PublicJwk {
            kty: self.kty.clone(),
            kid: self.kid.clone(),
            alg: self.alg.clone(),
            crv: self.crv.clone(),
            x: self.x.clone(),
            y: self.y.clone(),
            n: self.n.clone(),
            e: self.e.clone(),
        }
    }

    pub fn algorithm(&self) -> Result<SigningAlgorithm, JwkError> {
        algorithm_from_fields(self.alg.as_deref(), self.kty.as_str(), self.crv.as_deref())
    }

    fn validate_private(&self) -> Result<(), JwkError> {
        match self.algorithm() {
            Ok(SigningAlgorithm::EdDsa) => {
                if self.kty != "OKP" || self.crv.as_deref() != Some("Ed25519") {
                    return Err(JwkError::Invalid("EdDSA keys must be OKP/Ed25519"));
                }
                decode_fixed(self.d.as_deref(), 32, "d")?;
                decode_fixed(self.x.as_deref(), 32, "x")?;
            }
            Err(err) => return Err(err),
        }
        Ok(())
    }
}

impl PublicJwk {
    pub fn parse(json: &str) -> Result<Self, JwkError> {
        let value: Value = serde_json::from_str(json).map_err(JwkError::Json)?;
        reject_private_members(&value)?;
        let jwk: Self = serde_json::from_value(value).map_err(JwkError::Json)?;
        jwk.validate_public()?;
        Ok(jwk)
    }

    pub fn jkt(&self) -> Result<String, JwkError> {
        let thumbprint = match self.kty.as_str() {
            "OKP" => json_object(&[
                (
                    "crv",
                    required_thumbprint_member(self.crv.as_deref(), "crv")?,
                ),
                ("kty", "OKP"),
                ("x", required_thumbprint_member(self.x.as_deref(), "x")?),
            ]),
            "EC" => json_object(&[
                (
                    "crv",
                    required_thumbprint_member(self.crv.as_deref(), "crv")?,
                ),
                ("kty", "EC"),
                ("x", required_thumbprint_member(self.x.as_deref(), "x")?),
                ("y", required_thumbprint_member(self.y.as_deref(), "y")?),
            ]),
            "RSA" => json_object(&[
                ("e", required_thumbprint_member(self.e.as_deref(), "e")?),
                ("kty", "RSA"),
                ("n", required_thumbprint_member(self.n.as_deref(), "n")?),
            ]),
            _ => return Err(JwkError::UnsupportedAlgorithm),
        };
        let thumbprint = canonicalize_json(&thumbprint)
            .map_err(|_| JwkError::Invalid("JWK thumbprint members"))?;
        Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(&thumbprint)))
    }

    pub fn algorithm(&self) -> Result<SigningAlgorithm, JwkError> {
        algorithm_from_fields(self.alg.as_deref(), self.kty.as_str(), self.crv.as_deref())
    }

    fn validate_public(&self) -> Result<(), JwkError> {
        match self.algorithm() {
            Ok(SigningAlgorithm::EdDsa) => {
                if self.kty != "OKP" || self.crv.as_deref() != Some("Ed25519") {
                    return Err(JwkError::Invalid("EdDSA keys must be OKP/Ed25519"));
                }
                decode_fixed(self.x.as_deref(), 32, "x")?;
            }
            Err(err) => return Err(err),
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum JwkError {
    #[error("invalid JWK JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid JWK: {0}")]
    Invalid(&'static str),
    #[error("unsupported JWK algorithm")]
    UnsupportedAlgorithm,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CryptoError {
    #[error("invalid key: {0}")]
    InvalidKey(#[from] JwkError),
    #[error("invalid base64url member: {0}")]
    InvalidBase64(#[from] base64::DecodeError),
    #[error("invalid signature")]
    InvalidSignature,
}

/// Errors from local and external signing providers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SigningError {
    #[error("invalid signing key: {0}")]
    InvalidKey(JwkError),
    #[error("signing key is missing kid")]
    MissingKeyId,
    #[error("signing key kid does not match public JWK")]
    KeyIdMismatch,
    #[error("cryptographic signing failed: {0}")]
    Crypto(CryptoError),
    #[error("external signer failed: {message}")]
    External { message: String },
}

impl SigningError {
    #[must_use]
    pub fn external(message: impl AsRef<str>) -> Self {
        const MAX_SAFE_CHARS: usize = 160;
        let mut chars = message
            .as_ref()
            .chars()
            .map(|ch| if ch.is_control() { ' ' } else { ch });
        let mut bounded = chars.by_ref().take(MAX_SAFE_CHARS).collect::<String>();
        if chars.next().is_some() {
            bounded.push_str("...");
        }
        Self::External { message: bounded }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidMethod {
    Web,
    Key,
    Jwk,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedDid {
    pub method: DidMethod,
    pub identifier: String,
    pub fragment: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum DidError {
    #[error("DID must start with did:")]
    MissingPrefix,
    #[error("DID method is not allowed")]
    MethodNotAllowed,
    #[error("DID method is unsupported")]
    UnsupportedMethod,
    #[error("DID identifier is invalid")]
    InvalidIdentifier,
    #[error("did:web host is invalid")]
    InvalidDidWebHost,
    #[error("did:web paths must not contain traversal")]
    PathTraversal,
    #[error("did:jwk payload is invalid")]
    InvalidDidJwk,
    #[error("issuer URL is invalid")]
    InvalidIssuerUrl,
    #[error("issuer URL must use HTTPS")]
    IssuerMustUseHttps,
    #[error("did:web host does not match issuer host")]
    IssuerHostMismatch,
}

pub fn validate_did(s: &str, allowed_methods: &[DidMethod]) -> Result<ValidatedDid, DidError> {
    let rest = s.strip_prefix("did:").ok_or(DidError::MissingPrefix)?;
    let (method, remainder) = rest.split_once(':').ok_or(DidError::InvalidIdentifier)?;
    let (identifier, fragment) = match remainder.split_once('#') {
        Some((identifier, fragment)) => (identifier, Some(fragment.to_string())),
        None => (remainder, None),
    };
    if identifier.is_empty() {
        return Err(DidError::InvalidIdentifier);
    }
    let method = match method {
        "web" => DidMethod::Web,
        "key" => DidMethod::Key,
        "jwk" => DidMethod::Jwk,
        _ => return Err(DidError::UnsupportedMethod),
    };
    if !allowed_methods.contains(&method) {
        return Err(DidError::MethodNotAllowed);
    }
    match method {
        DidMethod::Web => validate_did_web(s)?,
        DidMethod::Key => {
            if identifier.contains('/') || identifier.contains('?') || identifier.contains('#') {
                return Err(DidError::InvalidIdentifier);
            }
        }
        DidMethod::Jwk => {
            if identifier.contains('/') || identifier.contains('?') {
                return Err(DidError::InvalidIdentifier);
            }
            parse_did_jwk(s)?;
        }
    }
    Ok(ValidatedDid {
        method,
        identifier: identifier.to_string(),
        fragment,
    })
}

pub fn parse_did_jwk(s: &str) -> Result<PublicJwk, DidError> {
    let rest = s
        .strip_prefix("did:jwk:")
        .ok_or(DidError::UnsupportedMethod)?;
    let identifier = rest
        .split_once('#')
        .map_or(rest, |(identifier, _)| identifier);
    if identifier.is_empty() || identifier.contains('/') || identifier.contains('?') {
        return Err(DidError::InvalidIdentifier);
    }
    let jwk_json = URL_SAFE_NO_PAD
        .decode(identifier)
        .map_err(|_| DidError::InvalidDidJwk)?;
    let value: Value = serde_json::from_slice(&jwk_json).map_err(|_| DidError::InvalidDidJwk)?;
    reject_private_members(&value).map_err(|_| DidError::InvalidDidJwk)?;
    let minimal = minimal_did_jwk_value_from_value(&value).map_err(|_| DidError::InvalidDidJwk)?;
    let canonical = canonicalize_json(&minimal).map_err(|_| DidError::InvalidDidJwk)?;
    if URL_SAFE_NO_PAD.encode(&canonical) != identifier {
        return Err(DidError::InvalidDidJwk);
    }
    let jwk: PublicJwk = serde_json::from_value(minimal).map_err(|_| DidError::InvalidDidJwk)?;
    jwk.validate_public().map_err(|_| DidError::InvalidDidJwk)?;
    Ok(jwk)
}

pub fn did_jwk_from_public_jwk(jwk: &PublicJwk) -> Result<String, DidError> {
    let value = minimal_did_jwk_value(jwk).map_err(|_| DidError::InvalidDidJwk)?;
    let canonical = canonicalize_json(&value).map_err(|_| DidError::InvalidDidJwk)?;
    Ok(format!("did:jwk:{}", URL_SAFE_NO_PAD.encode(canonical)))
}

pub fn validate_did_web(s: &str) -> Result<(), DidError> {
    let rest = s
        .strip_prefix("did:web:")
        .ok_or(DidError::UnsupportedMethod)?;
    let identifier = rest
        .split_once('#')
        .map_or(rest, |(identifier, _)| identifier);
    if identifier.is_empty() {
        return Err(DidError::InvalidIdentifier);
    }
    let mut segments = identifier.split(':');
    let host = percent_decode(segments.next().ok_or(DidError::InvalidIdentifier)?)
        .ok_or(DidError::InvalidIdentifier)?;
    validate_dns_host(&host)?;
    for segment in segments {
        let decoded = percent_decode(segment).ok_or(DidError::InvalidIdentifier)?;
        if decoded.is_empty() || decoded == "." || decoded == ".." || decoded.contains('/') {
            return Err(DidError::PathTraversal);
        }
    }
    Ok(())
}

pub fn validate_did_web_https_issuer_binding(did: &str, issuer: &str) -> Result<(), DidError> {
    validate_did_web(did)?;
    let did_host = did_web_host(did)?;
    let issuer = Url::parse(issuer).map_err(|_| DidError::InvalidIssuerUrl)?;
    if issuer.scheme() != "https" {
        return Err(DidError::IssuerMustUseHttps);
    }
    let issuer_host = issuer.host_str().ok_or(DidError::InvalidIssuerUrl)?;
    if did_host.eq_ignore_ascii_case(issuer_host) {
        Ok(())
    } else {
        Err(DidError::IssuerHostMismatch)
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum JcsError {
    #[error("JCS does not support non-finite numbers")]
    InvalidNumber,
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn canonicalize_json(value: &Value) -> Result<Vec<u8>, JcsError> {
    let mut out = Vec::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

#[must_use]
pub fn hmac_sha256_base64url_no_pad(key: &[u8], input: &[u8]) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts keys of any length");
    mac.update(input);
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

pub fn pairwise_subject_ref_hash(
    key: &[u8],
    aud: &str,
    issuer: &str,
    profile: &str,
    id_type: &str,
    subject_id: &str,
) -> Result<String, JcsError> {
    let input = json_string_object(&[
        ("aud", aud),
        ("issuer", issuer),
        ("profile", profile),
        ("id_type", id_type),
        ("subject_id", subject_id),
    ]);
    let canonical = canonicalize_json(&input)?;
    Ok(format!(
        "hmac-sha256:{}",
        hmac_sha256_base64url_no_pad(key, &canonical)
    ))
}

/// Sign `payload` using the Ed25519 private key in `jwk`.
///
/// Runs synchronously on the calling thread. Measured ~15 µs/op (release,
/// Apple M5 Max). Callers on a Tokio runtime that process many concurrent
/// issuances should offload to `tokio::task::spawn_blocking` if latency
/// becomes a concern. Run the ignored `eddsa_sign_microbench` test to
/// re-measure on your hardware.
pub fn sign(payload: &[u8], jwk: &PrivateJwk) -> Result<Vec<u8>, CryptoError> {
    jwk.validate_private()?;
    // Decode directly into a stack-allocated Zeroizing buffer to avoid any
    // intermediate heap allocation that would not be zeroed on error paths.
    let d_str = jwk.d.as_deref().ok_or(JwkError::Invalid("d"))?;
    let mut seed = Zeroizing::new([0u8; 32]);
    let decoded_len = URL_SAFE_NO_PAD
        .decode_slice(d_str, &mut *seed)
        .map_err(|_| JwkError::Invalid("d"))?;
    if decoded_len != 32 {
        return Err(JwkError::Invalid("d length").into());
    }
    let signature = SigningKey::from_bytes(&seed).sign(payload);
    Ok(signature.to_bytes().to_vec())
}

/// Verify `signature` over `payload` using the Ed25519 public key in `jwk`.
///
/// Runs synchronously on the calling thread. Measured ~22 µs/op (release,
/// Apple M5 Max). Run the ignored `eddsa_verify_microbench` test to
/// re-measure on your hardware.
pub fn verify(payload: &[u8], signature: &[u8], jwk: &PublicJwk) -> Result<(), CryptoError> {
    jwk.validate_public()?;
    let x = decode_fixed(jwk.x.as_deref(), 32, "x")?;
    let x: [u8; 32] = x.try_into().map_err(|_| JwkError::Invalid("x length"))?;
    let verifying_key = VerifyingKey::from_bytes(&x).map_err(|_| CryptoError::InvalidSignature)?;
    let signature = Signature::try_from(signature).map_err(|_| CryptoError::InvalidSignature)?;
    verifying_key
        .verify_strict(payload, &signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

fn algorithm_from_fields(
    alg: Option<&str>,
    kty: &str,
    crv: Option<&str>,
) -> Result<SigningAlgorithm, JwkError> {
    match alg {
        Some("EdDSA") => Ok(SigningAlgorithm::EdDsa),
        Some(_) => Err(JwkError::UnsupportedAlgorithm),
        None if kty == "OKP" && crv == Some("Ed25519") => Ok(SigningAlgorithm::EdDsa),
        None => Err(JwkError::UnsupportedAlgorithm),
    }
}

fn reject_private_members(value: &Value) -> Result<(), JwkError> {
    const PRIVATE_MEMBERS: [&str; 7] = ["d", "p", "q", "dp", "dq", "qi", "oth"];
    if PRIVATE_MEMBERS
        .iter()
        .any(|member| value.get(member).is_some())
    {
        return Err(JwkError::Invalid("public JWK contains private material"));
    }
    Ok(())
}

fn minimal_did_jwk_value(jwk: &PublicJwk) -> Result<Value, JwkError> {
    jwk.validate_public()?;
    if jwk.kty != "OKP" || jwk.crv.as_deref() != Some("Ed25519") {
        return Err(JwkError::UnsupportedAlgorithm);
    }
    Ok(json_object(&[
        ("crv", "Ed25519"),
        ("kty", "OKP"),
        ("x", required_thumbprint_member(jwk.x.as_deref(), "x")?),
    ]))
}

fn minimal_did_jwk_value_from_value(value: &Value) -> Result<Value, JwkError> {
    const DID_JWK_MEMBERS: [&str; 3] = ["kty", "crv", "x"];
    let Some(object) = value.as_object() else {
        return Err(JwkError::Invalid("JWK must be an object"));
    };
    if object
        .keys()
        .any(|member| !DID_JWK_MEMBERS.contains(&member.as_str()))
    {
        return Err(JwkError::Invalid("did:jwk contains unsupported members"));
    }
    let kty = required_thumbprint_member(value.get("kty").and_then(Value::as_str), "kty")?;
    let crv = required_thumbprint_member(value.get("crv").and_then(Value::as_str), "crv")?;
    let x = required_thumbprint_member(value.get("x").and_then(Value::as_str), "x")?;
    if kty != "OKP" || crv != "Ed25519" {
        return Err(JwkError::UnsupportedAlgorithm);
    }
    decode_fixed(Some(x), 32, "x")?;
    Ok(json_object(&[("crv", crv), ("kty", kty), ("x", x)]))
}

fn required_thumbprint_member<'a>(
    value: Option<&'a str>,
    field: &'static str,
) -> Result<&'a str, JwkError> {
    let value = value.ok_or(JwkError::Invalid(field))?;
    if value.is_empty() {
        return Err(JwkError::Invalid(field));
    }
    Ok(value)
}

fn json_object(entries: &[(&str, &str)]) -> Value {
    json_string_object(entries)
}

fn json_string_object(entries: &[(&str, &str)]) -> Value {
    let mut object = Map::new();
    for (key, value) in entries {
        object.insert((*key).to_string(), Value::String((*value).to_string()));
    }
    Value::Object(object)
}

fn decode_fixed(
    value: Option<&str>,
    expected_len: usize,
    field: &'static str,
) -> Result<Vec<u8>, JwkError> {
    let value = value.ok_or(JwkError::Invalid(field))?;
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| JwkError::Invalid(field))?;
    if decoded.len() != expected_len {
        return Err(JwkError::Invalid(field));
    }
    Ok(decoded)
}

fn validate_dns_host(host: &str) -> Result<(), DidError> {
    if host.parse::<IpAddr>().is_ok() {
        return Err(DidError::InvalidDidWebHost);
    }
    if Host::parse(host).is_err() {
        return Err(DidError::InvalidDidWebHost);
    }
    let lower = host.to_ascii_lowercase();
    if lower == "localhost"
        || lower.ends_with(".localhost")
        || lower == "metadata.google.internal"
        || lower.contains("169.254.169.254")
    {
        return Err(DidError::InvalidDidWebHost);
    }
    if lower
        .split('.')
        .any(|label| label.is_empty() || label == "." || label == "..")
    {
        return Err(DidError::InvalidDidWebHost);
    }
    Ok(())
}

fn did_web_host(s: &str) -> Result<String, DidError> {
    let rest = s
        .strip_prefix("did:web:")
        .ok_or(DidError::UnsupportedMethod)?;
    let identifier = rest
        .split_once('#')
        .map_or(rest, |(identifier, _)| identifier);
    let host = identifier
        .split(':')
        .next()
        .ok_or(DidError::InvalidIdentifier)?;
    percent_decode(host).ok_or(DidError::InvalidIdentifier)
}

fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hi = *bytes.get(index + 1)?;
            let lo = *bytes.get(index + 2)?;
            out.push((hex_value(hi)? << 4) | hex_value(lo)?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) -> Result<(), JcsError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(value) => out.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(number) => {
            if let Some(value) = number.as_f64() {
                if !value.is_finite() {
                    return Err(JcsError::InvalidNumber);
                }
            }
            out.extend_from_slice(number.to_string().as_bytes());
        }
        Value::String(value) => out.extend_from_slice(serde_json::to_string(value)?.as_bytes()),
        Value::Array(values) => {
            out.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => write_canonical_object(map, out)?,
    }
    Ok(())
}

fn write_canonical_object(map: &Map<String, Value>, out: &mut Vec<u8>) -> Result<(), JcsError> {
    out.push(b'{');
    let mut entries = map.iter().collect::<Vec<_>>();
    entries.sort_unstable_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
    for (index, (key, value)) in entries.into_iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(serde_json::to_string(key)?.as_bytes());
        out.push(b':');
        write_canonical(value, out)?;
    }
    out.push(b'}');
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RAW_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.test#key-1"}"#;

    #[test]
    fn private_jwk_parse_debug_redacts_and_public_strips_private_material() {
        let private = PrivateJwk::parse(RAW_JWK).expect("private jwk parses");
        let debug = format!("{private:?}");

        assert!(debug.contains("PrivateJwk"));
        assert!(!debug.contains("2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw"));
        assert!(debug.contains("[redacted]"));

        let public = private.public();
        let public_json = serde_json::to_value(&public).expect("public jwk serializes");
        assert_eq!(
            public_json.get("x").and_then(Value::as_str),
            private.x.as_deref()
        );
        assert!(public_json.get("d").is_none());
    }

    #[test]
    fn private_jwk_serializes_as_public_projection() {
        let private = PrivateJwk::parse(RAW_JWK).expect("private jwk parses");
        let serialized = serde_json::to_value(&private).expect("private jwk serializes safely");

        assert_eq!(
            serialized.get("x").and_then(Value::as_str),
            private.x.as_deref()
        );
        assert!(serialized.get("d").is_none());
        assert!(!serialized
            .to_string()
            .contains("2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw"));
    }

    #[test]
    fn public_jwk_rejects_private_members() {
        let err = PublicJwk::parse(RAW_JWK).expect_err("private member must reject");
        assert!(matches!(err, JwkError::Invalid(_)));
    }

    #[test]
    fn jwk_parse_allows_standard_public_metadata_outside_did_jwk() {
        let public = PublicJwk::parse(
            r#"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.test#key-1","use":"sig","key_ops":["verify"]}"#,
        )
        .expect("public JWK metadata is allowed");

        assert_eq!(public.kid.as_deref(), Some("did:web:issuer.test#key-1"));
        assert_eq!(public.alg.as_deref(), Some("EdDSA"));

        let private = PrivateJwk::parse(
            r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.test#key-1","use":"sig","key_ops":["sign"]}"#,
        )
        .expect("private JWK metadata is allowed");

        assert_eq!(private.kid.as_deref(), Some("did:web:issuer.test#key-1"));
        assert_eq!(private.alg.as_deref(), Some("EdDSA"));
    }

    #[test]
    fn eddsa_sign_and_verify_round_trip() {
        let private = PrivateJwk::parse(RAW_JWK).expect("private jwk parses");
        let public = private.public();
        let payload = b"registry-platform";
        let signature = sign(payload, &private).expect("payload signs");

        verify(payload, &signature, &public).expect("signature verifies");
        assert!(verify(b"tampered", &signature, &public).is_err());
    }

    #[tokio::test]
    async fn local_jwk_signer_signs_and_exposes_public_metadata() {
        let private = PrivateJwk::parse(RAW_JWK).expect("private jwk parses");
        let signer = LocalJwkSigner::new(private).expect("local signer builds");
        let payload = b"registry-platform-provider";
        let signature = signer.sign(payload).await.expect("payload signs");

        assert_eq!(signer.algorithm(), SigningAlgorithm::EdDsa);
        assert_eq!(signer.key_id(), "did:web:issuer.test#key-1");
        let public = signer.public_jwk();
        verify(payload, &signature, &public).expect("signature verifies");
        let public_json = serde_json::to_value(public).expect("public jwk serializes");
        assert!(public_json.get("d").is_none());
    }

    #[test]
    fn local_jwk_signer_requires_non_empty_key_id() {
        let mut private = PrivateJwk::parse(RAW_JWK).expect("private jwk parses");
        private.kid = None;
        assert!(matches!(
            LocalJwkSigner::new(private),
            Err(SigningError::MissingKeyId)
        ));

        let mut private = PrivateJwk::parse(RAW_JWK).expect("private jwk parses");
        private.kid = Some(String::new());
        assert!(matches!(
            LocalJwkSigner::new(private),
            Err(SigningError::MissingKeyId)
        ));
    }

    #[test]
    fn local_jwk_signer_validates_private_material_at_construction() {
        let mut private = PrivateJwk::parse(RAW_JWK).expect("private jwk parses");
        private.d = Some("not-base64url".to_string());

        assert!(matches!(
            LocalJwkSigner::new(private),
            Err(SigningError::InvalidKey(JwkError::Invalid("d")))
        ));
    }

    #[test]
    fn local_jwk_signer_debug_redacts_private_material() {
        let private = PrivateJwk::parse(RAW_JWK).expect("private jwk parses");
        let signer = LocalJwkSigner::new(private).expect("local signer builds");
        let debug = format!("{signer:?}");

        assert!(debug.contains("LocalJwkSigner"));
        assert!(debug.contains("did:web:issuer.test#key-1"));
        assert!(!debug.contains("2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw"));
    }

    #[test]
    fn external_signing_error_messages_are_bounded_and_single_line() {
        let message = format!("{}{}", "provider unavailable\n", "x".repeat(512));
        let err = SigningError::external(message);
        let rendered = err.to_string();

        assert!(!rendered.contains('\n'));
        assert!(rendered.len() <= 220, "{rendered}");
    }

    #[test]
    fn eddsa_may_be_inferred_from_okp_ed25519_without_alg() {
        let private = PrivateJwk::parse(
            r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc"}"#,
        )
        .expect("Ed25519 JWK parses without alg");

        assert_eq!(
            private.algorithm().expect("algorithm"),
            SigningAlgorithm::EdDsa
        );
    }

    #[test]
    fn unsupported_signing_algorithms_are_rejected_at_parse_time() {
        let p256 = r#"{"kty":"EC","crv":"P-256","d":"jpsQnnGQmTMRzLC0W_9-v8RC0ZQ79OJWfZPOGdXGdP8","x":"f83OJ3D2xF4k1JQWctzS0r8uXH6Gz-l4WfXccj5WHv0","y":"x_FEzRu9dVvZt2pSuGQgH7u9tZxU7I5oUJu-4G8Azjo","alg":"ES256"}"#;
        let rsa = r#"{"kty":"RSA","n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4PBO8BxG7NXXjO4IhYGoOi0Lem4xXeUq7W57RtgGF4wSGZ4HAvY8R9H_JVU3tO7K0XG3L8m5vB2T2KQeJ0gJg9g4nG9QpXJYpJ2NmgH6L7ZqQHX7I4M","e":"AQAB","d":"V8tFoZRiEbWqT2DF3t5R6u9vS9LqQEVtGg5oQ2Y0t5k","alg":"RS256"}"#;
        let public_p256 = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF4k1JQWctzS0r8uXH6Gz-l4WfXccj5WHv0","y":"x_FEzRu9dVvZt2pSuGQgH7u9tZxU7I5oUJu-4G8Azjo","alg":"ES256"}"#;

        assert!(matches!(
            PrivateJwk::parse(p256),
            Err(JwkError::UnsupportedAlgorithm)
        ));
        assert!(matches!(
            PrivateJwk::parse(rsa),
            Err(JwkError::UnsupportedAlgorithm)
        ));
        assert!(matches!(
            PublicJwk::parse(public_p256),
            Err(JwkError::UnsupportedAlgorithm)
        ));
    }

    #[test]
    #[ignore = "micro-benchmark: run explicitly with `cargo test -- --ignored` to measure local sign/verify latency"]
    fn eddsa_sign_microbench() {
        use std::time::Instant;
        let private = PrivateJwk::parse(RAW_JWK).expect("private jwk parses");
        let payload = b"registry-platform-bench-payload";
        let iterations = 1000;
        let start = Instant::now();
        for _ in 0..iterations {
            sign(payload, &private).expect("sign");
        }
        let elapsed = start.elapsed();
        println!(
            "sign: {} iterations in {:?} = {:.1} µs/op",
            iterations,
            elapsed,
            elapsed.as_secs_f64() * 1_000_000.0 / iterations as f64
        );
    }

    #[test]
    #[ignore = "micro-benchmark: run explicitly with `cargo test -- --ignored` to measure local sign/verify latency"]
    fn eddsa_verify_microbench() {
        use std::time::Instant;
        let private = PrivateJwk::parse(RAW_JWK).expect("private jwk parses");
        let public = private.public();
        let payload = b"registry-platform-bench-payload";
        let signature = sign(payload, &private).expect("sign");
        let iterations = 1000;
        let start = Instant::now();
        for _ in 0..iterations {
            verify(payload, &signature, &public).expect("verify");
        }
        let elapsed = start.elapsed();
        println!(
            "verify: {} iterations in {:?} = {:.1} µs/op",
            iterations,
            elapsed,
            elapsed.as_secs_f64() * 1_000_000.0 / iterations as f64
        );
    }

    #[test]
    fn validate_did_returns_missing_prefix_for_non_did_strings() {
        assert_eq!(
            validate_did("not-a-did", &[DidMethod::Web]),
            Err(DidError::MissingPrefix)
        );
        assert_eq!(
            validate_did("web:example.org", &[DidMethod::Web]),
            Err(DidError::MissingPrefix)
        );
    }

    #[test]
    fn validate_did_returns_method_not_allowed_for_unlisted_method() {
        assert_eq!(
            validate_did("did:web:example.org", &[DidMethod::Key]),
            Err(DidError::MethodNotAllowed)
        );
        assert_eq!(
            validate_did("did:key:z6MkiTBz", &[DidMethod::Web]),
            Err(DidError::MethodNotAllowed)
        );
    }

    #[test]
    fn validate_did_returns_unsupported_method_for_unknown_scheme() {
        assert_eq!(
            validate_did(
                "did:unknown:identifier",
                &[DidMethod::Web, DidMethod::Key, DidMethod::Jwk]
            ),
            Err(DidError::UnsupportedMethod)
        );
        assert_eq!(
            validate_did("did:ethr:0xabc", &[]),
            Err(DidError::UnsupportedMethod)
        );
    }

    #[test]
    fn validate_did_accepts_allowed_web_and_key_methods() {
        let did = validate_did(
            "did:web:example.org:issuers:alpha#key-1",
            &[DidMethod::Web, DidMethod::Key],
        )
        .expect("did:web validates");

        assert_eq!(did.method, DidMethod::Web);
        assert_eq!(did.identifier, "example.org:issuers:alpha");
        assert_eq!(did.fragment.as_deref(), Some("key-1"));

        validate_did("did:key:z6MkiTBz", &[DidMethod::Key]).expect("did:key validates");
    }

    #[test]
    fn did_jwk_round_trips_public_jwk_and_rejects_private_material() {
        let public = PrivateJwk::parse(RAW_JWK)
            .expect("private jwk parses")
            .public();
        let did = did_jwk_from_public_jwk(&public).expect("did:jwk encodes");
        let validated = validate_did(&did, &[DidMethod::Jwk]).expect("did:jwk validates");
        let parsed = parse_did_jwk(&did).expect("did:jwk parses");

        assert_eq!(validated.method, DidMethod::Jwk);
        assert_eq!(parsed.kty, public.kty);
        assert_eq!(parsed.crv, public.crv);
        assert_eq!(parsed.x, public.x);
        assert_eq!(parsed.alg, None);
        assert_eq!(parsed.kid, None);

        let private_payload = URL_SAFE_NO_PAD.encode(
            canonicalize_json(&json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc",
                "d": "2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw"
            }))
            .expect("canonical json"),
        );
        let private_did = format!("did:jwk:{private_payload}");
        assert_eq!(parse_did_jwk(&private_did), Err(DidError::InvalidDidJwk));
    }

    #[test]
    fn did_jwk_rejects_non_canonical_or_unsupported_payload_members() {
        let public = PrivateJwk::parse(RAW_JWK)
            .expect("private jwk parses")
            .public();
        let noncanonical = format!(
            "did:jwk:{}",
            URL_SAFE_NO_PAD.encode(
                br#"{"x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","kty":"OKP","crv":"Ed25519","alg":"EdDSA","kid":"did:web:issuer.test#key-1"}"#
            )
        );
        assert_eq!(parse_did_jwk(&noncanonical), Err(DidError::InvalidDidJwk));

        let unsupported_member = format!(
            "did:jwk:{}",
            URL_SAFE_NO_PAD.encode(
                canonicalize_json(&json!({
                    "alg": "EdDSA",
                    "crv": "Ed25519",
                    "kid": "did:web:issuer.test#key-1",
                    "kty": "OKP",
                    "use": "sig",
                    "x": public.x.as_deref().expect("x"),
                }))
                .expect("canonical json")
            )
        );
        assert_eq!(
            parse_did_jwk(&unsupported_member),
            Err(DidError::InvalidDidJwk)
        );
    }

    #[test]
    fn validate_did_web_rejects_localhost_ips_and_path_traversal() {
        assert!(validate_did_web("did:web:localhost").is_err());
        assert!(validate_did_web("did:web:127.0.0.1").is_err());
        assert!(validate_did_web("did:web:example.org:..:issuer").is_err());
        assert!(validate_did_web("did:web:example.org:%2e%2e:issuer").is_err());
    }

    #[test]
    fn did_web_https_issuer_binding_accepts_matching_https_host() {
        validate_did_web_https_issuer_binding(
            "did:web:agency-a.example.gov",
            "https://agency-a.example.gov",
        )
        .expect("matching HTTPS issuer host binds");
        validate_did_web_https_issuer_binding(
            "did:web:agency-a.example.gov:issuers:alpha#key-1",
            "https://AGENCY-A.example.gov/federation/v1",
        )
        .expect("matching HTTPS issuer host binds case-insensitively");
    }

    #[test]
    fn did_web_https_issuer_binding_rejects_non_https_and_mismatch() {
        assert_eq!(
            validate_did_web_https_issuer_binding(
                "did:web:agency-a.example.gov",
                "http://agency-a.example.gov"
            ),
            Err(DidError::IssuerMustUseHttps)
        );
        assert_eq!(
            validate_did_web_https_issuer_binding(
                "did:web:agency-a.example.gov",
                "https://agency-b.example.gov"
            ),
            Err(DidError::IssuerHostMismatch)
        );
        assert_eq!(
            validate_did_web_https_issuer_binding("did:key:z6MkiTBz", "https://example.gov"),
            Err(DidError::UnsupportedMethod)
        );
    }

    #[test]
    fn canonicalize_json_sorts_object_keys_recursively() {
        let value = json!({"z": 1, "a": {"b": true, "a": [null, "x"]}});
        let canonical = canonicalize_json(&value).expect("canonicalizes");

        assert_eq!(
            String::from_utf8(canonical).expect("utf8"),
            r#"{"a":{"a":[null,"x"],"b":true},"z":1}"#
        );
    }

    #[test]
    fn hmac_sha256_base64url_no_pad_matches_fixed_vector() {
        assert_eq!(
            hmac_sha256_base64url_no_pad(b"key", b"The quick brown fox jumps over the lazy dog"),
            "97yD9DBThCSxMpjmqm-xQ-9NWaFJRhdZl0edvC0aPNg"
        );
    }

    #[test]
    fn pairwise_subject_ref_hash_uses_stable_canonical_input() {
        assert_eq!(
            pairwise_subject_ref_hash(
                b"federation-subject-secret",
                "did:web:agency-b.example.gov",
                "did:web:agency-a.example.gov",
                "disability_status_predicate",
                "national_id",
                "example-subject-id",
            )
            .expect("subject ref hashes"),
            "hmac-sha256:XIUcSUpspCMpOXVEeUes5EqZso47ytCAwtwAzlLpMEE"
        );
    }

    #[test]
    fn pairwise_subject_ref_hash_separates_audience_and_profile() {
        let base = pairwise_subject_ref_hash(
            b"federation-subject-secret",
            "did:web:agency-b.example.gov",
            "did:web:agency-a.example.gov",
            "disability_status_predicate",
            "national_id",
            "example-subject-id",
        )
        .expect("subject ref hashes");
        let other_audience = pairwise_subject_ref_hash(
            b"federation-subject-secret",
            "did:web:agency-c.example.gov",
            "did:web:agency-a.example.gov",
            "disability_status_predicate",
            "national_id",
            "example-subject-id",
        )
        .expect("subject ref hashes");
        let other_profile = pairwise_subject_ref_hash(
            b"federation-subject-secret",
            "did:web:agency-b.example.gov",
            "did:web:agency-a.example.gov",
            "eligibility_predicate",
            "national_id",
            "example-subject-id",
        )
        .expect("subject ref hashes");

        assert_ne!(base, other_audience);
        assert_ne!(base, other_profile);
    }

    #[test]
    fn public_jwk_thumbprint_uses_required_members_only() {
        let public = PrivateJwk::parse(RAW_JWK)
            .expect("private jwk parses")
            .public();
        assert_eq!(
            public.jkt().expect("thumbprint computes"),
            "qDygv_6SkrJ6krP3sYb0DCoEuYSYVP0ttF5m1cp_094"
        );
    }

    #[test]
    fn public_jwk_thumbprint_rejects_missing_required_members() {
        let mut public = PrivateJwk::parse(RAW_JWK)
            .expect("private jwk parses")
            .public();
        public.x = None;

        assert!(matches!(public.jkt(), Err(JwkError::Invalid("x"))));
    }

    #[test]
    fn constant_time_eq_is_available_for_callers() {
        use subtle::ConstantTimeEq;

        assert_eq!(b"a".ct_eq(b"a").unwrap_u8(), 1);
    }
}
