// SPDX-License-Identifier: Apache-2.0
//! Compact JWE decryption for `alg: ECDH-ES` (direct key agreement) over P-256
//! with `enc` A128GCM or A256GCM.
//!
//! Standards: RFC 7516 (compact serialization), RFC 7518 section 4.6 (ECDH-ES
//! and its Concat KDF) and section 5.3 (AES-GCM). Everything runs on aws-lc-rs:
//! static-key ECDH from `agreement`, AES-GCM from `aead`, and SHA-256 from
//! `digest`.
//!
//! Every decryption failure is one opaque [`JweError`]. The closed
//! [`JweFailureReason`] behind it is readable only under test, so a caller
//! cannot turn the reason into an oracle for the sender.

use crate::{parse_json_strict, CryptoError, JwkError, PublicJwk};
use aws_lc_rs::agreement::{self, ParsedPublicKey, UnparsedPublicKey};
use aws_lc_rs::{aead, digest};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Map, Value};
use std::fmt;
use zeroize::Zeroizing;

const ALG_ECDH_ES: &str = "ECDH-ES";
const IV_BYTES: usize = 12;
/// Unpadded base64url length of the 128-bit tag.
const TAG_ENCODED_BYTES: usize = 22;
const TAG_BYTES: usize = 16;
const P256_COORDINATE_BYTES: usize = 32;
/// Unpadded base64url length of a P-256 coordinate.
const P256_COORDINATE_ENCODED_BYTES: usize = 43;
const P256_SCALAR_BYTES: usize = 32;
/// Uncompressed SEC1 point: `0x04 || x || y`.
const P256_POINT_BYTES: usize = 1 + 2 * P256_COORDINATE_BYTES;
/// Members an `epk` may carry; anything else, notably `d`, is refused.
const EPK_MEMBERS: [&str; 7] = ["kty", "crv", "x", "y", "use", "alg", "kid"];

/// Content encryption algorithms accepted with `ECDH-ES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JweEnc {
    A128Gcm,
    A256Gcm,
}

impl JweEnc {
    /// The JWE `enc` header value.
    #[must_use]
    pub const fn jwa_name(self) -> &'static str {
        match self {
            Self::A128Gcm => "A128GCM",
            Self::A256Gcm => "A256GCM",
        }
    }

    const fn key_bytes(self) -> usize {
        match self {
            Self::A128Gcm => 16,
            Self::A256Gcm => 32,
        }
    }

    fn aead_algorithm(self) -> &'static aead::Algorithm {
        match self {
            Self::A128Gcm => &aead::AES_128_GCM,
            Self::A256Gcm => &aead::AES_256_GCM,
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        [Self::A128Gcm, Self::A256Gcm]
            .into_iter()
            .find(|enc| enc.jwa_name() == name)
    }
}

/// Size bounds applied while parsing a compact JWE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JweLimits {
    /// Longest accepted compact serialization, in bytes.
    pub max_compact_bytes: usize,
    /// Longest accepted decoded protected header, in bytes.
    pub max_header_bytes: usize,
    /// Longest accepted decoded `apu` or `apv`, in bytes.
    pub max_party_info_bytes: usize,
    /// Longest accepted plaintext, in bytes.
    pub max_plaintext_bytes: usize,
}

impl Default for JweLimits {
    fn default() -> Self {
        Self {
            max_compact_bytes: 256 * 1024,
            max_header_bytes: 4 * 1024,
            max_party_info_bytes: 512,
            max_plaintext_bytes: 192 * 1024,
        }
    }
}

/// Why a JWE was refused. Diagnostic only: never send it to the sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JweFailureReason {
    TooLarge,
    Malformed,
    EncryptedKeyPresent,
    InvalidHeader,
    UnsupportedAlg,
    UnsupportedEnc,
    UnsupportedHeader,
    InvalidEpk,
    KidMismatch,
    InvalidPartyInfo,
    KeyAgreementFailed,
    AuthenticationFailed,
    EncryptionFailed,
}

/// Opaque JWE failure. Display and Debug never vary with the cause.
#[derive(Clone, PartialEq, Eq)]
pub struct JweError {
    reason: JweFailureReason,
}

impl JweError {
    const fn new(reason: JweFailureReason) -> Self {
        Self { reason }
    }

    /// The internal reason, for tests.
    #[cfg(any(test, feature = "jwe-test-support"))]
    #[must_use]
    pub const fn reason(&self) -> JweFailureReason {
        self.reason
    }
}

impl From<JweFailureReason> for JweError {
    fn from(reason: JweFailureReason) -> Self {
        Self::new(reason)
    }
}

impl fmt::Display for JweError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JWE decryption failed")
    }
}

impl fmt::Debug for JweError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JweError")
    }
}

impl std::error::Error for JweError {}

/// A static P-256 key-agreement key that receives `ECDH-ES` JWEs.
///
/// The private scalar is held by aws-lc-rs, which cleanses it when the key is
/// freed. It is never serialized and `Debug` is redacted.
pub struct EcdhEsP256Key {
    private: agreement::PrivateKey,
    public_point: [u8; P256_POINT_BYTES],
    kid: String,
}

impl fmt::Debug for EcdhEsP256Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdhEsP256Key")
            .field("key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl EcdhEsP256Key {
    fn from_private(private: agreement::PrivateKey, kid: &str) -> Result<Self, CryptoError> {
        let public = private
            .compute_public_key()
            .map_err(|_| CryptoError::Crypto("P-256 public key derivation failed"))?;
        let public_point: [u8; P256_POINT_BYTES] = public
            .as_ref()
            .try_into()
            .map_err(|_| CryptoError::Crypto("P-256 public key encoding"))?;
        Ok(Self {
            private,
            public_point,
            kid: kid.to_owned(),
        })
    }

    /// Generate a fresh key.
    pub fn generate(kid: &str) -> Result<Self, CryptoError> {
        let private = agreement::PrivateKey::generate(&agreement::ECDH_P256)
            .map_err(|_| CryptoError::Crypto("P-256 key generation failed"))?;
        Self::from_private(private, kid)
    }

    /// Load an unencrypted PKCS#8 (RFC 5208) P-256 private key.
    pub fn from_pkcs8_der(der: &[u8], kid: &str) -> Result<Self, CryptoError> {
        let private = agreement::PrivateKey::from_private_key_der(&agreement::ECDH_P256, der)
            .map_err(|_| CryptoError::Crypto("invalid P-256 PKCS#8 private key"))?;
        Self::from_private(private, kid)
    }

    /// Load a P-256 private key from its 32 byte big-endian scalar (a JWK `d`).
    pub fn from_private_scalar(scalar: &[u8], kid: &str) -> Result<Self, CryptoError> {
        if scalar.len() != P256_SCALAR_BYTES {
            return Err(CryptoError::Crypto("invalid P-256 private scalar length"));
        }
        let private = agreement::PrivateKey::from_private_key(&agreement::ECDH_P256, scalar)
            .map_err(|_| CryptoError::Crypto("invalid P-256 private scalar"))?;
        Self::from_private(private, kid)
    }

    /// The key identifier published in [`Self::public_jwk`].
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The public key as a JWK for encryption: `kty`, `crv`, `x`, `y`, `use`
    /// `enc`, `alg` `ECDH-ES`, `kid`. It never carries private members.
    #[must_use]
    pub fn public_jwk(&self) -> Map<String, Value> {
        let (x, y) = self.public_point[1..].split_at(P256_COORDINATE_BYTES);
        let Value::Object(map) = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(x),
            "y": URL_SAFE_NO_PAD.encode(y),
            "use": "enc",
            "alg": ALG_ECDH_ES,
            "kid": self.kid,
        }) else {
            unreachable!("json! object literal");
        };
        map
    }

    /// RFC 7638 thumbprint of the public key.
    pub fn thumbprint(&self) -> Result<String, JwkError> {
        let (x, y) = self.public_point[1..].split_at(P256_COORDINATE_BYTES);
        PublicJwk {
            kty: "EC".to_owned(),
            kid: None,
            alg: None,
            crv: Some("P-256".to_owned()),
            x: Some(URL_SAFE_NO_PAD.encode(x)),
            y: Some(URL_SAFE_NO_PAD.encode(y)),
            n: None,
            e: None,
        }
        .jkt()
    }

    /// PKCS#8 encoding of the private key, to build key fixtures.
    #[cfg(any(test, feature = "jwe-test-support"))]
    pub fn to_pkcs8_der_for_tests(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        use aws_lc_rs::encoding::{AsDer as _, Pkcs8V1Der};
        let der: Pkcs8V1Der<'static> = self
            .private
            .as_der()
            .map_err(|_| CryptoError::Crypto("PKCS#8 encoding failed"))?;
        Ok(Zeroizing::new(der.as_ref().to_vec()))
    }
}

/// A successfully decrypted compact JWE.
pub struct DecryptedJwe {
    pub plaintext: Zeroizing<Vec<u8>>,
    pub enc: JweEnc,
    pub kid: Option<String>,
    /// Decoded `apu` (empty when absent).
    pub apu: Vec<u8>,
    /// Decoded `apv` (empty when absent).
    pub apv: Vec<u8>,
}

impl fmt::Debug for DecryptedJwe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptedJwe")
            .field("enc", &self.enc)
            .finish_non_exhaustive()
    }
}

fn encoded_bound(decoded: usize) -> usize {
    decoded.div_ceil(3) * 4
}

fn decode(segment: &str) -> Result<Vec<u8>, JweFailureReason> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| JweFailureReason::Malformed)
}

/// Validate an EC P-256 public JWK and return its uncompressed SEC1 point.
/// The point itself is checked for curve membership by the key agreement.
fn p256_point_from_jwk(
    jwk: &Map<String, Value>,
) -> Result<[u8; P256_POINT_BYTES], JweFailureReason> {
    use JweFailureReason::InvalidEpk;
    if jwk
        .keys()
        .any(|member| !EPK_MEMBERS.contains(&member.as_str()))
    {
        return Err(InvalidEpk);
    }
    let text = |member: &str| jwk.get(member).and_then(Value::as_str).ok_or(InvalidEpk);
    if text("kty")? != "EC" || text("crv")? != "P-256" {
        return Err(InvalidEpk);
    }
    let mut point = [0u8; P256_POINT_BYTES];
    point[0] = 4;
    for (member, slot) in [("x", 1..33), ("y", 33..65)] {
        let encoded = text(member)?;
        if encoded.len() != P256_COORDINATE_ENCODED_BYTES {
            return Err(InvalidEpk);
        }
        let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| InvalidEpk)?;
        if bytes.len() != P256_COORDINATE_BYTES {
            return Err(InvalidEpk);
        }
        point[slot].copy_from_slice(&bytes);
    }
    Ok(point)
}

/// RFC 7518 section 4.6.2 Concat KDF with SHA-256. One hash round yields at
/// most 32 bytes, enough for A128GCM and A256GCM.
fn concat_kdf(
    shared_secret: &[u8],
    enc: JweEnc,
    apu: &[u8],
    apv: &[u8],
) -> Result<Zeroizing<Vec<u8>>, JweFailureReason> {
    let length = |len: usize| {
        u32::try_from(len)
            .map(u32::to_be_bytes)
            .map_err(|_| JweFailureReason::InvalidPartyInfo)
    };
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(&1u32.to_be_bytes());
    context.update(shared_secret);
    for field in [enc.jwa_name().as_bytes(), apu, apv] {
        context.update(&length(field.len())?);
        context.update(field);
    }
    context.update(&length(enc.key_bytes() * 8)?);
    let hash = context.finish();
    Ok(Zeroizing::new(hash.as_ref()[..enc.key_bytes()].to_vec()))
}

/// ECDH between `key` and the peer's point, then the Concat KDF.
fn derive_cek(
    key: &EcdhEsP256Key,
    peer_point: &[u8],
    enc: JweEnc,
    apu: &[u8],
    apv: &[u8],
) -> Result<Zeroizing<Vec<u8>>, JweFailureReason> {
    let peer = ParsedPublicKey::try_from(UnparsedPublicKey::new(&agreement::ECDH_P256, peer_point))
        .map_err(|_| JweFailureReason::InvalidEpk)?;
    agreement::agree(
        &key.private,
        peer,
        JweFailureReason::KeyAgreementFailed,
        |shared_secret| concat_kdf(shared_secret, enc, apu, apv),
    )
}

fn party_info(
    header: &Map<String, Value>,
    member: &str,
    limits: &JweLimits,
) -> Result<Vec<u8>, JweFailureReason> {
    use JweFailureReason::InvalidPartyInfo;
    let Some(value) = header.get(member) else {
        return Ok(Vec::new());
    };
    let encoded = value.as_str().ok_or(InvalidPartyInfo)?;
    if encoded.len() > encoded_bound(limits.max_party_info_bytes) {
        return Err(InvalidPartyInfo);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| InvalidPartyInfo)?;
    if decoded.len() > limits.max_party_info_bytes {
        return Err(InvalidPartyInfo);
    }
    Ok(decoded)
}

/// Decrypt a compact `ECDH-ES` JWE addressed to `key`.
///
/// Compact form only; the encrypted-key segment must be empty. `alg` must be
/// exactly `ECDH-ES` and `enc` one of `allowed`. `epk` must be a public EC
/// P-256 JWK on the curve. `kid`, when present, must equal the key's. `zip` and
/// `crit` are refused. `apu` and `apv` feed the KDF. The AAD is the transmitted
/// protected header segment. Any failure is one opaque [`JweError`].
pub fn decrypt_compact_ecdh_es(
    token: &str,
    key: &EcdhEsP256Key,
    allowed: &[JweEnc],
    limits: &JweLimits,
) -> Result<DecryptedJwe, JweError> {
    decrypt(token, key, allowed, limits).map_err(JweError::new)
}

fn decrypt(
    token: &str,
    key: &EcdhEsP256Key,
    allowed: &[JweEnc],
    limits: &JweLimits,
) -> Result<DecryptedJwe, JweFailureReason> {
    use JweFailureReason as R;
    if token.len() > limits.max_compact_bytes {
        return Err(R::TooLarge);
    }
    let mut segments = token.split('.');
    let (
        Some(header_b64),
        Some(encrypted_key),
        Some(iv_b64),
        Some(ciphertext_b64),
        Some(tag_b64),
        None,
    ) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    )
    else {
        return Err(R::Malformed);
    };
    if header_b64.len() > encoded_bound(limits.max_header_bytes)
        || ciphertext_b64.len() > encoded_bound(limits.max_plaintext_bytes)
    {
        return Err(R::TooLarge);
    }
    if !encrypted_key.is_empty() {
        return Err(R::EncryptedKeyPresent);
    }
    if header_b64.is_empty() {
        return Err(R::Malformed);
    }

    let header_bytes = decode(header_b64)?;
    if header_bytes.len() > limits.max_header_bytes {
        return Err(R::TooLarge);
    }
    let Ok(Value::Object(header)) = parse_json_strict(&header_bytes) else {
        return Err(R::InvalidHeader);
    };
    if header.contains_key("zip") || header.contains_key("crit") {
        return Err(R::UnsupportedHeader);
    }
    match header.get("alg") {
        Some(Value::String(alg)) if alg == ALG_ECDH_ES => {}
        Some(Value::String(_)) => return Err(R::UnsupportedAlg),
        _ => return Err(R::InvalidHeader),
    }
    let enc = match header.get("enc") {
        Some(Value::String(name)) => JweEnc::from_name(name)
            .filter(|enc| allowed.contains(enc))
            .ok_or(R::UnsupportedEnc)?,
        _ => return Err(R::InvalidHeader),
    };
    let Some(Value::Object(epk)) = header.get("epk") else {
        return Err(if header.contains_key("epk") {
            R::InvalidEpk
        } else {
            R::InvalidHeader
        });
    };
    let peer_point = p256_point_from_jwk(epk)?;
    let kid = match header.get("kid") {
        None => None,
        Some(Value::String(kid)) if kid == key.kid() => Some(kid.clone()),
        Some(Value::String(_)) => return Err(R::KidMismatch),
        Some(_) => return Err(R::InvalidHeader),
    };
    let apu = party_info(&header, "apu", limits)?;
    let apv = party_info(&header, "apv", limits)?;

    if iv_b64.len() != encoded_bound(IV_BYTES) || tag_b64.len() != TAG_ENCODED_BYTES {
        return Err(R::Malformed);
    }
    let iv: [u8; IV_BYTES] = decode(iv_b64)?.try_into().map_err(|_| R::Malformed)?;
    let tag = decode(tag_b64)?;
    if tag.len() != TAG_BYTES {
        return Err(R::Malformed);
    }
    let mut sealed = Zeroizing::new(decode(ciphertext_b64)?);
    let plaintext_len = sealed.len();
    sealed.extend_from_slice(&tag);

    let cek = derive_cek(key, &peer_point, enc, &apu, &apv)?;
    let opening_key = aead::RandomizedNonceKey::new(enc.aead_algorithm(), &cek)
        .map_err(|_| R::AuthenticationFailed)?;
    opening_key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(iv),
            aead::Aad::from(header_b64.as_bytes()),
            &mut sealed,
        )
        .map_err(|_| R::AuthenticationFailed)?;
    sealed.truncate(plaintext_len);
    Ok(DecryptedJwe {
        plaintext: sealed,
        enc,
        kid,
        apu,
        apv,
    })
}

/// Encrypt `plaintext` to `recipient` (an EC P-256 public JWK) as a compact
/// `ECDH-ES` JWE, to simulate a wallet in tests. A fresh ephemeral key and IV
/// are used for every call. `apu` and `apv` are omitted from the header when
/// empty.
#[cfg(any(test, feature = "jwe-test-support"))]
pub fn encrypt_compact_ecdh_es_for_tests(
    plaintext: &[u8],
    recipient: &Map<String, Value>,
    enc: JweEnc,
    apu: &[u8],
    apv: &[u8],
    kid: Option<&str>,
) -> Result<String, JweError> {
    encrypt(plaintext, recipient, enc, apu, apv, kid).map_err(JweError::new)
}

#[cfg(any(test, feature = "jwe-test-support"))]
fn encrypt(
    plaintext: &[u8],
    recipient: &Map<String, Value>,
    enc: JweEnc,
    apu: &[u8],
    apv: &[u8],
    kid: Option<&str>,
) -> Result<String, JweFailureReason> {
    use JweFailureReason::EncryptionFailed;
    let recipient_point = p256_point_from_jwk(recipient)?;
    let ephemeral = EcdhEsP256Key::generate("ephemeral").map_err(|_| EncryptionFailed)?;
    let cek = agreement::agree(
        &ephemeral.private,
        UnparsedPublicKey::new(&agreement::ECDH_P256, &recipient_point[..]),
        JweFailureReason::KeyAgreementFailed,
        |shared_secret| concat_kdf(shared_secret, enc, apu, apv),
    )?;

    let mut epk = ephemeral.public_jwk();
    for member in ["use", "alg", "kid"] {
        epk.remove(member);
    }
    let mut header = Map::new();
    header.insert("alg".to_owned(), ALG_ECDH_ES.into());
    header.insert("enc".to_owned(), enc.jwa_name().into());
    header.insert("epk".to_owned(), Value::Object(epk));
    if let Some(kid) = kid {
        header.insert("kid".to_owned(), kid.into());
    }
    for (member, value) in [("apu", apu), ("apv", apv)] {
        if !value.is_empty() {
            header.insert(member.to_owned(), URL_SAFE_NO_PAD.encode(value).into());
        }
    }
    let header_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&Value::Object(header)).map_err(|_| EncryptionFailed)?);

    let sealing_key =
        aead::RandomizedNonceKey::new(enc.aead_algorithm(), &cek).map_err(|_| EncryptionFailed)?;
    let mut sealed = plaintext.to_vec();
    let nonce = sealing_key
        .seal_in_place_append_tag(aead::Aad::from(header_b64.as_bytes()), &mut sealed)
        .map_err(|_| EncryptionFailed)?;
    let (ciphertext, tag) = sealed.split_at(sealed.len() - TAG_BYTES);
    Ok(format!(
        "{header_b64}..{}.{}.{}",
        URL_SAFE_NO_PAD.encode(nonce.as_ref()),
        URL_SAFE_NO_PAD.encode(ciphertext),
        URL_SAFE_NO_PAD.encode(tag),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7518 Appendix C: the worked ECDH-ES example (A128GCM, apu "Alice",
    /// apv "Bob"), Bob's private key and Alice's ephemeral public key.
    #[test]
    fn rfc7518_appendix_c_derived_key() {
        let b64 = |s: &str| URL_SAFE_NO_PAD.decode(s).unwrap();
        let bob = EcdhEsP256Key::from_private_scalar(
            &b64("VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"),
            "bob",
        )
        .unwrap();
        let mut alice = vec![4u8];
        alice.extend(b64("gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0"));
        alice.extend(b64("SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"));
        let cek = derive_cek(&bob, &alice, JweEnc::A128Gcm, b"Alice", b"Bob").unwrap();
        assert_eq!(URL_SAFE_NO_PAD.encode(&*cek), "VqqN6vgjbSBcIijNcacQGg");
    }

    #[test]
    fn rfc7518_appendix_c_shared_secret_feeds_the_kdf() {
        // The Z value of Appendix C, hashed directly, gives the same key.
        let z: [u8; 32] = [
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49,
            110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
        ];
        let cek = concat_kdf(&z, JweEnc::A128Gcm, b"Alice", b"Bob").unwrap();
        assert_eq!(URL_SAFE_NO_PAD.encode(&*cek), "VqqN6vgjbSBcIijNcacQGg");
    }
}
