// SPDX-License-Identifier: Apache-2.0
//! Field-level encryption for restricted Base Registry Engine fields.
//!
//! Every function here is pure and dependency-injected: the data-encryption
//! key (DEK) is always a caller-supplied 32-byte key, and no function reads
//! configuration, performs I/O, or keeps secrets beyond the buffers it returns.
//! The binary envelope layout, the HKDF info encodings, the AAD encoding, and
//! the JSON member tag are wire contract: changing any of them breaks stored
//! `bytea` columns and snapshot documents.

use aws_lc_rs::{aead, hkdf, hmac};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{Map, Value};
use thiserror::Error;
use zeroize::Zeroizing;

/// Algorithm name recorded for field encryption in operator-facing material.
pub const FIELD_ENCRYPTION_ALGORITHM: &str = "aes-256-gcm";
/// Version byte prefixing every Version 1 field envelope.
pub const FIELD_ENCRYPTION_ENVELOPE_VERSION: u8 = 1;
/// JSON member tag marking one encrypted field value inside row and snapshot
/// maps. Part of the stable wire contract.
pub const ENVELOPE_MEMBER_TAG: &str = "__bregEncryptedV1";

/// Domain separation for the HKDF info that derives a field AEAD subkey.
/// Exact bytes are wire contract.
const DOMAIN_FIELD_AEAD_KEY: &[u8] = b"breg-field-aead-key/v1";
/// Domain separation for the HKDF info that derives a field blind-index subkey.
/// Exact bytes are wire contract.
const DOMAIN_FIELD_INDEX_KEY: &[u8] = b"breg-field-index-key/v1";
/// Domain separation prefixing the AES-GCM associated data. Exact bytes are
/// wire contract.
const DOMAIN_FIELD_ENVELOPE_AAD: &[u8] = b"breg-field-envelope-aad/v1";

/// AES-GCM authentication tag length in bytes.
const TAG_BYTES: usize = 16;
/// Envelope bytes before ciphertext: version, key version, nonce.
const HEADER_BYTES: usize = 1 + 4 + aead::NONCE_LEN;
/// Maximum plaintext one field may carry. A row holds several encrypted
/// fields, and each envelope grows by roughly a third inside base64 JSON, so
/// fields stay an order below the 2 MiB snapshot budget.
pub const MAX_FIELD_PLAINTEXT_BYTES: usize = 64 * 1024;
/// Maximum accepted envelope length: header, plaintext cap, tag.
pub const MAX_FIELD_ENVELOPE_BYTES: usize = HEADER_BYTES + MAX_FIELD_PLAINTEXT_BYTES + TAG_BYTES;

/// Registry, entity, and field identity binding one HKDF subkey derivation.
#[derive(Clone, Copy, Debug)]
pub struct FieldKeyInfo<'a> {
    pub registry_id: &'a str,
    pub entity_id: &'a str,
    pub field_id: &'a str,
}

/// Exact additional-authenticated-data identity of one field envelope.
#[derive(Clone, Copy, Debug)]
pub struct FieldAad<'a> {
    pub registry_id: &'a str,
    pub entity_id: &'a str,
    pub field_id: &'a str,
    pub record_id: &'a str,
    pub key_version: u32,
}

/// Value-free failure while sealing, opening, or inspecting a field envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
#[non_exhaustive]
pub enum FieldCryptoError {
    #[error("field envelope version is unsupported")]
    UnsupportedEnvelopeVersion,
    #[error("field envelope is truncated or malformed")]
    MalformedEnvelope,
    #[error("field plaintext exceeds the encryption size limit")]
    FieldTooLarge,
    #[error("field envelope exceeds the encryption size limit")]
    EnvelopeTooLarge,
    #[error("field subkey derivation failed")]
    KeyDerivationFailed,
    #[error("field envelope could not be sealed")]
    SealingFailed,
    #[error("field envelope failed authentication")]
    AuthenticationFailed,
}

/// HKDF-Expand-SHA256 over `prk` and `info`, filling `okm` completely.
/// The field DEK is used directly as the PRK, so no Extract step runs.
fn hkdf_expand_sha256(prk: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), FieldCryptoError> {
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, prk);
    prk.expand(&[info], OkmLength(okm.len()))
        .and_then(|expanded| expanded.fill(okm))
        .map_err(|_| FieldCryptoError::KeyDerivationFailed)
}

/// Requested HKDF output length, so `hkdf::Prk::expand` can fill buffers of
/// any length the caller validated.
struct OkmLength(usize);

impl hkdf::KeyType for OkmLength {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-Expand info bytes: domain label, then each field as a big-endian u32
/// byte length followed by its UTF-8 bytes, so field boundaries are
/// unambiguous.
fn domain_prefixed_info(label: &[u8], fields: &[&str]) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(label.len() + fields.iter().map(|field| field.len() + 4).sum::<usize>());
    bytes.extend_from_slice(label);
    for field in fields {
        let length = u32::try_from(field.len()).expect("registry identifiers are far below 4 GiB");
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(field.as_bytes());
    }
    bytes
}

/// Associated data for one envelope: the domain label, the four identity
/// fields length-prefixed, then the key version as big-endian u32.
fn envelope_aad_bytes(aad: &FieldAad<'_>) -> Vec<u8> {
    let mut bytes = domain_prefixed_info(
        DOMAIN_FIELD_ENVELOPE_AAD,
        &[aad.registry_id, aad.entity_id, aad.field_id, aad.record_id],
    );
    bytes.extend_from_slice(&aad.key_version.to_be_bytes());
    bytes
}

/// Expand the DEK into one 32-byte subkey under a domain label.
fn derive_field_subkey(
    dek: &[u8; 32],
    info: &FieldKeyInfo<'_>,
    label: &[u8],
) -> Zeroizing<[u8; 32]> {
    let info_bytes =
        domain_prefixed_info(label, &[info.registry_id, info.entity_id, info.field_id]);
    let mut subkey = Zeroizing::new([0u8; 32]);
    hkdf_expand_sha256(dek, &info_bytes, subkey.as_mut())
        .expect("HKDF-SHA256 expands 32 bytes from a 32-byte PRK with non-empty info");
    subkey
}

/// Derive the AES-256-GCM subkey for one field from the DEK.
#[must_use]
pub fn derive_field_aead_key(dek: &[u8; 32], info: &FieldKeyInfo<'_>) -> Zeroizing<[u8; 32]> {
    derive_field_subkey(dek, info, DOMAIN_FIELD_AEAD_KEY)
}

/// Derive the blind-index HMAC subkey for one field from the DEK.
#[must_use]
pub fn derive_field_index_key(dek: &[u8; 32], info: &FieldKeyInfo<'_>) -> Zeroizing<[u8; 32]> {
    derive_field_subkey(dek, info, DOMAIN_FIELD_INDEX_KEY)
}

/// Seal one field plaintext into a Version 1 envelope under a fresh random
/// 96-bit nonce.
///
/// # Errors
/// [`FieldCryptoError::FieldTooLarge`] when the plaintext exceeds
/// [`MAX_FIELD_PLAINTEXT_BYTES`].
pub fn seal_field(
    key: &[u8; 32],
    aad: &FieldAad<'_>,
    plaintext: &[u8],
) -> Result<Vec<u8>, FieldCryptoError> {
    if plaintext.len() > MAX_FIELD_PLAINTEXT_BYTES {
        return Err(FieldCryptoError::FieldTooLarge);
    }
    let sealing_key = aead::RandomizedNonceKey::new(&aead::AES_256_GCM, key)
        .expect("AES-256-GCM accepts the fixed 32-byte field key");
    let aad_bytes = envelope_aad_bytes(aad);
    let mut ciphertext_and_tag = plaintext.to_vec();
    let nonce = sealing_key
        .seal_in_place_append_tag(aead::Aad::from(aad_bytes), &mut ciphertext_and_tag)
        .map_err(|_| FieldCryptoError::SealingFailed)?;
    let mut envelope = Vec::with_capacity(HEADER_BYTES + ciphertext_and_tag.len());
    envelope.push(FIELD_ENCRYPTION_ENVELOPE_VERSION);
    envelope.extend_from_slice(&aad.key_version.to_be_bytes());
    envelope.extend_from_slice(nonce.as_ref());
    envelope.extend_from_slice(&ciphertext_and_tag);
    Ok(envelope)
}

/// The validated header and payload slices of one Version 1 envelope.
struct ParsedEnvelope<'a> {
    key_version: u32,
    nonce: [u8; aead::NONCE_LEN],
    ciphertext_and_tag: &'a [u8],
}

/// Validate envelope structure without touching key material.
fn parse_envelope(envelope: &[u8]) -> Result<ParsedEnvelope<'_>, FieldCryptoError> {
    if envelope.len() > MAX_FIELD_ENVELOPE_BYTES {
        return Err(FieldCryptoError::EnvelopeTooLarge);
    }
    if envelope.len() < HEADER_BYTES + TAG_BYTES {
        return Err(FieldCryptoError::MalformedEnvelope);
    }
    if envelope[0] != FIELD_ENCRYPTION_ENVELOPE_VERSION {
        return Err(FieldCryptoError::UnsupportedEnvelopeVersion);
    }
    let key_version = u32::from_be_bytes(envelope[1..5].try_into().expect("four bytes are a u32"));
    let mut nonce = [0u8; aead::NONCE_LEN];
    nonce.copy_from_slice(&envelope[5..HEADER_BYTES]);
    Ok(ParsedEnvelope {
        key_version,
        nonce,
        ciphertext_and_tag: &envelope[HEADER_BYTES..],
    })
}

/// Open a Version 1 envelope, returning the zeroized-on-drop plaintext.
/// The key version stored in the envelope must equal `aad.key_version`, so a
/// stored version cannot be swapped without failing authentication.
///
/// # Errors
/// [`FieldCryptoError`] for any structural defect or any tamper with the
/// nonce, ciphertext, tag, or associated data.
pub fn open_field(
    key: &[u8; 32],
    aad: &FieldAad<'_>,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, FieldCryptoError> {
    let parsed = parse_envelope(envelope)?;
    if parsed.key_version != aad.key_version {
        return Err(FieldCryptoError::AuthenticationFailed);
    }
    let opening_key = aead::RandomizedNonceKey::new(&aead::AES_256_GCM, key)
        .expect("AES-256-GCM accepts the fixed 32-byte field key");
    let aad_bytes = envelope_aad_bytes(aad);
    let mut plaintext_and_tag = Zeroizing::new(parsed.ciphertext_and_tag.to_vec());
    opening_key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(parsed.nonce),
            aead::Aad::from(aad_bytes),
            &mut plaintext_and_tag,
        )
        .map_err(|_| FieldCryptoError::AuthenticationFailed)?;
    let plaintext_len = plaintext_and_tag.len() - TAG_BYTES;
    plaintext_and_tag.truncate(plaintext_len);
    Ok(plaintext_and_tag)
}

/// Deterministic blind index over a normalized field value. The domain label
/// is already bound through the HKDF info of the index subkey, so the HMAC
/// covers exactly the normalized UTF-8 bytes.
#[must_use]
pub fn blind_index_hmac(key: &[u8; 32], normalized: &str) -> [u8; 32] {
    let tag = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, key),
        normalized.as_bytes(),
    );
    let mut index = [0u8; 32];
    index.copy_from_slice(tag.as_ref());
    index
}

/// Read the key version from an envelope without opening it. The value is
/// unauthenticated until [`open_field`] succeeds.
///
/// # Errors
/// [`FieldCryptoError`] when the envelope is structurally invalid.
pub fn envelope_key_version(envelope: &[u8]) -> Result<u32, FieldCryptoError> {
    parse_envelope(envelope).map(|parsed| parsed.key_version)
}

/// The in-JSON representation of one encrypted field value inside row and
/// snapshot maps: `{"__bregEncryptedV1": "<standard base64 envelope>"}`.
#[must_use]
pub fn envelope_member_json(envelope: &[u8]) -> Value {
    let mut member = Map::new();
    member.insert(
        ENVELOPE_MEMBER_TAG.to_owned(),
        Value::String(STANDARD.encode(envelope)),
    );
    Value::Object(member)
}

/// Recover the envelope bytes from the value [`envelope_member_json`] produces.
/// Any other object shape, non-string member, or invalid base64 yields `None`;
/// structural envelope validation stays with [`open_field`] and
/// [`envelope_key_version`].
#[must_use]
pub fn parse_envelope_member(value: &Value) -> Option<Vec<u8>> {
    let object = value.as_object()?;
    if object.len() != 1 {
        return None;
    }
    let encoded = object.get(ENVELOPE_MEMBER_TAG)?.as_str()?;
    STANDARD.decode(encoded).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEK: [u8; 32] = [0x5A; 32];
    const OTHER_DEK: [u8; 32] = [0xA5; 32];
    const REGISTRY_ID: &str = "example-licensing";
    const ENTITY_ID: &str = "professional_licence";
    const FIELD_ID: &str = "holder_name";
    const RECORD_ID: &str = "rec-000042";
    const KEY_VERSION: u32 = 7;

    fn key_info() -> FieldKeyInfo<'static> {
        FieldKeyInfo {
            registry_id: REGISTRY_ID,
            entity_id: ENTITY_ID,
            field_id: FIELD_ID,
        }
    }

    fn aad() -> FieldAad<'static> {
        FieldAad {
            registry_id: REGISTRY_ID,
            entity_id: ENTITY_ID,
            field_id: FIELD_ID,
            record_id: RECORD_ID,
            key_version: KEY_VERSION,
        }
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert!(
            value.len().is_multiple_of(2),
            "hex vectors are byte-aligned"
        );
        let nibble = |byte: u8| -> u8 {
            match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => panic!("hex vectors use hexadecimal digits only"),
            }
        };
        value
            .as_bytes()
            .chunks(2)
            .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
            .collect()
    }

    #[test]
    fn seal_open_round_trips_representative_plaintexts() {
        let key = *derive_field_aead_key(&DEK, &key_info());
        let multi_kb: Vec<u8> = (0..8192).map(|byte| (byte % 251) as u8).collect();
        let boundary = vec![0xD7; MAX_FIELD_PLAINTEXT_BYTES];
        for plaintext in [
            &b""[..],
            &b"x"[..],
            multi_kb.as_slice(),
            boundary.as_slice(),
        ] {
            let envelope = seal_field(&key, &aad(), plaintext).expect("field seals");
            assert_eq!(envelope.len(), HEADER_BYTES + plaintext.len() + TAG_BYTES);
            let opened = open_field(&key, &aad(), &envelope).expect("field opens");
            assert_eq!(opened.as_slice(), plaintext);
        }
    }

    #[test]
    fn seal_draws_a_fresh_nonce_per_call() {
        let key = *derive_field_aead_key(&DEK, &key_info());
        let first = seal_field(&key, &aad(), b"same plaintext").expect("field seals");
        let second = seal_field(&key, &aad(), b"same plaintext").expect("field seals");
        assert_ne!(first, second);
        let nonce_range = HEADER_BYTES - aead::NONCE_LEN..HEADER_BYTES;
        assert_ne!(&first[nonce_range.clone()], &second[nonce_range]);
    }

    #[test]
    fn open_rejects_every_tampered_envelope_byte() {
        let key = *derive_field_aead_key(&DEK, &key_info());
        let envelope = seal_field(&key, &aad(), b"restricted holder name").expect("field seals");
        assert!(open_field(&key, &aad(), &envelope).is_ok());
        let mut offsets = vec![0];
        offsets.extend(1..HEADER_BYTES);
        offsets.push(HEADER_BYTES);
        offsets.push(envelope.len() - TAG_BYTES - 1);
        offsets.push(envelope.len() - 1);
        for offset in offsets {
            let mut tampered = envelope.clone();
            tampered[offset] ^= 0x01;
            assert!(
                open_field(&key, &aad(), &tampered).is_err(),
                "tampering with envelope byte {offset} must not open"
            );
        }
    }

    #[test]
    fn open_binds_every_aad_component() {
        let key = *derive_field_aead_key(&DEK, &key_info());
        let envelope = seal_field(&key, &aad(), b"restricted holder name").expect("field seals");
        assert!(open_field(&key, &aad(), &envelope).is_ok());
        macro_rules! assert_component_is_bound {
            ($member:ident, $changed:expr) => {{
                let mut changed = aad();
                changed.$member = $changed;
                assert_eq!(
                    open_field(&key, &changed, &envelope),
                    Err(FieldCryptoError::AuthenticationFailed)
                );
            }};
        }
        assert_component_is_bound!(registry_id, "other-registry");
        assert_component_is_bound!(entity_id, "other_entity");
        assert_component_is_bound!(field_id, "other_field");
        assert_component_is_bound!(record_id, "rec-000043");
        assert_component_is_bound!(key_version, KEY_VERSION + 1);
        let wrong_key = *derive_field_aead_key(&OTHER_DEK, &key_info());
        assert_eq!(
            open_field(&wrong_key, &aad(), &envelope),
            Err(FieldCryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn open_rejects_truncated_envelopes() {
        let key = *derive_field_aead_key(&DEK, &key_info());
        let envelope = seal_field(&key, &aad(), b"restricted holder name").expect("field seals");
        for truncation in 0..envelope.len() {
            assert!(
                open_field(&key, &aad(), &envelope[..truncation]).is_err(),
                "truncation to {truncation} bytes must not open"
            );
        }
    }

    #[test]
    fn envelopes_reject_oversize_input_and_wrong_versions() {
        let key = *derive_field_aead_key(&DEK, &key_info());
        assert_eq!(
            seal_field(&key, &aad(), &vec![0u8; MAX_FIELD_PLAINTEXT_BYTES + 1]),
            Err(FieldCryptoError::FieldTooLarge)
        );
        let mut oversize = vec![FIELD_ENCRYPTION_ENVELOPE_VERSION; MAX_FIELD_ENVELOPE_BYTES + 1];
        oversize[0] = FIELD_ENCRYPTION_ENVELOPE_VERSION;
        assert_eq!(
            open_field(&key, &aad(), &oversize),
            Err(FieldCryptoError::EnvelopeTooLarge)
        );
        let mut wrong_version =
            seal_field(&key, &aad(), b"restricted holder name").expect("field seals");
        for byte in [0u8, 2u8, 0xFFu8] {
            wrong_version[0] = byte;
            assert_eq!(
                open_field(&key, &aad(), &wrong_version),
                Err(FieldCryptoError::UnsupportedEnvelopeVersion)
            );
        }
    }

    #[test]
    fn hkdf_expand_matches_rfc5869_test_case_1() {
        // RFC 5869 Appendix A, Test Case 1 (SHA-256), Expand stage only: the
        // DEK-as-PRK construction never runs Extract.
        const PRK: &str = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
        const INFO: &str = "f0f1f2f3f4f5f6f7f8f9";
        const OKM: &str =
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
        let mut expanded = vec![0u8; OKM.len() / 2];
        hkdf_expand_sha256(&decode_hex(PRK), &decode_hex(INFO), &mut expanded)
            .expect("HKDF-Expand over RFC inputs succeeds");
        assert_eq!(expanded, decode_hex(OKM));
    }

    #[test]
    fn derived_subkeys_are_distinct_and_context_bound() {
        let aead_key = derive_field_aead_key(&DEK, &key_info());
        let index_key = derive_field_index_key(&DEK, &key_info());
        assert_ne!(aead_key.as_ref(), index_key.as_ref());
        macro_rules! assert_info_is_bound {
            ($member:ident, $changed:expr) => {{
                let mut changed = key_info();
                changed.$member = $changed;
                let changed_aead = derive_field_aead_key(&DEK, &changed);
                let changed_index = derive_field_index_key(&DEK, &changed);
                assert_ne!(aead_key.as_ref(), changed_aead.as_ref());
                assert_ne!(index_key.as_ref(), changed_index.as_ref());
            }};
        }
        assert_info_is_bound!(registry_id, "other-registry");
        assert_info_is_bound!(entity_id, "other_entity");
        assert_info_is_bound!(field_id, "other_field");
        let other_aead = derive_field_aead_key(&OTHER_DEK, &key_info());
        let other_index = derive_field_index_key(&OTHER_DEK, &key_info());
        assert_ne!(aead_key.as_ref(), other_aead.as_ref());
        assert_ne!(index_key.as_ref(), other_index.as_ref());
    }

    #[test]
    fn length_prefixes_keep_field_boundaries_unambiguous() {
        let joined = domain_prefixed_info(DOMAIN_FIELD_AEAD_KEY, &["ab", "cde"]);
        let collided = domain_prefixed_info(DOMAIN_FIELD_AEAD_KEY, &["a", "bcde"]);
        assert_ne!(joined, collided);
        let mut expected = DOMAIN_FIELD_AEAD_KEY.to_vec();
        expected.extend_from_slice(&2u32.to_be_bytes());
        expected.extend_from_slice(b"ab");
        expected.extend_from_slice(&3u32.to_be_bytes());
        expected.extend_from_slice(b"cde");
        assert_eq!(joined, expected);
    }

    #[test]
    fn blind_index_is_deterministic_and_key_sensitive() {
        let index_key = *derive_field_index_key(&DEK, &key_info());
        assert_eq!(
            blind_index_hmac(&index_key, "Ada Lovelace"),
            blind_index_hmac(&index_key, "Ada Lovelace")
        );
        let other_key = *derive_field_index_key(&OTHER_DEK, &key_info());
        assert_ne!(
            blind_index_hmac(&index_key, "Ada Lovelace"),
            blind_index_hmac(&other_key, "Ada Lovelace")
        );
        assert_ne!(
            blind_index_hmac(&index_key, "Ada Lovelace"),
            blind_index_hmac(&index_key, "ada lovelace")
        );
    }

    #[test]
    fn envelope_member_json_is_deterministic_and_round_trips() {
        let key = *derive_field_aead_key(&DEK, &key_info());
        let envelope = seal_field(&key, &aad(), b"restricted holder name").expect("field seals");
        let member = envelope_member_json(&envelope);
        let encoded = serde_json::to_string(&member).expect("member serializes");
        assert_eq!(
            encoded,
            format!(
                "{{\"{ENVELOPE_MEMBER_TAG}\":\"{}\"}}",
                STANDARD.encode(&envelope)
            )
        );
        assert_eq!(
            serde_json::to_string(&envelope_member_json(&envelope)).expect("member serializes"),
            encoded
        );
        assert_eq!(
            parse_envelope_member(&member).as_deref(),
            Some(&envelope[..])
        );
    }

    #[test]
    fn parse_envelope_member_rejects_other_shapes() {
        let key = *derive_field_aead_key(&DEK, &key_info());
        let envelope = seal_field(&key, &aad(), b"restricted holder name").expect("field seals");
        let base64_envelope = STANDARD.encode(&envelope);
        for value in [
            serde_json::json!("plain string"),
            serde_json::json!({}),
            serde_json::json!({"other": "value"}),
            serde_json::json!({"__bregEncryptedV2": "value"}),
            serde_json::json!({ENVELOPE_MEMBER_TAG: 7}),
            serde_json::json!({ENVELOPE_MEMBER_TAG: base64_envelope, "extra": null}),
            serde_json::json!({ENVELOPE_MEMBER_TAG: "not base64!"}),
        ] {
            assert_eq!(
                parse_envelope_member(&value),
                None,
                "shape {value} is not an envelope member"
            );
        }
        // Valid base64 of non-envelope bytes parses: structural validation
        // stays with open_field and envelope_key_version.
        let not_an_envelope = serde_json::json!({ENVELOPE_MEMBER_TAG: STANDARD.encode([2u8; 40])});
        let parsed = parse_envelope_member(&not_an_envelope).expect("shape decodes");
        assert_eq!(
            open_field(&key, &aad(), &parsed),
            Err(FieldCryptoError::UnsupportedEnvelopeVersion)
        );
    }

    #[test]
    fn envelope_key_version_peeks_without_opening() {
        let key = *derive_field_aead_key(&DEK, &key_info());
        let envelope = seal_field(&key, &aad(), b"restricted holder name").expect("field seals");
        assert_eq!(envelope_key_version(&envelope), Ok(KEY_VERSION));
        let mut wrong_version = envelope.clone();
        wrong_version[0] = 2;
        assert_eq!(
            envelope_key_version(&wrong_version),
            Err(FieldCryptoError::UnsupportedEnvelopeVersion)
        );
        assert_eq!(
            envelope_key_version(&[]),
            Err(FieldCryptoError::MalformedEnvelope)
        );
        let oversize = vec![0u8; MAX_FIELD_ENVELOPE_BYTES + 1];
        assert_eq!(
            envelope_key_version(&oversize),
            Err(FieldCryptoError::EnvelopeTooLarge)
        );
    }
}
