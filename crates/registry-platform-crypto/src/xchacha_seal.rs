// SPDX-License-Identifier: Apache-2.0
//! XChaCha20-Poly1305 sealing with a fresh random 192-bit nonce per seal.
//!
//! The 192-bit nonce is what makes random nonces safe under a long-lived key
//! that seals many values; a 96-bit random nonce would cap one key at about
//! 2^32 seals. The primitive works at the "nonce, ciphertext, tag" level:
//! [`seal`] returns `nonce (24) || ciphertext || tag (16)` and [`open`] takes
//! the same bytes. Version bytes, key derivation, associated data layout, and
//! where the nonce is stored all stay with the caller, so a product keeps its
//! own wire format (a caller that stores the nonce separately splits the first
//! [`NONCE_BYTES`] bytes off the result).
//!
//! Failures carry no key, nonce, plaintext, or ciphertext.

use aws_lc_rs::rand;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use thiserror::Error;
use zeroize::Zeroizing;

/// Length of the nonce that leads every sealed value.
pub const NONCE_BYTES: usize = 24;

/// Length of the Poly1305 authentication tag that ends every sealed value.
pub const TAG_BYTES: usize = 16;

/// Why a value was not sealed or opened.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum XChaChaSealError {
    /// The operating system's random number generator failed.
    #[error("the operating system random number generator failed")]
    Randomness,
    /// The value could not be encrypted.
    #[error("the value could not be sealed")]
    Seal,
    /// The input is too short to hold a nonce and a tag.
    #[error("the sealed value is malformed")]
    Malformed,
    /// The key, associated data, or sealed bytes do not authenticate.
    #[error("the sealed value does not open")]
    Open,
}

/// Seal `plaintext` under `key`, binding it to `aad`.
///
/// Returns `nonce (24) || ciphertext || tag (16)`.
///
/// # Errors
///
/// [`XChaChaSealError::Randomness`] when no nonce can be drawn and
/// [`XChaChaSealError::Seal`] when encryption fails.
pub fn seal(
    key: &Zeroizing<[u8; 32]>,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, XChaChaSealError> {
    let mut nonce = [0u8; NONCE_BYTES];
    rand::fill(&mut nonce).map_err(|_| XChaChaSealError::Randomness)?;
    seal_with_nonce(key, &nonce, aad, plaintext)
}

fn seal_with_nonce(
    key: &Zeroizing<[u8; 32]>,
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, XChaChaSealError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| XChaChaSealError::Seal)?;
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| XChaChaSealError::Seal)?;
    let mut sealed = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
    sealed.extend_from_slice(nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

/// Open `sealed` (`nonce || ciphertext || tag`) under `key` and `aad`.
///
/// The plaintext is returned in a buffer that is wiped when dropped.
///
/// # Errors
///
/// [`XChaChaSealError::Malformed`] when `sealed` is shorter than a nonce plus
/// a tag, and [`XChaChaSealError::Open`] when it does not authenticate.
pub fn open(
    key: &Zeroizing<[u8; 32]>,
    aad: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, XChaChaSealError> {
    if sealed.len() < NONCE_BYTES + TAG_BYTES {
        return Err(XChaChaSealError::Malformed);
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_BYTES);
    let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| XChaChaSealError::Malformed)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| XChaChaSealError::Open)?;
    cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| XChaChaSealError::Open)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> Zeroizing<[u8; 32]> {
        Zeroizing::new([byte; 32])
    }

    #[test]
    fn round_trips_and_uses_a_fresh_nonce_per_seal() {
        let first = seal(&key(7), b"aad", b"plaintext").expect("seals");
        let second = seal(&key(7), b"aad", b"plaintext").expect("seals");
        assert_eq!(first.len(), NONCE_BYTES + b"plaintext".len() + TAG_BYTES);
        assert_ne!(first[..NONCE_BYTES], second[..NONCE_BYTES]);
        assert_eq!(
            open(&key(7), b"aad", &first).expect("opens").as_slice(),
            b"plaintext"
        );
    }

    #[test]
    fn empty_plaintext_and_empty_aad_round_trip() {
        let sealed = seal(&key(1), b"", b"").expect("seals");
        assert!(open(&key(1), b"", &sealed).expect("opens").is_empty());
    }

    #[test]
    fn any_altered_byte_of_nonce_ciphertext_or_tag_is_refused() {
        let sealed = seal(&key(7), b"aad", b"plaintext").expect("seals");
        for index in [
            0,
            NONCE_BYTES - 1,
            NONCE_BYTES,
            sealed.len() - TAG_BYTES - 1,
            sealed.len() - TAG_BYTES,
            sealed.len() - 1,
        ] {
            let mut altered = sealed.clone();
            altered[index] ^= 1;
            assert_eq!(
                open(&key(7), b"aad", &altered),
                Err(XChaChaSealError::Open),
                "byte {index}"
            );
        }
    }

    #[test]
    fn truncation_and_extension_are_refused() {
        let sealed = seal(&key(7), b"aad", b"plaintext").expect("seals");
        let mut extended = sealed.clone();
        extended.push(0);
        assert_eq!(
            open(&key(7), b"aad", &extended),
            Err(XChaChaSealError::Open)
        );
        assert_eq!(
            open(&key(7), b"aad", &sealed[..sealed.len() - 1]),
            Err(XChaChaSealError::Open)
        );
        for length in [0, 1, NONCE_BYTES, NONCE_BYTES + TAG_BYTES - 1] {
            assert_eq!(
                open(&key(7), b"aad", &sealed[..length]),
                Err(XChaChaSealError::Malformed),
                "length {length}"
            );
        }
    }

    #[test]
    fn a_different_aad_or_key_is_refused() {
        let sealed = seal(&key(7), b"aad", b"plaintext").expect("seals");
        assert_eq!(open(&key(7), b"aae", &sealed), Err(XChaChaSealError::Open));
        assert_eq!(open(&key(7), b"", &sealed), Err(XChaChaSealError::Open));
        assert_eq!(open(&key(8), b"aad", &sealed), Err(XChaChaSealError::Open));
    }

    // Each product seals with its own framing today. These tests restate that
    // sealing logic with a fixed nonce and prove the primitive opens it.

    /// `registry-adapter-engine` continuation cursors and `registry-breg`
    /// cursors: `version || nonce || ciphertext || tag`, associated data a
    /// domain label.
    #[test]
    fn opens_a_version_prefixed_envelope() {
        let secret = [3u8; 32];
        let nonce = [9u8; NONCE_BYTES];
        let aad = b"registry.cursor\x00\x03";
        let ciphertext = XChaCha20Poly1305::new_from_slice(&secret)
            .expect("key")
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: b"{\"page\":2}",
                    aad,
                },
            )
            .expect("encrypts");
        let mut envelope = vec![3u8];
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);

        let opened = open(&Zeroizing::new(secret), aad, &envelope[1..]).expect("opens");
        assert_eq!(opened.as_slice(), b"{\"page\":2}");
        // The primitive's own output uses the same layout, so a caller can
        // prefix its version byte and strip it again.
        let sealed = seal(&Zeroizing::new(secret), aad, b"{\"page\":2}").expect("seals");
        let mut framed = vec![3u8];
        framed.extend_from_slice(&sealed);
        let (nonce_part, ciphertext_part) = framed[1..].split_at(NONCE_BYTES);
        let reopened = XChaCha20Poly1305::new_from_slice(&secret)
            .expect("key")
            .decrypt(
                &XNonce::from(<[u8; NONCE_BYTES]>::try_from(nonce_part).expect("nonce")),
                Payload {
                    msg: ciphertext_part,
                    aad,
                },
            )
            .expect("the product's own logic opens the primitive's output");
        assert_eq!(reopened, b"{\"page\":2}");
    }

    /// `registry-evidence-oid4vci` sealed requests: nonce and ciphertext are
    /// stored in separate columns, with versioned associated data.
    #[test]
    fn opens_a_value_whose_nonce_is_stored_separately() {
        let secret = [5u8; 32];
        let nonce = [1u8; NONCE_BYTES];
        let aad = b"oid4vci-sealed-request\x00wallet\x00issuance\x001\x002\x003";
        let ciphertext = XChaCha20Poly1305::new_from_slice(&secret)
            .expect("key")
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: b"prepared request",
                    aad,
                },
            )
            .expect("encrypts");

        let mut joined = nonce.to_vec();
        joined.extend_from_slice(&ciphertext);
        let opened = open(&Zeroizing::new(secret), aad, &joined).expect("opens");
        assert_eq!(opened.as_slice(), b"prepared request");

        let sealed = seal(&Zeroizing::new(secret), aad, b"prepared request").expect("seals");
        let (stored_nonce, stored_ciphertext) = sealed.split_at(NONCE_BYTES);
        assert_eq!(stored_nonce.len(), NONCE_BYTES);
        assert_eq!(
            stored_ciphertext.len(),
            b"prepared request".len() + TAG_BYTES
        );
    }

    #[test]
    fn seal_with_a_fixed_nonce_matches_the_reference_construction() {
        let secret = [5u8; 32];
        let nonce = [1u8; NONCE_BYTES];
        let expected = XChaCha20Poly1305::new_from_slice(&secret)
            .expect("key")
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: b"value",
                    aad: b"aad",
                },
            )
            .expect("encrypts");
        let sealed =
            seal_with_nonce(&Zeroizing::new(secret), &nonce, b"aad", b"value").expect("seals");
        assert_eq!(&sealed[..NONCE_BYTES], &nonce);
        assert_eq!(&sealed[NONCE_BYTES..], expected.as_slice());
    }
}
