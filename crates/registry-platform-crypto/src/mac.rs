// SPDX-License-Identifier: Apache-2.0
//! HMAC tags for message authentication schemes a registry consumer does not
//! choose, such as a provider's delivery callback signature.
//!
//! Verification compares tags in constant time and refuses a tag of the
//! wrong length. HMAC-SHA1 exists only to interoperate with legacy schemes
//! that still sign with it; a scheme a registry product defines uses
//! HMAC-SHA256.

use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::hmac;
use thiserror::Error;

/// The byte length of an HMAC-SHA1 tag.
pub const HMAC_SHA1_TAG_BYTES: usize = 20;

/// The byte length of an HMAC-SHA256 tag.
pub const HMAC_SHA256_TAG_BYTES: usize = 32;

/// A tag that does not authenticate the message under the key. Carries
/// nothing, so a refusal never repeats the tag, the key, or the message.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("the message authentication tag does not match")]
pub struct MacMismatch;

/// The HMAC-SHA1 tag of `message` under `key`, for legacy interoperability
/// only.
#[must_use]
pub fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; HMAC_SHA1_TAG_BYTES] {
    tag(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key, message)
}

/// The HMAC-SHA256 tag of `message` under `key`.
#[must_use]
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; HMAC_SHA256_TAG_BYTES] {
    tag(hmac::HMAC_SHA256, key, message)
}

/// Check `tag` against the HMAC-SHA1 tag of `message` under `key` in
/// constant time, for legacy interoperability only.
///
/// # Errors
///
/// [`MacMismatch`] when the tag differs or has the wrong length.
pub fn verify_hmac_sha1(key: &[u8], message: &[u8], tag: &[u8]) -> Result<(), MacMismatch> {
    verify(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key, message, tag)
}

/// Check `tag` against the HMAC-SHA256 tag of `message` under `key` in
/// constant time.
///
/// # Errors
///
/// [`MacMismatch`] when the tag differs or has the wrong length.
pub fn verify_hmac_sha256(key: &[u8], message: &[u8], tag: &[u8]) -> Result<(), MacMismatch> {
    verify(hmac::HMAC_SHA256, key, message, tag)
}

/// Whether two byte strings are equal, compared in time that depends only on
/// their lengths, for a shared secret such as a bearer token in a URL.
#[must_use]
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    verify_slices_are_equal(left, right).is_ok()
}

fn tag<const N: usize>(algorithm: hmac::Algorithm, key: &[u8], message: &[u8]) -> [u8; N] {
    let tag = hmac::sign(&hmac::Key::new(algorithm, key), message);
    let mut bytes = [0u8; N];
    bytes.copy_from_slice(tag.as_ref());
    bytes
}

fn verify(
    algorithm: hmac::Algorithm,
    key: &[u8],
    message: &[u8],
    tag: &[u8],
) -> Result<(), MacMismatch> {
    hmac::verify(&hmac::Key::new(algorithm, key), message, tag).map_err(|_| MacMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 2202 section 3, test case 2.
    const SHA1_KEY: &[u8] = b"Jefe";
    const SHA1_MESSAGE: &[u8] = b"what do ya want for nothing?";
    const SHA1_TAG: &str = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79";

    // RFC 4231 section 4.3, test case 2.
    const SHA256_KEY: &[u8] = b"Jefe";
    const SHA256_MESSAGE: &[u8] = b"what do ya want for nothing?";
    const SHA256_TAG: &str = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

    fn decode(tag: &str) -> Vec<u8> {
        (0..tag.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&tag[index..index + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn hmac_sha1_matches_its_known_answer() {
        assert_eq!(hmac_sha1(SHA1_KEY, SHA1_MESSAGE).to_vec(), decode(SHA1_TAG));
        assert_eq!(
            verify_hmac_sha1(SHA1_KEY, SHA1_MESSAGE, &decode(SHA1_TAG)),
            Ok(())
        );
    }

    #[test]
    fn hmac_sha256_matches_its_known_answer() {
        assert_eq!(
            hmac_sha256(SHA256_KEY, SHA256_MESSAGE).to_vec(),
            decode(SHA256_TAG)
        );
        assert_eq!(
            verify_hmac_sha256(SHA256_KEY, SHA256_MESSAGE, &decode(SHA256_TAG)),
            Ok(())
        );
    }

    #[test]
    fn a_wrong_hmac_sha1_tag_is_refused() {
        let tag = decode(SHA1_TAG);
        let mut flipped = tag.clone();
        flipped[19] ^= 1;
        for wrong in [
            flipped.as_slice(),
            &tag[..19],
            &[tag.as_slice(), &[0]].concat(),
            &[],
        ] {
            assert_eq!(
                verify_hmac_sha1(SHA1_KEY, SHA1_MESSAGE, wrong),
                Err(MacMismatch)
            );
        }
        assert_eq!(
            verify_hmac_sha1(b"Jeff", SHA1_MESSAGE, &tag),
            Err(MacMismatch)
        );
        assert_eq!(
            verify_hmac_sha1(SHA1_KEY, b"what do ya want for nothing!", &tag),
            Err(MacMismatch)
        );
    }

    #[test]
    fn a_wrong_hmac_sha256_tag_is_refused() {
        let tag = decode(SHA256_TAG);
        let mut flipped = tag.clone();
        flipped[0] ^= 0x80;
        for wrong in [
            flipped.as_slice(),
            &tag[..31],
            &[tag.as_slice(), &[0]].concat(),
            &[],
        ] {
            assert_eq!(
                verify_hmac_sha256(SHA256_KEY, SHA256_MESSAGE, wrong),
                Err(MacMismatch)
            );
        }
        assert_eq!(
            verify_hmac_sha256(b"Jeff", SHA256_MESSAGE, &tag),
            Err(MacMismatch)
        );
        // An HMAC-SHA1 tag never passes as a truncated HMAC-SHA256 one.
        assert_eq!(
            verify_hmac_sha256(SHA256_KEY, SHA256_MESSAGE, &decode(SHA1_TAG)),
            Err(MacMismatch)
        );
    }

    #[test]
    fn constant_time_equality_compares_bytes_and_lengths() {
        assert!(constant_time_eq(b"token", b"token"));
        assert!(constant_time_eq(b"", b""));
        assert!(!constant_time_eq(b"token", b"tokeN"));
        assert!(!constant_time_eq(b"token", b"toke"));
        assert!(!constant_time_eq(b"", b"t"));
    }
}
