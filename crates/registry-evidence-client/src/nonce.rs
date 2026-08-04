//! Canonical Evidence request nonce.
//!
//! The frozen request contract accepts exactly one encoding: the unpadded
//! base64url form of 32 bytes from a cryptographically secure random source.
//! The nonce is uninterpreted correlation data. It must never carry an
//! identifier, a selector value, a secret, or a document digest.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use thiserror::Error;

/// Exactly 32 random bytes per request, as the contract requires.
const DECODED_BYTES: usize = 32;
/// Unpadded base64url of 32 bytes is always 43 characters.
const ENCODED_CHARACTERS: usize = 43;

/// One canonical request nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestNonce(String);

impl RequestNonce {
    /// Draw a fresh nonce from the operating system random source.
    ///
    /// Every prepared request gets its own value. Reusing one across two
    /// requests would break the correlation the verifier depends on.
    pub fn generate() -> Result<Self, NonceError> {
        let mut bytes = [0_u8; DECODED_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| NonceError::Entropy)?;
        Ok(Self(URL_SAFE_NO_PAD.encode(bytes)))
    }

    /// Check that a retained nonce string is still the canonical encoding, such
    /// as one read back from a relying party's own request record.
    ///
    /// This does not supply a nonce to a request. Every prepared request draws
    /// its own from [`RequestNonce::generate`], and there is no seam for
    /// substituting an outside value.
    pub fn parse(value: &str) -> Result<Self, NonceError> {
        if is_canonical(value) {
            Ok(Self(value.to_owned()))
        } else {
            Err(NonceError::NotCanonical)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether a value is the canonical 43-character unpadded base64url encoding
/// of exactly 32 bytes. Padding, wrong length, a byte outside the alphabet,
/// and a noncanonical final symbol all fail, matching the runtime rule the
/// request contract states.
fn is_canonical(value: &str) -> bool {
    if value.len() != ENCODED_CHARACTERS
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return false;
    }
    match URL_SAFE_NO_PAD.decode(value) {
        Ok(decoded) => decoded.len() == DECODED_BYTES,
        Err(_) => false,
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NonceError {
    #[error("the system random source refused to supply request nonce bytes")]
    Entropy,
    #[error("the request nonce is not the canonical encoding of 32 bytes")]
    NotCanonical,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_nonce_is_canonical() {
        let nonce = RequestNonce::generate().expect("the system random source works");
        assert_eq!(nonce.as_str().len(), ENCODED_CHARACTERS);
        assert!(nonce
            .as_str()
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')));
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(nonce.as_str())
                .expect("a generated nonce decodes")
                .len(),
            DECODED_BYTES
        );
        assert_eq!(RequestNonce::parse(nonce.as_str()), Ok(nonce));
    }

    #[test]
    fn two_generated_nonces_differ() {
        let first = RequestNonce::generate().expect("the system random source works");
        let second = RequestNonce::generate().expect("the system random source works");
        assert_ne!(first, second);
    }

    #[test]
    fn noncanonical_values_are_refused() {
        // The final symbol of a 43-character encoding carries only two
        // significant bits, so "AAAB" style tails are not canonical.
        for candidate in [
            "",
            "short",
            &"A".repeat(ENCODED_CHARACTERS - 1),
            &"A".repeat(ENCODED_CHARACTERS + 1),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\u{00e9}",
        ] {
            assert_eq!(
                RequestNonce::parse(candidate),
                Err(NonceError::NotCanonical),
                "candidate of {} bytes was accepted",
                candidate.len()
            );
        }
    }

    #[test]
    fn the_all_zero_nonce_is_canonical() {
        // 43 'A' characters decode to 32 zero bytes. It is a legal encoding
        // and only unacceptable because it is not random, which is a caller
        // obligation this type cannot check.
        assert!(is_canonical("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    }
}
