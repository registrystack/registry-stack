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
        Ok(Self(draw()?))
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

/// Draw one canonical nonce from the operating system random source: 32 bytes,
/// unpadded base64url. Both nonces this module produces are the same
/// construction, so there is one place it is written.
fn draw() -> Result<String, NonceError> {
    let mut bytes = [0_u8; DECODED_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| NonceError::Entropy)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Draw a challenge for a holder's key-binding proof.
///
/// This is not a request nonce, and the two must not be substituted for one
/// another. A request nonce correlates one request with the assertion answering
/// it; this crate draws it itself for every prepared request and there is no
/// seam for supplying one. A presentation nonce is chosen by whoever is asking
/// a holder to prove possession of its key, and it belongs to an exchange that
/// happens after issuance, between a holder and that party. This crate neither
/// sends it, receives it, nor reads the proof it appears in: it is offered here
/// because the construction is the one the contract already fixes, and a
/// challenge a caller improvises is the thing worth not improvising.
///
/// The construction is [`RequestNonce::generate`]'s: 32 bytes from the
/// operating system random source, encoded as unpadded base64url. Like a
/// request nonce it is uninterpreted, and it must never carry an identifier, a
/// selector value, a secret, or a document digest.
///
/// A fresh value is drawn per presentation. Reusing one lets a proof made for
/// an earlier exchange satisfy a later one.
pub fn presentation_nonce() -> Result<String, NonceError> {
    draw()
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

impl NonceError {
    /// A stable, machine-readable name for which kind of nonce failure this is.
    ///
    /// It exists for callers that have to branch or aggregate without matching
    /// an enum this crate may extend: a metric label, a structured log field, or
    /// a language binding that carries the discriminant across a boundary. The
    /// rendered message is for people and may be reworded; these names are part
    /// of the crate's contract and will not be renamed. A variant added later
    /// brings a new name rather than reusing one of these.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Entropy => "entropy",
            Self::NotCanonical => "not_canonical",
        }
    }
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

    /// A presentation challenge carries the same unguessability a request nonce
    /// does, because it is the same construction.
    #[test]
    fn a_presentation_nonce_is_canonical_and_never_repeats() {
        let nonce = presentation_nonce().expect("the system random source works");
        assert!(is_canonical(&nonce), "{nonce}");
        assert_eq!(
            nonce.len(),
            ENCODED_CHARACTERS,
            "a challenge is the same length as a request nonce"
        );
        assert_ne!(
            nonce,
            presentation_nonce().expect("the system random source works")
        );
    }

    /// The two nonces are the same construction and separate values. A
    /// presentation challenge that arrived from `generate` would tie a
    /// presentation to the request that produced the credential.
    #[test]
    fn a_presentation_nonce_is_not_the_request_nonce() {
        let request = RequestNonce::generate().expect("the system random source works");
        let presentation = presentation_nonce().expect("the system random source works");
        assert_ne!(request.as_str(), presentation);
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

    /// The discriminant is what a binding, a metric label, or a caller's own
    /// branch reads, so every variant has one and no two share it.
    #[test]
    fn every_nonce_failure_reports_its_own_stable_kind() {
        let cases = [
            (NonceError::Entropy, "entropy"),
            (NonceError::NotCanonical, "not_canonical"),
        ];
        for (error, kind) in &cases {
            assert_eq!(error.kind(), *kind, "{error}");
        }
        let kinds: std::collections::BTreeSet<&str> =
            cases.iter().map(|(error, _)| error.kind()).collect();
        assert_eq!(kinds.len(), cases.len(), "two variants share a kind");
    }
}
