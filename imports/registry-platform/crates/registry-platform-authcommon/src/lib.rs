//! Shared authentication primitives that are independent of any identity
//! provider.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

const BEARER_SCHEME: &str = "Bearer";
const FINGERPRINT_PREFIX: &str = "sha256:";
const SHA256_HEX_LEN: usize = 64;

/// Minimum raw API-key size accepted by [`validate_api_key_entropy`].
///
/// This function cannot prove randomness, so the check intentionally enforces
/// the operator-facing invariant: generated keys must carry at least 256 bits
/// of material before they are hashed and distributed.
pub const MIN_API_KEY_ENTROPY_BYTES: usize = 32;

/// Error returned when an `Authorization: Bearer` value does not match the
/// platform's RFC 6750 profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum BearerParseError {
    /// The value is shorter than `Bearer <token>`.
    #[error("Authorization header must be 'Bearer <token>'")]
    Malformed,
    /// The auth scheme was not `Bearer`, compared ASCII case-insensitively.
    #[error("Authorization scheme must be Bearer")]
    InvalidScheme,
    /// The scheme and token must be separated by exactly one ASCII space.
    #[error("Bearer scheme and token must be separated by a single space")]
    InvalidSeparator,
    /// The header contains no token after the separator.
    #[error("Bearer token must not be empty")]
    EmptyToken,
    /// The token contains whitespace, which would create ambiguous extras.
    #[error("Bearer token must not contain whitespace")]
    TokenContainsWhitespace,
}

/// Parse `Authorization: Bearer <token>`.
///
/// The accepted shape is intentionally narrow: the scheme is
/// case-insensitive, the separator is exactly one ASCII space, and the token
/// must be non-empty with no whitespace.
pub fn parse_bearer_token(header: &str) -> Result<&str, BearerParseError> {
    if header.len() < BEARER_SCHEME.len() {
        return Err(BearerParseError::Malformed);
    }

    let (scheme, rest) = header.split_at(BEARER_SCHEME.len());
    if !scheme.eq_ignore_ascii_case(BEARER_SCHEME) {
        return Err(BearerParseError::InvalidScheme);
    }
    if rest.is_empty() {
        return Err(BearerParseError::Malformed);
    }
    if !rest.starts_with(' ') {
        return Err(BearerParseError::InvalidSeparator);
    }
    if rest.as_bytes().get(1).is_some_and(u8::is_ascii_whitespace) {
        return Err(BearerParseError::InvalidSeparator);
    }

    let token = &rest[1..];
    if token.is_empty() {
        return Err(BearerParseError::EmptyToken);
    }
    if token.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(BearerParseError::TokenContainsWhitespace);
    }

    Ok(token)
}

/// Error returned for malformed API-key fingerprints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum FingerprintFormatError {
    /// The fingerprint must start with `sha256:`.
    #[error("API key fingerprint must start with sha256:")]
    MissingPrefix,
    /// The digest must be exactly 64 lowercase hex characters.
    #[error("API key fingerprint must contain 64 lowercase hex characters")]
    InvalidLength,
    /// Uppercase or non-hex characters are not accepted.
    #[error("API key fingerprint must contain lowercase hex only")]
    InvalidHex,
}

/// Return the canonical `sha256:<64 lowercase hex>` fingerprint for a raw API
/// key.
pub fn fingerprint_api_key(plaintext: &str) -> String {
    let bytes = Zeroizing::new(plaintext.as_bytes().to_vec());
    let digest = Sha256::digest(&*bytes);
    format!("{}{}", FINGERPRINT_PREFIX, hex_lower(&digest))
}

/// Parse a canonical `sha256:<64 lowercase hex>` fingerprint.
pub fn parse_fingerprint(s: &str) -> Result<[u8; 32], FingerprintFormatError> {
    let hex = s
        .strip_prefix(FINGERPRINT_PREFIX)
        .ok_or(FingerprintFormatError::MissingPrefix)?;
    if hex.len() != SHA256_HEX_LEN {
        return Err(FingerprintFormatError::InvalidLength);
    }

    let mut out = [0_u8; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        out[index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Ok(out)
}

/// Verify a raw API key against a canonical fingerprint.
///
/// Fingerprint parsing is strict. Once parsed, digest comparison uses
/// `subtle`'s constant-time equality.
pub fn verify_api_key(plaintext: &str, fingerprint: &str) -> Result<bool, FingerprintFormatError> {
    let expected = parse_fingerprint(fingerprint)?;
    let bytes = Zeroizing::new(plaintext.as_bytes().to_vec());
    let actual: [u8; 32] = Sha256::digest(&*bytes).into();
    Ok(actual.ct_eq(&expected).into())
}

/// Error returned when a raw API key is too small to satisfy the platform
/// entropy floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum EntropyError {
    /// Raw keys must contain at least [`MIN_API_KEY_ENTROPY_BYTES`] bytes.
    #[error("API key must contain at least {min} bytes of random material; got {actual}")]
    TooShort { actual: usize, min: usize },
    /// Operators must supply generated ASCII key material so byte length and
    /// displayed length are identical during provisioning.
    #[error("API key material must be ASCII")]
    NonAscii,
}

/// Enforce the raw-key size floor before operators fingerprint and deploy a
/// key. Generated keys must be ASCII so byte-length entropy checks match the
/// operator-visible key length.
pub fn validate_api_key_entropy(plaintext: &str) -> Result<(), EntropyError> {
    if !plaintext.is_ascii() {
        return Err(EntropyError::NonAscii);
    }
    let actual = plaintext.len();
    if actual < MIN_API_KEY_ENTROPY_BYTES {
        return Err(EntropyError::TooShort {
            actual,
            min: MIN_API_KEY_ENTROPY_BYTES,
        });
    }
    Ok(())
}

fn hex_nibble(byte: u8) -> Result<u8, FingerprintFormatError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(FingerprintFormatError::InvalidHex),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const SAMPLE_KEY: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn parse_bearer_token_accepts_case_insensitive_scheme() {
        assert_eq!(parse_bearer_token("Bearer abc123"), Ok("abc123"));
        assert_eq!(parse_bearer_token("bEaReR abc123"), Ok("abc123"));
    }

    #[test]
    fn parse_bearer_token_requires_single_space_separator() {
        assert_eq!(
            parse_bearer_token("Bearer\tabc123"),
            Err(BearerParseError::InvalidSeparator)
        );
        assert_eq!(
            parse_bearer_token("Bearer  abc123"),
            Err(BearerParseError::InvalidSeparator)
        );
        assert_eq!(
            parse_bearer_token("Bearer"),
            Err(BearerParseError::Malformed)
        );
        assert_eq!(
            parse_bearer_token("Bearertoken"),
            Err(BearerParseError::InvalidSeparator)
        );
    }

    #[test]
    fn parse_bearer_token_rejects_empty_or_extra_token_parts() {
        assert_eq!(
            parse_bearer_token("Bearer "),
            Err(BearerParseError::EmptyToken)
        );
        assert_eq!(
            parse_bearer_token("Bearer abc extra"),
            Err(BearerParseError::TokenContainsWhitespace)
        );
        assert_eq!(
            parse_bearer_token("Bearer abc\tdef"),
            Err(BearerParseError::TokenContainsWhitespace)
        );
    }

    #[test]
    fn fingerprint_api_key_uses_canonical_sha256_format() {
        let fingerprint = fingerprint_api_key(SAMPLE_KEY);
        assert_eq!(fingerprint.len(), FINGERPRINT_PREFIX.len() + SHA256_HEX_LEN);
        assert!(fingerprint.starts_with(FINGERPRINT_PREFIX));
        assert!(fingerprint[FINGERPRINT_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        assert_eq!(
            parse_fingerprint(&fingerprint)
                .expect("fingerprint parses")
                .len(),
            32
        );
    }

    #[test]
    fn verify_api_key_matches_digest_in_constant_time_path() {
        let fingerprint = fingerprint_api_key(SAMPLE_KEY);
        assert_eq!(verify_api_key(SAMPLE_KEY, &fingerprint), Ok(true));
        assert_eq!(verify_api_key("wrong-key", &fingerprint), Ok(false));
    }

    #[test]
    fn parse_fingerprint_rejects_noncanonical_values() {
        assert_eq!(
            parse_fingerprint("not-a-fingerprint"),
            Err(FingerprintFormatError::MissingPrefix)
        );
        assert_eq!(
            parse_fingerprint("sha256:abc"),
            Err(FingerprintFormatError::InvalidLength)
        );
        assert_eq!(
            parse_fingerprint(
                "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            ),
            Err(FingerprintFormatError::InvalidHex)
        );
        assert_eq!(
            parse_fingerprint(
                "sha256:00000000000000000000000000000000000000000000000000000000000000xz"
            ),
            Err(FingerprintFormatError::InvalidHex)
        );
    }

    #[test]
    fn validate_api_key_entropy_enforces_256_bit_floor() {
        assert_eq!(
            validate_api_key_entropy("short"),
            Err(EntropyError::TooShort {
                actual: 5,
                min: MIN_API_KEY_ENTROPY_BYTES,
            })
        );
        assert!(validate_api_key_entropy(SAMPLE_KEY).is_ok());
    }

    #[test]
    fn validate_api_key_entropy_rejects_non_ascii_material() {
        let key = format!("{}é", "a".repeat(MIN_API_KEY_ENTROPY_BYTES));
        assert_eq!(validate_api_key_entropy(&key), Err(EntropyError::NonAscii));
    }

    proptest! {
        #[test]
        fn parse_bearer_token_round_trips_non_whitespace_tokens(token in "[!-~]{1,128}") {
            prop_assume!(!token.bytes().any(|byte| byte.is_ascii_whitespace()));
            let header = format!("Bearer {token}");
            prop_assert_eq!(parse_bearer_token(&header), Ok(token.as_str()));
        }

        #[test]
        fn parse_fingerprint_accepts_canonical_lower_hex(hex in "[0-9a-f]{64}") {
            let fingerprint = format!("{FINGERPRINT_PREFIX}{hex}");
            prop_assert!(parse_fingerprint(&fingerprint).is_ok());
        }
    }
}
