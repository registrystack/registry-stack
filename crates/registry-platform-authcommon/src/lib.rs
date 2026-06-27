//! Shared authentication primitives that are independent of any identity
//! provider.

use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{de, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

const BEARER_SCHEME: &str = "Bearer";
const FINGERPRINT_PREFIX: &str = "sha256:";
const SHA256_HEX_LEN: usize = 64;
const MAX_FINGERPRINT_FILE_BYTES: u64 = (FINGERPRINT_PREFIX.len() + SHA256_HEX_LEN + 2) as u64;

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

    // Validate the scheme on bytes before splitting. The byte-length guard above
    // ensures we have enough bytes, but split_at would panic if byte index
    // BEARER_SCHEME.len() falls inside a multibyte UTF-8 scalar. Comparing bytes
    // directly is safe because BEARER_SCHEME is pure ASCII, so a match on bytes
    // guarantees we are on a char boundary.
    let scheme_bytes = &header.as_bytes()[..BEARER_SCHEME.len()];
    if !scheme_bytes.eq_ignore_ascii_case(BEARER_SCHEME.as_bytes()) {
        return Err(BearerParseError::InvalidScheme);
    }

    // SAFETY: BEARER_SCHEME is all ASCII, so its byte length equals its char
    // length, and we just confirmed the first BEARER_SCHEME.len() bytes are
    // ASCII. The split is therefore on a valid char boundary.
    let (_, rest) = header.split_at(BEARER_SCHEME.len());
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

/// Provider for a canonical credential fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CredentialFingerprintProvider {
    /// Resolve from an environment variable.
    Env,
    /// Resolve from a local file.
    File,
}

impl CredentialFingerprintProvider {
    /// Stable provider label for redacted diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::File => "file",
        }
    }
}

/// Configured local reference to a canonical credential fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialFingerprintRef {
    pub provider: CredentialFingerprintProvider,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
}

impl<'de> Deserialize<'de> for CredentialFingerprintRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawCredentialFingerprintRef {
            provider: CredentialFingerprintProvider,
            #[serde(default)]
            name: Option<String>,
            #[serde(default)]
            path: Option<PathBuf>,
            #[serde(
                rename = "commitment",
                default,
                deserialize_with = "reject_removed_commitment"
            )]
            _commitment: (),
        }

        let raw = RawCredentialFingerprintRef::deserialize(deserializer)?;
        Ok(Self {
            provider: raw.provider,
            name: raw.name,
            path: raw.path,
        })
    }
}

fn reject_removed_commitment<'de, D>(_deserializer: D) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    Err(de::Error::custom(
        "fingerprint.commitment was removed; configure fingerprint.provider with fingerprint.name or fingerprint.path only",
    ))
}

impl CredentialFingerprintRef {
    /// Resolve and parse the referenced credential fingerprint.
    pub fn resolve(&self) -> Result<String, CredentialFingerprintRefError> {
        self.validate_shape()?;
        let fingerprint = match self.provider {
            CredentialFingerprintProvider::Env => {
                let name = self
                    .name
                    .as_deref()
                    .ok_or(CredentialFingerprintRefError::InvalidShape)?;
                env::var(name).map_err(|_| CredentialFingerprintRefError::MissingSecret)?
            }
            CredentialFingerprintProvider::File => {
                let path = self
                    .path
                    .as_ref()
                    .ok_or(CredentialFingerprintRefError::InvalidShape)?;
                read_bounded_fingerprint_file(path)?
            }
        };
        let fingerprint = trim_one_line_ending(fingerprint);
        if fingerprint.is_empty() {
            return Err(CredentialFingerprintRefError::EmptySecret);
        }
        parse_fingerprint(&fingerprint)
            .map_err(CredentialFingerprintRefError::InvalidFingerprint)?;
        Ok(fingerprint)
    }

    fn validate_shape(&self) -> Result<(), CredentialFingerprintRefError> {
        match self.provider {
            CredentialFingerprintProvider::Env => {
                if self.name.as_deref().is_none_or(str::is_empty) || self.path.is_some() {
                    return Err(CredentialFingerprintRefError::InvalidShape);
                }
            }
            CredentialFingerprintProvider::File => {
                if self.path.is_none() || self.name.is_some() {
                    return Err(CredentialFingerprintRefError::InvalidShape);
                }
            }
        }
        Ok(())
    }
}

/// Redacted error for resolving a credential fingerprint reference.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CredentialFingerprintRefError {
    /// The provider-specific fields do not match the selected provider.
    #[error("credential fingerprint reference shape is invalid")]
    InvalidShape,
    /// The configured env var or file was unavailable.
    #[error("credential fingerprint secret is missing")]
    MissingSecret,
    /// The resolved value was empty after permitted line-ending trimming.
    #[error("credential fingerprint secret is empty")]
    EmptySecret,
    /// The resolved value is not a canonical SHA-256 fingerprint.
    #[error("credential fingerprint secret is invalid")]
    InvalidFingerprint(FingerprintFormatError),
}

fn read_bounded_fingerprint_file(path: &Path) -> Result<String, CredentialFingerprintRefError> {
    let metadata = fs::metadata(path).map_err(|_| CredentialFingerprintRefError::MissingSecret)?;
    if !metadata.is_file() || metadata.len() > MAX_FINGERPRINT_FILE_BYTES {
        return Err(CredentialFingerprintRefError::InvalidFingerprint(
            FingerprintFormatError::InvalidLength,
        ));
    }
    let file = fs::File::open(path).map_err(|_| CredentialFingerprintRefError::MissingSecret)?;
    let metadata = file
        .metadata()
        .map_err(|_| CredentialFingerprintRefError::MissingSecret)?;
    if !metadata.is_file() || metadata.len() > MAX_FINGERPRINT_FILE_BYTES {
        return Err(CredentialFingerprintRefError::InvalidFingerprint(
            FingerprintFormatError::InvalidLength,
        ));
    }
    let mut contents = String::new();
    file.take(MAX_FINGERPRINT_FILE_BYTES + 1)
        .read_to_string(&mut contents)
        .map_err(|_| CredentialFingerprintRefError::MissingSecret)?;
    if contents.len() as u64 > MAX_FINGERPRINT_FILE_BYTES {
        return Err(CredentialFingerprintRefError::InvalidFingerprint(
            FingerprintFormatError::InvalidLength,
        ));
    }
    Ok(contents)
}

fn trim_one_line_ending(mut value: String) -> String {
    if value.ends_with("\r\n") {
        value.truncate(value.len() - 2);
    } else if value.ends_with('\n') || value.ends_with('\r') {
        value.truncate(value.len() - 1);
    }
    value
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
    use std::io::Write;

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

    #[test]
    fn credential_fingerprint_ref_resolves_env() {
        let fingerprint = fingerprint_api_key(SAMPLE_KEY);
        std::env::set_var("AUTHCOMMON_TEST_FINGERPRINT", &fingerprint);
        let reference = CredentialFingerprintRef {
            provider: CredentialFingerprintProvider::Env,
            name: Some("AUTHCOMMON_TEST_FINGERPRINT".to_string()),
            path: None,
        };

        assert_eq!(reference.resolve().as_deref(), Ok(fingerprint.as_str()));
        std::env::remove_var("AUTHCOMMON_TEST_FINGERPRINT");
    }

    #[test]
    fn credential_fingerprint_ref_resolves_file_with_one_trailing_newline() {
        let fingerprint = fingerprint_api_key(SAMPLE_KEY);
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        writeln!(file, "{fingerprint}").expect("fingerprint writes");
        let reference = CredentialFingerprintRef {
            provider: CredentialFingerprintProvider::File,
            name: None,
            path: Some(file.path().to_path_buf()),
        };

        assert_eq!(reference.resolve().as_deref(), Ok(fingerprint.as_str()));
    }

    #[test]
    fn credential_fingerprint_ref_rejects_oversized_file_before_parsing() {
        let fingerprint = fingerprint_api_key(SAMPLE_KEY);
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        write!(
            file,
            "{fingerprint}{}",
            "x".repeat(MAX_FINGERPRINT_FILE_BYTES as usize)
        )
        .expect("oversized fingerprint writes");
        let reference = CredentialFingerprintRef {
            provider: CredentialFingerprintProvider::File,
            name: None,
            path: Some(file.path().to_path_buf()),
        };

        assert!(matches!(
            reference.resolve(),
            Err(CredentialFingerprintRefError::InvalidFingerprint(
                FingerprintFormatError::InvalidLength
            ))
        ));
    }

    #[test]
    fn credential_fingerprint_ref_rejects_non_regular_file_before_reading() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let reference = CredentialFingerprintRef {
            provider: CredentialFingerprintProvider::File,
            name: None,
            path: Some(dir.path().to_path_buf()),
        };

        assert!(matches!(
            reference.resolve(),
            Err(CredentialFingerprintRefError::InvalidFingerprint(
                FingerprintFormatError::InvalidLength
            ))
        ));
    }

    #[test]
    fn credential_fingerprint_ref_rejects_legacy_commitment_field() {
        let error = serde_json::from_str::<CredentialFingerprintRef>(
            r#"
{
  "provider": "env",
  "name": "AUTHCOMMON_TEST_FINGERPRINT",
  "commitment": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}
"#,
        )
        .expect_err("legacy commitment field is rejected");

        assert!(
            error
                .to_string()
                .contains("fingerprint.commitment was removed"),
            "{error}"
        );
    }

    #[test]
    fn credential_fingerprint_ref_rejects_null_legacy_commitment_field() {
        let error = serde_json::from_str::<CredentialFingerprintRef>(
            r#"
{
  "provider": "env",
  "name": "AUTHCOMMON_TEST_FINGERPRINT",
  "commitment": null
}
"#,
        )
        .expect_err("legacy commitment field is rejected even when null");

        assert!(
            error
                .to_string()
                .contains("fingerprint.commitment was removed"),
            "{error}"
        );
    }

    #[test]
    fn credential_fingerprint_ref_rejects_env_file_shape_violations() {
        let fingerprint = fingerprint_api_key(SAMPLE_KEY);
        std::env::set_var("AUTHCOMMON_TEST_SHAPE", &fingerprint);
        let reference = CredentialFingerprintRef {
            provider: CredentialFingerprintProvider::Env,
            name: Some("AUTHCOMMON_TEST_SHAPE".to_string()),
            path: Some(PathBuf::from("/tmp/should-not-also-be-set")),
        };

        assert_eq!(
            reference.resolve(),
            Err(CredentialFingerprintRefError::InvalidShape)
        );
        std::env::remove_var("AUTHCOMMON_TEST_SHAPE");
    }

    #[test]
    fn credential_fingerprint_ref_rejects_extra_whitespace() {
        let fingerprint = fingerprint_api_key(SAMPLE_KEY);
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        writeln!(file, "{fingerprint}\n").expect("fingerprint writes");
        let reference = CredentialFingerprintRef {
            provider: CredentialFingerprintProvider::File,
            name: None,
            path: Some(file.path().to_path_buf()),
        };

        assert!(matches!(
            reference.resolve(),
            Err(CredentialFingerprintRefError::InvalidFingerprint(_))
        ));
    }

    // --- multibyte UTF-8 at the scheme-split boundary (regression for issue #50) ---
    //
    // "Bearer" is 6 bytes. Any input whose byte-length is >= 6 but whose byte
    // index 6 lands inside a multibyte scalar used to panic with
    // "end byte index N is not a char boundary". These tests must return a clean
    // Err, never panic.

    #[test]
    fn parse_bearer_token_does_not_panic_on_two_byte_char_at_boundary() {
        // "Beare" + é (U+00E9, encoded as 0xC3 0xA9 in UTF-8): 7 bytes total.
        // Byte 6 is the continuation byte 0xA9 — not a char boundary.
        let header = "Beare\u{00e9}";
        assert_eq!(header.len(), 7);
        assert_eq!(
            parse_bearer_token(header),
            Err(BearerParseError::InvalidScheme)
        );
    }

    #[test]
    fn parse_bearer_token_does_not_panic_on_three_byte_char_straddling_boundary() {
        // "Bear" + ' (U+2019 RIGHT SINGLE QUOTATION MARK, encoded as 0xE2 0x80 0x99): 7 bytes.
        // Byte 6 is 0x99 — continuation byte of the 3-byte sequence starting at byte 4.
        let header = "Bear\u{2019}";
        assert_eq!(header.len(), 7);
        assert_eq!(
            parse_bearer_token(header),
            Err(BearerParseError::InvalidScheme)
        );
    }

    #[test]
    fn parse_bearer_token_does_not_panic_on_two_byte_char_starting_at_boundary() {
        // "Bearer" (exactly 6 bytes) followed by a 2-byte UTF-8 char: 8 bytes total.
        // Byte 6 is 0xC3 — the leading byte of é. split_at(6) lands on a char boundary here,
        // but the scheme-check must still reject the non-ASCII separator gracefully.
        let header = "Bearer\u{00e9}";
        assert_eq!(header.len(), 8);
        assert_eq!(
            parse_bearer_token(header),
            Err(BearerParseError::InvalidSeparator)
        );
    }

    #[test]
    fn parse_bearer_token_does_not_panic_on_non_ascii_scheme_exact_length() {
        // A 6-byte string whose last char is the second byte of a 2-byte sequence
        // can never be valid UTF-8, but we can construct a case where a non-ASCII
        // char starts at byte 5, making byte 6 a continuation byte.
        // "Beare" (5 bytes) + ñ (U+00F1, 2 bytes) = 7 bytes; byte 6 = 0xB1 (continuation).
        let header = "Beare\u{00f1}";
        assert_eq!(header.len(), 7);
        assert_eq!(
            parse_bearer_token(header),
            Err(BearerParseError::InvalidScheme)
        );
    }

    #[test]
    fn parse_bearer_token_does_not_panic_on_empty_header() {
        assert_eq!(parse_bearer_token(""), Err(BearerParseError::Malformed));
    }

    #[test]
    fn parse_bearer_token_does_not_panic_on_scheme_only_no_space() {
        // Exactly "Bearer" with no trailing space or token.
        assert_eq!(
            parse_bearer_token("Bearer"),
            Err(BearerParseError::Malformed)
        );
    }

    #[test]
    fn parse_bearer_token_does_not_panic_on_four_byte_char_before_boundary() {
        // "Be" + 𝄞 (U+1D11E MUSICAL SYMBOL G CLEF, 4 bytes) = 6 bytes total.
        // split_at(6) would land after the 4-byte char — actually on a valid boundary.
        // The scheme check should still return InvalidScheme.
        let header = "Be\u{1d11e}";
        assert_eq!(header.len(), 6);
        assert_eq!(
            parse_bearer_token(header),
            Err(BearerParseError::InvalidScheme)
        );
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
