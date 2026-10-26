//! Token Status List (draft-ietf-oauth-status-list-21) codec and the pure
//! relying-party status check.
//!
//! The check takes the Status List Token bytes a caller already fetched; it
//! performs no I/O and reads no clock, so the verifier stays free of a network
//! stack (`sd-jwt-vc-profile.yaml`) and a caller supplies `now`. Every refusal
//! is a [`StatusUnknown`] reason: only [`StatusOutcome::Valid`] means the
//! issuer vouched for the credential, and a caller decides what an unknown
//! outcome means for its own policy.
//!
//! The profile is JWT only, ES256, 2 bits per entry. The codec also decodes 1,
//! 2, 4 and 8 bits so the draft's Appendix C vectors run against it.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, TimeZone, Utc};
use miniz_oxide::{
    deflate::compress_to_vec_zlib,
    inflate::{decompress_to_vec_zlib_with_limit, TINFLStatus},
};
use registry_platform_crypto::{parse_json_strict, verify, PublicJwk, SigningAlgorithm};
use serde_json::{Map, Value};
use thiserror::Error;

/// `typ` JOSE header of a Status List Token (SL 5.1).
pub const STATUS_LIST_JWT_TYP: &str = "statuslist+jwt";
/// Bits per entry the profile requires.
pub const PROFILE_BITS: u8 = 2;
/// Entries in a profile list.
pub const PROFILE_LIST_ENTRIES: usize = 1 << 20;
/// Inflated size of a full profile list: 2^20 entries at 2 bits.
pub const PROFILE_MAX_INFLATED_BYTES: usize = PROFILE_LIST_ENTRIES * PROFILE_BITS as usize / 8;

const MAX_URI_BYTES: usize = 2048;
/// DEFLATE level the draft recommends (SL 4.1: the highest available).
const COMPRESSION_LEVEL: u8 = 10;

// ---------------------------------------------------------------------------
// Codec

/// A decoded Status List: a packed byte array of `bits`-wide entries, entry 0
/// in the least significant bits of byte 0 (SL 4.1, SL 11.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusList {
    bits: u8,
    bytes: Vec<u8>,
}

/// A list that cannot be encoded or decoded.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StatusListError {
    #[error("bits per entry must be 1, 2, 4 or 8, not {0}")]
    UnsupportedBits(u8),
    #[error("value {value} does not fit in {bits} bits")]
    ValueOutOfRange { bits: u8, value: u8 },
    #[error("the list inflates past the {limit} byte limit")]
    Oversize { limit: usize },
    #[error("the compressed list is not valid zlib data")]
    Corrupt,
}

fn check_bits(bits: u8) -> Result<(), StatusListError> {
    match bits {
        1 | 2 | 4 | 8 => Ok(()),
        other => Err(StatusListError::UnsupportedBits(other)),
    }
}

impl StatusList {
    /// Pack one value per entry. A final partial byte is padded with zeros.
    ///
    /// # Errors
    /// Refuses `bits` other than 1, 2, 4 or 8 and a value wider than `bits`.
    pub fn from_values(bits: u8, values: &[u8]) -> Result<Self, StatusListError> {
        check_bits(bits)?;
        let per_byte = usize::from(8 / bits);
        let mut bytes = vec![0_u8; values.len().div_ceil(per_byte)];
        for (index, value) in values.iter().enumerate() {
            if u16::from(*value) >> bits != 0 {
                return Err(StatusListError::ValueOutOfRange {
                    bits,
                    value: *value,
                });
            }
            let shift = (index % per_byte) * usize::from(bits);
            bytes[index / per_byte] |= value << shift;
        }
        Ok(Self { bits, bytes })
    }

    #[must_use]
    pub fn bits(&self) -> u8 {
        self.bits
    }

    /// The packed byte array, before compression.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Entries the byte array holds, including any padding entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len() * 8 / usize::from(self.bits)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The value of entry `index`, or `None` when it lies outside the list.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<u8> {
        if index >= self.len() {
            return None;
        }
        let per_byte = usize::from(8 / self.bits);
        let shift = (index % per_byte) * usize::from(self.bits);
        let mask = u8::try_from((1_u16 << self.bits) - 1).unwrap_or(u8::MAX);
        Some((self.bytes[index / per_byte] >> shift) & mask)
    }

    /// Every entry, one value per element.
    #[must_use]
    pub fn to_values(&self) -> Vec<u8> {
        (0..self.len())
            .filter_map(|index| self.get(index))
            .collect()
    }
}

/// Pack `values` and compress them as zlib-wrapped DEFLATE (SL 4.1).
///
/// # Errors
/// Refuses `bits` other than 1, 2, 4 or 8 and a value wider than `bits`.
pub fn encode(bits: u8, values: &[u8]) -> Result<Vec<u8>, StatusListError> {
    let list = StatusList::from_values(bits, values)?;
    Ok(compress_to_vec_zlib(list.as_bytes(), COMPRESSION_LEVEL))
}

/// Inflate and unpack a compressed list, never producing more than
/// `max_inflated_bytes` (SL 8.3 step 5 sets no bound of its own).
///
/// # Errors
/// Refuses unsupported `bits`, data that is not zlib, and data that inflates
/// past the cap.
pub fn decode(
    bits: u8,
    compressed: &[u8],
    max_inflated_bytes: usize,
) -> Result<StatusList, StatusListError> {
    check_bits(bits)?;
    match decompress_to_vec_zlib_with_limit(compressed, max_inflated_bytes) {
        Ok(bytes) => Ok(StatusList { bits, bytes }),
        Err(error) if error.status == TINFLStatus::HasMoreOutput => {
            Err(StatusListError::Oversize {
                limit: max_inflated_bytes,
            })
        }
        Err(_) => Err(StatusListError::Corrupt),
    }
}

// ---------------------------------------------------------------------------
// Reference

/// The `status.status_list` claim of a credential (SL 6.2): where the list
/// lives and which entry describes the credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReference {
    uri: String,
    idx: u64,
}

/// A credential status claim that does not follow SL 6.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum StatusReferenceError {
    #[error("the status claim is not an object with a status_list object")]
    MissingStatusList,
    #[error("the status_list object carries members other than idx and uri")]
    UnexpectedMember,
    #[error("idx is not a non-negative integer")]
    InvalidIndex,
    #[error("uri is not an https URL")]
    InvalidUri,
}

impl StatusReference {
    /// # Errors
    /// Refuses a `uri` that is not an https URL.
    pub fn new(uri: impl Into<String>, idx: u64) -> Result<Self, StatusReferenceError> {
        let uri = uri.into();
        if !is_https_uri(&uri) {
            return Err(StatusReferenceError::InvalidUri);
        }
        Ok(Self { uri, idx })
    }

    /// Read the reference from a credential's `status` claim.
    ///
    /// # Errors
    /// Refuses a claim without a `status_list` object, extra `status_list`
    /// members, a missing or non-integer `idx`, and a missing or non-https
    /// `uri`.
    pub fn from_status_claim(status: &Value) -> Result<Self, StatusReferenceError> {
        let list = status
            .get("status_list")
            .and_then(Value::as_object)
            .ok_or(StatusReferenceError::MissingStatusList)?;
        if list.keys().any(|key| key != "idx" && key != "uri") {
            return Err(StatusReferenceError::UnexpectedMember);
        }
        let idx = list
            .get("idx")
            .and_then(Value::as_u64)
            .ok_or(StatusReferenceError::InvalidIndex)?;
        let uri = list
            .get("uri")
            .and_then(Value::as_str)
            .ok_or(StatusReferenceError::InvalidUri)?;
        Self::new(uri, idx)
    }

    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }

    #[must_use]
    pub fn idx(&self) -> u64 {
        self.idx
    }
}

/// An https URL with a host, no userinfo, no fragment, and only printable
/// ASCII, so a status host cannot be disguised by the parser a caller later
/// feeds the string to.
fn is_https_uri(uri: &str) -> bool {
    let Some(rest) = uri.strip_prefix("https://") else {
        return false;
    };
    if uri.len() > MAX_URI_BYTES || !uri.bytes().all(|byte| (0x21..0x7f).contains(&byte)) {
        return false;
    }
    if rest.contains('#') {
        return false;
    }
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    !authority.is_empty() && !authority.contains('@') && !authority.starts_with(':')
}

// ---------------------------------------------------------------------------
// Policy

/// The relying party's bounds on an untrusted Status List Token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusPolicy {
    max_token_bytes: usize,
    min_ttl_seconds: u64,
    max_ttl_seconds: u64,
    max_expiry_horizon_seconds: u64,
}

/// A policy bound outside the range the verifier accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum StatusPolicyError {
    #[error("the token size bound must be between 1 and {MAX_TOKEN_BYTES_LIMIT} bytes")]
    TokenBytes,
    #[error(
        "the ttl bounds must satisfy 1 <= minimum <= maximum <= {MAX_TTL_LIMIT_SECONDS} seconds"
    )]
    Ttl,
    #[error("the expiry horizon must be between 1 and {MAX_HORIZON_LIMIT_SECONDS} seconds")]
    ExpiryHorizon,
}

const MAX_TOKEN_BYTES_LIMIT: usize = 4 * 1024 * 1024;
const MAX_TTL_LIMIT_SECONDS: u64 = 7 * 86_400;
const MAX_HORIZON_LIMIT_SECONDS: u64 = 30 * 86_400;

impl StatusPolicy {
    /// Compressed token at most 1 MiB, `ttl` clamped to 60 s through 24 h,
    /// `exp` honoured at most 7 days after `iat`.
    pub const DEFAULT_MAX_TOKEN_BYTES: usize = 1_048_576;
    pub const DEFAULT_MIN_TTL_SECONDS: u64 = 60;
    pub const DEFAULT_MAX_TTL_SECONDS: u64 = 86_400;
    pub const DEFAULT_MAX_EXPIRY_HORIZON_SECONDS: u64 = 7 * 86_400;

    /// # Errors
    /// Refuses a zero or excessive token bound, a ttl range that is empty,
    /// zero or excessive, and a zero or excessive expiry horizon.
    pub fn new(
        max_token_bytes: usize,
        min_ttl_seconds: u64,
        max_ttl_seconds: u64,
        max_expiry_horizon_seconds: u64,
    ) -> Result<Self, StatusPolicyError> {
        if !(1..=MAX_TOKEN_BYTES_LIMIT).contains(&max_token_bytes) {
            return Err(StatusPolicyError::TokenBytes);
        }
        if min_ttl_seconds == 0
            || min_ttl_seconds > max_ttl_seconds
            || max_ttl_seconds > MAX_TTL_LIMIT_SECONDS
        {
            return Err(StatusPolicyError::Ttl);
        }
        if !(1..=MAX_HORIZON_LIMIT_SECONDS).contains(&max_expiry_horizon_seconds) {
            return Err(StatusPolicyError::ExpiryHorizon);
        }
        Ok(Self {
            max_token_bytes,
            min_ttl_seconds,
            max_ttl_seconds,
            max_expiry_horizon_seconds,
        })
    }

    #[must_use]
    pub fn max_token_bytes(&self) -> usize {
        self.max_token_bytes
    }

    #[must_use]
    pub fn min_ttl_seconds(&self) -> u64 {
        self.min_ttl_seconds
    }

    #[must_use]
    pub fn max_ttl_seconds(&self) -> u64 {
        self.max_ttl_seconds
    }

    #[must_use]
    pub fn max_expiry_horizon_seconds(&self) -> u64 {
        self.max_expiry_horizon_seconds
    }
}

impl Default for StatusPolicy {
    fn default() -> Self {
        Self {
            max_token_bytes: Self::DEFAULT_MAX_TOKEN_BYTES,
            min_ttl_seconds: Self::DEFAULT_MIN_TTL_SECONDS,
            max_ttl_seconds: Self::DEFAULT_MAX_TTL_SECONDS,
            max_expiry_horizon_seconds: Self::DEFAULT_MAX_EXPIRY_HORIZON_SECONDS,
        }
    }
}

// ---------------------------------------------------------------------------
// Check

/// What the status list says about a credential. Only `Valid` passes a policy
/// that requires status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusOutcome {
    /// Entry value 0x00.
    Valid,
    /// Entry value 0x01 (terminal), or 0x03, which the issuer never writes.
    Invalid,
    /// Entry value 0x02.
    Suspended,
    /// The token could not be trusted or read; the reason says why.
    Unknown(StatusUnknown),
}

/// Why a Status List Token yielded no statement about the credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum StatusUnknown {
    #[error("the status list token exceeds the size bound")]
    TokenTooLarge,
    #[error("the status list token is not a compact JWS")]
    MalformedToken,
    #[error("the JOSE typ is not statuslist+jwt")]
    WrongType,
    #[error("the JOSE alg is not ES256")]
    UnsupportedAlgorithm,
    #[error("the JOSE header carries a critical parameter")]
    UnsupportedCriticalHeader,
    #[error("no pinned issuer key matches the token")]
    UnknownKey,
    #[error("the signature does not verify under a pinned issuer key")]
    BadSignature,
    #[error("the token claims are malformed")]
    MalformedClaims,
    #[error("sub does not equal the credential's status list uri")]
    SubjectMismatch,
    #[error("iat is missing or not an integer")]
    MissingIssuedAt,
    #[error("exp is missing or not an integer")]
    MissingExpiry,
    #[error("the token has expired")]
    Expired,
    #[error("the status list does not use 2 bits per entry")]
    UnsupportedBits,
    #[error("the status list is missing or malformed")]
    MalformedList,
    #[error("the status list inflates past the profile maximum")]
    ListTooLarge,
    #[error("idx lies outside the status list")]
    IndexOutOfBounds,
}

/// The outcome plus what a caching client needs: the clamped `ttl` and the
/// instant the token stops being honoured. Both are `None` when the token was
/// refused before they could be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusReport {
    pub outcome: StatusOutcome,
    /// `ttl` clamped to the policy range; the policy maximum when absent.
    pub ttl_seconds: Option<u64>,
    /// The earlier of `exp` and `iat` plus the policy horizon.
    pub honoured_until: Option<DateTime<Utc>>,
}

/// Evaluate the credential's status against a fetched Status List Token.
///
/// See [`check_status_report`] for the same check with the cache hints.
#[must_use]
pub fn check_status(
    reference: &StatusReference,
    token_bytes: &[u8],
    issuer_keys: &[PublicJwk],
    now: DateTime<Utc>,
    policy: &StatusPolicy,
) -> StatusOutcome {
    check_status_report(reference, token_bytes, issuer_keys, now, policy).outcome
}

/// Evaluate the credential's status and report the cache hints, following SL
/// 8.3 with the JOSE `typ` first. Pure: the caller fetches the token and
/// supplies `now`.
#[must_use]
pub fn check_status_report(
    reference: &StatusReference,
    token_bytes: &[u8],
    issuer_keys: &[PublicJwk],
    now: DateTime<Utc>,
    policy: &StatusPolicy,
) -> StatusReport {
    let mut hints = Hints::default();
    let outcome = match evaluate(reference, token_bytes, issuer_keys, now, policy, &mut hints) {
        Ok(outcome) => outcome,
        Err(reason) => StatusOutcome::Unknown(reason),
    };
    StatusReport {
        outcome,
        ttl_seconds: hints.ttl_seconds,
        honoured_until: hints.honoured_until,
    }
}

#[derive(Default)]
struct Hints {
    ttl_seconds: Option<u64>,
    honoured_until: Option<DateTime<Utc>>,
}

fn evaluate(
    reference: &StatusReference,
    token_bytes: &[u8],
    issuer_keys: &[PublicJwk],
    now: DateTime<Utc>,
    policy: &StatusPolicy,
    hints: &mut Hints,
) -> Result<StatusOutcome, StatusUnknown> {
    if token_bytes.len() > policy.max_token_bytes {
        return Err(StatusUnknown::TokenTooLarge);
    }
    let token = std::str::from_utf8(token_bytes).map_err(|_| StatusUnknown::MalformedToken)?;
    let mut parts = token.split('.');
    let (Some(header_part), Some(payload_part), Some(signature_part), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(StatusUnknown::MalformedToken);
    };
    let header = decode_object(header_part).ok_or(StatusUnknown::MalformedToken)?;

    if header.get("typ").and_then(Value::as_str) != Some(STATUS_LIST_JWT_TYP) {
        return Err(StatusUnknown::WrongType);
    }
    if header.get("alg").and_then(Value::as_str) != Some("ES256") {
        return Err(StatusUnknown::UnsupportedAlgorithm);
    }
    if header.contains_key("crit") {
        return Err(StatusUnknown::UnsupportedCriticalHeader);
    }
    verify_signature(
        &header,
        header_part,
        payload_part,
        signature_part,
        issuer_keys,
    )?;

    // Claims are read only after the signature verifies.
    let claims = decode_object(payload_part).ok_or(StatusUnknown::MalformedClaims)?;
    if claims.get("sub").and_then(Value::as_str) != Some(reference.uri()) {
        return Err(StatusUnknown::SubjectMismatch);
    }
    let issued_at = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or(StatusUnknown::MissingIssuedAt)?;
    let expires_at = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(StatusUnknown::MissingExpiry)?;

    let horizon = i64::try_from(policy.max_expiry_horizon_seconds).unwrap_or(i64::MAX);
    let honoured_until = expires_at.min(issued_at.saturating_add(horizon));
    hints.honoured_until = Utc.timestamp_opt(honoured_until, 0).single();
    hints.ttl_seconds = Some(clamped_ttl(&claims, policy)?);
    if now.timestamp() >= honoured_until {
        return Err(StatusUnknown::Expired);
    }

    let list = decode_list(&claims)?;
    let value = usize::try_from(reference.idx())
        .ok()
        .and_then(|index| list.get(index))
        .ok_or(StatusUnknown::IndexOutOfBounds)?;
    Ok(match value {
        0 => StatusOutcome::Valid,
        2 => StatusOutcome::Suspended,
        _ => StatusOutcome::Invalid,
    })
}

/// Decode one base64url JWS segment as a JSON object with no repeated member.
fn decode_object(segment: &str) -> Option<Map<String, Value>> {
    let bytes = URL_SAFE_NO_PAD.decode(segment).ok()?;
    match parse_json_strict(&bytes).ok()? {
        Value::Object(members) => Some(members),
        _ => None,
    }
}

fn verify_signature(
    header: &Map<String, Value>,
    header_part: &str,
    payload_part: &str,
    signature_part: &str,
    issuer_keys: &[PublicJwk],
) -> Result<(), StatusUnknown> {
    let kid = match header.get("kid") {
        None => None,
        Some(Value::String(kid)) => Some(kid.as_str()),
        Some(_) => return Err(StatusUnknown::MalformedToken),
    };
    let mut candidates = issuer_keys
        .iter()
        .filter(|key| key.algorithm().ok() == Some(SigningAlgorithm::Es256))
        .filter(|key| kid.is_none() || key.kid.as_deref() == kid)
        .peekable();
    if candidates.peek().is_none() {
        return Err(StatusUnknown::UnknownKey);
    }
    let signature = URL_SAFE_NO_PAD
        .decode(signature_part)
        .map_err(|_| StatusUnknown::BadSignature)?;
    let signing_input = format!("{header_part}.{payload_part}");
    if candidates.any(|key| verify(signing_input.as_bytes(), &signature, key).is_ok()) {
        Ok(())
    } else {
        Err(StatusUnknown::BadSignature)
    }
}

fn clamped_ttl(claims: &Map<String, Value>, policy: &StatusPolicy) -> Result<u64, StatusUnknown> {
    match claims.get("ttl") {
        None => Ok(policy.max_ttl_seconds),
        Some(value) => match value.as_u64() {
            Some(ttl) if ttl > 0 => Ok(ttl.clamp(policy.min_ttl_seconds, policy.max_ttl_seconds)),
            _ => Err(StatusUnknown::MalformedClaims),
        },
    }
}

fn decode_list(claims: &Map<String, Value>) -> Result<StatusList, StatusUnknown> {
    let list = claims
        .get("status_list")
        .and_then(Value::as_object)
        .ok_or(StatusUnknown::MalformedList)?;
    let bits = list.get("bits").ok_or(StatusUnknown::MalformedList)?;
    if bits.as_u64() != Some(u64::from(PROFILE_BITS)) {
        return Err(StatusUnknown::UnsupportedBits);
    }
    let compressed = list
        .get("lst")
        .and_then(Value::as_str)
        .and_then(|lst| URL_SAFE_NO_PAD.decode(lst).ok())
        .ok_or(StatusUnknown::MalformedList)?;
    decode(PROFILE_BITS, &compressed, PROFILE_MAX_INFLATED_BYTES).map_err(|error| match error {
        StatusListError::Oversize { .. } => StatusUnknown::ListTooLarge,
        _ => StatusUnknown::MalformedList,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_value_wider_than_the_bits_is_refused() {
        assert_eq!(
            StatusList::from_values(2, &[0, 4]),
            Err(StatusListError::ValueOutOfRange { bits: 2, value: 4 })
        );
        assert!(StatusList::from_values(8, &[255]).is_ok());
        assert_eq!(
            encode(1, &[2]),
            Err(StatusListError::ValueOutOfRange { bits: 1, value: 2 })
        );
    }

    #[test]
    fn unsupported_bits_are_refused_by_both_directions() {
        for bits in [0, 3, 5, 16] {
            assert_eq!(
                encode(bits, &[0]),
                Err(StatusListError::UnsupportedBits(bits))
            );
            assert_eq!(
                decode(bits, &[], 8),
                Err(StatusListError::UnsupportedBits(bits))
            );
        }
    }

    #[test]
    fn corrupt_compressed_data_is_refused() {
        assert_eq!(decode(2, b"not zlib", 64), Err(StatusListError::Corrupt));
        assert_eq!(decode(2, &[], 64), Err(StatusListError::Corrupt));
    }

    #[test]
    fn a_partial_final_byte_pads_with_valid_entries() {
        let list = StatusList::from_values(2, &[1, 2, 3]).expect("list builds");
        assert_eq!(list.len(), 4);
        assert_eq!(list.to_values(), vec![1, 2, 3, 0]);
        assert_eq!(list.get(4), None);
        assert!(!list.is_empty());
    }

    #[test]
    fn the_reference_is_read_from_the_status_claim() {
        let status = json!({"status_list": {"idx": 412, "uri": "https://s.example/lists/1"}});
        let reference = StatusReference::from_status_claim(&status).expect("reference parses");
        assert_eq!(reference.idx(), 412);
        assert_eq!(reference.uri(), "https://s.example/lists/1");
    }

    #[test]
    fn a_malformed_status_claim_is_refused_with_a_typed_error() {
        let uri = "https://s.example/lists/1";
        let cases = [
            (json!(null), StatusReferenceError::MissingStatusList),
            (json!({}), StatusReferenceError::MissingStatusList),
            (
                json!({"status_list": "x"}),
                StatusReferenceError::MissingStatusList,
            ),
            (
                json!({"status_list": {"idx": 1, "uri": uri, "extra": 1}}),
                StatusReferenceError::UnexpectedMember,
            ),
            (
                json!({"status_list": {"uri": uri}}),
                StatusReferenceError::InvalidIndex,
            ),
            (
                json!({"status_list": {"idx": -1, "uri": uri}}),
                StatusReferenceError::InvalidIndex,
            ),
            (
                json!({"status_list": {"idx": 1.5, "uri": uri}}),
                StatusReferenceError::InvalidIndex,
            ),
            (
                json!({"status_list": {"idx": "1", "uri": uri}}),
                StatusReferenceError::InvalidIndex,
            ),
            (
                json!({"status_list": {"idx": 1}}),
                StatusReferenceError::InvalidUri,
            ),
            (
                json!({"status_list": {"idx": 1, "uri": 7}}),
                StatusReferenceError::InvalidUri,
            ),
        ];
        for (status, expected) in cases {
            assert_eq!(
                StatusReference::from_status_claim(&status),
                Err(expected),
                "{status}"
            );
        }
    }

    #[test]
    fn only_plain_https_urls_are_references() {
        for good in [
            "https://s.example/lists/1",
            "https://s.example",
            "https://s.example:8443/a?b=c",
        ] {
            assert!(StatusReference::new(good, 0).is_ok(), "{good}");
        }
        for bad in [
            "http://s.example/lists/1",
            "ftp://s.example/lists/1",
            "https://",
            "https:///lists/1",
            "https://user@s.example/lists/1",
            "https://s.example/lists/1#frag",
            "https://s.example/a b",
            "https://s.example/\u{e9}",
            "/lists/1",
            "",
        ] {
            assert_eq!(
                StatusReference::new(bad, 0),
                Err(StatusReferenceError::InvalidUri),
                "{bad}"
            );
        }
        let long = format!("https://s.example/{}", "a".repeat(MAX_URI_BYTES));
        assert_eq!(
            StatusReference::new(long, 0),
            Err(StatusReferenceError::InvalidUri)
        );
    }

    #[test]
    fn the_default_policy_carries_the_documented_bounds() {
        let policy = StatusPolicy::default();
        assert_eq!(policy.max_token_bytes(), 1_048_576);
        assert_eq!(policy.min_ttl_seconds(), 60);
        assert_eq!(policy.max_ttl_seconds(), 86_400);
        assert_eq!(policy.max_expiry_horizon_seconds(), 604_800);
        assert_eq!(
            StatusPolicy::new(1_048_576, 60, 86_400, 604_800),
            Ok(policy)
        );
    }

    #[test]
    fn the_policy_constructor_refuses_out_of_range_bounds() {
        let ok = |bytes, min, max, horizon| StatusPolicy::new(bytes, min, max, horizon);
        assert_eq!(
            ok(0, 60, 86_400, 86_400),
            Err(StatusPolicyError::TokenBytes)
        );
        assert_eq!(
            ok(MAX_TOKEN_BYTES_LIMIT + 1, 60, 86_400, 86_400),
            Err(StatusPolicyError::TokenBytes)
        );
        assert_eq!(ok(1, 0, 86_400, 86_400), Err(StatusPolicyError::Ttl));
        assert_eq!(ok(1, 100, 99, 86_400), Err(StatusPolicyError::Ttl));
        assert_eq!(
            ok(1, 60, MAX_TTL_LIMIT_SECONDS + 1, 86_400),
            Err(StatusPolicyError::Ttl)
        );
        assert_eq!(ok(1, 60, 60, 0), Err(StatusPolicyError::ExpiryHorizon));
        assert_eq!(
            ok(1, 60, 60, MAX_HORIZON_LIMIT_SECONDS + 1),
            Err(StatusPolicyError::ExpiryHorizon)
        );
        assert!(ok(
            MAX_TOKEN_BYTES_LIMIT,
            60,
            MAX_TTL_LIMIT_SECONDS,
            MAX_HORIZON_LIMIT_SECONDS
        )
        .is_ok());
    }
}
