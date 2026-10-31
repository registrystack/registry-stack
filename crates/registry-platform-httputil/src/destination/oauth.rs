// SPDX-License-Identifier: Apache-2.0
//! OAuth token response decoding for platform consumers.
//!
//! Two decoders share one credential discipline. [`decode_strict_oauth_token`]
//! closes the member set to exactly the reviewed shapes named by
//! [`StrictOAuthTokenSchema`]. [`decode_rfc6749_token_response`] is the
//! open-member read RFC 6749 section 5.1 defines: members outside the four it
//! reads are ignored after their values are validated as JSON, so ordinary
//! answers that carry extra members (a Keycloak answer does) decode, and
//! [`decode_rfc6749_error_code`] reads refusal codes into the closed
//! registered set.
//!
//! A parsed credential's bytes stay in the zeroizing buffer
//! [`ParsedBearerToken`] owns. They reach only concrete platform-owned
//! consumers, through [`ParsedBearerToken::authorization`] or
//! [`ParsedBearerToken::credential_bytes`], never a caller as a `String`,
//! and no rendering carries them.

use std::fmt;
use std::num::NonZeroU32;
use std::time::Duration;

use registry_platform_canonical_json::parse_json_strict;
use serde_json::Value;
use thiserror::Error;
use zeroize::Zeroizing;

use super::sensitive_json::SensitiveJsonValue;
use super::{
    BoundedDestinationBody, CredentialDestination, CredentialDestinationBody,
    DestinationAuthorizationValue,
};
use crate::client::OAuthErrorCode;

/// Closed OAuth response contract for generic client-credentials operations.
///
/// The `Bearer*` schemas accept exactly their members with `token_type`
/// spelled `Bearer`. The `Rfc6749Bearer*` schemas close the same member set
/// but also accept the optional string `scope` member RFC 6749 section 5.1
/// allows, and compare `token_type` case-insensitively as section 7.1
/// requires. Every other member is refused under every schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictOAuthTokenSchema {
    BearerWithExpiresIn,
    BearerWithoutExpiry,
    Rfc6749BearerWithExpiresIn,
    Rfc6749BearerWithoutExpiry,
}

impl StrictOAuthTokenSchema {
    const fn expects_expiry(self) -> bool {
        matches!(
            self,
            Self::BearerWithExpiresIn | Self::Rfc6749BearerWithExpiresIn
        )
    }

    const fn follows_rfc6749(self) -> bool {
        matches!(
            self,
            Self::Rfc6749BearerWithExpiresIn | Self::Rfc6749BearerWithoutExpiry
        )
    }
}

/// Value-free failures from the generic strict OAuth response decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum StrictOAuthTokenDecodeError {
    #[error("OAuth token response violates its reviewed contract")]
    ResponseContractViolation,
    #[error("OAuth token response expiry violates its reviewed contract")]
    InvalidExpiry,
    #[error("OAuth bearer token violates its reviewed bound or grammar")]
    InvalidAccessToken,
}

/// One parsed bearer token whose bytes remain opaque and zeroizing.
#[must_use = "the parsed bearer capability must be consumed or explicitly dropped"]
pub struct ParsedBearerToken {
    value: Zeroizing<String>,
    usable_lifetime_ms: Option<NonZeroU32>,
}

impl ParsedBearerToken {
    pub fn authorization(
        &self,
    ) -> Result<DestinationAuthorizationValue, StrictOAuthTokenDecodeError> {
        DestinationAuthorizationValue::bearer(self.value.as_bytes().to_vec())
            .map_err(|_| StrictOAuthTokenDecodeError::InvalidAccessToken)
    }

    /// The credential bytes, for a concrete platform-owned consumer that
    /// moves them straight into its own zeroizing custody. They never
    /// leave as a `String`, and no `Debug` or `Display` rendering carries
    /// them.
    #[must_use]
    pub fn credential_bytes(&self) -> &[u8] {
        self.value.as_bytes()
    }

    #[must_use]
    pub const fn usable_lifetime_ms(&self) -> Option<u32> {
        match self.usable_lifetime_ms {
            Some(value) => Some(value.get()),
            None => None,
        }
    }
}

impl fmt::Debug for ParsedBearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ParsedBearerToken([REDACTED])")
    }
}

/// Decode exactly one reviewed OAuth token shape without exposing response or token bytes.
#[allow(clippy::too_many_arguments)]
pub fn decode_strict_oauth_token(
    body: CredentialDestinationBody,
    schema: StrictOAuthTokenSchema,
    max_response_bytes: usize,
    access_token_max_bytes: usize,
    expires_in_min_seconds: Option<u32>,
    expires_in_max_seconds: Option<u32>,
    max_token_lifetime_ms: Option<u32>,
    expiry_safety_skew_ms: Option<u32>,
) -> Result<ParsedBearerToken, StrictOAuthTokenDecodeError> {
    let BoundedDestinationBody { bytes, slot: _ } = body;
    if bytes.len() > max_response_bytes {
        return Err(StrictOAuthTokenDecodeError::ResponseContractViolation);
    }
    let parsed = parse_json_strict(bytes.as_slice())
        .map_err(|_| StrictOAuthTokenDecodeError::ResponseContractViolation)?;
    drop(bytes);
    let mut sensitive = SensitiveJsonValue::new(parsed);
    let Value::Object(object) = sensitive.value_mut() else {
        return Err(StrictOAuthTokenDecodeError::ResponseContractViolation);
    };
    let scope_members = match (schema.follows_rfc6749(), object.get("scope")) {
        (true, Some(Value::String(_))) => 1,
        (true, Some(_)) => return Err(StrictOAuthTokenDecodeError::ResponseContractViolation),
        _ => 0,
    };
    let expected_members = (if schema.expects_expiry() { 3 } else { 2 }) + scope_members;
    if object.len() != expected_members
        || !object.contains_key("access_token")
        || !object.contains_key("token_type")
        || (schema.expects_expiry() != object.contains_key("expires_in"))
    {
        return Err(StrictOAuthTokenDecodeError::ResponseContractViolation);
    }
    let bearer = match object.get("token_type").and_then(Value::as_str) {
        Some(token_type) if schema.follows_rfc6749() => token_type.eq_ignore_ascii_case("Bearer"),
        Some(token_type) => token_type == "Bearer",
        None => false,
    };
    if !bearer {
        return Err(StrictOAuthTokenDecodeError::ResponseContractViolation);
    }
    let Value::String(access_token) = object
        .remove("access_token")
        .ok_or(StrictOAuthTokenDecodeError::ResponseContractViolation)?
    else {
        return Err(StrictOAuthTokenDecodeError::ResponseContractViolation);
    };
    let value = Zeroizing::new(access_token);
    if value.len() > access_token_max_bytes || !is_oauth_bearer_token(value.as_bytes()) {
        return Err(StrictOAuthTokenDecodeError::InvalidAccessToken);
    }
    let usable_lifetime_ms = if schema.expects_expiry() {
        let expires_in = object
            .remove("expires_in")
            .and_then(|value| value.as_u64())
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(StrictOAuthTokenDecodeError::InvalidExpiry)?;
        let minimum = expires_in_min_seconds.ok_or(StrictOAuthTokenDecodeError::InvalidExpiry)?;
        let maximum = expires_in_max_seconds.ok_or(StrictOAuthTokenDecodeError::InvalidExpiry)?;
        if !(minimum..=maximum).contains(&expires_in) {
            return Err(StrictOAuthTokenDecodeError::InvalidExpiry);
        }
        let lifetime_ms = expires_in
            .checked_mul(1_000)
            .ok_or(StrictOAuthTokenDecodeError::InvalidExpiry)?
            .min(max_token_lifetime_ms.ok_or(StrictOAuthTokenDecodeError::InvalidExpiry)?);
        Some(
            lifetime_ms
                .checked_sub(
                    expiry_safety_skew_ms.ok_or(StrictOAuthTokenDecodeError::InvalidExpiry)?,
                )
                .and_then(NonZeroU32::new)
                .ok_or(StrictOAuthTokenDecodeError::InvalidExpiry)?,
        )
    } else {
        None
    };
    Ok(ParsedBearerToken {
        value,
        usable_lifetime_ms,
    })
}

fn is_oauth_bearer_token(value: &[u8]) -> bool {
    let base_len = value
        .iter()
        .position(|byte| *byte == b'=')
        .unwrap_or(value.len());
    base_len > 0
        && value[..base_len].iter().all(|byte| {
            matches!(
                byte,
                b'A'..=b'Z'
                    | b'a'..=b'z'
                    | b'0'..=b'9'
                    | b'-'
                    | b'.'
                    | b'_'
                    | b'~'
                    | b'+'
                    | b'/'
            )
        })
        && value[base_len..].iter().all(|byte| *byte == b'=')
}

// Keep credential and data response bodies separated at the concrete API.
const _: fn(BoundedDestinationBody<CredentialDestination>) = |_: CredentialDestinationBody| {};

// ---------------------------------------------------------------------------
// The open-member RFC 6749 decode.
//
// RFC 6749 section 5.1 lets a token response carry members the client does
// not know, and section 5.2 puts the refusal code in one text member. This
// half of the module reads those bodies for a concrete consumer such as a
// product runtime's token acquisition: unknown members are ignored after
// their values are validated as JSON, duplicate members are refused, and
// every bound the caller states is enforced before anything parses.
// ---------------------------------------------------------------------------

/// Maximum nesting the open-member reader accepts. A token response is
/// flat; the bound exists so hostile nesting cannot drive recursion.
const MAXIMUM_JSON_DEPTH: usize = 8;

/// Why a document is not one readable JSON object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObjectFault {
    /// The document is empty or only whitespace.
    Empty,
    /// The document exceeds the caller's byte bound.
    TooLarge,
    /// The document is not RFC 8259 JSON, nests deeper than the reader
    /// allows, or is not a top-level object.
    Invalid,
    /// Two members of one object carry the same name.
    DuplicateMember,
}

/// One member of a decoded JSON object.
///
/// Numbers keep the distinction a token response depends on: RFC 8259
/// allows `3600.0` and `1e3`, and a caller that needs a count must be able
/// to refuse both rather than round them. There is no `Clone`: an
/// unbudgeted copy of a text member would duplicate a value that may be a
/// credential. `Debug` is written by hand and redacts text values, so a
/// failing assertion or a stray `{:?}` can never print one.
#[derive(PartialEq)]
enum Member {
    /// A decoded JSON string, in a zeroizing buffer: a text value can
    /// carry a credential, as `access_token` does.
    Text(Zeroizing<String>),
    /// A number with no sign, fraction, or exponent.
    Unsigned(u64),
    /// Any other value: a signed or fractional number, a boolean, null,
    /// or a nested object or array. The value was validated and skipped.
    Other,
}

impl fmt::Debug for Member {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(_) => formatter.write_str("Text([REDACTED])"),
            Self::Unsigned(value) => formatter.debug_tuple("Unsigned").field(value).finish(),
            Self::Other => formatter.write_str("Other"),
        }
    }
}

/// Read one bounded JSON object, refusing duplicate members.
///
/// Member order is preserved as the document states it. This function is
/// total over arbitrary bytes: it returns [`ObjectFault`] rather than
/// panicking, and it reads no more than `bound` bytes before refusing.
fn parse_bounded_object(
    bytes: &[u8],
    bound: usize,
) -> Result<Vec<(Zeroizing<String>, Member)>, ObjectFault> {
    if bytes.is_empty() || bytes.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Err(ObjectFault::Empty);
    }
    if bytes.len() > bound {
        return Err(ObjectFault::TooLarge);
    }
    let mut cursor = 0;
    skip_whitespace(bytes, &mut cursor);
    if bytes.get(cursor) != Some(&b'{') {
        return Err(ObjectFault::Invalid);
    }
    let members = read_object(bytes, &mut cursor, 0)?;
    skip_whitespace(bytes, &mut cursor);
    if cursor != bytes.len() {
        return Err(ObjectFault::Invalid);
    }
    Ok(members)
}

/// Whether one byte may appear in a JSON string's raw form: any byte
/// above the controls except the quote and the backslash, which carry
/// meaning and must be escaped.
fn is_raw_string_byte(byte: u8) -> bool {
    byte >= 0x20 && byte != b'"' && byte != b'\\'
}

/// Whether the escape sequence starting at `cursor` (on the backslash)
/// is well formed, returning the index just past it.
fn escape_is_valid(bytes: &[u8], cursor: usize) -> Option<usize> {
    if *bytes.get(cursor)? != b'\\' {
        return None;
    }
    match *bytes.get(cursor + 1)? {
        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => Some(cursor + 2),
        b'u' => {
            let digits = bytes.get(cursor + 2..cursor + 6)?;
            let all_hex = digits.iter().all(|digit| digit.is_ascii_hexdigit());
            if all_hex {
                Some(cursor + 6)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Decode a JSON string's contents, escapes included, into text in a
/// zeroizing buffer; a lone surrogate half or invalid UTF-8 refuses. The
/// decoded buffer is pre-sized to the raw length, so decoding never
/// reallocates, and the buffer is zeroizing on every path, so every
/// refusal — mid-string or at the UTF-8 check — erases the decoded
/// bytes it drops, including the copy a `FromUtf8Error` hands back.
fn decode_string(raw: &[u8]) -> Option<Zeroizing<String>> {
    let mut text = Zeroizing::new(Vec::with_capacity(raw.len()));
    let mut index = 0;
    while index < raw.len() {
        let byte = raw[index];
        if byte != b'\\' {
            text.push(byte);
            index += 1;
            continue;
        }
        index += 1;
        match raw.get(index)? {
            b'"' => text.push(b'"'),
            b'\\' => text.push(b'\\'),
            b'/' => text.push(b'/'),
            b'b' => text.push(0x08),
            b'f' => text.push(0x0c),
            b'n' => text.push(b'\n'),
            b'r' => text.push(b'\r'),
            b't' => text.push(b'\t'),
            b'u' => {
                let digits = raw.get(index + 1..index + 5)?;
                let code = u16::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()?;
                index += 4;
                let character = match char::from_u32(u32::from(code)) {
                    Some(character) => character,
                    None => {
                        let high = (0xd800..=0xdbff).contains(&code);
                        if !high {
                            return None;
                        }
                        let paired = raw.get(index + 1..index + 7)?;
                        if paired[0] != b'\\' || paired[1] != b'u' {
                            return None;
                        }
                        let low_digits = raw.get(index + 3..index + 7)?;
                        let low =
                            u16::from_str_radix(std::str::from_utf8(low_digits).ok()?, 16).ok()?;
                        if !(0xdc00..=0xdfff).contains(&low) {
                            return None;
                        }
                        let combined = 0x10000
                            + ((u32::from(code) - 0xd800) << 10)
                            + (u32::from(low) - 0xdc00);
                        index += 6;
                        char::from_u32(combined)?
                    }
                };
                let mut encoded = [0; 4];
                text.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
            }
            _ => return None,
        }
        index += 1;
    }
    // Hand the buffer to `from_utf8` without a plain copy: the bytes
    // leave the zeroizing buffer only to enter the checked string, and
    // a refused decode comes back inside the error to be erased rather
    // than freed as they stand.
    let bytes = std::mem::take(&mut *text);
    drop(text);
    match String::from_utf8(bytes) {
        Ok(text) => Some(Zeroizing::new(text)),
        Err(error) => {
            drop(Zeroizing::new(error.into_bytes()));
            None
        }
    }
}

/// Skip JSON whitespace.
fn skip_whitespace(bytes: &[u8], cursor: &mut usize) {
    while matches!(
        bytes.get(*cursor),
        Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r')
    ) {
        *cursor += 1;
    }
}

/// Read one string, opening quote at `cursor`, validating as it goes.
/// The raw bytes gather into one buffer pre-sized to the span up to the
/// closing quote, so gathering never reallocates and never frees a copy
/// of a value mid-read.
fn read_string(bytes: &[u8], cursor: &mut usize) -> Result<Zeroizing<String>, ObjectFault> {
    *cursor += 1;
    let close = closing_quote(bytes, *cursor).ok_or(ObjectFault::Invalid)?;
    let mut raw = Zeroizing::new(Vec::with_capacity(close - *cursor));
    loop {
        let byte = bytes.get(*cursor).copied().ok_or(ObjectFault::Invalid)?;
        if byte == b'"' {
            *cursor += 1;
            break;
        }
        if byte == b'\\' {
            let end = escape_is_valid(bytes, *cursor).ok_or(ObjectFault::Invalid)?;
            raw.extend_from_slice(&bytes[*cursor..end]);
            *cursor = end;
            continue;
        }
        if !is_raw_string_byte(byte) {
            return Err(ObjectFault::Invalid);
        }
        raw.push(byte);
        *cursor += 1;
    }
    decode_string(&raw).ok_or(ObjectFault::Invalid)
}

/// The index of the closing quote of the string whose contents start at
/// `from`, treating a backslash as quoting the byte after it; `None`
/// when the document ends inside the string. The span is a size bound
/// only: the escape and byte rules still decide validity as the string
/// is read.
fn closing_quote(bytes: &[u8], from: usize) -> Option<usize> {
    let mut index = from;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => return Some(index),
            b'\\' => index += 2,
            _ => index += 1,
        }
    }
    None
}

/// Read one JSON number at `cursor`, classifying it as an unsigned count
/// only when it is a bare run of digits.
fn read_number(bytes: &[u8], cursor: &mut usize) -> Result<Member, ObjectFault> {
    let start = *cursor;
    let mut classified = true;
    if bytes.get(*cursor) == Some(&b'-') {
        classified = false;
        *cursor += 1;
    }
    match bytes.get(*cursor) {
        Some(b'0') => *cursor += 1,
        Some(b'1'..=b'9') => {
            while matches!(bytes.get(*cursor), Some(b'0'..=b'9')) {
                *cursor += 1;
            }
        }
        _ => return Err(ObjectFault::Invalid),
    }
    if bytes.get(*cursor) == Some(&b'.') {
        classified = false;
        *cursor += 1;
        if !matches!(bytes.get(*cursor), Some(b'0'..=b'9')) {
            return Err(ObjectFault::Invalid);
        }
        while matches!(bytes.get(*cursor), Some(b'0'..=b'9')) {
            *cursor += 1;
        }
    }
    if matches!(bytes.get(*cursor), Some(b'e') | Some(b'E')) {
        classified = false;
        *cursor += 1;
        if matches!(bytes.get(*cursor), Some(b'+') | Some(b'-')) {
            *cursor += 1;
        }
        if !matches!(bytes.get(*cursor), Some(b'0'..=b'9')) {
            return Err(ObjectFault::Invalid);
        }
        while matches!(bytes.get(*cursor), Some(b'0'..=b'9')) {
            *cursor += 1;
        }
    }
    if !classified {
        return Ok(Member::Other);
    }
    let digits = std::str::from_utf8(&bytes[start..*cursor]).map_err(|_| ObjectFault::Invalid)?;
    digits
        .parse::<u64>()
        .map(Member::Unsigned)
        .or(Ok(Member::Other))
}

/// Read one JSON value at `cursor`.
fn read_value(bytes: &[u8], cursor: &mut usize, depth: usize) -> Result<Member, ObjectFault> {
    if depth > MAXIMUM_JSON_DEPTH {
        return Err(ObjectFault::Invalid);
    }
    match bytes.get(*cursor) {
        Some(b'"') => Ok(Member::Text(read_string(bytes, cursor)?)),
        Some(b'-') | Some(b'0'..=b'9') => read_number(bytes, cursor),
        Some(b't') => expect_literal(bytes, cursor, b"true"),
        Some(b'f') => expect_literal(bytes, cursor, b"false"),
        Some(b'n') => expect_literal(bytes, cursor, b"null"),
        Some(b'{') => {
            read_object(bytes, cursor, depth + 1)?;
            Ok(Member::Other)
        }
        Some(b'[') => {
            read_array(bytes, cursor, depth + 1)?;
            Ok(Member::Other)
        }
        _ => Err(ObjectFault::Invalid),
    }
}

/// Read one object at `cursor`, on the opening brace, collecting its
/// members in document order and refusing duplicate names.
fn read_object(
    bytes: &[u8],
    cursor: &mut usize,
    depth: usize,
) -> Result<Vec<(Zeroizing<String>, Member)>, ObjectFault> {
    *cursor += 1;
    skip_whitespace(bytes, cursor);
    let mut members = Vec::new();
    if bytes.get(*cursor) == Some(&b'}') {
        *cursor += 1;
        return Ok(members);
    }
    loop {
        skip_whitespace(bytes, cursor);
        if bytes.get(*cursor) != Some(&b'"') {
            return Err(ObjectFault::Invalid);
        }
        let name = read_string(bytes, cursor)?;
        skip_whitespace(bytes, cursor);
        if bytes.get(*cursor) != Some(&b':') {
            return Err(ObjectFault::Invalid);
        }
        *cursor += 1;
        skip_whitespace(bytes, cursor);
        let value = read_value(bytes, cursor, depth)?;
        if members
            .iter()
            .any(|(existing, _)| existing.as_str() == name.as_str())
        {
            return Err(ObjectFault::DuplicateMember);
        }
        members.push((name, value));
        skip_whitespace(bytes, cursor);
        match bytes.get(*cursor) {
            Some(b',') => *cursor += 1,
            Some(b'}') => {
                *cursor += 1;
                return Ok(members);
            }
            _ => return Err(ObjectFault::Invalid),
        }
    }
}

/// Read one array at `cursor`, on the opening bracket.
fn read_array(bytes: &[u8], cursor: &mut usize, depth: usize) -> Result<(), ObjectFault> {
    *cursor += 1;
    skip_whitespace(bytes, cursor);
    if bytes.get(*cursor) == Some(&b']') {
        *cursor += 1;
        return Ok(());
    }
    loop {
        skip_whitespace(bytes, cursor);
        read_value(bytes, cursor, depth)?;
        skip_whitespace(bytes, cursor);
        match bytes.get(*cursor) {
            Some(b',') => *cursor += 1,
            Some(b']') => {
                *cursor += 1;
                return Ok(());
            }
            _ => return Err(ObjectFault::Invalid),
        }
    }
}

/// Read one fixed literal at `cursor`.
fn expect_literal(bytes: &[u8], cursor: &mut usize, literal: &[u8]) -> Result<Member, ObjectFault> {
    if bytes.get(*cursor..*cursor + literal.len()) == Some(literal) {
        *cursor += literal.len();
        Ok(Member::Other)
    } else {
        Err(ObjectFault::Invalid)
    }
}

/// Why one RFC 6749 token response is not a usable bearer credential.
///
/// Every variant is value-free: no variant carries part of the body, so a
/// hostile or broken answer cannot reach a diagnostic through a decode
/// failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Rfc6749TokenDecodeError {
    /// The body is empty, exceeds the stated response bound, is not RFC
    /// 8259 JSON, is not one top-level object, nests deeper than the
    /// reader allows, or carries a duplicate member.
    #[error("the token response is not one bounded JSON object this decoder reads")]
    Unreadable,
    /// The answer carries no `access_token` this client can present:
    /// absent, not a string, empty, beyond the stated credential bound,
    /// or not the visible ASCII a header carries.
    #[error("the token response carries no access token this client can present")]
    CredentialUnusable,
    /// The answer states no `token_type` a bearer header can present.
    #[error("the token response states no token type a bearer header can present")]
    TokenTypeUnusable,
    /// The stated `expires_in` is present but is not a positive integer
    /// count of seconds.
    #[error("the token response states no usable positive expires_in")]
    StatedLifetimeUnusable,
    /// The answer states no `expires_in` and the caller assumed none.
    #[error("the token response states no lifetime and the caller assumes none")]
    LifetimeUnstated,
    /// The stated `scope` is present but is not a string, is empty, or
    /// exceeds the stated scope bound.
    #[error("the token response states an unusable scope")]
    ScopeUnusable,
    /// The stated `scope` does not include every scope the caller
    /// required.
    #[error("the token response does not include every required scope")]
    ScopeNarrowed,
}

/// Decode one RFC 6749 section 5.1 token response body: the access token,
/// the token type in any case, and the stated or assumed lifetime.
///
/// This is the open-member read beside [`decode_strict_oauth_token`]:
/// members outside `access_token`, `token_type`, `expires_in`, and
/// `scope` are ignored after their values are validated as JSON, so an
/// issuer's extra members (`refresh_expires_in`, `not-before-policy`)
/// cannot refuse an ordinary answer. The document must still be one
/// bounded JSON object with no duplicate members; nesting is bounded so
/// hostile depth cannot drive recursion.
///
/// The lifetime rides beside the token as the `Duration` of the answer:
/// the stated `expires_in`, or `assumed_lifetime` when the issuer stated
/// none. [`ParsedBearerToken::usable_lifetime_ms`] stays `None` because
/// no millisecond policy has been applied here.
///
/// The checks run in one fixed order, and a body that fails an earlier
/// check refuses with that check's fault even when a later one would
/// also fail: the credential, then the token type, then the lifetime,
/// then the scope.
pub fn decode_rfc6749_token_response(
    bytes: &[u8],
    maximum_response_bytes: usize,
    maximum_credential_bytes: usize,
    maximum_scope_bytes: usize,
    required_scope: Option<&str>,
    assumed_lifetime: Option<Duration>,
) -> Result<(ParsedBearerToken, Duration), Rfc6749TokenDecodeError> {
    let mut members = parse_bounded_object(bytes, maximum_response_bytes)
        .map_err(|_| Rfc6749TokenDecodeError::Unreadable)?;
    // The one member that is itself a credential is taken out of the
    // member list, moved once from the reader's zeroizing buffer into the
    // token's, never copied.
    let index = members
        .iter()
        .position(|(name, _)| name.as_str() == "access_token")
        .ok_or(Rfc6749TokenDecodeError::CredentialUnusable)?;
    let (_, Member::Text(token)) = members.remove(index) else {
        return Err(Rfc6749TokenDecodeError::CredentialUnusable);
    };
    if token.is_empty()
        || token.len() > maximum_credential_bytes
        || !token.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(Rfc6749TokenDecodeError::CredentialUnusable);
    }
    match find_text(
        &members,
        "token_type",
        Rfc6749TokenDecodeError::TokenTypeUnusable,
    )? {
        Some(token_type) if token_type.eq_ignore_ascii_case("bearer") => {}
        _ => return Err(Rfc6749TokenDecodeError::TokenTypeUnusable),
    }
    let lifetime = match find_unsigned(&members, "expires_in")? {
        Some(seconds) if seconds > 0 => Duration::from_secs(seconds),
        Some(_) => return Err(Rfc6749TokenDecodeError::StatedLifetimeUnusable),
        None => assumed_lifetime.ok_or(Rfc6749TokenDecodeError::LifetimeUnstated)?,
    };
    if let Some(scope) = find_text(&members, "scope", Rfc6749TokenDecodeError::ScopeUnusable)? {
        if scope.is_empty() || scope.len() > maximum_scope_bytes {
            return Err(Rfc6749TokenDecodeError::ScopeUnusable);
        }
        if required_scope.is_some_and(|required| scope != required) {
            return Err(Rfc6749TokenDecodeError::ScopeNarrowed);
        }
    }
    Ok((
        ParsedBearerToken {
            value: token,
            usable_lifetime_ms: None,
        },
        lifetime,
    ))
}

/// One member read as text: absent is `None`, present but not a string
/// refuses with the fault the member's own check names.
fn find_text<'a>(
    members: &'a [(Zeroizing<String>, Member)],
    name: &str,
    wrong_type: Rfc6749TokenDecodeError,
) -> Result<Option<&'a str>, Rfc6749TokenDecodeError> {
    match members.iter().find(|(member, _)| member.as_str() == name) {
        Some((_, Member::Text(value))) => Ok(Some(value.as_str())),
        Some((_, _)) => Err(wrong_type),
        None => Ok(None),
    }
}

/// One member read as an unsigned count, the same way.
fn find_unsigned(
    members: &[(Zeroizing<String>, Member)],
    name: &str,
) -> Result<Option<u64>, Rfc6749TokenDecodeError> {
    match members.iter().find(|(member, _)| member.as_str() == name) {
        Some((_, Member::Unsigned(value))) => Ok(Some(*value)),
        Some((_, _)) => Err(Rfc6749TokenDecodeError::StatedLifetimeUnusable),
        None => Ok(None),
    }
}

/// Read the RFC 6749 section 5.2 (and RFC 8707 section 2) error code off
/// one refusal body.
///
/// The body is read as one bounded JSON object, and only its `error` text
/// member is read; `error_description` and `error_uri` are server-authored
/// text about a failed authentication attempt and stay in the body. Every
/// body that is not such an object, or that states no readable code,
/// names [`OAuthErrorCode::Other`] — the registered spellings are the
/// whole of what crosses this decode, and a server's own unregistered
/// spelling never travels in the enum or in any of its names.
pub fn decode_rfc6749_error_code(body: &[u8], maximum_response_bytes: usize) -> OAuthErrorCode {
    parse_bounded_object(body, maximum_response_bytes)
        .ok()
        .and_then(|members| {
            members
                .iter()
                .find_map(|(name, member)| match (name.as_str(), member) {
                    ("error", Member::Text(code)) => Some(OAuthErrorCode::from_wire(code)),
                    _ => None,
                })
        })
        .unwrap_or(OAuthErrorCode::Other)
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use super::*;

    fn body(raw: impl AsRef<[u8]>) -> CredentialDestinationBody {
        BoundedDestinationBody {
            bytes: Zeroizing::new(raw.as_ref().to_vec()),
            slot: PhantomData,
        }
    }

    #[test]
    fn generic_decoder_closes_expiring_and_no_expiry_shapes_without_exposing_bytes() {
        let expiring = decode_strict_oauth_token(
            body(br#"{"access_token":"abc","token_type":"Bearer","expires_in":60}"#),
            StrictOAuthTokenSchema::BearerWithExpiresIn,
            1_024,
            64,
            Some(30),
            Some(120),
            Some(120_000),
            Some(5_000),
        )
        .expect("reviewed expiring response");
        assert_eq!(expiring.usable_lifetime_ms(), Some(55_000));
        assert_eq!(format!("{expiring:?}"), "ParsedBearerToken([REDACTED])");
        assert_eq!(
            format!("{:?}", expiring.authorization().expect("authorization")),
            "DestinationAuthorizationValue([REDACTED])"
        );

        let no_expiry = decode_strict_oauth_token(
            body(br#"{"access_token":"abc","token_type":"Bearer"}"#),
            StrictOAuthTokenSchema::BearerWithoutExpiry,
            1_024,
            64,
            None,
            None,
            None,
            None,
        )
        .expect("reviewed no-expiry response");
        assert_eq!(no_expiry.usable_lifetime_ms(), None);

        assert_eq!(
            decode_strict_oauth_token(
                body(br#"{"access_token":"abc","token_type":"Bearer","expires_in":4}"#),
                StrictOAuthTokenSchema::BearerWithExpiresIn,
                1_024,
                64,
                Some(30),
                Some(120),
                Some(120_000),
                Some(5_000),
            )
            .err(),
            Some(StrictOAuthTokenDecodeError::InvalidExpiry)
        );
    }

    fn decode_generic(
        raw: &[u8],
        schema: StrictOAuthTokenSchema,
    ) -> Result<ParsedBearerToken, StrictOAuthTokenDecodeError> {
        let expiring = matches!(
            schema,
            StrictOAuthTokenSchema::BearerWithExpiresIn
                | StrictOAuthTokenSchema::Rfc6749BearerWithExpiresIn
        );
        decode_strict_oauth_token(
            body(raw),
            schema,
            1_024,
            64,
            expiring.then_some(30),
            expiring.then_some(120),
            expiring.then_some(120_000),
            expiring.then_some(5_000),
        )
    }

    #[test]
    fn rfc6749_schemas_accept_an_optional_string_scope() {
        let expiring = decode_generic(
            br#"{"access_token":"abc","token_type":"Bearer","expires_in":60,"scope":"send"}"#,
            StrictOAuthTokenSchema::Rfc6749BearerWithExpiresIn,
        )
        .expect("scope is tolerated");
        assert_eq!(expiring.usable_lifetime_ms(), Some(55_000));
        let no_expiry = decode_generic(
            br#"{"access_token":"abc","token_type":"Bearer","scope":"send read"}"#,
            StrictOAuthTokenSchema::Rfc6749BearerWithoutExpiry,
        )
        .expect("scope is tolerated");
        assert_eq!(no_expiry.usable_lifetime_ms(), None);
        for (raw, schema) in [
            (
                br#"{"access_token":"abc","token_type":"Bearer","expires_in":60}"#.as_slice(),
                StrictOAuthTokenSchema::Rfc6749BearerWithExpiresIn,
            ),
            (
                br#"{"access_token":"abc","token_type":"Bearer"}"#,
                StrictOAuthTokenSchema::Rfc6749BearerWithoutExpiry,
            ),
        ] {
            assert!(decode_generic(raw, schema).is_ok(), "scope is optional");
        }
        for raw in [
            br#"{"access_token":"abc","token_type":"Bearer","scope":["send"]}"#.as_slice(),
            br#"{"access_token":"abc","token_type":"Bearer","scope":null}"#,
        ] {
            assert_eq!(
                decode_generic(raw, StrictOAuthTokenSchema::Rfc6749BearerWithoutExpiry).err(),
                Some(StrictOAuthTokenDecodeError::ResponseContractViolation),
                "a scope that is not a string is refused"
            );
        }
    }

    #[test]
    fn rfc6749_schemas_compare_the_token_type_case_insensitively() {
        for token_type in ["bearer", "BEARER", "Bearer", "bEaReR"] {
            let raw =
                format!(r#"{{"access_token":"abc","token_type":"{token_type}","expires_in":60}}"#);
            assert!(
                decode_generic(
                    raw.as_bytes(),
                    StrictOAuthTokenSchema::Rfc6749BearerWithExpiresIn
                )
                .is_ok(),
                "{token_type} is the bearer type"
            );
        }
    }

    #[test]
    fn rfc6749_schemas_still_refuse_other_members_and_other_token_types() {
        for raw in [
            br#"{"access_token":"abc","token_type":"Bearer","refresh_token":"r"}"#.as_slice(),
            br#"{"access_token":"abc","token_type":"Bearer","scope":"a","id_token":"x"}"#,
            br#"{"access_token":"abc","token_type":"Bearer","expires_in":60}"#,
            br#"{"access_token":"abc","token_type":"MAC"}"#,
            br#"{"access_token":"abc","token_type":"bearer-ish"}"#,
            br#"{"access_token":"abc","token_type":"Bearer","scope":"a","scope":"b"}"#,
            br#"{"token_type":"Bearer","scope":"a"}"#,
        ] {
            assert_eq!(
                decode_generic(raw, StrictOAuthTokenSchema::Rfc6749BearerWithoutExpiry).err(),
                Some(StrictOAuthTokenDecodeError::ResponseContractViolation),
                "{}",
                String::from_utf8_lossy(raw)
            );
        }
        assert_eq!(
            decode_generic(
                br#"{"access_token":"abc","token_type":"Bearer","scope":"a"}"#,
                StrictOAuthTokenSchema::Rfc6749BearerWithExpiresIn
            )
            .err(),
            Some(StrictOAuthTokenDecodeError::ResponseContractViolation),
            "the expiring schema still needs expires_in"
        );
    }

    #[test]
    fn the_exact_schemas_still_refuse_scope_and_a_lowercase_token_type() {
        for schema in [
            StrictOAuthTokenSchema::BearerWithExpiresIn,
            StrictOAuthTokenSchema::BearerWithoutExpiry,
        ] {
            for raw in [
                br#"{"access_token":"abc","token_type":"Bearer","expires_in":60,"scope":"a"}"#
                    .as_slice(),
                br#"{"access_token":"abc","token_type":"Bearer","scope":"a"}"#,
                br#"{"access_token":"abc","token_type":"bearer","expires_in":60}"#,
                br#"{"access_token":"abc","token_type":"bearer"}"#,
            ] {
                assert_eq!(
                    decode_generic(raw, schema).err(),
                    Some(StrictOAuthTokenDecodeError::ResponseContractViolation),
                    "{schema:?} {}",
                    String::from_utf8_lossy(raw)
                );
            }
        }
    }

    #[test]
    fn rejects_missing_expiry_substitutes_extras_and_duplicate_members() {
        for raw in [
            br#"{"access_token":"abc","token_type":"Bearer","expires_in":60}"#.as_slice(),
            br#"{"access_token":"abc","token_type":"Bearer","scope":"openid"}"#,
            br#"{"access_token":"abc","access_token":"def","token_type":"Bearer"}"#,
            br#"{"access_token":"abc"}"#,
            br#"["abc","Bearer"]"#,
        ] {
            assert!(
                decode_generic(raw, StrictOAuthTokenSchema::BearerWithoutExpiry).is_err(),
                "fixture must fail"
            );
        }
    }

    #[test]
    fn enforces_caller_body_and_token_bounds_and_bearer_grammar() {
        let raw = br#"{"access_token":"abc","token_type":"Bearer"}"#;
        let decode_bounded = |max_response_bytes, access_token_max_bytes| {
            decode_strict_oauth_token(
                body(raw),
                StrictOAuthTokenSchema::BearerWithoutExpiry,
                max_response_bytes,
                access_token_max_bytes,
                None,
                None,
                None,
                None,
            )
            .err()
        };
        assert_eq!(
            decode_bounded(8, 64),
            Some(StrictOAuthTokenDecodeError::ResponseContractViolation)
        );
        assert_eq!(
            decode_bounded(1_024, 2),
            Some(StrictOAuthTokenDecodeError::InvalidAccessToken)
        );
        for token in ["", "ab=cd", "has space", "snowman-☃"] {
            let raw = format!(r#"{{"access_token":"{token}","token_type":"Bearer"}}"#);
            assert_eq!(
                decode_generic(raw.as_bytes(), StrictOAuthTokenSchema::BearerWithoutExpiry).err(),
                Some(StrictOAuthTokenDecodeError::InvalidAccessToken)
            );
        }
    }

    #[test]
    fn requires_exact_case_and_string_types() {
        assert_eq!(
            decode_generic(
                br#"{"access_token":"abc","token_type":"bearer"}"#,
                StrictOAuthTokenSchema::BearerWithoutExpiry,
            )
            .err(),
            Some(StrictOAuthTokenDecodeError::ResponseContractViolation)
        );
        for raw in [
            br#"{"access_token":1,"token_type":"Bearer"}"#.as_slice(),
            br#"{"access_token":"abc","token_type":true}"#,
            br#"{"access_token":"abc","token_type":"Bearer"} trailing"#,
        ] {
            assert!(decode_generic(raw, StrictOAuthTokenSchema::BearerWithoutExpiry).is_err());
        }
    }

    #[test]
    fn failures_do_not_echo_token_or_response_values() {
        let error = decode_generic(
            br#"{"access_token":"token-secret value","token_type":"Bearer"}"#,
            StrictOAuthTokenSchema::BearerWithoutExpiry,
        )
        .expect_err("invalid token fails");
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains("token-secret"));
        assert!(!diagnostic.contains("Bearer"));
    }
}

#[cfg(test)]
mod rfc6749_tests {
    use super::*;
    use crate::client::MAXIMUM_TOKEN_BYTES;
    use crate::MAXIMUM_TOKEN_RESPONSE_BYTES;

    /// The response bound the platform client already reads token answers
    /// under.
    const RESPONSE_BOUND: usize = MAXIMUM_TOKEN_RESPONSE_BYTES as usize;
    /// Evidence's scope bound, the one the adapter token reader passes.
    const SCOPE_BOUND: usize = 512;

    fn decode(
        body: &[u8],
        required_scope: Option<&str>,
        assumed: Option<Duration>,
    ) -> Result<(ParsedBearerToken, Duration), Rfc6749TokenDecodeError> {
        decode_rfc6749_token_response(
            body,
            RESPONSE_BOUND,
            MAXIMUM_TOKEN_BYTES,
            SCOPE_BOUND,
            required_scope,
            assumed,
        )
    }

    fn answer(body: &[u8]) -> (ParsedBearerToken, Duration) {
        decode(body, None, None).expect("the body decodes")
    }

    /// The ordinary answer an issuer sends: bearer in any case, the
    /// lifetime stated, and members this decoder does not know ignored
    /// after validation. A Keycloak answer carries
    /// `refresh_expires_in` and `not-before-policy`.
    #[test]
    fn open_member_answers_decode() {
        let (token, lifetime) = answer(
            br#"{"access_token":"at","token_type":"bEaReR","expires_in":600,"refresh_expires_in":0,"not-before-policy":0}"#,
        );
        assert_eq!(token.credential_bytes(), b"at");
        assert_eq!(lifetime, Duration::from_secs(600));
        // No millisecond policy has been applied to an open decode.
        assert_eq!(token.usable_lifetime_ms(), None);
        assert_eq!(
            format!("{token:?}"),
            "ParsedBearerToken([REDACTED])",
            "the Debug rendering carries no credential"
        );
    }

    /// An absent `expires_in` takes the caller's assumed lifetime; with
    /// none assumed, the answer states no lifetime at all.
    #[test]
    fn an_absent_expires_in_takes_the_assumed_lifetime_or_refuses() {
        assert_eq!(
            decode(
                br#"{"access_token":"at","token_type":"Bearer"}"#,
                None,
                None,
            )
            .err(),
            Some(Rfc6749TokenDecodeError::LifetimeUnstated),
            "the missing lifetime is a credential fault, not a protocol one"
        );
        let (_, lifetime) = decode(
            br#"{"access_token":"at","token_type":"Bearer"}"#,
            None,
            Some(Duration::from_secs(60)),
        )
        .expect("the assumed lifetime stands in");
        assert_eq!(lifetime, Duration::from_secs(60));
    }

    /// A present but unusable `expires_in` is never rescued by the
    /// assumed lifetime: zero, negatives, fractions, strings, exponents,
    /// booleans, and null all refuse.
    #[test]
    fn an_unusable_stated_expires_in_never_takes_the_assumed_lifetime() {
        for body in [
            r#"{"access_token":"at","token_type":"Bearer","expires_in":0}"#,
            r#"{"access_token":"at","token_type":"Bearer","expires_in":-1}"#,
            r#"{"access_token":"at","token_type":"Bearer","expires_in":600.0}"#,
            r#"{"access_token":"at","token_type":"Bearer","expires_in":"600"}"#,
            r#"{"access_token":"at","token_type":"Bearer","expires_in":1e3}"#,
            r#"{"access_token":"at","token_type":"Bearer","expires_in":null}"#,
            r#"{"access_token":"at","token_type":"Bearer","expires_in":true}"#,
        ] {
            assert_eq!(
                decode(body.as_bytes(), None, Some(Duration::from_secs(60))).err(),
                Some(Rfc6749TokenDecodeError::StatedLifetimeUnusable),
                "{body} must refuse"
            );
        }
    }

    /// The credential itself must be presentable: present, a string,
    /// non-empty, within the bound, and only the visible ASCII a header
    /// carries.
    #[test]
    fn the_access_token_must_be_presentable() {
        let with_del = format!(
            r#"{{"access_token":"at{}del","token_type":"Bearer","expires_in":60}}"#,
            "\u{7f}"
        );
        for body in [
            r#"{"token_type":"Bearer","expires_in":60}"#,
            r#"{"access_token":"","token_type":"Bearer","expires_in":60}"#,
            r#"{"access_token":7,"token_type":"Bearer","expires_in":60}"#,
            r#"{"access_token":"has space","token_type":"Bearer","expires_in":60}"#,
            r#"{"access_token":"folded\ncred","token_type":"Bearer","expires_in":60}"#,
            with_del.as_str(),
        ] {
            assert_eq!(
                decode(body.as_bytes(), None, None).err(),
                Some(Rfc6749TokenDecodeError::CredentialUnusable),
                "{body} must refuse"
            );
        }
    }

    /// The credential bound the decoder is tested at is the platform
    /// bearer bound itself: exactly the bound decodes, one byte past
    /// refuses.
    #[test]
    fn the_credential_bound_is_the_platform_bearer_bound() {
        let at_bound = format!(
            r#"{{"access_token":"{}","token_type":"Bearer","expires_in":60}}"#,
            "a".repeat(MAXIMUM_TOKEN_BYTES)
        );
        assert!(decode(at_bound.as_bytes(), None, None).is_ok());
        let past_bound = format!(
            r#"{{"access_token":"{}","token_type":"Bearer","expires_in":60}}"#,
            "a".repeat(MAXIMUM_TOKEN_BYTES + 1)
        );
        assert_eq!(
            decode(past_bound.as_bytes(), None, None).err(),
            Some(Rfc6749TokenDecodeError::CredentialUnusable)
        );
    }

    /// The token type must be bearer in any case; a missing or other
    /// type is not presentable.
    #[test]
    fn the_token_type_must_be_bearer_in_any_case() {
        for body in [
            r#"{"access_token":"at","expires_in":60}"#,
            r#"{"access_token":"at","token_type":"MAC","expires_in":60}"#,
            r#"{"access_token":"at","token_type":7,"expires_in":60}"#,
        ] {
            assert_eq!(
                decode(body.as_bytes(), None, None).err(),
                Some(Rfc6749TokenDecodeError::TokenTypeUnusable),
                "{body} must refuse"
            );
        }
        assert!(decode(
            br#"{"access_token":"at","token_type":"BEARER","expires_in":60}"#,
            None,
            None,
        )
        .is_ok());
    }

    /// A stated scope must be a non-empty string within the bound and
    /// include every required scope; a response without a scope is fine,
    /// required scope or not.
    #[test]
    fn a_stated_scope_must_be_usable_and_include_every_required_scope() {
        assert_eq!(
            decode(
                br#"{"access_token":"at","token_type":"Bearer","expires_in":60,"scope":"read"}"#,
                Some("read write"),
                None,
            )
            .err(),
            Some(Rfc6749TokenDecodeError::ScopeNarrowed)
        );
        assert!(decode(
            br#"{"access_token":"at","token_type":"Bearer","expires_in":60,"scope":"read write"}"#,
            Some("read write"),
            None,
        )
        .is_ok());
        // Absent scope: fine whether or not a scope was required.
        assert!(decode(
            br#"{"access_token":"at","token_type":"Bearer","expires_in":60}"#,
            Some("read"),
            None,
        )
        .is_ok());
        for body in [
            r#"{"access_token":"at","token_type":"Bearer","expires_in":60,"scope":""}"#,
            r#"{"access_token":"at","token_type":"Bearer","expires_in":60,"scope":7}"#,
            r#"{"access_token":"at","token_type":"Bearer","expires_in":60,"scope":null}"#,
        ] {
            assert_eq!(
                decode(body.as_bytes(), None, None).err(),
                Some(Rfc6749TokenDecodeError::ScopeUnusable),
                "{body} must refuse"
            );
        }
        let overbound = format!(
            r#"{{"access_token":"at","token_type":"Bearer","expires_in":60,"scope":"{}"}}"#,
            "s".repeat(SCOPE_BOUND + 1)
        );
        assert_eq!(
            decode(overbound.as_bytes(), None, None).err(),
            Some(Rfc6749TokenDecodeError::ScopeUnusable)
        );
    }

    /// A body beyond the response bound, or not one readable JSON
    /// object — empty, whitespace, an array, truncated, or carrying
    /// duplicate members — is unreadable.
    #[test]
    fn unreadable_bodies_refuse() {
        let oversized = vec![b' '; RESPONSE_BOUND + 1];
        for body in [
            &b""[..],
            b"   ",
            b"[]",
            br#"{"access_token":"at","token_type":"Bearer","expires_in""#,
            br#"{"access_token":"at","access_token":"at","token_type":"Bearer","expires_in":60}"#,
            oversized.as_slice(),
        ] {
            assert_eq!(
                decode(body, None, None).err(),
                Some(Rfc6749TokenDecodeError::Unreadable),
                "{:?} must refuse",
                String::from_utf8_lossy(body)
            );
        }
    }

    /// Every decode fault is value-free: no rendering of any variant
    /// carries part of the body, so a hostile answer cannot reach a
    /// diagnostic through its own refusal.
    #[test]
    fn decode_faults_never_carry_the_body() {
        const MARKER: &str = "c4b-token-body-marker-41be11d5";
        let bodies = [
            format!(r#"{{"access_token":"{MARKER}","token_type":"MAC","expires_in":60}}"#),
            r#"{"access_token":"at","token_type":"Bearer","expires_in":0}"#.to_owned(),
            format!(
                r#"{{"access_token":"at","token_type":"Bearer","expires_in":60,"scope":"{MARKER}"}}"#
            ),
            MARKER.to_owned(),
        ];
        for body in &bodies {
            let error = decode(
                body.as_bytes(),
                Some("required"),
                Some(Duration::from_secs(60)),
            )
            .expect_err("the body must refuse");
            let rendered = format!("{error:?} {error}");
            assert!(
                !rendered.contains(MARKER),
                "a rendering carried the body: {rendered}"
            );
        }
    }

    /// The registered RFC 6749 and RFC 8707 spellings name their
    /// variants; every other spelling collapses to the one fixed
    /// unregistered name, and no server text surfaces.
    #[test]
    fn error_codes_read_off_the_wire() {
        for (spelling, code) in [
            ("invalid_request", OAuthErrorCode::InvalidRequest),
            ("invalid_client", OAuthErrorCode::InvalidClient),
            ("invalid_grant", OAuthErrorCode::InvalidGrant),
            ("unauthorized_client", OAuthErrorCode::UnauthorizedClient),
            (
                "unsupported_grant_type",
                OAuthErrorCode::UnsupportedGrantType,
            ),
            ("invalid_scope", OAuthErrorCode::InvalidScope),
            ("invalid_target", OAuthErrorCode::InvalidTarget),
        ] {
            let body = format!(r#"{{"error":"{spelling}"}}"#);
            assert_eq!(
                decode_rfc6749_error_code(body.as_bytes(), RESPONSE_BOUND),
                code
            );
            assert_eq!(code.as_str(), spelling);
            assert_eq!(
                decode_rfc6749_error_code(body.as_bytes(), RESPONSE_BOUND).as_str(),
                spelling
            );
        }
        for spelling in ["canary_extension", "", "Invalid_Client", "invalid client"] {
            let body = format!(r#"{{"error":"{spelling}"}}"#);
            let code = decode_rfc6749_error_code(body.as_bytes(), RESPONSE_BOUND);
            assert_eq!(code, OAuthErrorCode::Other, "{spelling}");
            assert_eq!(code.as_str(), "unregistered-error-code");
            assert!(!code.as_str().contains("canary"), "{spelling}");
        }
    }

    /// A body that is not one readable object, or that states no `error`
    /// text, names the unregistered code; a `error_description` beside a
    /// registered code is dropped whole.
    #[test]
    fn error_code_bodies_without_a_readable_code_collapse_to_other() {
        for body in [
            &b""[..],
            b"<html>bad gateway</html>",
            br#"{"error":7}"#,
            br#"{"other":"canary"}"#,
            br#"["error","invalid_client"]"#,
        ] {
            assert_eq!(
                decode_rfc6749_error_code(body, RESPONSE_BOUND),
                OAuthErrorCode::Other,
                "{:?} must collapse",
                String::from_utf8_lossy(body)
            );
        }
        // The description is server-authored text about a failed
        // authentication attempt: it stays in the body.
        let code = decode_rfc6749_error_code(
            br#"{"error":"invalid_client","error_description":"canary-server-text"}"#,
            RESPONSE_BOUND,
        );
        assert_eq!(code, OAuthErrorCode::InvalidClient);
        assert!(!code.as_str().contains("canary"));
    }

    // -- the bounded object reader itself ----------------------------------

    fn text(name: &str, value: &str) -> (Zeroizing<String>, Member) {
        (
            Zeroizing::new(name.to_owned()),
            Member::Text(Zeroizing::new(value.to_owned())),
        )
    }

    fn member(name: &str, value: Member) -> (Zeroizing<String>, Member) {
        (Zeroizing::new(name.to_owned()), value)
    }

    /// The members a token response carries, read in document order, with
    /// unknown members ignored after validation.
    #[test]
    fn reads_an_object_and_preserves_member_order() {
        let members = parse_bounded_object(
            br#"{"access_token":"at","token_type":"Bearer","expires_in":3600,"refresh_expires_in":0,"not-before-policy":0}"#,
            16 * 1024,
        )
        .expect("a readable token response");
        assert_eq!(
            members,
            vec![
                text("access_token", "at"),
                text("token_type", "Bearer"),
                member("expires_in", Member::Unsigned(3600)),
                member("refresh_expires_in", Member::Unsigned(0)),
                member("not-before-policy", Member::Unsigned(0)),
            ]
        );
    }

    /// Unknown members may nest arbitrarily within the depth bound; their
    /// values are validated as JSON and never surface.
    #[test]
    fn unknown_members_may_composite() {
        let members = parse_bounded_object(
            br#"{"known":"v","nested":{"a":[1,-2.5,true,null,"x"]},"tail":7}"#,
            16 * 1024,
        )
        .expect("composite unknown members are valid JSON");
        assert_eq!(
            members,
            vec![
                text("known", "v"),
                member("nested", Member::Other),
                member("tail", Member::Unsigned(7)),
            ]
        );
    }

    /// Fractional, signed, exponent, boolean, and null values are
    /// distinguishable from unsigned counts.
    #[test]
    fn number_kinds_do_not_round() {
        let members = parse_bounded_object(
            br#"{"a":1,"b":1.0,"c":-1,"d":1e3,"e":true,"f":null,"g":0}"#,
            16 * 1024,
        )
        .expect("all RFC 8259 value kinds parse");
        let map: Vec<(&str, &Member)> = members
            .iter()
            .map(|(name, value)| (name.as_str(), value))
            .collect();
        assert_eq!(
            map,
            vec![
                ("a", &Member::Unsigned(1)),
                ("b", &Member::Other),
                ("c", &Member::Other),
                ("d", &Member::Other),
                ("e", &Member::Other),
                ("f", &Member::Other),
                ("g", &Member::Unsigned(0)),
            ]
        );
    }

    /// Duplicate members are refused, wherever they sit.
    #[test]
    fn duplicate_members_are_refused() {
        assert_eq!(
            parse_bounded_object(br#"{"a":1,"a":2}"#, 1024),
            Err(ObjectFault::DuplicateMember)
        );
        assert_eq!(
            parse_bounded_object(br#"{"a":{"x":1,"x":2}}"#, 1024),
            Err(ObjectFault::DuplicateMember)
        );
    }

    /// A non-object document, truncated JSON, trailing content, and an
    /// empty document are all invalid, never a panic.
    #[test]
    fn non_objects_and_truncations_are_invalid() {
        for document in [
            &b""[..],
            b"   ",
            b"[]",
            b"1",
            br#"{"a":1"#,
            br#"{"a":1},"#,
            br#"{"a":1} trailing"#,
            b"{",
            br#"{"a"}"#,
            br#"{"a":}"#,
        ] {
            assert!(
                matches!(
                    parse_bounded_object(document, 1024),
                    Err(ObjectFault::Invalid | ObjectFault::Empty)
                ),
                "document {document:?} must not parse"
            );
        }
    }

    /// Hostile strings: raw control bytes, bad escapes, lone surrogates,
    /// truncated unicode escapes, and invalid UTF-8 all refuse.
    #[test]
    fn malformed_strings_refuse() {
        for document in [
            &b"{\"a\":\"\t\"}"[..],
            b"{\"a\":\"\\q\"}",
            b"{\"a\":\"\\u00\"}",
            b"{\"a\":\"\\ud800\"}",
            b"{\"a\":\"\\ud800\\u0061\"}",
            b"{\"a\":\"unterminated}",
            b"{\"a\":\"\xff\"}",
        ] {
            assert_eq!(
                parse_bounded_object(document, 1024),
                Err(ObjectFault::Invalid),
                "document {document:?} must refuse"
            );
        }
    }

    /// String escapes decode, including surrogate pairs.
    #[test]
    fn string_escapes_decode() {
        let members = parse_bounded_object(
            b"{\"a\":\"line\\nbreak \\u0041\\ud83d\\ude00 \\/ \\\"q\\\"\"}",
            1024,
        )
        .expect("escapes decode");
        assert_eq!(members, vec![text("a", "line\nbreak A\u{1f600} / \"q\"")]);
    }

    /// The byte bound refuses before parsing.
    #[test]
    fn the_byte_bound_refuses_first() {
        assert_eq!(
            parse_bounded_object(br#"{"a":1}"#, 3),
            Err(ObjectFault::TooLarge)
        );
    }

    /// Nesting deeper than the bound refuses rather than recursing.
    #[test]
    fn depth_is_bounded() {
        let deep = format!("{}1{}", "[".repeat(64), "]".repeat(64));
        let document = format!("{{\"a\":{deep}}}");
        assert_eq!(
            parse_bounded_object(document.as_bytes(), 1024 * 1024),
            Err(ObjectFault::Invalid)
        );
    }

    /// Malformed numbers refuse: leading zeros, plus signs, bare dots,
    /// and trailing letters.
    #[test]
    fn malformed_numbers_refuse() {
        for document in [
            &b"{\"a\":01}"[..],
            b"{\"a\":+1}",
            b"{\"a\":1.}",
            b"{\"a\":.5}",
            b"{\"a\":1e}",
            b"{\"a\":-}",
            b"{\"a\":Infinity}",
        ] {
            assert_eq!(
                parse_bounded_object(document, 1024),
                Err(ObjectFault::Invalid),
                "{document:?}"
            );
        }
    }

    /// The `Debug` of a parsed member redacts text values: a recognizable
    /// string read from a body never surfaces through a failing
    /// assertion or a stray `{:?}`.
    #[test]
    fn debug_redacts_text_members() {
        const MARKER: &str = "c4b-json-member-marker-9d2f61b4";
        let members = parse_bounded_object(
            format!(r#"{{"access_token":"{MARKER}","expires_in":60}}"#).as_bytes(),
            1024,
        )
        .expect("a readable object");
        let rendered = format!("{members:?}");
        assert!(
            !rendered.contains(MARKER),
            "the Debug rendering carries the text value: {rendered}"
        );
        assert!(rendered.contains("Text([REDACTED])"), "{rendered}");
    }
}
