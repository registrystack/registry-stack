// SPDX-License-Identifier: Apache-2.0
//! Closed OAuth client-credentials response decoding.
//!
//! This module intentionally implements only the two-member, no-expiry token
//! response observed from the pinned OpenCRVS adapter. It does not invent a
//! lifetime or expose a cacheable token. A separately reviewed expiring-token
//! contract can remain distinct if a product actually requires one.

use std::fmt;
use std::num::NonZeroU32;

use registry_platform_canonical_json::parse_json_strict;
use serde_json::Value;
use thiserror::Error;
use zeroize::Zeroizing;

use super::sensitive_json::SensitiveJsonValue;
use super::{
    BoundedDestinationBody, CredentialDestination, CredentialDestinationBody,
    DestinationAuthorizationValue, MAX_DESTINATION_HEADER_VALUE_BYTES,
};

/// Hard ceiling for a closed no-expiry OAuth token response.
const MAX_NO_EXPIRY_OAUTH_RESPONSE_BYTES: usize = 64 * 1_024;
const BEARER_PREFIX_BYTES: usize = b"Bearer ".len();

/// Invalid bounds supplied while compiling a no-expiry token decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum NoExpiryOAuthTokenDecoderBuildError {
    #[error("no-expiry OAuth token bounds are invalid")]
    InvalidBounds,
}

/// Value-free failures while decoding a no-expiry OAuth token response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum NoExpiryOAuthTokenDecodeError {
    #[error("OAuth token response exceeds its reviewed byte bound")]
    ResponseTooLarge,
    #[error("OAuth token response is not unambiguous strict JSON")]
    InvalidJson,
    #[error("OAuth token response violates the closed two-member contract")]
    ResponseContractViolation,
    #[error("OAuth token type is not exactly Bearer")]
    InvalidTokenType,
    #[error("OAuth bearer token violates its reviewed bound or grammar")]
    InvalidAccessToken,
}

/// Strict parser for exactly `access_token` plus `token_type`, with no expiry.
#[derive(Debug)]
pub struct NoExpiryOAuthTokenDecoder {
    max_response_bytes: usize,
    access_token_max_bytes: usize,
}

impl NoExpiryOAuthTokenDecoder {
    /// Compile caller-reviewed response and access-token byte ceilings.
    pub fn new(
        max_response_bytes: usize,
        access_token_max_bytes: usize,
    ) -> Result<Self, NoExpiryOAuthTokenDecoderBuildError> {
        let max_token_bytes = MAX_DESTINATION_HEADER_VALUE_BYTES
            .checked_sub(BEARER_PREFIX_BYTES)
            .ok_or(NoExpiryOAuthTokenDecoderBuildError::InvalidBounds)?;
        if !(1..=MAX_NO_EXPIRY_OAUTH_RESPONSE_BYTES).contains(&max_response_bytes)
            || !(1..=max_token_bytes).contains(&access_token_max_bytes)
        {
            return Err(NoExpiryOAuthTokenDecoderBuildError::InvalidBounds);
        }
        Ok(Self {
            max_response_bytes,
            access_token_max_bytes,
        })
    }

    /// Consume one opaque credential response and return a fresh bearer
    /// capability that cannot be inspected or cached with an invented expiry.
    pub fn decode(
        &self,
        body: CredentialDestinationBody,
    ) -> Result<FreshBearerToken, NoExpiryOAuthTokenDecodeError> {
        let BoundedDestinationBody { bytes, slot: _ } = body;
        if bytes.len() > self.max_response_bytes {
            return Err(NoExpiryOAuthTokenDecodeError::ResponseTooLarge);
        }
        let parsed = parse_json_strict(bytes.as_slice())
            .map_err(|_| NoExpiryOAuthTokenDecodeError::InvalidJson)?;
        drop(bytes);
        let mut sensitive = SensitiveJsonValue::new(parsed);
        let Value::Object(object) = sensitive.value_mut() else {
            return Err(NoExpiryOAuthTokenDecodeError::ResponseContractViolation);
        };
        if object.len() != 2
            || !object.contains_key("access_token")
            || !object.contains_key("token_type")
        {
            return Err(NoExpiryOAuthTokenDecodeError::ResponseContractViolation);
        }
        let token_type = object
            .get("token_type")
            .and_then(Value::as_str)
            .ok_or(NoExpiryOAuthTokenDecodeError::ResponseContractViolation)?;
        if token_type != "Bearer" {
            return Err(NoExpiryOAuthTokenDecodeError::InvalidTokenType);
        }

        let Value::String(access_token) = object
            .remove("access_token")
            .ok_or(NoExpiryOAuthTokenDecodeError::ResponseContractViolation)?
        else {
            return Err(NoExpiryOAuthTokenDecodeError::ResponseContractViolation);
        };
        let access_token = Zeroizing::new(access_token);
        if access_token.len() > self.access_token_max_bytes
            || !is_oauth_bearer_token(access_token.as_bytes())
        {
            return Err(NoExpiryOAuthTokenDecodeError::InvalidAccessToken);
        }

        let authorization = DestinationAuthorizationValue::bearer(access_token.as_bytes().to_vec())
            .map_err(|_| NoExpiryOAuthTokenDecodeError::InvalidAccessToken)?;
        Ok(FreshBearerToken { authorization })
    }
}

/// One fresh, move-only bearer capability.
///
/// It exposes neither token bytes nor lifetime metadata. Consuming it mints
/// exactly one destination authorization value.
///
/// ```compile_fail
/// use registry_platform_httputil::destination::oauth::FreshBearerToken;
///
/// fn raw_token_cannot_escape(token: FreshBearerToken) {
///     let _ = token.as_bytes();
/// }
/// ```
///
/// ```compile_fail
/// use registry_platform_httputil::destination::oauth::FreshBearerToken;
///
/// fn token_capability_is_move_only(token: FreshBearerToken) {
///     let _ = token.clone();
/// }
/// ```
#[must_use = "the fresh bearer capability must be consumed or explicitly dropped"]
pub struct FreshBearerToken {
    authorization: DestinationAuthorizationValue,
}

/// Closed OAuth response contract for generic client-credentials operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictOAuthTokenSchema {
    BearerWithExpiresIn,
    BearerWithoutExpiry,
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
    let expected_members = match schema {
        StrictOAuthTokenSchema::BearerWithExpiresIn => 3,
        StrictOAuthTokenSchema::BearerWithoutExpiry => 2,
    };
    if object.len() != expected_members
        || !object.contains_key("access_token")
        || !object.contains_key("token_type")
        || (matches!(schema, StrictOAuthTokenSchema::BearerWithExpiresIn)
            != object.contains_key("expires_in"))
    {
        return Err(StrictOAuthTokenDecodeError::ResponseContractViolation);
    }
    if object.get("token_type").and_then(Value::as_str) != Some("Bearer") {
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
    let usable_lifetime_ms = match schema {
        StrictOAuthTokenSchema::BearerWithoutExpiry => None,
        StrictOAuthTokenSchema::BearerWithExpiresIn => {
            let expires_in = object
                .remove("expires_in")
                .and_then(|value| value.as_u64())
                .and_then(|value| u32::try_from(value).ok())
                .ok_or(StrictOAuthTokenDecodeError::InvalidExpiry)?;
            let minimum =
                expires_in_min_seconds.ok_or(StrictOAuthTokenDecodeError::InvalidExpiry)?;
            let maximum =
                expires_in_max_seconds.ok_or(StrictOAuthTokenDecodeError::InvalidExpiry)?;
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
        }
    };
    Ok(ParsedBearerToken {
        value,
        usable_lifetime_ms,
    })
}

impl FreshBearerToken {
    /// Consume this one-use capability into a destination authorization value.
    #[must_use]
    pub fn into_authorization(self) -> DestinationAuthorizationValue {
        self.authorization
    }
}

impl fmt::Debug for FreshBearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FreshBearerToken([REDACTED])")
    }
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

    fn decoder() -> NoExpiryOAuthTokenDecoder {
        NoExpiryOAuthTokenDecoder::new(1_024, 64).expect("fixture bounds")
    }

    #[test]
    fn accepts_only_the_exact_no_expiry_shape_and_redacts_the_capability() {
        let token = decoder()
            .decode(body(
                br#"{"access_token":"abc+/._~-==","token_type":"Bearer"}"#,
            ))
            .expect("exact response");
        assert_eq!(format!("{token:?}"), "FreshBearerToken([REDACTED])");
        assert_eq!(
            format!("{:?}", token.into_authorization()),
            "DestinationAuthorizationValue([REDACTED])"
        );
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

    #[test]
    fn rejects_missing_expiry_substitutes_extras_and_duplicate_members() {
        for raw in [
            br#"{"access_token":"abc","token_type":"Bearer","expires_in":60}"#.as_slice(),
            br#"{"access_token":"abc","token_type":"Bearer","scope":"openid"}"#,
            br#"{"access_token":"abc","access_token":"def","token_type":"Bearer"}"#,
            br#"{"access_token":"abc"}"#,
            br#"["abc","Bearer"]"#,
        ] {
            assert!(decoder().decode(body(raw)).is_err(), "fixture must fail");
        }
    }

    #[test]
    fn enforces_caller_body_and_token_bounds_and_bearer_grammar() {
        assert_eq!(
            NoExpiryOAuthTokenDecoder::new(8, 64)
                .expect("valid bounds")
                .decode(body(br#"{"access_token":"abc","token_type":"Bearer"}"#))
                .err(),
            Some(NoExpiryOAuthTokenDecodeError::ResponseTooLarge)
        );
        assert_eq!(
            NoExpiryOAuthTokenDecoder::new(1_024, 2)
                .expect("valid bounds")
                .decode(body(br#"{"access_token":"abc","token_type":"Bearer"}"#))
                .err(),
            Some(NoExpiryOAuthTokenDecodeError::InvalidAccessToken)
        );
        for token in ["", "ab=cd", "has space", "snowman-☃"] {
            let raw = format!(r#"{{"access_token":"{token}","token_type":"Bearer"}}"#);
            assert_eq!(
                decoder().decode(body(raw)).err(),
                Some(NoExpiryOAuthTokenDecodeError::InvalidAccessToken)
            );
        }
    }

    #[test]
    fn requires_exact_case_and_string_types() {
        assert_eq!(
            decoder()
                .decode(body(br#"{"access_token":"abc","token_type":"bearer"}"#))
                .err(),
            Some(NoExpiryOAuthTokenDecodeError::InvalidTokenType)
        );
        for raw in [
            br#"{"access_token":1,"token_type":"Bearer"}"#.as_slice(),
            br#"{"access_token":"abc","token_type":true}"#,
            br#"{"access_token":"abc","token_type":"Bearer"} trailing"#,
        ] {
            assert!(decoder().decode(body(raw)).is_err());
        }
    }

    #[test]
    fn invalid_bounds_fail_closed() {
        assert!(NoExpiryOAuthTokenDecoder::new(0, 1).is_err());
        assert!(NoExpiryOAuthTokenDecoder::new(MAX_NO_EXPIRY_OAUTH_RESPONSE_BYTES + 1, 1).is_err());
        assert!(NoExpiryOAuthTokenDecoder::new(1, 0).is_err());
        assert!(NoExpiryOAuthTokenDecoder::new(
            1,
            MAX_DESTINATION_HEADER_VALUE_BYTES - BEARER_PREFIX_BYTES + 1
        )
        .is_err());
    }

    #[test]
    fn failures_do_not_echo_token_or_response_values() {
        let error = decoder()
            .decode(body(
                br#"{"access_token":"token-secret value","token_type":"Bearer"}"#,
            ))
            .expect_err("invalid token fails");
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains("token-secret"));
        assert!(!diagnostic.contains("Bearer"));
    }
}
