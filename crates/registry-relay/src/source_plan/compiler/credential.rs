//! Closed, slot-typed OAuth client-credentials request and response capabilities.

use std::fmt;
use std::num::NonZeroU32;

use registry_platform_crypto::parse_json_strict;
use registry_platform_httputil::destination::{
    CredentialDestinationRequest, CredentialDestinationRequestTemplate,
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::consultation::OperationId;

/// Closed OAuth request format retained by the compiled credential capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompiledOAuth2RequestFormat {
    JsonClientSecretBody,
    FormClientSecretBody,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompiledOAuth2TokenSchema {
    StrictAccessTokenBearerExpiresIn,
    StrictAccessTokenBearerNoExpiry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompiledOAuth2CacheMode {
    ExpiryBound,
    Disabled,
}

/// One hash-bound failure behavior for every credential-exchange failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompiledCredentialFailurePolicy {
    FailClosedSourceUnavailableNoRetryNoStaleNoDataDispatch,
}

impl CompiledCredentialFailurePolicy {
    pub(crate) const fn retry_allowed(self) -> bool {
        false
    }

    pub(crate) const fn stale_token_fallback_allowed(self) -> bool {
        false
    }

    pub(crate) const fn data_dispatch_allowed_after_failure(self) -> bool {
        false
    }
}

/// Value-free credential-operation failure taxonomy.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub(crate) enum CredentialOperationFailure {
    #[error("credential material is unavailable or invalid")]
    CredentialUnavailable,
    #[error("credential request could not be encoded within its reviewed bounds")]
    RequestEncoding,
    #[error("credential exchange timed out")]
    Timeout,
    #[error("credential transport failed")]
    Transport,
    #[error("credential endpoint returned an unaccepted status")]
    Status,
    #[error("credential response exceeded its reviewed bound")]
    ResponseTooLarge,
    #[error("credential response did not match the strict token schema")]
    MalformedResponse,
    #[error("credential response token type is not exactly Bearer")]
    InvalidTokenType,
    #[error("credential response expiry is outside the reviewed bounds")]
    InvalidExpiresIn,
    #[error("credential response is already expired after safety skew")]
    ExpiredAfterSkew,
}

/// Opaque parsed access token retained only in zeroizing memory.
pub(crate) struct ParsedOAuth2AccessToken {
    value: Zeroizing<String>,
    usable_lifetime_ms: Option<NonZeroU32>,
}

impl fmt::Debug for ParsedOAuth2AccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedOAuth2AccessToken")
            .field("value", &"[REDACTED]")
            .field("usable_lifetime_ms", &self.usable_lifetime_ms)
            .finish()
    }
}

impl ParsedOAuth2AccessToken {
    pub(crate) const fn usable_lifetime_ms(&self) -> Option<u32> {
        match self.usable_lifetime_ms {
            Some(value) => Some(value.get()),
            None => None,
        }
    }

    pub(crate) fn bearer_authorization(
        &self,
    ) -> Result<
        registry_platform_httputil::destination::DestinationAuthorizationValue,
        CredentialOperationFailure,
    > {
        registry_platform_httputil::destination::DestinationAuthorizationValue::bearer(
            self.value.as_bytes().to_vec(),
        )
        .map_err(|_| CredentialOperationFailure::MalformedResponse)
    }
}

/// Strict, bounded parser for the closed OAuth token response.
pub(crate) struct CompiledOAuth2TokenParser {
    pub(super) max_response_bytes: u32,
    pub(super) accepted_statuses: Box<[u16]>,
    pub(super) access_token_max_bytes: u16,
    pub(super) schema: CompiledOAuth2TokenSchema,
    pub(super) expires_in_min_seconds: Option<u32>,
    pub(super) expires_in_max_seconds: Option<u32>,
    pub(super) max_token_lifetime_ms: Option<u32>,
    pub(super) expiry_safety_skew_ms: Option<u32>,
}

impl fmt::Debug for CompiledOAuth2TokenParser {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledOAuth2TokenParser")
            .field("max_response_bytes", &self.max_response_bytes)
            .field("accepted_statuses", &self.accepted_statuses)
            .field("access_token_max_bytes", &self.access_token_max_bytes)
            .finish_non_exhaustive()
    }
}

impl CompiledOAuth2TokenParser {
    pub(crate) const fn max_response_bytes(&self) -> u32 {
        self.max_response_bytes
    }

    pub(crate) const fn access_token_max_bytes(&self) -> u16 {
        self.access_token_max_bytes
    }

    pub(crate) const fn is_no_expiry(&self) -> bool {
        matches!(
            self.schema,
            CompiledOAuth2TokenSchema::StrictAccessTokenBearerNoExpiry
        )
    }

    pub(crate) fn parse(
        &self,
        status: u16,
        bytes: &[u8],
    ) -> Result<ParsedOAuth2AccessToken, CredentialOperationFailure> {
        if self.accepted_statuses.binary_search(&status).is_err() {
            return Err(CredentialOperationFailure::Status);
        }
        if bytes.len() > self.max_response_bytes as usize {
            return Err(CredentialOperationFailure::ResponseTooLarge);
        }
        let value =
            parse_json_strict(bytes).map_err(|_| CredentialOperationFailure::MalformedResponse)?;
        let serde_json::Value::Object(mut object) = value else {
            return Err(CredentialOperationFailure::MalformedResponse);
        };
        let expected_members = match self.schema {
            CompiledOAuth2TokenSchema::StrictAccessTokenBearerExpiresIn => 3,
            CompiledOAuth2TokenSchema::StrictAccessTokenBearerNoExpiry => 2,
        };
        if object.len() != expected_members
            || !object.contains_key("access_token")
            || !object.contains_key("token_type")
            || (matches!(
                self.schema,
                CompiledOAuth2TokenSchema::StrictAccessTokenBearerExpiresIn
            ) != object.contains_key("expires_in"))
        {
            return Err(CredentialOperationFailure::MalformedResponse);
        }
        let serde_json::Value::String(access_token) = object
            .remove("access_token")
            .ok_or(CredentialOperationFailure::MalformedResponse)?
        else {
            return Err(CredentialOperationFailure::MalformedResponse);
        };
        let access_token = Zeroizing::new(access_token);
        if access_token.is_empty()
            || access_token.len() > usize::from(self.access_token_max_bytes)
            || !is_oauth_bearer_token(access_token.as_bytes())
        {
            return Err(CredentialOperationFailure::MalformedResponse);
        }
        if object
            .remove("token_type")
            .and_then(|value| value.as_str().map(str::to_owned))
            .as_deref()
            != Some("Bearer")
        {
            return Err(CredentialOperationFailure::InvalidTokenType);
        }
        let usable_lifetime_ms = match self.schema {
            CompiledOAuth2TokenSchema::StrictAccessTokenBearerNoExpiry => None,
            CompiledOAuth2TokenSchema::StrictAccessTokenBearerExpiresIn => {
                let expires_in = object
                    .remove("expires_in")
                    .and_then(|value| value.as_u64())
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or(CredentialOperationFailure::InvalidExpiresIn)?;
                let min_seconds = self
                    .expires_in_min_seconds
                    .ok_or(CredentialOperationFailure::InvalidExpiresIn)?;
                let max_seconds = self
                    .expires_in_max_seconds
                    .ok_or(CredentialOperationFailure::InvalidExpiresIn)?;
                if !(min_seconds..=max_seconds).contains(&expires_in) {
                    return Err(CredentialOperationFailure::InvalidExpiresIn);
                }
                let lifetime_ms = expires_in
                    .checked_mul(1_000)
                    .ok_or(CredentialOperationFailure::InvalidExpiresIn)?
                    .min(
                        self.max_token_lifetime_ms
                            .ok_or(CredentialOperationFailure::InvalidExpiresIn)?,
                    );
                let usable = lifetime_ms
                    .checked_sub(
                        self.expiry_safety_skew_ms
                            .ok_or(CredentialOperationFailure::InvalidExpiresIn)?,
                    )
                    .and_then(NonZeroU32::new)
                    .ok_or(CredentialOperationFailure::ExpiredAfterSkew)?;
                Some(usable)
            }
        };
        Ok(ParsedOAuth2AccessToken {
            value: access_token,
            usable_lifetime_ms,
        })
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

/// Slot-typed, fully compiled OAuth client-credentials operation.
pub(crate) struct CompiledCredentialOperation {
    pub(super) id: OperationId,
    pub(super) format: CompiledOAuth2RequestFormat,
    pub(super) transport_template: CredentialDestinationRequestTemplate,
    pub(super) max_client_id_bytes: u16,
    pub(super) max_client_secret_bytes: u16,
    pub(super) max_body_bytes: u32,
    pub(super) timeout_ms: u32,
    pub(super) audience: Option<Box<str>>,
    pub(super) scope: Option<Box<str>>,
    pub(super) resource: Option<Box<str>>,
    pub(super) parser: CompiledOAuth2TokenParser,
    pub(super) cache_mode: CompiledOAuth2CacheMode,
    pub(super) failure_policy: CompiledCredentialFailurePolicy,
}

impl fmt::Debug for CompiledCredentialOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledCredentialOperation")
            .field("id", &self.id)
            .field("format", &self.format)
            .field("transport_template", &self.transport_template)
            .field("timeout_ms", &self.timeout_ms)
            .field("parser", &self.parser)
            .field("failure_policy", &self.failure_policy)
            .finish_non_exhaustive()
    }
}

impl CompiledCredentialOperation {
    pub(crate) const fn id(&self) -> &OperationId {
        &self.id
    }

    pub(crate) const fn request_timeout_ms(&self) -> u32 {
        self.timeout_ms
    }

    pub(crate) fn render_request(
        &self,
        client_id: Zeroizing<Vec<u8>>,
        client_secret: Zeroizing<Vec<u8>>,
    ) -> Result<CredentialDestinationRequest, CredentialOperationFailure> {
        if client_id.is_empty()
            || client_id.len() > usize::from(self.max_client_id_bytes)
            || client_secret.is_empty()
            || client_secret.len() > usize::from(self.max_client_secret_bytes)
            || std::str::from_utf8(client_id.as_slice()).is_err()
            || std::str::from_utf8(client_secret.as_slice()).is_err()
        {
            return Err(CredentialOperationFailure::CredentialUnavailable);
        }
        let body = self.encode_body(client_id.as_slice(), client_secret.as_slice())?;
        self.transport_template
            .render_zeroizing(&[], &[], None, Some(body))
            .map_err(|_| CredentialOperationFailure::RequestEncoding)
    }

    pub(super) fn encode_body(
        &self,
        client_id: &[u8],
        client_secret: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CredentialOperationFailure> {
        let encoded_len = self.encoded_body_len(client_id, client_secret)?;
        if encoded_len > self.max_body_bytes as usize {
            return Err(CredentialOperationFailure::RequestEncoding);
        }
        let mut body = BoundedSensitiveWriter::with_exact_limit(encoded_len);
        match self.format {
            CompiledOAuth2RequestFormat::JsonClientSecretBody => {
                append_oauth_json_field(&mut body, true, b"grant_type", b"client_credentials")?;
                append_oauth_json_field(&mut body, false, b"client_id", client_id)?;
                append_oauth_json_field(&mut body, false, b"client_secret", client_secret)?;
                if let Some(audience) = &self.audience {
                    append_oauth_json_field(&mut body, false, b"audience", audience.as_bytes())?;
                }
                if let Some(scope) = &self.scope {
                    append_oauth_json_field(&mut body, false, b"scope", scope.as_bytes())?;
                }
                if let Some(resource) = &self.resource {
                    append_oauth_json_field(&mut body, false, b"resource", resource.as_bytes())?;
                }
                body.push(b'}')?;
            }
            CompiledOAuth2RequestFormat::FormClientSecretBody => {
                append_oauth_form_field(&mut body, true, b"grant_type", b"client_credentials")?;
                append_oauth_form_field(&mut body, false, b"client_id", client_id)?;
                append_oauth_form_field(&mut body, false, b"client_secret", client_secret)?;
                if let Some(audience) = &self.audience {
                    append_oauth_form_field(&mut body, false, b"audience", audience.as_bytes())?;
                }
                if let Some(scope) = &self.scope {
                    append_oauth_form_field(&mut body, false, b"scope", scope.as_bytes())?;
                }
                if let Some(resource) = &self.resource {
                    append_oauth_form_field(&mut body, false, b"resource", resource.as_bytes())?;
                }
            }
        }
        if body.len() != encoded_len {
            return Err(CredentialOperationFailure::RequestEncoding);
        }
        Ok(body.into_inner())
    }

    pub(crate) const fn parser(&self) -> &CompiledOAuth2TokenParser {
        &self.parser
    }

    pub(crate) const fn cache_mode(&self) -> CompiledOAuth2CacheMode {
        self.cache_mode
    }

    pub(crate) const fn failure_policy(&self) -> CompiledCredentialFailurePolicy {
        self.failure_policy
    }

    pub(super) fn encoded_body_len(
        &self,
        client_id: &[u8],
        client_secret: &[u8],
    ) -> Result<usize, CredentialOperationFailure> {
        let mut total = 0_usize;
        let mut field_count = 0_usize;
        {
            let mut add = |name: &[u8], value: &[u8]| -> Option<()> {
                let field_bytes = match self.format {
                    CompiledOAuth2RequestFormat::JsonClientSecretBody => {
                        usize::from(field_count == 0)
                            .checked_add(usize::from(field_count > 0))?
                            .checked_add(json_string_encoded_len(name)?)?
                            .checked_add(1)?
                            .checked_add(json_string_encoded_len(value)?)?
                    }
                    CompiledOAuth2RequestFormat::FormClientSecretBody => {
                        usize::from(field_count > 0)
                            .checked_add(form_component_encoded_len(name)?)?
                            .checked_add(1)?
                            .checked_add(form_component_encoded_len(value)?)?
                    }
                };
                total = total.checked_add(field_bytes)?;
                field_count += 1;
                Some(())
            };
            add(b"grant_type", b"client_credentials")
                .and_then(|()| add(b"client_id", client_id))
                .and_then(|()| add(b"client_secret", client_secret))
                .ok_or(CredentialOperationFailure::RequestEncoding)?;
            if let Some(audience) = &self.audience {
                add(b"audience", audience.as_bytes())
                    .ok_or(CredentialOperationFailure::RequestEncoding)?;
            }
            if let Some(scope) = &self.scope {
                add(b"scope", scope.as_bytes())
                    .ok_or(CredentialOperationFailure::RequestEncoding)?;
            }
            if let Some(resource) = &self.resource {
                add(b"resource", resource.as_bytes())
                    .ok_or(CredentialOperationFailure::RequestEncoding)?;
            }
        }
        if self.format == CompiledOAuth2RequestFormat::JsonClientSecretBody {
            total = total
                .checked_add(1)
                .ok_or(CredentialOperationFailure::RequestEncoding)?;
        }
        Ok(total)
    }
}

fn json_string_encoded_len(value: &[u8]) -> Option<usize> {
    value.iter().try_fold(2_usize, |total, byte| {
        total.checked_add(match byte {
            b'"' | b'\\' => 2,
            0x00..=0x1f => 6,
            _ => 1,
        })
    })
}

fn form_component_encoded_len(value: &[u8]) -> Option<usize> {
    value.iter().try_fold(0_usize, |total, byte| {
        total.checked_add(match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' | b' ' => 1,
            _ => 3,
        })
    })
}

struct BoundedSensitiveWriter {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}

impl BoundedSensitiveWriter {
    fn with_exact_limit(limit: usize) -> Self {
        Self {
            bytes: Zeroizing::new(Vec::with_capacity(limit)),
            limit,
        }
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn push(&mut self, byte: u8) -> Result<(), CredentialOperationFailure> {
        if self.bytes.len() >= self.limit || self.bytes.len() >= self.bytes.capacity() {
            return Err(CredentialOperationFailure::RequestEncoding);
        }
        self.bytes.push(byte);
        Ok(())
    }

    fn extend_from_slice(&mut self, value: &[u8]) -> Result<(), CredentialOperationFailure> {
        let next_len = self
            .bytes
            .len()
            .checked_add(value.len())
            .ok_or(CredentialOperationFailure::RequestEncoding)?;
        if next_len > self.limit || next_len > self.bytes.capacity() {
            return Err(CredentialOperationFailure::RequestEncoding);
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn into_inner(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

fn append_oauth_json_field(
    body: &mut BoundedSensitiveWriter,
    first: bool,
    name: &[u8],
    value: &[u8],
) -> Result<(), CredentialOperationFailure> {
    body.push(if first { b'{' } else { b',' })?;
    append_json_string(body, name)?;
    body.push(b':')?;
    append_json_string(body, value)
}

fn append_json_string(
    body: &mut BoundedSensitiveWriter,
    value: &[u8],
) -> Result<(), CredentialOperationFailure> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    body.push(b'"')?;
    for byte in value {
        match byte {
            b'"' => body.extend_from_slice(br#"\""#)?,
            b'\\' => body.extend_from_slice(br#"\\"#)?,
            0x00..=0x1f => {
                body.extend_from_slice(br"\u00")?;
                body.push(HEX[usize::from(*byte >> 4)])?;
                body.push(HEX[usize::from(*byte & 0x0f)])?;
            }
            _ => body.push(*byte)?,
        }
    }
    body.push(b'"')
}

fn append_oauth_form_field(
    body: &mut BoundedSensitiveWriter,
    first: bool,
    name: &[u8],
    value: &[u8],
) -> Result<(), CredentialOperationFailure> {
    if !first {
        body.push(b'&')?;
    }
    append_oauth_form_component(body, name)?;
    body.push(b'=')?;
    append_oauth_form_component(body, value)
}

fn append_oauth_form_component(
    body: &mut BoundedSensitiveWriter,
    value: &[u8],
) -> Result<(), CredentialOperationFailure> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                body.push(*byte)?;
            }
            b' ' => body.push(b'+')?,
            _ => {
                body.push(b'%')?;
                body.push(HEX[usize::from(*byte >> 4)])?;
                body.push(HEX[usize::from(*byte & 0x0f)])?;
            }
        }
    }
    Ok(())
}
