// SPDX-License-Identifier: Apache-2.0
//! Closed HTTP wire parsing for consultation v1.
//!
//! The router mounts exactly the protected metadata and execute operations. Its
//! execute handler preserves the security order: authenticate, resolve an exact
//! workload-visible profile, then acquire and parse the bounded subject body.
//! No raw HTTP request reaches a source backend.

use axum::body::Body;
use axum::extract::OriginalUri;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use futures::StreamExt;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::auth::AuthenticationResult;
use crate::consultation::{
    AuthenticatedNotaryWorkload, ConsultationExecutionError, ConsultationKey,
    ConsultationServiceError, NotaryEvaluationId, ParsedPurpose, ParsedSingleStringInput,
    ResolvedConsultationProfile,
};
use crate::error::{ConsultationError, Error};
use crate::runtime_config::RuntimeSnapshot;

/// Hard v1 limit applied before JSON parsing.
pub(crate) const MAX_CONSULTATION_REQUEST_BYTES: usize = 8 * 1024;

const DATA_PURPOSE_HEADER: &str = "data-purpose";
const NOTARY_EVALUATION_ID_HEADER: &str = "registry-notary-evaluation-id";
const JSON_MEDIA_TYPE: &str = "application/json";
const MIN_RETRY_AFTER_SECONDS: u64 = 1;
const MAX_RETRY_AFTER_SECONDS: u64 = 60;
pub(crate) const PROFILE_ROUTE: &str = "/v1/consultations/{profile_id}/versions/{profile_version}";
pub(crate) const EXECUTE_ROUTE: &str =
    "/v1/consultations/{profile_id}/versions/{profile_version}/execute";
const CONSULTATION_ROUTE_PREFIX: &str = "/v1/consultations/";
const CONSULTATION_VERSION_SEPARATOR: &str = "/versions/";
const EXECUTE_SUFFIX: &str = "/execute";

/// Mount only the two frozen consultation-v1 operations.
pub(crate) fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        // Axum normally treats HEAD as GET. The public contract intentionally
        // exposes GET only, so install an explicit closed denial for HEAD.
        .route(
            PROFILE_ROUTE,
            get(profile_metadata)
                .head(metadata_method_not_allowed)
                .fallback(metadata_method_not_allowed),
        )
        .route(
            EXECUTE_ROUTE,
            post(execute).fallback(execute_method_not_allowed),
        )
}

async fn metadata_method_not_allowed() -> Response {
    method_not_allowed("GET")
}

async fn execute_method_not_allowed() -> Response {
    method_not_allowed("POST")
}

fn method_not_allowed(allowed: &'static str) -> Response {
    let mut response = StatusCode::METHOD_NOT_ALLOWED.into_response();
    response
        .headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static(allowed));
    response
}

async fn profile_metadata(
    runtime: RuntimeSnapshot,
    Extension(authentication): Extension<AuthenticationResult>,
    OriginalUri(original_uri): OriginalUri,
) -> Response {
    let key = match parse_routed_consultation_key(&original_uri, false) {
        Ok(key) => key,
        Err(error) => return wire_error_response(error),
    };
    let Some(service) = runtime.consultation() else {
        return consultation_error_response(ConsultationError::Unavailable, None);
    };
    let context = match service.resolve(&authentication, &key) {
        Ok(context) => context,
        Err(error) => return service_error_response(error),
    };
    json_response(context.metadata_bytes().to_vec())
}

async fn execute(
    runtime: RuntimeSnapshot,
    Extension(authentication): Extension<AuthenticationResult>,
    OriginalUri(original_uri): OriginalUri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let key = match parse_routed_consultation_key(&original_uri, true) {
        Ok(key) => key,
        Err(error) => return wire_error_response(error),
    };
    let Some(service) = runtime.consultation() else {
        return consultation_error_response(ConsultationError::Unavailable, None);
    };
    let context = match service.resolve(&authentication, &key) {
        Ok(context) => context,
        Err(error) => return service_error_response(error),
    };

    // Do not poll the subject-bearing body until authentication and exact
    // workload-visible profile resolution have both produced their proofs.
    let notary_workload = context.notary_workload();
    let parsed_headers =
        match parse_execute_headers(context.resolved_profile(), &notary_workload, &headers) {
            Ok(parsed) => parsed,
            Err(error) => return wire_error_response(error),
        };
    // Authorization, cookies, forwarding metadata, and every other ambient
    // header are no longer retained when body acquisition or execution waits.
    drop(headers);
    let body = match ConsultationRequestBody::read_from(
        context.resolved_profile(),
        &notary_workload,
        body,
    )
    .await
    {
        Ok(body) => body,
        Err(error) => return wire_error_response(error),
    };
    let envelope = match parse_execute_body(
        context.resolved_profile(),
        &notary_workload,
        parsed_headers,
        body,
    ) {
        Ok(envelope) => envelope,
        Err(error) => return wire_error_response(error),
    };
    match service.execute(context, envelope).await {
        Ok(bytes) => json_response(bytes),
        Err(error) => execution_error_response(error),
    }
}

fn json_response(bytes: Vec<u8>) -> Response {
    let mut response = Response::new(Body::from(bytes));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(JSON_MEDIA_TYPE),
    );
    response
}

fn wire_error_response(error: ConsultationWireError) -> Response {
    consultation_error_response(error.public_error(), None)
}

fn parse_routed_consultation_key(
    original_uri: &axum::http::Uri,
    execute: bool,
) -> Result<ConsultationKey, ConsultationWireError> {
    let raw = original_uri
        .path_and_query()
        .map(|value| value.as_str())
        .ok_or(ConsultationWireError::InvalidProfilePath)?;
    if raw.contains('?') {
        return Err(ConsultationWireError::InvalidProfilePath);
    }
    let route = raw
        .strip_prefix(CONSULTATION_ROUTE_PREFIX)
        .ok_or(ConsultationWireError::InvalidProfilePath)?;
    let route = if execute {
        route
            .strip_suffix(EXECUTE_SUFFIX)
            .ok_or(ConsultationWireError::InvalidProfilePath)?
    } else {
        route
    };
    let (profile_id, profile_version) = route
        .split_once(CONSULTATION_VERSION_SEPARATOR)
        .ok_or(ConsultationWireError::InvalidProfilePath)?;
    parse_consultation_key(profile_id, profile_version)
}

fn service_error_response(error: ConsultationServiceError) -> Response {
    let (public, retry_after_seconds) = match error {
        ConsultationServiceError::InvalidCredentials => {
            (ConsultationError::InvalidCredentials, None)
        }
        ConsultationServiceError::Denied => (ConsultationError::Denied, None),
        ConsultationServiceError::ProfileNotFound => (ConsultationError::ProfileNotFound, None),
        ConsultationServiceError::InvalidRequest => (ConsultationError::InvalidRequest, None),
        ConsultationServiceError::RateLimited(retry_after) => (
            ConsultationError::RateLimited,
            Some(u64::from(retry_after.seconds())),
        ),
        ConsultationServiceError::Unavailable => (ConsultationError::Unavailable, None),
    };
    consultation_error_response(public, retry_after_seconds)
}

fn execution_error_response(error: ConsultationExecutionError) -> Response {
    let (error, denial_recorded) = error.into_parts();
    let mut response = service_error_response(error);
    if let Some(denial_recorded) = denial_recorded {
        response.extensions_mut().insert(denial_recorded);
    }
    response
}

pub(crate) fn consultation_error_response(
    error: ConsultationError,
    retry_after_seconds: Option<u64>,
) -> Response {
    let mut response = Error::from(error).into_response();
    if let Some(seconds) = retry_after_seconds {
        let seconds = seconds.clamp(MIN_RETRY_AFTER_SECONDS, MAX_RETRY_AFTER_SECONDS);
        let value = HeaderValue::from_str(&seconds.to_string())
            .expect("bounded consultation retry seconds form a valid header");
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

/// Non-debuggable, non-clonable ownership of the subject-bearing request body.
///
/// Construction immediately applies the v1 byte ceiling and places the owned
/// allocation under a zeroizing guard before JSON decoding begins.
pub(crate) struct ConsultationRequestBody(Zeroizing<Vec<u8>>);

impl ConsultationRequestBody {
    #[cfg(test)]
    fn try_from_owned(bytes: Vec<u8>) -> Result<Self, ConsultationWireError> {
        let bytes = Zeroizing::new(bytes);
        if bytes.len() > MAX_CONSULTATION_REQUEST_BYTES {
            return Err(ConsultationWireError::BodyTooLarge);
        }
        Ok(Self(bytes))
    }

    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Stream the HTTP body directly into its zeroizing owner. Individual
    /// transport chunks are never retained as a second complete request copy.
    /// Both non-forgeable service capabilities must exist before polling can
    /// acquire any subject-bearing bytes.
    pub(crate) async fn read_from(
        _resolved_profile: &ResolvedConsultationProfile,
        _notary_workload: &AuthenticatedNotaryWorkload<'_>,
        body: Body,
    ) -> Result<Self, ConsultationWireError> {
        let mut retained = Zeroizing::new(Vec::with_capacity(MAX_CONSULTATION_REQUEST_BYTES));
        let mut stream = body.into_data_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| ConsultationWireError::InvalidBody)?;
            let next_len = retained
                .len()
                .checked_add(chunk.len())
                .ok_or(ConsultationWireError::BodyTooLarge)?;
            if next_len > MAX_CONSULTATION_REQUEST_BYTES {
                return Err(ConsultationWireError::BodyTooLarge);
            }
            retained.extend_from_slice(&chunk);
        }
        Ok(Self(retained))
    }
}

/// A value-free reason that the public wire representation was rejected.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub(crate) enum ConsultationWireError {
    #[error("consultation profile path is invalid")]
    InvalidProfilePath,
    #[error("consultation purpose header is missing")]
    MissingPurpose,
    #[error("consultation purpose header is repeated")]
    DuplicatePurpose,
    #[error("consultation purpose header is malformed")]
    InvalidPurpose,
    #[error("consultation content type is missing")]
    MissingContentType,
    #[error("consultation content type is repeated")]
    DuplicateContentType,
    #[error("consultation content type is unsupported")]
    UnsupportedContentType,
    #[error("consultation request body exceeds the v1 bound")]
    BodyTooLarge,
    #[error("consultation request body is malformed")]
    InvalidBody,
    #[error("Notary evaluation id header is repeated")]
    DuplicateNotaryEvaluationId,
    #[error("Notary evaluation id header is malformed")]
    InvalidNotaryEvaluationId,
}

impl ConsultationWireError {
    /// Collapse parser detail into the frozen public taxonomy.
    #[must_use]
    pub(crate) const fn public_error(self) -> ConsultationError {
        match self {
            Self::InvalidProfilePath => ConsultationError::ProfileNotFound,
            Self::MissingPurpose
            | Self::DuplicatePurpose
            | Self::InvalidPurpose
            | Self::MissingContentType
            | Self::DuplicateContentType
            | Self::UnsupportedContentType
            | Self::BodyTooLarge
            | Self::InvalidBody
            | Self::DuplicateNotaryEvaluationId
            | Self::InvalidNotaryEvaluationId => ConsultationError::InvalidRequest,
        }
    }
}

/// Parsed request members awaiting profile-specific input and purpose checks.
///
/// This is not an authorization or dispatch capability and intentionally
/// implements neither `Debug` nor serialization because it retains the raw
/// subject input in its zeroizing domain container.
pub(crate) struct ParsedConsultationEnvelope {
    purpose: ParsedPurpose,
    input: ParsedSingleStringInput,
    notary_evaluation_id: Option<NotaryEvaluationId>,
}

struct ParsedConsultationHeaders {
    purpose: ParsedPurpose,
    notary_evaluation_id: Option<NotaryEvaluationId>,
}

impl ParsedConsultationEnvelope {
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn purpose(&self) -> &ParsedPurpose {
        &self.purpose
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn input(&self) -> &ParsedSingleStringInput {
        &self.input
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn notary_evaluation_id(&self) -> Option<NotaryEvaluationId> {
        self.notary_evaluation_id
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        ParsedPurpose,
        ParsedSingleStringInput,
        Option<NotaryEvaluationId>,
    ) {
        (self.purpose, self.input, self.notary_evaluation_id)
    }
}

/// A minimal decoder for the one closed JSON shape accepted by consultation
/// v1. It never gives subject-bearing escaped text to `serde_json`'s private
/// non-zeroizing scratch buffer. Raw bytes, decoded keys, and the decoded value
/// stay under zeroizing owners until the structural key is proven safe.
struct ClosedConsultationJson<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> ClosedConsultationJson<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn parse(mut self) -> Result<ParsedSingleStringInput, ConsultationWireError> {
        self.whitespace();
        self.byte(b'{')?;
        self.whitespace();
        let root_key = self.string("inputs".len())?;
        if root_key.as_str() != "inputs" {
            return Err(ConsultationWireError::InvalidBody);
        }
        self.whitespace();
        self.byte(b':')?;
        self.whitespace();
        self.byte(b'{')?;
        self.whitespace();
        let input_name = self.string(ParsedSingleStringInput::MAX_NAME_BYTES)?;
        self.whitespace();
        self.byte(b':')?;
        self.whitespace();
        let input_value = self.string(ParsedSingleStringInput::MAX_VALUE_BYTES)?;
        self.whitespace();
        self.byte(b'}')?;
        self.whitespace();
        self.byte(b'}')?;
        self.whitespace();
        if self.position != self.bytes.len() {
            return Err(ConsultationWireError::InvalidBody);
        }

        ParsedSingleStringInput::try_parse_zeroizing(input_name, input_value)
            .map_err(|_| ConsultationWireError::InvalidBody)
    }

    fn whitespace(&mut self) {
        while self
            .bytes
            .get(self.position)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
        {
            self.position += 1;
        }
    }

    fn byte(&mut self, expected: u8) -> Result<(), ConsultationWireError> {
        if self.bytes.get(self.position) != Some(&expected) {
            return Err(ConsultationWireError::InvalidBody);
        }
        self.position += 1;
        Ok(())
    }

    fn string(&mut self, decoded_limit: usize) -> Result<Zeroizing<String>, ConsultationWireError> {
        self.byte(b'"')?;
        // Preallocate the full decoded ceiling and bound every append. A
        // subject-bearing allocation is therefore never reallocated and freed
        // before its zeroizing owner is dropped.
        let mut decoded = Zeroizing::new(String::with_capacity(decoded_limit));
        let mut span_start = self.position;

        loop {
            let byte = *self
                .bytes
                .get(self.position)
                .ok_or(ConsultationWireError::InvalidBody)?;
            match byte {
                b'"' => {
                    self.push_utf8_span(&mut decoded, span_start, self.position, decoded_limit)?;
                    self.position += 1;
                    return Ok(decoded);
                }
                b'\\' => {
                    self.push_utf8_span(&mut decoded, span_start, self.position, decoded_limit)?;
                    self.position += 1;
                    self.escape(&mut decoded, decoded_limit)?;
                    span_start = self.position;
                }
                0x00..=0x1f => return Err(ConsultationWireError::InvalidBody),
                _ => self.position += 1,
            }
        }
    }

    fn push_utf8_span(
        &self,
        decoded: &mut String,
        start: usize,
        end: usize,
        decoded_limit: usize,
    ) -> Result<(), ConsultationWireError> {
        let value = std::str::from_utf8(&self.bytes[start..end])
            .map_err(|_| ConsultationWireError::InvalidBody)?;
        if decoded
            .len()
            .checked_add(value.len())
            .is_none_or(|length| length > decoded_limit)
        {
            return Err(ConsultationWireError::InvalidBody);
        }
        decoded.push_str(value);
        Ok(())
    }

    fn escape(
        &mut self,
        decoded: &mut String,
        decoded_limit: usize,
    ) -> Result<(), ConsultationWireError> {
        let escaped = *self
            .bytes
            .get(self.position)
            .ok_or(ConsultationWireError::InvalidBody)?;
        self.position += 1;
        match escaped {
            b'"' => Self::push_char(decoded, '"', decoded_limit)?,
            b'\\' => Self::push_char(decoded, '\\', decoded_limit)?,
            b'/' => Self::push_char(decoded, '/', decoded_limit)?,
            b'b' => Self::push_char(decoded, '\u{0008}', decoded_limit)?,
            b'f' => Self::push_char(decoded, '\u{000c}', decoded_limit)?,
            b'n' => Self::push_char(decoded, '\n', decoded_limit)?,
            b'r' => Self::push_char(decoded, '\r', decoded_limit)?,
            b't' => Self::push_char(decoded, '\t', decoded_limit)?,
            b'u' => {
                let first = self.hex_code_unit()?;
                let scalar = if (0xd800..=0xdbff).contains(&first) {
                    if self.bytes.get(self.position..self.position + 2) != Some(br"\u") {
                        return Err(ConsultationWireError::InvalidBody);
                    }
                    self.position += 2;
                    let second = self.hex_code_unit()?;
                    if !(0xdc00..=0xdfff).contains(&second) {
                        return Err(ConsultationWireError::InvalidBody);
                    }
                    0x1_0000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00)
                } else if (0xdc00..=0xdfff).contains(&first) {
                    return Err(ConsultationWireError::InvalidBody);
                } else {
                    u32::from(first)
                };
                Self::push_char(
                    decoded,
                    char::from_u32(scalar).ok_or(ConsultationWireError::InvalidBody)?,
                    decoded_limit,
                )?;
            }
            _ => return Err(ConsultationWireError::InvalidBody),
        }
        Ok(())
    }

    fn push_char(
        decoded: &mut String,
        value: char,
        decoded_limit: usize,
    ) -> Result<(), ConsultationWireError> {
        if decoded
            .len()
            .checked_add(value.len_utf8())
            .is_none_or(|length| length > decoded_limit)
        {
            return Err(ConsultationWireError::InvalidBody);
        }
        decoded.push(value);
        Ok(())
    }

    fn hex_code_unit(&mut self) -> Result<u16, ConsultationWireError> {
        let end = self
            .position
            .checked_add(4)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(ConsultationWireError::InvalidBody)?;
        let mut value = 0_u16;
        for byte in &self.bytes[self.position..end] {
            let digit = match byte {
                b'0'..=b'9' => u16::from(*byte - b'0'),
                b'a'..=b'f' => u16::from(*byte - b'a' + 10),
                b'A'..=b'F' => u16::from(*byte - b'A' + 10),
                _ => return Err(ConsultationWireError::InvalidBody),
            };
            value = (value << 4) | digit;
        }
        self.position = end;
        Ok(value)
    }
}

fn parse_consultation_body_strict(
    body: &[u8],
) -> Result<ParsedSingleStringInput, ConsultationWireError> {
    ClosedConsultationJson::new(body).parse()
}

/// Parse only the fixed route key. The service must authenticate first and
/// resolve this key against the workload-visible registry before parsing a
/// subject-bearing body.
pub(crate) fn parse_consultation_key(
    profile_id: &str,
    profile_version: &str,
) -> Result<ConsultationKey, ConsultationWireError> {
    ConsultationKey::try_parse(profile_id, profile_version)
        .map_err(|_| ConsultationWireError::InvalidProfilePath)
}

/// Strictly parse and retain only the three declared execute headers after
/// exact Notary authentication and workload-visible profile resolution. The
/// ambient header map can then be dropped before any body or backend await.
fn parse_execute_headers(
    _resolved_profile: &ResolvedConsultationProfile,
    _notary_workload: &AuthenticatedNotaryWorkload<'_>,
    headers: &HeaderMap,
) -> Result<ParsedConsultationHeaders, ConsultationWireError> {
    let content_type = exactly_one_header(
        headers,
        header::CONTENT_TYPE.as_str(),
        ConsultationWireError::MissingContentType,
        ConsultationWireError::DuplicateContentType,
    )?;
    if !content_type.eq_ignore_ascii_case(JSON_MEDIA_TYPE) {
        return Err(ConsultationWireError::UnsupportedContentType);
    }

    let purpose = exactly_one_header(
        headers,
        DATA_PURPOSE_HEADER,
        ConsultationWireError::MissingPurpose,
        ConsultationWireError::DuplicatePurpose,
    )?;
    let purpose =
        ParsedPurpose::try_parse(purpose).map_err(|_| ConsultationWireError::InvalidPurpose)?;

    let notary_evaluation_id = optional_header(
        headers,
        NOTARY_EVALUATION_ID_HEADER,
        ConsultationWireError::DuplicateNotaryEvaluationId,
    )?
    .map(|value| {
        NotaryEvaluationId::try_parse(value)
            .map_err(|_| ConsultationWireError::InvalidNotaryEvaluationId)
    })
    .transpose()?;

    Ok(ParsedConsultationHeaders {
        purpose,
        notary_evaluation_id,
    })
}

/// Decode the subject-bearing body under its zeroizing owner after all ambient
/// headers have been discarded. Both non-forgeable service capabilities remain
/// required at this second boundary.
fn parse_execute_body(
    _resolved_profile: &ResolvedConsultationProfile,
    _notary_workload: &AuthenticatedNotaryWorkload<'_>,
    headers: ParsedConsultationHeaders,
    body: ConsultationRequestBody,
) -> Result<ParsedConsultationEnvelope, ConsultationWireError> {
    let ParsedConsultationHeaders {
        purpose,
        notary_evaluation_id,
    } = headers;

    let input = parse_consultation_body_strict(body.as_slice())?;

    Ok(ParsedConsultationEnvelope {
        purpose,
        input,
        notary_evaluation_id,
    })
}

fn exactly_one_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
    missing: ConsultationWireError,
    duplicate: ConsultationWireError,
) -> Result<&'a str, ConsultationWireError> {
    let mut values = headers.get_all(name).iter();
    let first = values.next().ok_or(missing)?;
    if values.next().is_some() {
        return Err(duplicate);
    }
    first.to_str().map_err(|_| match name {
        DATA_PURPOSE_HEADER => ConsultationWireError::InvalidPurpose,
        NOTARY_EVALUATION_ID_HEADER => ConsultationWireError::InvalidNotaryEvaluationId,
        _ => ConsultationWireError::UnsupportedContentType,
    })
}

fn optional_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
    duplicate: ConsultationWireError,
) -> Result<Option<&'a str>, ConsultationWireError> {
    let mut values = headers.get_all(name).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(duplicate);
    }
    first
        .to_str()
        .map(Some)
        .map_err(|_| ConsultationWireError::InvalidNotaryEvaluationId)
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use axum::body::to_bytes;
    use axum::http::{HeaderValue, Method, Request, StatusCode};
    use axum::response::IntoResponse;
    use bytes::Bytes;
    use futures::stream;
    use proptest::prelude::*;
    use serde_json::{json, Value};
    use tower::ServiceExt;

    use super::*;
    use crate::auth::{AuthMode, Principal, ScopeSet};

    const EVALUATION_ID: &str = "01JYZZZZZZZZZZZZZZZZZZZZZZ";

    fn headers() -> HeaderMap {
        HeaderMap::from_iter([
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (
                header::HeaderName::from_static(DATA_PURPOSE_HEADER),
                HeaderValue::from_static("benefit-verification"),
            ),
        ])
    }

    fn body() -> &'static [u8] {
        br#"{"inputs":{"subject_id":"12345"}}"#
    }

    fn resolved_profile() -> ResolvedConsultationProfile {
        let plan = crate::source_plan::bounded_runtime_vector_plan_fixture();
        ResolvedConsultationProfile::for_wire_test(&plan)
    }

    fn notary_workload() -> AuthenticatedNotaryWorkload<'static> {
        AuthenticatedNotaryWorkload::for_wire_test()
    }

    fn route_app() -> Router {
        let authentication = AuthenticationResult::api_key(Principal {
            principal_id: "route-test-caller".to_string(),
            scopes: ScopeSet::from_iter(["registry:consult"]),
            auth_mode: AuthMode::ApiKey,
        })
        .expect("consistent test authentication");
        router::<()>().layer(Extension(authentication))
    }

    async fn route_request(method: Method, uri: &str, body: Body) -> Response {
        route_app()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(body)
                    .expect("route request builds"),
            )
            .await
            .expect("route responds")
    }

    async fn response_code(response: Response) -> String {
        let body = to_bytes(response.into_body(), 8 * 1024)
            .await
            .expect("bounded problem body");
        serde_json::from_slice::<Value>(&body).expect("problem JSON")["code"]
            .as_str()
            .expect("stable problem code")
            .to_string()
    }

    fn parse_envelope(
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<ParsedConsultationEnvelope, ConsultationWireError> {
        let resolved = resolved_profile();
        let workload = notary_workload();
        let headers = parse_execute_headers(&resolved, &workload, headers)?;
        let body = ConsultationRequestBody::try_from_owned(body.to_vec())?;
        parse_execute_body(&resolved, &workload, headers, body)
    }

    #[tokio::test]
    async fn request_body_streams_chunks_into_one_bounded_zeroizing_owner() {
        let resolved = resolved_profile();
        let workload = notary_workload();
        let streamed = Body::from_stream(stream::iter([
            Ok::<_, Infallible>(Bytes::from_static(br#"{"inputs":{"subject_"#)),
            Ok(Bytes::from_static(br#"id":"12345"}}"#)),
        ]));
        let retained = ConsultationRequestBody::read_from(&resolved, &workload, streamed)
            .await
            .expect("bounded chunks are retained");
        assert_eq!(retained.as_slice(), body());
        assert_eq!(retained.0.capacity(), MAX_CONSULTATION_REQUEST_BYTES);
    }

    #[tokio::test]
    async fn request_body_accepts_exactly_eight_kib_without_growing_storage() {
        let resolved = resolved_profile();
        let workload = notary_workload();
        let retained = ConsultationRequestBody::read_from(
            &resolved,
            &workload,
            Body::from(vec![b'x'; MAX_CONSULTATION_REQUEST_BYTES]),
        )
        .await
        .expect("the exact request cap is accepted");
        assert_eq!(retained.as_slice().len(), MAX_CONSULTATION_REQUEST_BYTES);
        assert_eq!(retained.0.capacity(), MAX_CONSULTATION_REQUEST_BYTES);
    }

    #[tokio::test]
    async fn request_body_rejects_chunk_overflow_before_storage_growth() {
        let resolved = resolved_profile();
        let workload = notary_workload();
        let oversized = Body::from_stream(stream::iter([
            Ok::<_, Infallible>(Bytes::from(vec![b'x'; MAX_CONSULTATION_REQUEST_BYTES])),
            Ok(Bytes::from_static(b"x")),
        ]));
        assert_eq!(
            ConsultationRequestBody::read_from(&resolved, &workload, oversized)
                .await
                .err(),
            Some(ConsultationWireError::BodyTooLarge)
        );
    }

    #[tokio::test]
    async fn request_body_collapses_transport_errors_without_retaining_values() {
        let resolved = resolved_profile();
        let workload = notary_workload();
        let failed = Body::from_stream(stream::iter([
            Ok::<_, std::io::Error>(Bytes::from_static(b"partial-subject")),
            Err(std::io::Error::other("transport detail must not escape")),
        ]));
        assert_eq!(
            ConsultationRequestBody::read_from(&resolved, &workload, failed)
                .await
                .err(),
            Some(ConsultationWireError::InvalidBody)
        );
    }

    #[tokio::test]
    async fn router_exposes_only_the_exact_get_and_post_paths() {
        const PROFILE: &str = "/v1/consultations/synthetic.person-status.exact/versions/1";
        const EXECUTE: &str = "/v1/consultations/synthetic.person-status.exact/versions/1/execute";

        // The handlers are reached for exactly the contracted operations. This
        // test router deliberately has no service runtime, so both fail closed.
        assert_eq!(
            route_request(Method::GET, PROFILE, Body::empty())
                .await
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            route_request(Method::POST, EXECUTE, Body::empty())
                .await
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        for (method, uri, allowed) in [
            (Method::HEAD, PROFILE, "GET"),
            (Method::POST, PROFILE, "GET"),
            (Method::GET, EXECUTE, "POST"),
            (Method::PUT, EXECUTE, "POST"),
        ] {
            let response = route_request(method, uri, Body::empty()).await;
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(response.headers().get(header::ALLOW).unwrap(), allowed);
        }
        for uri in [
            "/v1/consultations",
            "/v1/consultations/synthetic.person-status.exact/versions/1/status",
            "/v1/consultations/synthetic.person-status.exact/execute",
            "/v1/consultations/synthetic.person-status.exact/versions/1/",
        ] {
            assert_eq!(
                route_request(Method::GET, uri, Body::empty())
                    .await
                    .status(),
                StatusCode::NOT_FOUND
            );
        }
        for uri in [
            "/v1/consultations/%73ynthetic.person-status.exact/versions/1",
            "/v1/consultations/synthetic%2Fperson-status.exact/versions/1",
            "/v1/consultations/%FF/versions/1",
            "/v1/consultations/synthetic.person-status.exact/versions/1?view=summary",
        ] {
            let response = route_request(Method::GET, uri, Body::empty()).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert_eq!(
                response_code(response).await,
                "consultation.profile_not_found"
            );
        }
    }

    #[tokio::test]
    async fn route_rejects_invalid_profile_before_polling_the_subject_body() {
        let polled = Arc::new(AtomicBool::new(false));
        let body_polled = Arc::clone(&polled);
        let body = Body::from_stream(stream::once(async move {
            body_polled.store(true, Ordering::SeqCst);
            Ok::<_, Infallible>(Bytes::from_static(b"must-not-be-polled"))
        }));
        let response = route_request(
            Method::POST,
            "/v1/consultations/Invalid.Profile/versions/01/execute",
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response_code(response).await,
            "consultation.profile_not_found"
        );
        assert!(!polled.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn route_resolves_the_service_before_polling_the_subject_body() {
        let polled = Arc::new(AtomicBool::new(false));
        let body_polled = Arc::clone(&polled);
        let body = Body::from_stream(stream::once(async move {
            body_polled.store(true, Ordering::SeqCst);
            Ok::<_, Infallible>(Bytes::from_static(b"must-not-be-polled"))
        }));
        let response = route_request(
            Method::POST,
            "/v1/consultations/synthetic.person-status.exact/versions/1/execute",
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response_code(response).await, "consultation.unavailable");
        assert!(!polled.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn service_failures_collapse_to_the_frozen_public_taxonomy() {
        for (service_error, status, code) in [
            (
                ConsultationServiceError::InvalidCredentials,
                StatusCode::UNAUTHORIZED,
                "auth.invalid_credentials",
            ),
            (
                ConsultationServiceError::Denied,
                StatusCode::FORBIDDEN,
                "consultation.denied",
            ),
            (
                ConsultationServiceError::ProfileNotFound,
                StatusCode::NOT_FOUND,
                "consultation.profile_not_found",
            ),
            (
                ConsultationServiceError::InvalidRequest,
                StatusCode::BAD_REQUEST,
                "consultation.invalid_request",
            ),
            (
                ConsultationServiceError::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "consultation.unavailable",
            ),
        ] {
            let response = service_error_response(service_error);
            assert_eq!(response.status(), status);
            assert_eq!(response_code(response).await, code);
        }
    }

    #[tokio::test]
    async fn quota_denial_has_one_bounded_integer_retry_after_header() {
        for (candidate, expected) in [(0, "1"), (1, "1"), (60, "60"), (u64::from(u8::MAX), "60")] {
            let response =
                consultation_error_response(ConsultationError::RateLimited, Some(candidate));
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(
                response
                    .headers()
                    .get_all(header::RETRY_AFTER)
                    .iter()
                    .count(),
                1
            );
            assert_eq!(
                response.headers().get(header::RETRY_AFTER).unwrap(),
                expected
            );
            assert_eq!(response_code(response).await, "consultation.rate_limited");
        }
    }

    #[test]
    fn route_key_parser_does_not_normalize_or_echo_invalid_paths() {
        let key = parse_consultation_key("example.person-status.exact", "1").unwrap();
        assert_eq!(key.id().as_str(), "example.person-status.exact");
        assert_eq!(key.version().get(), 1);
        assert_eq!(
            parse_consultation_key("Example.person-status", "01"),
            Err(ConsultationWireError::InvalidProfilePath)
        );
        assert_eq!(
            ConsultationWireError::InvalidProfilePath.public_error(),
            ConsultationError::ProfileNotFound
        );
    }

    #[test]
    fn envelope_accepts_only_the_closed_single_string_shape() {
        let parsed = parse_envelope(&headers(), body()).unwrap();
        assert_eq!(parsed.purpose().as_str(), "benefit-verification");
        assert_eq!(parsed.input().name(), "subject_id");
        assert_eq!(parsed.input().value_for_internal_use(), "12345");
        assert_eq!(parsed.notary_evaluation_id(), None);

        let escaped = parse_envelope(
            &headers(),
            br#"{"\u0069nputs":{"subj\u0065ct_id":"12\u003345"}}"#,
        )
        .unwrap();
        assert_eq!(escaped.input().name(), "subject_id");
        assert_eq!(escaped.input().value_for_internal_use(), "12345");

        let surrogate_pair = parse_envelope(
            &headers(),
            br#"{"inputs":{"subject_id":"id-\uD83D\uDE00"}}"#,
        )
        .unwrap();
        assert_eq!(surrogate_pair.input().value_for_internal_use(), "id-😀");

        for invalid in [
            br#"{}"#.as_slice(),
            br#"[]"#,
            br#"{"inputs":{}}"#,
            br#"{"inputs":{"subject_id":null}}"#,
            br#"{"inputs":{"subject_id":12345}}"#,
            br#"{"inputs":{"subject_id":["12345"]}}"#,
            br#"{"inputs":{"subject_id":{"value":"12345"}}}"#,
            br#"{"inputs":{"subject_id":""}}"#,
            br#"{"inputs":{"subject_id":"123\u000045"}}"#,
            br#"{"inputs":{"subject_id":"\uD83D"}}"#,
            br#"{"inputs":{"subject_id":"\uDE00"}}"#,
            br#"{"inputs":{"subject_id":"\uD83D\u0041"}}"#,
            br#"{"inputs":{"subject_id":"\uZZZZ"}}"#,
            br#"{"inputs":{"subject_id":"\x41"}}"#,
            br#"{"inputs":{"subject-id":"12345"}}"#,
            br#"{"inputs":{"subject_id":"12345","other":"x"}}"#,
            br#"{"inputs":{"subject_id":"12345"},"other":true}"#,
        ] {
            assert_eq!(
                parse_envelope(&headers(), invalid).err(),
                Some(ConsultationWireError::InvalidBody)
            );
        }
    }

    #[test]
    fn closed_decoder_rejects_duplicates_nonstrings_and_invalid_utf8() {
        for invalid in [
            br#"{"inputs":{"subject_id":"first","subject_id":"second"}}"#.as_slice(),
            br#"{"inputs":{"subject_id":"first","subj\u0065ct_id":"second"}}"#,
            br#"{"inputs":{"subject_id":"12345"},"inputs":{"subject_id":"other"}}"#,
            br#"{"inputs":{"subject_id":"12345"},"n":9007199254740993}"#,
            b"{\"inputs\":{\"subject_id\":\"\xff\"}}",
        ] {
            assert_eq!(
                parse_envelope(&headers(), invalid).err(),
                Some(ConsultationWireError::InvalidBody)
            );
        }
    }

    #[test]
    fn body_and_subject_bounds_apply_after_capability_gates_before_json_decoding() {
        let oversized_body = vec![b' '; MAX_CONSULTATION_REQUEST_BYTES + 1];
        assert_eq!(
            parse_envelope(&headers(), &oversized_body).err(),
            Some(ConsultationWireError::BodyTooLarge)
        );

        let max_subject = "x".repeat(256);
        let accepted = serde_json::to_vec(&json!({"inputs": {"subject_id": max_subject}})).unwrap();
        assert!(parse_envelope(&headers(), &accepted).is_ok());

        let too_long = "x".repeat(257);
        let rejected = serde_json::to_vec(&json!({"inputs": {"subject_id": too_long}})).unwrap();
        assert_eq!(
            parse_envelope(&headers(), &rejected).err(),
            Some(ConsultationWireError::InvalidBody)
        );

        let unicode_max = "é".repeat(128);
        let accepted = serde_json::to_vec(&json!({"inputs": {"subject_id": unicode_max}})).unwrap();
        assert!(parse_envelope(&headers(), &accepted).is_ok());
        let unicode_too_long = "é".repeat(129);
        let rejected =
            serde_json::to_vec(&json!({"inputs": {"subject_id": unicode_too_long}})).unwrap();
        assert_eq!(
            parse_envelope(&headers(), &rejected).err(),
            Some(ConsultationWireError::InvalidBody)
        );

        let mut exact_body = body().to_vec();
        exact_body.resize(MAX_CONSULTATION_REQUEST_BYTES, b' ');
        assert!(parse_envelope(&headers(), &exact_body).is_ok());

        let escaped_max = "\\u0078".repeat(ParsedSingleStringInput::MAX_VALUE_BYTES);
        let encoded = format!(r#"{{"inputs":{{"subject_id":"{escaped_max}"}}}}"#);
        let parsed = parse_envelope(&headers(), encoded.as_bytes()).unwrap();
        assert_eq!(
            parsed.input().value_for_internal_use().len(),
            ParsedSingleStringInput::MAX_VALUE_BYTES
        );
        let escaped_too_long = "\\u0078".repeat(ParsedSingleStringInput::MAX_VALUE_BYTES + 1);
        let encoded = format!(r#"{{"inputs":{{"subject_id":"{escaped_too_long}"}}}}"#);
        assert_eq!(
            parse_envelope(&headers(), encoded.as_bytes()).err(),
            Some(ConsultationWireError::InvalidBody)
        );
    }

    #[test]
    fn content_type_and_purpose_are_exactly_once() {
        let mut missing_content_type = headers();
        missing_content_type.remove(header::CONTENT_TYPE);
        assert_eq!(
            parse_envelope(&missing_content_type, body()).err(),
            Some(ConsultationWireError::MissingContentType)
        );

        let mut duplicate_content_type = headers();
        duplicate_content_type.append(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        assert_eq!(
            parse_envelope(&duplicate_content_type, body()).err(),
            Some(ConsultationWireError::DuplicateContentType)
        );

        for unsupported in ["text/json", "application/json; charset=utf-8"] {
            let mut candidate = headers();
            candidate.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_str(unsupported).unwrap(),
            );
            assert_eq!(
                parse_envelope(&candidate, body()).err(),
                Some(ConsultationWireError::UnsupportedContentType)
            );
        }

        let mut missing_purpose = headers();
        missing_purpose.remove(DATA_PURPOSE_HEADER);
        assert_eq!(
            parse_envelope(&missing_purpose, body()).err(),
            Some(ConsultationWireError::MissingPurpose)
        );

        let mut duplicate_purpose = headers();
        duplicate_purpose.append(
            header::HeaderName::from_static(DATA_PURPOSE_HEADER),
            HeaderValue::from_static("another-purpose"),
        );
        assert_eq!(
            parse_envelope(&duplicate_purpose, body()).err(),
            Some(ConsultationWireError::DuplicatePurpose)
        );

        let mut malformed_purpose = headers();
        malformed_purpose.insert(
            header::HeaderName::from_static(DATA_PURPOSE_HEADER),
            HeaderValue::from_static("benefit verification"),
        );
        assert_eq!(
            parse_envelope(&malformed_purpose, body()).err(),
            Some(ConsultationWireError::InvalidPurpose)
        );

        let mut non_utf8_purpose = headers();
        non_utf8_purpose.insert(
            header::HeaderName::from_static(DATA_PURPOSE_HEADER),
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        assert_eq!(
            parse_envelope(&non_utf8_purpose, body()).err(),
            Some(ConsultationWireError::InvalidPurpose)
        );

        for coalesced in [
            "benefit-verification,other-purpose",
            "benefit-verification, other-purpose",
        ] {
            let mut coalesced_purpose = headers();
            coalesced_purpose.insert(
                header::HeaderName::from_static(DATA_PURPOSE_HEADER),
                HeaderValue::from_str(coalesced).unwrap(),
            );
            assert_eq!(
                parse_envelope(&coalesced_purpose, body()).err(),
                Some(ConsultationWireError::InvalidPurpose)
            );
        }
    }

    #[test]
    fn authenticated_notary_evaluation_id_is_optional_exactly_once_and_canonical() {
        let mut candidate = headers();
        candidate.insert(
            header::HeaderName::from_static(NOTARY_EVALUATION_ID_HEADER),
            HeaderValue::from_static(EVALUATION_ID),
        );
        let parsed = parse_envelope(&candidate, body()).unwrap();
        assert_eq!(
            parsed
                .notary_evaluation_id()
                .expect("typed evaluation id")
                .to_canonical_string(),
            EVALUATION_ID
        );

        candidate.append(
            header::HeaderName::from_static(NOTARY_EVALUATION_ID_HEADER),
            HeaderValue::from_static(EVALUATION_ID),
        );
        assert_eq!(
            parse_envelope(&candidate, body()).err(),
            Some(ConsultationWireError::DuplicateNotaryEvaluationId)
        );

        let mut malformed = headers();
        malformed.insert(
            header::HeaderName::from_static(NOTARY_EVALUATION_ID_HEADER),
            HeaderValue::from_static("01jyzzzzzzzzzzzzzzzzzzzzzz"),
        );
        assert_eq!(
            parse_envelope(&malformed, body()).err(),
            Some(ConsultationWireError::InvalidNotaryEvaluationId)
        );
    }

    #[test]
    fn every_parser_failure_collapses_to_one_of_the_frozen_public_errors() {
        let cases = [
            ConsultationWireError::InvalidProfilePath,
            ConsultationWireError::MissingPurpose,
            ConsultationWireError::DuplicatePurpose,
            ConsultationWireError::InvalidPurpose,
            ConsultationWireError::MissingContentType,
            ConsultationWireError::DuplicateContentType,
            ConsultationWireError::UnsupportedContentType,
            ConsultationWireError::BodyTooLarge,
            ConsultationWireError::InvalidBody,
            ConsultationWireError::DuplicateNotaryEvaluationId,
            ConsultationWireError::InvalidNotaryEvaluationId,
        ];
        for error in cases {
            let expected = if error == ConsultationWireError::InvalidProfilePath {
                ConsultationError::ProfileNotFound
            } else {
                ConsultationError::InvalidRequest
            };
            assert_eq!(error.public_error(), expected);
        }
    }

    #[test]
    fn consultation_problem_taxonomy_matches_the_frozen_statuses_and_codes() {
        let cases = [
            (
                ConsultationError::InvalidRequest,
                StatusCode::BAD_REQUEST,
                "consultation.invalid_request",
            ),
            (
                ConsultationError::InvalidCredentials,
                StatusCode::UNAUTHORIZED,
                "auth.invalid_credentials",
            ),
            (
                ConsultationError::Denied,
                StatusCode::FORBIDDEN,
                "consultation.denied",
            ),
            (
                ConsultationError::ProfileNotFound,
                StatusCode::NOT_FOUND,
                "consultation.profile_not_found",
            ),
            (
                ConsultationError::RateLimited,
                StatusCode::TOO_MANY_REQUESTS,
                "consultation.rate_limited",
            ),
            (
                ConsultationError::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "consultation.unavailable",
            ),
        ];

        for (variant, status, code) in cases {
            let error = crate::error::Error::from(variant);
            assert_eq!(error.http_status(), status);
            assert_eq!(error.code(), code);
            assert!(!error.title().is_empty());
            assert!(!error.detail().is_empty());
            assert!(!error.detail().contains("12345"));
        }
    }

    #[tokio::test]
    async fn consultation_problems_render_scrubbed_rfc_9457_json() {
        for variant in [
            ConsultationError::InvalidRequest,
            ConsultationError::InvalidCredentials,
            ConsultationError::Denied,
            ConsultationError::ProfileNotFound,
            ConsultationError::RateLimited,
            ConsultationError::Unavailable,
        ] {
            let expected = crate::error::Error::from(variant);
            let expected_status = expected.http_status();
            let expected_code = expected.code();
            let response = expected.into_response();
            assert_eq!(response.status(), expected_status);
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                "application/problem+json"
            );
            let body = to_bytes(response.into_body(), 8 * 1024).await.unwrap();
            let problem: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(problem["status"], u64::from(expected_status.as_u16()));
            assert_eq!(problem["code"], expected_code);
            assert!(problem["type"]
                .as_str()
                .unwrap()
                .ends_with(&expected_code.replace('.', "/")));
            let encoded = String::from_utf8(body.to_vec()).unwrap();
            assert!(!encoded.contains("12345"));
            assert!(!encoded.contains("source status"));
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn closed_decoder_round_trips_bounded_json_string_encodings(
            value in proptest::collection::vec(any::<char>(), 1..65)
                .prop_map(String::from_iter)
                .prop_filter("bounded non-control subject", |value| {
                    value.len() <= ParsedSingleStringInput::MAX_VALUE_BYTES
                        && value.chars().all(|character| !character.is_control())
                })
        ) {
            let body = serde_json::to_vec(&json!({"inputs": {"subject_id": value}})).unwrap();
            let parsed = parse_envelope(&headers(), &body).unwrap();
            prop_assert_eq!(parsed.input().value_for_internal_use(), value);
        }
    }
}
