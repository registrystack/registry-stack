// SPDX-License-Identifier: Apache-2.0
//! Closed HTTP wire parsing for consultation v1.
//!
//! This module deliberately does not mount a route or authorize a profile. It
//! gives the later consultation service an order-preserving boundary: bind the
//! authenticated workload, parse and resolve an allowed profile key, then parse
//! this bounded envelope. No raw HTTP request reaches a source backend.

use axum::body::Body;
use axum::http::{header, HeaderMap};
use futures::StreamExt;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::consultation::{
    AuthenticatedNotaryWorkload, ConsultationKey, NotaryEvaluationId, ParsedPurpose,
    ParsedSingleStringInput, ResolvedConsultationProfile,
};
use crate::error::ConsultationError;

/// Hard v1 limit applied before JSON parsing.
pub(crate) const MAX_CONSULTATION_REQUEST_BYTES: usize = 8 * 1024;

const DATA_PURPOSE_HEADER: &str = "data-purpose";
const NOTARY_EVALUATION_ID_HEADER: &str = "registry-notary-evaluation-id";
const JSON_MEDIA_TYPE: &str = "application/json";

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

impl ParsedConsultationEnvelope {
    #[must_use]
    pub(crate) const fn purpose(&self) -> &ParsedPurpose {
        &self.purpose
    }

    #[must_use]
    pub(crate) const fn input(&self) -> &ParsedSingleStringInput {
        &self.input
    }

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

/// Strictly parse the execute headers and body only after exact Notary
/// authentication and workload-visible profile resolution have both produced
/// their non-user-constructible proofs. The body is consumed under a zeroizing
/// owner, and the closed decoder places every decoded key and candidate input
/// string under its own zeroizing owner without a library scratch buffer.
/// Route integration must use [`ConsultationRequestBody::read_from`] to acquire
/// bytes only after these same capabilities exist.
pub(crate) fn parse_execute_envelope(
    _resolved_profile: &ResolvedConsultationProfile,
    _notary_workload: &AuthenticatedNotaryWorkload<'_>,
    headers: &HeaderMap,
    body: ConsultationRequestBody,
) -> Result<ParsedConsultationEnvelope, ConsultationWireError> {
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

    use axum::body::to_bytes;
    use axum::http::{HeaderValue, StatusCode};
    use axum::response::IntoResponse;
    use bytes::Bytes;
    use futures::stream;
    use proptest::prelude::*;
    use serde_json::{json, Value};

    use super::*;

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

    fn parse_envelope(
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<ParsedConsultationEnvelope, ConsultationWireError> {
        let body = ConsultationRequestBody::try_from_owned(body.to_vec())?;
        parse_execute_envelope(&resolved_profile(), &notary_workload(), headers, body)
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
