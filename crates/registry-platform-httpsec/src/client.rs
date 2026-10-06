//! Strict, client-safe parsing for response correlation and Problem Details.

use http::HeaderMap;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

/// Extract the trace identifier from exactly one canonical W3C Trace Context v0 field.
pub fn response_trace_id(headers: &HeaderMap) -> Result<TraceId, ResponseTraceError> {
    let mut values = headers.get_all("traceparent").iter();
    let value = match (values.next(), values.next()) {
        (None, None) => return Err(ResponseTraceError::Missing),
        (Some(_), Some(_)) => return Err(ResponseTraceError::Duplicate),
        (Some(value), None) => value.to_str().map_err(|_| ResponseTraceError::Invalid)?,
        (None, Some(_)) => unreachable!("a second header value cannot exist without a first"),
    };
    parse_v0_traceparent(value)
        .and_then(|trace_id| TraceId::parse(trace_id).ok())
        .ok_or(ResponseTraceError::Invalid)
}

/// Value-free reason response trace correlation could not be trusted.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResponseTraceError {
    #[error("the response carries no traceparent field")]
    Missing,
    #[error("the response carries more than one traceparent field")]
    Duplicate,
    #[error("the response traceparent is not canonical W3C Trace Context version 0")]
    Invalid,
}

/// A validated canonical W3C Trace Context trace identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct TraceId(String);

impl TraceId {
    pub fn parse(value: &str) -> Result<Self, TraceIdError> {
        if !is_nonzero_lower_hex(value, 32) {
            return Err(TraceIdError);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TraceId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for TraceId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("trace identifier is invalid")]
pub struct TraceIdError;

/// An owned exact-six-member Registry Stack Problem document received by a client.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProblemDocument {
    #[serde(rename = "type")]
    pub type_uri: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub code: String,
    pub trace_id: TraceId,
}

impl ProblemDocument {
    /// Parse a bounded exact-six-member document with a canonical trace identifier.
    pub fn parse_exact(body: &[u8], max_bytes: usize) -> Result<Self, ProblemDocumentError> {
        if body.is_empty() || body.len() > max_bytes {
            return Err(ProblemDocumentError);
        }
        let problem: Self = serde_json::from_slice(body).map_err(|_| ProblemDocumentError)?;
        Ok(problem)
    }

    /// Parse the six required members and one optional bounded `fieldPath`.
    ///
    /// Products that define `fieldPath` must still validate which problem codes
    /// may carry it and the product's closed location grammar. Other products
    /// continue to use [`Self::parse_exact`] and reject the extension.
    pub fn parse_with_field_path(
        body: &[u8],
        max_bytes: usize,
    ) -> Result<(Self, Option<String>), ProblemDocumentError> {
        if body.is_empty() || body.len() > max_bytes {
            return Err(ProblemDocumentError);
        }
        let problem: ProblemDocumentWithFieldPath =
            serde_json::from_slice(body).map_err(|_| ProblemDocumentError)?;
        Ok((
            Self {
                type_uri: problem.type_uri,
                title: problem.title,
                status: problem.status,
                detail: problem.detail,
                code: problem.code,
                trace_id: problem.trace_id,
            },
            problem.field_path,
        ))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProblemDocumentWithFieldPath {
    #[serde(rename = "type")]
    type_uri: String,
    title: String,
    status: u16,
    detail: String,
    code: String,
    trace_id: TraceId,
    #[serde(default, deserialize_with = "deserialize_field_path")]
    field_path: Option<String>,
}

fn deserialize_field_path<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.chars().count() > 256 {
        return Err(serde::de::Error::custom(
            "fieldPath exceeds its character bound",
        ));
    }
    Ok(Some(value))
}

/// Value-free strict Problem parsing failure.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("the response Problem document is not an exact bounded Registry Stack problem")]
pub struct ProblemDocumentError;

fn parse_v0_traceparent(value: &str) -> Option<&str> {
    let mut parts = value.split('-');
    let [version, trace_id, parent_id, flags] =
        [parts.next()?, parts.next()?, parts.next()?, parts.next()?];
    if parts.next().is_some()
        || version != "00"
        || !is_nonzero_lower_hex(trace_id, 32)
        || !is_nonzero_lower_hex(parent_id, 16)
        || !is_lower_hex(flags, 2)
    {
        return None;
    }
    Some(trace_id)
}

fn is_nonzero_lower_hex(value: &str, length: usize) -> bool {
    is_lower_hex(value, length) && value.bytes().any(|byte| byte != b'0')
}

pub(crate) fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;
    use serde_json::json;

    const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
    const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    #[test]
    fn response_trace_requires_exactly_one_canonical_v0_field() {
        let mut headers = HeaderMap::new();
        assert_eq!(
            response_trace_id(&headers),
            Err(ResponseTraceError::Missing)
        );
        headers.append("traceparent", HeaderValue::from_static(TRACEPARENT));
        assert_eq!(response_trace_id(&headers).unwrap().as_str(), TRACE_ID);
        headers.append("traceparent", HeaderValue::from_static(TRACEPARENT));
        assert_eq!(
            response_trace_id(&headers),
            Err(ResponseTraceError::Duplicate)
        );
        let mut malformed = HeaderMap::new();
        malformed.insert(
            "traceparent",
            HeaderValue::from_static("00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01"),
        );
        assert_eq!(
            response_trace_id(&malformed),
            Err(ResponseTraceError::Invalid)
        );
    }

    #[test]
    fn problem_parsing_is_exact_bounded_and_product_owned() {
        let expected = ProblemDocument {
            type_uri: "https://id.example/problems/resource/not-found".to_owned(),
            title: "Resource not found".to_owned(),
            status: 404,
            detail: "the requested resource was not found".to_owned(),
            code: "resource.not_found".to_owned(),
            trace_id: TraceId::parse(TRACE_ID).unwrap(),
        };
        let body = serde_json::to_vec(&json!({
            "type": expected.type_uri, "title": expected.title,
            "status": expected.status, "detail": expected.detail,
            "code": expected.code, "traceId": TRACE_ID,
        }))
        .unwrap();
        let parsed = ProblemDocument::parse_exact(&body, body.len()).unwrap();
        assert_eq!(parsed, expected);
        assert!(ProblemDocument::parse_exact(&body, body.len() - 1).is_err());
        let with_extra = serde_json::to_vec(&json!({
            "type": expected.type_uri, "title": expected.title,
            "status": expected.status, "detail": expected.detail,
            "code": expected.code, "traceId": TRACE_ID, "canary": true,
        }))
        .unwrap();
        assert!(ProblemDocument::parse_exact(&with_extra, 4096).is_err());

        let located = serde_json::to_vec(&json!({
            "type": expected.type_uri, "title": expected.title,
            "status": expected.status, "detail": expected.detail,
            "code": expected.code, "traceId": TRACE_ID,
            "fieldPath": "/input/declaredField",
        }))
        .unwrap();
        assert!(ProblemDocument::parse_exact(&located, 4096).is_err());
        let (document, field_path) =
            ProblemDocument::parse_with_field_path(&located, 4096).unwrap();
        assert_eq!(document, expected);
        assert_eq!(field_path.as_deref(), Some("/input/declaredField"));
        for refused in [
            json!({
                "type": expected.type_uri, "title": expected.title,
                "status": expected.status, "detail": expected.detail,
                "code": expected.code, "traceId": TRACE_ID,
                "fieldPath": null,
            }),
            json!({
                "type": expected.type_uri, "title": expected.title,
                "status": expected.status, "detail": expected.detail,
                "code": expected.code, "traceId": TRACE_ID,
                "fieldPath": "x".repeat(257),
            }),
        ] {
            let refused = serde_json::to_vec(&refused).unwrap();
            assert!(ProblemDocument::parse_with_field_path(&refused, 4096).is_err());
        }
    }
}
