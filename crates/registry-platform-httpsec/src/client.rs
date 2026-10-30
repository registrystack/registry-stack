//! Strict, client-safe parsing for response correlation and Problem Details.

use std::{collections::BTreeSet, fmt};

use http::HeaderMap;
use serde::{
    de::{MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
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

/// An owned Registry Stack Problem document received by a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProblemDocument {
    pub type_uri: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub code: String,
    pub trace_id: TraceId,
}

impl<'de> Deserialize<'de> for ProblemDocument {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        ProblemDocumentExactWire::deserialize(deserializer)
            .map(ProblemDocumentExactWire::into_document)
    }
}

impl ProblemDocument {
    /// Parse a bounded document with the six required Problem members.
    ///
    /// Additive members are ignored. Duplicate members, including duplicate
    /// additive members, remain invalid.
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
    /// use [`Self::parse_exact`] and ignore it like any other additive member.
    pub fn parse_with_field_path(
        body: &[u8],
        max_bytes: usize,
    ) -> Result<(Self, Option<String>), ProblemDocumentError> {
        if body.is_empty() || body.len() > max_bytes {
            return Err(ProblemDocumentError);
        }
        let problem: ProblemDocumentWire =
            serde_json::from_slice(body).map_err(|_| ProblemDocumentError)?;
        let field_path = problem.field_path.clone();
        Ok((problem.into_document(), field_path))
    }
}

struct ProblemDocumentExactWire {
    type_uri: String,
    title: String,
    status: u16,
    detail: String,
    code: String,
    trace_id: TraceId,
}

impl ProblemDocumentExactWire {
    fn into_document(self) -> ProblemDocument {
        ProblemDocument {
            type_uri: self.type_uri,
            title: self.title,
            status: self.status,
            detail: self.detail,
            code: self.code,
            trace_id: self.trace_id,
        }
    }
}

impl<'de> Deserialize<'de> for ProblemDocumentExactWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ProblemVisitor;

        impl<'de> Visitor<'de> for ProblemVisitor {
            type Value = ProblemDocumentExactWire;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a Registry Stack Problem document")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut seen = BTreeSet::new();
                let mut type_uri = None;
                let mut title = None;
                let mut status = None;
                let mut detail = None;
                let mut code = None;
                let mut trace_id = None;

                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(serde::de::Error::custom("duplicate problem member"));
                    }
                    match key.as_str() {
                        "type" => type_uri = Some(map.next_value()?),
                        "title" => title = Some(map.next_value()?),
                        "status" => status = Some(map.next_value()?),
                        "detail" => detail = Some(map.next_value()?),
                        "code" => code = Some(map.next_value()?),
                        "traceId" => trace_id = Some(map.next_value()?),
                        _ => {
                            map.next_value::<DuplicateSafeIgnoredAny>()?;
                        }
                    }
                }

                Ok(ProblemDocumentExactWire {
                    type_uri: type_uri.ok_or_else(|| serde::de::Error::missing_field("type"))?,
                    title: title.ok_or_else(|| serde::de::Error::missing_field("title"))?,
                    status: status.ok_or_else(|| serde::de::Error::missing_field("status"))?,
                    detail: detail.ok_or_else(|| serde::de::Error::missing_field("detail"))?,
                    code: code.ok_or_else(|| serde::de::Error::missing_field("code"))?,
                    trace_id: trace_id.ok_or_else(|| serde::de::Error::missing_field("traceId"))?,
                })
            }
        }

        deserializer.deserialize_map(ProblemVisitor)
    }
}

struct ProblemDocumentWire {
    type_uri: String,
    title: String,
    status: u16,
    detail: String,
    code: String,
    trace_id: TraceId,
    field_path: Option<String>,
}

impl ProblemDocumentWire {
    fn into_document(self) -> ProblemDocument {
        ProblemDocument {
            type_uri: self.type_uri,
            title: self.title,
            status: self.status,
            detail: self.detail,
            code: self.code,
            trace_id: self.trace_id,
        }
    }
}

impl<'de> Deserialize<'de> for ProblemDocumentWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ProblemVisitor;

        impl<'de> Visitor<'de> for ProblemVisitor {
            type Value = ProblemDocumentWire;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a Registry Stack Problem document")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut seen = BTreeSet::new();
                let mut type_uri = None;
                let mut title = None;
                let mut status = None;
                let mut detail = None;
                let mut code = None;
                let mut trace_id = None;
                let mut field_path = None;

                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(serde::de::Error::custom("duplicate problem member"));
                    }
                    match key.as_str() {
                        "type" => type_uri = Some(map.next_value()?),
                        "title" => title = Some(map.next_value()?),
                        "status" => status = Some(map.next_value()?),
                        "detail" => detail = Some(map.next_value()?),
                        "code" => code = Some(map.next_value()?),
                        "traceId" => trace_id = Some(map.next_value()?),
                        "fieldPath" => {
                            field_path = deserialize_field_path_value(map.next_value()?)?
                        }
                        _ => {
                            map.next_value::<DuplicateSafeIgnoredAny>()?;
                        }
                    }
                }

                Ok(ProblemDocumentWire {
                    type_uri: type_uri.ok_or_else(|| serde::de::Error::missing_field("type"))?,
                    title: title.ok_or_else(|| serde::de::Error::missing_field("title"))?,
                    status: status.ok_or_else(|| serde::de::Error::missing_field("status"))?,
                    detail: detail.ok_or_else(|| serde::de::Error::missing_field("detail"))?,
                    code: code.ok_or_else(|| serde::de::Error::missing_field("code"))?,
                    trace_id: trace_id.ok_or_else(|| serde::de::Error::missing_field("traceId"))?,
                    field_path,
                })
            }
        }

        deserializer.deserialize_map(ProblemVisitor)
    }
}

/// Consume an additive JSON value while retaining duplicate-member rejection
/// inside any nested object it contains.
struct DuplicateSafeIgnoredAny;

impl<'de> Deserialize<'de> for DuplicateSafeIgnoredAny {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IgnoredVisitor;

        impl<'de> Visitor<'de> for IgnoredVisitor {
            type Value = DuplicateSafeIgnoredAny;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a duplicate-safe JSON value")
            }

            fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
                Ok(DuplicateSafeIgnoredAny)
            }

            fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
                Ok(DuplicateSafeIgnoredAny)
            }

            fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
                Ok(DuplicateSafeIgnoredAny)
            }

            fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
                Ok(DuplicateSafeIgnoredAny)
            }

            fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
                Ok(DuplicateSafeIgnoredAny)
            }

            fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
                Ok(DuplicateSafeIgnoredAny)
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(DuplicateSafeIgnoredAny)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(DuplicateSafeIgnoredAny)
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                DuplicateSafeIgnoredAny::deserialize(deserializer)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                while sequence
                    .next_element::<DuplicateSafeIgnoredAny>()?
                    .is_some()
                {}
                Ok(DuplicateSafeIgnoredAny)
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut seen = BTreeSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key) {
                        return Err(serde::de::Error::custom("duplicate additive member"));
                    }
                    map.next_value::<DuplicateSafeIgnoredAny>()?;
                }
                Ok(DuplicateSafeIgnoredAny)
            }
        }

        deserializer.deserialize_any(IgnoredVisitor)
    }
}

fn deserialize_field_path_value<E>(value: String) -> Result<Option<String>, E>
where
    E: serde::de::Error,
{
    if value.chars().count() > 256 {
        return Err(E::custom("fieldPath exceeds its character bound"));
    }
    Ok(Some(value))
}

/// Value-free strict Problem parsing failure.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("the response Problem document is not a bounded Registry Stack problem")]
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
        assert_eq!(
            ProblemDocument::parse_exact(&with_extra, 4096).unwrap(),
            expected
        );

        let duplicate_extra = format!(
            r#"{{"type":"{}","title":"{}","status":{},"detail":"{}","code":"{}","traceId":"{}","canary":true,"canary":false}}"#,
            expected.type_uri,
            expected.title,
            expected.status,
            expected.detail,
            expected.code,
            TRACE_ID,
        );
        assert!(ProblemDocument::parse_exact(duplicate_extra.as_bytes(), 4096).is_err());
        let nested_duplicate_extra = format!(
            r#"{{"type":"{}","title":"{}","status":{},"detail":"{}","code":"{}","traceId":"{}","future":{{"canary":true,"canary":false}}}}"#,
            expected.type_uri,
            expected.title,
            expected.status,
            expected.detail,
            expected.code,
            TRACE_ID,
        );
        assert!(ProblemDocument::parse_exact(nested_duplicate_extra.as_bytes(), 4096).is_err());

        let located = serde_json::to_vec(&json!({
            "type": expected.type_uri, "title": expected.title,
            "status": expected.status, "detail": expected.detail,
            "code": expected.code, "traceId": TRACE_ID,
            "fieldPath": "/input/declaredField",
        }))
        .unwrap();
        assert_eq!(
            ProblemDocument::parse_exact(&located, 4096).unwrap(),
            expected
        );
        for additive_field_path in [
            json!(null),
            json!(42),
            json!({"future": [true, {"nested": "value"}]}),
            json!("x".repeat(257)),
        ] {
            let additive = serde_json::to_vec(&json!({
                "type": expected.type_uri, "title": expected.title,
                "status": expected.status, "detail": expected.detail,
                "code": expected.code, "traceId": TRACE_ID,
                "fieldPath": additive_field_path,
            }))
            .unwrap();
            assert_eq!(
                ProblemDocument::parse_exact(&additive, 4096).unwrap(),
                expected
            );
        }
        let duplicate_field_path = format!(
            r#"{{"type":"{}","title":"{}","status":{},"detail":"{}","code":"{}","traceId":"{}","fieldPath":null,"fieldPath":{{}}}}"#,
            expected.type_uri,
            expected.title,
            expected.status,
            expected.detail,
            expected.code,
            TRACE_ID,
        );
        assert!(ProblemDocument::parse_exact(duplicate_field_path.as_bytes(), 4096).is_err());
        let nested_duplicate_field_path = format!(
            r#"{{"type":"{}","title":"{}","status":{},"detail":"{}","code":"{}","traceId":"{}","fieldPath":{{"future":true,"future":false}}}}"#,
            expected.type_uri,
            expected.title,
            expected.status,
            expected.detail,
            expected.code,
            TRACE_ID,
        );
        assert!(
            ProblemDocument::parse_exact(nested_duplicate_field_path.as_bytes(), 4096).is_err()
        );
        let (document, field_path) =
            ProblemDocument::parse_with_field_path(&located, 4096).unwrap();
        assert_eq!(document, expected);
        assert_eq!(field_path.as_deref(), Some("/input/declaredField"));
        let located_with_extra = serde_json::to_vec(&json!({
            "type": expected.type_uri, "title": expected.title,
            "status": expected.status, "detail": expected.detail,
            "code": expected.code, "traceId": TRACE_ID,
            "fieldPath": "/input/declaredField", "canary": true,
        }))
        .unwrap();
        let (document, field_path) =
            ProblemDocument::parse_with_field_path(&located_with_extra, 4096).unwrap();
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
                "fieldPath": 42,
            }),
            json!({
                "type": expected.type_uri, "title": expected.title,
                "status": expected.status, "detail": expected.detail,
                "code": expected.code, "traceId": TRACE_ID,
                "fieldPath": {"future": true},
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
