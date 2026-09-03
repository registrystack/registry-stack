use registry_platform_httpsec::TraceId;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BRegProbeStatus {
    pub status: String,
}

/// A BReg artifact or protocol document with a caller-selected representation.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegRawDocument {
    media_type: String,
    bytes: Vec<u8>,
}

impl BRegRawDocument {
    pub(crate) fn new(media_type: String, bytes: Vec<u8>) -> Self {
        Self { media_type, bytes }
    }

    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for BRegRawDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegRawDocument")
            .field("media_type", &self.media_type)
            .field("body_bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// A validated strong Base Registry Engine entity tag.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct BRegEtag(String);

impl BRegEtag {
    pub fn parse(value: &str) -> Result<Self, BRegEtagError> {
        let bytes = value.as_bytes();
        if bytes.len() < 8
            || bytes.len() > 256
            || !value.starts_with("\"breg-")
            || !value.ends_with('"')
            || !bytes[1..bytes.len() - 1]
                .iter()
                .all(|byte| matches!(byte, 0x21 | 0x23..=0x7e))
        {
            return Err(BRegEtagError);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for BRegEtag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BRegEtag(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("entity tag is not a strong Base Registry Engine tag")]
pub struct BRegEtagError;

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegResponseMetadata {
    trace_id: TraceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    etag: Option<BRegEtag>,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<String>,
}

impl BRegResponseMetadata {
    pub(crate) fn new(trace_id: TraceId, etag: Option<BRegEtag>) -> Self {
        Self {
            trace_id,
            etag,
            location: None,
        }
    }

    pub(crate) fn with_location(mut self, location: String) -> Self {
        self.location = Some(location);
        self
    }

    #[must_use]
    pub fn trace_id(&self) -> &TraceId {
        &self.trace_id
    }

    #[must_use]
    pub fn etag(&self) -> Option<&BRegEtag> {
        self.etag.as_ref()
    }

    /// Root-relative, inert location returned by a successful create.
    ///
    /// The client validates this value but never follows or resolves it.
    #[must_use]
    pub fn location(&self) -> Option<&str> {
        self.location.as_deref()
    }
}

impl fmt::Debug for BRegResponseMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegResponseMetadata")
            .field("trace_id", &self.trace_id)
            .field("etag", &self.etag.is_some())
            .field("location", &self.location.is_some())
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegComplete<T> {
    pub value: T,
    pub metadata: BRegResponseMetadata,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegPage<T> {
    pub value: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation: Option<crate::BRegContinuation>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breg_etags_use_the_closed_strong_breg_grammar() {
        for valid in ["\"breg-a\"", "\"breg-record-v1-abcdef012345\""] {
            assert_eq!(BRegEtag::parse(valid).unwrap().as_str(), valid);
        }
        for invalid in [
            "W/\"breg-a\"",
            "\"relay\"",
            "\"breg-\"",
            "\"breg-has space\"",
            "\"breg-has\\\"quote\"",
        ] {
            assert!(BRegEtag::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn mutation_response_facts_are_redacted_from_debug() {
        let etag = BRegEtag::parse("\"breg-sensitive-precondition-canary\"").unwrap();
        assert!(!format!("{etag:?}").contains("sensitive-precondition-canary"));
    }
}
