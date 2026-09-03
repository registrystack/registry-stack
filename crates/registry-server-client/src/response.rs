use registry_platform_httpsec::TraceId;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistryServerProbeStatus {
    pub status: String,
}

/// A Server artifact or protocol document with a caller-selected representation.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryServerRawDocument {
    media_type: String,
    bytes: Vec<u8>,
}

impl RegistryServerRawDocument {
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

impl fmt::Debug for RegistryServerRawDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryServerRawDocument")
            .field("media_type", &self.media_type)
            .field("body_bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// A validated strong Registry Server entity tag.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RegistryServerEtag(String);

impl RegistryServerEtag {
    pub fn parse(value: &str) -> Result<Self, RegistryServerEtagError> {
        let bytes = value.as_bytes();
        if bytes.len() < 6
            || bytes.len() > 256
            || !value.starts_with("\"rs-")
            || !value.ends_with('"')
            || !bytes[1..bytes.len() - 1]
                .iter()
                .all(|byte| matches!(byte, 0x21 | 0x23..=0x7e))
        {
            return Err(RegistryServerEtagError);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RegistryServerEtag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RegistryServerEtag(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("entity tag is not a strong Registry Server tag")]
pub struct RegistryServerEtagError;

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryServerResponseMetadata {
    trace_id: TraceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    etag: Option<RegistryServerEtag>,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<String>,
}

impl RegistryServerResponseMetadata {
    pub(crate) fn new(trace_id: TraceId, etag: Option<RegistryServerEtag>) -> Self {
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
    pub fn etag(&self) -> Option<&RegistryServerEtag> {
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

impl fmt::Debug for RegistryServerResponseMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryServerResponseMetadata")
            .field("trace_id", &self.trace_id)
            .field("etag", &self.etag.is_some())
            .field("location", &self.location.is_some())
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryServerComplete<T> {
    pub value: T,
    pub metadata: RegistryServerResponseMetadata,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryServerPage<T> {
    pub value: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation: Option<crate::ServerContinuation>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_server_etags_use_the_closed_strong_rs_grammar() {
        for valid in ["\"rs-a\"", "\"rs-record-v1-abcdef012345\""] {
            assert_eq!(RegistryServerEtag::parse(valid).unwrap().as_str(), valid);
        }
        for invalid in [
            "W/\"rs-a\"",
            "\"relay\"",
            "\"rs-\"",
            "\"rs-has space\"",
            "\"rs-has\\\"quote\"",
        ] {
            assert!(RegistryServerEtag::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn mutation_response_facts_are_redacted_from_debug() {
        let etag = RegistryServerEtag::parse("\"rs-sensitive-precondition-canary\"").unwrap();
        assert!(!format!("{etag:?}").contains("sensitive-precondition-canary"));
    }
}
