use registry_platform_httpsec::TraceId;
use serde::Serialize;

/// A validated strong Registry Server entity tag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("entity tag is not a strong Registry Server tag")]
pub struct RegistryServerEtagError;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryServerResponseMetadata {
    trace_id: TraceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    etag: Option<RegistryServerEtag>,
}

impl RegistryServerResponseMetadata {
    pub(crate) fn new(trace_id: TraceId, etag: Option<RegistryServerEtag>) -> Self {
        Self { trace_id, etag }
    }

    #[must_use]
    pub fn trace_id(&self) -> &TraceId {
        &self.trace_id
    }

    #[must_use]
    pub fn etag(&self) -> Option<&RegistryServerEtag> {
        self.etag.as_ref()
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
}
