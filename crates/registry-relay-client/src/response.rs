use std::fmt;

use registry_platform_httpsec::TraceId;
use serde::{Deserialize, Serialize};

use crate::query::validate_access_profile_identifier;
use crate::RecordFormat;

/// A validated strong entity tag over SHA-256 bytes (`"` plus 64 lower hex digits plus `"`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct StrongEtag(String);

impl StrongEtag {
    pub fn parse(value: &str) -> Result<Self, StrongEtagError> {
        let bytes = value.as_bytes();
        if bytes.len() != 66
            || bytes.first() != Some(&b'"')
            || bytes.last() != Some(&b'"')
            || !bytes[1..65]
                .iter()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(StrongEtagError);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("entity tag is not a strong quoted SHA-256 tag")]
pub struct StrongEtagError;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseMetadata {
    trace_id: TraceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    etag: Option<StrongEtag>,
}

impl ResponseMetadata {
    pub(crate) fn new(trace_id: TraceId, etag: Option<StrongEtag>) -> Self {
        Self { trace_id, etag }
    }
    #[must_use]
    pub fn trace_id(&self) -> &TraceId {
        &self.trace_id
    }
    #[must_use]
    pub fn etag(&self) -> Option<&StrongEtag> {
        self.etag.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Complete<T> {
    pub value: T,
    pub metadata: ResponseMetadata,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotModified {
    pub etag: StrongEtag,
    pub trace_id: TraceId,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Conditional<T> {
    Complete(Complete<T>),
    NotModified(NotModified),
}

/// An artifact or protocol document whose shape belongs outside the SDK kernel.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RawDocument {
    media_type: String,
    bytes: Vec<u8>,
}

impl RawDocument {
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

impl fmt::Debug for RawDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawDocument")
            .field("media_type", &self.media_type)
            .field("body_bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CollectionRoute {
    Records { resource: String },
    Search { resource: String, search: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "camelCase")]
pub enum CollectionRouteProjection {
    Records { resource: String },
    Search { resource: String, search: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CollectionContinuationProjection {
    pub route: CollectionRouteProjection,
    pub cursor: String,
    pub format: RecordFormat,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_profile: Option<String>,
}

/// Opaque server cursor plus the caller-selected route representation.
///
/// Only [`crate::RelayClient::continue_collection`] consumes this type. Its
/// internals are deliberately private, preventing callers from mixing a cursor
/// with first-page filters, fields, bbox, page size, or a different route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionContinuation {
    pub(crate) cursor: String,
    pub(crate) route: CollectionRoute,
    pub(crate) format: RecordFormat,
    pub(crate) access_profile: Option<String>,
}

impl CollectionContinuation {
    #[must_use]
    pub fn projection(&self) -> CollectionContinuationProjection {
        CollectionContinuationProjection {
            route: match &self.route {
                CollectionRoute::Records { resource } => CollectionRouteProjection::Records {
                    resource: resource.clone(),
                },
                CollectionRoute::Search { resource, search } => CollectionRouteProjection::Search {
                    resource: resource.clone(),
                    search: search.clone(),
                },
            },
            cursor: self.cursor.clone(),
            format: self.format,
            access_profile: self.access_profile.clone(),
        }
    }

    pub fn try_from_projection(
        value: CollectionContinuationProjection,
    ) -> Result<Self, crate::RelayClientError> {
        validate_cursor(&value.cursor)?;
        let route = match value.route {
            CollectionRouteProjection::Records { resource } => {
                validate_route_identifier(&resource)?;
                CollectionRoute::Records { resource }
            }
            CollectionRouteProjection::Search { resource, search } => {
                validate_route_identifier(&resource)?;
                validate_route_identifier(&search)?;
                CollectionRoute::Search { resource, search }
            }
        };
        if let Some(profile) = &value.access_profile {
            validate_access_profile_identifier(profile)?;
        }
        Ok(Self {
            cursor: value.cursor,
            route,
            format: value.format,
            access_profile: value.access_profile,
        })
    }
}

impl Serialize for CollectionContinuation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.projection().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CollectionContinuation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::try_from_projection(CollectionContinuationProjection::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionPage<T> {
    pub value: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation: Option<CollectionContinuation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceContinuationProjection {
    pub cursor: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceContinuation {
    pub(crate) cursor: String,
}

impl ResourceContinuation {
    #[must_use]
    pub fn cursor(&self) -> &str {
        &self.cursor
    }

    pub fn try_from_cursor(cursor: impl Into<String>) -> Result<Self, crate::RelayClientError> {
        let cursor = cursor.into();
        validate_cursor(&cursor)?;
        Ok(Self { cursor })
    }

    #[must_use]
    pub fn projection(&self) -> ResourceContinuationProjection {
        ResourceContinuationProjection {
            cursor: self.cursor.clone(),
        }
    }

    pub fn try_from_projection(
        value: ResourceContinuationProjection,
    ) -> Result<Self, crate::RelayClientError> {
        Self::try_from_cursor(value.cursor)
    }
}

impl Serialize for ResourceContinuation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.projection().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ResourceContinuation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::try_from_projection(ResourceContinuationProjection::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourcePage<T> {
    pub value: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation: Option<ResourceContinuation>,
}

pub(crate) fn validate_cursor(value: &str) -> Result<(), crate::RelayClientError> {
    if value.is_empty()
        || value.len() > 16 * 1024
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(crate::RelayClientError::invalid_request(
            "the continuation cursor is invalid",
        ));
    }
    Ok(())
}

fn validate_route_identifier(value: &str) -> Result<(), crate::RelayClientError> {
    if value.is_empty()
        || value.len() > 128
        || value.starts_with('-')
        || value.ends_with('-')
        || value.contains("--")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(crate::RelayClientError::invalid_request(
            "a continuation route identifier is invalid",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::CollectionContinuationProjection;
    use serde_json::json;

    #[test]
    fn collection_continuation_projection_rejects_unknown_outer_and_route_members() {
        let valid = json!({
            "route": {"kind": "records", "resource": "people"},
            "cursor": "opaque-cursor",
            "format": "json"
        });
        assert!(serde_json::from_value::<CollectionContinuationProjection>(valid.clone()).is_ok());

        let mut outer = valid.clone();
        outer["unexpected"] = json!(true);
        assert!(serde_json::from_value::<CollectionContinuationProjection>(outer).is_err());

        let mut route = valid;
        route["route"]["unexpected"] = json!(true);
        assert!(serde_json::from_value::<CollectionContinuationProjection>(route).is_err());
    }
}
