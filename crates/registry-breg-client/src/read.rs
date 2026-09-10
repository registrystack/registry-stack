// SPDX-License-Identifier: Apache-2.0

//! Operation-specific bounded BReg collection reads.

use std::fmt;

use registry_record::{RegistryRecordCollectionResponse, RegistryRecordMeta};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

use crate::{
    BRegContinuation, BRegContinuationProjection, BRegListRequest, BRegRecordFormat,
    BRegRecordOptions, BRegRequestError,
};

const INVALID_AS_OF: &str = "the Base Registry Engine as-of instant must be canonical UTC RFC 3339";
const INVALID_SNAPSHOT: &str = "the Base Registry Engine snapshot reference is invalid";
const INVALID_VALID_AT: &str = "the Base Registry Engine snapshot validity value is invalid";

macro_rules! collection_request {
    ($name:ident) => {
        impl $name {
            /// Set projection, access profile, and Registry Record representation.
            #[must_use]
            pub fn options(mut self, options: BRegRecordOptions) -> Self {
                self.list = self.list.options(options);
                self
            }

            /// Set the requested page size from one through 100.
            pub fn top(mut self, value: u32) -> Result<Self, BRegRequestError> {
                self.list = self.list.top(value)?;
                Ok(self)
            }

            /// Set a bounded opaque BReg filter expression.
            pub fn filter(mut self, value: impl Into<String>) -> Result<Self, BRegRequestError> {
                self.list = self.list.filter(value)?;
                Ok(self)
            }

            /// Set a bounded opaque BReg ordering expression.
            pub fn orderby(mut self, value: impl Into<String>) -> Result<Self, BRegRequestError> {
                self.list = self.list.orderby(value)?;
                Ok(self)
            }

            /// Ask the BReg to include or explicitly omit the collection count.
            #[must_use]
            pub fn count(mut self, value: bool) -> Self {
                self.list = self.list.count(value);
                self
            }

            pub(crate) fn query_pairs(&self) -> Result<Vec<(String, String)>, BRegRequestError> {
                self.list.query_pairs()
            }

            pub(crate) fn format(&self) -> BRegRecordFormat {
                self.list.record_options().format_value()
            }

            pub(crate) fn access_profile(&self) -> Option<&str> {
                self.list.record_options().access_profile_value()
            }
        }
    };
}

/// Scalar first-page facts for the effective-time `:current` collection.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct BRegCurrentListRequest {
    list: BRegListRequest,
}

collection_request!(BRegCurrentListRequest);

impl fmt::Debug for BRegCurrentListRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegCurrentListRequest")
            .field("query", &self.list)
            .finish()
    }
}

/// Scalar first-page facts for the effective-time `:as-of` collection.
#[derive(Clone, PartialEq, Eq)]
pub struct BRegAsOfListRequest {
    as_of: String,
    list: BRegListRequest,
}

impl BRegAsOfListRequest {
    /// Construct a request for one canonical UTC RFC 3339 instant.
    pub fn new(as_of: impl Into<String>) -> Result<Self, BRegRequestError> {
        let as_of = as_of.into();
        validate_as_of(&as_of)?;
        Ok(Self {
            as_of,
            list: BRegListRequest::default(),
        })
    }

    pub(crate) fn as_of(&self) -> &str {
        &self.as_of
    }

    pub(crate) fn as_of_query_pairs(&self) -> Result<Vec<(String, String)>, BRegRequestError> {
        let mut pairs = self.query_pairs()?;
        let position = usize::from(
            pairs
                .first()
                .is_some_and(|(name, _)| name == "accessProfile"),
        );
        pairs.insert(position, ("asOf".into(), self.as_of.clone()));
        crate::query::ensure_query_bound(&pairs)?;
        Ok(pairs)
    }
}

collection_request!(BRegAsOfListRequest);

impl fmt::Debug for BRegAsOfListRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegAsOfListRequest")
            .field("as_of_present", &true)
            .field("query", &self.list)
            .finish()
    }
}

/// Scalar first-page facts for a retained `:snapshot` collection.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct BRegSnapshotListRequest {
    snapshot: Option<String>,
    valid_at: Option<String>,
    list: BRegListRequest,
}

impl BRegSnapshotListRequest {
    /// Reproduce an earlier snapshot. Omit this to capture the latest committed state.
    pub fn snapshot(mut self, value: impl Into<String>) -> Result<Self, BRegRequestError> {
        let value = value.into();
        validate_snapshot_reference(&value)?;
        self.snapshot = Some(value);
        Ok(self)
    }

    /// Apply an effective-time filter inside the selected snapshot.
    ///
    /// The active registry contract determines whether this is a calendar date
    /// or canonical UTC timestamp, so the client performs only bounded syntax
    /// checks before the server applies that configured type.
    pub fn valid_at(mut self, value: impl Into<String>) -> Result<Self, BRegRequestError> {
        let value = value.into();
        validate_bounded_scalar(&value, 1024, INVALID_VALID_AT)?;
        self.valid_at = Some(value);
        Ok(self)
    }

    pub(crate) fn snapshot_query_pairs(&self) -> Result<Vec<(String, String)>, BRegRequestError> {
        let mut pairs = self.query_pairs()?;
        let mut position = usize::from(
            pairs
                .first()
                .is_some_and(|(name, _)| name == "accessProfile"),
        );
        if let Some(value) = &self.snapshot {
            pairs.insert(position, ("snapshot".into(), value.clone()));
            position += 1;
        }
        if let Some(value) = &self.valid_at {
            pairs.insert(position, ("validAt".into(), value.clone()));
        }
        crate::query::ensure_query_bound(&pairs)?;
        Ok(pairs)
    }

    pub(crate) fn requested_snapshot(&self) -> Option<&str> {
        self.snapshot.as_deref()
    }

    pub(crate) fn valid_at_value(&self) -> Option<&str> {
        self.valid_at.as_deref()
    }
}

collection_request!(BRegSnapshotListRequest);

impl fmt::Debug for BRegSnapshotListRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegSnapshotListRequest")
            .field("snapshot_present", &self.snapshot.is_some())
            .field("valid_at_present", &self.valid_at.is_some())
            .field("query", &self.list)
            .finish()
    }
}

/// Scalar first-page facts for one configured relationship path.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct BRegRelationshipListRequest {
    list: BRegListRequest,
}

collection_request!(BRegRelationshipListRequest);

impl fmt::Debug for BRegRelationshipListRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegRelationshipListRequest")
            .field("query", &self.list)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegCurrentPage {
    pub value: RegistryRecordCollectionResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation: Option<BRegCurrentContinuation>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegAsOfPage {
    pub value: RegistryRecordCollectionResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation: Option<BRegAsOfContinuation>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegSnapshotPage {
    pub value: RegistryRecordCollectionResponse,
    pub snapshot: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation: Option<BRegSnapshotContinuation>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegRelationshipPage {
    pub value: RegistryRecordCollectionResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation: Option<BRegRelationshipContinuation>,
}

macro_rules! simple_continuation {
    ($name:ident, $projection:ident) => {
        #[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        pub struct $projection {
            #[serde(flatten)]
            pub collection: BRegContinuationProjection,
        }

        #[derive(Clone, Eq, PartialEq)]
        pub struct $name {
            collection: BRegContinuation,
        }

        impl $name {
            pub(crate) fn try_from_parts(
                route: &str,
                skiptoken: &str,
                format: BRegRecordFormat,
                access_profile: Option<String>,
                meta: &RegistryRecordMeta,
            ) -> Result<Self, BRegRequestError> {
                Ok(Self {
                    collection: BRegContinuation::try_from_parts(
                        route,
                        skiptoken,
                        format,
                        access_profile,
                        meta,
                    )?,
                })
            }

            pub fn try_from_projection(value: $projection) -> Result<Self, BRegRequestError> {
                Ok(Self {
                    collection: BRegContinuation::try_from_projection(value.collection)?,
                })
            }

            #[must_use]
            pub fn projection(&self) -> $projection {
                $projection {
                    collection: self.collection.projection(),
                }
            }

            pub(crate) fn route(&self) -> &str {
                self.collection.route()
            }

            pub(crate) fn format(&self) -> BRegRecordFormat {
                self.collection.format()
            }

            pub(crate) fn access_profile(&self) -> Option<&str> {
                self.collection.access_profile()
            }

            pub(crate) fn query_pairs(&self) -> Result<Vec<(String, String)>, BRegRequestError> {
                self.collection.query_pairs()
            }

            pub(crate) fn matches_meta(&self, meta: &RegistryRecordMeta) -> bool {
                self.collection.matches_meta(meta)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                self.projection().serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                Self::try_from_projection($projection::deserialize(deserializer)?)
                    .map_err(serde::de::Error::custom)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("binding", &"<redacted>")
                    .finish()
            }
        }
    };
}

simple_continuation!(BRegCurrentContinuation, BRegCurrentContinuationProjection);

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BRegAsOfContinuationProjection {
    #[serde(flatten)]
    pub collection: BRegContinuationProjection,
    pub as_of: String,
}

#[derive(Clone, Eq, PartialEq)]
pub struct BRegAsOfContinuation {
    collection: BRegContinuation,
    as_of: String,
}

impl BRegAsOfContinuation {
    pub(crate) fn try_from_parts(
        route: &str,
        skiptoken: &str,
        format: BRegRecordFormat,
        access_profile: Option<String>,
        meta: &RegistryRecordMeta,
        as_of: &str,
    ) -> Result<Self, BRegRequestError> {
        validate_as_of(as_of)?;
        Ok(Self {
            collection: BRegContinuation::try_from_parts(
                route,
                skiptoken,
                format,
                access_profile,
                meta,
            )?,
            as_of: as_of.to_owned(),
        })
    }

    pub fn try_from_projection(
        value: BRegAsOfContinuationProjection,
    ) -> Result<Self, BRegRequestError> {
        validate_as_of(&value.as_of)?;
        Ok(Self {
            collection: BRegContinuation::try_from_projection(value.collection)?,
            as_of: value.as_of,
        })
    }

    #[must_use]
    pub fn projection(&self) -> BRegAsOfContinuationProjection {
        BRegAsOfContinuationProjection {
            collection: self.collection.projection(),
            as_of: self.as_of.clone(),
        }
    }

    pub(crate) fn route(&self) -> &str {
        self.collection.route()
    }
    pub(crate) fn format(&self) -> BRegRecordFormat {
        self.collection.format()
    }
    pub(crate) fn access_profile(&self) -> Option<&str> {
        self.collection.access_profile()
    }
    pub(crate) fn query_pairs(&self) -> Result<Vec<(String, String)>, BRegRequestError> {
        self.collection.query_pairs()
    }
    pub(crate) fn matches_meta(&self, meta: &RegistryRecordMeta) -> bool {
        self.collection.matches_meta(meta)
    }
    pub(crate) fn as_of(&self) -> &str {
        &self.as_of
    }
}

impl Serialize for BRegAsOfContinuation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.projection().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BRegAsOfContinuation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::try_from_projection(BRegAsOfContinuationProjection::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for BRegAsOfContinuation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegAsOfContinuation")
            .field("binding", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BRegSnapshotContinuationProjection {
    #[serde(flatten)]
    pub collection: BRegContinuationProjection,
    pub snapshot: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_at: Option<String>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct BRegSnapshotContinuation {
    collection: BRegContinuation,
    snapshot: String,
    valid_at: Option<String>,
}

impl BRegSnapshotContinuation {
    pub(crate) fn try_from_parts(
        route: &str,
        skiptoken: &str,
        format: BRegRecordFormat,
        access_profile: Option<String>,
        meta: &RegistryRecordMeta,
        snapshot: &str,
        valid_at: Option<&str>,
    ) -> Result<Self, BRegRequestError> {
        validate_snapshot_reference(snapshot)?;
        if let Some(value) = valid_at {
            validate_bounded_scalar(value, 1024, INVALID_VALID_AT)?;
        }
        Ok(Self {
            collection: BRegContinuation::try_from_parts(
                route,
                skiptoken,
                format,
                access_profile,
                meta,
            )?,
            snapshot: snapshot.to_owned(),
            valid_at: valid_at.map(str::to_owned),
        })
    }

    pub fn try_from_projection(
        value: BRegSnapshotContinuationProjection,
    ) -> Result<Self, BRegRequestError> {
        validate_snapshot_reference(&value.snapshot)?;
        if let Some(valid_at) = &value.valid_at {
            validate_bounded_scalar(valid_at, 1024, INVALID_VALID_AT)?;
        }
        Ok(Self {
            collection: BRegContinuation::try_from_projection(value.collection)?,
            snapshot: value.snapshot,
            valid_at: value.valid_at,
        })
    }

    #[must_use]
    pub fn projection(&self) -> BRegSnapshotContinuationProjection {
        BRegSnapshotContinuationProjection {
            collection: self.collection.projection(),
            snapshot: self.snapshot.clone(),
            valid_at: self.valid_at.clone(),
        }
    }

    pub(crate) fn route(&self) -> &str {
        self.collection.route()
    }
    pub(crate) fn format(&self) -> BRegRecordFormat {
        self.collection.format()
    }
    pub(crate) fn access_profile(&self) -> Option<&str> {
        self.collection.access_profile()
    }
    pub(crate) fn query_pairs(&self) -> Result<Vec<(String, String)>, BRegRequestError> {
        self.collection.query_pairs()
    }
    pub(crate) fn matches_meta(&self, meta: &RegistryRecordMeta) -> bool {
        self.collection.matches_meta(meta)
    }
    pub(crate) fn snapshot(&self) -> &str {
        &self.snapshot
    }
    pub(crate) fn valid_at(&self) -> Option<&str> {
        self.valid_at.as_deref()
    }
}

impl Serialize for BRegSnapshotContinuation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.projection().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BRegSnapshotContinuation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::try_from_projection(BRegSnapshotContinuationProjection::deserialize(
            deserializer,
        )?)
        .map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for BRegSnapshotContinuation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegSnapshotContinuation")
            .field("binding", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BRegRelationshipContinuationProjection {
    #[serde(flatten)]
    pub collection: BRegContinuationProjection,
    pub root_record_identifier: String,
    pub path_route: String,
}

#[derive(Clone, Eq, PartialEq)]
pub struct BRegRelationshipContinuation {
    collection: BRegContinuation,
    root_record_identifier: String,
    path_route: String,
}

impl BRegRelationshipContinuation {
    pub(crate) fn try_from_parts(
        route: &str,
        root_record_identifier: &str,
        path_route: &str,
        skiptoken: &str,
        format: BRegRecordFormat,
        access_profile: Option<String>,
        meta: &RegistryRecordMeta,
    ) -> Result<Self, BRegRequestError> {
        validate_route(path_route)?;
        validate_canonical_uuid(root_record_identifier)?;
        Ok(Self {
            collection: BRegContinuation::try_from_parts(
                route,
                skiptoken,
                format,
                access_profile,
                meta,
            )?,
            root_record_identifier: root_record_identifier.to_owned(),
            path_route: path_route.to_owned(),
        })
    }

    pub fn try_from_projection(
        value: BRegRelationshipContinuationProjection,
    ) -> Result<Self, BRegRequestError> {
        validate_route(&value.path_route)?;
        validate_canonical_uuid(&value.root_record_identifier)?;
        Ok(Self {
            collection: BRegContinuation::try_from_projection(value.collection)?,
            root_record_identifier: value.root_record_identifier,
            path_route: value.path_route,
        })
    }

    #[must_use]
    pub fn projection(&self) -> BRegRelationshipContinuationProjection {
        BRegRelationshipContinuationProjection {
            collection: self.collection.projection(),
            root_record_identifier: self.root_record_identifier.clone(),
            path_route: self.path_route.clone(),
        }
    }

    pub(crate) fn route(&self) -> &str {
        self.collection.route()
    }
    pub(crate) fn format(&self) -> BRegRecordFormat {
        self.collection.format()
    }
    pub(crate) fn access_profile(&self) -> Option<&str> {
        self.collection.access_profile()
    }
    pub(crate) fn query_pairs(&self) -> Result<Vec<(String, String)>, BRegRequestError> {
        self.collection.query_pairs()
    }
    pub(crate) fn matches_meta(&self, meta: &RegistryRecordMeta) -> bool {
        self.collection.matches_meta(meta)
    }
    pub(crate) fn root_record_identifier(&self) -> &str {
        &self.root_record_identifier
    }
    pub(crate) fn path_route(&self) -> &str {
        &self.path_route
    }
}

impl Serialize for BRegRelationshipContinuation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.projection().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BRegRelationshipContinuation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::try_from_projection(BRegRelationshipContinuationProjection::deserialize(
            deserializer,
        )?)
        .map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for BRegRelationshipContinuation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegRelationshipContinuation")
            .field("binding", &"<redacted>")
            .finish()
    }
}

fn validate_as_of(value: &str) -> Result<(), BRegRequestError> {
    let parsed =
        OffsetDateTime::parse(value, &Rfc3339).map_err(|_| BRegRequestError::new(INVALID_AS_OF))?;
    let canonical = parsed
        .format(&Rfc3339)
        .map_err(|_| BRegRequestError::new(INVALID_AS_OF))?;
    if parsed.offset() != UtcOffset::UTC || canonical != value {
        return Err(BRegRequestError::new(INVALID_AS_OF));
    }
    Ok(())
}

fn validate_bounded_scalar(
    value: &str,
    maximum_bytes: usize,
    reason: &'static str,
) -> Result<(), BRegRequestError> {
    if value.is_empty()
        || value.len() > maximum_bytes
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(BRegRequestError::new(reason));
    }
    Ok(())
}

fn validate_snapshot_reference(value: &str) -> Result<(), BRegRequestError> {
    if !value.strip_prefix("breg1_").is_some_and(is_canonical_uuid) {
        return Err(BRegRequestError::new(INVALID_SNAPSHOT));
    }
    Ok(())
}

fn validate_route(value: &str) -> Result<(), BRegRequestError> {
    let projection = BRegContinuationProjection {
        route: value.to_owned(),
        skiptoken: "valid".to_owned(),
        format: BRegRecordFormat::Json,
        access_profile: None,
        registry_identifier: "registry".to_owned(),
        dataset_identifier: "dataset".to_owned(),
        entity_type_identifier: "entity".to_owned(),
    };
    BRegContinuation::try_from_projection(projection).map(|_| ())
}

fn validate_canonical_uuid(value: &str) -> Result<(), BRegRequestError> {
    if !is_canonical_uuid(value) {
        return Err(BRegRequestError::new(
            "the Base Registry Engine relationship root identifier must be a canonical lowercase UUID",
        ));
    }
    Ok(())
}

fn is_canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && uuid::Uuid::parse_str(value).is_ok_and(|identifier| identifier.to_string() == value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn meta() -> RegistryRecordMeta {
        RegistryRecordMeta {
            registry_identifier: "registry".into(),
            dataset_identifier: "dataset".into(),
            entity_type_identifier: "entry".into(),
            extensions: BTreeMap::new(),
        }
    }

    #[test]
    fn as_of_requires_the_servers_canonical_utc_timestamp() {
        assert!(BRegAsOfListRequest::new("2026-09-10T00:00:00Z").is_ok());
        for invalid in [
            "2026-09-10",
            "2026-09-10T00:00:00+00:00",
            "2026-09-10T07:00:00+07:00",
            "2026-09-10t00:00:00z",
        ] {
            assert!(BRegAsOfListRequest::new(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn operation_specific_first_pages_use_the_exact_query_grammar() {
        assert!(BRegSnapshotListRequest::default()
            .snapshot("not-a-snapshot-reference")
            .is_err());
        let current = BRegCurrentListRequest::default()
            .filter("status eq 'active'")
            .unwrap()
            .top(10)
            .unwrap();
        assert_eq!(
            crate::query::breg_encoded_query(&current.query_pairs().unwrap()),
            "$filter=status%20eq%20%27active%27&$top=10"
        );
        let as_of = BRegAsOfListRequest::new("2026-09-10T00:00:00Z")
            .unwrap()
            .count(true);
        assert_eq!(
            crate::query::breg_encoded_query(&as_of.as_of_query_pairs().unwrap()),
            "asOf=2026-09-10T00%3A00%3A00Z&$count=true"
        );
        let snapshot = BRegSnapshotListRequest::default()
            .snapshot("breg1_00000000-0000-4000-8000-000000000001")
            .unwrap()
            .valid_at("2026-09-10")
            .unwrap();
        assert_eq!(
            crate::query::breg_encoded_query(&snapshot.snapshot_query_pairs().unwrap()),
            "snapshot=breg1_00000000-0000-4000-8000-000000000001&validAt=2026-09-10"
        );
    }

    #[test]
    fn snapshot_continuation_retains_history_identity_but_sends_only_the_cursor() {
        let continuation = BRegSnapshotContinuation::try_from_parts(
            "entries",
            "opaque-token",
            BRegRecordFormat::JsonLd,
            Some("reader".into()),
            &meta(),
            "breg1_00000000-0000-4000-8000-000000000001",
            Some("2026-09-10"),
        )
        .unwrap();
        let value = serde_json::to_value(&continuation).unwrap();
        assert_eq!(value["route"], "entries");
        assert_eq!(value["format"], "json-ld");
        assert_eq!(
            value["snapshot"],
            "breg1_00000000-0000-4000-8000-000000000001"
        );
        assert_eq!(value["validAt"], "2026-09-10");
        let restored: BRegSnapshotContinuation = serde_json::from_value(value).unwrap();
        assert_eq!(restored.snapshot(), continuation.snapshot());
        assert_eq!(restored.valid_at(), continuation.valid_at());
        assert_eq!(
            crate::query::breg_encoded_query(&restored.query_pairs().unwrap()),
            "accessProfile=reader&$skiptoken=opaque-token"
        );
    }

    #[test]
    fn relationship_continuation_revalidates_separate_route_id_and_path() {
        let root = "00000000-0000-4000-8000-000000000001";
        assert!(BRegRelationshipContinuation::try_from_parts(
            "entries",
            root,
            "related-items",
            "token",
            BRegRecordFormat::Json,
            None,
            &meta(),
        )
        .is_ok());
        assert!(BRegRelationshipContinuation::try_from_parts(
            "entries/other",
            root,
            "related-items",
            "token",
            BRegRecordFormat::Json,
            None,
            &meta(),
        )
        .is_err());
        assert!(BRegRelationshipContinuation::try_from_parts(
            "entries",
            "not-a-uuid",
            "related-items",
            "token",
            BRegRecordFormat::Json,
            None,
            &meta(),
        )
        .is_err());
    }
}
