// SPDX-License-Identifier: Apache-2.0

//! Strict native GeoJSON response and request types for BReg.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use uuid::Uuid;

use crate::{
    BRegBoundingBox, BRegContinuation, BRegContinuationProjection, BRegListRequest,
    BRegRecordFormat, BRegRecordOptions, BRegRequestError,
};

pub(crate) const GEOJSON_MEDIA_TYPE: &str = "application/geo+json";

/// Projection and authorization options for one native GeoJSON record read.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct BRegGeoJsonOptions {
    options: BRegRecordOptions,
}

impl BRegGeoJsonOptions {
    /// Select a nonempty, bounded set of unique API field names.
    pub fn select(
        mut self,
        fields: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, BRegRequestError> {
        self.options = self.options.select(fields)?;
        Ok(self)
    }

    /// Select one Base Registry Engine access profile.
    pub fn access_profile(mut self, value: impl Into<String>) -> Result<Self, BRegRequestError> {
        self.options = self.options.access_profile(value)?;
        Ok(self)
    }

    pub(crate) fn query_pairs(&self) -> Result<Vec<(String, String)>, BRegRequestError> {
        self.options.ensure_collection_compatible()?;
        let mut pairs = Vec::new();
        self.options.append_query(&mut pairs);
        crate::query::ensure_query_bound(&pairs)?;
        Ok(pairs)
    }
}

impl fmt::Debug for BRegGeoJsonOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegGeoJsonOptions")
            .field("options", &self.options)
            .finish()
    }
}

/// First-page facts for a native direct GeoJSON collection.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct BRegGeoJsonListRequest {
    list: BRegListRequest,
}

impl BRegGeoJsonListRequest {
    #[must_use]
    pub fn options(mut self, options: BRegGeoJsonOptions) -> Self {
        self.list = self.list.options(options.options);
        self
    }

    pub fn top(mut self, value: u32) -> Result<Self, BRegRequestError> {
        self.list = self.list.top(value)?;
        Ok(self)
    }

    pub fn filter(mut self, value: impl Into<String>) -> Result<Self, BRegRequestError> {
        self.list = self.list.filter(value)?;
        Ok(self)
    }

    pub fn orderby(mut self, value: impl Into<String>) -> Result<Self, BRegRequestError> {
        self.list = self.list.orderby(value)?;
        Ok(self)
    }

    #[must_use]
    pub fn count(mut self, value: bool) -> Self {
        self.list = self.list.count(value);
        self
    }

    #[must_use]
    pub fn bbox(mut self, value: BRegBoundingBox) -> Self {
        self.list = self.list.bbox(value);
        self
    }

    pub(crate) fn query_pairs(&self) -> Result<Vec<(String, String)>, BRegRequestError> {
        self.list.query_pairs()
    }

    pub(crate) fn access_profile(&self) -> Option<&str> {
        self.list.record_options().access_profile_value()
    }
}

impl fmt::Debug for BRegGeoJsonListRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegGeoJsonListRequest")
            .field("query", &self.list)
            .finish()
    }
}

/// One strict CRS84 GeoJSON Point.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct BRegGeoJsonPoint {
    #[serde(rename = "type")]
    pub point_type: BRegGeoJsonPointType,
    pub coordinates: [Number; 2],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum BRegGeoJsonPointType {
    Point,
}

/// BReg foreign members attached to one GeoJSON Feature.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BRegGeoJsonFeatureRegistry {
    pub revision: u64,
}

/// One strict native BReg GeoJSON Feature.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct BRegGeoJsonFeature {
    #[serde(rename = "type")]
    pub feature_type: BRegGeoJsonFeatureType,
    pub id: String,
    pub geometry: Option<BRegGeoJsonPoint>,
    pub properties: BTreeMap<String, Value>,
    pub registry: BRegGeoJsonFeatureRegistry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum BRegGeoJsonFeatureType {
    Feature,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegGeoJsonPageInfo {
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegGeoJsonCollectionRegistry {
    pub page_info: BRegGeoJsonPageInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
}

/// One strict native BReg GeoJSON FeatureCollection.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegGeoJsonFeatureCollection {
    #[serde(rename = "type")]
    pub collection_type: BRegGeoJsonFeatureCollectionType,
    pub features: Vec<BRegGeoJsonFeature>,
    pub number_returned: u32,
    pub registry: BRegGeoJsonCollectionRegistry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum BRegGeoJsonFeatureCollectionType {
    FeatureCollection,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegGeoJsonPage {
    pub value: BRegGeoJsonFeatureCollection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation: Option<BRegGeoJsonContinuation>,
}

/// Persistable native GeoJSON continuation facts.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BRegGeoJsonContinuationProjection {
    pub route: String,
    pub skiptoken: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_profile: Option<String>,
}

/// Opaque continuation whose type fixes the native GeoJSON representation.
#[derive(Clone, Eq, PartialEq)]
pub struct BRegGeoJsonContinuation {
    collection: BRegContinuation,
}

impl BRegGeoJsonContinuation {
    pub(crate) fn try_from_parts(
        route: &str,
        skiptoken: &str,
        access_profile: Option<String>,
    ) -> Result<Self, BRegRequestError> {
        Self::try_from_projection(BRegGeoJsonContinuationProjection {
            route: route.to_owned(),
            skiptoken: skiptoken.to_owned(),
            access_profile,
        })
    }

    pub fn try_from_projection(
        value: BRegGeoJsonContinuationProjection,
    ) -> Result<Self, BRegRequestError> {
        let placeholder = BRegContinuationProjection {
            route: value.route,
            skiptoken: value.skiptoken,
            format: BRegRecordFormat::Json,
            access_profile: value.access_profile,
            registry_identifier: "geojson".to_owned(),
            dataset_identifier: "geojson".to_owned(),
            entity_type_identifier: "geojson".to_owned(),
        };
        Ok(Self {
            collection: BRegContinuation::try_from_projection(placeholder)?,
        })
    }

    #[must_use]
    pub fn projection(&self) -> BRegGeoJsonContinuationProjection {
        let projection = self.collection.projection();
        BRegGeoJsonContinuationProjection {
            route: projection.route,
            skiptoken: projection.skiptoken,
            access_profile: projection.access_profile,
        }
    }

    pub(crate) fn route(&self) -> &str {
        self.collection.route()
    }

    pub(crate) fn access_profile(&self) -> Option<&str> {
        self.collection.access_profile()
    }

    pub(crate) fn query_pairs(&self) -> Result<Vec<(String, String)>, BRegRequestError> {
        self.collection.query_pairs()
    }
}

impl Serialize for BRegGeoJsonContinuation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.projection().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BRegGeoJsonContinuation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::try_from_projection(BRegGeoJsonContinuationProjection::deserialize(
            deserializer,
        )?)
        .map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for BRegGeoJsonContinuation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegGeoJsonContinuation")
            .field("binding", &"<redacted>")
            .finish()
    }
}

pub(crate) fn decode_feature(value: Value) -> Result<BRegGeoJsonFeature, ()> {
    let mut document = object(value)?;
    exact_string(take(&mut document, "type")?, "Feature")?;
    let id = string(take(&mut document, "id")?)?;
    if Uuid::parse_str(&id).is_err()
        || Uuid::parse_str(&id).is_ok_and(|value| value.to_string() != id)
    {
        return Err(());
    }
    let geometry = match take(&mut document, "geometry")? {
        Value::Null => None,
        value => Some(decode_point(value)?),
    };
    let properties = object(take(&mut document, "properties")?)?
        .into_iter()
        .collect();
    let mut registry = object(take(&mut document, "registry")?)?;
    let revision = positive_i64(take(&mut registry, "revision")?)?;
    empty(document)?;
    empty(registry)?;
    Ok(BRegGeoJsonFeature {
        feature_type: BRegGeoJsonFeatureType::Feature,
        id,
        geometry,
        properties,
        registry: BRegGeoJsonFeatureRegistry { revision },
    })
}

pub(crate) fn decode_collection(value: Value) -> Result<BRegGeoJsonFeatureCollection, ()> {
    let mut document = object(value)?;
    exact_string(take(&mut document, "type")?, "FeatureCollection")?;
    let features = match take(&mut document, "features")? {
        Value::Array(values) if values.len() <= 100 => values
            .into_iter()
            .map(decode_feature)
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(()),
    };
    let number_returned = positive_or_zero_u32(take(&mut document, "numberReturned")?)?;
    if number_returned as usize != features.len() {
        return Err(());
    }
    let mut registry = object(take(&mut document, "registry")?)?;
    let mut page_info = object(take(&mut registry, "pageInfo")?)?;
    let next_cursor = match take(&mut page_info, "nextCursor")? {
        Value::Null => None,
        Value::String(value)
            if !value.is_empty()
                && value.len() <= 4096
                && !value.bytes().any(|byte| byte.is_ascii_control()) =>
        {
            Some(value)
        }
        _ => return Err(()),
    };
    let count = registry
        .remove("count")
        .map(positive_i64_or_zero)
        .transpose()?;
    empty(document)?;
    empty(page_info)?;
    empty(registry)?;
    Ok(BRegGeoJsonFeatureCollection {
        collection_type: BRegGeoJsonFeatureCollectionType::FeatureCollection,
        features,
        number_returned,
        registry: BRegGeoJsonCollectionRegistry {
            page_info: BRegGeoJsonPageInfo { next_cursor },
            count,
        },
    })
}

fn decode_point(value: Value) -> Result<BRegGeoJsonPoint, ()> {
    let mut document = object(value)?;
    exact_string(take(&mut document, "type")?, "Point")?;
    let coordinates = match take(&mut document, "coordinates")? {
        Value::Array(values) if values.len() == 2 => {
            let mut values = values.into_iter();
            let longitude = number(values.next().ok_or(())?, -180.0, 180.0)?;
            let latitude = number(values.next().ok_or(())?, -90.0, 90.0)?;
            [longitude, latitude]
        }
        _ => return Err(()),
    };
    empty(document)?;
    Ok(BRegGeoJsonPoint {
        point_type: BRegGeoJsonPointType::Point,
        coordinates,
    })
}

fn object(value: Value) -> Result<Map<String, Value>, ()> {
    value.as_object().cloned().ok_or(())
}

fn take(object: &mut Map<String, Value>, name: &str) -> Result<Value, ()> {
    object.remove(name).ok_or(())
}

fn empty(object: Map<String, Value>) -> Result<(), ()> {
    if object.is_empty() {
        Ok(())
    } else {
        Err(())
    }
}

fn string(value: Value) -> Result<String, ()> {
    value.as_str().map(str::to_owned).ok_or(())
}

fn exact_string(value: Value, expected: &str) -> Result<(), ()> {
    if value.as_str() == Some(expected) {
        Ok(())
    } else {
        Err(())
    }
}

fn number(value: Value, minimum: f64, maximum: f64) -> Result<Number, ()> {
    let Value::Number(value) = value else {
        return Err(());
    };
    let numeric = value.as_f64().ok_or(())?;
    if numeric < minimum || numeric > maximum {
        return Err(());
    }
    Ok(value)
}

fn positive_i64(value: Value) -> Result<u64, ()> {
    let value = value.as_u64().ok_or(())?;
    if value == 0 || value > i64::MAX as u64 {
        Err(())
    } else {
        Ok(value)
    }
}

fn positive_i64_or_zero(value: Value) -> Result<u64, ()> {
    let value = value.as_u64().ok_or(())?;
    if value > i64::MAX as u64 {
        Err(())
    } else {
        Ok(value)
    }
}

fn positive_or_zero_u32(value: Value) -> Result<u32, ()> {
    u32::try_from(value.as_u64().ok_or(())?).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn feature_preserves_null_geometry_and_has_no_mutation_metadata() {
        let feature = decode_feature(json!({
            "type": "Feature",
            "id": "00000000-0000-4000-8000-000000000001",
            "geometry": null,
            "properties": {"label": "one"},
            "registry": {"revision": 1}
        }))
        .unwrap();
        assert_eq!(feature.geometry, None);
        assert_eq!(feature.registry.revision, 1);
        let encoded = serde_json::to_value(feature).unwrap();
        assert!(encoded.get("etag").is_none());
        assert!(encoded["geometry"].is_null());
    }

    #[test]
    fn collection_matches_the_real_runtime_envelope_and_bounds() {
        let collection = decode_collection(json!({
            "type": "FeatureCollection",
            "features": [{
                "type": "Feature",
                "id": "00000000-0000-4000-8000-000000000001",
                "geometry": {"type": "Point", "coordinates": [180, -90]},
                "properties": {},
                "registry": {"revision": i64::MAX}
            }],
            "numberReturned": 1,
            "registry": {"pageInfo": {"nextCursor": null}, "count": 1}
        }))
        .unwrap();
        assert_eq!(collection.number_returned, 1);
        assert_eq!(collection.registry.count, Some(1));

        for invalid in [
            json!({
                "type":"FeatureCollection", "features": [], "numberReturned": 1,
                "registry":{"pageInfo":{"nextCursor":null}}
            }),
            json!({
                "type":"FeatureCollection", "features": [], "numberReturned": 0,
                "registry":{"pageInfo":{"nextCursor":""}}
            }),
            json!({
                "type":"FeatureCollection", "features": [], "numberReturned": 0,
                "registry":{"pageInfo":{"nextCursor":null}}, "links": []
            }),
        ] {
            assert!(decode_collection(invalid).is_err());
        }
    }

    #[test]
    fn point_and_revision_boundaries_are_closed() {
        let feature = |longitude: Value, latitude: Value, revision: Value| {
            json!({
                "type": "Feature",
                "id": "00000000-0000-4000-8000-000000000001",
                "geometry": {"type": "Point", "coordinates": [longitude, latitude]},
                "properties": {},
                "registry": {"revision": revision}
            })
        };
        assert!(decode_feature(feature(json!(-180), json!(90), json!(1))).is_ok());
        assert!(decode_feature(feature(json!(-181), json!(0), json!(1))).is_err());
        assert!(decode_feature(feature(json!(0), json!(91), json!(1))).is_err());
        assert!(decode_feature(feature(json!(0), json!(0), json!(0))).is_err());
        assert!(decode_feature(feature(json!(0), json!(0), json!(u64::MAX))).is_err());
    }
}
