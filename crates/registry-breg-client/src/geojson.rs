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
const MAXIMUM_GEOMETRY_POSITIONS: usize = 10_000;

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

/// One strict CRS84 GeoJSON Polygon. Ring order and winding are preserved.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct BRegGeoJsonPolygon {
    #[serde(rename = "type")]
    pub polygon_type: BRegGeoJsonPolygonType,
    pub coordinates: Vec<Vec<[Number; 2]>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum BRegGeoJsonPolygonType {
    Polygon,
}

/// One strict CRS84 GeoJSON MultiPolygon. Part, ring, and winding order are preserved.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct BRegGeoJsonMultiPolygon {
    #[serde(rename = "type")]
    pub multi_polygon_type: BRegGeoJsonMultiPolygonType,
    pub coordinates: Vec<Vec<Vec<[Number; 2]>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum BRegGeoJsonMultiPolygonType {
    MultiPolygon,
}

/// A strict native CRS84 GeoJSON geometry served by BReg.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum BRegGeoJsonGeometry {
    Point(BRegGeoJsonPoint),
    Polygon(BRegGeoJsonPolygon),
    MultiPolygon(BRegGeoJsonMultiPolygon),
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
    pub geometry: Option<BRegGeoJsonGeometry>,
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
            record_type_identifier: "geojson".to_owned(),
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
        value => Some(decode_geometry(value)?),
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
                && value.len() <= crate::query::MAX_SKIPTOKEN_BYTES
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

fn decode_geometry(value: Value) -> Result<BRegGeoJsonGeometry, ()> {
    match value.get("type").and_then(Value::as_str) {
        Some("Point") => decode_point(value).map(BRegGeoJsonGeometry::Point),
        Some("Polygon") => decode_polygon(value).map(BRegGeoJsonGeometry::Polygon),
        Some("MultiPolygon") => decode_multi_polygon(value).map(BRegGeoJsonGeometry::MultiPolygon),
        _ => Err(()),
    }
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

fn decode_polygon(value: Value) -> Result<BRegGeoJsonPolygon, ()> {
    let mut document = object(value)?;
    exact_string(take(&mut document, "type")?, "Polygon")?;
    let mut positions = 0;
    let coordinates =
        decode_polygon_coordinates(take(&mut document, "coordinates")?, &mut positions)?;
    empty(document)?;
    Ok(BRegGeoJsonPolygon {
        polygon_type: BRegGeoJsonPolygonType::Polygon,
        coordinates,
    })
}

fn decode_multi_polygon(value: Value) -> Result<BRegGeoJsonMultiPolygon, ()> {
    let mut document = object(value)?;
    exact_string(take(&mut document, "type")?, "MultiPolygon")?;
    let polygons = match take(&mut document, "coordinates")? {
        Value::Array(polygons) if !polygons.is_empty() => polygons,
        _ => return Err(()),
    };
    let mut positions = 0;
    let coordinates = polygons
        .into_iter()
        .map(|polygon| decode_polygon_coordinates(polygon, &mut positions))
        .collect::<Result<Vec<_>, _>>()?;
    empty(document)?;
    Ok(BRegGeoJsonMultiPolygon {
        multi_polygon_type: BRegGeoJsonMultiPolygonType::MultiPolygon,
        coordinates,
    })
}

fn decode_polygon_coordinates(
    value: Value,
    positions: &mut usize,
) -> Result<Vec<Vec<[Number; 2]>>, ()> {
    let rings = match value {
        Value::Array(rings) if !rings.is_empty() => rings,
        _ => return Err(()),
    };
    rings
        .into_iter()
        .map(|ring| decode_ring(ring, positions))
        .collect()
}

fn decode_ring(value: Value, positions: &mut usize) -> Result<Vec<[Number; 2]>, ()> {
    let values = match value {
        Value::Array(values) if values.len() >= 4 => values,
        _ => return Err(()),
    };
    *positions = positions.checked_add(values.len()).ok_or(())?;
    if *positions > MAXIMUM_GEOMETRY_POSITIONS {
        return Err(());
    }
    let ring = values
        .into_iter()
        .map(decode_position)
        .collect::<Result<Vec<_>, _>>()?;
    if !same_position(&ring[0], ring.last().ok_or(())?)
        || ring
            .windows(2)
            .any(|edge| longitude_delta(&edge[0], &edge[1]) > 180.0)
    {
        return Err(());
    }
    Ok(ring)
}

fn decode_position(value: Value) -> Result<[Number; 2], ()> {
    match value {
        Value::Array(mut values) if values.len() == 2 => {
            let latitude = number(values.pop().ok_or(())?, -90.0, 90.0)?;
            let longitude = number(values.pop().ok_or(())?, -180.0, 180.0)?;
            Ok([longitude, latitude])
        }
        _ => Err(()),
    }
}

fn same_position(left: &[Number; 2], right: &[Number; 2]) -> bool {
    left.iter()
        .zip(right)
        .all(|(left, right)| left.as_f64() == right.as_f64())
}

fn longitude_delta(left: &[Number; 2], right: &[Number; 2]) -> f64 {
    (left[0].as_f64().unwrap_or(f64::INFINITY) - right[0].as_f64().unwrap_or(f64::NEG_INFINITY))
        .abs()
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
    fn collection_cursor_accepts_only_the_bounded_codec_envelope() {
        let document = |token: String| {
            json!({
                "type": "FeatureCollection", "features": [], "numberReturned": 0,
                "registry": {"pageInfo": {"nextCursor": token}}
            })
        };
        let maximum = "A".repeat(crate::query::MAX_SKIPTOKEN_BYTES);
        assert!(decode_collection(document(maximum)).is_ok());
        for invalid in [
            "A".repeat(crate::query::MAX_SKIPTOKEN_BYTES + 1),
            "token\n".to_owned(),
            String::new(),
        ] {
            assert!(decode_collection(document(invalid)).is_err());
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

    #[test]
    fn polygon_and_multipolygon_preserve_tagged_shapes_and_winding() {
        let polygon = json!({
            "type": "Feature",
            "id": "00000000-0000-4000-8000-000000000001",
            "geometry": {
                "type": "Polygon",
                "coordinates": [[
                    [100.125, 13.25], [101, 13.25], [101, 14], [100.125, 13.25]
                ]]
            },
            "properties": {},
            "registry": {"revision": 1}
        });
        let decoded = decode_feature(polygon.clone()).expect("valid polygon");
        assert_eq!(serde_json::to_value(decoded).unwrap(), polygon);

        let multipolygon = json!({
            "type": "Feature",
            "id": "00000000-0000-4000-8000-000000000001",
            "geometry": {
                "type": "MultiPolygon",
                "coordinates": [
                    [[[100, 13], [100, 14], [101, 14], [100, 13]]],
                    [[[102, 15], [103, 15], [103, 16], [102, 15]]]
                ]
            },
            "properties": {},
            "registry": {"revision": 1}
        });
        let decoded = decode_feature(multipolygon.clone()).expect("valid multipolygon");
        assert_eq!(serde_json::to_value(decoded).unwrap(), multipolygon);
    }

    #[test]
    fn polygon_geometry_rejects_invalid_rings_parts_and_edges() {
        let feature = |geometry: Value| {
            json!({
                "type": "Feature",
                "id": "00000000-0000-4000-8000-000000000001",
                "geometry": geometry,
                "properties": {},
                "registry": {"revision": 1}
            })
        };
        for invalid in [
            json!({"type":"Polygon","coordinates":[]}),
            json!({"type":"Polygon","coordinates":[[]]}),
            json!({"type":"Polygon","coordinates":[[[0,0],[1,0],[0,0]]]}),
            json!({"type":"Polygon","coordinates":[[[0,0],[1,0],[1,1],[0,1]]]}),
            json!({"type":"Polygon","coordinates":[[[-170,0],[170,0],[170,1],[-170,0]]]}),
            json!({"type":"MultiPolygon","coordinates":[]}),
            json!({"type":"MultiPolygon","coordinates":[[]]}),
            json!({"type":"MultiPolygon","coordinates":[[[[0,0,1],[1,0],[1,1],[0,0]]]]}),
        ] {
            assert!(decode_feature(feature(invalid)).is_err());
        }
    }
}
