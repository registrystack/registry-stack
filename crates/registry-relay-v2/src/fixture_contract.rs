// SPDX-License-Identifier: Apache-2.0
//! Strict shared wire contract for offline HTTP acceptance journeys.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FixtureJourney {
    pub schema_version: String,
    pub registry: String,
    #[serde(default)]
    pub authorizations: BTreeMap<String, FixtureAuthorization>,
    pub steps: Vec<FixtureStep>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FixtureAuthorization {
    pub principal: String,
    pub scopes: BTreeSet<String>,
    #[serde(default)]
    pub claims: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FixtureStep {
    pub id: String,
    #[serde(default)]
    pub authorization_fixture: Option<String>,
    pub request: FixtureRequest,
    pub expect: FixtureExpectation,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FixtureRequest {
    pub method: FixtureMethod,
    pub path: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub query: BTreeMap<String, Value>,
    #[serde(default)]
    pub body: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum FixtureMethod {
    Get,
    Post,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FixtureExpectation {
    pub status: u16,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub capability_patterns: Vec<String>,
    #[serde(default)]
    pub absent_capability_patterns: Vec<String>,
    #[serde(default)]
    pub item_count: Option<u32>,
    #[serde(default)]
    pub next_cursor: Option<Value>,
    #[serde(default)]
    pub registry_core_required: Option<bool>,
    #[serde(default)]
    pub domain_data_keys: Vec<String>,
    #[serde(default)]
    pub domain_data_values: BTreeMap<String, Value>,
    #[serde(default)]
    pub record_identifier: Option<String>,
    #[serde(default)]
    pub cache: Option<String>,
    #[serde(default)]
    pub route_absent: Option<bool>,
    #[serde(default)]
    pub equivalence_class: Option<String>,
    #[serde(default)]
    pub absent_everywhere: Vec<String>,
    #[serde(default)]
    pub records_equivalent_to: Option<String>,
    #[serde(default)]
    pub body_empty: Option<bool>,
    #[serde(default)]
    pub etag_same_as: Option<String>,
    #[serde(default)]
    pub geo_json_root: Option<FixtureGeoJsonRoot>,
    #[serde(default)]
    pub geometry_type: Option<FixtureGeometryType>,
    #[serde(default)]
    pub format_profile: Option<FixtureFormatProfile>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FixtureGeoJsonRoot {
    Feature,
    FeatureCollection,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum FixtureGeometryType {
    #[serde(rename = "Point")]
    Point,
    #[serde(rename = "null")]
    Null,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FixtureFormatProfile {
    Rfc7946,
    JsonFg,
}

#[derive(Debug, Error)]
pub enum FixtureError {
    #[error("fixture YAML is not valid")]
    InvalidYaml,
}

pub fn parse_journey(yaml: &str) -> Result<FixtureJourney, FixtureError> {
    serde_norway::from_str(yaml).map_err(|_| FixtureError::InvalidYaml)
}
