use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::RelayClientError;

const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_QUERY_BYTES: usize = 16 * 1024;
const MAX_VALUE_BYTES: usize = 4 * 1024;
const MAX_LOOKUP_BODY_BYTES: usize = 1024 * 1024;
const RESERVED: &[&str] = &[
    "pageSize",
    "cursor",
    "fields",
    "accessProfile",
    "bbox",
    "formatProfile",
];

/// First-page facts for resource discovery. Continuations use a distinct,
/// opaque type and therefore cannot be mixed with `pageSize`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResourceListRequest {
    pub(crate) page_size: Option<u32>,
}

impl ResourceListRequest {
    pub fn page_size(mut self, value: u32) -> Result<Self, RelayClientError> {
        if !(1..=100).contains(&value) {
            return Err(RelayClientError::invalid_request(
                "resource page size must be between 1 and 100",
            ));
        }
        self.page_size = Some(value);
        Ok(self)
    }

    pub(crate) fn pairs(self) -> Vec<(String, String)> {
        self.page_size
            .map(|value| vec![("pageSize".into(), value.to_string())])
            .unwrap_or_default()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordFormat {
    #[default]
    #[serde(rename = "json")]
    Json,
    #[serde(rename = "json-ld")]
    JsonLd,
    #[serde(rename = "geojson-rfc7946")]
    GeoJsonRfc7946,
    #[serde(rename = "json-fg")]
    JsonFg,
}

impl RecordFormat {
    pub(crate) const fn media_type(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::JsonLd => "application/ld+json",
            Self::GeoJsonRfc7946 | Self::JsonFg => "application/geo+json",
        }
    }

    pub(crate) const fn profile(self) -> Option<&'static str> {
        match self {
            Self::GeoJsonRfc7946 => Some("rfc7946"),
            Self::JsonFg => Some("jsonfg"),
            Self::Json | Self::JsonLd => None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RecordOptions {
    pub(crate) fields: Vec<String>,
    pub(crate) access_profile: Option<String>,
    pub(crate) format: RecordFormat,
}

impl RecordOptions {
    pub fn fields(
        mut self,
        fields: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, RelayClientError> {
        self.fields = fields.into_iter().map(Into::into).collect();
        validate_fields(&self.fields)?;
        Ok(self)
    }

    pub fn access_profile(mut self, value: impl Into<String>) -> Result<Self, RelayClientError> {
        let value = value.into();
        validate_identifier(&value, "the access profile identifier is invalid")?;
        self.access_profile = Some(value);
        Ok(self)
    }

    #[must_use]
    pub fn format(mut self, value: RecordFormat) -> Self {
        self.format = value;
        self
    }

    pub(crate) fn append_query(&self, pairs: &mut Vec<(String, String)>) {
        if !self.fields.is_empty() {
            pairs.push(("fields".into(), self.fields.join(",")));
        }
        if let Some(value) = &self.access_profile {
            pairs.push(("accessProfile".into(), value.clone()));
        }
        if let Some(value) = self.format.profile() {
            pairs.push(("formatProfile".into(), value.into()));
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BoundingBox {
    west: f64,
    south: f64,
    east: f64,
    north: f64,
}

impl BoundingBox {
    pub fn new(west: f64, south: f64, east: f64, north: f64) -> Result<Self, RelayClientError> {
        if [west, south, east, north]
            .iter()
            .any(|value| !value.is_finite())
            || !(-180.0..=180.0).contains(&west)
            || !(-180.0..=180.0).contains(&east)
            || !(-90.0..=90.0).contains(&south)
            || !(-90.0..=90.0).contains(&north)
            || west > east
            || south > north
        {
            return Err(RelayClientError::invalid_request(
                "the bounding box is invalid",
            ));
        }
        Ok(Self {
            west,
            south,
            east,
            north,
        })
    }

    fn text(self) -> String {
        format!("{},{},{},{}", self.west, self.south, self.east, self.north)
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct CollectionRequest {
    pub(crate) options: RecordOptions,
    pub(crate) page_size: Option<u32>,
    pub(crate) filters: BTreeMap<String, String>,
    pub(crate) bbox: Option<BoundingBox>,
}

impl CollectionRequest {
    #[must_use]
    pub fn options(mut self, options: RecordOptions) -> Self {
        self.options = options;
        self
    }

    pub fn page_size(mut self, value: u32) -> Result<Self, RelayClientError> {
        if value == 0 {
            return Err(RelayClientError::invalid_request(
                "page size must be greater than zero",
            ));
        }
        self.page_size = Some(value);
        Ok(self)
    }

    pub fn filter(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, RelayClientError> {
        let name = name.into();
        let value = value.into();
        validate_identifier(&name, "the filter name is invalid")?;
        if RESERVED.contains(&name.as_str()) {
            return Err(RelayClientError::invalid_request(
                "a filter name collides with a reserved Relay query parameter",
            ));
        }
        validate_query_value(&value)?;
        if self.filters.insert(name, value).is_some() {
            return Err(RelayClientError::invalid_request(
                "a filter name is duplicated",
            ));
        }
        Ok(self)
    }

    #[must_use]
    pub fn bbox(mut self, value: BoundingBox) -> Self {
        self.bbox = Some(value);
        self
    }

    pub(crate) fn pairs(&self) -> Result<Vec<(String, String)>, RelayClientError> {
        let mut pairs = Vec::new();
        if let Some(value) = self.page_size {
            pairs.push(("pageSize".into(), value.to_string()));
        }
        self.options.append_query(&mut pairs);
        if let Some(value) = self.bbox {
            pairs.push(("bbox".into(), value.text()));
        }
        pairs.extend(
            self.filters
                .iter()
                .map(|(name, value)| (name.clone(), value.clone())),
        );
        ensure_query_bound(&pairs)?;
        Ok(pairs)
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct LookupRequest {
    pub(crate) options: RecordOptions,
    pub(crate) selectors: BTreeMap<String, Value>,
}

impl LookupRequest {
    #[must_use]
    pub fn options(mut self, options: RecordOptions) -> Self {
        self.options = options;
        self
    }

    pub fn selector(
        mut self,
        name: impl Into<String>,
        value: Value,
    ) -> Result<Self, RelayClientError> {
        let name = name.into();
        validate_identifier(&name, "the selector name is invalid")?;
        if !matches!(value, Value::String(_) | Value::Bool(_) | Value::Number(_)) {
            return Err(RelayClientError::invalid_request(
                "a lookup selector must be a JSON string, boolean, or integer",
            ));
        }
        if value.as_str().is_some_and(|text| {
            text.is_empty() || text.len() > MAX_VALUE_BYTES || text.chars().any(char::is_control)
        }) || value.as_number().is_some_and(|number| !number.is_i64())
        {
            return Err(RelayClientError::invalid_request(
                "a lookup selector value is invalid",
            ));
        }
        if self.selectors.insert(name, value).is_some() {
            return Err(RelayClientError::invalid_request(
                "a lookup selector is duplicated",
            ));
        }
        Ok(self)
    }

    pub(crate) fn body(&self) -> Result<Vec<u8>, RelayClientError> {
        if self.selectors.is_empty() {
            return Err(RelayClientError::invalid_request(
                "a lookup requires at least one selector",
            ));
        }
        let body = serde_json::to_vec(&crate::model::LookupBody {
            selectors: &self.selectors,
        })
        .map_err(|_| {
            RelayClientError::invalid_request("lookup selectors could not be serialized")
        })?;
        if body.len() > MAX_LOOKUP_BODY_BYTES {
            return Err(RelayClientError::invalid_request(
                "the lookup request exceeds the client body bound",
            ));
        }
        Ok(body)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SdmxDataFormat {
    #[default]
    Json,
    Csv,
}

impl SdmxDataFormat {
    pub(crate) const fn media_type(self) -> &'static str {
        match self {
            Self::Json => "application/vnd.sdmx.data+json;version=2.1.0",
            Self::Csv => "application/vnd.sdmx.data+csv;version=2.1.0",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SdmxDataRequest {
    pub(crate) agency: String,
    pub(crate) resource: String,
    pub(crate) version: String,
    pub(crate) key: Option<String>,
    pub(crate) constraints: BTreeMap<String, String>,
    pub(crate) offset: Option<u32>,
    pub(crate) limit: Option<u32>,
    pub(crate) dimension_at_observation: Option<String>,
    pub(crate) format: SdmxDataFormat,
}

impl SdmxDataRequest {
    pub fn new(
        agency: impl Into<String>,
        resource: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<Self, RelayClientError> {
        let request = Self {
            agency: agency.into(),
            resource: resource.into(),
            version: version.into(),
            key: None,
            constraints: BTreeMap::new(),
            offset: None,
            limit: None,
            dimension_at_observation: None,
            format: SdmxDataFormat::Json,
        };
        request.validate_path()?;
        Ok(request)
    }

    pub fn keyed(mut self, key: impl Into<String>) -> Result<Self, RelayClientError> {
        let key = key.into();
        if !valid_sdmx_key(&key) {
            return Err(RelayClientError::invalid_request("the SDMX key is invalid"));
        }
        self.key = Some(key);
        Ok(self)
    }

    pub fn constraint(
        mut self,
        component: impl Into<String>,
        expression: impl Into<String>,
    ) -> Result<Self, RelayClientError> {
        let component = component.into();
        let expression = expression.into();
        if !valid_sdmx_component_id(&component) {
            return Err(RelayClientError::invalid_request(
                "the SDMX component identifier is invalid",
            ));
        }
        validate_query_value(&expression)?;
        if self.constraints.insert(component, expression).is_some() {
            return Err(RelayClientError::invalid_request(
                "an SDMX component constraint is duplicated",
            ));
        }
        Ok(self)
    }

    #[must_use]
    pub fn offset(mut self, value: u32) -> Self {
        self.offset = Some(value);
        self
    }

    pub fn limit(mut self, value: u32) -> Result<Self, RelayClientError> {
        if value == 0 {
            return Err(RelayClientError::invalid_request(
                "the SDMX limit must be greater than zero",
            ));
        }
        self.limit = Some(value);
        Ok(self)
    }

    pub fn dimension_at_observation(
        mut self,
        value: impl Into<String>,
    ) -> Result<Self, RelayClientError> {
        let value = value.into();
        if value != "AllDimensions" && !valid_sdmx_component_id(&value) {
            return Err(RelayClientError::invalid_request(
                "the SDMX dimension-at-observation identifier is invalid",
            ));
        }
        self.dimension_at_observation = Some(value);
        Ok(self)
    }

    #[must_use]
    pub fn format(mut self, value: SdmxDataFormat) -> Self {
        self.format = value;
        self
    }

    fn validate_path(&self) -> Result<(), RelayClientError> {
        if self.agency.len() > MAX_IDENTIFIER_BYTES
            || !self.agency.split('.').all(valid_sdmx_ncname_segment)
            || self.resource.len() > MAX_IDENTIFIER_BYTES
            || !valid_sdmx_ncname_segment(&self.resource)
            || !valid_sdmx_version(&self.version)
        {
            return Err(RelayClientError::invalid_request(
                "an SDMX route identifier is invalid",
            ));
        }
        Ok(())
    }

    pub(crate) fn pairs(&self) -> Result<Vec<(String, String)>, RelayClientError> {
        let mut pairs = self
            .constraints
            .iter()
            .map(|(name, value)| (format!("c[{name}]"), value.clone()))
            .collect::<Vec<_>>();
        if let Some(value) = self.offset {
            pairs.push(("offset".into(), value.to_string()));
        }
        if let Some(value) = self.limit {
            pairs.push(("limit".into(), value.to_string()));
        }
        if let Some(value) = &self.dimension_at_observation {
            pairs.push(("dimensionAtObservation".into(), value.clone()));
        }
        ensure_query_bound(&pairs)?;
        Ok(pairs)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SdmxStructureKind {
    Dataflow,
    DataStructure,
}

impl SdmxStructureKind {
    pub(crate) const fn path(self) -> &'static str {
        match self {
            Self::Dataflow => "dataflow",
            Self::DataStructure => "datastructure",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SdmxStructureRequest {
    pub kind: SdmxStructureKind,
    pub agency: String,
    pub resource: String,
    pub version: String,
}

impl SdmxStructureRequest {
    pub fn new(
        kind: SdmxStructureKind,
        agency: impl Into<String>,
        resource: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<Self, RelayClientError> {
        let result = Self {
            kind,
            agency: agency.into(),
            resource: resource.into(),
            version: version.into(),
        };
        if result.agency.len() > MAX_IDENTIFIER_BYTES
            || !result.agency.split('.').all(valid_sdmx_ncname_segment)
            || result.resource.len() > MAX_IDENTIFIER_BYTES
            || !valid_sdmx_ncname_segment(&result.resource)
            || !valid_sdmx_version(&result.version)
        {
            return Err(RelayClientError::invalid_request(
                "an SDMX structure route identifier is invalid",
            ));
        }
        Ok(result)
    }
}

fn validate_identifier(value: &str, reason: &'static str) -> Result<(), RelayClientError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(RelayClientError::invalid_request(reason));
    }
    Ok(())
}

fn valid_sdmx_ncname_segment(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(first) if first.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_sdmx_component_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    value.len() <= MAX_IDENTIFIER_BYTES
        && matches!(bytes.next(), Some(first) if first.is_ascii_uppercase())
        && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_sdmx_key(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_QUERY_BYTES || value.chars().any(char::is_control) {
        return false;
    }
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() > 16 {
        return false;
    }
    parts.into_iter().all(|part| {
        if part == "*" {
            return true;
        }
        if part.is_empty() || part.contains('+') {
            return false;
        }
        let terms = part.split(',').collect::<Vec<_>>();
        terms.len() <= 16
            && terms.into_iter().all(|term| {
                let value = term.strip_prefix("eq:").unwrap_or(term);
                !term.is_empty()
                    && !term.starts_with("ge:")
                    && !term.starts_with("le:")
                    && !value.is_empty()
                    && value.len() <= 1024
            })
    })
}

fn valid_sdmx_version(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    value.len() <= MAX_IDENTIFIER_BYTES
        && parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (*part == "0" || !part.starts_with('0'))
        })
}

fn validate_fields(fields: &[String]) -> Result<(), RelayClientError> {
    if fields.is_empty() {
        return Err(RelayClientError::invalid_request(
            "field selection must not be empty",
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for field in fields {
        validate_identifier(field, "a selected field name is invalid")?;
        if !seen.insert(field) {
            return Err(RelayClientError::invalid_request(
                "a selected field is duplicated",
            ));
        }
    }
    Ok(())
}

fn validate_query_value(value: &str) -> Result<(), RelayClientError> {
    if value.is_empty() || value.len() > MAX_VALUE_BYTES || value.chars().any(char::is_control) {
        return Err(RelayClientError::invalid_request(
            "a query value is invalid",
        ));
    }
    Ok(())
}

pub(crate) fn encoded_query(pairs: &[(String, String)]) -> String {
    // The form serializer escapes a literal `+` as `%2B`. Relay therefore sees
    // the SDMX range separator as plus, never as form-urlencoded space.
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(
            pairs
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        )
        .finish()
}

fn ensure_query_bound(pairs: &[(String, String)]) -> Result<(), RelayClientError> {
    if encoded_query(pairs).len() > MAX_QUERY_BYTES {
        return Err(RelayClientError::invalid_request(
            "the request query exceeds the client bound",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdmx_literal_plus_is_never_decoded_as_space() {
        let request = SdmxDataRequest::new("A", "F", "1.0.0")
            .unwrap()
            .constraint("TIME_PERIOD", "ge:2020+le:2024")
            .unwrap();
        let text = encoded_query(&request.pairs().unwrap());
        assert!(text.contains("ge%3A2020%2Ble%3A2024"));
        let decoded = url::form_urlencoded::parse(text.as_bytes()).collect::<Vec<_>>();
        assert_eq!(decoded[0].1, "ge:2020+le:2024");
    }

    #[test]
    fn sdmx_component_identifiers_match_the_compiled_uppercase_grammar() {
        let base = SdmxDataRequest::new("A", "F", "1.0.0").unwrap();
        assert!(base.clone().constraint("TIME_PERIOD", "2024").is_ok());
        assert!(base.clone().constraint("time_period", "2024").is_err());
        assert!(base
            .clone()
            .dimension_at_observation("AllDimensions")
            .is_ok());
        assert!(base.dimension_at_observation("time_period").is_err());
    }

    #[test]
    fn keyed_sdmx_preserves_bounded_non_code_strings_but_rejects_query_grammar() {
        let base = SdmxDataRequest::new("A", "F", "1.0.0").unwrap();
        assert!(base.clone().keyed("South East,กรุงเทพ.*").is_ok());
        for invalid in ["", ".value", "value.", "ge:2020", "one+two", "one,,two"] {
            assert!(base.clone().keyed(invalid).is_err(), "accepted {invalid:?}");
        }
        assert!(base
            .keyed((0..17).map(|_| "*").collect::<Vec<_>>().join("."))
            .is_err());
    }

    #[test]
    fn first_page_filters_cannot_claim_reserved_parameters() {
        let error = CollectionRequest::default()
            .filter("cursor", "opaque")
            .unwrap_err();
        assert!(matches!(error, RelayClientError::InvalidRequest { .. }));
    }

    #[test]
    fn request_builders_reject_ambiguous_or_oversized_first_page_facts() {
        assert!(ResourceListRequest::default().page_size(101).is_err());
        assert!(BoundingBox::new(10.0, -1.0, -10.0, 1.0).is_err());
        assert!(RecordOptions::default().fields(["name", "name"]).is_err());
        assert!(LookupRequest::default()
            .selector("subject", serde_json::json!({"nested": true}))
            .is_err());
    }

    #[test]
    fn lookup_body_has_exactly_one_outer_selectors_member() {
        let request = LookupRequest::default()
            .selector("number", serde_json::json!(42))
            .unwrap()
            .selector("active", serde_json::json!(true))
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&request.body().unwrap()).unwrap();
        assert_eq!(value.as_object().map(serde_json::Map::len), Some(1));
        assert!(value.get("selectors").is_some());
    }
}
