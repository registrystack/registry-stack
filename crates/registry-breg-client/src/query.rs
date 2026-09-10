// SPDX-License-Identifier: Apache-2.0

//! Bounded request facts for the Base Registry Engine read surface.
//!
//! Base Registry Engine and Relay deliberately have different query contracts. This
//! module mirrors the BReg wire names and bounds without interpreting its
//! governed filter or ordering grammar in the client.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use registry_record::RegistryRecordMeta;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const MAX_QUERY_PAYLOAD_BYTES: usize = 16 * 1024;
pub(crate) const MAX_BREG_REQUEST_URI_BYTES: usize = 16 * 1024;
const MAX_LOOKUP_BODY_BYTES: usize = 16 * 1024;
const MAX_LOOKUP_VALUES: usize = 16;
const MAX_SELECTED_FIELDS: usize = 128;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_ROUTE_IDENTIFIER_BYTES: usize = 64;
const MAX_SKIPTOKEN_BYTES: usize = 4096;
const MAX_TOP: u32 = 100;
const MAX_BBOX_PARAMETER_BYTES: usize = 256;

const INVALID_ACCESS_PROFILE: &str =
    "the Base Registry Engine access profile identifier is invalid";
const INVALID_FIELD: &str = "a Base Registry Engine selected field identifier is invalid";
const INVALID_FILTER: &str = "the Base Registry Engine filter expression is invalid";
const INVALID_ORDERBY: &str = "the Base Registry Engine ordering expression is invalid";
const INVALID_ROUTE: &str = "the Base Registry Engine continuation route is invalid";
const INVALID_COLLECTION_BINDING: &str =
    "the Base Registry Engine continuation collection binding is invalid";
const INVALID_SELECTOR: &str = "the Base Registry Engine lookup selector is invalid";
const INVALID_SKIPTOKEN: &str = "the Base Registry Engine continuation token is invalid";
const INVALID_BBOX: &str = "the Base Registry Engine bounding box is invalid";
const INVALID_REQUEST_HISTORY_CURSOR: &str =
    "the Base Registry Engine request history proposal version must be positive";

/// A value-free reason that a Base Registry Engine request cannot be constructed.
///
/// The owning client error can preserve this closed static reason with
/// `BaseRegistryClientError::invalid_request(error.reason())`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BRegRequestError {
    reason: &'static str,
}

impl BRegRequestError {
    pub(crate) const fn new(reason: &'static str) -> Self {
        Self { reason }
    }

    /// Return the closed, value-free failure reason.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for BRegRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason)
    }
}

impl std::error::Error for BRegRequestError {}

/// Shared Registry Record representations supported by this client slice.
///
/// Base Registry Engine GeoJSON uses a separate response contract and is not a
/// Registry Record representation.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BRegRecordFormat {
    /// `application/json` Registry Record response.
    #[default]
    Json,
    /// `application/ld+json` Registry Record response.
    JsonLd,
}

impl BRegRecordFormat {
    /// Exact media type sent in `Accept` and retained by continuations.
    #[must_use]
    pub const fn media_type(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::JsonLd => "application/ld+json",
        }
    }
}

/// Projection, authorization profile, and representation for one BReg read.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct BRegRecordOptions {
    select: Vec<String>,
    access_profile: Option<String>,
    format: BRegRecordFormat,
    request_history_after_proposal_version: Option<u32>,
}

impl BRegRecordOptions {
    /// Select a nonempty, bounded set of unique API field names.
    pub fn select(
        mut self,
        fields: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, BRegRequestError> {
        let fields = fields.into_iter().map(Into::into).collect::<Vec<_>>();
        validate_selected_fields(&fields)?;
        self.select = fields;
        Ok(self)
    }

    /// Select one Base Registry Engine access profile.
    pub fn access_profile(mut self, value: impl Into<String>) -> Result<Self, BRegRequestError> {
        let value = value.into();
        validate_access_profile(&value)?;
        self.access_profile = Some(value);
        Ok(self)
    }

    /// Select the shared Registry Record representation.
    #[must_use]
    pub fn format(mut self, value: BRegRecordFormat) -> Self {
        self.format = value;
        self
    }

    /// Continue the retained proposal history returned with a change-request GET.
    ///
    /// This option is valid only for [`crate::BaseRegistryClient::get_record`].
    /// Collection and lookup methods refuse it before acquiring a token.
    pub fn request_history_after_proposal_version(
        mut self,
        value: u32,
    ) -> Result<Self, BRegRequestError> {
        if value == 0 {
            return Err(BRegRequestError::new(INVALID_REQUEST_HISTORY_CURSOR));
        }
        self.request_history_after_proposal_version = Some(value);
        Ok(self)
    }

    #[must_use]
    pub(crate) const fn format_value(&self) -> BRegRecordFormat {
        self.format
    }

    #[must_use]
    pub(crate) fn access_profile_value(&self) -> Option<&str> {
        self.access_profile.as_deref()
    }

    pub(crate) fn append_query(&self, pairs: &mut Vec<(String, String)>) {
        if let Some(value) = &self.access_profile {
            pairs.push(("accessProfile".into(), value.clone()));
        }
        if !self.select.is_empty() {
            pairs.push(("$select".into(), self.select.join(",")));
        }
    }

    pub(crate) fn append_get_query(&self, pairs: &mut Vec<(String, String)>) {
        self.append_query(pairs);
        if let Some(value) = self.request_history_after_proposal_version {
            pairs.push((
                "requestHistoryAfterProposalVersion".into(),
                value.to_string(),
            ));
        }
    }

    pub(crate) fn ensure_collection_compatible(&self) -> Result<(), BRegRequestError> {
        if self.request_history_after_proposal_version.is_some() {
            return Err(BRegRequestError::new(
                "a Base Registry Engine request history cursor is valid only for a record GET",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for BRegRecordOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegRecordOptions")
            .field("selected_field_count", &self.select.len())
            .field("access_profile_present", &self.access_profile.is_some())
            .field("format", &self.format)
            .field(
                "request_history_cursor_present",
                &self.request_history_after_proposal_version.is_some(),
            )
            .finish()
    }
}

/// One validated CRS84 bounding box, retaining exact canonical decimal text.
///
/// Coordinates are ordered west, south, east, north. Zero-width and zero-height
/// boxes are permitted; antimeridian-crossing and inverted boxes are refused.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct BRegBoundingBox {
    coordinates: Box<[String; 4]>,
}

impl BRegBoundingBox {
    /// Construct a bounded CRS84 box without converting through binary floats.
    pub fn new(
        west: impl AsRef<str>,
        south: impl AsRef<str>,
        east: impl AsRef<str>,
        north: impl AsRef<str>,
    ) -> Result<Self, BRegRequestError> {
        let west = canonical_bounded_decimal(west.as_ref(), "-180", "180")?;
        let south = canonical_bounded_decimal(south.as_ref(), "-90", "90")?;
        let east = canonical_bounded_decimal(east.as_ref(), "-180", "180")?;
        let north = canonical_bounded_decimal(north.as_ref(), "-90", "90")?;
        if west.len() + south.len() + east.len() + north.len() + 3 > MAX_BBOX_PARAMETER_BYTES
            || compare_decimal_text(&west, &east)? == std::cmp::Ordering::Greater
            || compare_decimal_text(&south, &north)? == std::cmp::Ordering::Greater
        {
            return Err(BRegRequestError::new(INVALID_BBOX));
        }
        Ok(Self {
            coordinates: Box::new([west, south, east, north]),
        })
    }

    /// Return the exact canonical wire value.
    #[must_use]
    pub fn as_str(&self) -> String {
        self.coordinates.join(",")
    }

    #[must_use]
    pub fn west(&self) -> &str {
        &self.coordinates[0]
    }

    #[must_use]
    pub fn south(&self) -> &str {
        &self.coordinates[1]
    }

    #[must_use]
    pub fn east(&self) -> &str {
        &self.coordinates[2]
    }

    #[must_use]
    pub fn north(&self) -> &str {
        &self.coordinates[3]
    }
}

impl fmt::Debug for BRegBoundingBox {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BRegBoundingBox(<redacted>)")
    }
}

/// First-page facts for a Base Registry Engine list operation.
///
/// Filter and ordering expressions remain opaque here. Base Registry Engine parses
/// them against the selected compiled operation after authorization.
/// Continuations use [`BRegContinuation`], a distinct type with no first-page
/// setters.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct BRegListRequest {
    options: BRegRecordOptions,
    top: Option<u32>,
    filter: Option<String>,
    orderby: Option<String>,
    count: Option<bool>,
    bbox: Option<BRegBoundingBox>,
}

impl BRegListRequest {
    /// Set projection, access profile, and representation options.
    #[must_use]
    pub fn options(mut self, options: BRegRecordOptions) -> Self {
        self.options = options;
        self
    }

    /// Set the requested page size, from one through the BReg maximum of 100.
    pub fn top(mut self, value: u32) -> Result<Self, BRegRequestError> {
        if !(1..=MAX_TOP).contains(&value) {
            return Err(BRegRequestError::new(
                "Base Registry Engine $top must be between 1 and 100",
            ));
        }
        self.top = Some(value);
        Ok(self)
    }

    /// Set a bounded opaque Base Registry Engine `$filter` expression.
    pub fn filter(mut self, value: impl Into<String>) -> Result<Self, BRegRequestError> {
        let value = value.into();
        validate_opaque_query_member(&value, MAX_QUERY_PAYLOAD_BYTES, INVALID_FILTER)?;
        self.filter = Some(value);
        Ok(self)
    }

    /// Set a bounded opaque Base Registry Engine `$orderby` expression.
    pub fn orderby(mut self, value: impl Into<String>) -> Result<Self, BRegRequestError> {
        let value = value.into();
        validate_opaque_query_member(&value, MAX_IDENTIFIER_BYTES, INVALID_ORDERBY)?;
        self.orderby = Some(value);
        Ok(self)
    }

    /// Ask the BReg to include or explicitly omit the collection count.
    #[must_use]
    pub fn count(mut self, value: bool) -> Self {
        self.count = Some(value);
        self
    }

    /// Restrict a direct current collection to one validated CRS84 box.
    #[must_use]
    pub fn bbox(mut self, value: BRegBoundingBox) -> Self {
        self.bbox = Some(value);
        self
    }

    pub(crate) fn query_pairs(&self) -> Result<Vec<(String, String)>, BRegRequestError> {
        self.options.ensure_collection_compatible()?;
        let mut pairs = Vec::new();
        self.options.append_query(&mut pairs);
        if let Some(value) = &self.filter {
            pairs.push(("$filter".into(), value.clone()));
        }
        if let Some(value) = &self.orderby {
            pairs.push(("$orderby".into(), value.clone()));
        }
        if let Some(value) = self.top {
            pairs.push(("$top".into(), value.to_string()));
        }
        if let Some(value) = self.count {
            pairs.push(("$count".into(), value.to_string()));
        }
        if let Some(value) = &self.bbox {
            pairs.push(("bbox".into(), value.as_str()));
        }
        ensure_query_bound(&pairs)?;
        Ok(pairs)
    }

    #[must_use]
    pub(crate) fn record_options(&self) -> &BRegRecordOptions {
        &self.options
    }
}

impl fmt::Debug for BRegListRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegListRequest")
            .field("options", &self.options)
            .field("top", &self.top)
            .field("filter_present", &self.filter.is_some())
            .field("orderby_present", &self.orderby.is_some())
            .field("count", &self.count)
            .field("bbox_present", &self.bbox.is_some())
            .finish()
    }
}

/// Base Registry Engine lookup facts and Registry Record response options.
///
/// A lookup whose values originate in verified claims is represented by a
/// request with no calls to [`Self::value`], producing only `selector` in the
/// body. Request-origin selectors add the exact expected field/value members.
#[derive(Clone, PartialEq, Eq)]
pub struct BRegLookupRequest {
    selector: String,
    values: Option<BTreeMap<String, Value>>,
    options: BRegRecordOptions,
}

impl BRegLookupRequest {
    /// Construct a lookup for one compiled selector profile.
    pub fn new(selector: impl Into<String>) -> Result<Self, BRegRequestError> {
        let selector = selector.into();
        if !valid_compiled_identifier(&selector) {
            return Err(BRegRequestError::new(INVALID_SELECTOR));
        }
        Ok(Self {
            selector,
            values: None,
            options: BRegRecordOptions::default(),
        })
    }

    /// Set projection, access profile, and representation options.
    #[must_use]
    pub fn options(mut self, options: BRegRecordOptions) -> Self {
        self.options = options;
        self
    }

    /// Add one request-origin selector value.
    pub fn value(
        mut self,
        name: impl Into<String>,
        value: Value,
    ) -> Result<Self, BRegRequestError> {
        let name = name.into();
        if !valid_api_identifier(&name) {
            return Err(BRegRequestError::new(
                "a Base Registry Engine lookup value field is invalid",
            ));
        }
        if !valid_lookup_value(&value) {
            return Err(BRegRequestError::new(
                "a Base Registry Engine lookup value must be a bounded string, boolean, or integer",
            ));
        }
        let values = self.values.get_or_insert_with(BTreeMap::new);
        if values.contains_key(&name) {
            return Err(BRegRequestError::new(
                "a Base Registry Engine lookup value field is duplicated",
            ));
        }
        if values.len() >= MAX_LOOKUP_VALUES {
            return Err(BRegRequestError::new(
                "a Base Registry Engine lookup must not contain more than 16 values",
            ));
        }
        values.insert(name, value);
        Ok(self)
    }

    pub(crate) fn query_pairs(&self) -> Result<Vec<(String, String)>, BRegRequestError> {
        self.options.ensure_collection_compatible()?;
        let mut pairs = Vec::new();
        self.options.append_query(&mut pairs);
        ensure_query_bound(&pairs)?;
        Ok(pairs)
    }

    pub(crate) fn body(&self) -> Result<Vec<u8>, BRegRequestError> {
        #[derive(Serialize)]
        struct LookupBody<'a> {
            selector: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            values: Option<&'a BTreeMap<String, Value>>,
        }

        let body = serde_json::to_vec(&LookupBody {
            selector: &self.selector,
            values: self.values.as_ref(),
        })
        .map_err(|_| {
            BRegRequestError::new("the Base Registry Engine lookup body could not be serialized")
        })?;
        if body.len() > MAX_LOOKUP_BODY_BYTES {
            return Err(BRegRequestError::new(
                "the Base Registry Engine lookup body exceeds 16384 bytes",
            ));
        }
        Ok(body)
    }

    #[must_use]
    pub(crate) fn record_options(&self) -> &BRegRecordOptions {
        &self.options
    }
}

impl fmt::Debug for BRegLookupRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegLookupRequest")
            .field("selector", &"<redacted>")
            .field(
                "value_count",
                &self.values.as_ref().map(BTreeMap::len).unwrap_or_default(),
            )
            .field("options", &self.options)
            .finish()
    }
}

/// Persistable, validated projection of a Base Registry Engine continuation.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BRegContinuationProjection {
    /// Logical Base Registry Engine entity route segment.
    pub route: String,
    /// Opaque Base Registry Engine `$skiptoken`.
    pub skiptoken: String,
    /// Representation selected for the original page.
    pub format: BRegRecordFormat,
    /// Access profile selected for the original page, when explicit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_profile: Option<String>,
    /// Registry identifier returned with the first page.
    pub registry_identifier: String,
    /// Dataset identifier returned with the first page.
    pub dataset_identifier: String,
    /// Entity identifier returned with the first page.
    pub entity_type_identifier: String,
}

impl fmt::Debug for BRegContinuationProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegContinuationProjection")
            .field("route", &"<redacted>")
            .field("skiptoken", &"<redacted>")
            .field("format", &self.format)
            .field("access_profile_present", &self.access_profile.is_some())
            .field("collection_binding", &"<redacted>")
            .finish()
    }
}

/// Opaque Base Registry Engine continuation bound to its route, representation,
/// and first-page collection identity.
///
/// Only continuation operations consume this type. It intentionally exposes no
/// `$select`, `$filter`, `$orderby`, `$top`, or `$count` setters, preventing a
/// cursor from being mixed with first-page facts.
#[derive(Clone, Eq, PartialEq)]
pub struct BRegContinuation {
    route: String,
    skiptoken: String,
    format: BRegRecordFormat,
    access_profile: Option<String>,
    registry_identifier: String,
    dataset_identifier: String,
    entity_type_identifier: String,
}

impl BRegContinuation {
    pub(crate) fn try_from_parts(
        route: impl Into<String>,
        skiptoken: impl Into<String>,
        format: BRegRecordFormat,
        access_profile: Option<String>,
        meta: &RegistryRecordMeta,
    ) -> Result<Self, BRegRequestError> {
        Self::try_from_projection(BRegContinuationProjection {
            route: route.into(),
            skiptoken: skiptoken.into(),
            format,
            access_profile,
            registry_identifier: meta.registry_identifier.clone(),
            dataset_identifier: meta.dataset_identifier.clone(),
            entity_type_identifier: meta.entity_type_identifier.clone(),
        })
    }

    /// Revalidate a persisted continuation before it can be used.
    pub fn try_from_projection(
        value: BRegContinuationProjection,
    ) -> Result<Self, BRegRequestError> {
        if !valid_compiled_identifier(&value.route) {
            return Err(BRegRequestError::new(INVALID_ROUTE));
        }
        validate_skiptoken(&value.skiptoken)?;
        if let Some(profile) = &value.access_profile {
            validate_access_profile(profile)?;
        }
        if [
            &value.registry_identifier,
            &value.dataset_identifier,
            &value.entity_type_identifier,
        ]
        .into_iter()
        .any(|identifier| !valid_collection_identifier(identifier))
        {
            return Err(BRegRequestError::new(INVALID_COLLECTION_BINDING));
        }
        Ok(Self {
            route: value.route,
            skiptoken: value.skiptoken,
            format: value.format,
            access_profile: value.access_profile,
            registry_identifier: value.registry_identifier,
            dataset_identifier: value.dataset_identifier,
            entity_type_identifier: value.entity_type_identifier,
        })
    }

    /// Produce the inert serializable continuation projection.
    #[must_use]
    pub fn projection(&self) -> BRegContinuationProjection {
        BRegContinuationProjection {
            route: self.route.clone(),
            skiptoken: self.skiptoken.clone(),
            format: self.format,
            access_profile: self.access_profile.clone(),
            registry_identifier: self.registry_identifier.clone(),
            dataset_identifier: self.dataset_identifier.clone(),
            entity_type_identifier: self.entity_type_identifier.clone(),
        }
    }

    /// Logical Base Registry Engine entity route selected for the original page.
    #[must_use]
    pub fn route(&self) -> &str {
        &self.route
    }

    /// Registry Record representation selected for the original page.
    #[must_use]
    pub const fn format(&self) -> BRegRecordFormat {
        self.format
    }

    /// Explicit access profile selected for the original page, when any.
    #[must_use]
    pub fn access_profile(&self) -> Option<&str> {
        self.access_profile.as_deref()
    }

    pub(crate) fn matches_meta(&self, meta: &RegistryRecordMeta) -> bool {
        self.registry_identifier == meta.registry_identifier
            && self.dataset_identifier == meta.dataset_identifier
            && self.entity_type_identifier == meta.entity_type_identifier
    }

    pub(crate) fn query_pairs(&self) -> Result<Vec<(String, String)>, BRegRequestError> {
        let mut pairs = Vec::with_capacity(2);
        if let Some(value) = &self.access_profile {
            pairs.push(("accessProfile".into(), value.clone()));
        }
        pairs.push(("$skiptoken".into(), self.skiptoken.clone()));
        ensure_query_bound(&pairs)?;
        Ok(pairs)
    }
}

impl fmt::Debug for BRegContinuation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegContinuation")
            .field("route", &"<redacted>")
            .field("skiptoken", &"<redacted>")
            .field("format", &self.format)
            .field("access_profile_present", &self.access_profile.is_some())
            .field("collection_binding", &"<redacted>")
            .finish()
    }
}

impl Serialize for BRegContinuation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.projection().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BRegContinuation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::try_from_projection(BRegContinuationProjection::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

fn validate_selected_fields(fields: &[String]) -> Result<(), BRegRequestError> {
    if fields.is_empty() || fields.len() > MAX_SELECTED_FIELDS {
        return Err(BRegRequestError::new(
            "Base Registry Engine $select must contain 1 to 128 fields",
        ));
    }
    let mut seen = BTreeSet::new();
    for field in fields {
        if !valid_api_identifier(field) {
            return Err(BRegRequestError::new(INVALID_FIELD));
        }
        if !seen.insert(field) {
            return Err(BRegRequestError::new(
                "a Base Registry Engine selected field is duplicated",
            ));
        }
    }
    Ok(())
}

fn validate_access_profile(value: &str) -> Result<(), BRegRequestError> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(BRegRequestError::new(INVALID_ACCESS_PROFILE));
    };
    if value.len() > MAX_IDENTIFIER_BYTES
        || !(first.is_ascii_lowercase() || first == b'_')
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        return Err(BRegRequestError::new(INVALID_ACCESS_PROFILE));
    }
    Ok(())
}

fn valid_api_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    value.len() <= MAX_IDENTIFIER_BYTES
        && (first.is_ascii_lowercase() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_compiled_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    value.len() <= MAX_ROUTE_IDENTIFIER_BYTES
        && first.is_ascii_lowercase()
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn valid_collection_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    value.len() <= MAX_IDENTIFIER_BYTES
        && first.is_ascii_lowercase()
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn valid_lookup_value(value: &Value) -> bool {
    match value {
        Value::String(value) => {
            value.len() <= MAX_LOOKUP_BODY_BYTES && !value.chars().any(char::is_control)
        }
        Value::Bool(_) => true,
        Value::Number(value) => value.is_i64(),
        Value::Null | Value::Array(_) | Value::Object(_) => false,
    }
}

fn validate_opaque_query_member(
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

fn validate_skiptoken(value: &str) -> Result<(), BRegRequestError> {
    if value.is_empty()
        || value.len() > MAX_SKIPTOKEN_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(BRegRequestError::new(INVALID_SKIPTOKEN));
    }
    Ok(())
}

fn canonical_bounded_decimal(
    value: &str,
    minimum: &str,
    maximum: &str,
) -> Result<String, BRegRequestError> {
    if value.is_empty() || value.len() > MAX_BBOX_PARAMETER_BYTES {
        return Err(BRegRequestError::new(INVALID_BBOX));
    }
    let parsed = ParsedDecimal::parse(value)?;
    if compare_decimal(&parsed, &ParsedDecimal::parse(minimum)?)? == std::cmp::Ordering::Less
        || compare_decimal(&parsed, &ParsedDecimal::parse(maximum)?)? == std::cmp::Ordering::Greater
    {
        return Err(BRegRequestError::new(INVALID_BBOX));
    }
    let canonical = parsed.canonical();
    if canonical.len() > MAX_BBOX_PARAMETER_BYTES {
        return Err(BRegRequestError::new(INVALID_BBOX));
    }
    Ok(canonical)
}

#[derive(Clone, Eq, PartialEq)]
struct ParsedDecimal {
    negative: bool,
    digits: Vec<u8>,
    scale: usize,
}

impl ParsedDecimal {
    fn parse(value: &str) -> Result<Self, BRegRequestError> {
        if !is_decimal_number(value) {
            return Err(BRegRequestError::new(INVALID_BBOX));
        }
        let (number, exponent) = split_decimal_exponent(value)?;
        let (negative, number) = number
            .strip_prefix('-')
            .map_or((false, number), |rest| (true, rest));
        let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
        let mut digits = whole
            .bytes()
            .chain(fraction.bytes())
            .map(|byte| byte - b'0')
            .collect::<Vec<_>>();
        let mut scale = i32::try_from(fraction.len())
            .map_err(|_| BRegRequestError::new(INVALID_BBOX))?
            - exponent.unwrap_or(0);
        if scale < 0 {
            digits.extend(std::iter::repeat_n(0, (-scale) as usize));
            scale = 0;
        }
        if scale > 1000 {
            return Err(BRegRequestError::new(INVALID_BBOX));
        }
        trim_leading_decimal_zeroes(&mut digits);
        let mut parsed = Self {
            negative,
            digits,
            scale: scale as usize,
        };
        while parsed.scale > 0 && parsed.digits.last() == Some(&0) {
            parsed.digits.pop();
            parsed.scale -= 1;
        }
        if parsed.digits.is_empty() || parsed.digits == [0] {
            parsed.digits.clear();
            parsed.digits.push(0);
            parsed.negative = false;
            parsed.scale = 0;
        }
        Ok(parsed)
    }

    fn canonical(&self) -> String {
        let digits = self
            .digits
            .iter()
            .map(|digit| char::from(b'0' + *digit))
            .collect::<String>();
        let magnitude = if self.scale == 0 {
            digits
        } else if self.digits.len() > self.scale {
            let split = self.digits.len() - self.scale;
            format!("{}.{}", &digits[..split], &digits[split..])
        } else {
            format!("0.{}{}", "0".repeat(self.scale - self.digits.len()), digits)
        };
        if self.negative {
            format!("-{magnitude}")
        } else {
            magnitude
        }
    }

    fn scaled_digits(&self, scale: usize) -> Result<Vec<u8>, BRegRequestError> {
        if self.scale > scale || scale - self.scale > 1000 {
            return Err(BRegRequestError::new(INVALID_BBOX));
        }
        let mut digits = self.digits.clone();
        digits.extend(std::iter::repeat_n(0, scale - self.scale));
        trim_leading_decimal_zeroes(&mut digits);
        Ok(digits)
    }
}

fn compare_decimal_text(left: &str, right: &str) -> Result<std::cmp::Ordering, BRegRequestError> {
    compare_decimal(&ParsedDecimal::parse(left)?, &ParsedDecimal::parse(right)?)
}

fn compare_decimal(
    left: &ParsedDecimal,
    right: &ParsedDecimal,
) -> Result<std::cmp::Ordering, BRegRequestError> {
    match (left.negative, right.negative) {
        (true, false) => return Ok(std::cmp::Ordering::Less),
        (false, true) => return Ok(std::cmp::Ordering::Greater),
        _ => {}
    }
    let scale = left.scale.max(right.scale);
    let ordering =
        compare_decimal_digits(&left.scaled_digits(scale)?, &right.scaled_digits(scale)?);
    Ok(if left.negative && right.negative {
        ordering.reverse()
    } else {
        ordering
    })
}

fn split_decimal_exponent(value: &str) -> Result<(&str, Option<i32>), BRegRequestError> {
    let mut separator = None;
    for (index, byte) in value.bytes().enumerate() {
        if matches!(byte, b'e' | b'E') && separator.replace(index).is_some() {
            return Err(BRegRequestError::new(INVALID_BBOX));
        }
    }
    let Some(index) = separator else {
        return Ok((value, None));
    };
    let (number, exponent) = value.split_at(index);
    let exponent = exponent[1..]
        .parse::<i32>()
        .map_err(|_| BRegRequestError::new(INVALID_BBOX))?;
    if exponent.unsigned_abs() > 1000 {
        return Err(BRegRequestError::new(INVALID_BBOX));
    }
    Ok((number, Some(exponent)))
}

fn compare_decimal_digits(left: &[u8], right: &[u8]) -> std::cmp::Ordering {
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    trim_leading_decimal_zeroes(&mut left);
    trim_leading_decimal_zeroes(&mut right);
    left.len().cmp(&right.len()).then_with(|| left.cmp(&right))
}

fn trim_leading_decimal_zeroes(digits: &mut Vec<u8>) {
    match digits.iter().position(|digit| *digit != 0) {
        Some(index) if index > 0 => {
            digits.drain(..index);
        }
        Some(_) => {}
        None => {
            digits.clear();
            digits.push(0);
        }
    }
}

fn is_decimal_number(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let mut index = usize::from(bytes[0] == b'-');
    if index == bytes.len() {
        return false;
    }
    match bytes[index] {
        b'0' => index += 1,
        b'1'..=b'9' => {
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
        }
        _ => return false,
    }
    if index < bytes.len() && bytes[index] == b'.' {
        index += 1;
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index == start {
            return false;
        }
    }
    if index < bytes.len() && matches!(bytes[index], b'e' | b'E') {
        index += 1;
        if index < bytes.len() && matches!(bytes[index], b'+' | b'-') {
            index += 1;
        }
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index == start {
            return false;
        }
    }
    index == bytes.len()
}

pub(crate) fn ensure_query_bound(pairs: &[(String, String)]) -> Result<(), BRegRequestError> {
    if breg_encoded_query(pairs).len() > MAX_QUERY_PAYLOAD_BYTES {
        return Err(BRegRequestError::new(
            "the Base Registry Engine query exceeds 16384 encoded bytes",
        ));
    }
    Ok(())
}

/// Encode a deterministic Base Registry Engine query using RFC 3986 unreserved
/// bytes and uppercase hexadecimal escapes. Pair order is preserved.
pub(crate) fn breg_encoded_query(pairs: &[(String, String)]) -> String {
    let capacity = pairs
        .iter()
        .map(|(name, value)| name.len() + value.len() + 2)
        .sum();
    let mut output = String::with_capacity(capacity);
    for (index, (name, value)) in pairs.iter().enumerate() {
        if index != 0 {
            output.push('&');
        }
        output.push_str(name);
        output.push('=');
        percent_encode_query_value(value, &mut output);
    }
    output
}

fn percent_encode_query_value(value: &str, output: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn collection_meta() -> RegistryRecordMeta {
        RegistryRecordMeta {
            registry_identifier: "business-registry".into(),
            dataset_identifier: "legal-entities".into(),
            entity_type_identifier: "company".into(),
            extensions: BTreeMap::new(),
        }
    }

    #[test]
    fn access_profile_matches_the_breg_config_identifier_grammar() {
        for valid in [
            "reader",
            "_reader",
            "reader.v1",
            "reader_1",
            "reader-one",
            &"a".repeat(MAX_IDENTIFIER_BYTES),
        ] {
            assert!(
                BRegRecordOptions::default().access_profile(valid).is_ok(),
                "rejected {valid:?}"
            );
        }
        for invalid in [
            "",
            "1reader",
            "Reader",
            "reader.V1",
            "público",
            &"a".repeat(MAX_IDENTIFIER_BYTES + 1),
        ] {
            assert!(
                BRegRecordOptions::default()
                    .access_profile(invalid)
                    .is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn select_is_bounded_unique_and_uses_breg_api_identifiers() {
        assert!(BRegRecordOptions::default()
            .select(["caseCode", "opened-on", "_internal.v1"])
            .is_ok());
        assert!(BRegRecordOptions::default()
            .select(std::iter::empty::<&str>())
            .is_err());
        assert!(BRegRecordOptions::default()
            .select(["caseCode", "caseCode"])
            .is_err());
        assert!(BRegRecordOptions::default().select(["CaseCode"]).is_err());
        assert!(BRegRecordOptions::default().select(["case/code"]).is_err());
        assert!(BRegRecordOptions::default()
            .select((0..=MAX_SELECTED_FIELDS).map(|index| format!("field{index}")))
            .is_err());
    }

    #[test]
    fn list_query_is_canonical_and_matches_breg_wire_names() {
        let options = BRegRecordOptions::default()
            .access_profile("caseworker")
            .unwrap()
            .select(["caseCode", "status"])
            .unwrap()
            .format(BRegRecordFormat::JsonLd);
        let request = BRegListRequest::default()
            .options(options)
            .filter("status eq 'open'")
            .unwrap()
            .orderby("openedOn desc")
            .unwrap()
            .top(50)
            .unwrap()
            .count(false);
        let query = breg_encoded_query(&request.query_pairs().unwrap());
        assert_eq!(
            query,
            "accessProfile=caseworker&$select=caseCode%2Cstatus&$filter=status%20eq%20%27open%27&$orderby=openedOn%20desc&$top=50&$count=false"
        );
        assert_eq!(
            request.record_options().format_value().media_type(),
            "application/ld+json"
        );
    }

    #[test]
    fn list_bounds_top_and_opaque_query_members_without_parsing_their_grammar() {
        assert!(BRegListRequest::default().top(1).is_ok());
        assert!(BRegListRequest::default().top(MAX_TOP).is_ok());
        assert!(BRegListRequest::default().top(0).is_err());
        assert!(BRegListRequest::default().top(MAX_TOP + 1).is_err());
        assert!(BRegListRequest::default().filter("not parsed here").is_ok());
        assert!(BRegListRequest::default().filter("").is_err());
        assert!(BRegListRequest::default().filter("field\nvalue").is_err());
        assert!(BRegListRequest::default().orderby("").is_err());
        assert!(BRegListRequest::default().orderby("field\rdesc").is_err());
    }

    #[test]
    fn bbox_preserves_exact_decimals_and_rejects_invalid_boundaries() {
        let bbox = BRegBoundingBox::new(
            "-0",
            "1e1",
            "0.30000000000000000000000000000000000001",
            "2.05e1",
        )
        .expect("exact bbox");
        assert_eq!(bbox.west(), "0");
        assert_eq!(bbox.south(), "10");
        assert_eq!(bbox.east(), "0.30000000000000000000000000000000000001");
        assert_eq!(bbox.north(), "20.5");
        let query = BRegListRequest::default().bbox(bbox).query_pairs().unwrap();
        assert_eq!(
            breg_encoded_query(&query),
            "bbox=0%2C10%2C0.30000000000000000000000000000000000001%2C20.5"
        );

        for coordinates in [
            ["1", "0", "0", "1"],
            ["0", "1", "1", "0"],
            ["-181", "0", "0", "1"],
            ["0", "0", "181", "1"],
            ["NaN", "0", "1", "1"],
            ["0", "0", "1e1001", "1"],
        ] {
            assert!(BRegBoundingBox::new(
                coordinates[0],
                coordinates[1],
                coordinates[2],
                coordinates[3]
            )
            .is_err());
        }
        assert!(BRegBoundingBox::new("1".repeat(257), "0", "1", "1").is_err());
        assert!(BRegBoundingBox::new("0", "0", "0", "0").is_ok());
    }

    #[test]
    fn proposal_history_cursor_is_get_only_and_positive() {
        assert!(BRegRecordOptions::default()
            .request_history_after_proposal_version(0)
            .is_err());
        let options = BRegRecordOptions::default()
            .request_history_after_proposal_version(u32::MAX)
            .unwrap();
        let mut pairs = Vec::new();
        options.append_get_query(&mut pairs);
        assert_eq!(
            breg_encoded_query(&pairs),
            "requestHistoryAfterProposalVersion=4294967295"
        );
        assert!(BRegListRequest::default()
            .options(options)
            .query_pairs()
            .is_err());
    }

    #[test]
    fn encoded_query_bound_counts_percent_encoding() {
        let request = BRegListRequest::default()
            .filter(" ".repeat(6_000))
            .expect("raw expression is within its input bound");
        assert!(request.query_pairs().is_err());
        assert_eq!(breg_encoded_query(&[]), "");
        assert_eq!(
            breg_encoded_query(&[("$filter".into(), "é +".into())]),
            "$filter=%C3%A9%20%2B"
        );
    }

    #[test]
    fn lookup_body_omits_values_for_verified_claim_selectors() {
        let request = BRegLookupRequest::new("by-verified-subject").unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&request.body().unwrap()).unwrap(),
            json!({"selector": "by-verified-subject"})
        );
    }

    #[test]
    fn request_origin_lookup_body_is_exact_bounded_and_canonical() {
        let request = BRegLookupRequest::new("by-case-and-year")
            .unwrap()
            .value("year", json!(2026))
            .unwrap()
            .value("caseCode", json!("A-42"))
            .unwrap();
        assert_eq!(
            String::from_utf8(request.body().unwrap()).unwrap(),
            r#"{"selector":"by-case-and-year","values":{"caseCode":"A-42","year":2026}}"#
        );
        assert!(request.clone().value("year", json!(2027)).is_err());
        let mut bounded = BRegLookupRequest::new("by-value").unwrap();
        for index in 0..MAX_LOOKUP_VALUES {
            bounded = bounded
                .value(format!("value{index}"), json!(index))
                .unwrap();
        }
        assert!(bounded.value("oneTooMany", json!(true)).is_err());
        for invalid in [json!(null), json!(1.5), json!([]), json!({"nested": true})] {
            assert!(BRegLookupRequest::new("by-value")
                .unwrap()
                .value("value", invalid)
                .is_err());
        }
        let oversized = BRegLookupRequest::new("by-value")
            .unwrap()
            .value("value", json!("x".repeat(MAX_LOOKUP_BODY_BYTES)))
            .unwrap();
        assert!(oversized.body().is_err());
    }

    #[test]
    fn continuation_preserves_request_and_collection_bindings() {
        let continuation = BRegContinuation::try_from_parts(
            "case-files",
            "opaque+/=token",
            BRegRecordFormat::JsonLd,
            Some("caseworker.v1".into()),
            &collection_meta(),
        )
        .unwrap();
        assert_eq!(continuation.route(), "case-files");
        assert_eq!(continuation.format(), BRegRecordFormat::JsonLd);
        assert_eq!(continuation.access_profile(), Some("caseworker.v1"));
        assert_eq!(
            breg_encoded_query(&continuation.query_pairs().unwrap()),
            "accessProfile=caseworker.v1&$skiptoken=opaque%2B%2F%3Dtoken"
        );
        assert_eq!(
            serde_json::to_value(&continuation).unwrap(),
            json!({
                "route": "case-files",
                "skiptoken": "opaque+/=token",
                "format": "json-ld",
                "accessProfile": "caseworker.v1",
                "registryIdentifier": "business-registry",
                "datasetIdentifier": "legal-entities",
                "entityTypeIdentifier": "company"
            })
        );
    }

    #[test]
    fn continuation_revalidates_persisted_untrusted_facts() {
        for token in ["", "token\n", &"x".repeat(MAX_SKIPTOKEN_BYTES + 1)] {
            assert!(BRegContinuation::try_from_parts(
                "cases",
                token,
                BRegRecordFormat::Json,
                None,
                &collection_meta(),
            )
            .is_err());
        }
        assert!(BRegContinuation::try_from_parts(
            "Cases",
            "token",
            BRegRecordFormat::Json,
            None,
            &collection_meta(),
        )
        .is_err());
        assert!(serde_json::from_value::<BRegContinuation>(json!({
            "route": "cases",
            "skiptoken": "token",
            "format": "json",
            "registryIdentifier": "business-registry",
            "datasetIdentifier": "legal-entities",
            "entityTypeIdentifier": "company",
            "firstPageFilter": "status eq 'secret'"
        }))
        .is_err());

        let mut invalid_meta = collection_meta();
        invalid_meta.registry_identifier = "Business-Registry".into();
        assert!(BRegContinuation::try_from_parts(
            "cases",
            "token",
            BRegRecordFormat::Json,
            None,
            &invalid_meta,
        )
        .is_err());
    }

    #[test]
    fn debug_output_does_not_render_request_facts_or_tokens() {
        let list = BRegListRequest::default()
            .options(
                BRegRecordOptions::default()
                    .access_profile("profile-canary")
                    .unwrap()
                    .select(["fieldCanary"])
                    .unwrap(),
            )
            .filter("secret eq 'filter-canary'")
            .unwrap()
            .orderby("orderingCanary")
            .unwrap();
        let lookup = BRegLookupRequest::new("selector-canary")
            .unwrap()
            .value("fieldCanary", json!("value-canary"))
            .unwrap();
        let continuation = BRegContinuation::try_from_parts(
            "route-canary",
            "token-canary",
            BRegRecordFormat::Json,
            Some("profile-canary".into()),
            &collection_meta(),
        )
        .unwrap();
        for debug in [
            format!("{list:?}"),
            format!("{lookup:?}"),
            format!("{continuation:?}"),
        ] {
            assert!(!debug.contains("canary"), "debug leaked: {debug}");
        }
    }
}
