// SPDX-License-Identifier: Apache-2.0

//! Bounded request facts for the Registry Server read surface.
//!
//! Registry Server and Relay deliberately have different query contracts. This
//! module mirrors the Server wire names and bounds without interpreting its
//! governed filter or ordering grammar in the client.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

const MAX_QUERY_PAYLOAD_BYTES: usize = 16 * 1024;
pub(crate) const MAX_SERVER_REQUEST_URI_BYTES: usize = 16 * 1024;
const MAX_LOOKUP_BODY_BYTES: usize = 16 * 1024;
const MAX_LOOKUP_VALUES: usize = 16;
const MAX_SELECTED_FIELDS: usize = 128;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_ROUTE_IDENTIFIER_BYTES: usize = 64;
const MAX_SKIPTOKEN_BYTES: usize = 4096;
const MAX_TOP: u32 = 100;

const INVALID_ACCESS_PROFILE: &str = "the Registry Server access profile identifier is invalid";
const INVALID_FIELD: &str = "a Registry Server selected field identifier is invalid";
const INVALID_FILTER: &str = "the Registry Server filter expression is invalid";
const INVALID_ORDERBY: &str = "the Registry Server ordering expression is invalid";
const INVALID_ROUTE: &str = "the Registry Server continuation route is invalid";
const INVALID_SELECTOR: &str = "the Registry Server lookup selector is invalid";
const INVALID_SKIPTOKEN: &str = "the Registry Server continuation token is invalid";

/// A value-free reason that a Registry Server request cannot be constructed.
///
/// The owning client error can preserve this closed static reason with
/// `RegistryServerClientError::invalid_request(error.reason())`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerRequestError {
    reason: &'static str,
}

impl ServerRequestError {
    const fn new(reason: &'static str) -> Self {
        Self { reason }
    }

    /// Return the closed, value-free failure reason.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for ServerRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason)
    }
}

impl std::error::Error for ServerRequestError {}

/// Shared Registry Record representations supported by this client slice.
///
/// Registry Server GeoJSON uses a separate response contract and is not a
/// Registry Record representation.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServerRecordFormat {
    /// `application/json` Registry Record response.
    #[default]
    Json,
    /// `application/ld+json` Registry Record response.
    JsonLd,
}

impl ServerRecordFormat {
    /// Exact media type sent in `Accept` and retained by continuations.
    #[must_use]
    pub const fn media_type(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::JsonLd => "application/ld+json",
        }
    }
}

/// Projection, authorization profile, and representation for one Server read.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ServerRecordOptions {
    select: Vec<String>,
    access_profile: Option<String>,
    format: ServerRecordFormat,
}

impl ServerRecordOptions {
    /// Select a nonempty, bounded set of unique API field names.
    pub fn select(
        mut self,
        fields: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, ServerRequestError> {
        let fields = fields.into_iter().map(Into::into).collect::<Vec<_>>();
        validate_selected_fields(&fields)?;
        self.select = fields;
        Ok(self)
    }

    /// Select one Registry Server access profile.
    pub fn access_profile(mut self, value: impl Into<String>) -> Result<Self, ServerRequestError> {
        let value = value.into();
        validate_access_profile(&value)?;
        self.access_profile = Some(value);
        Ok(self)
    }

    /// Select the shared Registry Record representation.
    #[must_use]
    pub fn format(mut self, value: ServerRecordFormat) -> Self {
        self.format = value;
        self
    }

    #[must_use]
    pub(crate) const fn format_value(&self) -> ServerRecordFormat {
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
}

impl fmt::Debug for ServerRecordOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerRecordOptions")
            .field("selected_field_count", &self.select.len())
            .field("access_profile_present", &self.access_profile.is_some())
            .field("format", &self.format)
            .finish()
    }
}

/// First-page facts for a Registry Server list operation.
///
/// Filter and ordering expressions remain opaque here. Registry Server parses
/// them against the selected compiled operation after authorization.
/// Continuations use [`ServerContinuation`], a distinct type with no first-page
/// setters.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ServerListRequest {
    options: ServerRecordOptions,
    top: Option<u32>,
    filter: Option<String>,
    orderby: Option<String>,
    count: Option<bool>,
}

impl ServerListRequest {
    /// Set projection, access profile, and representation options.
    #[must_use]
    pub fn options(mut self, options: ServerRecordOptions) -> Self {
        self.options = options;
        self
    }

    /// Set the requested page size, from one through the Server maximum of 100.
    pub fn top(mut self, value: u32) -> Result<Self, ServerRequestError> {
        if !(1..=MAX_TOP).contains(&value) {
            return Err(ServerRequestError::new(
                "Registry Server $top must be between 1 and 100",
            ));
        }
        self.top = Some(value);
        Ok(self)
    }

    /// Set a bounded opaque Registry Server `$filter` expression.
    pub fn filter(mut self, value: impl Into<String>) -> Result<Self, ServerRequestError> {
        let value = value.into();
        validate_opaque_query_member(&value, MAX_QUERY_PAYLOAD_BYTES, INVALID_FILTER)?;
        self.filter = Some(value);
        Ok(self)
    }

    /// Set a bounded opaque Registry Server `$orderby` expression.
    pub fn orderby(mut self, value: impl Into<String>) -> Result<Self, ServerRequestError> {
        let value = value.into();
        validate_opaque_query_member(&value, MAX_IDENTIFIER_BYTES, INVALID_ORDERBY)?;
        self.orderby = Some(value);
        Ok(self)
    }

    /// Ask the Server to include or explicitly omit the collection count.
    #[must_use]
    pub fn count(mut self, value: bool) -> Self {
        self.count = Some(value);
        self
    }

    pub(crate) fn query_pairs(&self) -> Result<Vec<(String, String)>, ServerRequestError> {
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
        ensure_query_bound(&pairs)?;
        Ok(pairs)
    }

    #[must_use]
    pub(crate) fn record_options(&self) -> &ServerRecordOptions {
        &self.options
    }
}

impl fmt::Debug for ServerListRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerListRequest")
            .field("options", &self.options)
            .field("top", &self.top)
            .field("filter_present", &self.filter.is_some())
            .field("orderby_present", &self.orderby.is_some())
            .field("count", &self.count)
            .finish()
    }
}

/// Registry Server lookup facts and Registry Record response options.
///
/// A lookup whose values originate in verified claims is represented by a
/// request with no calls to [`Self::value`], producing only `selector` in the
/// body. Request-origin selectors add the exact expected field/value members.
#[derive(Clone, PartialEq, Eq)]
pub struct ServerLookupRequest {
    selector: String,
    values: Option<BTreeMap<String, Value>>,
    options: ServerRecordOptions,
}

impl ServerLookupRequest {
    /// Construct a lookup for one compiled selector profile.
    pub fn new(selector: impl Into<String>) -> Result<Self, ServerRequestError> {
        let selector = selector.into();
        if !valid_compiled_identifier(&selector) {
            return Err(ServerRequestError::new(INVALID_SELECTOR));
        }
        Ok(Self {
            selector,
            values: None,
            options: ServerRecordOptions::default(),
        })
    }

    /// Set projection, access profile, and representation options.
    #[must_use]
    pub fn options(mut self, options: ServerRecordOptions) -> Self {
        self.options = options;
        self
    }

    /// Add one request-origin selector value.
    pub fn value(
        mut self,
        name: impl Into<String>,
        value: Value,
    ) -> Result<Self, ServerRequestError> {
        let name = name.into();
        if !valid_api_identifier(&name) {
            return Err(ServerRequestError::new(
                "a Registry Server lookup value field is invalid",
            ));
        }
        if !valid_lookup_value(&value) {
            return Err(ServerRequestError::new(
                "a Registry Server lookup value must be a bounded string, boolean, or integer",
            ));
        }
        let values = self.values.get_or_insert_with(BTreeMap::new);
        if values.contains_key(&name) {
            return Err(ServerRequestError::new(
                "a Registry Server lookup value field is duplicated",
            ));
        }
        if values.len() >= MAX_LOOKUP_VALUES {
            return Err(ServerRequestError::new(
                "a Registry Server lookup must not contain more than 16 values",
            ));
        }
        values.insert(name, value);
        Ok(self)
    }

    pub(crate) fn query_pairs(&self) -> Result<Vec<(String, String)>, ServerRequestError> {
        let mut pairs = Vec::new();
        self.options.append_query(&mut pairs);
        ensure_query_bound(&pairs)?;
        Ok(pairs)
    }

    pub(crate) fn body(&self) -> Result<Vec<u8>, ServerRequestError> {
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
            ServerRequestError::new("the Registry Server lookup body could not be serialized")
        })?;
        if body.len() > MAX_LOOKUP_BODY_BYTES {
            return Err(ServerRequestError::new(
                "the Registry Server lookup body exceeds 16384 bytes",
            ));
        }
        Ok(body)
    }

    #[must_use]
    pub(crate) fn record_options(&self) -> &ServerRecordOptions {
        &self.options
    }
}

impl fmt::Debug for ServerLookupRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerLookupRequest")
            .field("selector", &"<redacted>")
            .field(
                "value_count",
                &self.values.as_ref().map(BTreeMap::len).unwrap_or_default(),
            )
            .field("options", &self.options)
            .finish()
    }
}

/// Persistable, validated projection of a Registry Server continuation.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServerContinuationProjection {
    /// Logical Registry Server entity route segment.
    pub route: String,
    /// Opaque Registry Server `$skiptoken`.
    pub skiptoken: String,
    /// Representation selected for the original page.
    pub format: ServerRecordFormat,
    /// Access profile selected for the original page, when explicit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_profile: Option<String>,
}

impl fmt::Debug for ServerContinuationProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerContinuationProjection")
            .field("route", &"<redacted>")
            .field("skiptoken", &"<redacted>")
            .field("format", &self.format)
            .field("access_profile_present", &self.access_profile.is_some())
            .finish()
    }
}

/// Opaque Registry Server continuation bound to its route and representation.
///
/// Only continuation operations consume this type. It intentionally exposes no
/// `$select`, `$filter`, `$orderby`, `$top`, or `$count` setters, preventing a
/// cursor from being mixed with first-page facts.
#[derive(Clone, Eq, PartialEq)]
pub struct ServerContinuation {
    route: String,
    skiptoken: String,
    format: ServerRecordFormat,
    access_profile: Option<String>,
}

impl ServerContinuation {
    pub(crate) fn try_from_parts(
        route: impl Into<String>,
        skiptoken: impl Into<String>,
        format: ServerRecordFormat,
        access_profile: Option<String>,
    ) -> Result<Self, ServerRequestError> {
        Self::try_from_projection(ServerContinuationProjection {
            route: route.into(),
            skiptoken: skiptoken.into(),
            format,
            access_profile,
        })
    }

    /// Revalidate a persisted continuation before it can be used.
    pub fn try_from_projection(
        value: ServerContinuationProjection,
    ) -> Result<Self, ServerRequestError> {
        if !valid_compiled_identifier(&value.route) {
            return Err(ServerRequestError::new(INVALID_ROUTE));
        }
        validate_skiptoken(&value.skiptoken)?;
        if let Some(profile) = &value.access_profile {
            validate_access_profile(profile)?;
        }
        Ok(Self {
            route: value.route,
            skiptoken: value.skiptoken,
            format: value.format,
            access_profile: value.access_profile,
        })
    }

    /// Produce the inert serializable continuation projection.
    #[must_use]
    pub fn projection(&self) -> ServerContinuationProjection {
        ServerContinuationProjection {
            route: self.route.clone(),
            skiptoken: self.skiptoken.clone(),
            format: self.format,
            access_profile: self.access_profile.clone(),
        }
    }

    /// Logical Registry Server entity route selected for the original page.
    #[must_use]
    pub fn route(&self) -> &str {
        &self.route
    }

    /// Registry Record representation selected for the original page.
    #[must_use]
    pub const fn format(&self) -> ServerRecordFormat {
        self.format
    }

    /// Explicit access profile selected for the original page, when any.
    #[must_use]
    pub fn access_profile(&self) -> Option<&str> {
        self.access_profile.as_deref()
    }

    pub(crate) fn query_pairs(&self) -> Result<Vec<(String, String)>, ServerRequestError> {
        let mut pairs = Vec::with_capacity(2);
        if let Some(value) = &self.access_profile {
            pairs.push(("accessProfile".into(), value.clone()));
        }
        pairs.push(("$skiptoken".into(), self.skiptoken.clone()));
        ensure_query_bound(&pairs)?;
        Ok(pairs)
    }
}

impl fmt::Debug for ServerContinuation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerContinuation")
            .field("route", &"<redacted>")
            .field("skiptoken", &"<redacted>")
            .field("format", &self.format)
            .field("access_profile_present", &self.access_profile.is_some())
            .finish()
    }
}

impl Serialize for ServerContinuation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.projection().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ServerContinuation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::try_from_projection(ServerContinuationProjection::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

fn validate_selected_fields(fields: &[String]) -> Result<(), ServerRequestError> {
    if fields.is_empty() || fields.len() > MAX_SELECTED_FIELDS {
        return Err(ServerRequestError::new(
            "Registry Server $select must contain 1 to 128 fields",
        ));
    }
    let mut seen = BTreeSet::new();
    for field in fields {
        if !valid_api_identifier(field) {
            return Err(ServerRequestError::new(INVALID_FIELD));
        }
        if !seen.insert(field) {
            return Err(ServerRequestError::new(
                "a Registry Server selected field is duplicated",
            ));
        }
    }
    Ok(())
}

fn validate_access_profile(value: &str) -> Result<(), ServerRequestError> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(ServerRequestError::new(INVALID_ACCESS_PROFILE));
    };
    if value.len() > MAX_IDENTIFIER_BYTES
        || !(first.is_ascii_lowercase() || first == b'_')
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        return Err(ServerRequestError::new(INVALID_ACCESS_PROFILE));
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
) -> Result<(), ServerRequestError> {
    if value.is_empty()
        || value.len() > maximum_bytes
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ServerRequestError::new(reason));
    }
    Ok(())
}

fn validate_skiptoken(value: &str) -> Result<(), ServerRequestError> {
    if value.is_empty()
        || value.len() > MAX_SKIPTOKEN_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ServerRequestError::new(INVALID_SKIPTOKEN));
    }
    Ok(())
}

fn ensure_query_bound(pairs: &[(String, String)]) -> Result<(), ServerRequestError> {
    if server_encoded_query(pairs).len() > MAX_QUERY_PAYLOAD_BYTES {
        return Err(ServerRequestError::new(
            "the Registry Server query exceeds 16384 encoded bytes",
        ));
    }
    Ok(())
}

/// Encode a deterministic Registry Server query using RFC 3986 unreserved
/// bytes and uppercase hexadecimal escapes. Pair order is preserved.
pub(crate) fn server_encoded_query(pairs: &[(String, String)]) -> String {
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

    #[test]
    fn access_profile_matches_the_server_config_identifier_grammar() {
        for valid in [
            "reader",
            "_reader",
            "reader.v1",
            "reader_1",
            "reader-one",
            &"a".repeat(MAX_IDENTIFIER_BYTES),
        ] {
            assert!(
                ServerRecordOptions::default().access_profile(valid).is_ok(),
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
                ServerRecordOptions::default()
                    .access_profile(invalid)
                    .is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn select_is_bounded_unique_and_uses_server_api_identifiers() {
        assert!(ServerRecordOptions::default()
            .select(["caseCode", "opened-on", "_internal.v1"])
            .is_ok());
        assert!(ServerRecordOptions::default()
            .select(std::iter::empty::<&str>())
            .is_err());
        assert!(ServerRecordOptions::default()
            .select(["caseCode", "caseCode"])
            .is_err());
        assert!(ServerRecordOptions::default().select(["CaseCode"]).is_err());
        assert!(ServerRecordOptions::default()
            .select(["case/code"])
            .is_err());
        assert!(ServerRecordOptions::default()
            .select((0..=MAX_SELECTED_FIELDS).map(|index| format!("field{index}")))
            .is_err());
    }

    #[test]
    fn list_query_is_canonical_and_matches_server_wire_names() {
        let options = ServerRecordOptions::default()
            .access_profile("caseworker")
            .unwrap()
            .select(["caseCode", "status"])
            .unwrap()
            .format(ServerRecordFormat::JsonLd);
        let request = ServerListRequest::default()
            .options(options)
            .filter("status eq 'open'")
            .unwrap()
            .orderby("openedOn desc")
            .unwrap()
            .top(50)
            .unwrap()
            .count(false);
        let query = server_encoded_query(&request.query_pairs().unwrap());
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
        assert!(ServerListRequest::default().top(1).is_ok());
        assert!(ServerListRequest::default().top(MAX_TOP).is_ok());
        assert!(ServerListRequest::default().top(0).is_err());
        assert!(ServerListRequest::default().top(MAX_TOP + 1).is_err());
        assert!(ServerListRequest::default()
            .filter("not parsed here")
            .is_ok());
        assert!(ServerListRequest::default().filter("").is_err());
        assert!(ServerListRequest::default().filter("field\nvalue").is_err());
        assert!(ServerListRequest::default().orderby("").is_err());
        assert!(ServerListRequest::default().orderby("field\rdesc").is_err());
    }

    #[test]
    fn encoded_query_bound_counts_percent_encoding() {
        let request = ServerListRequest::default()
            .filter(" ".repeat(6_000))
            .expect("raw expression is within its input bound");
        assert!(request.query_pairs().is_err());
        assert_eq!(server_encoded_query(&[]), "");
        assert_eq!(
            server_encoded_query(&[("$filter".into(), "é +".into())]),
            "$filter=%C3%A9%20%2B"
        );
    }

    #[test]
    fn lookup_body_omits_values_for_verified_claim_selectors() {
        let request = ServerLookupRequest::new("by-verified-subject").unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&request.body().unwrap()).unwrap(),
            json!({"selector": "by-verified-subject"})
        );
    }

    #[test]
    fn request_origin_lookup_body_is_exact_bounded_and_canonical() {
        let request = ServerLookupRequest::new("by-case-and-year")
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
        let mut bounded = ServerLookupRequest::new("by-value").unwrap();
        for index in 0..MAX_LOOKUP_VALUES {
            bounded = bounded
                .value(format!("value{index}"), json!(index))
                .unwrap();
        }
        assert!(bounded.value("oneTooMany", json!(true)).is_err());
        for invalid in [json!(null), json!(1.5), json!([]), json!({"nested": true})] {
            assert!(ServerLookupRequest::new("by-value")
                .unwrap()
                .value("value", invalid)
                .is_err());
        }
        let oversized = ServerLookupRequest::new("by-value")
            .unwrap()
            .value("value", json!("x".repeat(MAX_LOOKUP_BODY_BYTES)))
            .unwrap();
        assert!(oversized.body().is_err());
    }

    #[test]
    fn continuation_preserves_route_format_and_access_profile_only() {
        let continuation = ServerContinuation::try_from_parts(
            "case-files",
            "opaque+/=token",
            ServerRecordFormat::JsonLd,
            Some("caseworker.v1".into()),
        )
        .unwrap();
        assert_eq!(continuation.route(), "case-files");
        assert_eq!(continuation.format(), ServerRecordFormat::JsonLd);
        assert_eq!(continuation.access_profile(), Some("caseworker.v1"));
        assert_eq!(
            server_encoded_query(&continuation.query_pairs().unwrap()),
            "accessProfile=caseworker.v1&$skiptoken=opaque%2B%2F%3Dtoken"
        );
        assert_eq!(
            serde_json::to_value(&continuation).unwrap(),
            json!({
                "route": "case-files",
                "skiptoken": "opaque+/=token",
                "format": "json-ld",
                "accessProfile": "caseworker.v1"
            })
        );
    }

    #[test]
    fn continuation_revalidates_persisted_untrusted_facts() {
        for token in ["", "token\n", &"x".repeat(MAX_SKIPTOKEN_BYTES + 1)] {
            assert!(ServerContinuation::try_from_parts(
                "cases",
                token,
                ServerRecordFormat::Json,
                None,
            )
            .is_err());
        }
        assert!(ServerContinuation::try_from_parts(
            "Cases",
            "token",
            ServerRecordFormat::Json,
            None,
        )
        .is_err());
        assert!(serde_json::from_value::<ServerContinuation>(json!({
            "route": "cases",
            "skiptoken": "token",
            "format": "json",
            "firstPageFilter": "status eq 'secret'"
        }))
        .is_err());
    }

    #[test]
    fn debug_output_does_not_render_request_facts_or_tokens() {
        let list = ServerListRequest::default()
            .options(
                ServerRecordOptions::default()
                    .access_profile("profile-canary")
                    .unwrap()
                    .select(["fieldCanary"])
                    .unwrap(),
            )
            .filter("secret eq 'filter-canary'")
            .unwrap()
            .orderby("orderingCanary")
            .unwrap();
        let lookup = ServerLookupRequest::new("selector-canary")
            .unwrap()
            .value("fieldCanary", json!("value-canary"))
            .unwrap();
        let continuation = ServerContinuation::try_from_parts(
            "route-canary",
            "token-canary",
            ServerRecordFormat::Json,
            Some("profile-canary".into()),
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
