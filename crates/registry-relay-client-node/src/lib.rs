// SPDX-License-Identifier: Apache-2.0
//! Node.js binding for the canonical Registry Relay V2 client.

#![deny(unsafe_code)]

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use napi::{
    bindgen_prelude::{Buffer, Either},
    Error as NapiError, Result,
};
use napi_derive::napi;
use registry_platform_crypto::PrivateJwk;
use registry_relay_client::{
    BoundingBox, CollectionContinuation, CollectionContinuationProjection, CollectionPage,
    CollectionRouteProjection, Complete, Conditional, ListRequest, LookupRequest, NotModified,
    PrivateKeyJwt, PrivateKeyJwtConfig, ProtocolFailure, RawDocument, RecordFormat, RecordOptions,
    RelayClient as CoreClient, RelayClientConfig, RelayClientError, ResourceContinuation,
    ResourceContinuationProjection, ResourceListRequest, ResourcePage, ResponseMetadata,
    SdmxDataFormat, SdmxDataRequest, SdmxStructureKind, SdmxStructureRequest, SearchRequest,
    StaticToken, StrongEtag, TokenError, TokenProvider,
};
use serde::Serialize;
use serde_json::{json, Map, Value};
use url::Url;

type JsonOutcome = Either<CompleteOutcome, NotModifiedOutcome>;
type ResourceOutcome = Either<ResourcePageOutcome, NotModifiedOutcome>;
type CollectionOutcome = Either<CollectionPageOutcome, NotModifiedOutcome>;
type RawOutcome = Either<RawCompleteOutcome, NotModifiedOutcome>;

const MAXIMUM_JAVASCRIPT_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[napi(object)]
pub struct CompleteOutcome {
    pub kind: String,
    pub value: Value,
    pub trace_id: String,
    pub etag: Option<String>,
}

#[napi(object)]
pub struct ResourcePageOutcome {
    pub kind: String,
    pub value: Value,
    pub continuation: Option<Value>,
    pub trace_id: String,
    pub etag: Option<String>,
}

#[napi(object)]
pub struct CollectionPageOutcome {
    pub kind: String,
    pub value: Value,
    pub continuation: Option<Value>,
    pub trace_id: String,
    pub etag: Option<String>,
}

#[napi(object)]
pub struct RawCompleteOutcome {
    pub kind: String,
    pub body: Buffer,
    pub media_type: String,
    pub trace_id: String,
    pub etag: Option<String>,
}

#[napi(object)]
pub struct NotModifiedOutcome {
    pub kind: String,
    pub etag: String,
    pub trace_id: String,
}

fn mapped_error(value: Value) -> NapiError {
    NapiError::from_reason(serde_json::to_string(&value).unwrap_or_else(|_| {
        r#"{"kind":"protocol","message":"the failure could not be described"}"#.to_owned()
    }))
}

fn binding_error(kind: &'static str, message: &'static str) -> NapiError {
    mapped_error(json!({"kind": kind, "message": message}))
}

fn protocol_code(value: ProtocolFailure) -> &'static str {
    match value {
        ProtocolFailure::HeaderBounds => "header_bounds",
        ProtocolFailure::TraceContext => "trace_context",
        ProtocolFailure::MediaType => "media_type",
        ProtocolFailure::Body => "body",
        ProtocolFailure::Problem => "problem",
        ProtocolFailure::EntityTag => "entity_tag",
        ProtocolFailure::NotModifiedBody => "not_modified_body",
        ProtocolFailure::Status => "status",
        _ => "protocol",
    }
}

fn client_error(error: RelayClientError) -> NapiError {
    let value = match error {
        RelayClientError::Configuration { reason } => {
            json!({"kind": "configuration", "message": reason})
        }
        RelayClientError::InvalidRequest { reason } => {
            json!({"kind": "invalid_request", "message": reason})
        }
        RelayClientError::Transport { kind } => {
            json!({"kind": "transport", "transportKind": kind.kind(), "message": "Relay exchange did not complete"})
        }
        RelayClientError::Problem {
            status,
            code,
            trace_id,
            retry_after_seconds,
        } => json!({
            "kind": "problem",
            "status": status,
            "code": code.code(),
            "traceId": trace_id.as_str(),
            "retryAfterSeconds": retry_after_seconds,
            "message": "Relay refused the request"
        }),
        RelayClientError::Protocol {
            status,
            failure,
            trace_id,
        } => json!({
            "kind": "protocol",
            "status": status,
            "code": protocol_code(failure),
            "traceId": trace_id.map(|value| value.as_str().to_owned()),
            "message": failure.to_string()
        }),
        RelayClientError::Token(error) => token_error_value(error),
        _ => json!({"kind": "client", "message": "Relay client returned an unsupported failure"}),
    };
    mapped_error(value)
}

fn token_error_value(error: TokenError) -> Value {
    let mut value = json!({
        "kind": "token",
        "tokenKind": error.kind(),
        "message": error.to_string()
    });
    let object = value
        .as_object_mut()
        .expect("the token error envelope is an object");
    match error {
        TokenError::Transport { kind } => {
            object.insert("transportKind".into(), Value::String(kind.kind().into()));
        }
        TokenError::Refused { code } => {
            object.insert("code".into(), Value::String(code.as_str().into()));
        }
        TokenError::Protocol { status } => {
            object.insert("status".into(), Value::from(status));
        }
        _ => {}
    }
    value
}

fn serialization_error() -> NapiError {
    binding_error(
        "protocol",
        "a Relay client result could not be represented for JavaScript",
    )
}

fn required_object<'a>(value: &'a Value, what: &'static str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| binding_error("configuration", what))
}

fn only_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    kind: &'static str,
    message: &'static str,
) -> Result<()> {
    if object
        .keys()
        .any(|field| !allowed.contains(&field.as_str()))
    {
        return Err(binding_error(kind, message));
    }
    Ok(())
}

fn required_string(
    object: &Map<String, Value>,
    field: &str,
    kind: &'static str,
    message: &'static str,
) -> Result<String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| binding_error(kind, message))
}

fn optional_string(
    object: &Map<String, Value>,
    field: &str,
    kind: &'static str,
    message: &'static str,
) -> Result<Option<String>> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(binding_error(kind, message)),
    }
}

fn bounded_safe_integer(
    value: &Value,
    minimum: i64,
    maximum: i64,
    kind: &'static str,
    message: &'static str,
) -> Result<i64> {
    debug_assert!(minimum >= -MAXIMUM_JAVASCRIPT_SAFE_INTEGER);
    debug_assert!(maximum <= MAXIMUM_JAVASCRIPT_SAFE_INTEGER);

    let invalid = || binding_error(kind, message);
    let Value::Number(number) = value else {
        return Err(invalid());
    };
    let integer = if let Some(integer) = number.as_i64() {
        integer
    } else {
        let number = number.as_f64().ok_or_else(&invalid)?;
        if !number.is_finite()
            || number.fract() != 0.0
            || !(-(MAXIMUM_JAVASCRIPT_SAFE_INTEGER as f64)..=MAXIMUM_JAVASCRIPT_SAFE_INTEGER as f64)
                .contains(&number)
        {
            return Err(invalid());
        }
        number as i64
    };
    if !(minimum..=maximum).contains(&integer) {
        return Err(invalid());
    }
    Ok(integer)
}

fn optional_u64(
    object: &Map<String, Value>,
    field: &str,
    kind: &'static str,
    message: &'static str,
) -> Result<Option<u64>> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            bounded_safe_integer(value, 0, MAXIMUM_JAVASCRIPT_SAFE_INTEGER, kind, message)
                .map(|value| Some(value as u64))
        }
    }
}

fn optional_i64(
    object: &Map<String, Value>,
    field: &str,
    message: &'static str,
) -> Result<Option<i64>> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => bounded_safe_integer(
            value,
            -MAXIMUM_JAVASCRIPT_SAFE_INTEGER,
            MAXIMUM_JAVASCRIPT_SAFE_INTEGER,
            "configuration",
            message,
        )
        .map(Some),
    }
}

fn private_key_jwt(value: &Value) -> Result<PrivateKeyJwt> {
    let object = required_object(value, "authorization.privateKeyJwt must be an object")?;
    only_fields(
        object,
        &[
            "tokenEndpoint",
            "clientId",
            "clientKey",
            "audience",
            "assertionLifetimeSeconds",
            "refreshMarginSeconds",
            "requestTimeoutMilliseconds",
            "connectTimeoutMilliseconds",
            "userAgent",
            "trustedRootCertificates",
        ],
        "configuration",
        "authorization.privateKeyJwt contains an unsupported field",
    )?;
    let endpoint = required_string(
        object,
        "tokenEndpoint",
        "configuration",
        "authorization.privateKeyJwt.tokenEndpoint must be a string",
    )?;
    let endpoint = Url::parse(&endpoint).map_err(|_| {
        binding_error(
            "configuration",
            "authorization.privateKeyJwt.tokenEndpoint must be a URL",
        )
    })?;
    let client_id = required_string(
        object,
        "clientId",
        "configuration",
        "authorization.privateKeyJwt.clientId must be a string",
    )?;
    let key = object.get("clientKey").ok_or_else(|| {
        binding_error(
            "configuration",
            "authorization.privateKeyJwt.clientKey must be present",
        )
    })?;
    let key = serde_json::to_string(key).map_err(|_| {
        binding_error(
            "configuration",
            "authorization.privateKeyJwt.clientKey is invalid",
        )
    })?;
    let key = PrivateJwk::parse(&key).map_err(|_| {
        binding_error(
            "configuration",
            "authorization.privateKeyJwt.clientKey is invalid",
        )
    })?;

    let mut config = PrivateKeyJwtConfig::new(endpoint, client_id, key);
    if let Some(value) = optional_string(
        object,
        "audience",
        "configuration",
        "authorization.privateKeyJwt.audience must be a string",
    )? {
        config = config.with_audience(value);
    }
    if let Some(value) = optional_i64(
        object,
        "assertionLifetimeSeconds",
        "authorization.privateKeyJwt.assertionLifetimeSeconds must be an integer",
    )? {
        config = config.with_assertion_lifetime_seconds(value);
    }
    if let Some(value) = optional_i64(
        object,
        "refreshMarginSeconds",
        "authorization.privateKeyJwt.refreshMarginSeconds must be an integer",
    )? {
        config = config.with_refresh_margin_seconds(value);
    }
    if let Some(value) = optional_u64(
        object,
        "requestTimeoutMilliseconds",
        "configuration",
        "authorization.privateKeyJwt.requestTimeoutMilliseconds must be a non-negative integer",
    )? {
        config = config.with_request_timeout(Duration::from_millis(value));
    }
    if let Some(value) = optional_u64(
        object,
        "connectTimeoutMilliseconds",
        "configuration",
        "authorization.privateKeyJwt.connectTimeoutMilliseconds must be a non-negative integer",
    )? {
        config = config.with_connect_timeout(Duration::from_millis(value));
    }
    if let Some(value) = optional_string(
        object,
        "userAgent",
        "configuration",
        "authorization.privateKeyJwt.userAgent must be a string",
    )? {
        config = config.with_user_agent(value);
    }
    if let Some(value) = optional_string(
        object,
        "trustedRootCertificates",
        "configuration",
        "authorization.privateKeyJwt.trustedRootCertificates must be a string",
    )? {
        config = config.with_trusted_root_certificates(value.into_bytes());
    }
    PrivateKeyJwt::new(config).map_err(|error| mapped_error(token_error_value(error)))
}

fn authorization_provider(value: &Value) -> Result<Option<Arc<dyn TokenProvider>>> {
    if value.is_null() {
        return Ok(None);
    }
    let object = required_object(value, "authorization must be an object")?;
    if object.len() != 1 {
        return Err(binding_error(
            "configuration",
            "authorization must contain exactly one of static or privateKeyJwt",
        ));
    }
    if let Some(value) = object.get("static") {
        let token = value.as_str().ok_or_else(|| {
            binding_error("configuration", "authorization.static must be a string")
        })?;
        return StaticToken::new(token)
            .map(|provider| Some(Arc::new(provider) as Arc<dyn TokenProvider>))
            .map_err(|error| mapped_error(token_error_value(error)));
    }
    if let Some(value) = object.get("privateKeyJwt") {
        return private_key_jwt(value)
            .map(|provider| Some(Arc::new(provider) as Arc<dyn TokenProvider>));
    }
    Err(binding_error(
        "configuration",
        "authorization must contain exactly one of static or privateKeyJwt",
    ))
}

fn config(value: Value) -> Result<CoreClient> {
    let object = required_object(&value, "client configuration must be an object")?;
    only_fields(
        object,
        &[
            "baseUrl",
            "authorization",
            "requestTimeoutMilliseconds",
            "connectTimeoutMilliseconds",
            "maxResponseBytes",
            "userAgent",
            "trustedRootCertificates",
        ],
        "configuration",
        "client configuration contains an unsupported field",
    )?;
    let base_url = required_string(
        object,
        "baseUrl",
        "configuration",
        "baseUrl must be a string",
    )?;
    let base_url = Url::parse(&base_url)
        .map_err(|_| binding_error("configuration", "baseUrl must be a URL"))?;
    let mut config = RelayClientConfig::new(base_url);
    if let Some(value) = object.get("authorization") {
        if let Some(provider) = authorization_provider(value)? {
            config = config.with_token_provider(provider);
        }
    }
    if let Some(value) = optional_u64(
        object,
        "requestTimeoutMilliseconds",
        "configuration",
        "requestTimeoutMilliseconds must be a non-negative integer",
    )? {
        config = config.with_request_timeout(Duration::from_millis(value));
    }
    if let Some(value) = optional_u64(
        object,
        "connectTimeoutMilliseconds",
        "configuration",
        "connectTimeoutMilliseconds must be a non-negative integer",
    )? {
        config = config.with_connect_timeout(Duration::from_millis(value));
    }
    if let Some(value) = optional_u64(
        object,
        "maxResponseBytes",
        "configuration",
        "maxResponseBytes must be a non-negative integer",
    )? {
        config = config.with_max_response_bytes(value);
    }
    if let Some(value) = optional_string(
        object,
        "userAgent",
        "configuration",
        "userAgent must be a string",
    )? {
        config = config.with_user_agent(value);
    }
    if let Some(value) = optional_string(
        object,
        "trustedRootCertificates",
        "configuration",
        "trustedRootCertificates must be a string",
    )? {
        config = config.with_trusted_root_certificates(value.into_bytes());
    }
    CoreClient::new(config).map_err(client_error)
}

fn parse_etag(value: Option<String>) -> Result<Option<StrongEtag>> {
    value
        .as_deref()
        .map(StrongEtag::parse)
        .transpose()
        .map_err(|_| {
            binding_error(
                "invalid_request",
                "etag must be a strong quoted SHA-256 entity tag",
            )
        })
}

fn metadata_parts(metadata: &ResponseMetadata) -> (String, Option<String>) {
    (
        metadata.trace_id().as_str().to_owned(),
        metadata.etag().map(|value| value.as_str().to_owned()),
    )
}

fn complete_value<T: Serialize>(
    value: T,
    metadata_value: ResponseMetadata,
) -> Result<CompleteOutcome> {
    let (trace_id, etag) = metadata_parts(&metadata_value);
    Ok(CompleteOutcome {
        kind: "complete".into(),
        value: serde_json::to_value(value).map_err(|_| serialization_error())?,
        trace_id,
        etag,
    })
}

fn not_modified(value: NotModified) -> NotModifiedOutcome {
    NotModifiedOutcome {
        kind: "notModified".into(),
        etag: value.etag.as_str().to_owned(),
        trace_id: value.trace_id.as_str().to_owned(),
    }
}

fn conditional_value<T: Serialize>(value: Conditional<T>) -> Result<JsonOutcome> {
    match value {
        Conditional::Complete(Complete { value, metadata }) => {
            complete_value(value, metadata).map(Either::A)
        }
        Conditional::NotModified(value) => Ok(Either::B(not_modified(value))),
    }
}

fn resource_page<T: Serialize>(value: Conditional<ResourcePage<T>>) -> Result<ResourceOutcome> {
    match value {
        Conditional::NotModified(value) => Ok(Either::B(not_modified(value))),
        Conditional::Complete(Complete { value, metadata }) => {
            let (trace_id, etag) = metadata_parts(&metadata);
            Ok(Either::A(ResourcePageOutcome {
                kind: "complete".into(),
                value: serde_json::to_value(value.value).map_err(|_| serialization_error())?,
                continuation: value
                    .continuation
                    .map(|value| serde_json::to_value(value.projection()))
                    .transpose()
                    .map_err(|_| serialization_error())?,
                trace_id,
                etag,
            }))
        }
    }
}

fn collection_page<T: Serialize>(
    value: Conditional<CollectionPage<T>>,
) -> Result<CollectionOutcome> {
    match value {
        Conditional::NotModified(value) => Ok(Either::B(not_modified(value))),
        Conditional::Complete(Complete { value, metadata }) => {
            let (trace_id, etag) = metadata_parts(&metadata);
            let continuation = value
                .continuation
                .map(|value| serde_json::to_value(value.projection()))
                .transpose()
                .map_err(|_| serialization_error())?;
            Ok(Either::A(CollectionPageOutcome {
                kind: "complete".into(),
                value: serde_json::to_value(value.value).map_err(|_| serialization_error())?,
                continuation,
                trace_id,
                etag,
            }))
        }
    }
}

fn conditional_raw(value: Conditional<RawDocument>) -> RawOutcome {
    match value {
        Conditional::NotModified(value) => Either::B(not_modified(value)),
        Conditional::Complete(Complete { value, metadata }) => {
            let (trace_id, etag) = metadata_parts(&metadata);
            Either::A(RawCompleteOutcome {
                kind: "complete".into(),
                body: value.as_bytes().to_vec().into(),
                media_type: value.media_type().to_owned(),
                trace_id,
                etag,
            })
        }
    }
}

fn request_object(
    value: Option<Value>,
    allowed: &[&str],
    message: &'static str,
) -> Result<Map<String, Value>> {
    match value {
        None | Some(Value::Null) => Ok(Map::new()),
        Some(Value::Object(object)) => {
            only_fields(&object, allowed, "invalid_request", message)?;
            Ok(object)
        }
        Some(_) => Err(binding_error("invalid_request", message)),
    }
}

fn record_format(value: Option<String>) -> Result<RecordFormat> {
    match value.as_deref().unwrap_or("json") {
        "json" => Ok(RecordFormat::Json),
        "json-ld" => Ok(RecordFormat::JsonLd),
        "geojson" | "geo-json-rfc7946" => Ok(RecordFormat::GeoJsonRfc7946),
        "json-fg" => Ok(RecordFormat::JsonFg),
        _ => Err(binding_error(
            "invalid_request",
            "format must be json, json-ld, geojson, or json-fg",
        )),
    }
}

fn request_optional_string(
    object: &Map<String, Value>,
    field: &str,
    message: &'static str,
) -> Result<Option<String>> {
    optional_string(object, field, "invalid_request", message)
}

fn request_optional_u32(
    object: &Map<String, Value>,
    field: &str,
    message: &'static str,
) -> Result<Option<u32>> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            bounded_safe_integer(value, 0, i64::from(u32::MAX), "invalid_request", message)
                .map(|value| Some(value as u32))
        }
    }
}

fn string_array(
    object: &Map<String, Value>,
    field: &str,
    message: &'static str,
) -> Result<Option<Vec<String>>> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| value.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
            .map(Some)
            .ok_or_else(|| binding_error("invalid_request", message)),
        Some(_) => Err(binding_error("invalid_request", message)),
    }
}

fn string_map(
    object: &Map<String, Value>,
    field: &str,
    message: &'static str,
) -> Result<BTreeMap<String, String>> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(BTreeMap::new()),
        Some(Value::Object(values)) => values
            .iter()
            .map(|(name, value)| {
                value
                    .as_str()
                    .map(|value| (name.clone(), value.to_owned()))
                    .ok_or_else(|| binding_error("invalid_request", message))
            })
            .collect(),
        Some(_) => Err(binding_error("invalid_request", message)),
    }
}

fn record_options(object: &Map<String, Value>) -> Result<RecordOptions> {
    let format = record_format(request_optional_string(
        object,
        "format",
        "format must be a string",
    )?)?;
    let mut options = RecordOptions::default().format(format);
    if let Some(fields) = string_array(object, "fields", "fields must be an array of strings")? {
        options = options.fields(fields).map_err(client_error)?;
    }
    if let Some(value) =
        request_optional_string(object, "accessProfile", "accessProfile must be a string")?
    {
        options = options.access_profile(value).map_err(client_error)?;
    }
    Ok(options)
}

fn list_request(value: Option<Value>) -> Result<ListRequest> {
    let object = request_object(
        value,
        &["pageSize", "fields", "accessProfile", "format", "filters"],
        "list options must be an object with supported fields",
    )?;
    let mut request = ListRequest::default().options(record_options(&object)?);
    if let Some(value) = request_optional_u32(
        &object,
        "pageSize",
        "pageSize must be a non-negative integer",
    )? {
        request = request.page_size(value).map_err(client_error)?;
    }
    for (name, value) in string_map(&object, "filters", "filters must map strings to strings")? {
        request = request.filter(name, value).map_err(client_error)?;
    }
    Ok(request)
}

fn search_request(value: Value) -> Result<SearchRequest> {
    let object = request_object(
        Some(value),
        &["pageSize", "fields", "accessProfile", "format", "bbox"],
        "search options must be an object with supported fields",
    )?;
    let values = object
        .get("bbox")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            binding_error(
                "invalid_request",
                "search options must include bbox as an array of four numbers",
            )
        })?;
    let numbers = values
        .iter()
        .map(Value::as_f64)
        .collect::<Option<Vec<_>>>()
        .filter(|values| values.len() == 4)
        .ok_or_else(|| {
            binding_error(
                "invalid_request",
                "search options must include bbox as an array of four numbers",
            )
        })?;
    let bbox =
        BoundingBox::new(numbers[0], numbers[1], numbers[2], numbers[3]).map_err(client_error)?;
    let mut request = SearchRequest::new(bbox).options(record_options(&object)?);
    if let Some(value) = request_optional_u32(
        &object,
        "pageSize",
        "pageSize must be a non-negative integer",
    )? {
        request = request.page_size(value).map_err(client_error)?;
    }
    Ok(request)
}

fn record_options_request(value: Option<Value>) -> Result<RecordOptions> {
    let object = request_object(
        value,
        &["fields", "accessProfile", "format"],
        "record options must be an object with supported fields",
    )?;
    record_options(&object)
}

fn lookup_selector_value(value: &Value) -> Result<Value> {
    if !value.is_number() {
        return Ok(value.clone());
    }
    bounded_safe_integer(
        value,
        -MAXIMUM_JAVASCRIPT_SAFE_INTEGER,
        MAXIMUM_JAVASCRIPT_SAFE_INTEGER,
        "invalid_request",
        "a lookup selector value is invalid",
    )
    .map(Value::from)
}

fn collection_continuation(value: Value, expected: &'static str) -> Result<CollectionContinuation> {
    let object = value
        .as_object()
        .ok_or_else(|| binding_error("invalid_request", "continuation must be an object"))?;
    only_fields(
        object,
        &["route", "cursor", "format", "accessProfile"],
        "invalid_request",
        "continuation is invalid",
    )?;
    let projection: CollectionContinuationProjection = serde_json::from_value(value)
        .map_err(|_| binding_error("invalid_request", "continuation is invalid"))?;
    let matches = matches!(
        (&projection.route, expected),
        (CollectionRouteProjection::Records { .. }, "records")
            | (CollectionRouteProjection::Search { .. }, "search")
    );
    if !matches {
        return Err(binding_error(
            "invalid_request",
            "continuation does not match the method that consumes it",
        ));
    }
    CollectionContinuation::try_from_projection(projection).map_err(client_error)
}

fn resource_continuation(value: Value) -> Result<ResourceContinuation> {
    let object = value
        .as_object()
        .ok_or_else(|| binding_error("invalid_request", "resource continuation is invalid"))?;
    only_fields(
        object,
        &["cursor"],
        "invalid_request",
        "resource continuation is invalid",
    )?;
    let projection: ResourceContinuationProjection = serde_json::from_value(value)
        .map_err(|_| binding_error("invalid_request", "resource continuation is invalid"))?;
    ResourceContinuation::try_from_projection(projection).map_err(client_error)
}

#[napi]
pub struct RelayClient {
    inner: Arc<CoreClient>,
}

#[napi]
impl RelayClient {
    #[napi(constructor)]
    pub fn new(config_value: Value) -> Result<Self> {
        Ok(Self {
            inner: Arc::new(config(config_value)?),
        })
    }

    #[napi]
    pub async fn health(&self) -> Result<CompleteOutcome> {
        let Complete { value, metadata } = self.inner.health().await.map_err(client_error)?;
        complete_value(value, metadata)
    }

    #[napi]
    pub async fn ready(&self) -> Result<CompleteOutcome> {
        let Complete { value, metadata } = self.inner.ready().await.map_err(client_error)?;
        complete_value(value, metadata)
    }

    #[napi]
    pub async fn openapi(
        &self,
        etag: Option<String>,
    ) -> Result<Either<RawCompleteOutcome, NotModifiedOutcome>> {
        let etag = parse_etag(etag)?;
        Ok(conditional_raw(
            self.inner
                .openapi(etag.as_ref())
                .await
                .map_err(client_error)?,
        ))
    }

    #[napi]
    pub async fn service_metadata(
        &self,
        etag: Option<String>,
    ) -> Result<Either<CompleteOutcome, NotModifiedOutcome>> {
        let etag = parse_etag(etag)?;
        conditional_value(
            self.inner
                .service_metadata(etag.as_ref())
                .await
                .map_err(client_error)?,
        )
    }

    #[napi]
    pub async fn resources(
        &self,
        options: Option<Value>,
        etag: Option<String>,
    ) -> Result<Either<ResourcePageOutcome, NotModifiedOutcome>> {
        let object = request_object(
            options,
            &["pageSize"],
            "resource list options must contain only pageSize",
        )?;
        let mut request = ResourceListRequest::default();
        if let Some(value) = request_optional_u32(
            &object,
            "pageSize",
            "pageSize must be a non-negative integer",
        )? {
            request = request.page_size(value).map_err(client_error)?;
        }
        let etag = parse_etag(etag)?;
        resource_page(
            self.inner
                .resources(request, etag.as_ref())
                .await
                .map_err(client_error)?,
        )
    }

    #[napi]
    pub async fn continue_resources(
        &self,
        continuation: Value,
        etag: Option<String>,
    ) -> Result<Either<ResourcePageOutcome, NotModifiedOutcome>> {
        let continuation = resource_continuation(continuation)?;
        let etag = parse_etag(etag)?;
        resource_page(
            self.inner
                .continue_resources(&continuation, etag.as_ref())
                .await
                .map_err(client_error)?,
        )
    }

    #[napi]
    pub async fn resource(
        &self,
        resource: String,
        etag: Option<String>,
    ) -> Result<Either<CompleteOutcome, NotModifiedOutcome>> {
        let etag = parse_etag(etag)?;
        conditional_value(
            self.inner
                .resource(&resource, etag.as_ref())
                .await
                .map_err(client_error)?,
        )
    }

    #[napi]
    pub async fn list_records(
        &self,
        resource: String,
        options: Option<Value>,
        etag: Option<String>,
    ) -> Result<Either<CollectionPageOutcome, NotModifiedOutcome>> {
        let request = list_request(options)?;
        let etag = parse_etag(etag)?;
        collection_page(
            self.inner
                .list_records(&resource, &request, etag.as_ref())
                .await
                .map_err(client_error)?,
        )
    }

    #[napi]
    pub async fn continue_list_records(
        &self,
        continuation: Value,
        etag: Option<String>,
    ) -> Result<Either<CollectionPageOutcome, NotModifiedOutcome>> {
        self.continue_collection(continuation, etag, "records")
            .await
    }

    #[napi]
    pub async fn read_record(
        &self,
        resource: String,
        record_identifier: String,
        options: Option<Value>,
        etag: Option<String>,
    ) -> Result<Either<CompleteOutcome, NotModifiedOutcome>> {
        let options = record_options_request(options)?;
        let etag = parse_etag(etag)?;
        conditional_value(
            self.inner
                .read_record(&resource, &record_identifier, &options, etag.as_ref())
                .await
                .map_err(client_error)?,
        )
    }

    #[napi]
    pub async fn lookup(
        &self,
        resource: String,
        lookup: String,
        selectors: Value,
        options: Option<Value>,
        etag: Option<String>,
    ) -> Result<Either<CompleteOutcome, NotModifiedOutcome>> {
        let selectors = selectors
            .as_object()
            .ok_or_else(|| binding_error("invalid_request", "selectors must be an object"))?;
        let mut request = LookupRequest::default().options(record_options_request(options)?);
        for (name, value) in selectors {
            request = request
                .selector(name, lookup_selector_value(value)?)
                .map_err(client_error)?;
        }
        let etag = parse_etag(etag)?;
        conditional_value(
            self.inner
                .lookup_record(&resource, &lookup, &request, etag.as_ref())
                .await
                .map_err(client_error)?,
        )
    }

    #[napi]
    pub async fn search(
        &self,
        resource: String,
        search: String,
        options: Value,
        etag: Option<String>,
    ) -> Result<Either<CollectionPageOutcome, NotModifiedOutcome>> {
        let request = search_request(options)?;
        let etag = parse_etag(etag)?;
        collection_page(
            self.inner
                .search_records(&resource, &search, &request, etag.as_ref())
                .await
                .map_err(client_error)?,
        )
    }

    #[napi]
    pub async fn continue_search(
        &self,
        continuation: Value,
        etag: Option<String>,
    ) -> Result<Either<CollectionPageOutcome, NotModifiedOutcome>> {
        self.continue_collection(continuation, etag, "search").await
    }

    #[napi]
    pub async fn artifact(
        &self,
        artifact_identifier: String,
        etag: Option<String>,
    ) -> Result<Either<RawCompleteOutcome, NotModifiedOutcome>> {
        let etag = parse_etag(etag)?;
        Ok(conditional_raw(
            self.inner
                .artifact(&artifact_identifier, etag.as_ref())
                .await
                .map_err(client_error)?,
        ))
    }

    #[napi]
    pub async fn sdmx_data(
        &self,
        request_value: Value,
        etag: Option<String>,
    ) -> Result<Either<RawCompleteOutcome, NotModifiedOutcome>> {
        let object = request_object(
            Some(request_value),
            &[
                "agency",
                "resource",
                "version",
                "key",
                "constraints",
                "offset",
                "limit",
                "dimensionAtObservation",
                "format",
            ],
            "SDMX data request must be an object with supported fields",
        )?;
        let mut request = SdmxDataRequest::new(
            required_string(
                &object,
                "agency",
                "invalid_request",
                "agency must be a string",
            )?,
            required_string(
                &object,
                "resource",
                "invalid_request",
                "resource must be a string",
            )?,
            required_string(
                &object,
                "version",
                "invalid_request",
                "version must be a string",
            )?,
        )
        .map_err(client_error)?;
        if let Some(value) = request_optional_string(&object, "key", "key must be a string")? {
            request = request.keyed(value).map_err(client_error)?;
        }
        for (name, value) in string_map(
            &object,
            "constraints",
            "constraints must map strings to strings",
        )? {
            request = request.constraint(name, value).map_err(client_error)?;
        }
        if let Some(value) =
            request_optional_u32(&object, "offset", "offset must be a non-negative integer")?
        {
            request = request.offset(value);
        }
        if let Some(value) =
            request_optional_u32(&object, "limit", "limit must be a non-negative integer")?
        {
            request = request.limit(value).map_err(client_error)?;
        }
        if let Some(value) = request_optional_string(
            &object,
            "dimensionAtObservation",
            "dimensionAtObservation must be a string",
        )? {
            request = request
                .dimension_at_observation(value)
                .map_err(client_error)?;
        }
        request = request.format(
            match request_optional_string(&object, "format", "format must be a string")?
                .as_deref()
                .unwrap_or("json")
            {
                "json" => SdmxDataFormat::Json,
                "csv" => SdmxDataFormat::Csv,
                _ => {
                    return Err(binding_error(
                        "invalid_request",
                        "SDMX data format must be json or csv",
                    ));
                }
            },
        );
        let etag = parse_etag(etag)?;
        Ok(conditional_raw(
            self.inner
                .sdmx_data(&request, etag.as_ref())
                .await
                .map_err(client_error)?,
        ))
    }

    #[napi]
    pub async fn sdmx_structure(
        &self,
        request_value: Value,
        etag: Option<String>,
    ) -> Result<Either<RawCompleteOutcome, NotModifiedOutcome>> {
        let object = request_object(
            Some(request_value),
            &["kind", "agency", "resource", "version"],
            "SDMX structure request must be an object with supported fields",
        )?;
        let kind =
            match required_string(&object, "kind", "invalid_request", "kind must be a string")?
                .as_str()
            {
                "dataflow" => SdmxStructureKind::Dataflow,
                "datastructure" | "data-structure" => SdmxStructureKind::DataStructure,
                _ => {
                    return Err(binding_error(
                        "invalid_request",
                        "SDMX structure kind must be dataflow or datastructure",
                    ));
                }
            };
        let request = SdmxStructureRequest::new(
            kind,
            required_string(
                &object,
                "agency",
                "invalid_request",
                "agency must be a string",
            )?,
            required_string(
                &object,
                "resource",
                "invalid_request",
                "resource must be a string",
            )?,
            required_string(
                &object,
                "version",
                "invalid_request",
                "version must be a string",
            )?,
        )
        .map_err(client_error)?;
        let etag = parse_etag(etag)?;
        Ok(conditional_raw(
            self.inner
                .sdmx_structure(&request, etag.as_ref())
                .await
                .map_err(client_error)?,
        ))
    }
}

impl RelayClient {
    async fn continue_collection(
        &self,
        continuation: Value,
        etag: Option<String>,
        expected: &'static str,
    ) -> Result<CollectionOutcome> {
        let continuation = collection_continuation(continuation, expected)?;
        let etag = parse_etag(etag)?;
        collection_page(
            self.inner
                .continue_collection(&continuation, etag.as_ref())
                .await
                .map_err(client_error)?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error_envelope(error: NapiError) -> Value {
        serde_json::from_str(&error.reason).expect("error reason is a JSON envelope")
    }

    #[test]
    fn configuration_is_exact_and_value_free() {
        let secret = "canary-secret-token";
        let error = config(json!({
            "baseUrl": "https://relay.invalid",
            "authorization": {"static": secret, "privateKeyJwt": {}}
        }))
        .unwrap_err();
        let text = error.reason;
        assert!(!text.contains(secret));
        assert_eq!(
            serde_json::from_str::<Value>(&text).unwrap()["kind"],
            "configuration"
        );
    }

    #[test]
    fn invalid_request_kind_is_not_configuration() {
        let error = list_request(Some(json!({"pageSize": 0}))).unwrap_err();
        assert_eq!(error_envelope(error)["kind"], "invalid_request");
    }

    #[test]
    fn list_and_search_options_keep_distinct_query_shapes() {
        let list_error =
            list_request(Some(json!({"bbox": [100.0, 13.0, 101.0, 14.0]}))).unwrap_err();
        assert_eq!(error_envelope(list_error)["kind"], "invalid_request");

        let missing_bbox = search_request(json!({"pageSize": 10})).unwrap_err();
        assert_eq!(error_envelope(missing_bbox)["kind"], "invalid_request");

        let filter_error = search_request(json!({
            "bbox": [100.0, 13.0, 101.0, 14.0],
            "filters": {"status": "active"}
        }))
        .unwrap_err();
        assert_eq!(error_envelope(filter_error)["kind"], "invalid_request");

        search_request(json!({
            "pageSize": 10,
            "bbox": [100.0, 13.0, 101.0, 14.0]
        }))
        .expect("the closed search query shape is accepted");
    }

    #[test]
    fn public_integer_fields_share_the_javascript_safe_integer_decoder() {
        let object = serde_json::from_str::<Value>(
            r#"{
                "u64": 4294967296.0,
                "i64": -9007199254740991.0,
                "u32": 4294967295.0
            }"#,
        )
        .expect("floating JSON numbers");
        let object = object.as_object().expect("an object");
        assert_eq!(
            optional_u64(object, "u64", "configuration", "invalid").unwrap(),
            Some(4_294_967_296)
        );
        assert_eq!(
            optional_i64(object, "i64", "invalid").unwrap(),
            Some(-9_007_199_254_740_991)
        );
        assert_eq!(
            request_optional_u32(object, "u32", "invalid").unwrap(),
            Some(u32::MAX)
        );

        for (wire, maximum, kind) in [
            ("1.5", MAXIMUM_JAVASCRIPT_SAFE_INTEGER, "configuration"),
            (
                "9007199254740992",
                MAXIMUM_JAVASCRIPT_SAFE_INTEGER,
                "configuration",
            ),
            (
                "9007199254740992.0",
                MAXIMUM_JAVASCRIPT_SAFE_INTEGER,
                "configuration",
            ),
            ("4294967296.0", i64::from(u32::MAX), "invalid_request"),
            ("-1", i64::from(u32::MAX), "invalid_request"),
        ] {
            let value = serde_json::from_str(wire).expect("a JSON number");
            let error = bounded_safe_integer(&value, 0, maximum, kind, "invalid").unwrap_err();
            let envelope = error_envelope(error);
            assert_eq!(envelope["kind"], kind);
            assert_eq!(envelope["message"], "invalid");
        }
    }

    #[test]
    fn javascript_safe_integer_selectors_become_signed_json_integers() {
        for (wire, expected) in [
            ("4294967296.0", 4_294_967_296_i64),
            ("9007199254740991.0", 9_007_199_254_740_991_i64),
            ("-9007199254740991.0", -9_007_199_254_740_991_i64),
        ] {
            let value = serde_json::from_str(wire).expect("a floating JSON number");
            let normalized = lookup_selector_value(&value).expect("a safe integer");
            assert_eq!(normalized.as_i64(), Some(expected));
            assert!(normalized
                .as_number()
                .is_some_and(serde_json::Number::is_i64));
        }

        for wire in [
            "1.5",
            "9007199254740992",
            "9007199254740992.0",
            "-9007199254740992.0",
        ] {
            let value = serde_json::from_str(wire).expect("a floating JSON number");
            let error = lookup_selector_value(&value).unwrap_err();
            let envelope = error_envelope(error);
            assert_eq!(envelope["kind"], "invalid_request");
            assert_eq!(envelope["message"], "a lookup selector value is invalid");
        }
    }

    #[test]
    fn continuation_route_must_match_its_consumer() {
        let error = collection_continuation(
            json!({
                "route": {"kind": "search", "resource": "people", "search": "by-name"},
                "cursor": "opaque",
                "format": "json"
            }),
            "records",
        )
        .unwrap_err();
        assert_eq!(error_envelope(error)["kind"], "invalid_request");
    }

    #[test]
    fn resource_continuation_uses_the_closed_core_projection() {
        let error = resource_continuation(json!({
            "cursor": "opaque",
            "pageSize": 100
        }))
        .unwrap_err();
        assert_eq!(error_envelope(error)["kind"], "invalid_request");
    }

    #[test]
    fn private_key_jwt_rejects_unknown_oauth_settings_without_exposing_key() {
        let secret = "canary-private-key";
        let result = authorization_provider(&json!({
            "privateKeyJwt": {
                "tokenEndpoint": "https://issuer.invalid/token",
                "clientId": "client",
                "clientKey": {"kty": "OKP", "d": secret},
                "scope": "not-supported"
            }
        }));
        let error = match result {
            Ok(_) => panic!("unsupported private-key JWT configuration was accepted"),
            Err(error) => error,
        };
        assert!(!error.reason.contains(secret));
        assert_eq!(error_envelope(error)["kind"], "configuration");
    }
}
