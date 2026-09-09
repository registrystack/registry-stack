// SPDX-License-Identifier: Apache-2.0
//! Node.js binding for the canonical Base Registry Engine client.

#![deny(unsafe_code)]

use std::{sync::Arc, time::Duration};

use napi::{bindgen_prelude::Buffer, Error as NapiError, Result};
use napi_derive::napi;
use registry_breg_client::{
    BRegAttachmentSlot as CoreAttachmentSlot, BRegAttachmentSlotValue, BRegAttachmentState,
    BRegAttachmentUpload as CoreAttachmentUpload, BRegAttachmentVerificationStatus, BRegComplete,
    BRegContinuation, BRegContinuationProjection, BRegCreateBinding, BRegCreateRequest,
    BRegDirectWrite, BRegEtag, BRegLifecycleAction as CoreLifecycleAction,
    BRegLifecycleActionReceipt, BRegLifecycleAuthority, BRegLifecyclePromotionError,
    BRegListRequest, BRegLookupRequest, BRegMetadata as CoreMetadata, BRegMetadataSelectionError,
    BRegMetadataSelectionErrorKind, BRegPage, BRegPatchBinding, BRegPatchRequest, BRegProblemCode,
    BRegProtocolFailure, BRegRawDocument, BRegRecordFormat, BRegRecordOptions,
    BRegRequestApplicationDisposition, BRegRequestProposal, BRegRequestReview,
    BRegRequestReviewMode, BRegRequestState, BaseRegistryClient as CoreClient,
    BaseRegistryClientConfig, BaseRegistryClientError, PrivateKeyJwt, PrivateKeyJwtConfig,
    RegistryRecordRepresentation, RegistryRecordResponse, StaticToken, TokenError, TokenProvider,
};
use registry_platform_crypto::PrivateJwk;
use serde::Serialize;
use serde_json::{json, Map, Value};
use url::Url;

const MAXIMUM_JAVASCRIPT_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[napi(object)]
pub struct CompleteOutcome {
    pub kind: String,
    pub value: Value,
    pub trace_id: String,
    pub etag: Option<String>,
    pub location: Option<String>,
}

/// Validated product result serialized before the JavaScript number boundary.
#[napi(object)]
pub struct JsonOutcome {
    pub kind: String,
    pub value_json: String,
    pub continuation: Option<Value>,
    pub trace_id: String,
    pub etag: Option<String>,
    pub location: Option<String>,
}

fn exact_input(value: &str) -> Result<Value> {
    registry_breg_client::decode_exact_json(value.as_bytes()).map_err(|_| {
        binding_error(
            "invalid_request",
            "JSON value is invalid or cannot be represented exactly",
        )
    })
}

fn complete_json_value<T: Serialize>(
    value: T,
    metadata: registry_breg_client::BRegResponseMetadata,
) -> Result<JsonOutcome> {
    let (trace_id, etag, location) = metadata_parts(&metadata);
    Ok(JsonOutcome {
        kind: "complete".into(),
        value_json: serde_json::to_string(&value)
            .map_err(|_| binding_error("protocol", "client result is not representable"))?,
        continuation: None,
        trace_id,
        etag,
        location,
    })
}

fn page_json_value<T: Serialize>(value: BRegComplete<BRegPage<T>>) -> Result<JsonOutcome> {
    let mut result = complete_json_value(value.value.value, value.metadata)?;
    result.continuation = value
        .value
        .continuation
        .map(|value| serde_json::to_value(value.projection()))
        .transpose()
        .map_err(|_| binding_error("protocol", "client continuation is not representable"))?;
    Ok(result)
}

#[napi(object)]
pub struct PageOutcome {
    pub kind: String,
    pub value: Value,
    pub continuation: Option<Value>,
    pub trace_id: String,
    pub etag: Option<String>,
}

#[napi(object)]
pub struct RawOutcome {
    pub kind: String,
    pub body: Buffer,
    pub media_type: String,
    pub trace_id: String,
    pub etag: Option<String>,
}

fn mapped_error(value: Value) -> NapiError {
    NapiError::from_reason(serde_json::to_string(&value).unwrap_or_else(|_| {
        r#"{"kind":"protocol","message":"the failure could not be described"}"#.to_owned()
    }))
}

fn binding_error(kind: &'static str, message: impl Into<String>) -> NapiError {
    mapped_error(json!({"kind": kind, "message": message.into()}))
}

fn protocol_code(value: BRegProtocolFailure) -> &'static str {
    match value {
        BRegProtocolFailure::HeaderBounds => "header_bounds",
        BRegProtocolFailure::TraceContext => "trace_context",
        BRegProtocolFailure::MediaType => "media_type",
        BRegProtocolFailure::Body => "body",
        BRegProtocolFailure::Problem => "problem",
        BRegProtocolFailure::EntityTag => "entity_tag",
        BRegProtocolFailure::ProfileLink => "profile_link",
        BRegProtocolFailure::Location => "location",
        BRegProtocolFailure::CachePolicy => "cache_policy",
        BRegProtocolFailure::Status => "status",
        _ => "protocol",
    }
}

fn token_error_value(error: TokenError) -> Value {
    let mut value = json!({
        "kind": "token",
        "tokenKind": error.kind(),
        "message": error.to_string(),
    });
    let object = value.as_object_mut().expect("token error is an object");
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

fn client_error(error: BaseRegistryClientError) -> NapiError {
    let value = match error {
        BaseRegistryClientError::Configuration { reason } => {
            json!({"kind": "configuration", "message": reason})
        }
        BaseRegistryClientError::InvalidRequest { reason } => {
            json!({"kind": "invalid_request", "message": reason})
        }
        BaseRegistryClientError::Token(error) => token_error_value(error),
        BaseRegistryClientError::Transport { kind } => json!({
            "kind": "transport",
            "transportKind": kind.kind(),
            "message": "Base Registry Engine exchange did not complete",
        }),
        BaseRegistryClientError::Problem {
            status,
            code,
            trace_id,
            refusal_code,
        } => json!({
            // app-developer-22: a missing resource is its own kind, not_found,
            // rather than the generic problem kind every other refusal shares.
            "kind": match code {
                BRegProblemCode::ResourceNotFound => "not_found",
                _ => "problem",
            },
            "status": status,
            "code": code.code(),
            "planRefusal": match code {
                BRegProblemCode::RequestPlanRefused(value) => Some(value.kind()),
                _ => None,
            },
            // The refusal catalogue belongs to the package, so the declared code
            // travels as the bounded string the Problem schema admits.
            "refusalCode": refusal_code.as_ref().map(|value| value.as_str()),
            "traceId": trace_id.as_str(),
            "message": "Base Registry Engine refused the request",
        }),
        BaseRegistryClientError::Protocol {
            status,
            failure,
            trace_id,
        } => json!({
            "kind": "protocol",
            "status": status,
            "code": protocol_code(failure),
            "traceId": trace_id.map(|value| value.as_str().to_owned()),
            "message": failure.to_string(),
        }),
        _ => json!({
            "kind": "client",
            "message": "Base Registry Engine client returned an unsupported failure",
        }),
    };
    mapped_error(value)
}

fn selection_error(error: BRegMetadataSelectionError) -> NapiError {
    let code = match error.kind() {
        BRegMetadataSelectionErrorKind::NotFound => "not_found",
        BRegMetadataSelectionErrorKind::UnboundSource => "unbound_source",
        BRegMetadataSelectionErrorKind::ProfileMismatch => "profile_mismatch",
        BRegMetadataSelectionErrorKind::UnsupportedOperation => "unsupported_operation",
        BRegMetadataSelectionErrorKind::RequiredCapability => "required_capability",
        BRegMetadataSelectionErrorKind::ContractMismatch => "contract_mismatch",
    };
    mapped_error(json!({
        "kind": "metadata_selection",
        "code": code,
        "message": error.to_string(),
    }))
}

fn required_object<'a>(value: &'a Value, message: &'static str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| binding_error("configuration", message))
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

fn safe_integer(
    value: &Value,
    minimum: i64,
    maximum: i64,
    kind: &'static str,
    message: &'static str,
) -> Result<i64> {
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
            || number.abs() > MAXIMUM_JAVASCRIPT_SAFE_INTEGER as f64
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
        Some(value) => safe_integer(value, 0, MAXIMUM_JAVASCRIPT_SAFE_INTEGER, kind, message)
            .map(|value| Some(value as u64)),
    }
}

fn optional_i64(
    object: &Map<String, Value>,
    field: &str,
    message: &'static str,
) -> Result<Option<i64>> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => safe_integer(
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
    let key = PrivateJwk::parse(
        &serde_json::to_string(key)
            .map_err(|_| binding_error("configuration", "clientKey is invalid"))?,
    )
    .map_err(|_| binding_error("configuration", "clientKey is invalid"))?;
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
        "private-key JWT request timeout must be a non-negative integer",
    )? {
        config = config.with_request_timeout(Duration::from_millis(value));
    }
    if let Some(value) = optional_u64(
        object,
        "connectTimeoutMilliseconds",
        "configuration",
        "private-key JWT connection timeout must be a non-negative integer",
    )? {
        config = config.with_connect_timeout(Duration::from_millis(value));
    }
    if let Some(value) = optional_string(
        object,
        "userAgent",
        "configuration",
        "private-key JWT userAgent must be a string",
    )? {
        config = config.with_user_agent(value);
    }
    if let Some(value) = optional_string(
        object,
        "trustedRootCertificates",
        "configuration",
        "private-key JWT trustedRootCertificates must be a string",
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

fn client_from_config(value: Value) -> Result<CoreClient> {
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
    let mut config = BaseRegistryClientConfig::new(base_url);
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

fn format(value: Option<String>) -> Result<BRegRecordFormat> {
    match value.as_deref().unwrap_or("json") {
        "json" => Ok(BRegRecordFormat::Json),
        "json-ld" => Ok(BRegRecordFormat::JsonLd),
        _ => Err(binding_error(
            "invalid_request",
            "format must be json or json-ld",
        )),
    }
}

/// Preconditions every attachment mutation shares, parsed before any request.
fn attachment_preconditions(
    record_identifier: String,
    etag: String,
    idempotency_key: String,
) -> Result<(
    uuid::Uuid,
    BRegEtag,
    registry_breg_client::BRegIdempotencyKey,
)> {
    let record_identifier = uuid::Uuid::parse_str(&record_identifier)
        .map_err(|_| binding_error("invalid_request", "recordIdentifier must be a UUID"))?;
    let etag = BRegEtag::parse(&etag).map_err(|_| {
        binding_error(
            "invalid_request",
            "etag must be a strong Base Registry Engine entity tag",
        )
    })?;
    let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
        .map_err(|error| binding_error("invalid_request", error.to_string()))?;
    Ok((record_identifier, etag, key))
}

fn record_options(object: Option<&Map<String, Value>>) -> Result<BRegRecordOptions> {
    let Some(object) = object else {
        return Ok(BRegRecordOptions::default());
    };
    only_fields(
        object,
        &["select", "accessProfile", "format"],
        "invalid_request",
        "record options contain an unsupported field",
    )?;
    let mut options = BRegRecordOptions::default().format(format(optional_string(
        object,
        "format",
        "invalid_request",
        "format must be a string",
    )?)?);
    match object.get("select") {
        None | Some(Value::Null) => {}
        Some(value) => {
            let fields = value
                .as_array()
                .and_then(|values| {
                    values
                        .iter()
                        .map(|value| value.as_str().map(str::to_owned))
                        .collect::<Option<Vec<_>>>()
                })
                .ok_or_else(|| {
                    binding_error("invalid_request", "select must be an array of strings")
                })?;
            options = options
                .select(fields)
                .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        }
    }
    if let Some(value) = optional_string(
        object,
        "accessProfile",
        "invalid_request",
        "accessProfile must be a string",
    )? {
        options = options
            .access_profile(value)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
    }
    Ok(options)
}

fn options_object(
    value: Option<Value>,
    message: &'static str,
) -> Result<Option<Map<String, Value>>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(value)) => Ok(Some(value)),
        Some(_) => Err(binding_error("invalid_request", message)),
    }
}

fn list_request(value: Option<Value>) -> Result<BRegListRequest> {
    let object = options_object(value, "list options must be an object")?.unwrap_or_default();
    only_fields(
        &object,
        &[
            "select",
            "accessProfile",
            "format",
            "top",
            "filter",
            "orderby",
            "count",
        ],
        "invalid_request",
        "list options contain an unsupported field",
    )?;
    let base = object
        .iter()
        .filter(|(field, _)| matches!(field.as_str(), "select" | "accessProfile" | "format"))
        .map(|(field, value)| (field.clone(), value.clone()))
        .collect();
    let mut request = BRegListRequest::default().options(record_options(Some(&base))?);
    match object.get("top") {
        None | Some(Value::Null) => {}
        Some(value) => {
            let value = safe_integer(
                value,
                1,
                100,
                "invalid_request",
                "top must be 1 through 100",
            )?;
            request = request
                .top(value as u32)
                .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        }
    }
    if let Some(value) = optional_string(
        &object,
        "filter",
        "invalid_request",
        "filter must be a string",
    )? {
        request = request
            .filter(value)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
    }
    if let Some(value) = optional_string(
        &object,
        "orderby",
        "invalid_request",
        "orderby must be a string",
    )? {
        request = request
            .orderby(value)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
    }
    match object.get("count") {
        None | Some(Value::Null) => {}
        Some(value) => {
            let value = value
                .as_bool()
                .ok_or_else(|| binding_error("invalid_request", "count must be a boolean"))?;
            request = request.count(value);
        }
    }
    Ok(request)
}

fn lookup_request(
    selector: String,
    values: Option<Value>,
    options: Option<Value>,
) -> Result<BRegLookupRequest> {
    let mut request = BRegLookupRequest::new(selector)
        .map_err(|error| binding_error("invalid_request", error.to_string()))?;
    let options = options_object(options, "record options must be an object")?;
    request = request.options(record_options(options.as_ref())?);
    match values {
        None | Some(Value::Null) => {}
        Some(Value::Object(values)) => {
            for (name, value) in values {
                request = request
                    .value(name, value)
                    .map_err(|error| binding_error("invalid_request", error.to_string()))?;
            }
        }
        Some(_) => {
            return Err(binding_error(
                "invalid_request",
                "lookup values must be an object",
            ))
        }
    }
    Ok(request)
}

fn metadata_parts(
    metadata: &registry_breg_client::BRegResponseMetadata,
) -> (String, Option<String>, Option<String>) {
    (
        metadata.trace_id().as_str().to_owned(),
        metadata.etag().map(|value| value.as_str().to_owned()),
        metadata.location().map(str::to_owned),
    )
}

fn complete_value<T: Serialize>(
    value: T,
    metadata: registry_breg_client::BRegResponseMetadata,
) -> Result<CompleteOutcome> {
    let (trace_id, etag, location) = metadata_parts(&metadata);
    Ok(CompleteOutcome {
        kind: "complete".into(),
        value: serde_json::to_value(value)
            .map_err(|_| binding_error("protocol", "client result is not representable"))?,
        trace_id,
        etag,
        location,
    })
}

fn page_value<T: Serialize>(value: BRegComplete<BRegPage<T>>) -> Result<PageOutcome> {
    let (trace_id, etag, _) = metadata_parts(&value.metadata);
    Ok(PageOutcome {
        kind: "complete".into(),
        value: serde_json::to_value(value.value.value)
            .map_err(|_| binding_error("protocol", "client result is not representable"))?,
        continuation: value
            .value
            .continuation
            .map(|value| serde_json::to_value(value.projection()))
            .transpose()
            .map_err(|_| binding_error("protocol", "client continuation is not representable"))?,
        trace_id,
        etag,
    })
}

fn raw_value(value: BRegComplete<BRegRawDocument>) -> RawOutcome {
    let (trace_id, etag, _) = metadata_parts(&value.metadata);
    RawOutcome {
        kind: "complete".into(),
        body: value.value.as_bytes().to_vec().into(),
        media_type: value.value.media_type().to_owned(),
        trace_id,
        etag,
    }
}

fn patch_request(value: Value) -> Result<BRegPatchRequest> {
    let operations = value
        .as_array()
        .ok_or_else(|| binding_error("invalid_request", "patch must be an array"))?;
    let mut builder = BRegPatchRequest::builder();
    for operation in operations {
        let object = operation.as_object().ok_or_else(|| {
            binding_error("invalid_request", "every patch operation must be an object")
        })?;
        let op = required_string(object, "op", "invalid_request", "patch op must be a string")?;
        let allowed = if op == "remove" {
            &["op", "field"][..]
        } else {
            &["op", "field", "value"][..]
        };
        only_fields(
            object,
            allowed,
            "invalid_request",
            "patch operation contains an unsupported field",
        )?;
        let field = required_string(
            object,
            "field",
            "invalid_request",
            "patch field must be a string",
        )?;
        let result = match op.as_str() {
            "add" => builder.add(
                field,
                object
                    .get("value")
                    .cloned()
                    .ok_or_else(|| binding_error("invalid_request", "add requires value"))?,
            ),
            "replace" => builder.replace(
                field,
                object
                    .get("value")
                    .cloned()
                    .ok_or_else(|| binding_error("invalid_request", "replace requires value"))?,
            ),
            "remove" => builder.remove(field),
            "test" => builder.test(
                field,
                object
                    .get("value")
                    .cloned()
                    .ok_or_else(|| binding_error("invalid_request", "test requires value"))?,
            ),
            _ => return Err(binding_error("invalid_request", "patch op is unsupported")),
        };
        builder = result.map_err(|error| binding_error("invalid_request", error.to_string()))?;
    }
    builder
        .build()
        .map_err(|error| binding_error("invalid_request", error.to_string()))
}

fn parse_record(
    value: Value,
    format: BRegRecordFormat,
) -> Result<registry_breg_client::RegistryRecordSingleResponse> {
    let representation = match format {
        BRegRecordFormat::Json => RegistryRecordRepresentation::Json,
        BRegRecordFormat::JsonLd => RegistryRecordRepresentation::JsonLdSharedContext,
    };
    match RegistryRecordResponse::from_value(value, representation) {
        Ok(RegistryRecordResponse::Single(value)) => Ok(value),
        _ => Err(binding_error(
            "invalid_request",
            "record must be one Registry Record response",
        )),
    }
}

fn state_name(value: BRegRequestState) -> &'static str {
    match value {
        BRegRequestState::Draft => "draft",
        BRegRequestState::Submitted => "submitted",
        BRegRequestState::Approved => "approved",
        BRegRequestState::NeedsChanges => "needs_changes",
        BRegRequestState::Rejected => "rejected",
        BRegRequestState::Canceled => "canceled",
        BRegRequestState::Applied => "applied",
    }
}

fn proposal_value(value: &BRegRequestProposal) -> Value {
    json!({
        "reviewMode": match value.review_mode() {
            BRegRequestReviewMode::None => "none",
            BRegRequestReviewMode::Staged => "staged",
        },
        "applicationDisposition": match value.application_disposition() {
            BRegRequestApplicationDisposition::Apply => "apply",
            BRegRequestApplicationDisposition::Queue => "queue",
        },
        "queueReason": value.queue_reason().map(|reason| json!({
            "code": reason.code(),
            "label": reason.label(),
        })),
    })
}

fn receipt_value(value: &BRegLifecycleActionReceipt) -> Value {
    let request = value.request();
    json!({
        "id": value.record_identifier(),
        "revision": value.revision(),
        "snapshot": value.snapshot(),
        "request": {
            "bregState": state_name(request.breg_state()),
            "proposalVersion": request.proposal_version().map(|value| value.get()),
            "effectDigest": request.effect_digest().map(|value| value.as_str()),
            "proposal": request.proposal().map(proposal_value),
            "application": request.application().map(|application| json!({
                "id": application.application_identifier(),
                "proposalVersion": application.proposal_version().get(),
                "effectDigest": application.effect_digest().as_str(),
                "appliedAt": application.applied_at(),
            })),
        },
    })
}

fn review_value(value: &BRegRequestReview) -> Value {
    json!({
        "targets": value.targets().iter().map(|target| json!({
            "entityIdentifier": target.entity_identifier(),
            "recordIdentifier": target.record_identifier(),
            "operation": match target.operation() {
                registry_breg_client::BRegReviewOperation::Create => "create",
                registry_breg_client::BRegReviewOperation::Patch => "patch",
            },
            "baseRevision": target.base_revision(),
            "before": target.before(),
            "after": target.after(),
        })).collect::<Vec<_>>(),
    })
}

fn attachment_state_value(value: &BRegAttachmentState) -> Value {
    json!({
        "slotIdentifier": value.slot_identifier(),
        "proposalVersion": value.proposal_version(),
        "erased": value.erased(),
        "byteSize": value.byte_size(),
        "sha256": value.sha256(),
        "contentType": value.content_type(),
        "uploadedAt": value.uploaded_at(),
        "uploadedBy": value.uploaded_by(),
        "verificationStatus": value
            .verification_status()
            .map(BRegAttachmentVerificationStatus::as_str),
    })
}

fn attachment_slot_value(value: &BRegAttachmentSlotValue) -> Value {
    match value {
        BRegAttachmentSlotValue::NotSelected => json!({"kind": "not_selected", "value": null}),
        BRegAttachmentSlotValue::Empty => json!({"kind": "empty", "value": null}),
        BRegAttachmentSlotValue::Filled(state) => json!({
            "kind": "filled",
            "value": attachment_state_value(state),
        }),
    }
}

fn attachment_error(error: registry_breg_client::BRegAttachmentError) -> NapiError {
    binding_error("invalid_request", error.reason())
}

/// Opaque governed attachment slot selected from metadata fetched by this client source.
#[napi(js_name = "BRegAttachmentSlot")]
pub struct AttachmentSlot {
    inner: CoreAttachmentSlot,
}

/// Opaque bytes already accepted by one slot's served upload policy.
#[napi(js_name = "BRegAttachmentUpload")]
pub struct AttachmentUpload {
    inner: CoreAttachmentUpload,
}

#[napi]
impl AttachmentSlot {
    #[napi(getter)]
    pub fn slot_identifier(&self) -> String {
        self.inner.slot_identifier().to_owned()
    }

    #[napi(getter)]
    pub fn entity_identifier(&self) -> String {
        self.inner.entity_identifier().to_owned()
    }

    #[napi(getter)]
    pub fn access_profile(&self) -> String {
        self.inner.access_profile().to_owned()
    }

    #[napi(getter)]
    pub fn required_for_submit(&self) -> bool {
        self.inner.required_for_submit()
    }

    /// Largest body the served slot policy accepts, in bytes.
    #[napi(getter)]
    pub fn maximum_bytes(&self) -> i64 {
        i64::try_from(self.inner.maximum_bytes()).unwrap_or(MAXIMUM_JAVASCRIPT_SAFE_INTEGER)
    }

    #[napi(getter)]
    pub fn content_types(&self) -> Vec<String> {
        self.inner.content_types().to_vec()
    }

    /// Authored sensitivity of this slot's content.
    #[napi(getter)]
    pub fn classification(&self) -> String {
        self.inner.classification().as_str().to_owned()
    }

    #[napi(getter)]
    pub fn can_download(&self) -> bool {
        self.inner.can_download()
    }

    #[napi(getter)]
    pub fn can_upload(&self) -> bool {
        self.inner.can_upload()
    }

    #[napi(getter)]
    pub fn can_remove(&self) -> bool {
        self.inner.can_remove()
    }

    #[napi]
    pub fn accepts_content_type(&self, content_type: String) -> bool {
        self.inner.accepts_content_type(&content_type)
    }

    /// Bind exact bytes to this slot. Refusals happen here, before any request.
    #[napi]
    pub fn prepare_upload(&self, content_type: String, body: Buffer) -> Result<AttachmentUpload> {
        CoreAttachmentUpload::new(&self.inner, &content_type, body.to_vec())
            .map(|inner| AttachmentUpload { inner })
            .map_err(attachment_error)
    }

    /// Read this slot's engine-owned state out of one Registry Record envelope.
    #[napi]
    pub fn value_in(&self, record: Value, format_value: Option<String>) -> Result<Value> {
        let record = parse_record(record, format(format_value)?)?;
        self.inner
            .value_in(&record.data)
            .map(|value| attachment_slot_value(&value))
            .map_err(attachment_error)
    }
}

#[napi]
impl AttachmentUpload {
    #[napi(getter)]
    pub fn content_type(&self) -> String {
        self.inner.content_type().to_owned()
    }

    #[napi(getter)]
    pub fn byte_size(&self) -> i64 {
        i64::try_from(self.inner.byte_size()).unwrap_or(MAXIMUM_JAVASCRIPT_SAFE_INTEGER)
    }
}

#[napi(js_name = "BRegCreateBinding")]
pub struct CreateBinding {
    inner: BRegCreateBinding,
}

#[napi(js_name = "BRegPatchBinding")]
pub struct PatchBinding {
    inner: BRegPatchBinding,
}

#[napi(js_name = "BRegLifecycleAuthority")]
pub struct LifecycleAuthority {
    inner: BRegLifecycleAuthority,
}

#[napi(js_name = "BRegLifecycleAction")]
pub struct LifecycleAction {
    inner: CoreLifecycleAction,
}

#[napi]
impl LifecycleAction {
    #[napi]
    pub fn with_reason(&self, reason: String) -> Result<Self> {
        self.inner
            .with_reason(reason)
            .map(|inner| Self { inner })
            .map_err(|error| binding_error("invalid_request", error.to_string()))
    }

    #[napi(getter)]
    pub fn body_json(&self) -> Result<String> {
        serde_json::to_string(&self.inner.body().to_value())
            .map_err(|_| binding_error("protocol", "action body is not representable"))
    }
    #[napi(getter)]
    pub fn review_json(&self) -> Result<Option<String>> {
        self.inner
            .review()
            .map(|value| serde_json::to_string(&review_value(value)))
            .transpose()
            .map_err(|_| binding_error("protocol", "action review is not representable"))
    }

    #[napi(getter)]
    pub fn operation(&self) -> String {
        self.inner.operation().identifier().to_owned()
    }

    #[napi(getter)]
    pub fn stage(&self) -> Option<String> {
        self.inner.stage().map(str::to_owned)
    }

    #[napi(getter)]
    pub fn href(&self) -> String {
        self.inner.href().to_owned()
    }

    #[napi(getter)]
    pub fn body(&self) -> Value {
        self.inner.body().to_value()
    }

    #[napi(getter)]
    pub fn review(&self) -> Option<Value> {
        self.inner.review().map(review_value)
    }
}

#[napi(js_name = "BRegMetadata")]
pub struct Metadata {
    inner: CoreMetadata,
    trace_id: String,
    etag: Option<String>,
}

#[napi]
impl Metadata {
    /// Caller-filtered inert descriptors. Selectors below remain the only authority constructors.
    #[napi(getter)]
    pub fn operations(&self) -> Value {
        Value::Array(self.inner.operations().iter().map(|operation| {
            let request = operation.request();
            json!({
                "id": operation.identifier(), "method": operation.method(), "path": operation.path(),
                "kind": operation.kind().as_str(), "sourceEntity": operation.source_entity(),
                "responseEntity": operation.response_entity(), "accessProfile": operation.access_profile(),
                "entityLabel": operation.entity_label(), "titleFields": operation.title_fields(),
                "requiredCapabilities": operation.required_capabilities(),
                "readableFields": operation.readable_fields(), "createWritableFields": operation.create_writable_fields(),
                "patchWritableFields": operation.patch_writable_fields(), "query": operation.query(),
                "fields": operation.fields().iter().map(|field| json!({
                    "id": field.identifier(), "apiName": field.api_name(), "label": field.label(),
                    "schemaJson": field.schema().to_string(), "required": field.required(),
                    "nullable": field.nullable(), "readOnly": field.read_only(), "removable": field.removable(),
                    "referenceTargetEntity": field.reference_target_entity(),
                })).collect::<Vec<_>>(),
                "request": { "fieldNames": request.field_names(), "queryParameters": request.query_parameters(),
                    "body": request.body(), "contentType": request.content_type(),
                    "schemaJson": request.schema().map(Value::to_string),
                    "idempotencyKeyRequired": request.idempotency_key_required(), "ifMatchRequired": request.if_match_required(),
                    "mutationSemantics": request.mutation_semantics(), "patchPathPrefix": request.patch_path_prefix(),
                    "patchOperations": request.patch_operations(), "removeSemantics": request.remove_semantics() },
            })
        }).collect())
    }

    #[napi(getter)]
    pub fn registry_identifier(&self) -> String {
        self.inner.registry_identifier().to_owned()
    }

    #[napi(getter)]
    pub fn registry_version(&self) -> String {
        self.inner.registry_version().to_owned()
    }

    #[napi(getter)]
    pub fn registry_revision(&self) -> String {
        self.inner.registry_revision().to_owned()
    }

    #[napi(getter)]
    pub fn trace_id(&self) -> String {
        self.trace_id.clone()
    }

    #[napi(getter)]
    pub fn etag(&self) -> Option<String> {
        self.etag.clone()
    }

    #[napi]
    pub fn select_create(
        &self,
        operation_identifier: String,
        expected_profile: String,
    ) -> Result<CreateBinding> {
        match self
            .inner
            .select_direct_write(&operation_identifier, &expected_profile)
            .map_err(selection_error)?
        {
            BRegDirectWrite::Create(inner) => Ok(CreateBinding { inner }),
            BRegDirectWrite::Patch(_) => Err(binding_error(
                "metadata_selection",
                "operation is not a create",
            )),
        }
    }

    #[napi]
    pub fn select_patch(
        &self,
        operation_identifier: String,
        expected_profile: String,
    ) -> Result<PatchBinding> {
        match self
            .inner
            .select_direct_write(&operation_identifier, &expected_profile)
            .map_err(selection_error)?
        {
            BRegDirectWrite::Patch(inner) => Ok(PatchBinding { inner }),
            BRegDirectWrite::Create(_) => Err(binding_error(
                "metadata_selection",
                "operation is not a patch",
            )),
        }
    }

    #[napi]
    pub fn select_lifecycle(
        &self,
        entity_identifier: String,
        expected_profile: String,
    ) -> Result<LifecycleAuthority> {
        self.inner
            .select_lifecycle(&entity_identifier, &expected_profile)
            .map(|inner| LifecycleAuthority { inner })
            .map_err(selection_error)
    }

    #[napi]
    pub fn select_attachments(
        &self,
        entity_identifier: String,
        expected_profile: String,
    ) -> Result<Vec<AttachmentSlot>> {
        self.inner
            .select_attachments(&entity_identifier, &expected_profile)
            .map(|slots| {
                slots
                    .into_iter()
                    .map(|inner| AttachmentSlot { inner })
                    .collect()
            })
            .map_err(selection_error)
    }
}

#[napi]
pub struct BaseRegistryClient {
    inner: Arc<CoreClient>,
}

#[napi]
impl BaseRegistryClient {
    #[napi(constructor)]
    pub fn new(config: Value) -> Result<Self> {
        Ok(Self {
            inner: Arc::new(client_from_config(config)?),
        })
    }

    #[napi]
    pub async fn health(&self) -> Result<CompleteOutcome> {
        let BRegComplete { value, metadata } = self.inner.health().await.map_err(client_error)?;
        complete_value(value, metadata)
    }

    #[napi]
    pub async fn ready(&self) -> Result<CompleteOutcome> {
        let BRegComplete { value, metadata } = self.inner.ready().await.map_err(client_error)?;
        complete_value(value, metadata)
    }

    #[napi]
    pub async fn openapi(&self, access_profile: Option<String>) -> Result<RawOutcome> {
        self.inner
            .openapi(access_profile.as_deref())
            .await
            .map(raw_value)
            .map_err(client_error)
    }

    #[napi]
    pub async fn registry_metadata(&self, access_profile: Option<String>) -> Result<RawOutcome> {
        self.inner
            .registry_metadata(access_profile.as_deref())
            .await
            .map(raw_value)
            .map_err(client_error)
    }

    #[napi]
    pub async fn registry_contract(&self, access_profile: Option<String>) -> Result<Metadata> {
        let BRegComplete { value, metadata } = self
            .inner
            .registry_contract(access_profile.as_deref())
            .await
            .map_err(client_error)?;
        let (trace_id, etag, _) = metadata_parts(&metadata);
        Ok(Metadata {
            inner: value,
            trace_id,
            etag,
        })
    }

    #[napi]
    pub async fn entity_schema(
        &self,
        entity_identifier: String,
        access_profile: Option<String>,
    ) -> Result<RawOutcome> {
        self.inner
            .entity_schema(&entity_identifier, access_profile.as_deref())
            .await
            .map(raw_value)
            .map_err(client_error)
    }

    #[napi]
    pub async fn get_record(
        &self,
        entity_route: String,
        record_identifier: String,
        options: Option<Value>,
    ) -> Result<CompleteOutcome> {
        let options = options_object(options, "record options must be an object")?;
        let BRegComplete { value, metadata } = self
            .inner
            .get_record(
                &entity_route,
                &record_identifier,
                &record_options(options.as_ref())?,
            )
            .await
            .map_err(client_error)?;
        complete_value(value, metadata)
    }

    #[napi]
    pub async fn list_records(
        &self,
        entity_route: String,
        options: Option<Value>,
    ) -> Result<PageOutcome> {
        self.inner
            .list_records(&entity_route, &list_request(options)?)
            .await
            .map_err(client_error)
            .and_then(page_value)
    }

    #[napi]
    pub async fn continue_list(&self, value: Value) -> Result<PageOutcome> {
        let projection: BRegContinuationProjection = serde_json::from_value(value)
            .map_err(|_| binding_error("invalid_request", "continuation is invalid"))?;
        let continuation = BRegContinuation::try_from_projection(projection)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        self.inner
            .continue_list(&continuation)
            .await
            .map_err(client_error)
            .and_then(page_value)
    }

    #[napi]
    pub async fn lookup_record(
        &self,
        entity_route: String,
        selector: String,
        values: Option<Value>,
        options: Option<Value>,
    ) -> Result<CompleteOutcome> {
        let request = lookup_request(selector, values, options)?;
        let BRegComplete { value, metadata } = self
            .inner
            .lookup_record(&entity_route, &request)
            .await
            .map_err(client_error)?;
        complete_value(value, metadata)
    }

    #[napi]
    pub async fn create_record(
        &self,
        binding: &CreateBinding,
        data: Value,
        idempotency_key: String,
        format_value: Option<String>,
    ) -> Result<CompleteOutcome> {
        let data = data
            .as_object()
            .cloned()
            .ok_or_else(|| binding_error("invalid_request", "create data must be an object"))?;
        let request = BRegCreateRequest::new(data)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let operation = binding.inner.clone();
        let BRegComplete { value, metadata } = self
            .inner
            .create_record(&operation, &request, &key, format(format_value)?)
            .await
            .map_err(client_error)?;
        complete_value(value, metadata)
    }

    #[napi]
    pub async fn patch_record(
        &self,
        binding: &PatchBinding,
        record_identifier: String,
        etag: String,
        operations: Value,
        idempotency_key: String,
        format_value: Option<String>,
    ) -> Result<CompleteOutcome> {
        let record_identifier = uuid::Uuid::parse_str(&record_identifier)
            .map_err(|_| binding_error("invalid_request", "recordIdentifier must be a UUID"))?;
        let etag = BRegEtag::parse(&etag).map_err(|_| {
            binding_error(
                "invalid_request",
                "etag must be a strong Base Registry Engine entity tag",
            )
        })?;
        let request = patch_request(operations)?;
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let operation = binding.inner.clone();
        let BRegComplete { value, metadata } = self
            .inner
            .patch_record(
                &operation,
                record_identifier,
                &etag,
                &request,
                &key,
                format(format_value)?,
            )
            .await
            .map_err(client_error)?;
        complete_value(value, metadata)
    }

    /// Replace one governed attachment slot with exact bytes. The prepared
    /// upload already satisfies the slot's served size and content-type policy.
    #[napi]
    pub async fn upload_attachment(
        &self,
        slot: &AttachmentSlot,
        record_identifier: String,
        etag: String,
        upload: &AttachmentUpload,
        idempotency_key: String,
        format_value: Option<String>,
    ) -> Result<CompleteOutcome> {
        let (record_identifier, etag, key) =
            attachment_preconditions(record_identifier, etag, idempotency_key)?;
        let (slot, upload) = (slot.inner.clone(), upload.inner.clone());
        let BRegComplete { value, metadata } = self
            .inner
            .upload_attachment(
                &slot,
                record_identifier,
                &etag,
                &upload,
                &key,
                format(format_value)?,
            )
            .await
            .map_err(client_error)?;
        complete_value(value, metadata)
    }

    /// Read the exact bytes one governed slot holds for one proposal version.
    #[napi]
    pub async fn download_attachment(
        &self,
        slot: &AttachmentSlot,
        record_identifier: String,
        proposal_version: u32,
    ) -> Result<RawOutcome> {
        let record_identifier = uuid::Uuid::parse_str(&record_identifier)
            .map_err(|_| binding_error("invalid_request", "recordIdentifier must be a UUID"))?;
        let slot = slot.inner.clone();
        self.inner
            .download_attachment(&slot, record_identifier, proposal_version)
            .await
            .map(raw_value)
            .map_err(client_error)
    }

    /// Empty one governed attachment slot.
    #[napi]
    pub async fn delete_attachment(
        &self,
        slot: &AttachmentSlot,
        record_identifier: String,
        etag: String,
        idempotency_key: String,
        format_value: Option<String>,
    ) -> Result<CompleteOutcome> {
        let (record_identifier, etag, key) =
            attachment_preconditions(record_identifier, etag, idempotency_key)?;
        let slot = slot.inner.clone();
        let BRegComplete { value, metadata } = self
            .inner
            .delete_attachment(&slot, record_identifier, &etag, &key, format(format_value)?)
            .await
            .map_err(client_error)?;
        complete_value(value, metadata)
    }

    #[napi]
    pub fn lifecycle_actions(
        &self,
        authority: &LifecycleAuthority,
        record: Value,
        format_value: Option<String>,
    ) -> Result<Vec<LifecycleAction>> {
        let record = parse_record(record, format(format_value)?)?;
        self.inner.lifecycle_actions(&authority.inner, &record)
            .map(|actions| actions.into_iter().map(|inner| LifecycleAction { inner }).collect())
            .map_err(|error| {
                let code = match error {
                    BRegLifecyclePromotionError::Authority => "authority",
                    BRegLifecyclePromotionError::Binding => "binding",
                };
                mapped_error(json!({"kind": "lifecycle_promotion", "code": code, "message": error.to_string()}))
            })
    }

    #[napi]
    pub async fn execute_lifecycle_action(
        &self,
        action: &LifecycleAction,
        idempotency_key: String,
    ) -> Result<CompleteOutcome> {
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let action = action.inner.clone();
        let BRegComplete { value, metadata } = self
            .inner
            .execute_lifecycle_action(&action, &key)
            .await
            .map_err(client_error)?;
        complete_value(receipt_value(&value), metadata)
    }
    #[napi]
    pub async fn get_record_json(
        &self,
        entity_route: String,
        record_identifier: String,
        options: Option<Value>,
    ) -> Result<JsonOutcome> {
        let options = options_object(options, "record options must be an object")?;
        let BRegComplete { value, metadata } = self
            .inner
            .get_record(
                &entity_route,
                &record_identifier,
                &record_options(options.as_ref())?,
            )
            .await
            .map_err(client_error)?;
        complete_json_value(value, metadata)
    }

    #[napi]
    pub async fn list_records_json(
        &self,
        entity_route: String,
        options: Option<Value>,
    ) -> Result<JsonOutcome> {
        self.inner
            .list_records(&entity_route, &list_request(options)?)
            .await
            .map_err(client_error)
            .and_then(page_json_value)
    }

    #[napi]
    pub async fn continue_list_json(&self, value: Value) -> Result<JsonOutcome> {
        let projection: BRegContinuationProjection = serde_json::from_value(value)
            .map_err(|_| binding_error("invalid_request", "continuation is invalid"))?;
        let continuation = BRegContinuation::try_from_projection(projection)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        self.inner
            .continue_list(&continuation)
            .await
            .map_err(client_error)
            .and_then(page_json_value)
    }

    #[napi]
    pub async fn lookup_record_json(
        &self,
        entity_route: String,
        selector: String,
        values_json: Option<String>,
        options: Option<Value>,
    ) -> Result<JsonOutcome> {
        let values = values_json.map(|value| exact_input(&value)).transpose()?;
        let request = lookup_request(selector, values, options)?;
        let BRegComplete { value, metadata } = self
            .inner
            .lookup_record(&entity_route, &request)
            .await
            .map_err(client_error)?;
        complete_json_value(value, metadata)
    }

    #[napi]
    pub async fn create_record_json(
        &self,
        binding: &CreateBinding,
        data_json: String,
        idempotency_key: String,
        format_value: Option<String>,
    ) -> Result<JsonOutcome> {
        let data = exact_input(&data_json)?;
        let data = data
            .as_object()
            .cloned()
            .ok_or_else(|| binding_error("invalid_request", "create data must be an object"))?;
        let request = BRegCreateRequest::new(data)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let operation = binding.inner.clone();
        let BRegComplete { value, metadata } = self
            .inner
            .create_record(&operation, &request, &key, format(format_value)?)
            .await
            .map_err(client_error)?;
        complete_json_value(value, metadata)
    }

    #[napi]
    pub async fn patch_record_json(
        &self,
        binding: &PatchBinding,
        record_identifier: String,
        etag: String,
        operations_json: String,
        idempotency_key: String,
        format_value: Option<String>,
    ) -> Result<JsonOutcome> {
        let record_identifier = uuid::Uuid::parse_str(&record_identifier)
            .map_err(|_| binding_error("invalid_request", "recordIdentifier must be a UUID"))?;
        let etag = BRegEtag::parse(&etag).map_err(|_| {
            binding_error(
                "invalid_request",
                "etag must be a strong Base Registry Engine entity tag",
            )
        })?;
        let request = patch_request(exact_input(&operations_json)?)?;
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let operation = binding.inner.clone();
        let BRegComplete { value, metadata } = self
            .inner
            .patch_record(
                &operation,
                record_identifier,
                &etag,
                &request,
                &key,
                format(format_value)?,
            )
            .await
            .map_err(client_error)?;
        complete_json_value(value, metadata)
    }

    #[napi]
    pub async fn upload_attachment_json(
        &self,
        slot: &AttachmentSlot,
        record_identifier: String,
        etag: String,
        upload: &AttachmentUpload,
        idempotency_key: String,
        format_value: Option<String>,
    ) -> Result<JsonOutcome> {
        let (record_identifier, etag, key) =
            attachment_preconditions(record_identifier, etag, idempotency_key)?;
        let (slot, upload) = (slot.inner.clone(), upload.inner.clone());
        let BRegComplete { value, metadata } = self
            .inner
            .upload_attachment(
                &slot,
                record_identifier,
                &etag,
                &upload,
                &key,
                format(format_value)?,
            )
            .await
            .map_err(client_error)?;
        complete_json_value(value, metadata)
    }

    #[napi]
    pub async fn delete_attachment_json(
        &self,
        slot: &AttachmentSlot,
        record_identifier: String,
        etag: String,
        idempotency_key: String,
        format_value: Option<String>,
    ) -> Result<JsonOutcome> {
        let (record_identifier, etag, key) =
            attachment_preconditions(record_identifier, etag, idempotency_key)?;
        let slot = slot.inner.clone();
        let BRegComplete { value, metadata } = self
            .inner
            .delete_attachment(&slot, record_identifier, &etag, &key, format(format_value)?)
            .await
            .map_err(client_error)?;
        complete_json_value(value, metadata)
    }

    #[napi]
    pub fn lifecycle_actions_json(
        &self,
        authority: &LifecycleAuthority,
        record_json: String,
        format_value: Option<String>,
    ) -> Result<Vec<LifecycleAction>> {
        let record = parse_record(exact_input(&record_json)?, format(format_value)?)?;
        self.inner.lifecycle_actions(&authority.inner, &record)
            .map(|actions| actions.into_iter().map(|inner| LifecycleAction { inner }).collect())
            .map_err(|error| {
                let code = match error {
                    BRegLifecyclePromotionError::Authority => "authority",
                    BRegLifecyclePromotionError::Binding => "binding",
                };
                mapped_error(json!({"kind": "lifecycle_promotion", "code": code, "message": error.to_string()}))
            })
    }

    #[napi]
    pub async fn execute_lifecycle_action_json(
        &self,
        action: &LifecycleAction,
        idempotency_key: String,
    ) -> Result<JsonOutcome> {
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let action = action.inner.clone();
        let BRegComplete { value, metadata } = self
            .inner
            .execute_lifecycle_action(&action, &key)
            .await
            .map_err(client_error)?;
        complete_json_value(receipt_value(&value), metadata)
    }
}
