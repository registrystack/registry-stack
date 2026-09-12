// SPDX-License-Identifier: Apache-2.0
//! Node.js binding for the canonical Base Registry Engine client.

#![deny(unsafe_code)]

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use napi::{bindgen_prelude::Buffer, Error as NapiError, Result};
use napi_derive::napi;
use registry_breg_client::{
    verify_webhook_delivery as verify_core_webhook_delivery, BRegActionInvocationRequest,
    BRegActionTargetConditions as CoreActionTargetConditions, BRegActionTargetConditionsRequest,
    BRegAsOfContinuation, BRegAsOfContinuationProjection, BRegAsOfListRequest,
    BRegAttachmentSlot as CoreAttachmentSlot, BRegAttachmentSlotValue, BRegAttachmentState,
    BRegAttachmentUpload as CoreAttachmentUpload, BRegAttachmentVerificationStatus,
    BRegBatchBinding, BRegBatchBuilder, BRegBatchRequest, BRegBoundingBox, BRegChangeContext,
    BRegComplete, BRegContinuation, BRegContinuationProjection, BRegCreateBinding,
    BRegCreateRequest, BRegCurrentContinuation, BRegCurrentContinuationProjection,
    BRegCurrentListRequest, BRegDirectWrite, BRegEtag, BRegGeoJsonContinuation,
    BRegGeoJsonContinuationProjection, BRegGeoJsonListRequest, BRegGeoJsonOptions,
    BRegImmediateActionBinding, BRegLifecycleAction as CoreLifecycleAction,
    BRegLifecycleActionReceipt, BRegLifecycleAuthority, BRegLifecyclePromotionError,
    BRegListRequest, BRegLookupRequest, BRegMetadata as CoreMetadata, BRegMetadataSelectionError,
    BRegMetadataSelectionErrorKind, BRegPage, BRegPatchBinding, BRegPatchRequest,
    BRegPreparedCreate as CorePreparedCreate, BRegPreparedLifecycle as CorePreparedLifecycle,
    BRegProblemCode, BRegProtocolFailure, BRegRawDocument, BRegRecordFormat, BRegRecordOptions,
    BRegRelationshipContinuation, BRegRelationshipContinuationProjection,
    BRegRelationshipListRequest, BRegRequestApplicationDisposition, BRegRequestProposal,
    BRegRequestReview, BRegRequestReviewMode, BRegRequestState, BRegSnapshotContinuation,
    BRegSnapshotContinuationProjection, BRegSnapshotListRequest, BRegTombstoneBinding,
    BRegWebhookDelivery as CoreWebhookDelivery, BRegWebhookVerificationError,
    BaseRegistryClient as CoreClient, BaseRegistryClientConfig, BaseRegistryClientError,
    PrivateKeyJwt, PrivateKeyJwtConfig, RegistryRecordRepresentation, RegistryRecordResponse,
    StaticToken, TokenError, TokenProvider,
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
    pub snapshot: Option<String>,
    pub valid_at: Option<String>,
}

/// Exact BReg webhook request supplied by a receiver.
#[napi(object)]
pub struct WebhookDeliveryInput {
    pub method: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: Buffer,
    pub key: Buffer,
}

/// Authenticated BReg webhook metadata and exact body.
#[napi(object)]
pub struct VerifiedWebhookDelivery {
    pub id: String,
    pub source: String,
    pub r#type: String,
    pub time: String,
    pub dataschema: String,
    pub generation: String,
    pub attempt: String,
    pub delivery_time: String,
    pub idempotency_key: String,
    pub body: Buffer,
}

/// Verify a BReg Version 1 webhook signature without applying receiver policy.
#[napi]
pub fn verify_webhook_delivery(input: WebhookDeliveryInput) -> Result<VerifiedWebhookDelivery> {
    let verified = verify_core_webhook_delivery(CoreWebhookDelivery {
        method: &input.method,
        path: &input.path,
        headers: &input.headers,
        body: input.body.as_ref(),
        key: input.key.as_ref(),
    })
    .map_err(webhook_verification_error)?;
    Ok(VerifiedWebhookDelivery {
        id: verified.id,
        source: verified.source,
        r#type: verified.event_type,
        time: verified.time,
        dataschema: verified.data_schema,
        generation: verified.generation,
        attempt: verified.attempt,
        delivery_time: verified.delivery_time,
        idempotency_key: verified.idempotency_key,
        body: verified.body.into(),
    })
}

fn webhook_verification_error(error: BRegWebhookVerificationError) -> NapiError {
    mapped_error(json!({
        "kind": "webhook_verification",
        "code": error.code(),
        "message": error.to_string(),
    }))
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
        snapshot: None,
        valid_at: None,
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
    pub snapshot: Option<String>,
    pub valid_at: Option<String>,
}

#[napi(object)]
pub struct RawOutcome {
    pub kind: String,
    pub body: Buffer,
    pub media_type: String,
    pub trace_id: String,
    pub etag: Option<String>,
}

/// Inert original Create request evidence. The bytes carry values and an
/// idempotency key, but no token or executable metadata authority.
#[napi(js_name = "BRegPreparedCreate")]
pub struct PreparedCreate {
    inner: CorePreparedCreate,
}

#[napi]
impl PreparedCreate {
    /// Restore bounded inert evidence previously returned by `toBytes`.
    #[napi(factory)]
    pub fn from_bytes(bytes: Buffer) -> Result<Self> {
        CorePreparedCreate::from_slice(bytes.as_ref())
            .map(|inner| Self { inner })
            .map_err(client_error)
    }

    /// Copy the exact evidence bytes for owner-protected persistence.
    #[napi]
    pub fn to_bytes(&self) -> Buffer {
        self.inner.as_bytes().to_vec().into()
    }
}

/// Inert original lifecycle request evidence. The bytes carry record values
/// and an idempotency key, but no token or executable metadata authority.
#[napi(js_name = "BRegPreparedLifecycle")]
pub struct PreparedLifecycle {
    inner: CorePreparedLifecycle,
}

#[napi]
impl PreparedLifecycle {
    /// Restore bounded inert evidence previously returned by `toBytes`.
    #[napi(factory)]
    pub fn from_bytes(bytes: Buffer) -> Result<Self> {
        CorePreparedLifecycle::from_slice(bytes.as_ref())
            .map(|inner| Self { inner })
            .map_err(client_error)
    }

    /// Copy the exact evidence bytes for owner-protected persistence.
    #[napi]
    pub fn to_bytes(&self) -> Buffer {
        self.inner.as_bytes().to_vec().into()
    }
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
        &[
            "select",
            "accessProfile",
            "format",
            "requestHistoryAfterProposalVersion",
        ],
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
    match object.get("requestHistoryAfterProposalVersion") {
        None | Some(Value::Null) => {}
        Some(value) => {
            let value = safe_integer(
                value,
                1,
                i64::from(u32::MAX),
                "invalid_request",
                "requestHistoryAfterProposalVersion must be 1 through 4294967295",
            )?;
            options = options
                .request_history_after_proposal_version(value as u32)
                .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        }
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
            "bbox",
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
    if let Some(value) = object.get("bbox").filter(|value| !value.is_null()) {
        request = request.bbox(bounding_box(value)?);
    }
    Ok(request)
}

struct CollectionInputs {
    options: BRegRecordOptions,
    top: Option<u32>,
    filter: Option<String>,
    orderby: Option<String>,
    count: Option<bool>,
}

fn collection_inputs(
    value: Option<Value>,
    extra_fields: &[&str],
) -> Result<(Map<String, Value>, CollectionInputs)> {
    let object = options_object(value, "list options must be an object")?.unwrap_or_default();
    let mut allowed = vec![
        "select",
        "accessProfile",
        "format",
        "top",
        "filter",
        "orderby",
        "count",
    ];
    allowed.extend_from_slice(extra_fields);
    only_fields(
        &object,
        &allowed,
        "invalid_request",
        "list options contain an unsupported field",
    )?;
    let base = object
        .iter()
        .filter(|(field, _)| matches!(field.as_str(), "select" | "accessProfile" | "format"))
        .map(|(field, value)| (field.clone(), value.clone()))
        .collect();
    let top = object
        .get("top")
        .filter(|value| !value.is_null())
        .map(|value| {
            safe_integer(
                value,
                1,
                100,
                "invalid_request",
                "top must be 1 through 100",
            )
            .map(|value| value as u32)
        })
        .transpose()?;
    let filter = optional_string(
        &object,
        "filter",
        "invalid_request",
        "filter must be a string",
    )?;
    let orderby = optional_string(
        &object,
        "orderby",
        "invalid_request",
        "orderby must be a string",
    )?;
    let count = match object.get("count") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_bool()
                .ok_or_else(|| binding_error("invalid_request", "count must be a boolean"))?,
        ),
    };
    Ok((
        object,
        CollectionInputs {
            options: record_options(Some(&base))?,
            top,
            filter,
            orderby,
            count,
        },
    ))
}

macro_rules! apply_collection_inputs {
    ($request:ident, $inputs:ident) => {
        $request = $request.options($inputs.options);
        if let Some(value) = $inputs.top {
            $request = $request
                .top(value)
                .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        }
        if let Some(value) = $inputs.filter {
            $request = $request
                .filter(value)
                .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        }
        if let Some(value) = $inputs.orderby {
            $request = $request
                .orderby(value)
                .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        }
        if let Some(value) = $inputs.count {
            $request = $request.count(value);
        }
    };
}

fn current_list_request(value: Option<Value>) -> Result<BRegCurrentListRequest> {
    let (_, inputs) = collection_inputs(value, &[])?;
    let mut request = BRegCurrentListRequest::default();
    apply_collection_inputs!(request, inputs);
    Ok(request)
}

fn as_of_list_request(value: Option<Value>) -> Result<BRegAsOfListRequest> {
    let (object, inputs) = collection_inputs(value, &["asOf"])?;
    let as_of = required_string(
        &object,
        "asOf",
        "invalid_request",
        "asOf must be a canonical UTC RFC 3339 string",
    )?;
    let mut request = BRegAsOfListRequest::new(as_of)
        .map_err(|error| binding_error("invalid_request", error.to_string()))?;
    apply_collection_inputs!(request, inputs);
    Ok(request)
}

fn snapshot_list_request(value: Option<Value>) -> Result<BRegSnapshotListRequest> {
    let (object, inputs) = collection_inputs(value, &["snapshot", "validAt"])?;
    let mut request = BRegSnapshotListRequest::default();
    apply_collection_inputs!(request, inputs);
    if let Some(value) = optional_string(
        &object,
        "snapshot",
        "invalid_request",
        "snapshot must be a string",
    )? {
        request = request
            .snapshot(value)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
    }
    if let Some(value) = optional_string(
        &object,
        "validAt",
        "invalid_request",
        "validAt must be a string",
    )? {
        request = request
            .valid_at(value)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
    }
    Ok(request)
}

fn relationship_list_request(value: Option<Value>) -> Result<BRegRelationshipListRequest> {
    let (_, inputs) = collection_inputs(value, &[])?;
    let mut request = BRegRelationshipListRequest::default();
    apply_collection_inputs!(request, inputs);
    Ok(request)
}

fn bounding_box(value: &Value) -> Result<BRegBoundingBox> {
    let coordinates = value
        .as_array()
        .filter(|values| values.len() == 4)
        .ok_or_else(|| {
            binding_error("invalid_request", "bbox must contain four decimal strings")
        })?;
    let coordinates = coordinates
        .iter()
        .map(|value| value.as_str())
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| binding_error("invalid_request", "bbox must contain decimal strings"))?;
    BRegBoundingBox::new(
        coordinates[0],
        coordinates[1],
        coordinates[2],
        coordinates[3],
    )
    .map_err(|error| binding_error("invalid_request", error.to_string()))
}

fn geojson_options(object: &Map<String, Value>) -> Result<BRegGeoJsonOptions> {
    let mut options = BRegGeoJsonOptions::default();
    match object.get("select") {
        None | Some(Value::Null) => {}
        Some(Value::Array(values)) => {
            let fields = values
                .iter()
                .map(|value| value.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| {
                    binding_error("invalid_request", "select must be an array of strings")
                })?;
            options = options
                .select(fields)
                .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        }
        Some(_) => {
            return Err(binding_error(
                "invalid_request",
                "select must be an array of strings",
            ))
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

fn geojson_list_request(value: Option<Value>) -> Result<BRegGeoJsonListRequest> {
    let (object, inputs) = collection_inputs(value, &["bbox"])?;
    if object.contains_key("format") {
        return Err(binding_error(
            "invalid_request",
            "GeoJSON options do not accept a format",
        ));
    }
    let base = object
        .iter()
        .filter(|(field, _)| matches!(field.as_str(), "select" | "accessProfile"))
        .map(|(field, value)| (field.clone(), value.clone()))
        .collect();
    let mut request = BRegGeoJsonListRequest::default().options(geojson_options(&base)?);
    if let Some(value) = inputs.top {
        request = request
            .top(value)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
    }
    if let Some(value) = inputs.filter {
        request = request
            .filter(value)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
    }
    if let Some(value) = inputs.orderby {
        request = request
            .orderby(value)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
    }
    if let Some(value) = inputs.count {
        request = request.count(value);
    }
    if let Some(value) = object.get("bbox").filter(|value| !value.is_null()) {
        request = request.bbox(bounding_box(value)?);
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
        snapshot: None,
        valid_at: None,
    })
}

fn specialized_page_value<T: Serialize, C: Serialize>(
    value: T,
    continuation: Option<C>,
    metadata: registry_breg_client::BRegResponseMetadata,
    snapshot: Option<String>,
    valid_at: Option<String>,
) -> Result<PageOutcome> {
    let (trace_id, etag, _) = metadata_parts(&metadata);
    Ok(PageOutcome {
        kind: "complete".into(),
        value: serde_json::to_value(value)
            .map_err(|_| binding_error("protocol", "client result is not representable"))?,
        continuation: continuation
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| binding_error("protocol", "client continuation is not representable"))?,
        trace_id,
        etag,
        snapshot,
        valid_at,
    })
}

fn specialized_page_json<T: Serialize, C: Serialize>(
    value: T,
    continuation: Option<C>,
    metadata: registry_breg_client::BRegResponseMetadata,
    snapshot: Option<String>,
    valid_at: Option<String>,
) -> Result<JsonOutcome> {
    let mut result = complete_json_value(value, metadata)?;
    result.continuation = continuation
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| binding_error("protocol", "client continuation is not representable"))?;
    result.snapshot = snapshot;
    result.valid_at = valid_at;
    Ok(result)
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

fn input_object(value: Value, message: &'static str) -> Result<Map<String, Value>> {
    value
        .as_object()
        .cloned()
        .ok_or_else(|| binding_error("invalid_request", message))
}

fn change_context(value: Value) -> Result<BRegChangeContext> {
    let object = input_object(value, "changeContext must be an object")?;
    only_fields(
        &object,
        &["kind", "reasonCode", "reasonText", "sourceReferences"],
        "invalid_request",
        "changeContext contains an unsupported field",
    )?;
    let kind = required_string(
        &object,
        "kind",
        "invalid_request",
        "changeContext.kind must be a string",
    )?;
    let mut context = match kind.as_str() {
        "change" if !object.contains_key("reasonCode") => BRegChangeContext::change(),
        "correction" => BRegChangeContext::correction(required_string(
            &object,
            "reasonCode",
            "invalid_request",
            "a correction requires reasonCode",
        )?)
        .map_err(|error| binding_error("invalid_request", error.to_string()))?,
        _ => {
            return Err(binding_error(
                "invalid_request",
                "changeContext.kind or reasonCode is invalid",
            ))
        }
    };
    if let Some(value) = optional_string(
        &object,
        "reasonText",
        "invalid_request",
        "changeContext.reasonText must be a string",
    )? {
        context = context
            .reason_text(value)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
    }
    match object.get("sourceReferences") {
        None => {}
        Some(Value::Array(values)) => {
            for value in values {
                let value = value.as_str().ok_or_else(|| {
                    binding_error(
                        "invalid_request",
                        "changeContext.sourceReferences must contain strings",
                    )
                })?;
                context = context
                    .source_reference(value)
                    .map_err(|error| binding_error("invalid_request", error.to_string()))?;
            }
        }
        Some(_) => {
            return Err(binding_error(
                "invalid_request",
                "changeContext.sourceReferences must be an array",
            ))
        }
    }
    Ok(context)
}

fn batch_request(binding: &BRegBatchBinding, value: Value) -> Result<BRegBatchRequest> {
    let object = input_object(value, "batch request must be an object")?;
    only_fields(
        &object,
        &["items", "changeContext"],
        "invalid_request",
        "batch request contains an unsupported field",
    )?;
    let items = object
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| binding_error("invalid_request", "batch items must be an array"))?;
    let mut builder = BRegBatchBuilder::new(binding);
    for item in items {
        let item = item.as_object().ok_or_else(|| {
            binding_error("invalid_request", "every batch item must be an object")
        })?;
        let operation = required_string(
            item,
            "operation",
            "invalid_request",
            "batch item operation must be a string",
        )?;
        builder = match operation.as_str() {
            "create" => {
                only_fields(
                    item,
                    &["operation", "data"],
                    "invalid_request",
                    "Create batch item contains an unsupported field",
                )?;
                let data = item
                    .get("data")
                    .and_then(Value::as_object)
                    .cloned()
                    .ok_or_else(|| {
                        binding_error("invalid_request", "Create batch data must be an object")
                    })?;
                let request = BRegCreateRequest::new(data)
                    .map_err(|error| binding_error("invalid_request", error.to_string()))?;
                builder
                    .create(&request)
                    .map_err(|error| binding_error("invalid_request", error.to_string()))?
            }
            "patch" => {
                only_fields(
                    item,
                    &["operation", "recordIdentifier", "etag", "operations"],
                    "invalid_request",
                    "Patch batch item contains an unsupported field",
                )?;
                let record_identifier = uuid::Uuid::parse_str(&required_string(
                    item,
                    "recordIdentifier",
                    "invalid_request",
                    "Patch batch recordIdentifier must be a UUID",
                )?)
                .map_err(|_| {
                    binding_error(
                        "invalid_request",
                        "Patch batch recordIdentifier must be a UUID",
                    )
                })?;
                let etag = BRegEtag::parse(&required_string(
                    item,
                    "etag",
                    "invalid_request",
                    "Patch batch etag must be a string",
                )?)
                .map_err(|error| binding_error("invalid_request", error.to_string()))?;
                let request = patch_request(item.get("operations").cloned().ok_or_else(|| {
                    binding_error("invalid_request", "Patch batch operations are required")
                })?)?;
                builder
                    .patch(record_identifier, &etag, &request)
                    .map_err(|error| binding_error("invalid_request", error.to_string()))?
            }
            _ => {
                return Err(binding_error(
                    "invalid_request",
                    "batch item operation is unsupported",
                ))
            }
        };
    }
    if let Some(value) = object.get("changeContext") {
        builder = builder.change_context(change_context(value.clone())?);
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
    let mut receipt = json!({
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
    });
    if let Some(actor_reference) = value.actor_reference() {
        receipt["actorReference"] = Value::String(actor_reference.to_owned());
    }
    receipt
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

fn change_request_capability_value(
    value: &registry_breg_client::BRegChangeRequestCapability,
) -> Value {
    let planner = value.planner();
    let limits = planner.limits();
    json!({
        "planner": {
            "kind": match planner.kind() {
                registry_breg_client::BRegChangeRequestPlannerKind::Declarative => "declarative",
                registry_breg_client::BRegChangeRequestPlannerKind::Rhai => "rhai",
            },
            "abi": planner.abi(),
            "limits": limits.map(|limits| json!({
                "maximumTargets": limits.maximum_targets(),
                "maximumFieldMutations": limits.maximum_field_mutations(),
                "maximumSnapshotBytes": limits.maximum_snapshot_bytes(),
                "maximumSourceBytes": limits.maximum_source_bytes(),
                "maximumOperations": limits.maximum_operations(),
                "maximumCallDepth": limits.maximum_call_depth(),
                "maximumExpressionDepth": limits.maximum_expression_depth(),
                "maximumStringBytes": limits.maximum_string_bytes(),
                "maximumArrayItems": limits.maximum_array_items(),
                "maximumMapEntries": limits.maximum_map_entries(),
                "maximumModules": limits.maximum_modules(),
            })),
            "possibleWriteCount": planner.possible_write_count(),
            "possibleWriteOperations": planner.possible_write_operations().iter()
                .map(registry_breg_client::BRegOperationKind::as_str).collect::<Vec<_>>(),
        },
        "reviewMode": match value.review_mode() {
            registry_breg_client::BRegChangeRequestReviewMode::None => "none",
            registry_breg_client::BRegChangeRequestReviewMode::Staged => "staged",
        },
        "stages": value.stages().map(|stages| {
            stages.iter().map(|stage| json!({
                "id": stage.identifier(),
                "approvals": stage.approvals(),
                "excludeSubmitter": stage.exclude_submitter(),
                "excludePreviousReviewers": stage.exclude_previous_reviewers(),
            })).collect::<Vec<_>>()
        }),
        "application": {
            "mode": match value.application().mode() {
                registry_breg_client::BRegChangeRequestApplicationMode::Manual => "manual",
                registry_breg_client::BRegChangeRequestApplicationMode::Automatic => "automatic",
                registry_breg_client::BRegChangeRequestApplicationMode::Planner => "planner",
            },
            "allowedDispositions": value.application().allowed_dispositions().iter().map(|value| match value {
                registry_breg_client::BRegChangeRequestDisposition::Apply => "apply",
                registry_breg_client::BRegChangeRequestDisposition::Queue => "queue",
            }).collect::<Vec<_>>(),
            "queueReasons": value.application().queue_reasons().iter().map(|reason| json!({
                "code": reason.code(), "label": reason.label(),
            })).collect::<Vec<_>>(),
        },
    })
}

fn immediate_action_descriptor_value(
    value: &registry_breg_client::BRegImmediateActionDescriptor,
) -> Value {
    let bounds = value.bounds();
    json!({
        "id": value.identifier(),
        "contractFingerprint": value.contract_fingerprint(),
        "inputMode": value.input_mode(),
        "maximumInputStringBytes": value.maximum_input_string_bytes(),
        "inputs": value.inputs().iter().map(|input| json!({
            "id": input.identifier(), "apiName": input.api_name(),
            "fieldTypeJson": input.field_type().to_string(), "required": input.required(),
            "nullable": input.nullable(), "classification": input.classification(),
        })).collect::<Vec<_>>(),
        "referenceInputs": value.reference_inputs().iter().map(|input| json!({
            "input": input.input_identifier(), "apiName": input.api_name(),
            "targetEntity": input.target_entity(),
        })).collect::<Vec<_>>(),
        "requiredConditionKeys": value.required_condition_keys(),
        "resultEffects": value.result_effects().iter().map(|effect| json!({
            "effect": effect.effect_identifier(), "entity": effect.entity_identifier(),
            "operation": effect.operation().as_str(),
        })).collect::<Vec<_>>(),
        "accessProfile": value.access_profile(), "invokePath": value.invoke_path(),
        "targetConditionsPath": value.target_conditions_path(),
        "bounds": {
            "maximumTargets": bounds.maximum_targets(),
            "maximumFieldMutations": bounds.maximum_field_mutations(),
            "maximumSnapshotBytes": bounds.maximum_snapshot_bytes(),
        },
    })
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

#[napi(js_name = "BRegImmediateActionBinding")]
pub struct ImmediateActionBinding {
    inner: BRegImmediateActionBinding,
}

#[napi(js_name = "BRegTombstoneBinding")]
pub struct TombstoneBinding {
    inner: BRegTombstoneBinding,
}

#[napi(js_name = "BRegBatchBinding")]
pub struct BatchBinding {
    inner: BRegBatchBinding,
}

/// Opaque server-validated target conditions for one immediate action.
#[napi(js_name = "BRegActionTargetConditions")]
pub struct ActionTargetConditions {
    inner: CoreActionTargetConditions,
    trace_id: String,
}

#[napi]
impl ActionTargetConditions {
    #[napi(getter)]
    pub fn precondition_keys(&self) -> Vec<String> {
        self.inner.precondition_keys().map(str::to_owned).collect()
    }

    #[napi(getter)]
    pub fn value_json(&self) -> Result<String> {
        serde_json::to_string(&self.inner)
            .map_err(|_| binding_error("protocol", "target conditions are not representable"))
    }

    #[napi(getter)]
    pub fn trace_id(&self) -> String {
        self.trace_id.clone()
    }
}

#[napi(js_name = "BRegLifecycleAuthority")]
pub struct LifecycleAuthority {
    inner: BRegLifecycleAuthority,
}

#[napi(js_name = "BRegLifecycleAction")]
pub struct LifecycleAction {
    inner: CoreLifecycleAction,
}

/// A recovered Create request, key, and representation. This remains inert
/// until `executeRecoveredCreate` is explicitly called with fresh authority.
#[napi(js_name = "BRegRecoveredCreate")]
pub struct RecoveredCreate {
    request: BRegCreateRequest,
    key: registry_breg_client::BRegIdempotencyKey,
    format: BRegRecordFormat,
}

/// A recovered lifecycle action and key. This remains inert until
/// `executeRecoveredLifecycleAction` is explicitly called.
#[napi(js_name = "BRegRecoveredLifecycle")]
pub struct RecoveredLifecycle {
    action: CoreLifecycleAction,
    key: registry_breg_client::BRegIdempotencyKey,
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
                "readableFields": operation.readable_fields(),
                "readableRequestFields": operation.readable_request_fields(),
                "createWritableFields": operation.create_writable_fields(),
                "patchWritableFields": operation.patch_writable_fields(), "query": operation.query(),
                "selectors": operation.selectors().iter().map(|selector| json!({
                    "id": selector.identifier(), "label": selector.label(),
                    "valueOrigin": selector.value_origin(), "requestFields": selector.request_fields(),
                    "fields": selector.fields().iter().map(|field| json!({
                        "id": field.identifier(), "apiName": field.api_name(), "label": field.label(),
                        "schemaJson": field.schema().to_string(), "required": field.required(),
                    })).collect::<Vec<_>>(),
                })).collect::<Vec<_>>(),
                "readPath": operation.read_path().map(|path| json!({
                    "id": path.identifier(), "label": path.label(),
                })),
                "fields": operation.fields().iter().map(|field| json!({
                    "id": field.identifier(), "apiName": field.api_name(), "label": field.label(),
                    "schemaJson": field.schema().to_string(), "required": field.required(),
                    "nullable": field.nullable(), "readOnly": field.read_only(), "removable": field.removable(),
                    "referenceTargetEntity": field.reference_target_entity(),
                    "codeLabels": field.code_labels(),
                    "storageValidation": field.storage_validation().map(|validation| json!({
                        "kind": validation.kind(), "pattern": validation.pattern(),
                    })),
                    "reference": field.reference().map(|reference| json!({
                        "manualEntry": reference.manual_entry(), "targetEntity": reference.target_entity(),
                        "operations": reference.operations().iter().map(|operation| json!({
                            "operationId": operation.operation_identifier(),
                            "accessProfile": operation.access_profile(), "labelFields": operation.label_fields(),
                        })).collect::<Vec<_>>(),
                    })),
                })).collect::<Vec<_>>(),
                "request": { "fieldNames": request.field_names(), "queryParameters": request.query_parameters(),
                    "body": request.body(), "contentType": request.content_type(),
                    "schemaJson": request.schema().map(Value::to_string),
                    "idempotencyKeyRequired": request.idempotency_key_required(), "ifMatchRequired": request.if_match_required(),
                    "mutationSemantics": request.mutation_semantics(), "patchPathPrefix": request.patch_path_prefix(),
                    "patchOperations": request.patch_operations(), "removeSemantics": request.remove_semantics(),
                    "maximumItems": request.maximum_items(), "maximumBodyBytes": request.maximum_body_bytes(),
                    "allowCreate": request.allow_create(), "allowPatch": request.allow_patch() },
            })
        }).collect())
    }

    /// Complete typed caller-filtered immediate-action descriptors.
    #[napi(getter)]
    pub fn immediate_actions(&self) -> Value {
        Value::Array(
            self.inner
                .immediate_actions()
                .iter()
                .map(immediate_action_descriptor_value)
                .collect(),
        )
    }

    /// Original caller-filtered action metadata as exact JSON text.
    #[napi(getter)]
    pub fn actions_json(&self) -> Result<Option<String>> {
        self.inner
            .actions()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| binding_error("protocol", "action metadata is not representable"))
    }

    /// Descriptive change-request capability for one entity, when advertised.
    #[napi]
    pub fn change_request_capability(&self, entity_identifier: String) -> Option<Value> {
        self.inner
            .change_request_capability(&entity_identifier)
            .map(change_request_capability_value)
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

    #[napi]
    pub fn select_immediate_action(
        &self,
        action_identifier: String,
        expected_profile: String,
    ) -> Result<ImmediateActionBinding> {
        self.inner
            .select_immediate_action(&action_identifier, &expected_profile)
            .map(|inner| ImmediateActionBinding { inner })
            .map_err(selection_error)
    }

    #[napi]
    pub fn select_tombstone(
        &self,
        entity_identifier: String,
        expected_profile: String,
    ) -> Result<TombstoneBinding> {
        self.inner
            .select_tombstone(&entity_identifier, &expected_profile)
            .map(|inner| TombstoneBinding { inner })
            .map_err(selection_error)
    }

    #[napi]
    pub fn select_batch(
        &self,
        entity_identifier: String,
        expected_profile: String,
    ) -> Result<BatchBinding> {
        self.inner
            .select_batch(&entity_identifier, &expected_profile)
            .map(|inner| BatchBinding { inner })
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

    /// Retrieve one bounded first page of record revisions as inert JSON.
    #[napi]
    pub async fn record_revisions(
        &self,
        entity_route: String,
        record_identifier: String,
        access_profile: Option<String>,
    ) -> Result<RawOutcome> {
        self.inner
            .record_revisions(&entity_route, &record_identifier, access_profile.as_deref())
            .await
            .map(raw_value)
            .map_err(client_error)
    }

    /// Retrieve one exact retained revision as validated inert record JSON.
    #[napi]
    pub async fn get_record_revision(
        &self,
        entity_route: String,
        record_identifier: String,
        revision: i64,
        options: Option<Value>,
    ) -> Result<RawOutcome> {
        if !(1..=MAXIMUM_JAVASCRIPT_SAFE_INTEGER).contains(&revision) {
            return Err(binding_error(
                "invalid_request",
                "revision must be a positive safe integer",
            ));
        }
        let options = options_object(options, "record options must be an object")?;
        self.inner
            .get_record_revision(
                &entity_route,
                &record_identifier,
                revision as u64,
                &record_options(options.as_ref())?,
            )
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

    #[napi(js_name = "getGeoJsonRecord")]
    pub async fn get_geo_json_record(
        &self,
        entity_route: String,
        record_identifier: String,
        options: Option<Value>,
    ) -> Result<CompleteOutcome> {
        let options =
            options_object(options, "GeoJSON options must be an object")?.unwrap_or_default();
        only_fields(
            &options,
            &["select", "accessProfile"],
            "invalid_request",
            "GeoJSON options contain an unsupported field",
        )?;
        let BRegComplete { value, metadata } = self
            .inner
            .get_geojson_record(
                &entity_route,
                &record_identifier,
                &geojson_options(&options)?,
            )
            .await
            .map_err(client_error)?;
        complete_value(value, metadata)
    }

    #[napi(js_name = "listGeoJsonRecords")]
    pub async fn list_geo_json_records(
        &self,
        entity_route: String,
        options: Option<Value>,
    ) -> Result<PageOutcome> {
        let BRegComplete { value, metadata } = self
            .inner
            .list_geojson_records(&entity_route, &geojson_list_request(options)?)
            .await
            .map_err(client_error)?;
        specialized_page_value(value.value, value.continuation, metadata, None, None)
    }

    #[napi(js_name = "continueGeoJsonList")]
    pub async fn continue_geo_json_list(&self, value: Value) -> Result<PageOutcome> {
        let projection: BRegGeoJsonContinuationProjection = serde_json::from_value(value)
            .map_err(|_| binding_error("invalid_request", "GeoJSON continuation is invalid"))?;
        let continuation = BRegGeoJsonContinuation::try_from_projection(projection)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let BRegComplete { value, metadata } = self
            .inner
            .continue_geojson_list(&continuation)
            .await
            .map_err(client_error)?;
        specialized_page_value(value.value, value.continuation, metadata, None, None)
    }

    #[napi]
    pub async fn list_current_records(
        &self,
        entity_route: String,
        options: Option<Value>,
    ) -> Result<PageOutcome> {
        let BRegComplete { value, metadata } = self
            .inner
            .list_current_records(&entity_route, &current_list_request(options)?)
            .await
            .map_err(client_error)?;
        specialized_page_value(value.value, value.continuation, metadata, None, None)
    }

    #[napi]
    pub async fn continue_current_list(&self, value: Value) -> Result<PageOutcome> {
        let projection: BRegCurrentContinuationProjection = serde_json::from_value(value)
            .map_err(|_| binding_error("invalid_request", "current continuation is invalid"))?;
        let continuation = BRegCurrentContinuation::try_from_projection(projection)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let BRegComplete { value, metadata } = self
            .inner
            .continue_current_list(&continuation)
            .await
            .map_err(client_error)?;
        specialized_page_value(value.value, value.continuation, metadata, None, None)
    }

    #[napi]
    pub async fn list_records_as_of(
        &self,
        entity_route: String,
        options: Option<Value>,
    ) -> Result<PageOutcome> {
        let BRegComplete { value, metadata } = self
            .inner
            .list_records_as_of(&entity_route, &as_of_list_request(options)?)
            .await
            .map_err(client_error)?;
        specialized_page_value(value.value, value.continuation, metadata, None, None)
    }

    #[napi]
    pub async fn continue_as_of_list(&self, value: Value) -> Result<PageOutcome> {
        let projection: BRegAsOfContinuationProjection = serde_json::from_value(value)
            .map_err(|_| binding_error("invalid_request", "as-of continuation is invalid"))?;
        let continuation = BRegAsOfContinuation::try_from_projection(projection)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let BRegComplete { value, metadata } = self
            .inner
            .continue_as_of_list(&continuation)
            .await
            .map_err(client_error)?;
        specialized_page_value(value.value, value.continuation, metadata, None, None)
    }

    #[napi]
    pub async fn list_snapshot_records(
        &self,
        entity_route: String,
        options: Option<Value>,
    ) -> Result<PageOutcome> {
        let BRegComplete { value, metadata } = self
            .inner
            .list_snapshot_records(&entity_route, &snapshot_list_request(options)?)
            .await
            .map_err(client_error)?;
        specialized_page_value(
            value.value,
            value.continuation,
            metadata,
            Some(value.snapshot),
            value.valid_at,
        )
    }

    #[napi]
    pub async fn continue_snapshot_list(&self, value: Value) -> Result<PageOutcome> {
        let projection: BRegSnapshotContinuationProjection = serde_json::from_value(value)
            .map_err(|_| binding_error("invalid_request", "snapshot continuation is invalid"))?;
        let continuation = BRegSnapshotContinuation::try_from_projection(projection)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let BRegComplete { value, metadata } = self
            .inner
            .continue_snapshot_list(&continuation)
            .await
            .map_err(client_error)?;
        specialized_page_value(
            value.value,
            value.continuation,
            metadata,
            Some(value.snapshot),
            value.valid_at,
        )
    }

    #[napi]
    pub async fn list_relationship_records(
        &self,
        entity_route: String,
        record_identifier: String,
        path_route: String,
        options: Option<Value>,
    ) -> Result<PageOutcome> {
        let BRegComplete { value, metadata } = self
            .inner
            .list_relationship_records(
                &entity_route,
                &record_identifier,
                &path_route,
                &relationship_list_request(options)?,
            )
            .await
            .map_err(client_error)?;
        specialized_page_value(value.value, value.continuation, metadata, None, None)
    }

    #[napi]
    pub async fn continue_relationship_list(&self, value: Value) -> Result<PageOutcome> {
        let projection: BRegRelationshipContinuationProjection = serde_json::from_value(value)
            .map_err(|_| {
                binding_error("invalid_request", "relationship continuation is invalid")
            })?;
        let continuation = BRegRelationshipContinuation::try_from_projection(projection)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let BRegComplete { value, metadata } = self
            .inner
            .continue_relationship_list(&continuation)
            .await
            .map_err(client_error)?;
        specialized_page_value(value.value, value.continuation, metadata, None, None)
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

    /// Fetch opaque target conditions for one metadata-selected action.
    #[napi]
    pub async fn action_target_conditions(
        &self,
        binding: &ImmediateActionBinding,
        inputs: Value,
    ) -> Result<ActionTargetConditions> {
        let request = BRegActionTargetConditionsRequest::new(
            &binding.inner,
            input_object(inputs, "action inputs must be an object")?,
        )
        .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let BRegComplete { value, metadata } = self
            .inner
            .action_target_conditions(&binding.inner, &request)
            .await
            .map_err(client_error)?;
        Ok(ActionTargetConditions {
            inner: value,
            trace_id: metadata.trace_id().as_str().to_owned(),
        })
    }

    /// Invoke one metadata-selected immediate action without automatic retry.
    #[napi]
    pub async fn invoke_action(
        &self,
        binding: &ImmediateActionBinding,
        inputs: Value,
        idempotency_key: String,
        conditions: Option<&ActionTargetConditions>,
    ) -> Result<CompleteOutcome> {
        let request = BRegActionInvocationRequest::new(
            &binding.inner,
            input_object(inputs, "action inputs must be an object")?,
            conditions.map(|value| &value.inner),
        )
        .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let BRegComplete { value, metadata } = self
            .inner
            .invoke_action(&binding.inner, &request, &key)
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

    /// Prepare inert Create evidence before any token acquisition or I/O.
    #[napi]
    pub fn prepare_create(
        &self,
        binding: &CreateBinding,
        data: Value,
        idempotency_key: String,
        format_value: Option<String>,
    ) -> Result<PreparedCreate> {
        let data = data
            .as_object()
            .cloned()
            .ok_or_else(|| binding_error("invalid_request", "create data must be an object"))?;
        let request = BRegCreateRequest::new(data)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        self.inner
            .prepare_create(&binding.inner, &request, &key, format(format_value)?)
            .map(|inner| PreparedCreate { inner })
            .map_err(client_error)
    }

    /// Revalidate saved Create evidence against freshly selected authority.
    #[napi]
    pub fn recover_create(
        &self,
        binding: &CreateBinding,
        prepared: &PreparedCreate,
    ) -> Result<RecoveredCreate> {
        let (request, key, format) = self
            .inner
            .recover_create(&binding.inner, &prepared.inner)
            .map_err(client_error)?;
        Ok(RecoveredCreate {
            request,
            key,
            format,
        })
    }

    /// Explicitly send a recovered Create request with fresh authority.
    #[napi]
    pub async fn execute_recovered_create(
        &self,
        binding: &CreateBinding,
        recovered: &RecoveredCreate,
    ) -> Result<CompleteOutcome> {
        let BRegComplete { value, metadata } = self
            .inner
            .create_record(
                &binding.inner,
                &recovered.request,
                &recovered.key,
                recovered.format,
            )
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

    /// Execute one metadata-selected atomic batch without automatic retry.
    #[napi]
    pub async fn batch_records(
        &self,
        binding: &BatchBinding,
        request: Value,
        idempotency_key: String,
    ) -> Result<CompleteOutcome> {
        let request = batch_request(&binding.inner, request)?;
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let BRegComplete { value, metadata } = self
            .inner
            .batch_records(&binding.inner, &request, &key)
            .await
            .map_err(client_error)?;
        complete_value(value, metadata)
    }

    /// Tombstone one record against its current strong ETag.
    #[napi]
    pub async fn tombstone_record(
        &self,
        binding: &TombstoneBinding,
        record_identifier: String,
        etag: String,
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
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let BRegComplete { value, metadata } = self
            .inner
            .tombstone_record(
                &binding.inner,
                record_identifier,
                &etag,
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

    /// Prepare inert lifecycle evidence before any token acquisition or I/O.
    #[napi]
    pub fn prepare_lifecycle_action(
        &self,
        authority: &LifecycleAuthority,
        record: Value,
        action: &LifecycleAction,
        idempotency_key: String,
        format_value: Option<String>,
    ) -> Result<PreparedLifecycle> {
        let record = parse_record(record, format(format_value)?)?;
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        self.inner
            .prepare_lifecycle_action(&authority.inner, &record, &action.inner, &key)
            .map(|inner| PreparedLifecycle { inner })
            .map_err(client_error)
    }

    /// Revalidate saved lifecycle evidence against freshly selected authority.
    #[napi]
    pub fn recover_lifecycle_action(
        &self,
        authority: &LifecycleAuthority,
        prepared: &PreparedLifecycle,
    ) -> Result<RecoveredLifecycle> {
        let (action, key) = self
            .inner
            .recover_lifecycle_action(&authority.inner, &prepared.inner)
            .map_err(client_error)?;
        Ok(RecoveredLifecycle { action, key })
    }

    /// Explicitly send a recovered lifecycle action.
    #[napi]
    pub async fn execute_recovered_lifecycle_action(
        &self,
        recovered: &RecoveredLifecycle,
    ) -> Result<CompleteOutcome> {
        let BRegComplete { value, metadata } = self
            .inner
            .execute_lifecycle_action(&recovered.action, &recovered.key)
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

    #[napi(js_name = "getGeoJsonRecordJson")]
    pub async fn get_geo_json_record_json(
        &self,
        entity_route: String,
        record_identifier: String,
        options: Option<Value>,
    ) -> Result<JsonOutcome> {
        let options =
            options_object(options, "GeoJSON options must be an object")?.unwrap_or_default();
        only_fields(
            &options,
            &["select", "accessProfile"],
            "invalid_request",
            "GeoJSON options contain an unsupported field",
        )?;
        let BRegComplete { value, metadata } = self
            .inner
            .get_geojson_record(
                &entity_route,
                &record_identifier,
                &geojson_options(&options)?,
            )
            .await
            .map_err(client_error)?;
        complete_json_value(value, metadata)
    }

    #[napi(js_name = "listGeoJsonRecordsJson")]
    pub async fn list_geo_json_records_json(
        &self,
        entity_route: String,
        options: Option<Value>,
    ) -> Result<JsonOutcome> {
        let BRegComplete { value, metadata } = self
            .inner
            .list_geojson_records(&entity_route, &geojson_list_request(options)?)
            .await
            .map_err(client_error)?;
        specialized_page_json(value.value, value.continuation, metadata, None, None)
    }

    #[napi(js_name = "continueGeoJsonListJson")]
    pub async fn continue_geo_json_list_json(&self, value: Value) -> Result<JsonOutcome> {
        let projection: BRegGeoJsonContinuationProjection = serde_json::from_value(value)
            .map_err(|_| binding_error("invalid_request", "GeoJSON continuation is invalid"))?;
        let continuation = BRegGeoJsonContinuation::try_from_projection(projection)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let BRegComplete { value, metadata } = self
            .inner
            .continue_geojson_list(&continuation)
            .await
            .map_err(client_error)?;
        specialized_page_json(value.value, value.continuation, metadata, None, None)
    }

    #[napi]
    pub async fn list_current_records_json(
        &self,
        entity_route: String,
        options: Option<Value>,
    ) -> Result<JsonOutcome> {
        let BRegComplete { value, metadata } = self
            .inner
            .list_current_records(&entity_route, &current_list_request(options)?)
            .await
            .map_err(client_error)?;
        specialized_page_json(value.value, value.continuation, metadata, None, None)
    }

    #[napi]
    pub async fn continue_current_list_json(&self, value: Value) -> Result<JsonOutcome> {
        let projection: BRegCurrentContinuationProjection = serde_json::from_value(value)
            .map_err(|_| binding_error("invalid_request", "current continuation is invalid"))?;
        let continuation = BRegCurrentContinuation::try_from_projection(projection)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let BRegComplete { value, metadata } = self
            .inner
            .continue_current_list(&continuation)
            .await
            .map_err(client_error)?;
        specialized_page_json(value.value, value.continuation, metadata, None, None)
    }

    #[napi]
    pub async fn list_records_as_of_json(
        &self,
        entity_route: String,
        options: Option<Value>,
    ) -> Result<JsonOutcome> {
        let BRegComplete { value, metadata } = self
            .inner
            .list_records_as_of(&entity_route, &as_of_list_request(options)?)
            .await
            .map_err(client_error)?;
        specialized_page_json(value.value, value.continuation, metadata, None, None)
    }

    #[napi]
    pub async fn continue_as_of_list_json(&self, value: Value) -> Result<JsonOutcome> {
        let projection: BRegAsOfContinuationProjection = serde_json::from_value(value)
            .map_err(|_| binding_error("invalid_request", "as-of continuation is invalid"))?;
        let continuation = BRegAsOfContinuation::try_from_projection(projection)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let BRegComplete { value, metadata } = self
            .inner
            .continue_as_of_list(&continuation)
            .await
            .map_err(client_error)?;
        specialized_page_json(value.value, value.continuation, metadata, None, None)
    }

    #[napi]
    pub async fn list_snapshot_records_json(
        &self,
        entity_route: String,
        options: Option<Value>,
    ) -> Result<JsonOutcome> {
        let BRegComplete { value, metadata } = self
            .inner
            .list_snapshot_records(&entity_route, &snapshot_list_request(options)?)
            .await
            .map_err(client_error)?;
        specialized_page_json(
            value.value,
            value.continuation,
            metadata,
            Some(value.snapshot),
            value.valid_at,
        )
    }

    #[napi]
    pub async fn continue_snapshot_list_json(&self, value: Value) -> Result<JsonOutcome> {
        let projection: BRegSnapshotContinuationProjection = serde_json::from_value(value)
            .map_err(|_| binding_error("invalid_request", "snapshot continuation is invalid"))?;
        let continuation = BRegSnapshotContinuation::try_from_projection(projection)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let BRegComplete { value, metadata } = self
            .inner
            .continue_snapshot_list(&continuation)
            .await
            .map_err(client_error)?;
        specialized_page_json(
            value.value,
            value.continuation,
            metadata,
            Some(value.snapshot),
            value.valid_at,
        )
    }

    #[napi]
    pub async fn list_relationship_records_json(
        &self,
        entity_route: String,
        record_identifier: String,
        path_route: String,
        options: Option<Value>,
    ) -> Result<JsonOutcome> {
        let BRegComplete { value, metadata } = self
            .inner
            .list_relationship_records(
                &entity_route,
                &record_identifier,
                &path_route,
                &relationship_list_request(options)?,
            )
            .await
            .map_err(client_error)?;
        specialized_page_json(value.value, value.continuation, metadata, None, None)
    }

    #[napi]
    pub async fn continue_relationship_list_json(&self, value: Value) -> Result<JsonOutcome> {
        let projection: BRegRelationshipContinuationProjection = serde_json::from_value(value)
            .map_err(|_| {
                binding_error("invalid_request", "relationship continuation is invalid")
            })?;
        let continuation = BRegRelationshipContinuation::try_from_projection(projection)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let BRegComplete { value, metadata } = self
            .inner
            .continue_relationship_list(&continuation)
            .await
            .map_err(client_error)?;
        specialized_page_json(value.value, value.continuation, metadata, None, None)
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

    /// Fetch opaque target conditions from exact action-input JSON.
    #[napi]
    pub async fn action_target_conditions_json(
        &self,
        binding: &ImmediateActionBinding,
        inputs_json: String,
    ) -> Result<ActionTargetConditions> {
        let request = BRegActionTargetConditionsRequest::new(
            &binding.inner,
            input_object(
                exact_input(&inputs_json)?,
                "action inputs must be an object",
            )?,
        )
        .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let BRegComplete { value, metadata } = self
            .inner
            .action_target_conditions(&binding.inner, &request)
            .await
            .map_err(client_error)?;
        Ok(ActionTargetConditions {
            inner: value,
            trace_id: metadata.trace_id().as_str().to_owned(),
        })
    }

    /// Invoke an action from exact JSON and preserve exact receipt values.
    #[napi]
    pub async fn invoke_action_json(
        &self,
        binding: &ImmediateActionBinding,
        inputs_json: String,
        idempotency_key: String,
        conditions: Option<&ActionTargetConditions>,
    ) -> Result<JsonOutcome> {
        let request = BRegActionInvocationRequest::new(
            &binding.inner,
            input_object(
                exact_input(&inputs_json)?,
                "action inputs must be an object",
            )?,
            conditions.map(|value| &value.inner),
        )
        .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let BRegComplete { value, metadata } = self
            .inner
            .invoke_action(&binding.inner, &request, &key)
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

    /// Prepare inert Create evidence from exact JSON text.
    #[napi]
    pub fn prepare_create_json(
        &self,
        binding: &CreateBinding,
        data_json: String,
        idempotency_key: String,
        format_value: Option<String>,
    ) -> Result<PreparedCreate> {
        let data = exact_input(&data_json)?;
        let data = data
            .as_object()
            .cloned()
            .ok_or_else(|| binding_error("invalid_request", "create data must be an object"))?;
        let request = BRegCreateRequest::new(data)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        self.inner
            .prepare_create(&binding.inner, &request, &key, format(format_value)?)
            .map(|inner| PreparedCreate { inner })
            .map_err(client_error)
    }

    /// Explicitly send a recovered Create request and preserve exact values.
    #[napi]
    pub async fn execute_recovered_create_json(
        &self,
        binding: &CreateBinding,
        recovered: &RecoveredCreate,
    ) -> Result<JsonOutcome> {
        let BRegComplete { value, metadata } = self
            .inner
            .create_record(
                &binding.inner,
                &recovered.request,
                &recovered.key,
                recovered.format,
            )
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

    /// Execute one metadata-selected atomic batch from exact JSON.
    #[napi]
    pub async fn batch_records_json(
        &self,
        binding: &BatchBinding,
        request_json: String,
        idempotency_key: String,
    ) -> Result<JsonOutcome> {
        let request = batch_request(&binding.inner, exact_input(&request_json)?)?;
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let BRegComplete { value, metadata } = self
            .inner
            .batch_records(&binding.inner, &request, &key)
            .await
            .map_err(client_error)?;
        complete_json_value(value, metadata)
    }

    /// Tombstone one record and preserve exact response values.
    #[napi]
    pub async fn tombstone_record_json(
        &self,
        binding: &TombstoneBinding,
        record_identifier: String,
        etag: String,
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
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        let BRegComplete { value, metadata } = self
            .inner
            .tombstone_record(
                &binding.inner,
                record_identifier,
                &etag,
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

    /// Prepare inert lifecycle evidence from an exact Registry Record response.
    #[napi]
    pub fn prepare_lifecycle_action_json(
        &self,
        authority: &LifecycleAuthority,
        record_json: String,
        action: &LifecycleAction,
        idempotency_key: String,
        format_value: Option<String>,
    ) -> Result<PreparedLifecycle> {
        let record = parse_record(exact_input(&record_json)?, format(format_value)?)?;
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid_request", error.to_string()))?;
        self.inner
            .prepare_lifecycle_action(&authority.inner, &record, &action.inner, &key)
            .map(|inner| PreparedLifecycle { inner })
            .map_err(client_error)
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

    /// Explicitly send a recovered lifecycle action and preserve exact values.
    #[napi]
    pub async fn execute_recovered_lifecycle_action_json(
        &self,
        recovered: &RecoveredLifecycle,
    ) -> Result<JsonOutcome> {
        let BRegComplete { value, metadata } = self
            .inner
            .execute_lifecycle_action(&recovered.action, &recovered.key)
            .await
            .map_err(client_error)?;
        complete_json_value(receipt_value(&value), metadata)
    }
}
