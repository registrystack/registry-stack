// SPDX-License-Identifier: Apache-2.0
//! Node.js binding for the canonical Base Registry Engine client.

#![deny(unsafe_code)]

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use napi::{bindgen_prelude::Buffer, Error as NapiError, Result};
use napi_derive::napi;
use registry_breg_client::{
    event_record_view_from_json, verify_hook_delivery as verify_core_hook_delivery,
    BRegActionAvailabilityRequest, BRegActionBinding, BRegActionInvocationRequest,
    BRegActionTargetConditions as CoreActionTargetConditions, BRegActionTargetConditionsRequest,
    BRegAsOfContinuation, BRegAsOfContinuationProjection, BRegAsOfListRequest, BRegBatchBinding,
    BRegBatchBuilder, BRegBatchRequest, BRegBoundingBox, BRegChangeContext, BRegComplete,
    BRegContinuation, BRegContinuationProjection, BRegCreateBinding, BRegCreateRequest,
    BRegCurrentContinuation, BRegCurrentContinuationProjection, BRegCurrentListRequest,
    BRegDirectWrite, BRegEtag, BRegEventRecordError, BRegGeoJsonContinuation,
    BRegGeoJsonContinuationProjection, BRegGeoJsonListRequest, BRegGeoJsonOptions,
    BRegHookDelivery as CoreHookDelivery, BRegHookVerificationError,
    BRegIngestionChunk as CoreIngestionChunk, BRegIngestionError,
    BRegIngestionPrefixDigest as CoreIngestionPrefixDigest, BRegIngestionRunListQuery,
    BRegIngestionRunRequest, BRegListRequest, BRegLookupRequest, BRegMetadata as CoreMetadata,
    BRegMetadataSelectionError, BRegMetadataSelectionErrorKind, BRegPage, BRegPatchBinding,
    BRegPatchRequest, BRegPreparedAction as CorePreparedAction,
    BRegPreparedCreate as CorePreparedCreate, BRegProtocolFailure, BRegRawDocument,
    BRegRecordFormat, BRegRecordOptions, BRegRelationshipContinuation,
    BRegRelationshipContinuationProjection, BRegRelationshipListRequest, BRegReleaseSelection,
    BRegReleaseStatus, BRegSnapshotContinuation, BRegSnapshotContinuationProjection,
    BRegSnapshotListRequest, BRegStatisticsFormat, BRegTombstoneBinding, BRegWithdrawalReason,
    BaseRegistryClient as CoreClient, BaseRegistryClientConfig, BaseRegistryClientError,
    PrivateKeyJwt, PrivateKeyJwtConfig, StaticToken, TokenError, TokenProvider,
};
use registry_platform_crypto::PrivateJwk;
use registry_platform_httputil::exchange_authorization_from_json;
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

/// Exact BReg hook request supplied by a receiver.
#[napi(object)]
pub struct HookDeliveryInput {
    pub method: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: Buffer,
    pub key: Buffer,
}

/// Authenticated BReg hook metadata and exact body.
#[napi(object)]
pub struct VerifiedHookDelivery {
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

/// Verify a BReg Version 1 hook signature without applying receiver policy.
#[napi]
pub fn verify_hook_delivery(input: HookDeliveryInput) -> Result<VerifiedHookDelivery> {
    let headers = input.headers.into_iter().collect::<Vec<_>>();
    let verified = verify_core_hook_delivery(CoreHookDelivery {
        method: &input.method,
        path: &input.path,
        headers: &headers,
        body: input.body.as_ref(),
        key: input.key.as_ref(),
    })
    .map_err(hook_verification_error)?;
    Ok(VerifiedHookDelivery {
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

/// Project one record revision into the event record view. The input is the
/// JSON arguments document of the Rust projection; the result is the view
/// document as JSON text.
#[napi]
pub fn event_record_view(arguments_json: String) -> Result<String> {
    let view =
        event_record_view_from_json(arguments_json.as_bytes()).map_err(event_record_error)?;
    serde_json::to_string(&view)
        .map_err(|_| binding_error("protocol", "event record view is not representable"))
}

fn event_record_error(error: BRegEventRecordError) -> NapiError {
    mapped_error(json!({
        "kind": "event-record",
        "code": error.code(),
        "message": error.to_string(),
    }))
}

fn hook_verification_error(error: BRegHookVerificationError) -> NapiError {
    mapped_error(json!({
        "kind": "hook-verification",
        "code": error.code(),
        "message": error.to_string(),
    }))
}

fn exact_input(value: &str) -> Result<Value> {
    registry_breg_client::decode_exact_json(value.as_bytes()).map_err(|_| {
        binding_error(
            "invalid-request",
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
    pub repr_digest: Option<String>,
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

/// Inert original immediate-action invocation evidence. The bytes carry the
/// inputs, saved target conditions, and idempotency key, but no token or
/// executable metadata authority.
#[napi(js_name = "BRegPreparedAction")]
pub struct PreparedAction {
    inner: CorePreparedAction,
}

#[napi(js_name = "BRegProposal")]
pub struct Proposal {
    inner: registry_breg_client::BRegProposal,
}

#[napi(js_name = "BRegProposalCollection")]
pub struct ProposalCollection {
    inner: registry_breg_client::BRegProposalCollection,
}
#[napi(js_name = "BRegProposalGetBinding")]
pub struct ProposalGetBinding {
    inner: registry_breg_client::BRegProposalGetBinding,
}

#[napi(js_name = "BRegProposalReviewBinding")]
pub struct ProposalReviewBinding {
    inner: registry_breg_client::BRegProposalReviewBinding,
}

#[napi(object, object_from_js = false)]
pub struct ProposalPage {
    pub items: Vec<Proposal>,
    pub next_cursor: Option<String>,
}

#[napi]
impl Proposal {
    #[napi(getter)]
    pub fn input_json(&self) -> Result<Option<String>> {
        self.inner
            .input()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| binding_error("protocol", "Proposal input is not representable"))
    }
    #[napi(getter)]
    pub fn identifier(&self) -> String {
        self.inner.id().to_owned()
    }
    #[napi(getter)]
    pub fn action_identifier(&self) -> String {
        self.inner.action_id().to_owned()
    }
    #[napi(getter)]
    pub fn document_json(&self) -> Result<String> {
        serde_json::to_string(&self.inner)
            .map_err(|_| binding_error("protocol", "Proposal is not representable"))
    }
}

#[napi(js_name = "BRegPreparedProposal")]
pub struct PreparedProposal {
    inner: registry_breg_client::BRegPreparedProposal,
}

#[napi]
impl PreparedProposal {
    #[napi(factory)]
    pub fn from_bytes(bytes: Buffer) -> Result<Self> {
        registry_breg_client::BRegPreparedProposal::from_slice(bytes.as_ref())
            .map(|inner| Self { inner })
            .map_err(client_error)
    }
    #[napi]
    pub fn to_bytes(&self) -> Buffer {
        self.inner.as_bytes().to_vec().into()
    }
}

#[napi]
impl PreparedAction {
    /// Restore bounded inert evidence previously returned by `toBytes`.
    #[napi(factory)]
    pub fn from_bytes(bytes: Buffer) -> Result<Self> {
        CorePreparedAction::from_slice(bytes.as_ref())
            .map(|inner| Self { inner })
            .map_err(client_error)
    }

    /// Copy the exact evidence bytes for owner-protected persistence.
    #[napi]
    pub fn to_bytes(&self) -> Buffer {
        self.inner.as_bytes().to_vec().into()
    }
}

/// Raise a described failure. A failure that does not report its outcome
/// followed no exchange that could have taken effect, so its outcome is known.
fn mapped_error(mut value: Value) -> NapiError {
    if let Some(object) = value.as_object_mut() {
        object.entry("outcomeUnknown").or_insert(Value::Bool(false));
    }
    NapiError::from_reason(serde_json::to_string(&value).unwrap_or_else(|_| {
        r#"{"kind":"protocol","message":"the failure could not be described","outcomeUnknown":true}"#
            .to_owned()
    }))
}

/// A failure the binding detects itself. Only a protocol failure follows an
/// exchange, a result the binding cannot represent, so only it leaves the
/// outcome unknown.
fn binding_error(kind: &'static str, message: impl Into<String>) -> NapiError {
    mapped_error(json!({
        "kind": kind,
        "message": message.into(),
        "outcomeUnknown": kind == "protocol",
    }))
}

fn protocol_code(value: BRegProtocolFailure) -> &'static str {
    match value {
        BRegProtocolFailure::HeaderBounds => "header-bounds",
        BRegProtocolFailure::TraceContext => "trace-context",
        BRegProtocolFailure::MediaType => "media-type",
        BRegProtocolFailure::Body => "body",
        BRegProtocolFailure::Problem => "problem",
        BRegProtocolFailure::EntityTag => "entity-tag",
        BRegProtocolFailure::ProfileLink => "profile-link",
        BRegProtocolFailure::Location => "location",
        BRegProtocolFailure::CachePolicy => "cache-policy",
        BRegProtocolFailure::RepresentationDigest => "representation-digest",
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
    let outcome_unknown = error.is_outcome_unknown();
    let kind = error.kind();
    let status = error.status();
    let code = error.problem_code().map(|value| value.code().to_owned());
    let refusal_code = error.refusal_code().map(|value| value.as_str().to_owned());
    let reason_code = error.reason_code().map(str::to_owned);
    let guard_reason = error.guard_reason().map(str::to_owned);
    let field_path = error.field_path().map(|value| value.as_str().to_owned());
    let constraint = error.constraint().cloned();
    let trace_id = error.trace_id().map(|value| value.as_str().to_owned());
    let mut value = match error {
        BaseRegistryClientError::Configuration { reason } => {
            json!({"kind": "configuration", "message": reason})
        }
        BaseRegistryClientError::InvalidRequest { reason } => {
            json!({"kind": "invalid-request", "message": reason})
        }
        BaseRegistryClientError::Token(error) => token_error_value(error),
        BaseRegistryClientError::Transport { kind } => json!({
            "kind": "transport",
            "transportKind": kind.kind(),
            "message": "Base Registry Engine exchange did not complete",
        }),
        BaseRegistryClientError::Problem { .. } => json!({
            "kind": kind,
            "status": status,
            "code": code,
            // Problem detail codes travel as bounded strings after their
            // operation-specific vocabulary has been checked by the Rust client.
            "refusalCode": refusal_code,
            "reasonCode": reason_code,
            "guardReason": guard_reason,
            "fieldPath": field_path,
            "constraint": constraint,
            "traceId": trace_id,
            "message": "Base Registry Engine refused the request",
        }),
        BaseRegistryClientError::UnrecognizedProblem { .. } => json!({
            "kind": kind,
            "status": status,
            "traceId": trace_id,
            "message": "Base Registry Engine refused or failed the request with an unrecognized problem code",
        }),
        BaseRegistryClientError::Protocol {
            status,
            failure,
            trace_id,
            ..
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
    value["outcomeUnknown"] = Value::Bool(outcome_unknown);
    mapped_error(value)
}

fn selection_error(error: BRegMetadataSelectionError) -> NapiError {
    let code = match error.kind() {
        BRegMetadataSelectionErrorKind::NotFound => "not-found",
        BRegMetadataSelectionErrorKind::UnboundSource => "unbound-source",
        BRegMetadataSelectionErrorKind::ProfileMismatch => "profile-mismatch",
        BRegMetadataSelectionErrorKind::UnsupportedOperation => "unsupported-operation",
        BRegMetadataSelectionErrorKind::RequiredCapability => "required-capability",
        BRegMetadataSelectionErrorKind::ContractMismatch => "contract-mismatch",
    };
    mapped_error(json!({
        "kind": "metadata-selection",
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

fn refuse_null_fields(
    object: &Map<String, Value>,
    fields: &[&str],
    kind: &'static str,
    message: &'static str,
) -> Result<()> {
    if fields
        .iter()
        .any(|field| matches!(object.get(*field), Some(Value::Null)))
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

/// An optional member that, when present, must be an array of strings. The
/// values' own grammar is the provider's to check; this holds only the shape.
fn optional_string_array(
    object: &Map<String, Value>,
    field: &str,
    kind: &'static str,
    message: &'static str,
) -> Result<Option<Vec<String>>> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| binding_error(kind, message))
            })
            .collect::<Result<Vec<_>>>()
            .map(Some),
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
            "resource",
            "scopes",
            "assertionLifetimeSeconds",
            "refreshMarginSeconds",
            "attemptTimeoutMilliseconds",
            "connectTimeoutMilliseconds",
            "userAgent",
            "trustedRootCertificates",
        ],
        "configuration",
        "authorization.privateKeyJwt contains an unsupported field",
    )?;
    refuse_null_fields(
        object,
        &[
            "audience",
            "resource",
            "scopes",
            "assertionLifetimeSeconds",
            "refreshMarginSeconds",
            "attemptTimeoutMilliseconds",
            "connectTimeoutMilliseconds",
            "userAgent",
            "trustedRootCertificates",
        ],
        "configuration",
        "authorization.privateKeyJwt options must be omitted instead of null",
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
    if let Some(value) = optional_string(
        object,
        "resource",
        "configuration",
        "authorization.privateKeyJwt.resource must be a string",
    )? {
        config = config.with_resource(value);
    }
    if let Some(values) = optional_string_array(
        object,
        "scopes",
        "configuration",
        "authorization.privateKeyJwt.scopes must be an array of strings",
    )? {
        config = config.with_scopes(values);
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
        "attemptTimeoutMilliseconds",
        "configuration",
        "private-key JWT attempt timeout must be a non-negative integer",
    )? {
        config = config.with_attempt_timeout(Duration::from_millis(value));
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

/// Shared OAuth client authentication and uncached task-token exchange.
#[napi(js_name = "PrivateKeyJwt")]
pub struct PrivateKeyJwtBinding {
    inner: PrivateKeyJwt,
}

#[napi]
impl PrivateKeyJwtBinding {
    #[napi(constructor)]
    pub fn new(config: Value) -> Result<Self> {
        Ok(Self {
            inner: private_key_jwt(&config)?,
        })
    }

    #[napi]
    pub async fn exchange(&self, subject_token: String) -> Result<String> {
        let token = self
            .inner
            .exchange(&subject_token)
            .await
            .map_err(|error| mapped_error(token_error_value(error)))?;
        bearer_value(token)
    }

    #[napi]
    pub async fn bearer_token(&self) -> Result<String> {
        let token = self
            .inner
            .bearer_token()
            .await
            .map_err(|error| mapped_error(token_error_value(error)))?;
        bearer_value(token)
    }
}

fn bearer_value(token: registry_breg_client::BearerToken) -> Result<String> {
    let header = token.authorization_header_value();
    header
        .to_str()
        .ok()
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::to_owned)
        .ok_or_else(|| binding_error("token", "the issued credential is invalid"))
}

fn validate_exchange_client(value: &Value, what: &'static str) -> Result<()> {
    let object = required_object(value, what)?;
    only_fields(
        object,
        &[
            "tokenEndpoint",
            "clientId",
            "clientKey",
            "audience",
            "resource",
            "scopes",
            "assertionLifetimeSeconds",
            "refreshMarginSeconds",
            "attemptTimeoutMilliseconds",
            "connectTimeoutMilliseconds",
            "userAgent",
            "trustedRootCertificates",
        ],
        "configuration",
        "exchange client contains an unsupported field",
    )?;
    refuse_null_fields(
        object,
        &[
            "audience",
            "assertionLifetimeSeconds",
            "refreshMarginSeconds",
            "attemptTimeoutMilliseconds",
            "connectTimeoutMilliseconds",
            "userAgent",
            "trustedRootCertificates",
        ],
        "configuration",
        "exchange client options must be omitted instead of null",
    )?;
    optional_i64(
        object,
        "assertionLifetimeSeconds",
        "exchange assertionLifetimeSeconds must be a safe integer",
    )?;
    optional_i64(
        object,
        "refreshMarginSeconds",
        "exchange refreshMarginSeconds must be a safe integer",
    )?;
    optional_u64(
        object,
        "attemptTimeoutMilliseconds",
        "configuration",
        "exchange attemptTimeoutMilliseconds must be a non-negative safe integer",
    )?;
    optional_u64(
        object,
        "connectTimeoutMilliseconds",
        "configuration",
        "exchange connectTimeoutMilliseconds must be a non-negative safe integer",
    )?;
    Ok(())
}

fn validate_exchange_config(value: &Value) -> Result<()> {
    let object = required_object(value, "authorization.exchange must be an object")?;
    only_fields(
        object,
        &["client", "context", "firstParty", "remote"],
        "configuration",
        "authorization.exchange contains an unsupported field",
    )?;
    refuse_null_fields(
        object,
        &["firstParty", "remote"],
        "configuration",
        "authorization.exchange options must be omitted instead of null",
    )?;

    validate_exchange_client(
        object.get("client").ok_or_else(|| {
            binding_error(
                "configuration",
                "authorization.exchange.client must be present",
            )
        })?,
        "authorization.exchange.client must be an object",
    )?;

    let context = required_object(
        object.get("context").ok_or_else(|| {
            binding_error(
                "configuration",
                "authorization.exchange.context must be present",
            )
        })?,
        "authorization.exchange.context must be an object",
    )?;
    only_fields(
        context,
        &[
            "issuer",
            "subject",
            "audience",
            "generation",
            "deadlineSeconds",
            "grantId",
        ],
        "configuration",
        "authorization.exchange.context contains an unsupported field",
    )?;
    refuse_null_fields(
        context,
        &["grantId"],
        "configuration",
        "authorization.exchange.context options must be omitted instead of null",
    )?;
    let deadline = context.get("deadlineSeconds").ok_or_else(|| {
        binding_error(
            "configuration",
            "authorization.exchange.context.deadlineSeconds must be present",
        )
    })?;
    safe_integer(
        deadline,
        0,
        MAXIMUM_JAVASCRIPT_SAFE_INTEGER,
        "configuration",
        "authorization.exchange.context.deadlineSeconds must be a non-negative safe integer",
    )?;

    if let Some(first_party) = object.get("firstParty") {
        let first_party = required_object(
            first_party,
            "authorization.exchange.firstParty must be an object",
        )?;
        only_fields(
            first_party,
            &["key", "attributes"],
            "configuration",
            "authorization.exchange.firstParty contains an unsupported field",
        )?;
    }

    if let Some(remote) = object.get("remote") {
        let remote = required_object(remote, "authorization.exchange.remote must be an object")?;
        only_fields(
            remote,
            &[
                "endpoint",
                "bootstrap",
                "bootstrapResource",
                "bootstrapScope",
                "attemptTimeoutMilliseconds",
                "connectTimeoutMilliseconds",
                "userAgent",
                "trustedRootCertificates",
            ],
            "configuration",
            "authorization.exchange.remote contains an unsupported field",
        )?;
        refuse_null_fields(
            remote,
            &[
                "attemptTimeoutMilliseconds",
                "connectTimeoutMilliseconds",
                "userAgent",
                "trustedRootCertificates",
            ],
            "configuration",
            "authorization.exchange.remote options must be omitted instead of null",
        )?;
        validate_exchange_client(
            remote.get("bootstrap").ok_or_else(|| {
                binding_error(
                    "configuration",
                    "authorization.exchange.remote.bootstrap must be present",
                )
            })?,
            "authorization.exchange.remote.bootstrap must be an object",
        )?;
        optional_u64(
            remote,
            "attemptTimeoutMilliseconds",
            "configuration",
            "remote exchange attemptTimeoutMilliseconds must be a non-negative safe integer",
        )?;
        optional_u64(
            remote,
            "connectTimeoutMilliseconds",
            "configuration",
            "remote exchange connectTimeoutMilliseconds must be a non-negative safe integer",
        )?;
    }
    Ok(())
}

fn authorization_provider(value: &Value) -> Result<Option<Arc<dyn TokenProvider>>> {
    if value.is_null() {
        return Ok(None);
    }
    let object = required_object(value, "authorization must be an object")?;
    if object.len() != 1 {
        return Err(binding_error(
            "configuration",
            "authorization must contain exactly one of static, privateKeyJwt, or exchange",
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
    if let Some(value) = object.get("exchange") {
        validate_exchange_config(value)?;
        return exchange_authorization_from_json(value)
            .map(|provider| Some(Arc::new(provider) as Arc<dyn TokenProvider>))
            .map_err(|error| mapped_error(token_error_value(error)));
    }
    Err(binding_error(
        "configuration",
        "authorization must contain exactly one of static, privateKeyJwt, or exchange",
    ))
}

fn client_from_config(value: Value) -> Result<CoreClient> {
    let object = required_object(&value, "client configuration must be an object")?;
    only_fields(
        object,
        &[
            "baseUrl",
            "authorization",
            "attemptTimeoutMilliseconds",
            "connectTimeoutMilliseconds",
            "maximumResponseBytes",
            "userAgent",
            "trustedRootCertificates",
            "maximumMutationRetries",
        ],
        "configuration",
        "client configuration contains an unsupported field",
    )?;
    refuse_null_fields(
        object,
        &[
            "authorization",
            "attemptTimeoutMilliseconds",
            "connectTimeoutMilliseconds",
            "maximumResponseBytes",
            "userAgent",
            "trustedRootCertificates",
            "maximumMutationRetries",
        ],
        "configuration",
        "client configuration options must be omitted instead of null",
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
        "attemptTimeoutMilliseconds",
        "configuration",
        "attemptTimeoutMilliseconds must be a non-negative integer",
    )? {
        config = config.with_attempt_timeout(Duration::from_millis(value));
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
        "maximumResponseBytes",
        "configuration",
        "maximumResponseBytes must be a non-negative integer",
    )? {
        config = config.with_maximum_response_bytes(value);
    }
    if let Some(value) = optional_u64(
        object,
        "maximumMutationRetries",
        "configuration",
        "maximumMutationRetries must be a whole number from 0 to 2",
    )? {
        // Only a value in the `u8` range reaches the client, which refuses one
        // above its own bound.
        let value = u8::try_from(value).map_err(|_| {
            binding_error(
                "configuration",
                "maximumMutationRetries must be a whole number from 0 to 2",
            )
        })?;
        config = config.with_maximum_mutation_retries(value);
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
            "invalid-request",
            "format must be json or json-ld",
        )),
    }
}

fn statistics_format(value: Option<&str>) -> Result<BRegStatisticsFormat> {
    match value.unwrap_or("json") {
        "json" => Ok(BRegStatisticsFormat::Json),
        "csv" => Ok(BRegStatisticsFormat::Csv),
        _ => Err(binding_error(
            "invalid-request",
            "statistics format must be json or csv",
        )),
    }
}

fn release_selection(value: &str) -> Result<BRegReleaseSelection> {
    match value {
        "any" => Ok(BRegReleaseSelection::Any),
        "final" => Ok(BRegReleaseSelection::Final),
        _ => Err(binding_error(
            "invalid-request",
            "statistics release selection must be any or final",
        )),
    }
}

fn release_status(value: &str) -> Result<BRegReleaseStatus> {
    match value {
        "provisional" => Ok(BRegReleaseStatus::Provisional),
        "final" => Ok(BRegReleaseStatus::Final),
        _ => Err(binding_error(
            "invalid-request",
            "statistics release status must be provisional or final",
        )),
    }
}

fn withdrawal_reason(value: &str) -> Result<BRegWithdrawalReason> {
    match value {
        "computation-error" => Ok(BRegWithdrawalReason::ComputationError),
        "source-data-error" => Ok(BRegWithdrawalReason::SourceDataError),
        "disclosure-risk" => Ok(BRegWithdrawalReason::DisclosureRisk),
        _ => Err(binding_error(
            "invalid-request",
            "statistics withdrawal reason is invalid",
        )),
    }
}

fn statistics_version(value: i64) -> Result<u64> {
    if !(1..=MAXIMUM_JAVASCRIPT_SAFE_INTEGER).contains(&value) {
        return Err(binding_error(
            "invalid-request",
            "statistics release version must be a positive safe integer",
        ));
    }
    Ok(value as u64)
}

fn record_options(object: Option<&Map<String, Value>>) -> Result<BRegRecordOptions> {
    let Some(object) = object else {
        return Ok(BRegRecordOptions::default());
    };
    only_fields(
        object,
        &["select", "accessProfile", "format"],
        "invalid-request",
        "record options contain an unsupported field",
    )?;
    let mut options = BRegRecordOptions::default().format(format(optional_string(
        object,
        "format",
        "invalid-request",
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
                    binding_error("invalid-request", "select must be an array of strings")
                })?;
            options = options
                .select(fields)
                .map_err(|error| binding_error("invalid-request", error.to_string()))?;
        }
    }
    if let Some(value) = optional_string(
        object,
        "accessProfile",
        "invalid-request",
        "accessProfile must be a string",
    )? {
        options = options
            .access_profile(value)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
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
        Some(_) => Err(binding_error("invalid-request", message)),
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
        "invalid-request",
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
                "invalid-request",
                "top must be 1 through 100",
            )?;
            request = request
                .top(value as u32)
                .map_err(|error| binding_error("invalid-request", error.to_string()))?;
        }
    }
    if let Some(value) = optional_string(
        &object,
        "filter",
        "invalid-request",
        "filter must be a string",
    )? {
        request = request
            .filter(value)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
    }
    if let Some(value) = optional_string(
        &object,
        "orderby",
        "invalid-request",
        "orderby must be a string",
    )? {
        request = request
            .orderby(value)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
    }
    match object.get("count") {
        None | Some(Value::Null) => {}
        Some(value) => {
            let value = value
                .as_bool()
                .ok_or_else(|| binding_error("invalid-request", "count must be a boolean"))?;
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
        "invalid-request",
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
                "invalid-request",
                "top must be 1 through 100",
            )
            .map(|value| value as u32)
        })
        .transpose()?;
    let filter = optional_string(
        &object,
        "filter",
        "invalid-request",
        "filter must be a string",
    )?;
    let orderby = optional_string(
        &object,
        "orderby",
        "invalid-request",
        "orderby must be a string",
    )?;
    let count = match object.get("count") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_bool()
                .ok_or_else(|| binding_error("invalid-request", "count must be a boolean"))?,
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
                .map_err(|error| binding_error("invalid-request", error.to_string()))?;
        }
        if let Some(value) = $inputs.filter {
            $request = $request
                .filter(value)
                .map_err(|error| binding_error("invalid-request", error.to_string()))?;
        }
        if let Some(value) = $inputs.orderby {
            $request = $request
                .orderby(value)
                .map_err(|error| binding_error("invalid-request", error.to_string()))?;
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
        "invalid-request",
        "asOf must be a canonical UTC RFC 3339 string",
    )?;
    let mut request = BRegAsOfListRequest::new(as_of)
        .map_err(|error| binding_error("invalid-request", error.to_string()))?;
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
        "invalid-request",
        "snapshot must be a string",
    )? {
        request = request
            .snapshot(value)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
    }
    if let Some(value) = optional_string(
        &object,
        "validAt",
        "invalid-request",
        "validAt must be a string",
    )? {
        request = request
            .valid_at(value)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
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
            binding_error("invalid-request", "bbox must contain four decimal strings")
        })?;
    let coordinates = coordinates
        .iter()
        .map(|value| value.as_str())
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| binding_error("invalid-request", "bbox must contain decimal strings"))?;
    BRegBoundingBox::new(
        coordinates[0],
        coordinates[1],
        coordinates[2],
        coordinates[3],
    )
    .map_err(|error| binding_error("invalid-request", error.to_string()))
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
                    binding_error("invalid-request", "select must be an array of strings")
                })?;
            options = options
                .select(fields)
                .map_err(|error| binding_error("invalid-request", error.to_string()))?;
        }
        Some(_) => {
            return Err(binding_error(
                "invalid-request",
                "select must be an array of strings",
            ));
        }
    }
    if let Some(value) = optional_string(
        object,
        "accessProfile",
        "invalid-request",
        "accessProfile must be a string",
    )? {
        options = options
            .access_profile(value)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
    }
    Ok(options)
}

fn geojson_list_request(value: Option<Value>) -> Result<BRegGeoJsonListRequest> {
    let (object, inputs) = collection_inputs(value, &["bbox"])?;
    if object.contains_key("format") {
        return Err(binding_error(
            "invalid-request",
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
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
    }
    if let Some(value) = inputs.filter {
        request = request
            .filter(value)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
    }
    if let Some(value) = inputs.orderby {
        request = request
            .orderby(value)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
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
        .map_err(|error| binding_error("invalid-request", error.to_string()))?;
    let options = options_object(options, "record options must be an object")?;
    request = request.options(record_options(options.as_ref())?);
    match values {
        None | Some(Value::Null) => {}
        Some(Value::Object(values)) => {
            for (name, value) in values {
                request = request
                    .value(name, value)
                    .map_err(|error| binding_error("invalid-request", error.to_string()))?;
            }
        }
        Some(_) => {
            return Err(binding_error(
                "invalid-request",
                "lookup values must be an object",
            ));
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
        repr_digest: value
            .value
            .representation_digest()
            .map(|digest| digest.as_str().to_owned()),
    }
}

fn patch_request(value: Value) -> Result<BRegPatchRequest> {
    let operations = value
        .as_array()
        .ok_or_else(|| binding_error("invalid-request", "patch must be an array"))?;
    let mut builder = BRegPatchRequest::builder();
    for operation in operations {
        let object = operation.as_object().ok_or_else(|| {
            binding_error("invalid-request", "every patch operation must be an object")
        })?;
        let op = required_string(object, "op", "invalid-request", "patch op must be a string")?;
        let allowed = if op == "remove" {
            &["op", "field"][..]
        } else {
            &["op", "field", "value"][..]
        };
        only_fields(
            object,
            allowed,
            "invalid-request",
            "patch operation contains an unsupported field",
        )?;
        let field = required_string(
            object,
            "field",
            "invalid-request",
            "patch field must be a string",
        )?;
        let result = match op.as_str() {
            "add" => builder.add(
                field,
                object
                    .get("value")
                    .cloned()
                    .ok_or_else(|| binding_error("invalid-request", "add requires value"))?,
            ),
            "replace" => builder.replace(
                field,
                object
                    .get("value")
                    .cloned()
                    .ok_or_else(|| binding_error("invalid-request", "replace requires value"))?,
            ),
            "remove" => builder.remove(field),
            "test" => builder.test(
                field,
                object
                    .get("value")
                    .cloned()
                    .ok_or_else(|| binding_error("invalid-request", "test requires value"))?,
            ),
            _ => return Err(binding_error("invalid-request", "patch op is unsupported")),
        };
        builder = result.map_err(|error| binding_error("invalid-request", error.to_string()))?;
    }
    builder
        .build()
        .map_err(|error| binding_error("invalid-request", error.to_string()))
}

fn action_invocation(
    binding: &ActionBinding,
    inputs: Map<String, Value>,
    conditions: Option<&ActionTargetConditions>,
) -> Result<BRegActionInvocationRequest> {
    BRegActionInvocationRequest::new(&binding.inner, inputs, conditions.map(|value| &value.inner))
        .map_err(|error| binding_error("invalid-request", error.to_string()))
}

fn idempotency_key(value: String) -> Result<registry_breg_client::BRegIdempotencyKey> {
    registry_breg_client::BRegIdempotencyKey::parse(value)
        .map_err(|error| binding_error("invalid-request", error.to_string()))
}

fn prepare_action_evidence(
    client: &CoreClient,
    binding: &ActionBinding,
    inputs: Map<String, Value>,
    idempotency_key_value: String,
    conditions: Option<&ActionTargetConditions>,
) -> Result<PreparedAction> {
    let request = action_invocation(binding, inputs, conditions)?;
    let key = idempotency_key(idempotency_key_value)?;
    client
        .prepare_action(&binding.inner, &request, &key)
        .map(|inner| PreparedAction { inner })
        .map_err(client_error)
}

fn recover_action_evidence(
    client: &CoreClient,
    binding: &ActionBinding,
    prepared: &PreparedAction,
    original_inputs: &Map<String, Value>,
    original_idempotency_key: String,
) -> Result<RecoveredAction> {
    let key = idempotency_key(original_idempotency_key)?;
    let request = client
        .recover_action(&binding.inner, &prepared.inner, original_inputs, &key)
        .map_err(client_error)?;
    Ok(RecoveredAction { request, key })
}

fn input_object(value: Value, message: &'static str) -> Result<Map<String, Value>> {
    value
        .as_object()
        .cloned()
        .ok_or_else(|| binding_error("invalid-request", message))
}

fn change_context(value: Value) -> Result<BRegChangeContext> {
    let object = input_object(value, "changeContext must be an object")?;
    only_fields(
        &object,
        &["kind", "reasonCode", "reasonText", "sourceReferences"],
        "invalid-request",
        "changeContext contains an unsupported field",
    )?;
    let kind = required_string(
        &object,
        "kind",
        "invalid-request",
        "changeContext.kind must be a string",
    )?;
    let mut context = match kind.as_str() {
        "change" if !object.contains_key("reasonCode") => BRegChangeContext::change(),
        "correction" => BRegChangeContext::correction(required_string(
            &object,
            "reasonCode",
            "invalid-request",
            "a correction requires reasonCode",
        )?)
        .map_err(|error| binding_error("invalid-request", error.to_string()))?,
        _ => {
            return Err(binding_error(
                "invalid-request",
                "changeContext.kind or reasonCode is invalid",
            ));
        }
    };
    if let Some(value) = optional_string(
        &object,
        "reasonText",
        "invalid-request",
        "changeContext.reasonText must be a string",
    )? {
        context = context
            .reason_text(value)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
    }
    match object.get("sourceReferences") {
        None => {}
        Some(Value::Array(values)) => {
            for value in values {
                let value = value.as_str().ok_or_else(|| {
                    binding_error(
                        "invalid-request",
                        "changeContext.sourceReferences must contain strings",
                    )
                })?;
                context = context
                    .source_reference(value)
                    .map_err(|error| binding_error("invalid-request", error.to_string()))?;
            }
        }
        Some(_) => {
            return Err(binding_error(
                "invalid-request",
                "changeContext.sourceReferences must be an array",
            ));
        }
    }
    Ok(context)
}

fn batch_request(binding: &BRegBatchBinding, value: Value) -> Result<BRegBatchRequest> {
    let object = input_object(value, "batch request must be an object")?;
    only_fields(
        &object,
        &["items", "changeContext"],
        "invalid-request",
        "batch request contains an unsupported field",
    )?;
    let items = object
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| binding_error("invalid-request", "batch items must be an array"))?;
    let mut builder = BRegBatchBuilder::new(binding);
    for item in items {
        let item = item.as_object().ok_or_else(|| {
            binding_error("invalid-request", "every batch item must be an object")
        })?;
        let operation = required_string(
            item,
            "operation",
            "invalid-request",
            "batch item operation must be a string",
        )?;
        builder = match operation.as_str() {
            "create" => {
                only_fields(
                    item,
                    &["operation", "data"],
                    "invalid-request",
                    "Create batch item contains an unsupported field",
                )?;
                let data = item
                    .get("data")
                    .and_then(Value::as_object)
                    .cloned()
                    .ok_or_else(|| {
                        binding_error("invalid-request", "Create batch data must be an object")
                    })?;
                let request = BRegCreateRequest::new(data)
                    .map_err(|error| binding_error("invalid-request", error.to_string()))?;
                builder
                    .create(&request)
                    .map_err(|error| binding_error("invalid-request", error.to_string()))?
            }
            "patch" => {
                only_fields(
                    item,
                    &["operation", "recordIdentifier", "ifMatch", "patch"],
                    "invalid-request",
                    "Patch batch item contains an unsupported field",
                )?;
                let record_identifier = uuid::Uuid::parse_str(&required_string(
                    item,
                    "recordIdentifier",
                    "invalid-request",
                    "Patch batch recordIdentifier must be a UUID",
                )?)
                .map_err(|_| {
                    binding_error(
                        "invalid-request",
                        "Patch batch recordIdentifier must be a UUID",
                    )
                })?;
                let etag = BRegEtag::parse(&required_string(
                    item,
                    "ifMatch",
                    "invalid-request",
                    "Patch batch ifMatch must be a string",
                )?)
                .map_err(|error| binding_error("invalid-request", error.to_string()))?;
                let request = patch_request(item.get("patch").cloned().ok_or_else(|| {
                    binding_error("invalid-request", "Patch batch patch is required")
                })?)?;
                builder
                    .patch(record_identifier, &etag, &request)
                    .map_err(|error| binding_error("invalid-request", error.to_string()))?
            }
            _ => {
                return Err(binding_error(
                    "invalid-request",
                    "batch item operation is unsupported",
                ));
            }
        };
    }
    if let Some(value) = object.get("changeContext") {
        builder = builder.change_context(change_context(value.clone())?);
    }
    builder
        .build()
        .map_err(|error| binding_error("invalid-request", error.to_string()))
}

fn ingestion_error(error: BRegIngestionError) -> NapiError {
    binding_error("invalid-request", error.to_string())
}

const INGESTION_RUN_REQUEST_FIELDS: [&str; 9] = [
    "operation",
    "profileId",
    "packageRevision",
    "schemaFingerprint",
    "inputDigest",
    "inputLength",
    "itemCount",
    "chunkCount",
    "chunkAlgorithmVersion",
];

fn ingestion_run_request(value: Value) -> Result<BRegIngestionRunRequest> {
    let object = input_object(value, "run request must be an object")?;
    only_fields(
        &object,
        &INGESTION_RUN_REQUEST_FIELDS,
        "invalid-request",
        "run request contains an unsupported field",
    )?;
    let operation = match required_string(
        &object,
        "operation",
        "invalid-request",
        "run request requires operation",
    )?
    .as_str()
    {
        "create" => registry_breg_client::BRegBatchOperation::Create,
        "patch" => registry_breg_client::BRegBatchOperation::Patch,
        _ => {
            return Err(binding_error(
                "invalid-request",
                "run request operation must be create or patch",
            ));
        }
    };
    let builder = BRegIngestionRunRequest::builder().operation(operation);
    let builder = builder
        .profile(required_string(
            &object,
            "profileId",
            "invalid-request",
            "run request requires profileId",
        )?)
        .map_err(ingestion_error)?;
    let builder = builder
        .package_revision(required_string(
            &object,
            "packageRevision",
            "invalid-request",
            "run request requires packageRevision",
        )?)
        .map_err(ingestion_error)?;
    let builder = builder
        .schema_fingerprint(required_string(
            &object,
            "schemaFingerprint",
            "invalid-request",
            "run request requires schemaFingerprint",
        )?)
        .map_err(ingestion_error)?;
    let builder = builder
        .input_digest(required_string(
            &object,
            "inputDigest",
            "invalid-request",
            "run request requires inputDigest",
        )?)
        .map_err(ingestion_error)?;
    let input_length = safe_integer(
        object
            .get("inputLength")
            .ok_or_else(|| binding_error("invalid-request", "run request requires inputLength"))?,
        0,
        MAXIMUM_JAVASCRIPT_SAFE_INTEGER,
        "invalid-request",
        "run request inputLength must be a safe integer",
    )?;
    let builder = builder.input_length(u64::try_from(input_length).map_err(|_| {
        binding_error(
            "invalid-request",
            "run request inputLength must be a safe integer",
        )
    })?);
    let item_count = safe_integer(
        object
            .get("itemCount")
            .ok_or_else(|| binding_error("invalid-request", "run request requires itemCount"))?,
        1,
        MAXIMUM_JAVASCRIPT_SAFE_INTEGER,
        "invalid-request",
        "run request itemCount must be a positive safe integer",
    )?;
    let chunk_count = safe_integer(
        object
            .get("chunkCount")
            .ok_or_else(|| binding_error("invalid-request", "run request requires chunkCount"))?,
        1,
        MAXIMUM_JAVASCRIPT_SAFE_INTEGER,
        "invalid-request",
        "run request chunkCount must be a positive safe integer",
    )?;
    let builder = builder
        .item_count(item_count as u64)
        .map_err(ingestion_error)?;
    let builder = builder
        .chunk_count(chunk_count as u64)
        .map_err(ingestion_error)?;
    let builder = builder
        .chunk_algorithm_version(required_string(
            &object,
            "chunkAlgorithmVersion",
            "invalid-request",
            "run request requires chunkAlgorithmVersion",
        )?)
        .map_err(ingestion_error)?;
    builder.build().map_err(ingestion_error)
}

fn ingestion_run_list_query(value: Option<&Value>) -> Result<BRegIngestionRunListQuery> {
    let Some(value) = value else {
        return Ok(BRegIngestionRunListQuery::default());
    };
    let object = input_object(value.clone(), "run list query must be an object")?;
    if object.contains_key("after") {
        return Err(binding_error(
            "invalid-request",
            "run list query takes cursor, not after",
        ));
    }
    only_fields(
        &object,
        &["accessProfile", "limit", "cursor", "status", "inputDigest"],
        "invalid-request",
        "run list query contains an unsupported field",
    )?;
    let mut query = BRegIngestionRunListQuery::default();
    if let Some(access_profile) = optional_string(
        &object,
        "accessProfile",
        "invalid-request",
        "run list query accessProfile must be a string",
    )? {
        query = query
            .access_profile(access_profile)
            .map_err(ingestion_error)?;
    }
    if let Some(limit) = object.get("limit") {
        let limit = safe_integer(
            limit,
            1,
            MAXIMUM_JAVASCRIPT_SAFE_INTEGER,
            "invalid-request",
            "run list query limit must be a positive safe integer",
        )?;
        let limit = u32::try_from(limit).map_err(|_| {
            binding_error(
                "invalid-request",
                "run list query limit must be a positive safe integer",
            )
        })?;
        query = query.limit(limit).map_err(ingestion_error)?;
    }
    if let Some(cursor) = optional_string(
        &object,
        "cursor",
        "invalid-request",
        "run list query cursor must be a string",
    )? {
        query = query.cursor(cursor).map_err(ingestion_error)?;
    }
    if let Some(status) = optional_string(
        &object,
        "status",
        "invalid-request",
        "run list query status must be a string",
    )? {
        let status = match status.as_str() {
            "open" => registry_breg_client::BRegIngestionRunStatus::Open,
            "complete" => registry_breg_client::BRegIngestionRunStatus::Complete,
            "cancelled" => registry_breg_client::BRegIngestionRunStatus::Cancelled,
            "blocked" => registry_breg_client::BRegIngestionRunStatus::Blocked,
            _ => {
                return Err(binding_error(
                    "invalid-request",
                    "run list query status is unsupported",
                ));
            }
        };
        query = query.status(status);
    }
    if let Some(input_digest) = optional_string(
        &object,
        "inputDigest",
        "invalid-request",
        "run list query inputDigest must be a string",
    )? {
        query = query.input_digest(input_digest).map_err(ingestion_error)?;
    }
    Ok(query)
}

fn ingestion_run_identifier(value: String) -> Result<uuid::Uuid> {
    uuid::Uuid::parse_str(&value)
        .map_err(|_| binding_error("invalid-request", "runId must be a UUID"))
}

fn ingestion_chunk_index(value: i64, message: &'static str) -> Result<u64> {
    if !(0..=MAXIMUM_JAVASCRIPT_SAFE_INTEGER).contains(&value) {
        return Err(binding_error("invalid-request", message));
    }
    Ok(value as u64)
}

/// One bounded, digest-bound chunk of an ingestion run. The chunk digest is
/// derived in Rust from the exact canonical batch body the items hash to.
#[napi(js_name = "BRegIngestionChunk")]
pub struct IngestionChunk {
    inner: Arc<CoreIngestionChunk>,
}

#[napi]
impl IngestionChunk {
    #[napi(getter)]
    pub fn chunk_index(&self) -> i64 {
        i64::try_from(self.inner.chunk_index()).unwrap_or(MAXIMUM_JAVASCRIPT_SAFE_INTEGER)
    }

    #[napi(getter)]
    pub fn item_count(&self) -> i64 {
        i64::try_from(self.inner.item_count()).unwrap_or(MAXIMUM_JAVASCRIPT_SAFE_INTEGER)
    }

    /// The derived lowercase SHA-256 of the chunk's canonical batch body.
    #[napi(getter)]
    pub fn digest(&self) -> String {
        self.inner.digest().to_owned()
    }

    #[napi(getter)]
    pub fn prefix_digest(&self) -> String {
        self.inner.prefix_digest().to_owned()
    }
}

/// Encode one ingestion chunk submission: derive its digest in Rust and bind
/// the announced prefix digest into the exact wire body. `items` are the same
/// batch items the entity's atomic batch route executes; `prefixDigest` is the
/// lowercase SHA-256 of the complete raw source input through the end of this
/// chunk, which `BRegIngestionPrefixDigest` accumulates.
#[napi]
pub fn encode_ingestion_chunk(
    chunk_index: i64,
    items: Value,
    prefix_digest: String,
) -> Result<IngestionChunk> {
    let chunk_index = ingestion_chunk_index(
        chunk_index,
        "chunkIndex must be a non-negative safe integer",
    )?;
    let items = items
        .as_array()
        .cloned()
        .ok_or_else(|| binding_error("invalid-request", "items must be an array"))?;
    CoreIngestionChunk::new(chunk_index, items, prefix_digest)
        .map(|inner| IngestionChunk {
            inner: Arc::new(inner),
        })
        .map_err(ingestion_error)
}

/// Accumulate the raw source bytes of one ingestion input and derive the
/// prefix digest the run binds: the lowercase SHA-256 of everything absorbed
/// through the end of the current chunk. The digest of an empty accumulation
/// is `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
/// The digest is never a chain over chunk digests: the server stores it as an
/// opaque value and cannot re-derive the raw bytes.
#[napi(js_name = "BRegIngestionPrefixDigest")]
#[derive(Default)]
pub struct IngestionPrefixDigest {
    inner: CoreIngestionPrefixDigest,
}

#[napi]
impl IngestionPrefixDigest {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: CoreIngestionPrefixDigest::new(),
        }
    }

    /// Absorb the next raw source bytes, typically one chunk's source extent.
    #[napi]
    pub fn update(&mut self, data: Buffer) {
        self.inner.update(data.as_ref());
    }

    /// The lowercase SHA-256 of every raw source byte absorbed so far.
    #[napi]
    pub fn digest(&self) -> String {
        self.inner.digest()
    }
}

fn action_descriptor_value(value: &registry_breg_client::BRegActionDescriptor) -> Value {
    let bounds = value.bounds();
    json!({
        "id": value.identifier(), "apiName": value.api_name(), "revision": value.definition_revision(), "display": value.display(), "mode": value.mode(),
        "inputMode": value.input_mode(),
        "maximumInputStringBytes": value.maximum_input_string_bytes(),
        "attachments": value.attachments(),
        "inputs": value.inputs().iter().map(|input| json!({
            "id": input.identifier(), "apiName": input.api_name(),
            "label": input.label(), "description": input.description(),
            "schemaJson": input.schema().to_string(),
            "fieldTypeJson": input.field_type().to_string(), "required": input.required(),
            "nullable": input.nullable(), "classification": input.classification(),
        })).collect::<Vec<_>>(),
        "referenceInputs": value.reference_inputs().iter().map(|input| json!({
            "input": input.input_identifier(), "apiName": input.api_name(),
            "targetRecordType": input.target_record_type(),
        })).collect::<Vec<_>>(),
        "requiredConditionKeys": value.required_condition_keys(),
        "resultEffects": value.result_effects().iter().map(|effect| json!({
            "effect": effect.effect_identifier(), "recordType": effect.record_type_identifier(),
            "operation": effect.operation().as_str(),
        })).collect::<Vec<_>>(),
        "accessProfile": value.access_profile(), "invokePath": value.invoke_path(),
        "targetConditionsPath": value.target_conditions_path(),
        "availabilityPath": value.availability_path(),
        "bounds": {
            "maximumTargets": bounds.maximum_targets(),
            "maximumFieldMutations": bounds.maximum_field_mutations(),
            "maximumSnapshotBytes": bounds.maximum_snapshot_bytes(),
        },
    })
}

#[napi(js_name = "BRegCreateBinding")]
pub struct CreateBinding {
    inner: BRegCreateBinding,
}

#[napi(js_name = "BRegPatchBinding")]
pub struct PatchBinding {
    inner: BRegPatchBinding,
}

#[napi(js_name = "BRegActionBinding")]
pub struct ActionBinding {
    inner: BRegActionBinding,
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

/// A recovered Create request, key, and representation. This remains inert
/// until `executeRecoveredCreate` is explicitly called with fresh authority.
#[napi(js_name = "BRegRecoveredCreate")]
pub struct RecoveredCreate {
    request: BRegCreateRequest,
    key: registry_breg_client::BRegIdempotencyKey,
    format: BRegRecordFormat,
}

/// A recovered immediate-action invocation and key. This remains inert until
/// `executeRecoveredAction` is explicitly called with freshly selected
/// authority.
#[napi(js_name = "BRegRecoveredAction")]
pub struct RecoveredAction {
    request: BRegActionInvocationRequest,
    key: registry_breg_client::BRegIdempotencyKey,
}

#[napi(js_name = "BRegMetadata")]
pub struct Metadata {
    inner: CoreMetadata,
    trace_id: String,
    etag: Option<String>,
}

#[napi]
impl Metadata {
    /// The event record descriptor declared for one record type, as JSON text.
    #[napi]
    pub fn event_record_descriptor(&self, record_type: String) -> Result<String> {
        let descriptor = self
            .inner
            .event_record(&record_type)
            .map_err(event_record_error)?;
        serde_json::to_string(&descriptor.to_value())
            .map_err(|_| binding_error("protocol", "event record descriptor is not representable"))
    }

    /// Read-only capability inventory for each exact Action/profile pair.
    #[napi(getter)]
    pub fn proposal_actions(&self) -> Value {
        serde_json::to_value(self.inner.proposal_actions()).expect("validated Proposal inventory")
    }

    /// Caller-filtered inert descriptors. Selectors below remain the only authority constructors.
    #[napi(getter)]
    pub fn operations(&self) -> Value {
        Value::Array(self.inner.operations().iter().map(|operation| {
            let request = operation.request();
            json!({
                "id": operation.identifier(), "method": operation.method(), "path": operation.path(),
                "kind": operation.kind().as_str(), "sourceRecordType": operation.source_record_type(),
                "responseRecordType": operation.response_record_type(), "accessProfile": operation.access_profile(),
                "recordTypeLabel": operation.record_type_label(), "titleFields": operation.title_fields(),
                "requiredCapabilities": operation.required_capabilities(),
                "readableFields": operation.readable_fields(),
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
                    "referenceTargetRecordType": field.reference_target_record_type(),
                    "codeLabels": field.code_labels(),
                    "storageValidation": field.storage_validation().map(|validation| json!({
                        "kind": validation.kind(), "pattern": validation.pattern(),
                    })),
                    "reference": field.reference().map(|reference| json!({
                        "name":reference.name(),"cardinality":reference.cardinality(),"inverseName":reference.inverse_name(),
                        "manualEntry": reference.manual_entry(), "targetRecordType": reference.target_record_type(),
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

    #[napi]
    pub fn select_proposals(&self, profile: String) -> Result<ProposalCollection> {
        self.inner
            .select_proposals(&profile)
            .map(|inner| ProposalCollection { inner })
            .map_err(selection_error)
    }
    #[napi]
    pub fn select_proposal_get(&self, profile: String) -> Result<ProposalGetBinding> {
        self.inner
            .select_proposal_get(&profile)
            .map(|inner| ProposalGetBinding { inner })
            .map_err(selection_error)
    }

    #[napi]
    pub fn select_proposal_review_context(
        &self,
        profile: String,
        action: String,
    ) -> Result<ProposalReviewBinding> {
        self.inner
            .select_proposal_review_context(&profile, &action)
            .map(|inner| ProposalReviewBinding { inner })
            .map_err(selection_error)
    }

    #[napi]
    pub fn select_proposal_review_status(
        &self,
        profile: String,
        action: String,
    ) -> Result<ProposalReviewBinding> {
        self.inner
            .select_proposal_review_status(&profile, &action)
            .map(|inner| ProposalReviewBinding { inner })
            .map_err(selection_error)
    }

    /// Complete typed caller-filtered Action descriptors.
    #[napi(getter)]
    pub fn actions(&self) -> Value {
        Value::Array(
            self.inner
                .actions()
                .iter()
                .map(action_descriptor_value)
                .collect(),
        )
    }

    /// Original caller-filtered action metadata as exact JSON text.
    #[napi(getter)]
    pub fn actions_json(&self) -> Result<Option<String>> {
        self.inner
            .action_metadata()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| binding_error("protocol", "action metadata is not representable"))
    }

    /// Validated caller-filtered statistical dataset descriptions, without entity authority.
    #[napi(getter)]
    pub fn statistical_datasets(&self) -> Option<Value> {
        self.inner.statistical_datasets().cloned()
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
                "metadata-selection",
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
                "metadata-selection",
                "operation is not a patch",
            )),
        }
    }

    #[napi]
    pub fn select_action(
        &self,
        action_identifier: String,
        expected_profile: String,
    ) -> Result<ActionBinding> {
        self.inner
            .select_action(&action_identifier, &expected_profile)
            .map(|inner| ActionBinding { inner })
            .map_err(selection_error)
    }

    #[napi]
    pub fn select_tombstone(
        &self,
        record_type_identifier: String,
        expected_profile: String,
    ) -> Result<TombstoneBinding> {
        self.inner
            .select_tombstone(&record_type_identifier, &expected_profile)
            .map(|inner| TombstoneBinding { inner })
            .map_err(selection_error)
    }

    #[napi]
    pub fn select_batch(
        &self,
        record_type_identifier: String,
        expected_profile: String,
    ) -> Result<BatchBinding> {
        self.inner
            .select_batch(&record_type_identifier, &expected_profile)
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
    pub async fn statistics_live(
        &self,
        dataset: String,
        from: Option<String>,
        to: Option<String>,
        access_profile: Option<String>,
        format: Option<String>,
    ) -> Result<RawOutcome> {
        self.inner
            .statistics_live(
                &dataset,
                from.as_deref(),
                to.as_deref(),
                access_profile.as_deref(),
                statistics_format(format.as_deref())?,
            )
            .await
            .map(raw_value)
            .map_err(client_error)
    }

    #[napi]
    pub async fn statistics_releases(
        &self,
        dataset: String,
        top: Option<u32>,
        skip_token: Option<String>,
        access_profile: Option<String>,
    ) -> Result<RawOutcome> {
        let top = top
            .map(|value| {
                u16::try_from(value).map_err(|_| binding_error("invalid-request", "top is invalid"))
            })
            .transpose()?;
        self.inner
            .statistics_releases(
                &dataset,
                top,
                skip_token.as_deref(),
                access_profile.as_deref(),
            )
            .await
            .map(raw_value)
            .map_err(client_error)
    }

    #[napi]
    pub async fn statistics_latest_release(
        &self,
        dataset: String,
        period: String,
        selection: String,
        access_profile: Option<String>,
        format: Option<String>,
    ) -> Result<RawOutcome> {
        self.inner
            .statistics_latest_release(
                &dataset,
                &period,
                release_selection(&selection)?,
                access_profile.as_deref(),
                statistics_format(format.as_deref())?,
            )
            .await
            .map(raw_value)
            .map_err(client_error)
    }

    #[napi]
    pub async fn statistics_release_version(
        &self,
        dataset: String,
        period: String,
        version: i64,
        access_profile: Option<String>,
        format: Option<String>,
    ) -> Result<RawOutcome> {
        self.inner
            .statistics_release_version(
                &dataset,
                &period,
                statistics_version(version)?,
                access_profile.as_deref(),
                statistics_format(format.as_deref())?,
            )
            .await
            .map(raw_value)
            .map_err(client_error)
    }

    #[napi]
    pub async fn statistics_release_series(
        &self,
        dataset: String,
        from: String,
        to: String,
        selection: String,
        access_profile: Option<String>,
        format: Option<String>,
    ) -> Result<RawOutcome> {
        self.inner
            .statistics_release_series(
                &dataset,
                &from,
                &to,
                release_selection(&selection)?,
                access_profile.as_deref(),
                statistics_format(format.as_deref())?,
            )
            .await
            .map(raw_value)
            .map_err(client_error)
    }

    #[napi]
    pub async fn statistics_publish(
        &self,
        dataset: String,
        period: String,
        status: String,
        access_profile: String,
        idempotency_key: String,
    ) -> Result<RawOutcome> {
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
        self.inner
            .statistics_publish(
                &dataset,
                &period,
                release_status(&status)?,
                &access_profile,
                &key,
            )
            .await
            .map(raw_value)
            .map_err(client_error)
    }

    #[napi]
    pub async fn statistics_withdraw(
        &self,
        dataset: String,
        period: String,
        version: i64,
        reason: String,
        access_profile: String,
        idempotency_key: String,
    ) -> Result<RawOutcome> {
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
        self.inner
            .statistics_withdraw(
                &dataset,
                &period,
                statistics_version(version)?,
                withdrawal_reason(&reason)?,
                &access_profile,
                &key,
            )
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
    pub async fn record_schema(
        &self,
        record_type_identifier: String,
        access_profile: Option<String>,
    ) -> Result<RawOutcome> {
        self.inner
            .record_schema(&record_type_identifier, access_profile.as_deref())
            .await
            .map(raw_value)
            .map_err(client_error)
    }

    /// Retrieve one bounded first page of record revisions as inert JSON.
    #[napi]
    pub async fn record_revisions(
        &self,
        record_route: String,
        record_identifier: String,
        access_profile: Option<String>,
    ) -> Result<RawOutcome> {
        self.inner
            .record_revisions(&record_route, &record_identifier, access_profile.as_deref())
            .await
            .map(raw_value)
            .map_err(client_error)
    }

    /// Retrieve one exact retained revision as validated inert record JSON.
    #[napi]
    pub async fn get_record_revision(
        &self,
        record_route: String,
        record_identifier: String,
        revision: i64,
        options: Option<Value>,
    ) -> Result<RawOutcome> {
        if !(1..=MAXIMUM_JAVASCRIPT_SAFE_INTEGER).contains(&revision) {
            return Err(binding_error(
                "invalid-request",
                "revision must be a positive safe integer",
            ));
        }
        let options = options_object(options, "record options must be an object")?;
        self.inner
            .get_record_revision(
                &record_route,
                &record_identifier,
                revision as u64,
                &record_options(options.as_ref())?,
            )
            .await
            .map(raw_value)
            .map_err(client_error)
    }

    /// Read the first revision of one record as the compact
    /// `{recordType, recordId, revision, createdAt}` JSON, or null when the
    /// caller may not read it.
    #[napi]
    pub async fn event_record_creation_revision(
        &self,
        record_route: String,
        record_identifier: String,
        access_profile: Option<String>,
    ) -> Result<Option<String>> {
        self.inner
            .event_record_creation_revision(
                &record_route,
                &record_identifier,
                access_profile.as_deref(),
            )
            .await
            .map_err(client_error)?
            .map(|revision| {
                serde_json::to_string(&revision).map_err(|_| {
                    binding_error("protocol", "creation revision is not representable")
                })
            })
            .transpose()
    }

    #[napi]
    pub async fn get_record(
        &self,
        record_route: String,
        record_identifier: String,
        options: Option<Value>,
    ) -> Result<CompleteOutcome> {
        let options = options_object(options, "record options must be an object")?;
        let BRegComplete { value, metadata } = self
            .inner
            .get_record(
                &record_route,
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
        record_route: String,
        options: Option<Value>,
    ) -> Result<PageOutcome> {
        self.inner
            .list_records(&record_route, &list_request(options)?)
            .await
            .map_err(client_error)
            .and_then(page_value)
    }

    #[napi]
    pub async fn continue_list(&self, value: Value) -> Result<PageOutcome> {
        let projection: BRegContinuationProjection = serde_json::from_value(value)
            .map_err(|_| binding_error("invalid-request", "continuation is invalid"))?;
        let continuation = BRegContinuation::try_from_projection(projection)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
        self.inner
            .continue_list(&continuation)
            .await
            .map_err(client_error)
            .and_then(page_value)
    }

    #[napi(js_name = "getGeoJsonRecord")]
    pub async fn get_geo_json_record(
        &self,
        record_route: String,
        record_identifier: String,
        options: Option<Value>,
    ) -> Result<CompleteOutcome> {
        let options =
            options_object(options, "GeoJSON options must be an object")?.unwrap_or_default();
        only_fields(
            &options,
            &["select", "accessProfile"],
            "invalid-request",
            "GeoJSON options contain an unsupported field",
        )?;
        let BRegComplete { value, metadata } = self
            .inner
            .get_geojson_record(
                &record_route,
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
        record_route: String,
        options: Option<Value>,
    ) -> Result<PageOutcome> {
        let BRegComplete { value, metadata } = self
            .inner
            .list_geojson_records(&record_route, &geojson_list_request(options)?)
            .await
            .map_err(client_error)?;
        specialized_page_value(value.value, value.continuation, metadata, None, None)
    }

    #[napi(js_name = "continueGeoJsonList")]
    pub async fn continue_geo_json_list(&self, value: Value) -> Result<PageOutcome> {
        let projection: BRegGeoJsonContinuationProjection = serde_json::from_value(value)
            .map_err(|_| binding_error("invalid-request", "GeoJSON continuation is invalid"))?;
        let continuation = BRegGeoJsonContinuation::try_from_projection(projection)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
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
        record_route: String,
        options: Option<Value>,
    ) -> Result<PageOutcome> {
        let BRegComplete { value, metadata } = self
            .inner
            .list_current_records(&record_route, &current_list_request(options)?)
            .await
            .map_err(client_error)?;
        specialized_page_value(value.value, value.continuation, metadata, None, None)
    }

    #[napi]
    pub async fn continue_current_list(&self, value: Value) -> Result<PageOutcome> {
        let projection: BRegCurrentContinuationProjection = serde_json::from_value(value)
            .map_err(|_| binding_error("invalid-request", "current continuation is invalid"))?;
        let continuation = BRegCurrentContinuation::try_from_projection(projection)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
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
        record_route: String,
        options: Option<Value>,
    ) -> Result<PageOutcome> {
        let BRegComplete { value, metadata } = self
            .inner
            .list_records_as_of(&record_route, &as_of_list_request(options)?)
            .await
            .map_err(client_error)?;
        specialized_page_value(value.value, value.continuation, metadata, None, None)
    }

    #[napi]
    pub async fn continue_as_of_list(&self, value: Value) -> Result<PageOutcome> {
        let projection: BRegAsOfContinuationProjection = serde_json::from_value(value)
            .map_err(|_| binding_error("invalid-request", "as-of continuation is invalid"))?;
        let continuation = BRegAsOfContinuation::try_from_projection(projection)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
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
        record_route: String,
        options: Option<Value>,
    ) -> Result<PageOutcome> {
        let BRegComplete { value, metadata } = self
            .inner
            .list_snapshot_records(&record_route, &snapshot_list_request(options)?)
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
            .map_err(|_| binding_error("invalid-request", "snapshot continuation is invalid"))?;
        let continuation = BRegSnapshotContinuation::try_from_projection(projection)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
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
        record_route: String,
        record_identifier: String,
        path_route: String,
        options: Option<Value>,
    ) -> Result<PageOutcome> {
        let BRegComplete { value, metadata } = self
            .inner
            .list_relationship_records(
                &record_route,
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
                binding_error("invalid-request", "relationship continuation is invalid")
            })?;
        let continuation = BRegRelationshipContinuation::try_from_projection(projection)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
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
        record_route: String,
        selector: String,
        values: Option<Value>,
        options: Option<Value>,
    ) -> Result<CompleteOutcome> {
        let request = lookup_request(selector, values, options)?;
        let BRegComplete { value, metadata } = self
            .inner
            .lookup_record(&record_route, &request)
            .await
            .map_err(client_error)?;
        complete_value(value, metadata)
    }

    #[napi]
    pub async fn start_proposal(
        &self,
        binding: &ActionBinding,
        inputs: Value,
        key: String,
    ) -> Result<Proposal> {
        let inputs = input_object(inputs, "action inputs must be an object")?;
        let request = action_invocation(binding, inputs, None)?;
        let key = idempotency_key(key)?;
        self.inner
            .start_proposal(&binding.inner, &request, &key)
            .await
            .map(|response| Proposal {
                inner: response.value,
            })
            .map_err(client_error)
    }

    #[napi]
    pub async fn read_proposal(&self, proposal: &Proposal) -> Result<Proposal> {
        self.inner
            .read_proposal(&proposal.inner)
            .await
            .map(|response| Proposal {
                inner: response.value,
            })
            .map_err(client_error)
    }
    #[napi]
    pub async fn read_proposal_submission(
        &self,
        proposal: &Proposal,
        version: u32,
    ) -> Result<CompleteOutcome> {
        let response = self
            .inner
            .read_proposal_submission(&proposal.inner, version)
            .await
            .map_err(client_error)?;
        complete_value(response.value, response.metadata)
    }
    #[napi]
    pub async fn get_proposal(&self, binding: &ProposalGetBinding, id: String) -> Result<Proposal> {
        self.inner
            .get_proposal(&binding.inner, &id)
            .await
            .map(|response| Proposal {
                inner: response.value,
            })
            .map_err(client_error)
    }

    #[napi]
    pub async fn download_proposal_attachment(
        &self,
        proposal: &Proposal,
        slot: String,
    ) -> Result<RawOutcome> {
        self.inner
            .download_proposal_attachment(&proposal.inner, &slot)
            .await
            .map(raw_value)
            .map_err(client_error)
    }

    #[napi]
    pub async fn read_proposal_review_by_id(
        &self,
        binding: &ProposalReviewBinding,
        id: String,
    ) -> Result<CompleteOutcome> {
        let response = self
            .inner
            .read_proposal_review_by_id(&binding.inner, &id)
            .await
            .map_err(client_error)?;
        complete_value(response.value, response.metadata)
    }

    #[napi]
    pub async fn download_proposal_review_document(
        &self,
        binding: &ProposalReviewBinding,
        context: Value,
        field: String,
    ) -> Result<RawOutcome> {
        let context = serde_json::from_value(context)
            .map_err(|_| binding_error("invalid-request", "Proposal review context is invalid"))?;
        self.inner
            .download_proposal_review_document(&binding.inner, &context, &field)
            .await
            .map(raw_value)
            .map_err(client_error)
    }
    #[napi]
    pub async fn read_proposal_review_status(
        &self,
        proposal: &Proposal,
    ) -> Result<CompleteOutcome> {
        let response = self
            .inner
            .read_proposal_review_status(&proposal.inner)
            .await
            .map_err(client_error)?;
        complete_value(response.value, response.metadata)
    }
    #[napi]
    pub async fn read_proposal_review_context(
        &self,
        proposal: &Proposal,
    ) -> Result<CompleteOutcome> {
        let response = self
            .inner
            .read_proposal_review_context(&proposal.inner)
            .await
            .map_err(client_error)?;
        complete_value(response.value, response.metadata)
    }
    #[napi]
    pub async fn read_proposal_review_context_batch(
        &self,
        binding: &ProposalReviewBinding,
        ids: Vec<String>,
    ) -> Result<CompleteOutcome> {
        let ids = ids.iter().map(String::as_str).collect::<Vec<_>>();
        let response = self
            .inner
            .read_proposal_review_context_batch(&binding.inner, &ids)
            .await
            .map_err(client_error)?;
        complete_value(response.value, response.metadata)
    }

    #[napi]
    pub async fn upload_proposal_attachment(
        &self,
        proposal: &Proposal,
        slot: String,
        content_type: String,
        bytes: Buffer,
        key: String,
    ) -> Result<Proposal> {
        let key = idempotency_key(key)?;
        self.inner
            .upload_proposal_attachment(&proposal.inner, &slot, &content_type, &bytes, &key)
            .await
            .map(|response| Proposal {
                inner: response.value,
            })
            .map_err(client_error)
    }
    #[napi]
    pub async fn delete_proposal_attachment(
        &self,
        proposal: &Proposal,
        slot: String,
        key: String,
    ) -> Result<Proposal> {
        let key = idempotency_key(key)?;
        self.inner
            .delete_proposal_attachment(&proposal.inner, &slot, &key)
            .await
            .map(|response| Proposal {
                inner: response.value,
            })
            .map_err(client_error)
    }

    #[napi]
    pub async fn list_proposals(
        &self,
        collection: &ProposalCollection,
        query: Value,
    ) -> Result<ProposalPage> {
        let query = serde_json::from_value(query)
            .map_err(|_| binding_error("invalid-request", "Proposal query does not conform"))?;
        self.inner
            .list_proposals(&collection.inner, &query)
            .await
            .map(|response| ProposalPage {
                items: response
                    .value
                    .items
                    .into_iter()
                    .map(|inner| Proposal { inner })
                    .collect(),
                next_cursor: response.value.next_cursor,
            })
            .map_err(client_error)
    }

    #[napi]
    pub fn prepare_proposal(
        &self,
        proposal: &Proposal,
        operation: String,
        body: Value,
        key: String,
    ) -> Result<PreparedProposal> {
        self.inner
            .prepare_proposal(&proposal.inner, &operation, body, &idempotency_key(key)?)
            .map(|inner| PreparedProposal { inner })
            .map_err(client_error)
    }

    /// Prepare a transition from exact JSON through the same lifecycle authority.
    #[napi]
    pub fn prepare_proposal_json(
        &self,
        proposal: &Proposal,
        operation: String,
        body_json: String,
        key: String,
    ) -> Result<PreparedProposal> {
        self.prepare_proposal(proposal, operation, exact_input(&body_json)?, key)
    }

    /// List through the same metadata-selected collection with an exact JSON query.
    #[napi]
    pub async fn list_proposals_json(
        &self,
        collection: &ProposalCollection,
        query_json: String,
    ) -> Result<ProposalPage> {
        self.list_proposals(collection, exact_input(&query_json)?)
            .await
    }

    #[napi]
    pub fn recover_proposal(
        &self,
        proposal: &Proposal,
        attempt: &PreparedProposal,
    ) -> Result<PreparedProposal> {
        self.inner
            .recover_proposal(&proposal.inner, &attempt.inner)
            .map(|inner| PreparedProposal { inner })
            .map_err(client_error)
    }

    #[napi]
    pub async fn execute_proposal(&self, attempt: &PreparedProposal) -> Result<Proposal> {
        self.inner
            .execute_proposal(&attempt.inner)
            .await
            .map(|response| Proposal {
                inner: response.value,
            })
            .map_err(client_error)
    }

    /// Fetch opaque target conditions for one metadata-selected action.
    #[napi]
    pub async fn action_target_conditions(
        &self,
        binding: &ActionBinding,
        inputs: Value,
    ) -> Result<ActionTargetConditions> {
        let request = BRegActionTargetConditionsRequest::new(
            &binding.inner,
            input_object(inputs, "action inputs must be an object")?,
        )
        .map_err(|error| binding_error("invalid-request", error.to_string()))?;
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

    /// Read current field-guard availability for one selected reference.
    #[napi]
    pub async fn action_availability(
        &self,
        binding: &ActionBinding,
        target_input: String,
        inputs: Value,
    ) -> Result<CompleteOutcome> {
        let request = BRegActionAvailabilityRequest::new(
            &binding.inner,
            target_input,
            input_object(inputs, "action inputs must be an object")?,
        )
        .map_err(|error| binding_error("invalid-request", error.to_string()))?;
        let BRegComplete { value, metadata } = self
            .inner
            .action_availability(&binding.inner, &request)
            .await
            .map_err(client_error)?;
        complete_value(value, metadata)
    }

    /// Invoke one metadata-selected immediate action. An invocation whose
    /// outcome is unknown is resent identically under the same key, at most
    /// `maximumMutationRetries` times.
    #[napi]
    pub async fn invoke_action(
        &self,
        binding: &ActionBinding,
        inputs: Value,
        idempotency_key: String,
        conditions: Option<&ActionTargetConditions>,
    ) -> Result<CompleteOutcome> {
        let request = BRegActionInvocationRequest::new(
            &binding.inner,
            input_object(inputs, "action inputs must be an object")?,
            conditions.map(|value| &value.inner),
        )
        .map_err(|error| binding_error("invalid-request", error.to_string()))?;
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
        let BRegComplete { value, metadata } = self
            .inner
            .invoke_action(&binding.inner, &request, &key)
            .await
            .map_err(client_error)?;
        complete_value(value, metadata)
    }

    /// Prepare inert invocation evidence before any token acquisition or I/O.
    /// Persist `toBytes` before invoking so a lost response can be recovered.
    #[napi]
    pub fn prepare_action(
        &self,
        binding: &ActionBinding,
        inputs: Value,
        idempotency_key: String,
        conditions: Option<&ActionTargetConditions>,
    ) -> Result<PreparedAction> {
        prepare_action_evidence(
            &self.inner,
            binding,
            input_object(inputs, "action inputs must be an object")?,
            idempotency_key,
            conditions,
        )
    }

    /// Revalidate saved invocation evidence against freshly selected authority
    /// and the caller's original inputs and key. The saved target conditions
    /// are reused exactly; this never fetches conditions or sends a request.
    #[napi]
    pub fn recover_action(
        &self,
        binding: &ActionBinding,
        prepared: &PreparedAction,
        inputs: Value,
        idempotency_key: String,
    ) -> Result<RecoveredAction> {
        recover_action_evidence(
            &self.inner,
            binding,
            prepared,
            &input_object(inputs, "action inputs must be an object")?,
            idempotency_key,
        )
    }

    /// Explicitly send a recovered invocation under its original key. An
    /// invocation whose outcome is unknown is resent identically under that
    /// key, at most `maximumMutationRetries` times.
    #[napi]
    pub async fn execute_recovered_action(
        &self,
        binding: &ActionBinding,
        recovered: &RecoveredAction,
    ) -> Result<CompleteOutcome> {
        let BRegComplete { value, metadata } = self
            .inner
            .invoke_action(&binding.inner, &recovered.request, &recovered.key)
            .await
            .map_err(client_error)?;
        complete_value(value, metadata)
    }

    /// Execute a recovered proposal start with its exact original request and key.
    #[napi]
    pub async fn execute_recovered_proposal_start(
        &self,
        binding: &ActionBinding,
        recovered: &RecoveredAction,
    ) -> Result<Proposal> {
        self.inner
            .start_proposal(&binding.inner, &recovered.request, &recovered.key)
            .await
            .map(|response| Proposal {
                inner: response.value,
            })
            .map_err(client_error)
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
            .ok_or_else(|| binding_error("invalid-request", "create data must be an object"))?;
        let request = BRegCreateRequest::new(data)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
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
            .ok_or_else(|| binding_error("invalid-request", "create data must be an object"))?;
        let request = BRegCreateRequest::new(data)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
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
            .map_err(|_| binding_error("invalid-request", "recordIdentifier must be a UUID"))?;
        let etag = BRegEtag::parse(&etag).map_err(|_| {
            binding_error(
                "invalid-request",
                "etag must be a strong Base Registry Engine entity tag",
            )
        })?;
        let request = patch_request(operations)?;
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
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

    /// Execute one metadata-selected atomic batch. A batch whose outcome is
    /// unknown is resent identically under the same key, at most
    /// `maximumMutationRetries` times.
    #[napi]
    pub async fn batch_records(
        &self,
        binding: &BatchBinding,
        request: Value,
        idempotency_key: String,
    ) -> Result<CompleteOutcome> {
        let request = batch_request(&binding.inner, request)?;
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
        let BRegComplete { value, metadata } = self
            .inner
            .batch_records(&binding.inner, &request, &key)
            .await
            .map_err(client_error)?;
        complete_value(value, metadata)
    }

    /// Announce one whole input and open a durable ingestion run for it. The
    /// run request names the access profile, which the client selects for the
    /// exchange.
    #[napi]
    pub async fn create_ingestion_run(
        &self,
        record_route: String,
        request: Value,
    ) -> Result<CompleteOutcome> {
        let request = ingestion_run_request(request)?;
        let BRegComplete { value, metadata } = self
            .inner
            .create_ingestion_run(&record_route, &request)
            .await
            .map_err(client_error)?;
        complete_value(value, metadata)
    }

    /// Read one bounded page of ingestion runs for one record route.
    #[napi]
    pub async fn list_ingestion_runs(
        &self,
        record_route: String,
        query: Option<Value>,
    ) -> Result<CompleteOutcome> {
        let query = ingestion_run_list_query(query.as_ref())?;
        let BRegComplete { value, metadata } = self
            .inner
            .list_ingestion_runs(&record_route, &query)
            .await
            .map_err(client_error)?;
        complete_value(value, metadata)
    }

    /// Read the current durable state of one ingestion run.
    #[napi]
    pub async fn read_ingestion_run(
        &self,
        record_route: String,
        run_id: String,
        access_profile: Option<String>,
    ) -> Result<CompleteOutcome> {
        let run_id = ingestion_run_identifier(run_id)?;
        let BRegComplete { value, metadata } = self
            .inner
            .read_ingestion_run(&record_route, run_id, access_profile.as_deref())
            .await
            .map_err(client_error)?;
        complete_value(value, metadata)
    }

    /// Submit one bounded chunk of an open ingestion run under the run's
    /// access profile. A resubmitted chunk replays its retained receipt
    /// instead of executing twice.
    #[napi]
    pub async fn submit_ingestion_chunk(
        &self,
        record_route: String,
        run_id: String,
        chunk: &IngestionChunk,
        profile_id: String,
    ) -> Result<CompleteOutcome> {
        let run_id = ingestion_run_identifier(run_id)?;
        let chunk = Arc::clone(&chunk.inner);
        let BRegComplete { value, metadata } = self
            .inner
            .submit_ingestion_chunk(&record_route, run_id, chunk.as_ref(), &profile_id)
            .await
            .map_err(client_error)?;
        complete_value(value, metadata)
    }

    /// Cancel an open ingestion run. Committed chunks stay committed.
    #[napi]
    pub async fn cancel_ingestion_run(
        &self,
        record_route: String,
        run_id: String,
        access_profile: Option<String>,
    ) -> Result<CompleteOutcome> {
        let run_id = ingestion_run_identifier(run_id)?;
        let BRegComplete { value, metadata } = self
            .inner
            .cancel_ingestion_run(&record_route, run_id, access_profile.as_deref())
            .await
            .map_err(client_error)?;
        complete_value(value, metadata)
    }

    /// Read the retained receipt of one committed chunk under the run's
    /// access profile. An erased receipt answers with the
    /// `ingestion.receipt_erased` problem instead.
    #[napi]
    pub async fn ingestion_chunk_receipt(
        &self,
        record_route: String,
        run_id: String,
        chunk_index: i64,
        profile_id: String,
    ) -> Result<CompleteOutcome> {
        let run_id = ingestion_run_identifier(run_id)?;
        let chunk_index = ingestion_chunk_index(
            chunk_index,
            "chunkIndex must be a non-negative safe integer",
        )?;
        let BRegComplete { value, metadata } = self
            .inner
            .ingestion_chunk_receipt(&record_route, run_id, chunk_index, &profile_id)
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
            .map_err(|_| binding_error("invalid-request", "recordIdentifier must be a UUID"))?;
        let etag = BRegEtag::parse(&etag).map_err(|_| {
            binding_error(
                "invalid-request",
                "etag must be a strong Base Registry Engine entity tag",
            )
        })?;
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
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

    #[napi]
    pub async fn get_record_json(
        &self,
        record_route: String,
        record_identifier: String,
        options: Option<Value>,
    ) -> Result<JsonOutcome> {
        let options = options_object(options, "record options must be an object")?;
        let BRegComplete { value, metadata } = self
            .inner
            .get_record(
                &record_route,
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
        record_route: String,
        options: Option<Value>,
    ) -> Result<JsonOutcome> {
        self.inner
            .list_records(&record_route, &list_request(options)?)
            .await
            .map_err(client_error)
            .and_then(page_json_value)
    }

    #[napi]
    pub async fn continue_list_json(&self, value: Value) -> Result<JsonOutcome> {
        let projection: BRegContinuationProjection = serde_json::from_value(value)
            .map_err(|_| binding_error("invalid-request", "continuation is invalid"))?;
        let continuation = BRegContinuation::try_from_projection(projection)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
        self.inner
            .continue_list(&continuation)
            .await
            .map_err(client_error)
            .and_then(page_json_value)
    }

    #[napi(js_name = "getGeoJsonRecordJson")]
    pub async fn get_geo_json_record_json(
        &self,
        record_route: String,
        record_identifier: String,
        options: Option<Value>,
    ) -> Result<JsonOutcome> {
        let options =
            options_object(options, "GeoJSON options must be an object")?.unwrap_or_default();
        only_fields(
            &options,
            &["select", "accessProfile"],
            "invalid-request",
            "GeoJSON options contain an unsupported field",
        )?;
        let BRegComplete { value, metadata } = self
            .inner
            .get_geojson_record(
                &record_route,
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
        record_route: String,
        options: Option<Value>,
    ) -> Result<JsonOutcome> {
        let BRegComplete { value, metadata } = self
            .inner
            .list_geojson_records(&record_route, &geojson_list_request(options)?)
            .await
            .map_err(client_error)?;
        specialized_page_json(value.value, value.continuation, metadata, None, None)
    }

    #[napi(js_name = "continueGeoJsonListJson")]
    pub async fn continue_geo_json_list_json(&self, value: Value) -> Result<JsonOutcome> {
        let projection: BRegGeoJsonContinuationProjection = serde_json::from_value(value)
            .map_err(|_| binding_error("invalid-request", "GeoJSON continuation is invalid"))?;
        let continuation = BRegGeoJsonContinuation::try_from_projection(projection)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
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
        record_route: String,
        options: Option<Value>,
    ) -> Result<JsonOutcome> {
        let BRegComplete { value, metadata } = self
            .inner
            .list_current_records(&record_route, &current_list_request(options)?)
            .await
            .map_err(client_error)?;
        specialized_page_json(value.value, value.continuation, metadata, None, None)
    }

    #[napi]
    pub async fn continue_current_list_json(&self, value: Value) -> Result<JsonOutcome> {
        let projection: BRegCurrentContinuationProjection = serde_json::from_value(value)
            .map_err(|_| binding_error("invalid-request", "current continuation is invalid"))?;
        let continuation = BRegCurrentContinuation::try_from_projection(projection)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
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
        record_route: String,
        options: Option<Value>,
    ) -> Result<JsonOutcome> {
        let BRegComplete { value, metadata } = self
            .inner
            .list_records_as_of(&record_route, &as_of_list_request(options)?)
            .await
            .map_err(client_error)?;
        specialized_page_json(value.value, value.continuation, metadata, None, None)
    }

    #[napi]
    pub async fn continue_as_of_list_json(&self, value: Value) -> Result<JsonOutcome> {
        let projection: BRegAsOfContinuationProjection = serde_json::from_value(value)
            .map_err(|_| binding_error("invalid-request", "as-of continuation is invalid"))?;
        let continuation = BRegAsOfContinuation::try_from_projection(projection)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
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
        record_route: String,
        options: Option<Value>,
    ) -> Result<JsonOutcome> {
        let BRegComplete { value, metadata } = self
            .inner
            .list_snapshot_records(&record_route, &snapshot_list_request(options)?)
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
            .map_err(|_| binding_error("invalid-request", "snapshot continuation is invalid"))?;
        let continuation = BRegSnapshotContinuation::try_from_projection(projection)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
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
        record_route: String,
        record_identifier: String,
        path_route: String,
        options: Option<Value>,
    ) -> Result<JsonOutcome> {
        let BRegComplete { value, metadata } = self
            .inner
            .list_relationship_records(
                &record_route,
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
                binding_error("invalid-request", "relationship continuation is invalid")
            })?;
        let continuation = BRegRelationshipContinuation::try_from_projection(projection)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
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
        record_route: String,
        selector: String,
        values_json: Option<String>,
        options: Option<Value>,
    ) -> Result<JsonOutcome> {
        let values = values_json.map(|value| exact_input(&value)).transpose()?;
        let request = lookup_request(selector, values, options)?;
        let BRegComplete { value, metadata } = self
            .inner
            .lookup_record(&record_route, &request)
            .await
            .map_err(client_error)?;
        complete_json_value(value, metadata)
    }

    /// Fetch opaque target conditions from exact action-input JSON.
    #[napi]
    pub async fn action_target_conditions_json(
        &self,
        binding: &ActionBinding,
        inputs_json: String,
    ) -> Result<ActionTargetConditions> {
        let request = BRegActionTargetConditionsRequest::new(
            &binding.inner,
            input_object(
                exact_input(&inputs_json)?,
                "action inputs must be an object",
            )?,
        )
        .map_err(|error| binding_error("invalid-request", error.to_string()))?;
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

    /// Read field-guard availability from exact action-input JSON.
    #[napi]
    pub async fn action_availability_json(
        &self,
        binding: &ActionBinding,
        target_input: String,
        inputs_json: String,
    ) -> Result<JsonOutcome> {
        let request = BRegActionAvailabilityRequest::new(
            &binding.inner,
            target_input,
            input_object(
                exact_input(&inputs_json)?,
                "action inputs must be an object",
            )?,
        )
        .map_err(|error| binding_error("invalid-request", error.to_string()))?;
        let BRegComplete { value, metadata } = self
            .inner
            .action_availability(&binding.inner, &request)
            .await
            .map_err(client_error)?;
        complete_json_value(value, metadata)
    }

    /// Invoke an action from exact JSON and preserve exact receipt values.
    #[napi]
    pub async fn invoke_action_json(
        &self,
        binding: &ActionBinding,
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
        .map_err(|error| binding_error("invalid-request", error.to_string()))?;
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
        let BRegComplete { value, metadata } = self
            .inner
            .invoke_action(&binding.inner, &request, &key)
            .await
            .map_err(client_error)?;
        complete_json_value(value, metadata)
    }

    /// Prepare inert invocation evidence from exact action-input JSON.
    #[napi]
    pub fn prepare_action_json(
        &self,
        binding: &ActionBinding,
        inputs_json: String,
        idempotency_key: String,
        conditions: Option<&ActionTargetConditions>,
    ) -> Result<PreparedAction> {
        prepare_action_evidence(
            &self.inner,
            binding,
            input_object(
                exact_input(&inputs_json)?,
                "action inputs must be an object",
            )?,
            idempotency_key,
            conditions,
        )
    }

    /// Revalidate saved invocation evidence against exact original input JSON.
    #[napi]
    pub fn recover_action_json(
        &self,
        binding: &ActionBinding,
        prepared: &PreparedAction,
        inputs_json: String,
        idempotency_key: String,
    ) -> Result<RecoveredAction> {
        recover_action_evidence(
            &self.inner,
            binding,
            prepared,
            &input_object(
                exact_input(&inputs_json)?,
                "action inputs must be an object",
            )?,
            idempotency_key,
        )
    }

    /// Explicitly send a recovered invocation and preserve exact receipt values.
    #[napi]
    pub async fn execute_recovered_action_json(
        &self,
        binding: &ActionBinding,
        recovered: &RecoveredAction,
    ) -> Result<JsonOutcome> {
        let BRegComplete { value, metadata } = self
            .inner
            .invoke_action(&binding.inner, &recovered.request, &recovered.key)
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
            .ok_or_else(|| binding_error("invalid-request", "create data must be an object"))?;
        let request = BRegCreateRequest::new(data)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
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
            .ok_or_else(|| binding_error("invalid-request", "create data must be an object"))?;
        let request = BRegCreateRequest::new(data)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
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
            .map_err(|_| binding_error("invalid-request", "recordIdentifier must be a UUID"))?;
        let etag = BRegEtag::parse(&etag).map_err(|_| {
            binding_error(
                "invalid-request",
                "etag must be a strong Base Registry Engine entity tag",
            )
        })?;
        let request = patch_request(exact_input(&operations_json)?)?;
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
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
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
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
            .map_err(|_| binding_error("invalid-request", "recordIdentifier must be a UUID"))?;
        let etag = BRegEtag::parse(&etag).map_err(|_| {
            binding_error(
                "invalid-request",
                "etag must be a strong Base Registry Engine entity tag",
            )
        })?;
        let key = registry_breg_client::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| binding_error("invalid-request", error.to_string()))?;
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
}
