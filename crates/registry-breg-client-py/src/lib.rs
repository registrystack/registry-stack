// SPDX-License-Identifier: Apache-2.0
//! Synchronous Python binding for the canonical Base Registry Engine client.

#![deny(unsafe_code)]

use std::sync::Arc;

use breg_client_sdk::{
    BRegActionInvocationRequest, BRegActionTargetConditions, BRegActionTargetConditionsRequest,
    BRegAsOfContinuation, BRegAsOfContinuationProjection, BRegAsOfListRequest,
    BRegAttachmentSlot as CoreAttachmentSlot, BRegAttachmentSlotValue, BRegAttachmentState,
    BRegAttachmentUpload as CoreAttachmentUpload, BRegAttachmentVerificationStatus,
    BRegBatchBinding, BRegBatchBuilder, BRegBoundingBox, BRegChangeContext, BRegComplete,
    BRegContinuation, BRegContinuationProjection, BRegCreateBinding, BRegCreateRequest,
    BRegCurrentContinuation, BRegCurrentContinuationProjection, BRegCurrentListRequest,
    BRegDirectWrite, BRegEtag, BRegGeoJsonContinuation, BRegGeoJsonContinuationProjection,
    BRegGeoJsonListRequest, BRegGeoJsonOptions, BRegIdempotencyKey, BRegImmediateActionBinding,
    BRegLifecycleAction as CoreLifecycleAction, BRegLifecycleActionReceipt, BRegLifecycleAuthority,
    BRegLifecyclePromotionError, BRegListRequest, BRegLookupRequest, BRegMetadata as CoreMetadata,
    BRegMetadataSelectionError, BRegMetadataSelectionErrorKind, BRegPage, BRegPatchBinding,
    BRegPatchRequest, BRegPreparedCreate as CorePreparedCreate,
    BRegPreparedLifecycle as CorePreparedLifecycle, BRegProblemCode, BRegProtocolFailure,
    BRegRawDocument, BRegRecordFormat, BRegRecordOptions, BRegRelationshipContinuation,
    BRegRelationshipContinuationProjection, BRegRelationshipListRequest,
    BRegRequestApplicationDisposition, BRegRequestProposal, BRegRequestReview,
    BRegRequestReviewMode, BRegRequestState, BRegSnapshotContinuation,
    BRegSnapshotContinuationProjection, BRegSnapshotListRequest, BRegTombstoneBinding,
    BaseRegistryClient as RustClient, BaseRegistryClientError as RustClientError,
    RegistryRecordRepresentation, RegistryRecordResponse, TokenError,
};
use pyo3::{
    exceptions::{PyException, PyRuntimeError},
    prelude::*,
    types::{PyBytes, PyDict},
};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};

mod convert;

use convert::{
    authorization_from_python, config_from_parts, json_to_python, python_to_json,
    serialize_to_python, ConfigError, ConversionError,
};

pyo3::create_exception!(
    registry_breg_client,
    BaseRegistryClientError,
    PyException,
    "A stable, value-free Base Registry Engine client failure."
);

#[derive(Default)]
struct MappedError {
    kind: &'static str,
    message: String,
    code: Option<String>,
    plan_refusal: Option<String>,
    refusal_code: Option<String>,
    status: Option<u16>,
    trace_id: Option<String>,
    transport_kind: Option<&'static str>,
    token_kind: Option<&'static str>,
}

impl MappedError {
    fn binding(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            ..Self::default()
        }
    }
}

fn to_py_err(py: Python<'_>, mapped: MappedError) -> PyErr {
    let error = BaseRegistryClientError::new_err(mapped.message);
    let instance = error.value(py);
    instance
        .setattr("kind", mapped.kind)
        .expect("fresh exception accepts attributes");
    instance
        .setattr("code", mapped.code)
        .expect("fresh exception accepts attributes");
    instance
        .setattr("plan_refusal", mapped.plan_refusal)
        .expect("fresh exception accepts attributes");
    instance
        .setattr("refusal_code", mapped.refusal_code)
        .expect("fresh exception accepts attributes");
    instance
        .setattr("status", mapped.status)
        .expect("fresh exception accepts attributes");
    instance
        .setattr("trace_id", mapped.trace_id)
        .expect("fresh exception accepts attributes");
    instance
        .setattr("transport_kind", mapped.transport_kind)
        .expect("fresh exception accepts attributes");
    instance
        .setattr("token_kind", mapped.token_kind)
        .expect("fresh exception accepts attributes");
    error
}

fn conversion_error(py: Python<'_>, kind: &'static str, error: ConversionError) -> PyErr {
    to_py_err(py, MappedError::binding(kind, error.message()))
}

fn config_error(py: Python<'_>, error: ConfigError) -> PyErr {
    match error {
        ConfigError::Shape(error) => conversion_error(py, "configuration", error),
        ConfigError::Token(error) => token_error(py, error),
    }
}

fn token_error(py: Python<'_>, error: TokenError) -> PyErr {
    let mut mapped = MappedError::binding("token", error.to_string());
    mapped.token_kind = Some(error.kind());
    match error {
        TokenError::Transport { kind } => mapped.transport_kind = Some(kind.kind()),
        TokenError::Refused { code } => mapped.code = Some(code.as_str().to_owned()),
        TokenError::Protocol { status } => mapped.status = Some(status),
        _ => {}
    }
    to_py_err(py, mapped)
}

fn sdk_error(py: Python<'_>, error: RustClientError) -> PyErr {
    let mut mapped = MappedError::binding(
        match &error {
            RustClientError::Configuration { .. } => "configuration",
            RustClientError::InvalidRequest { .. } => "invalid_request",
            RustClientError::Token(_) => "token",
            RustClientError::Transport { .. } => "transport",
            // app-developer-22: a missing resource is its own kind, not_found,
            // rather than the generic problem kind every other refusal shares.
            RustClientError::Problem {
                code: BRegProblemCode::ResourceNotFound,
                ..
            } => "not_found",
            RustClientError::Problem { .. } => "problem",
            RustClientError::Protocol { .. } => "protocol",
            _ => "client",
        },
        error.to_string(),
    );
    match error {
        RustClientError::Token(error) => return token_error(py, error),
        RustClientError::Transport { kind } => mapped.transport_kind = Some(kind.kind()),
        RustClientError::Problem {
            status,
            code,
            trace_id,
            refusal_code,
        } => {
            mapped.status = Some(status);
            mapped.code = Some(code.code().to_owned());
            mapped.trace_id = Some(trace_id.as_str().to_owned());
            if let BRegProblemCode::RequestPlanRefused(value) = code {
                mapped.plan_refusal = Some(value.kind().to_owned());
            }
            // The refusal catalogue belongs to the package, so the declared code
            // travels as the bounded string the Problem schema admits.
            mapped.refusal_code = refusal_code.map(|value| value.as_str().to_owned());
        }
        RustClientError::Protocol {
            status,
            failure,
            trace_id,
        } => {
            mapped.status = Some(status);
            mapped.code = Some(
                match failure {
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
                .to_owned(),
            );
            mapped.trace_id = trace_id.map(|value| value.as_str().to_owned());
        }
        _ => {}
    }
    to_py_err(py, mapped)
}

fn invalid(py: Python<'_>, message: impl Into<String>) -> PyErr {
    to_py_err(py, MappedError::binding("invalid_request", message))
}

fn record_format(py: Python<'_>, value: &str) -> PyResult<BRegRecordFormat> {
    match value {
        "json" => Ok(BRegRecordFormat::Json),
        "json-ld" => Ok(BRegRecordFormat::JsonLd),
        _ => Err(invalid(py, "format must be json or json-ld")),
    }
}

fn record_options(
    py: Python<'_>,
    select: Option<Vec<String>>,
    access_profile: Option<String>,
    format: &str,
) -> PyResult<BRegRecordOptions> {
    let mut options = BRegRecordOptions::default().format(record_format(py, format)?);
    if let Some(select) = select {
        options = options
            .select(select)
            .map_err(|error| invalid(py, error.to_string()))?;
    }
    if let Some(access_profile) = access_profile {
        options = options
            .access_profile(access_profile)
            .map_err(|error| invalid(py, error.to_string()))?;
    }
    Ok(options)
}

#[allow(clippy::too_many_arguments)]
fn list_request(
    py: Python<'_>,
    top: Option<u32>,
    select: Option<Vec<String>>,
    access_profile: Option<String>,
    format: &str,
    filter: Option<String>,
    orderby: Option<String>,
    count: Option<bool>,
    bbox: Option<(String, String, String, String)>,
) -> PyResult<BRegListRequest> {
    let mut request =
        BRegListRequest::default().options(record_options(py, select, access_profile, format)?);
    if let Some(value) = top {
        request = request
            .top(value)
            .map_err(|error| invalid(py, error.to_string()))?;
    }
    if let Some(value) = filter {
        request = request
            .filter(value)
            .map_err(|error| invalid(py, error.to_string()))?;
    }
    if let Some(value) = orderby {
        request = request
            .orderby(value)
            .map_err(|error| invalid(py, error.to_string()))?;
    }
    if let Some(value) = count {
        request = request.count(value);
    }
    if let Some((west, south, east, north)) = bbox {
        request = request.bbox(
            BRegBoundingBox::new(west, south, east, north)
                .map_err(|error| invalid(py, error.to_string()))?,
        );
    }
    Ok(request)
}

struct ScalarListArguments {
    top: Option<u32>,
    select: Option<Vec<String>>,
    access_profile: Option<String>,
    format: String,
    filter: Option<String>,
    orderby: Option<String>,
    count: Option<bool>,
}

macro_rules! configure_scalar_list {
    ($py:expr, $request:expr, $arguments:expr) => {{
        let arguments = $arguments;
        let mut request = $request.options(record_options(
            $py,
            arguments.select,
            arguments.access_profile,
            &arguments.format,
        )?);
        if let Some(value) = arguments.top {
            request = request
                .top(value)
                .map_err(|error| invalid($py, error.to_string()))?;
        }
        if let Some(value) = arguments.filter {
            request = request
                .filter(value)
                .map_err(|error| invalid($py, error.to_string()))?;
        }
        if let Some(value) = arguments.orderby {
            request = request
                .orderby(value)
                .map_err(|error| invalid($py, error.to_string()))?;
        }
        if let Some(value) = arguments.count {
            request = request.count(value);
        }
        request
    }};
}

fn geojson_list_request(
    py: Python<'_>,
    arguments: ScalarListArguments,
    bbox: Option<(String, String, String, String)>,
) -> PyResult<BRegGeoJsonListRequest> {
    let mut options = BRegGeoJsonOptions::default();
    if let Some(select) = arguments.select.clone() {
        options = options
            .select(select)
            .map_err(|error| invalid(py, error.to_string()))?;
    }
    if let Some(access_profile) = arguments.access_profile.clone() {
        options = options
            .access_profile(access_profile)
            .map_err(|error| invalid(py, error.to_string()))?;
    }
    let mut request = BRegGeoJsonListRequest::default().options(options);
    if let Some(value) = arguments.top {
        request = request
            .top(value)
            .map_err(|error| invalid(py, error.to_string()))?;
    }
    if let Some(value) = arguments.filter {
        request = request
            .filter(value)
            .map_err(|error| invalid(py, error.to_string()))?;
    }
    if let Some(value) = arguments.orderby {
        request = request
            .orderby(value)
            .map_err(|error| invalid(py, error.to_string()))?;
    }
    if let Some(value) = arguments.count {
        request = request.count(value);
    }
    if let Some((west, south, east, north)) = bbox {
        request = request.bbox(
            BRegBoundingBox::new(west, south, east, north)
                .map_err(|error| invalid(py, error.to_string()))?,
        );
    }
    Ok(request)
}

fn projected_page_value<'py, T: Serialize, C: Serialize>(
    py: Python<'py>,
    value: &T,
    continuation: Option<&C>,
    metadata: &breg_client_sdk::BRegResponseMetadata,
) -> PyResult<Bound<'py, PyAny>> {
    let result = PyDict::new(py);
    result.set_item("kind", "complete")?;
    result.set_item("value", serialize_to_python(py, value)?)?;
    result.set_item("trace_id", metadata.trace_id().as_str())?;
    result.set_item("etag", metadata.etag().map(BRegEtag::as_str))?;
    result.set_item(
        "continuation",
        match continuation {
            Some(value) => serialize_to_python(py, value)?,
            None => py.None().into_bound(py),
        },
    )?;
    Ok(result.into_any())
}

fn projection_from_python<T: DeserializeOwned>(
    py: Python<'_>,
    value: &Bound<'_, PyAny>,
    what: &str,
) -> PyResult<T> {
    let value =
        python_to_json(value).map_err(|error| conversion_error(py, "invalid_request", error))?;
    serde_json::from_value(value).map_err(|_| invalid(py, format!("{what} is invalid")))
}

fn complete_value<'py, T: Serialize>(
    py: Python<'py>,
    value: &T,
    metadata: &breg_client_sdk::BRegResponseMetadata,
) -> PyResult<Bound<'py, PyAny>> {
    let result = PyDict::new(py);
    result.set_item("kind", "complete")?;
    result.set_item("value", serialize_to_python(py, value)?)?;
    result.set_item("trace_id", metadata.trace_id().as_str())?;
    result.set_item("etag", metadata.etag().map(BRegEtag::as_str))?;
    result.set_item("location", metadata.location())?;
    Ok(result.into_any())
}

fn raw_value<'py>(
    py: Python<'py>,
    value: &BRegRawDocument,
    metadata: &breg_client_sdk::BRegResponseMetadata,
) -> PyResult<Bound<'py, PyAny>> {
    let result = PyDict::new(py);
    result.set_item("kind", "complete")?;
    result.set_item("body", PyBytes::new(py, value.as_bytes()))?;
    result.set_item("media_type", value.media_type())?;
    result.set_item("trace_id", metadata.trace_id().as_str())?;
    result.set_item("etag", metadata.etag().map(BRegEtag::as_str))?;
    Ok(result.into_any())
}

fn page_value<'py, T: Serialize>(
    py: Python<'py>,
    value: BRegComplete<BRegPage<T>>,
) -> PyResult<Bound<'py, PyAny>> {
    let result = PyDict::new(py);
    result.set_item("kind", "complete")?;
    result.set_item("value", serialize_to_python(py, &value.value.value)?)?;
    result.set_item("trace_id", value.metadata.trace_id().as_str())?;
    result.set_item("etag", value.metadata.etag().map(BRegEtag::as_str))?;
    result.set_item(
        "continuation",
        match value.value.continuation {
            Some(value) => serialize_to_python(py, &value.projection())?,
            None => py.None().into_bound(py),
        },
    )?;
    Ok(result.into_any())
}

fn patch_request(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<BRegPatchRequest> {
    let value =
        python_to_json(value).map_err(|error| conversion_error(py, "invalid_request", error))?;
    patch_request_from_value(py, value)
}

fn patch_request_from_value(py: Python<'_>, value: Value) -> PyResult<BRegPatchRequest> {
    let operations = value
        .as_array()
        .ok_or_else(|| invalid(py, "patch must be a sequence"))?;
    let mut builder = BRegPatchRequest::builder();
    for operation in operations {
        let object = operation
            .as_object()
            .ok_or_else(|| invalid(py, "every patch operation must be a mapping"))?;
        let op = object
            .get("op")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(py, "patch op must be a string"))?;
        let field = object
            .get("field")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(py, "patch field must be a string"))?;
        let allowed = if op == "remove" {
            &["op", "field"][..]
        } else {
            &["op", "field", "value"][..]
        };
        if object.keys().any(|key| !allowed.contains(&key.as_str())) {
            return Err(invalid(py, "patch operation contains an unsupported field"));
        }
        let result = match op {
            "add" => builder.add(
                field,
                object
                    .get("value")
                    .cloned()
                    .ok_or_else(|| invalid(py, "add requires value"))?,
            ),
            "replace" => builder.replace(
                field,
                object
                    .get("value")
                    .cloned()
                    .ok_or_else(|| invalid(py, "replace requires value"))?,
            ),
            "remove" => builder.remove(field),
            "test" => builder.test(
                field,
                object
                    .get("value")
                    .cloned()
                    .ok_or_else(|| invalid(py, "test requires value"))?,
            ),
            _ => return Err(invalid(py, "patch op is unsupported")),
        };
        builder = result.map_err(|error| invalid(py, error.to_string()))?;
    }
    builder
        .build()
        .map_err(|error| invalid(py, error.to_string()))
}

fn json_object(
    py: Python<'_>,
    value: &Bound<'_, PyAny>,
    what: &str,
) -> PyResult<serde_json::Map<String, Value>> {
    let value =
        python_to_json(value).map_err(|error| conversion_error(py, "invalid_request", error))?;
    let Value::Object(value) = value else {
        return Err(invalid(py, format!("{what} must be a mapping")));
    };
    Ok(value)
}

fn change_context_from_value(py: Python<'_>, value: Value) -> PyResult<BRegChangeContext> {
    let Value::Object(mut value) = value else {
        return Err(invalid(py, "change_context must be a mapping"));
    };
    if value.keys().any(|key| {
        !matches!(
            key.as_str(),
            "kind" | "reason_code" | "reason_text" | "source_references"
        )
    }) {
        return Err(invalid(py, "change_context contains an unsupported field"));
    }
    let kind = value
        .remove("kind")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| invalid(py, "change_context kind must be a string"))?;
    let reason_code = value.remove("reason_code");
    let mut context = match (kind.as_str(), reason_code) {
        ("change", None) => BRegChangeContext::change(),
        ("correction", Some(Value::String(reason))) => {
            BRegChangeContext::correction(reason).map_err(|error| invalid(py, error.to_string()))?
        }
        ("change", Some(_)) => {
            return Err(invalid(py, "an ordinary change must not have reason_code"));
        }
        ("correction", _) => {
            return Err(invalid(py, "a correction requires reason_code"));
        }
        _ => return Err(invalid(py, "change_context kind is unsupported")),
    };
    if let Some(reason_text) = value.remove("reason_text") {
        let Value::String(reason_text) = reason_text else {
            return Err(invalid(py, "change_context reason_text must be a string"));
        };
        context = context
            .reason_text(reason_text)
            .map_err(|error| invalid(py, error.to_string()))?;
    }
    if let Some(source_references) = value.remove("source_references") {
        let Value::Array(source_references) = source_references else {
            return Err(invalid(
                py,
                "change_context source_references must be a sequence",
            ));
        };
        for source_reference in source_references {
            let Value::String(source_reference) = source_reference else {
                return Err(invalid(
                    py,
                    "every change_context source reference must be a string",
                ));
            };
            context = context
                .source_reference(source_reference)
                .map_err(|error| invalid(py, error.to_string()))?;
        }
    }
    Ok(context)
}

fn batch_request(
    py: Python<'_>,
    binding: &BRegBatchBinding,
    items: &Bound<'_, PyAny>,
    change_context: Option<&Bound<'_, PyAny>>,
) -> PyResult<breg_client_sdk::BRegBatchRequest> {
    let items =
        python_to_json(items).map_err(|error| conversion_error(py, "invalid_request", error))?;
    let Value::Array(items) = items else {
        return Err(invalid(py, "items must be a sequence"));
    };
    let mut builder = BRegBatchBuilder::new(binding);
    for item in items {
        let Value::Object(mut item) = item else {
            return Err(invalid(py, "every batch item must be a mapping"));
        };
        let operation = item
            .remove("operation")
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or_else(|| invalid(py, "every batch item operation must be a string"))?;
        match operation.as_str() {
            "create" => {
                if item.keys().any(|key| key != "data") {
                    return Err(invalid(
                        py,
                        "create batch item contains an unsupported field",
                    ));
                }
                let data = item
                    .remove("data")
                    .and_then(|value| value.as_object().cloned())
                    .ok_or_else(|| invalid(py, "create batch item data must be a mapping"))?;
                let request =
                    BRegCreateRequest::new(data).map_err(|error| invalid(py, error.to_string()))?;
                builder = builder
                    .create(&request)
                    .map_err(|error| invalid(py, error.to_string()))?;
            }
            "patch" => {
                if item
                    .keys()
                    .any(|key| !matches!(key.as_str(), "record_identifier" | "etag" | "operations"))
                {
                    return Err(invalid(
                        py,
                        "patch batch item contains an unsupported field",
                    ));
                }
                let record_identifier = item
                    .remove("record_identifier")
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .and_then(|value| uuid::Uuid::parse_str(&value).ok())
                    .ok_or_else(|| invalid(py, "batch record_identifier must be a UUID"))?;
                let etag = item
                    .remove("etag")
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .ok_or_else(|| invalid(py, "batch etag must be a string"))?;
                let etag = BRegEtag::parse(&etag).map_err(|_| {
                    invalid(
                        py,
                        "batch etag must be a strong Base Registry Engine entity tag",
                    )
                })?;
                let operations = item
                    .remove("operations")
                    .ok_or_else(|| invalid(py, "patch batch item requires operations"))?;
                let request = patch_request_from_value(py, operations)?;
                builder = builder
                    .patch(record_identifier, &etag, &request)
                    .map_err(|error| invalid(py, error.to_string()))?;
            }
            _ => return Err(invalid(py, "batch item operation is unsupported")),
        }
    }
    if let Some(change_context) = change_context {
        let change_context = python_to_json(change_context)
            .map_err(|error| conversion_error(py, "invalid_request", error))?;
        builder = builder.change_context(change_context_from_value(py, change_context)?);
    }
    builder
        .build()
        .map_err(|error| invalid(py, error.to_string()))
}

fn record_value(
    py: Python<'_>,
    value: &Bound<'_, PyAny>,
    format: BRegRecordFormat,
) -> PyResult<breg_client_sdk::RegistryRecordSingleResponse> {
    let value =
        python_to_json(value).map_err(|error| conversion_error(py, "invalid_request", error))?;
    let representation = match format {
        BRegRecordFormat::Json => RegistryRecordRepresentation::Json,
        BRegRecordFormat::JsonLd => RegistryRecordRepresentation::JsonLdSharedContext,
    };
    match RegistryRecordResponse::from_value(value, representation) {
        Ok(RegistryRecordResponse::Single(value)) => Ok(value),
        _ => Err(invalid(py, "record must be one Registry Record response")),
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
        "review_mode": match value.review_mode() { BRegRequestReviewMode::None => "none", BRegRequestReviewMode::Staged => "staged" },
        "application_disposition": match value.application_disposition() { BRegRequestApplicationDisposition::Apply => "apply", BRegRequestApplicationDisposition::Queue => "queue" },
        "queue_reason": value.queue_reason().map(|reason| json!({"code": reason.code(), "label": reason.label()})),
    })
}

fn receipt_value(value: &BRegLifecycleActionReceipt) -> Value {
    let request = value.request();
    json!({
        "id": value.record_identifier(),
        "revision": value.revision(),
        "snapshot": value.snapshot(),
        "request": {
            "breg_state": state_name(request.breg_state()),
            "proposal_version": request.proposal_version().map(|value| value.get()),
            "effect_digest": request.effect_digest().map(|value| value.as_str()),
            "proposal": request.proposal().map(proposal_value),
            "application": request.application().map(|value| json!({
                "id": value.application_identifier(),
                "proposal_version": value.proposal_version().get(),
                "effect_digest": value.effect_digest().as_str(),
                "applied_at": value.applied_at(),
            })),
        },
    })
}

fn review_value(value: &BRegRequestReview) -> Value {
    json!({"targets": value.targets().iter().map(|target| json!({
        "entity_identifier": target.entity_identifier(),
        "record_identifier": target.record_identifier(),
        "operation": match target.operation() {
            breg_client_sdk::BRegReviewOperation::Create => "create",
            breg_client_sdk::BRegReviewOperation::Patch => "patch",
        },
        "base_revision": target.base_revision(),
        "before": target.before(),
        "after": target.after(),
    })).collect::<Vec<_>>()})
}

fn attachment_state_value(value: &BRegAttachmentState) -> Value {
    json!({
        "slot_identifier": value.slot_identifier(),
        "proposal_version": value.proposal_version(),
        "erased": value.erased(),
        "byte_size": value.byte_size(),
        "sha256": value.sha256(),
        "content_type": value.content_type(),
        "uploaded_at": value.uploaded_at(),
        "uploaded_by": value.uploaded_by(),
        "verification_status": value
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

fn metadata_field_value(value: &breg_client_sdk::BRegMetadataField) -> Value {
    let reference = value.reference().map(|reference| {
        json!({
            "manual_entry": reference.manual_entry(),
            "target_entity": reference.target_entity(),
            "operations": reference.operations().iter().map(|operation| json!({
                "operation_id": operation.operation_identifier(),
                "access_profile": operation.access_profile(),
                "label_fields": operation.label_fields(),
            })).collect::<Vec<_>>(),
        })
    });
    json!({
        "id": value.identifier(),
        "api_name": value.api_name(),
        "label": value.label(),
        "schema": value.schema(),
        "required": value.required(),
        "nullable": value.nullable(),
        "read_only": value.read_only(),
        "removable": value.removable(),
        "reference_target_entity": value.reference_target_entity(),
        "reference": reference,
        "code_labels": value.code_labels(),
        "storage_validation": value.storage_validation().map(|validation| json!({
            "kind": validation.kind(),
            "pattern": validation.pattern(),
        })),
    })
}

fn lookup_selector_value(value: &breg_client_sdk::BRegLookupSelectorDescriptor) -> Value {
    json!({
        "id": value.identifier(),
        "label": value.label(),
        "value_origin": value.value_origin(),
        "fields": value.fields().iter().map(|field| json!({
            "id": field.identifier(),
            "api_name": field.api_name(),
            "label": field.label(),
            "schema": field.schema(),
            "required": field.required(),
        })).collect::<Vec<_>>(),
        "request_fields": value.request_fields(),
    })
}

fn metadata_operation_value(value: &breg_client_sdk::BRegMetadataOperation) -> Value {
    let request = value.request();
    json!({
        "id": value.identifier(),
        "method": value.method(),
        "path": value.path(),
        "kind": value.kind().as_str(),
        "source_entity": value.source_entity(),
        "response_entity": value.response_entity(),
        "access_profile": value.access_profile(),
        "entity_label": value.entity_label(),
        "title_fields": value.title_fields(),
        "required_capabilities": value.required_capabilities(),
        "readable_fields": value.readable_fields(),
        "create_writable_fields": value.create_writable_fields(),
        "patch_writable_fields": value.patch_writable_fields(),
        "query": value.query(),
        "selectors": value.selectors().iter().map(lookup_selector_value).collect::<Vec<_>>(),
        "read_path": value.read_path().map(|path| json!({
            "id": path.identifier(),
            "label": path.label(),
        })),
        "fields": value.fields().iter().map(metadata_field_value).collect::<Vec<_>>(),
        "request": {
            "field_names": request.field_names(),
            "query_parameters": request.query_parameters(),
            "body": request.body(),
            "content_type": request.content_type(),
            "schema": request.schema(),
            "idempotency_key_required": request.idempotency_key_required(),
            "if_match_required": request.if_match_required(),
            "mutation_semantics": request.mutation_semantics(),
            "patch_path_prefix": request.patch_path_prefix(),
            "patch_operations": request.patch_operations(),
            "remove_semantics": request.remove_semantics(),
            "maximum_items": request.maximum_items(),
            "maximum_body_bytes": request.maximum_body_bytes(),
            "allow_create": request.allow_create(),
            "allow_patch": request.allow_patch(),
        },
    })
}

fn immediate_action_value(value: &breg_client_sdk::BRegImmediateActionDescriptor) -> Value {
    let bounds = value.bounds();
    json!({
        "id": value.identifier(),
        "contract_fingerprint": value.contract_fingerprint(),
        "input_mode": value.input_mode(),
        "maximum_input_string_bytes": value.maximum_input_string_bytes(),
        "inputs": value.inputs().iter().map(|input| json!({
            "id": input.identifier(),
            "api_name": input.api_name(),
            "field_type": input.field_type(),
            "required": input.required(),
            "nullable": input.nullable(),
            "classification": input.classification(),
        })).collect::<Vec<_>>(),
        "reference_inputs": value.reference_inputs().iter().map(|input| json!({
            "input": input.input_identifier(),
            "api_name": input.api_name(),
            "target_entity": input.target_entity(),
        })).collect::<Vec<_>>(),
        "required_condition_keys": value.required_condition_keys(),
        "result_effects": value.result_effects().iter().map(|effect| json!({
            "effect": effect.effect_identifier(),
            "entity": effect.entity_identifier(),
            "operation": effect.operation().as_str(),
        })).collect::<Vec<_>>(),
        "access_profile": value.access_profile(),
        "invoke_path": value.invoke_path(),
        "target_conditions_path": value.target_conditions_path(),
        "bounds": {
            "maximum_targets": bounds.maximum_targets(),
            "maximum_field_mutations": bounds.maximum_field_mutations(),
            "maximum_snapshot_bytes": bounds.maximum_snapshot_bytes(),
        },
    })
}

fn change_request_capability_value(value: &breg_client_sdk::BRegChangeRequestCapability) -> Value {
    use breg_client_sdk::{
        BRegChangeRequestApplicationMode as ApplicationMode,
        BRegChangeRequestDisposition as Disposition, BRegChangeRequestPlannerKind as PlannerKind,
        BRegChangeRequestReviewMode as ReviewMode,
    };

    let planner = value.planner();
    let limits = planner.limits().map(|limits| {
        json!({
            "maximum_targets": limits.maximum_targets(),
            "maximum_field_mutations": limits.maximum_field_mutations(),
            "maximum_snapshot_bytes": limits.maximum_snapshot_bytes(),
            "maximum_source_bytes": limits.maximum_source_bytes(),
            "maximum_operations": limits.maximum_operations(),
            "maximum_call_depth": limits.maximum_call_depth(),
            "maximum_expression_depth": limits.maximum_expression_depth(),
            "maximum_string_bytes": limits.maximum_string_bytes(),
            "maximum_array_items": limits.maximum_array_items(),
            "maximum_map_entries": limits.maximum_map_entries(),
            "maximum_modules": limits.maximum_modules(),
        })
    });
    let application = value.application();
    json!({
        "planner": {
            "kind": match planner.kind() {
                PlannerKind::Declarative => "declarative",
                PlannerKind::Rhai => "rhai",
            },
            "abi": planner.abi(),
            "limits": limits,
            "possible_write_count": planner.possible_write_count(),
            "possible_write_operations": planner
                .possible_write_operations()
                .iter()
                .map(|value| value.as_str())
                .collect::<Vec<_>>(),
        },
        "review_mode": match value.review_mode() {
            ReviewMode::None => "none",
            ReviewMode::Staged => "staged",
        },
        "application": {
            "mode": match application.mode() {
                ApplicationMode::Manual => "manual",
                ApplicationMode::Automatic => "automatic",
                ApplicationMode::Planner => "planner",
            },
            "allowed_dispositions": application.allowed_dispositions().iter().map(|value| match value {
                Disposition::Apply => "apply",
                Disposition::Queue => "queue",
            }).collect::<Vec<_>>(),
            "queue_reasons": application.queue_reasons().iter().map(|value| json!({
                "code": value.code(),
                "label": value.label(),
            })).collect::<Vec<_>>(),
        },
    })
}

fn attachment_error(py: Python<'_>, error: breg_client_sdk::BRegAttachmentError) -> PyErr {
    to_py_err(py, MappedError::binding("invalid_request", error.reason()))
}

#[pyclass(name = "BRegAttachmentSlot", module = "registry_breg_client", frozen)]
struct AttachmentSlot {
    inner: CoreAttachmentSlot,
}

#[pyclass(name = "BRegAttachmentUpload", module = "registry_breg_client", frozen)]
struct AttachmentUpload {
    inner: CoreAttachmentUpload,
}

#[pymethods]
impl AttachmentSlot {
    #[getter]
    fn slot_identifier(&self) -> String {
        self.inner.slot_identifier().to_owned()
    }
    #[getter]
    fn entity_identifier(&self) -> String {
        self.inner.entity_identifier().to_owned()
    }
    #[getter]
    fn access_profile(&self) -> String {
        self.inner.access_profile().to_owned()
    }
    #[getter]
    fn required_for_submit(&self) -> bool {
        self.inner.required_for_submit()
    }
    /// Largest body the served slot policy accepts, in bytes.
    #[getter]
    fn maximum_bytes(&self) -> u64 {
        self.inner.maximum_bytes()
    }
    #[getter]
    fn content_types(&self) -> Vec<String> {
        self.inner.content_types().to_vec()
    }
    /// Authored sensitivity of this slot's content.
    #[getter]
    fn classification(&self) -> &'static str {
        self.inner.classification().as_str()
    }
    #[getter]
    fn can_download(&self) -> bool {
        self.inner.can_download()
    }
    #[getter]
    fn can_upload(&self) -> bool {
        self.inner.can_upload()
    }
    #[getter]
    fn can_remove(&self) -> bool {
        self.inner.can_remove()
    }

    fn accepts_content_type(&self, content_type: &str) -> bool {
        self.inner.accepts_content_type(content_type)
    }

    /// Bind exact bytes to this slot. Refusals happen here, before any request.
    fn prepare_upload(
        &self,
        py: Python<'_>,
        content_type: &str,
        body: Vec<u8>,
    ) -> PyResult<AttachmentUpload> {
        CoreAttachmentUpload::new(&self.inner, content_type, body)
            .map(|inner| AttachmentUpload { inner })
            .map_err(|error| attachment_error(py, error))
    }

    /// Read this slot's engine-owned state out of one Registry Record mapping.
    #[pyo3(signature = (record, *, format="json"))]
    fn value_in<'py>(
        &self,
        py: Python<'py>,
        record: &Bound<'_, PyAny>,
        format: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let record = record_value(py, record, record_format(py, format)?)?;
        let value = self
            .inner
            .value_in(&record.data)
            .map_err(|error| attachment_error(py, error))?;
        json_to_python(py, &attachment_slot_value(&value))
    }
}

#[pymethods]
impl AttachmentUpload {
    #[getter]
    fn content_type(&self) -> String {
        self.inner.content_type().to_owned()
    }
    #[getter]
    fn byte_size(&self) -> usize {
        self.inner.byte_size()
    }
}

#[pyclass(name = "BRegCreateBinding", module = "registry_breg_client", frozen)]
struct CreateBinding {
    inner: BRegCreateBinding,
}

#[pyclass(name = "BRegPatchBinding", module = "registry_breg_client", frozen)]
struct PatchBinding {
    inner: BRegPatchBinding,
}

#[pyclass(
    name = "BRegImmediateActionBinding",
    module = "registry_breg_client",
    frozen
)]
struct ImmediateActionBinding {
    inner: BRegImmediateActionBinding,
}

#[pyclass(name = "BRegTombstoneBinding", module = "registry_breg_client", frozen)]
struct TombstoneBinding {
    inner: BRegTombstoneBinding,
}

#[pyclass(name = "BRegBatchBinding", module = "registry_breg_client", frozen)]
struct BatchBinding {
    inner: BRegBatchBinding,
}

#[pyclass(
    name = "BRegActionTargetConditions",
    module = "registry_breg_client",
    frozen
)]
struct ActionTargetConditions {
    inner: BRegActionTargetConditions,
    trace_id: String,
}

#[pymethods]
impl ActionTargetConditions {
    #[getter]
    fn document<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        serialize_to_python(py, &self.inner)
    }

    #[getter]
    fn trace_id(&self) -> String {
        self.trace_id.clone()
    }

    fn __repr__(&self) -> &'static str {
        "BRegActionTargetConditions(<redacted>)"
    }
}

#[pyclass(
    name = "BRegLifecycleAuthority",
    module = "registry_breg_client",
    frozen
)]
struct LifecycleAuthority {
    inner: BRegLifecycleAuthority,
}

#[pyclass(name = "BRegLifecycleAction", module = "registry_breg_client", frozen)]
struct LifecycleAction {
    inner: CoreLifecycleAction,
}

#[pyclass(name = "BRegPreparedCreate", module = "registry_breg_client", frozen)]
struct PreparedCreate {
    inner: CorePreparedCreate,
}

#[pyclass(
    name = "BRegPreparedLifecycle",
    module = "registry_breg_client",
    frozen
)]
struct PreparedLifecycle {
    inner: CorePreparedLifecycle,
}

#[pyclass(name = "BRegRecoveredCreate", module = "registry_breg_client", frozen)]
struct RecoveredCreate {
    request: Arc<BRegCreateRequest>,
    key: BRegIdempotencyKey,
    format: BRegRecordFormat,
}

#[pyclass(
    name = "BRegRecoveredLifecycle",
    module = "registry_breg_client",
    frozen
)]
struct RecoveredLifecycle {
    action: CoreLifecycleAction,
    key: BRegIdempotencyKey,
}

#[pymethods]
impl PreparedCreate {
    #[staticmethod]
    fn from_bytes(py: Python<'_>, bytes: Vec<u8>) -> PyResult<Self> {
        CorePreparedCreate::from_slice(&bytes)
            .map(|inner| Self { inner })
            .map_err(|error| sdk_error(py, error))
    }

    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.as_bytes())
    }

    fn __repr__(&self) -> &'static str {
        "BRegPreparedCreate(<redacted>)"
    }
}

#[pymethods]
impl PreparedLifecycle {
    #[staticmethod]
    fn from_bytes(py: Python<'_>, bytes: Vec<u8>) -> PyResult<Self> {
        CorePreparedLifecycle::from_slice(&bytes)
            .map(|inner| Self { inner })
            .map_err(|error| sdk_error(py, error))
    }

    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.as_bytes())
    }

    fn __repr__(&self) -> &'static str {
        "BRegPreparedLifecycle(<redacted>)"
    }
}

#[pymethods]
impl RecoveredCreate {
    fn __repr__(&self) -> &'static str {
        "BRegRecoveredCreate(<redacted>)"
    }
}

#[pymethods]
impl RecoveredLifecycle {
    fn __repr__(&self) -> &'static str {
        "BRegRecoveredLifecycle(<redacted>)"
    }
}

#[pymethods]
impl LifecycleAction {
    fn with_reason(&self, py: Python<'_>, reason: String) -> PyResult<Self> {
        self.inner
            .with_reason(reason)
            .map(|inner| Self { inner })
            .map_err(|error| {
                to_py_err(
                    py,
                    MappedError::binding("invalid_request", error.to_string()),
                )
            })
    }

    #[getter]
    fn operation(&self) -> String {
        self.inner.operation().identifier().to_owned()
    }
    #[getter]
    fn stage(&self) -> Option<String> {
        self.inner.stage().map(str::to_owned)
    }
    #[getter]
    fn href(&self) -> String {
        self.inner.href().to_owned()
    }
    #[getter]
    fn body<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        json_to_python(py, &self.inner.body().to_value())
    }
    #[getter]
    fn review<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        self.inner
            .review()
            .map(|value| json_to_python(py, &review_value(value)))
            .transpose()
    }
}

#[pyclass(name = "BRegMetadata", module = "registry_breg_client", frozen)]
struct Metadata {
    inner: CoreMetadata,
    trace_id: String,
    etag: Option<String>,
}

#[pymethods]
impl Metadata {
    #[getter]
    fn operations<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        json_to_python(
            py,
            &Value::Array(
                self.inner
                    .operations()
                    .iter()
                    .map(metadata_operation_value)
                    .collect(),
            ),
        )
    }

    #[getter]
    fn actions<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        self.inner
            .actions()
            .map(|value| json_to_python(py, value))
            .transpose()
    }

    #[getter]
    fn immediate_actions<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        json_to_python(
            py,
            &Value::Array(
                self.inner
                    .immediate_actions()
                    .iter()
                    .map(immediate_action_value)
                    .collect(),
            ),
        )
    }

    fn change_request_capability<'py>(
        &self,
        py: Python<'py>,
        entity_identifier: &str,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
        self.inner
            .change_request_capability(entity_identifier)
            .map(|value| json_to_python(py, &change_request_capability_value(value)))
            .transpose()
    }

    #[getter]
    fn registry_identifier(&self) -> String {
        self.inner.registry_identifier().to_owned()
    }
    #[getter]
    fn registry_version(&self) -> String {
        self.inner.registry_version().to_owned()
    }
    #[getter]
    fn registry_revision(&self) -> String {
        self.inner.registry_revision().to_owned()
    }
    #[getter]
    fn trace_id(&self) -> String {
        self.trace_id.clone()
    }
    #[getter]
    fn etag(&self) -> Option<String> {
        self.etag.clone()
    }

    fn select_create(
        &self,
        py: Python<'_>,
        operation_identifier: &str,
        expected_profile: &str,
    ) -> PyResult<CreateBinding> {
        match self
            .inner
            .select_direct_write(operation_identifier, expected_profile)
            .map_err(|error| selection_error(py, error))?
        {
            BRegDirectWrite::Create(inner) => Ok(CreateBinding { inner }),
            BRegDirectWrite::Patch(_) => Err(invalid(py, "operation is not a create")),
        }
    }

    fn select_patch(
        &self,
        py: Python<'_>,
        operation_identifier: &str,
        expected_profile: &str,
    ) -> PyResult<PatchBinding> {
        match self
            .inner
            .select_direct_write(operation_identifier, expected_profile)
            .map_err(|error| selection_error(py, error))?
        {
            BRegDirectWrite::Patch(inner) => Ok(PatchBinding { inner }),
            BRegDirectWrite::Create(_) => Err(invalid(py, "operation is not a patch")),
        }
    }

    fn select_immediate_action(
        &self,
        py: Python<'_>,
        action_identifier: &str,
        expected_profile: &str,
    ) -> PyResult<ImmediateActionBinding> {
        self.inner
            .select_immediate_action(action_identifier, expected_profile)
            .map(|inner| ImmediateActionBinding { inner })
            .map_err(|error| selection_error(py, error))
    }

    fn select_tombstone(
        &self,
        py: Python<'_>,
        entity_identifier: &str,
        expected_profile: &str,
    ) -> PyResult<TombstoneBinding> {
        self.inner
            .select_tombstone(entity_identifier, expected_profile)
            .map(|inner| TombstoneBinding { inner })
            .map_err(|error| selection_error(py, error))
    }

    fn select_batch(
        &self,
        py: Python<'_>,
        entity_identifier: &str,
        expected_profile: &str,
    ) -> PyResult<BatchBinding> {
        self.inner
            .select_batch(entity_identifier, expected_profile)
            .map(|inner| BatchBinding { inner })
            .map_err(|error| selection_error(py, error))
    }

    fn select_lifecycle(
        &self,
        py: Python<'_>,
        entity_identifier: &str,
        expected_profile: &str,
    ) -> PyResult<LifecycleAuthority> {
        self.inner
            .select_lifecycle(entity_identifier, expected_profile)
            .map(|inner| LifecycleAuthority { inner })
            .map_err(|error| selection_error(py, error))
    }

    fn select_attachments(
        &self,
        py: Python<'_>,
        entity_identifier: &str,
        expected_profile: &str,
    ) -> PyResult<Vec<AttachmentSlot>> {
        self.inner
            .select_attachments(entity_identifier, expected_profile)
            .map(|slots| {
                slots
                    .into_iter()
                    .map(|inner| AttachmentSlot { inner })
                    .collect()
            })
            .map_err(|error| selection_error(py, error))
    }
}

/// Preconditions every attachment mutation shares, parsed before any request.
fn attachment_preconditions(
    py: Python<'_>,
    record_identifier: &str,
    etag: &str,
    idempotency_key: &str,
) -> PyResult<(uuid::Uuid, BRegEtag, breg_client_sdk::BRegIdempotencyKey)> {
    let record_identifier = uuid::Uuid::parse_str(record_identifier)
        .map_err(|_| invalid(py, "record_identifier must be a UUID"))?;
    let etag = BRegEtag::parse(etag)
        .map_err(|_| invalid(py, "etag must be a strong Base Registry Engine entity tag"))?;
    let key = breg_client_sdk::BRegIdempotencyKey::parse(idempotency_key)
        .map_err(|error| invalid(py, error.to_string()))?;
    Ok((record_identifier, etag, key))
}

fn selection_error(py: Python<'_>, error: BRegMetadataSelectionError) -> PyErr {
    let mut mapped = MappedError::binding("metadata_selection", error.to_string());
    mapped.code = Some(
        match error.kind() {
            BRegMetadataSelectionErrorKind::NotFound => "not_found",
            BRegMetadataSelectionErrorKind::UnboundSource => "unbound_source",
            BRegMetadataSelectionErrorKind::ProfileMismatch => "profile_mismatch",
            BRegMetadataSelectionErrorKind::UnsupportedOperation => "unsupported_operation",
            BRegMetadataSelectionErrorKind::RequiredCapability => "required_capability",
            BRegMetadataSelectionErrorKind::ContractMismatch => "contract_mismatch",
        }
        .to_owned(),
    );
    to_py_err(py, mapped)
}

#[pyclass(name = "BaseRegistryClient", module = "registry_breg_client")]
struct BaseRegistryClient {
    inner: RustClient,
    runtime: tokio::runtime::Runtime,
}

#[pymethods]
impl BaseRegistryClient {
    #[new]
    #[pyo3(signature = (base_url, authorization=None, request_timeout_seconds=None, connect_timeout_seconds=None, user_agent=None, max_response_bytes=None, trusted_root_certificates=None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        base_url: &str,
        authorization: Option<&Bound<'_, PyAny>>,
        request_timeout_seconds: Option<f64>,
        connect_timeout_seconds: Option<f64>,
        user_agent: Option<String>,
        max_response_bytes: Option<u64>,
        trusted_root_certificates: Option<Vec<u8>>,
    ) -> PyResult<Self> {
        let (authorization, private_roots) = authorization_from_python(authorization)
            .map_err(|error| conversion_error(py, "configuration", error))?;
        let config = config_from_parts(
            base_url,
            &authorization,
            private_roots,
            request_timeout_seconds,
            connect_timeout_seconds,
            user_agent,
            max_response_bytes,
            trusted_root_certificates,
        )
        .map_err(|error| config_error(py, error))?;
        let inner = py
            .detach(|| RustClient::new(config))
            .map_err(|error| sdk_error(py, error))?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| {
                PyRuntimeError::new_err("the client's internal runtime could not start")
            })?;
        Ok(Self { inner, runtime })
    }

    fn health<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let value = py
            .detach(|| self.runtime.block_on(self.inner.health()))
            .map_err(|error| sdk_error(py, error))?;
        complete_value(py, &value.value, &value.metadata)
    }

    fn ready<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let value = py
            .detach(|| self.runtime.block_on(self.inner.ready()))
            .map_err(|error| sdk_error(py, error))?;
        complete_value(py, &value.value, &value.metadata)
    }

    #[pyo3(signature = (access_profile=None))]
    fn openapi<'py>(
        &self,
        py: Python<'py>,
        access_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let value = py
            .detach(|| self.runtime.block_on(self.inner.openapi(access_profile)))
            .map_err(|error| sdk_error(py, error))?;
        raw_value(py, &value.value, &value.metadata)
    }

    #[pyo3(signature = (access_profile=None))]
    fn registry_metadata<'py>(
        &self,
        py: Python<'py>,
        access_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.registry_metadata(access_profile))
            })
            .map_err(|error| sdk_error(py, error))?;
        raw_value(py, &value.value, &value.metadata)
    }

    #[pyo3(signature = (access_profile=None))]
    fn registry_contract(
        &self,
        py: Python<'_>,
        access_profile: Option<&str>,
    ) -> PyResult<Metadata> {
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.registry_contract(access_profile))
            })
            .map_err(|error| sdk_error(py, error))?;
        Ok(Metadata {
            inner: value.value,
            trace_id: value.metadata.trace_id().as_str().to_owned(),
            etag: value.metadata.etag().map(|value| value.as_str().to_owned()),
        })
    }

    #[pyo3(signature = (entity_identifier, access_profile=None))]
    fn entity_schema<'py>(
        &self,
        py: Python<'py>,
        entity_identifier: &str,
        access_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.entity_schema(entity_identifier, access_profile))
            })
            .map_err(|error| sdk_error(py, error))?;
        raw_value(py, &value.value, &value.metadata)
    }

    #[pyo3(signature = (entity_route, record_identifier, *, select=None, access_profile=None, format="json", request_history_after_proposal_version=None))]
    #[allow(clippy::too_many_arguments)]
    fn get_record<'py>(
        &self,
        py: Python<'py>,
        entity_route: &str,
        record_identifier: &str,
        select: Option<Vec<String>>,
        access_profile: Option<String>,
        format: &str,
        request_history_after_proposal_version: Option<u32>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let mut options = record_options(py, select, access_profile, format)?;
        if let Some(value) = request_history_after_proposal_version {
            options = options
                .request_history_after_proposal_version(value)
                .map_err(|error| invalid(py, error.to_string()))?;
        }
        let value = py
            .detach(|| {
                self.runtime.block_on(self.inner.get_record(
                    entity_route,
                    record_identifier,
                    &options,
                ))
            })
            .map_err(|error| sdk_error(py, error))?;
        complete_value(py, &value.value, &value.metadata)
    }

    #[pyo3(signature = (entity_route, record_identifier, *, select=None, access_profile=None))]
    fn get_geojson_record<'py>(
        &self,
        py: Python<'py>,
        entity_route: &str,
        record_identifier: &str,
        select: Option<Vec<String>>,
        access_profile: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let mut options = BRegGeoJsonOptions::default();
        if let Some(select) = select {
            options = options
                .select(select)
                .map_err(|error| invalid(py, error.to_string()))?;
        }
        if let Some(access_profile) = access_profile {
            options = options
                .access_profile(access_profile)
                .map_err(|error| invalid(py, error.to_string()))?;
        }
        let value = py
            .detach(|| {
                self.runtime.block_on(self.inner.get_geojson_record(
                    entity_route,
                    record_identifier,
                    &options,
                ))
            })
            .map_err(|error| sdk_error(py, error))?;
        complete_value(py, &value.value, &value.metadata)
    }

    #[pyo3(signature = (entity_route, *, top=None, select=None, access_profile=None, filter=None, orderby=None, count=None, bbox=None))]
    #[allow(clippy::too_many_arguments)]
    fn list_geojson_records<'py>(
        &self,
        py: Python<'py>,
        entity_route: &str,
        top: Option<u32>,
        select: Option<Vec<String>>,
        access_profile: Option<String>,
        filter: Option<String>,
        orderby: Option<String>,
        count: Option<bool>,
        bbox: Option<(String, String, String, String)>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let request = geojson_list_request(
            py,
            ScalarListArguments {
                top,
                select,
                access_profile,
                format: "json".to_owned(),
                filter,
                orderby,
                count,
            },
            bbox,
        )?;
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.list_geojson_records(entity_route, &request))
            })
            .map_err(|error| sdk_error(py, error))?;
        projected_page_value(
            py,
            &value.value.value,
            value.value.continuation.as_ref(),
            &value.metadata,
        )
    }

    fn continue_geojson_list<'py>(
        &self,
        py: Python<'py>,
        continuation: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let projection: BRegGeoJsonContinuationProjection =
            projection_from_python(py, continuation, "GeoJSON continuation")?;
        let continuation = BRegGeoJsonContinuation::try_from_projection(projection)
            .map_err(|error| invalid(py, error.to_string()))?;
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.continue_geojson_list(&continuation))
            })
            .map_err(|error| sdk_error(py, error))?;
        projected_page_value(
            py,
            &value.value.value,
            value.value.continuation.as_ref(),
            &value.metadata,
        )
    }

    #[pyo3(signature = (entity_route, record_identifier, access_profile=None))]
    fn record_revisions<'py>(
        &self,
        py: Python<'py>,
        entity_route: &str,
        record_identifier: &str,
        access_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let value = py
            .detach(|| {
                self.runtime.block_on(self.inner.record_revisions(
                    entity_route,
                    record_identifier,
                    access_profile,
                ))
            })
            .map_err(|error| sdk_error(py, error))?;
        raw_value(py, &value.value, &value.metadata)
    }

    #[pyo3(signature = (entity_route, record_identifier, revision, *, select=None, access_profile=None, format="json"))]
    #[allow(clippy::too_many_arguments)]
    fn get_record_revision<'py>(
        &self,
        py: Python<'py>,
        entity_route: &str,
        record_identifier: &str,
        revision: u64,
        select: Option<Vec<String>>,
        access_profile: Option<String>,
        format: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let options = record_options(py, select, access_profile, format)?;
        let value = py
            .detach(|| {
                self.runtime.block_on(self.inner.get_record_revision(
                    entity_route,
                    record_identifier,
                    revision,
                    &options,
                ))
            })
            .map_err(|error| sdk_error(py, error))?;
        raw_value(py, &value.value, &value.metadata)
    }

    #[pyo3(signature = (entity_route, *, top=None, select=None, access_profile=None, format="json", filter=None, orderby=None, count=None, bbox=None))]
    #[allow(clippy::too_many_arguments)]
    fn list_records<'py>(
        &self,
        py: Python<'py>,
        entity_route: &str,
        top: Option<u32>,
        select: Option<Vec<String>>,
        access_profile: Option<String>,
        format: &str,
        filter: Option<String>,
        orderby: Option<String>,
        count: Option<bool>,
        bbox: Option<(String, String, String, String)>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let request = list_request(
            py,
            top,
            select,
            access_profile,
            format,
            filter,
            orderby,
            count,
            bbox,
        )?;
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.list_records(entity_route, &request))
            })
            .map_err(|error| sdk_error(py, error))?;
        page_value(py, value)
    }

    #[pyo3(signature = (entity_route, *, top=None, select=None, access_profile=None, format="json", filter=None, orderby=None, count=None))]
    #[allow(clippy::too_many_arguments)]
    fn list_current_records<'py>(
        &self,
        py: Python<'py>,
        entity_route: &str,
        top: Option<u32>,
        select: Option<Vec<String>>,
        access_profile: Option<String>,
        format: &str,
        filter: Option<String>,
        orderby: Option<String>,
        count: Option<bool>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let request = configure_scalar_list!(
            py,
            BRegCurrentListRequest::default(),
            ScalarListArguments {
                top,
                select,
                access_profile,
                format: format.to_owned(),
                filter,
                orderby,
                count,
            }
        );
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.list_current_records(entity_route, &request))
            })
            .map_err(|error| sdk_error(py, error))?;
        projected_page_value(
            py,
            &value.value.value,
            value.value.continuation.as_ref(),
            &value.metadata,
        )
    }

    fn continue_current_list<'py>(
        &self,
        py: Python<'py>,
        continuation: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let projection: BRegCurrentContinuationProjection =
            projection_from_python(py, continuation, "current-list continuation")?;
        let continuation = BRegCurrentContinuation::try_from_projection(projection)
            .map_err(|error| invalid(py, error.to_string()))?;
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.continue_current_list(&continuation))
            })
            .map_err(|error| sdk_error(py, error))?;
        projected_page_value(
            py,
            &value.value.value,
            value.value.continuation.as_ref(),
            &value.metadata,
        )
    }

    #[pyo3(signature = (entity_route, as_of, *, top=None, select=None, access_profile=None, format="json", filter=None, orderby=None, count=None))]
    #[allow(clippy::too_many_arguments)]
    fn list_records_as_of<'py>(
        &self,
        py: Python<'py>,
        entity_route: &str,
        as_of: &str,
        top: Option<u32>,
        select: Option<Vec<String>>,
        access_profile: Option<String>,
        format: &str,
        filter: Option<String>,
        orderby: Option<String>,
        count: Option<bool>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let request =
            BRegAsOfListRequest::new(as_of).map_err(|error| invalid(py, error.to_string()))?;
        let request = configure_scalar_list!(
            py,
            request,
            ScalarListArguments {
                top,
                select,
                access_profile,
                format: format.to_owned(),
                filter,
                orderby,
                count,
            }
        );
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.list_records_as_of(entity_route, &request))
            })
            .map_err(|error| sdk_error(py, error))?;
        projected_page_value(
            py,
            &value.value.value,
            value.value.continuation.as_ref(),
            &value.metadata,
        )
    }

    fn continue_as_of_list<'py>(
        &self,
        py: Python<'py>,
        continuation: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let projection: BRegAsOfContinuationProjection =
            projection_from_python(py, continuation, "as-of continuation")?;
        let continuation = BRegAsOfContinuation::try_from_projection(projection)
            .map_err(|error| invalid(py, error.to_string()))?;
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.continue_as_of_list(&continuation))
            })
            .map_err(|error| sdk_error(py, error))?;
        projected_page_value(
            py,
            &value.value.value,
            value.value.continuation.as_ref(),
            &value.metadata,
        )
    }

    #[pyo3(signature = (entity_route, *, snapshot=None, valid_at=None, top=None, select=None, access_profile=None, format="json", filter=None, orderby=None, count=None))]
    #[allow(clippy::too_many_arguments)]
    fn list_snapshot_records<'py>(
        &self,
        py: Python<'py>,
        entity_route: &str,
        snapshot: Option<String>,
        valid_at: Option<String>,
        top: Option<u32>,
        select: Option<Vec<String>>,
        access_profile: Option<String>,
        format: &str,
        filter: Option<String>,
        orderby: Option<String>,
        count: Option<bool>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let mut request = configure_scalar_list!(
            py,
            BRegSnapshotListRequest::default(),
            ScalarListArguments {
                top,
                select,
                access_profile,
                format: format.to_owned(),
                filter,
                orderby,
                count,
            }
        );
        if let Some(snapshot) = snapshot {
            request = request
                .snapshot(snapshot)
                .map_err(|error| invalid(py, error.to_string()))?;
        }
        if let Some(valid_at) = valid_at {
            request = request
                .valid_at(valid_at)
                .map_err(|error| invalid(py, error.to_string()))?;
        }
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.list_snapshot_records(entity_route, &request))
            })
            .map_err(|error| sdk_error(py, error))?;
        let result = projected_page_value(
            py,
            &value.value.value,
            value.value.continuation.as_ref(),
            &value.metadata,
        )?;
        result
            .cast::<PyDict>()?
            .set_item("snapshot", &value.value.snapshot)?;
        if let Some(valid_at) = &value.value.valid_at {
            result.cast::<PyDict>()?.set_item("valid_at", valid_at)?;
        }
        Ok(result)
    }

    fn continue_snapshot_list<'py>(
        &self,
        py: Python<'py>,
        continuation: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let projection: BRegSnapshotContinuationProjection =
            projection_from_python(py, continuation, "snapshot continuation")?;
        let continuation = BRegSnapshotContinuation::try_from_projection(projection)
            .map_err(|error| invalid(py, error.to_string()))?;
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.continue_snapshot_list(&continuation))
            })
            .map_err(|error| sdk_error(py, error))?;
        let result = projected_page_value(
            py,
            &value.value.value,
            value.value.continuation.as_ref(),
            &value.metadata,
        )?;
        result
            .cast::<PyDict>()?
            .set_item("snapshot", &value.value.snapshot)?;
        if let Some(valid_at) = &value.value.valid_at {
            result.cast::<PyDict>()?.set_item("valid_at", valid_at)?;
        }
        Ok(result)
    }

    #[pyo3(signature = (entity_route, record_identifier, path_route, *, top=None, select=None, access_profile=None, format="json", filter=None, orderby=None, count=None))]
    #[allow(clippy::too_many_arguments)]
    fn list_relationship_records<'py>(
        &self,
        py: Python<'py>,
        entity_route: &str,
        record_identifier: &str,
        path_route: &str,
        top: Option<u32>,
        select: Option<Vec<String>>,
        access_profile: Option<String>,
        format: &str,
        filter: Option<String>,
        orderby: Option<String>,
        count: Option<bool>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let request = configure_scalar_list!(
            py,
            BRegRelationshipListRequest::default(),
            ScalarListArguments {
                top,
                select,
                access_profile,
                format: format.to_owned(),
                filter,
                orderby,
                count,
            }
        );
        let value = py
            .detach(|| {
                self.runtime.block_on(self.inner.list_relationship_records(
                    entity_route,
                    record_identifier,
                    path_route,
                    &request,
                ))
            })
            .map_err(|error| sdk_error(py, error))?;
        projected_page_value(
            py,
            &value.value.value,
            value.value.continuation.as_ref(),
            &value.metadata,
        )
    }

    fn continue_relationship_list<'py>(
        &self,
        py: Python<'py>,
        continuation: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let projection: BRegRelationshipContinuationProjection =
            projection_from_python(py, continuation, "relationship continuation")?;
        let continuation = BRegRelationshipContinuation::try_from_projection(projection)
            .map_err(|error| invalid(py, error.to_string()))?;
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.continue_relationship_list(&continuation))
            })
            .map_err(|error| sdk_error(py, error))?;
        projected_page_value(
            py,
            &value.value.value,
            value.value.continuation.as_ref(),
            &value.metadata,
        )
    }

    fn continue_list<'py>(
        &self,
        py: Python<'py>,
        continuation: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let value = python_to_json(continuation)
            .map_err(|error| conversion_error(py, "invalid_request", error))?;
        let projection: BRegContinuationProjection =
            serde_json::from_value(value).map_err(|_| invalid(py, "continuation is invalid"))?;
        let continuation = BRegContinuation::try_from_projection(projection)
            .map_err(|error| invalid(py, error.to_string()))?;
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.continue_list(&continuation))
            })
            .map_err(|error| sdk_error(py, error))?;
        page_value(py, value)
    }

    #[pyo3(signature = (entity_route, selector, values=None, *, select=None, access_profile=None, format="json"))]
    #[allow(clippy::too_many_arguments)]
    fn lookup_record<'py>(
        &self,
        py: Python<'py>,
        entity_route: &str,
        selector: &str,
        values: Option<&Bound<'_, PyAny>>,
        select: Option<Vec<String>>,
        access_profile: Option<String>,
        format: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let mut request = BRegLookupRequest::new(selector)
            .map_err(|error| invalid(py, error.to_string()))?
            .options(record_options(py, select, access_profile, format)?);
        if let Some(values) = values {
            let values = python_to_json(values)
                .map_err(|error| conversion_error(py, "invalid_request", error))?;
            let Value::Object(values) = values else {
                return Err(invalid(py, "values must be a mapping"));
            };
            for (name, value) in values {
                request = request
                    .value(name, value)
                    .map_err(|error| invalid(py, error.to_string()))?;
            }
        }
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.lookup_record(entity_route, &request))
            })
            .map_err(|error| sdk_error(py, error))?;
        complete_value(py, &value.value, &value.metadata)
    }

    #[pyo3(signature = (binding, data, idempotency_key, *, format="json"))]
    fn create_record<'py>(
        &self,
        py: Python<'py>,
        binding: PyRef<'_, CreateBinding>,
        data: &Bound<'_, PyAny>,
        idempotency_key: &str,
        format: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let data =
            python_to_json(data).map_err(|error| conversion_error(py, "invalid_request", error))?;
        let Value::Object(data) = data else {
            return Err(invalid(py, "data must be a mapping"));
        };
        let request =
            BRegCreateRequest::new(data).map_err(|error| invalid(py, error.to_string()))?;
        let key = breg_client_sdk::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| invalid(py, error.to_string()))?;
        let operation = binding.inner.clone();
        let format = record_format(py, format)?;
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.create_record(&operation, &request, &key, format))
            })
            .map_err(|error| sdk_error(py, error))?;
        complete_value(py, &value.value, &value.metadata)
    }

    #[pyo3(signature = (binding, data, idempotency_key, *, format="json"))]
    fn prepare_create(
        &self,
        py: Python<'_>,
        binding: PyRef<'_, CreateBinding>,
        data: &Bound<'_, PyAny>,
        idempotency_key: &str,
        format: &str,
    ) -> PyResult<PreparedCreate> {
        let data =
            python_to_json(data).map_err(|error| conversion_error(py, "invalid_request", error))?;
        let Value::Object(data) = data else {
            return Err(invalid(py, "data must be a mapping"));
        };
        let request =
            BRegCreateRequest::new(data).map_err(|error| invalid(py, error.to_string()))?;
        let key = BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| invalid(py, error.to_string()))?;
        let format = record_format(py, format)?;
        self.inner
            .prepare_create(&binding.inner, &request, &key, format)
            .map(|inner| PreparedCreate { inner })
            .map_err(|error| sdk_error(py, error))
    }

    fn recover_create(
        &self,
        py: Python<'_>,
        binding: PyRef<'_, CreateBinding>,
        prepared: PyRef<'_, PreparedCreate>,
    ) -> PyResult<RecoveredCreate> {
        self.inner
            .recover_create(&binding.inner, &prepared.inner)
            .map(|(request, key, format)| RecoveredCreate {
                request: Arc::new(request),
                key,
                format,
            })
            .map_err(|error| sdk_error(py, error))
    }

    fn execute_recovered_create<'py>(
        &self,
        py: Python<'py>,
        binding: PyRef<'_, CreateBinding>,
        recovered: PyRef<'_, RecoveredCreate>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let binding = binding.inner.clone();
        let request = Arc::clone(&recovered.request);
        let key = recovered.key.clone();
        let format = recovered.format;
        let value = py
            .detach(|| {
                self.runtime.block_on(self.inner.create_record(
                    &binding,
                    request.as_ref(),
                    &key,
                    format,
                ))
            })
            .map_err(|error| sdk_error(py, error))?;
        complete_value(py, &value.value, &value.metadata)
    }

    #[pyo3(signature = (binding, record_identifier, etag, operations, idempotency_key, *, format="json"))]
    #[allow(clippy::too_many_arguments)]
    fn patch_record<'py>(
        &self,
        py: Python<'py>,
        binding: PyRef<'_, PatchBinding>,
        record_identifier: &str,
        etag: &str,
        operations: &Bound<'_, PyAny>,
        idempotency_key: &str,
        format: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let record_identifier = uuid::Uuid::parse_str(record_identifier)
            .map_err(|_| invalid(py, "record_identifier must be a UUID"))?;
        let etag = BRegEtag::parse(etag)
            .map_err(|_| invalid(py, "etag must be a strong Base Registry Engine entity tag"))?;
        let request = patch_request(py, operations)?;
        let key = breg_client_sdk::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| invalid(py, error.to_string()))?;
        let operation = binding.inner.clone();
        let format = record_format(py, format)?;
        let value = py
            .detach(|| {
                self.runtime.block_on(self.inner.patch_record(
                    &operation,
                    record_identifier,
                    &etag,
                    &request,
                    &key,
                    format,
                ))
            })
            .map_err(|error| sdk_error(py, error))?;
        complete_value(py, &value.value, &value.metadata)
    }

    #[pyo3(signature = (binding, inputs))]
    fn action_target_conditions(
        &self,
        py: Python<'_>,
        binding: PyRef<'_, ImmediateActionBinding>,
        inputs: &Bound<'_, PyAny>,
    ) -> PyResult<ActionTargetConditions> {
        let inputs = json_object(py, inputs, "inputs")?;
        let request = BRegActionTargetConditionsRequest::new(&binding.inner, inputs)
            .map_err(|error| invalid(py, error.to_string()))?;
        let binding = binding.inner.clone();
        let request = Arc::new(request);
        let value = py
            .detach(|| {
                self.runtime.block_on(
                    self.inner
                        .action_target_conditions(&binding, request.as_ref()),
                )
            })
            .map_err(|error| sdk_error(py, error))?;
        Ok(ActionTargetConditions {
            inner: value.value,
            trace_id: value.metadata.trace_id().as_str().to_owned(),
        })
    }

    #[pyo3(signature = (binding, inputs, idempotency_key, conditions=None))]
    fn invoke_action<'py>(
        &self,
        py: Python<'py>,
        binding: PyRef<'_, ImmediateActionBinding>,
        inputs: &Bound<'_, PyAny>,
        idempotency_key: &str,
        conditions: Option<PyRef<'_, ActionTargetConditions>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inputs = json_object(py, inputs, "inputs")?;
        let request = BRegActionInvocationRequest::new(
            &binding.inner,
            inputs,
            conditions.as_ref().map(|value| &value.inner),
        )
        .map_err(|error| invalid(py, error.to_string()))?;
        let key = BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| invalid(py, error.to_string()))?;
        let binding = binding.inner.clone();
        let request = Arc::new(request);
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.invoke_action(&binding, request.as_ref(), &key))
            })
            .map_err(|error| sdk_error(py, error))?;
        complete_value(py, &value.value, &value.metadata)
    }

    #[pyo3(signature = (binding, record_identifier, etag, idempotency_key, *, format="json"))]
    fn tombstone_record<'py>(
        &self,
        py: Python<'py>,
        binding: PyRef<'_, TombstoneBinding>,
        record_identifier: &str,
        etag: &str,
        idempotency_key: &str,
        format: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let record_identifier = uuid::Uuid::parse_str(record_identifier)
            .map_err(|_| invalid(py, "record_identifier must be a UUID"))?;
        let etag = BRegEtag::parse(etag)
            .map_err(|_| invalid(py, "etag must be a strong Base Registry Engine entity tag"))?;
        let key = BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| invalid(py, error.to_string()))?;
        let binding = binding.inner.clone();
        let format = record_format(py, format)?;
        let value = py
            .detach(|| {
                self.runtime.block_on(self.inner.tombstone_record(
                    &binding,
                    record_identifier,
                    &etag,
                    &key,
                    format,
                ))
            })
            .map_err(|error| sdk_error(py, error))?;
        complete_value(py, &value.value, &value.metadata)
    }

    #[pyo3(signature = (binding, items, idempotency_key, *, change_context=None))]
    fn batch_records<'py>(
        &self,
        py: Python<'py>,
        binding: PyRef<'_, BatchBinding>,
        items: &Bound<'_, PyAny>,
        idempotency_key: &str,
        change_context: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let request = batch_request(py, &binding.inner, items, change_context)?;
        let key = BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| invalid(py, error.to_string()))?;
        let binding = binding.inner.clone();
        let request = Arc::new(request);
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.batch_records(&binding, request.as_ref(), &key))
            })
            .map_err(|error| sdk_error(py, error))?;
        complete_value(py, &value.value, &value.metadata)
    }

    /// Replace one governed attachment slot with exact bytes. The prepared
    /// upload already satisfies the slot's served size and content-type policy.
    #[pyo3(signature = (slot, record_identifier, etag, upload, idempotency_key, *, format="json"))]
    #[allow(clippy::too_many_arguments)]
    fn upload_attachment<'py>(
        &self,
        py: Python<'py>,
        slot: PyRef<'_, AttachmentSlot>,
        record_identifier: &str,
        etag: &str,
        upload: PyRef<'_, AttachmentUpload>,
        idempotency_key: &str,
        format: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let (record_identifier, etag, key) =
            attachment_preconditions(py, record_identifier, etag, idempotency_key)?;
        let (slot, upload) = (slot.inner.clone(), upload.inner.clone());
        let format = record_format(py, format)?;
        let value = py
            .detach(|| {
                self.runtime.block_on(self.inner.upload_attachment(
                    &slot,
                    record_identifier,
                    &etag,
                    &upload,
                    &key,
                    format,
                ))
            })
            .map_err(|error| sdk_error(py, error))?;
        complete_value(py, &value.value, &value.metadata)
    }

    /// Read the exact bytes one governed slot holds for one proposal version.
    fn download_attachment<'py>(
        &self,
        py: Python<'py>,
        slot: PyRef<'_, AttachmentSlot>,
        record_identifier: &str,
        proposal_version: u32,
    ) -> PyResult<Bound<'py, PyAny>> {
        let record_identifier = uuid::Uuid::parse_str(record_identifier)
            .map_err(|_| invalid(py, "record_identifier must be a UUID"))?;
        let slot = slot.inner.clone();
        let value = py
            .detach(|| {
                self.runtime.block_on(self.inner.download_attachment(
                    &slot,
                    record_identifier,
                    proposal_version,
                ))
            })
            .map_err(|error| sdk_error(py, error))?;
        raw_value(py, &value.value, &value.metadata)
    }

    /// Empty one governed attachment slot.
    #[pyo3(signature = (slot, record_identifier, etag, idempotency_key, *, format="json"))]
    fn delete_attachment<'py>(
        &self,
        py: Python<'py>,
        slot: PyRef<'_, AttachmentSlot>,
        record_identifier: &str,
        etag: &str,
        idempotency_key: &str,
        format: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let (record_identifier, etag, key) =
            attachment_preconditions(py, record_identifier, etag, idempotency_key)?;
        let slot = slot.inner.clone();
        let format = record_format(py, format)?;
        let value = py
            .detach(|| {
                self.runtime.block_on(self.inner.delete_attachment(
                    &slot,
                    record_identifier,
                    &etag,
                    &key,
                    format,
                ))
            })
            .map_err(|error| sdk_error(py, error))?;
        complete_value(py, &value.value, &value.metadata)
    }

    #[pyo3(signature = (authority, record, *, format="json"))]
    fn lifecycle_actions(
        &self,
        py: Python<'_>,
        authority: PyRef<'_, LifecycleAuthority>,
        record: &Bound<'_, PyAny>,
        format: &str,
    ) -> PyResult<Vec<LifecycleAction>> {
        let record = record_value(py, record, record_format(py, format)?)?;
        self.inner
            .lifecycle_actions(&authority.inner, &record)
            .map(|values| {
                values
                    .into_iter()
                    .map(|inner| LifecycleAction { inner })
                    .collect()
            })
            .map_err(|error| {
                let mut mapped = MappedError::binding("lifecycle_promotion", error.to_string());
                mapped.code = Some(
                    match error {
                        BRegLifecyclePromotionError::Authority => "authority",
                        BRegLifecyclePromotionError::Binding => "binding",
                    }
                    .to_owned(),
                );
                to_py_err(py, mapped)
            })
    }

    #[pyo3(signature = (authority, record, action, idempotency_key, *, format="json"))]
    fn prepare_lifecycle_action(
        &self,
        py: Python<'_>,
        authority: PyRef<'_, LifecycleAuthority>,
        record: &Bound<'_, PyAny>,
        action: PyRef<'_, LifecycleAction>,
        idempotency_key: &str,
        format: &str,
    ) -> PyResult<PreparedLifecycle> {
        let record = record_value(py, record, record_format(py, format)?)?;
        let key = BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| invalid(py, error.to_string()))?;
        self.inner
            .prepare_lifecycle_action(&authority.inner, &record, &action.inner, &key)
            .map(|inner| PreparedLifecycle { inner })
            .map_err(|error| sdk_error(py, error))
    }

    fn recover_lifecycle_action(
        &self,
        py: Python<'_>,
        authority: PyRef<'_, LifecycleAuthority>,
        prepared: PyRef<'_, PreparedLifecycle>,
    ) -> PyResult<RecoveredLifecycle> {
        self.inner
            .recover_lifecycle_action(&authority.inner, &prepared.inner)
            .map(|(action, key)| RecoveredLifecycle { action, key })
            .map_err(|error| sdk_error(py, error))
    }

    fn execute_recovered_lifecycle_action<'py>(
        &self,
        py: Python<'py>,
        recovered: PyRef<'_, RecoveredLifecycle>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let action = recovered.action.clone();
        let key = recovered.key.clone();
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.execute_lifecycle_action(&action, &key))
            })
            .map_err(|error| sdk_error(py, error))?;
        complete_value(py, &receipt_value(&value.value), &value.metadata)
    }

    fn execute_lifecycle_action<'py>(
        &self,
        py: Python<'py>,
        action: PyRef<'_, LifecycleAction>,
        idempotency_key: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let key = breg_client_sdk::BRegIdempotencyKey::parse(idempotency_key)
            .map_err(|error| invalid(py, error.to_string()))?;
        let action = action.inner.clone();
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.execute_lifecycle_action(&action, &key))
            })
            .map_err(|error| sdk_error(py, error))?;
        complete_value(py, &receipt_value(&value.value), &value.metadata)
    }
}

#[pymodule]
fn registry_breg_client(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<BaseRegistryClient>()?;
    module.add_class::<Metadata>()?;
    module.add_class::<CreateBinding>()?;
    module.add_class::<PatchBinding>()?;
    module.add_class::<ImmediateActionBinding>()?;
    module.add_class::<TombstoneBinding>()?;
    module.add_class::<BatchBinding>()?;
    module.add_class::<ActionTargetConditions>()?;
    module.add_class::<LifecycleAuthority>()?;
    module.add_class::<LifecycleAction>()?;
    module.add_class::<PreparedCreate>()?;
    module.add_class::<PreparedLifecycle>()?;
    module.add_class::<RecoveredCreate>()?;
    module.add_class::<RecoveredLifecycle>()?;
    module.add_class::<AttachmentSlot>()?;
    module.add_class::<AttachmentUpload>()?;
    module.add(
        "BaseRegistryClientError",
        module.py().get_type::<BaseRegistryClientError>(),
    )?;
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
