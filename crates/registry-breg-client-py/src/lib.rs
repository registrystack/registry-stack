// SPDX-License-Identifier: Apache-2.0
//! Synchronous Python binding for the canonical Base Registry Engine client.

#![deny(unsafe_code)]

use breg_client_sdk::{
    BRegComplete, BRegContinuation, BRegContinuationProjection, BRegCreateBinding,
    BRegCreateRequest, BRegDirectWrite, BRegEtag, BRegLifecycleAction as CoreLifecycleAction,
    BRegLifecycleActionReceipt, BRegLifecycleAuthority, BRegLifecyclePromotionError,
    BRegListRequest, BRegLookupRequest, BRegMetadata as CoreMetadata, BRegMetadataSelectionError,
    BRegMetadataSelectionErrorKind, BRegPage, BRegPatchBinding, BRegPatchRequest, BRegProblemCode,
    BRegProtocolFailure, BRegRawDocument, BRegRecordFormat, BRegRecordOptions,
    BRegRequestApplicationDisposition, BRegRequestProposal, BRegRequestReview,
    BRegRequestReviewMode, BRegRequestState, BaseRegistryClient as RustClient,
    BaseRegistryClientError as RustClientError, RegistryRecordRepresentation,
    RegistryRecordResponse, TokenError,
};
use pyo3::{
    exceptions::{PyException, PyRuntimeError},
    prelude::*,
    types::{PyBytes, PyDict},
};
use serde::Serialize;
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
        } => {
            mapped.status = Some(status);
            mapped.code = Some(code.code().to_owned());
            mapped.trace_id = Some(trace_id.as_str().to_owned());
            if let BRegProblemCode::RequestPlanRefused(value) = code {
                mapped.plan_refusal = Some(value.kind().to_owned());
            }
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
    Ok(request)
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

#[pyclass(name = "BRegCreateBinding", module = "registry_breg_client", frozen)]
struct CreateBinding {
    inner: BRegCreateBinding,
}

#[pyclass(name = "BRegPatchBinding", module = "registry_breg_client", frozen)]
struct PatchBinding {
    inner: BRegPatchBinding,
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

#[pymethods]
impl LifecycleAction {
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

    #[pyo3(signature = (entity_route, record_identifier, *, select=None, access_profile=None, format="json"))]
    fn get_record<'py>(
        &self,
        py: Python<'py>,
        entity_route: &str,
        record_identifier: &str,
        select: Option<Vec<String>>,
        access_profile: Option<String>,
        format: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let options = record_options(py, select, access_profile, format)?;
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

    #[pyo3(signature = (entity_route, *, top=None, select=None, access_profile=None, format="json", filter=None, orderby=None, count=None))]
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
        )?;
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.list_records(entity_route, &request))
            })
            .map_err(|error| sdk_error(py, error))?;
        page_value(py, value)
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
    module.add_class::<LifecycleAuthority>()?;
    module.add_class::<LifecycleAction>()?;
    module.add(
        "BaseRegistryClientError",
        module.py().get_type::<BaseRegistryClientError>(),
    )?;
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
