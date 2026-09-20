// SPDX-License-Identifier: Apache-2.0
//! Synchronous Python binding for the canonical Registry Casework client.

#![deny(unsafe_code)]
// The canonical error carries bounded validation and recovery metadata. The
// binding keeps that typed value intact until it is projected onto Python.
#![allow(clippy::result_large_err)]

use std::time::Duration;

use casework_client_sdk::{
    AbsenceInput, AbsencesQuery, AssignmentRequest, BearerToken, BootstrapDirectoryRequest,
    CaseloadApplyRequest, CaseloadMoveRequest, CaseloadPreviewQuery, CaseworkAction, CaseworkAuth,
    CaseworkClient as RustClient, CaseworkClientConfig, CaseworkClientError as RustClientError,
    CaseworkComplete, CaseworkProblemCode, CaseworkProtocolFailure, ClockRecomputeApplyRequest,
    ClockRecomputeRequest, DecideRequest, DelegateRequest, DirectoryTargetsQuery,
    DirectoryTeamUpdateRequest, HoldingsQuery, HolidaySetRevisionInput, ListWorkItemsQuery,
    NextWorkItemQuery, RecoverAttemptRequest, ReviewCancelRequest, ReviewCreateRequest,
    ReviewNoteRequest, ReviewPageQuery, ReviewResultResponse, ReviewTaskDecisionRequest,
    ReviewTaskDraftInput, ReviewTaskQuery, SaveDraftRequest, SubmissionDigest,
    WorkItemHistoryQuery,
};
use pyo3::{
    exceptions::{PyException, PyRuntimeError},
    prelude::*,
    types::PyDict,
};
use serde::{de::DeserializeOwned, Serialize};
use url::Url;
use uuid::Uuid;

mod convert;

use convert::{json_to_python, python_to_json, serialize_to_python};

pyo3::create_exception!(
    registry_casework_client,
    CaseworkClientError,
    PyException,
    "A stable, value-free Registry Casework client failure."
);

#[derive(Default)]
struct MappedError {
    kind: &'static str,
    message: String,
    code: Option<String>,
    detail: Option<String>,
    status: Option<u16>,
    trace_id: Option<String>,
    original_attempt_id: Option<String>,
    validation: Option<serde_json::Value>,
    transport_kind: Option<String>,
    protocol_failure: Option<&'static str>,
}

fn to_py_err(py: Python<'_>, mapped: MappedError) -> PyErr {
    let error = CaseworkClientError::new_err(mapped.message);
    let instance = error.value(py);
    instance
        .setattr("kind", mapped.kind)
        .expect("fresh exception accepts attributes");
    instance
        .setattr("code", mapped.code)
        .expect("fresh exception accepts attributes");
    instance
        .setattr("detail", mapped.detail)
        .expect("fresh exception accepts attributes");
    instance
        .setattr("status", mapped.status)
        .expect("fresh exception accepts attributes");
    instance
        .setattr("trace_id", mapped.trace_id)
        .expect("fresh exception accepts attributes");
    instance
        .setattr("original_attempt_id", mapped.original_attempt_id)
        .expect("fresh exception accepts attributes");
    let validation = mapped
        .validation
        .as_ref()
        .map(|value| json_to_python(py, value))
        .transpose()
        .expect("validated error metadata is representable")
        .unwrap_or_else(|| py.None().into_bound(py));
    instance
        .setattr("validation", validation)
        .expect("fresh exception accepts attributes");
    instance
        .setattr("transport_kind", mapped.transport_kind)
        .expect("fresh exception accepts attributes");
    instance
        .setattr("protocol_failure", mapped.protocol_failure)
        .expect("fresh exception accepts attributes");
    error
}

fn binding_error(py: Python<'_>, kind: &'static str, message: &'static str) -> PyErr {
    to_py_err(
        py,
        MappedError {
            kind,
            message: message.to_owned(),
            ..MappedError::default()
        },
    )
}

fn client_error(py: Python<'_>, error: RustClientError) -> PyErr {
    let mut mapped = match &error {
        RustClientError::Configuration { .. } => MappedError {
            kind: "configuration",
            message: "Casework client configuration is invalid".to_owned(),
            ..MappedError::default()
        },
        RustClientError::InvalidRequest { .. } => MappedError {
            kind: "invalid_request",
            message: "Casework client arguments are invalid".to_owned(),
            ..MappedError::default()
        },
        RustClientError::Transport { .. } => MappedError {
            kind: "transport",
            message: "Registry Casework exchange did not complete".to_owned(),
            ..MappedError::default()
        },
        RustClientError::Problem { detail, .. } => MappedError {
            kind: "problem",
            message: detail
                .clone()
                .unwrap_or_else(|| "Registry Casework refused the request".to_owned()),
            ..MappedError::default()
        },
        RustClientError::Protocol { .. } => MappedError {
            kind: "protocol",
            message: "Registry Casework returned an invalid response".to_owned(),
            ..MappedError::default()
        },
        _ => MappedError {
            kind: "protocol",
            message: "Registry Casework client failed".to_owned(),
            ..MappedError::default()
        },
    };
    match error {
        RustClientError::Transport { kind } => mapped.transport_kind = Some(kind.kind().to_owned()),
        RustClientError::Problem {
            status,
            code,
            detail,
            trace_id,
            original_attempt_id,
            validation,
        } => {
            mapped.status = Some(status);
            mapped.code = Some(code.code().to_owned());
            mapped.detail = detail;
            mapped.trace_id = trace_id;
            mapped.original_attempt_id = original_attempt_id.map(|value| value.to_string());
            mapped.validation = validation.map(|value| {
                serde_json::json!({
                    "path": value.path,
                    "reason": validation_reason(value.reason),
                })
            });
        }
        RustClientError::Protocol {
            status,
            failure,
            trace_id,
        } => {
            mapped.status = Some(status);
            mapped.trace_id = trace_id;
            mapped.protocol_failure = Some(match failure {
                CaseworkProtocolFailure::HeaderBounds => "header_bounds",
                CaseworkProtocolFailure::TraceContext => "trace_context",
                CaseworkProtocolFailure::MediaType => "media_type",
                CaseworkProtocolFailure::Body => "body",
                CaseworkProtocolFailure::Problem => "problem",
                CaseworkProtocolFailure::Status => "status",
                _ => "protocol",
            });
        }
        _ => {}
    }
    to_py_err(py, mapped)
}

fn input<T: DeserializeOwned>(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<T> {
    let value = python_to_json(value).map_err(|error| {
        let _ = error.message();
        binding_error(
            py,
            "invalid_request",
            "Casework client arguments are invalid",
        )
    })?;
    serde_json::from_value(value).map_err(|_| {
        binding_error(
            py,
            "invalid_request",
            "Casework client arguments are invalid",
        )
    })
}

fn optional_input<T: DeserializeOwned + Default>(
    py: Python<'_>,
    value: Option<&Bound<'_, PyAny>>,
) -> PyResult<T> {
    value
        .map(|value| input(py, value))
        .transpose()
        .map(Option::unwrap_or_default)
}

fn bearer(py: Python<'_>, value: &str) -> PyResult<BearerToken> {
    BearerToken::new(value.to_owned())
        .map_err(|_| binding_error(py, "invalid_request", "the bearer token is invalid"))
}

fn uuid(py: Python<'_>, value: &str) -> PyResult<Uuid> {
    Uuid::parse_str(value).map_err(|_| binding_error(py, "invalid_request", "the UUID is invalid"))
}

fn duration(py: Python<'_>, value: f64) -> PyResult<Duration> {
    Duration::try_from_secs_f64(value).map_err(|_| {
        binding_error(
            py,
            "configuration",
            "client timeouts must be finite non-negative seconds",
        )
    })
}

fn complete<'py, T: Serialize>(
    py: Python<'py>,
    result: Result<CaseworkComplete<T>, RustClientError>,
) -> PyResult<Bound<'py, PyAny>> {
    let complete = result.map_err(|error| client_error(py, error))?;
    let value = PyDict::new(py);
    value.set_item("kind", "complete")?;
    value.set_item("value", serialize_to_python(py, &complete.value)?)?;
    value.set_item("trace_id", complete.trace_id)?;
    Ok(value.into_any())
}

fn review_result_complete<'py>(
    py: Python<'py>,
    result: Result<ReviewResultResponse, RustClientError>,
) -> PyResult<Bound<'py, PyAny>> {
    let result = result.map_err(|error| client_error(py, error))?;
    let value = PyDict::new(py);
    match result {
        ReviewResultResponse::Available(complete) => {
            value.set_item("kind", "available")?;
            value.set_item("value", serialize_to_python(py, &complete.value)?)?;
            value.set_item("trace_id", complete.trace_id)?;
        }
        ReviewResultResponse::Pending { trace_id } => {
            value.set_item("kind", "pending")?;
            value.set_item("value", py.None())?;
            value.set_item("trace_id", trace_id)?;
        }
        ReviewResultResponse::ConcealedOrUnknown { trace_id } => {
            value.set_item("kind", "concealed_or_unknown")?;
            value.set_item("value", py.None())?;
            value.set_item("trace_id", trace_id)?;
        }
        ReviewResultResponse::Expired { trace_id } => {
            value.set_item("kind", "expired")?;
            value.set_item("value", py.None())?;
            value.set_item("trace_id", trace_id)?;
        }
    }
    Ok(value.into_any())
}

fn auth<'a>(
    token: &'a BearerToken,
    profile: &'a str,
    source_profile: Option<&'a str>,
) -> CaseworkAuth<'a> {
    match source_profile {
        Some(source) => CaseworkAuth::new(token, profile).with_source_profile(source),
        None => CaseworkAuth::new(token, profile),
    }
}

/// Every validation reason the binding can answer, in the order the mapping
/// below names them. A reason the client adds stops that mapping compiling, so
/// a new reason is named here before it can reach a caller.
const VALIDATION_REASONS: [casework_client_sdk::ReviewValidationReason; 14] = {
    use casework_client_sdk::ReviewValidationReason;
    [
        ReviewValidationReason::KindNotAllowed,
        ReviewValidationReason::ReferenceInvalid,
        ReviewValidationReason::ObjectRequired,
        ReviewValidationReason::MaximumBytesExceeded,
        ReviewValidationReason::MaximumDepthExceeded,
        ReviewValidationReason::SchemaMismatch,
        ReviewValidationReason::OutcomeNotDeclared,
        ReviewValidationReason::ReasonRequired,
        ReviewValidationReason::TextInvalid,
        ReviewValidationReason::ResultNotDeclared,
        ReviewValidationReason::ResultRequired,
        ReviewValidationReason::FieldNotDeclared,
        ReviewValidationReason::ConstraintInvalid,
        ReviewValidationReason::ConstraintViolated,
    ]
};

fn validation_reason(value: casework_client_sdk::ReviewValidationReason) -> &'static str {
    use casework_client_sdk::ReviewValidationReason;
    match value {
        ReviewValidationReason::KindNotAllowed => "kind_not_allowed",
        ReviewValidationReason::ReferenceInvalid => "reference_invalid",
        ReviewValidationReason::ObjectRequired => "object_required",
        ReviewValidationReason::MaximumBytesExceeded => "maximum_bytes_exceeded",
        ReviewValidationReason::MaximumDepthExceeded => "maximum_depth_exceeded",
        ReviewValidationReason::SchemaMismatch => "schema_mismatch",
        ReviewValidationReason::OutcomeNotDeclared => "outcome_not_declared",
        ReviewValidationReason::ReasonRequired => "reason_required",
        ReviewValidationReason::TextInvalid => "text_invalid",
        ReviewValidationReason::ResultNotDeclared => "result_not_declared",
        ReviewValidationReason::ResultRequired => "result_required",
        ReviewValidationReason::FieldNotDeclared => "field_not_declared",
        ReviewValidationReason::ConstraintInvalid => "constraint_invalid",
        ReviewValidationReason::ConstraintViolated => "constraint_violated",
    }
}

#[pyclass(name = "CaseworkClient", module = "registry_casework_client")]
struct CaseworkClient {
    inner: RustClient,
    runtime: tokio::runtime::Runtime,
}

#[pymethods]
impl CaseworkClient {
    #[new]
    #[pyo3(signature = (base_url, request_timeout_seconds=None, connect_timeout_seconds=None, max_response_bytes=None, user_agent=None, trusted_root_certificates=None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        base_url: &str,
        request_timeout_seconds: Option<f64>,
        connect_timeout_seconds: Option<f64>,
        max_response_bytes: Option<u64>,
        user_agent: Option<String>,
        trusted_root_certificates: Option<Vec<u8>>,
    ) -> PyResult<Self> {
        let base_url = Url::parse(base_url).map_err(|_| {
            binding_error(
                py,
                "configuration",
                "Casework client configuration is invalid",
            )
        })?;
        let mut config = CaseworkClientConfig::new(base_url);
        if let Some(value) = request_timeout_seconds {
            config = config.with_request_timeout(duration(py, value)?);
        }
        if let Some(value) = connect_timeout_seconds {
            config = config.with_connect_timeout(duration(py, value)?);
        }
        if let Some(value) = max_response_bytes {
            config = config.with_max_response_bytes(value);
        }
        if let Some(value) = user_agent {
            config = config.with_user_agent(value);
        }
        if let Some(value) = trusted_root_certificates {
            config = config.with_trusted_root_certificates(value);
        }
        let inner = py
            .detach(|| RustClient::new(config))
            .map_err(|error| client_error(py, error))?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| {
                PyRuntimeError::new_err("the client's internal runtime could not start")
            })?;
        Ok(Self { inner, runtime })
    }

    fn description<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime
                    .block_on(self.inner.description(auth(&token, profile, None)))
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn create_or_recover_review_request<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        idempotency_key: &str,
        request: &Bound<'_, PyAny>,
        expected_submission_digest: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let request: ReviewCreateRequest = input(py, request)?;
        let digest = SubmissionDigest::parse(expected_submission_digest).map_err(|_| {
            binding_error(py, "invalid_request", "the submission digest is invalid")
        })?;
        complete(
            py,
            py.detach(|| {
                self.runtime
                    .block_on(self.inner.create_or_recover_review_request(
                        auth(&token, profile, None),
                        idempotency_key,
                        &request,
                        &digest,
                    ))
            }),
        )
    }

    fn review_request<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        request_id: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let request_id = uuid(py, request_id)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .review_request(auth(&token, profile, None), request_id),
                )
            }),
        )
    }

    fn review_result<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        accepted: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let accepted = input(py, accepted)?;
        review_result_complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .review_result(auth(&token, profile, None), &accepted),
                )
            }),
        )
    }

    fn review_results<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        query: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let query: ReviewPageQuery = optional_input(py, query)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .review_results(auth(&token, profile, None), &query),
                )
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn cancel_review_request<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        request_id: &str,
        idempotency_key: &str,
        request: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let request_id = uuid(py, request_id)?;
        let request: ReviewCancelRequest = input(py, request)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.cancel_review_request(
                    auth(&token, profile, None),
                    request_id,
                    idempotency_key,
                    &request,
                ))
            }),
        )
    }

    fn review_kinds<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime
                    .block_on(self.inner.review_kinds(auth(&token, profile, None)))
            }),
        )
    }

    fn review_kind<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        kind_id: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime
                    .block_on(self.inner.review_kind(auth(&token, profile, None), kind_id))
            }),
        )
    }

    fn review_tasks<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        query: Option<&Bound<'_, PyAny>>,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let query: ReviewTaskQuery = optional_input(py, query)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .review_tasks(auth(&token, profile, source_profile), &query),
                )
            }),
        )
    }

    fn review_task<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        task_id: &str,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let task_id = uuid(py, task_id)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .review_task(auth(&token, profile, source_profile), task_id),
                )
            }),
        )
    }

    fn review_task_context<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        task_id: &str,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let task_id = uuid(py, task_id)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .review_task_context(auth(&token, profile, source_profile), task_id),
                )
            }),
        )
    }

    fn preview_review_task_templates<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        source_profile: &str,
        task_id: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let task_id = uuid(py, task_id)?;
        complete(
            py,
            py.detach(|| {
                self.runtime
                    .block_on(self.inner.preview_review_task_templates(
                        auth(&token, profile, Some(source_profile)),
                        task_id,
                    ))
            }),
        )
    }

    fn list_review_task_grants<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        source_profile: &str,
        task_id: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let task_id = uuid(py, task_id)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner.list_review_task_grants(
                        auth(&token, profile, Some(source_profile)),
                        task_id,
                    ),
                )
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn approve_review_task_grant<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        source_profile: &str,
        task_id: &str,
        expected_revision: i64,
        idempotency_key: &str,
        approval: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let task_id = uuid(py, task_id)?;
        let approval: casework_client_sdk::TaskApprovalRequest = input(py, approval)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.approve_review_task_grant(
                    auth(&token, profile, Some(source_profile)),
                    task_id,
                    expected_revision,
                    idempotency_key,
                    &approval,
                ))
            }),
        )
    }

    fn revoke_review_task_grant<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        task_id: &str,
        grant_id: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let task_id = uuid(py, task_id)?;
        let grant_id = uuid(py, grant_id)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.revoke_review_task_grant(
                    auth(&token, profile, None),
                    task_id,
                    grant_id,
                ))
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn claim_review_task<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        task_id: &str,
        expected_revision: i64,
        idempotency_key: &str,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let task_id = uuid(py, task_id)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.claim_review_task(
                    auth(&token, profile, source_profile),
                    task_id,
                    expected_revision,
                    idempotency_key,
                ))
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn release_review_task<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        task_id: &str,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let task_id = uuid(py, task_id)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.release_review_task(
                    auth(&token, profile, None),
                    task_id,
                    expected_revision,
                    idempotency_key,
                ))
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (token, profile, task_id, expected_revision, idempotency_key, request, source_profile=None))]
    fn assign_review_task<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        task_id: &str,
        expected_revision: i64,
        idempotency_key: &str,
        request: &Bound<'_, PyAny>,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let task_id = uuid(py, task_id)?;
        let request: AssignmentRequest = input(py, request)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.assign_review_task(
                    auth(&token, profile, source_profile),
                    task_id,
                    expected_revision,
                    idempotency_key,
                    &request,
                ))
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (token, profile, task_id, expected_revision, idempotency_key, request, source_profile=None))]
    fn delegate_review_task<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        task_id: &str,
        expected_revision: i64,
        idempotency_key: &str,
        request: &Bound<'_, PyAny>,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let task_id = uuid(py, task_id)?;
        let request: DelegateRequest = input(py, request)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.delegate_review_task(
                    auth(&token, profile, source_profile),
                    task_id,
                    expected_revision,
                    idempotency_key,
                    &request,
                ))
            }),
        )
    }

    #[pyo3(signature = (token, profile, task_id, source_profile=None))]
    fn review_task_draft<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        task_id: &str,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let task_id = uuid(py, task_id)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .review_task_draft(auth(&token, profile, source_profile), task_id),
                )
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (token, profile, task_id, expected_revision, idempotency_key, draft, source_profile=None))]
    fn save_review_task_draft<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        task_id: &str,
        expected_revision: i64,
        idempotency_key: &str,
        draft: &Bound<'_, PyAny>,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let task_id = uuid(py, task_id)?;
        let draft: ReviewTaskDraftInput = input(py, draft)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.save_review_task_draft(
                    auth(&token, profile, source_profile),
                    task_id,
                    expected_revision,
                    idempotency_key,
                    &draft,
                ))
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (token, profile, task_id, expected_revision, idempotency_key, source_profile=None))]
    fn delete_review_task_draft<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        task_id: &str,
        expected_revision: i64,
        idempotency_key: &str,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let task_id = uuid(py, task_id)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.delete_review_task_draft(
                    auth(&token, profile, source_profile),
                    task_id,
                    expected_revision,
                    idempotency_key,
                ))
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn decide_review_task<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        task_id: &str,
        expected_revision: i64,
        idempotency_key: &str,
        decision: &Bound<'_, PyAny>,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let task_id = uuid(py, task_id)?;
        let decision: ReviewTaskDecisionRequest = input(py, decision)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.decide_review_task(
                    auth(&token, profile, source_profile),
                    task_id,
                    expected_revision,
                    idempotency_key,
                    &decision,
                ))
            }),
        )
    }

    #[pyo3(signature = (token, profile, request_id, query=None, source_profile=None))]
    fn review_history<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        request_id: &str,
        query: Option<&Bound<'_, PyAny>>,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let request_id = uuid(py, request_id)?;
        let query: ReviewPageQuery = optional_input(py, query)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.review_history(
                    auth(&token, profile, source_profile),
                    request_id,
                    &query,
                ))
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (token, profile, request_id, idempotency_key, note, source_profile=None))]
    fn add_review_note<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        request_id: &str,
        idempotency_key: &str,
        note: &Bound<'_, PyAny>,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let request_id = uuid(py, request_id)?;
        let note: ReviewNoteRequest = input(py, note)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.add_review_note(
                    auth(&token, profile, source_profile),
                    request_id,
                    idempotency_key,
                    &note,
                ))
            }),
        )
    }

    #[pyo3(signature = (token, profile, request_id, source_profile=None))]
    fn review_clocks<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        request_id: &str,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let request_id = uuid(py, request_id)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .review_clocks(auth(&token, profile, source_profile), request_id),
                )
            }),
        )
    }

    fn review_accountability<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        event_id: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let event_id = uuid(py, event_id)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .review_accountability(auth(&token, profile, None), event_id),
                )
            }),
        )
    }

    fn list_work_items<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        source_profile: &str,
        query: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let query: ListWorkItemsQuery = input(py, query)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .list_work_items(auth(&token, profile, Some(source_profile)), &query),
                )
            }),
        )
    }

    #[pyo3(signature = (token, profile, source_profile, query=None))]
    fn next_work_item<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        source_profile: &str,
        query: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let query: NextWorkItemQuery = optional_input(py, query)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .next_work_item(auth(&token, profile, Some(source_profile)), &query),
                )
            }),
        )
    }

    fn get_work_item<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        source_profile: &str,
        item_id: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let item_id = uuid(py, item_id)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .get_work_item(auth(&token, profile, Some(source_profile)), item_id),
                )
            }),
        )
    }

    fn preview_task_templates<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        source_profile: &str,
        item_id: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let item_id = uuid(py, item_id)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner.preview_task_templates(
                        auth(&token, profile, Some(source_profile)),
                        item_id,
                    ),
                )
            }),
        )
    }
    fn list_task_grants<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        source_profile: &str,
        item_id: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let item_id = uuid(py, item_id)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .list_task_grants(auth(&token, profile, Some(source_profile)), item_id),
                )
            }),
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn approve_task_grant<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        source_profile: &str,
        item_id: &str,
        expected_revision: i64,
        idempotency_key: &str,
        approval: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let item_id = uuid(py, item_id)?;
        let approval: casework_client_sdk::TaskApprovalRequest = input(py, approval)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.approve_task_grant(
                    auth(&token, profile, Some(source_profile)),
                    item_id,
                    expected_revision,
                    idempotency_key,
                    &approval,
                ))
            }),
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn revoke_task_grant<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        source_profile: &str,
        item_id: &str,
        grant_id: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let item_id = uuid(py, item_id)?;
        let grant_id = uuid(py, grant_id)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.revoke_task_grant(
                    auth(&token, profile, Some(source_profile)),
                    item_id,
                    grant_id,
                ))
            }),
        )
    }
    fn task_assertion<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        grant_id: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let grant_id = uuid(py, grant_id)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime
                    .block_on(self.inner.task_assertion(&token, grant_id))
            }),
        )
    }
    fn task_assertion_endpoint(&self, py: Python<'_>, grant_id: &str) -> PyResult<String> {
        self.inner
            .task_assertion_endpoint(uuid(py, grant_id)?)
            .map(|value| value.to_string())
            .map_err(|error| client_error(py, error))
    }
    fn task_grant_status<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        grant_id: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let grant_id = uuid(py, grant_id)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime
                    .block_on(self.inner.task_grant_status(&token, grant_id))
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn claim_work_item<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        source_profile: &str,
        action: &Bound<'_, PyAny>,
        idempotency_key: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let action: CaseworkAction = input(py, action)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.claim_work_item(
                    auth(&token, profile, Some(source_profile)),
                    &action,
                    idempotency_key,
                ))
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn release_work_item<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        source_profile: &str,
        action: &Bound<'_, PyAny>,
        idempotency_key: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let action: CaseworkAction = input(py, action)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.release_work_item(
                    auth(&token, profile, Some(source_profile)),
                    &action,
                    idempotency_key,
                ))
            }),
        )
    }

    fn get_draft<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        source_profile: &str,
        item_id: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let item_id = uuid(py, item_id)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .get_draft(auth(&token, profile, Some(source_profile)), item_id),
                )
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn save_draft<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        source_profile: &str,
        item_id: &str,
        expected_revision: i64,
        idempotency_key: &str,
        draft: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let item_id = uuid(py, item_id)?;
        let draft: SaveDraftRequest = input(py, draft)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.save_draft(
                    auth(&token, profile, Some(source_profile)),
                    item_id,
                    expected_revision,
                    idempotency_key,
                    &draft,
                ))
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn delete_draft<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        source_profile: &str,
        item_id: &str,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let item_id = uuid(py, item_id)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.delete_draft(
                    auth(&token, profile, Some(source_profile)),
                    item_id,
                    expected_revision,
                    idempotency_key,
                ))
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn decide_work_item<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        source_profile: &str,
        action: &Bound<'_, PyAny>,
        idempotency_key: &str,
        decision: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let action: CaseworkAction = input(py, action)?;
        let decision: DecideRequest = input(py, decision)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.decide_work_item(
                    auth(&token, profile, Some(source_profile)),
                    &action,
                    idempotency_key,
                    &decision,
                ))
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn recover_decision<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        source_profile: &str,
        item_id: &str,
        attempt_id: &str,
        recovery: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let item_id = uuid(py, item_id)?;
        let attempt_id = uuid(py, attempt_id)?;
        let recovery: RecoverAttemptRequest = input(py, recovery)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.recover_decision(
                    auth(&token, profile, Some(source_profile)),
                    item_id,
                    attempt_id,
                    &recovery,
                ))
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn recover_decision_by_key<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        source_profile: &str,
        item_id: &str,
        idempotency_key: &str,
        recovery: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let item_id = uuid(py, item_id)?;
        let recovery: RecoverAttemptRequest = input(py, recovery)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.recover_decision_by_key(
                    auth(&token, profile, Some(source_profile)),
                    item_id,
                    idempotency_key,
                    &recovery,
                ))
            }),
        )
    }

    #[pyo3(signature = (token, profile, source_profile, item_id, query=None))]
    fn work_item_history<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        source_profile: &str,
        item_id: &str,
        query: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let item_id = uuid(py, item_id)?;
        let query: WorkItemHistoryQuery = optional_input(py, query)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.work_item_history(
                    auth(&token, profile, Some(source_profile)),
                    item_id,
                    &query,
                ))
            }),
        )
    }

    #[pyo3(signature = (token, profile, source_profile, query=None))]
    fn holdings<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        source_profile: &str,
        query: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let query: HoldingsQuery = optional_input(py, query)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .holdings(auth(&token, profile, Some(source_profile)), &query),
                )
            }),
        )
    }

    fn directory<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime
                    .block_on(self.inner.directory(auth(&token, profile, None)))
            }),
        )
    }

    fn directory_targets<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        query: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let query: DirectoryTargetsQuery = input(py, query)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .directory_targets(auth(&token, profile, None), &query),
                )
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn bootstrap_directory<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        expected_revision: i64,
        idempotency_key: &str,
        request: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let request: BootstrapDirectoryRequest = input(py, request)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.bootstrap_directory(
                    auth(&token, profile, None),
                    expected_revision,
                    idempotency_key,
                    &request,
                ))
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn update_directory_team<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        team_id: &str,
        expected_directory_revision: i64,
        idempotency_key: &str,
        request: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let request: DirectoryTeamUpdateRequest = input(py, request)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.update_directory_team(
                    auth(&token, profile, None),
                    team_id,
                    expected_directory_revision,
                    idempotency_key,
                    &request,
                ))
            }),
        )
    }

    #[pyo3(signature = (token, profile, source_profile=None, query=None))]
    fn absences<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        source_profile: Option<&str>,
        query: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let query: AbsencesQuery = optional_input(py, query)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .absences_page(auth(&token, profile, source_profile), &query),
                )
            }),
        )
    }

    #[pyo3(signature = (token, profile, expected_directory_revision, idempotency_key, absence, source_profile=None))]
    #[allow(clippy::too_many_arguments)]
    fn create_absence<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        expected_directory_revision: i64,
        idempotency_key: &str,
        absence: &Bound<'_, PyAny>,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let absence: AbsenceInput = input(py, absence)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.create_absence(
                    auth(&token, profile, source_profile),
                    expected_directory_revision,
                    idempotency_key,
                    &absence,
                ))
            }),
        )
    }

    #[pyo3(signature = (token, profile, absence_id, expected_directory_revision, idempotency_key, absence, source_profile=None))]
    #[allow(clippy::too_many_arguments)]
    fn update_absence<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        absence_id: &str,
        expected_directory_revision: i64,
        idempotency_key: &str,
        absence: &Bound<'_, PyAny>,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let absence_id = uuid(py, absence_id)?;
        let absence: AbsenceInput = input(py, absence)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.update_absence(
                    auth(&token, profile, source_profile),
                    absence_id,
                    expected_directory_revision,
                    idempotency_key,
                    &absence,
                ))
            }),
        )
    }

    #[pyo3(signature = (token, profile, absence_id, expected_directory_revision, idempotency_key, source_profile=None))]
    #[allow(clippy::too_many_arguments)]
    fn delete_absence<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        absence_id: &str,
        expected_directory_revision: i64,
        idempotency_key: &str,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let absence_id = uuid(py, absence_id)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.delete_absence(
                    auth(&token, profile, source_profile),
                    absence_id,
                    expected_directory_revision,
                    idempotency_key,
                ))
            }),
        )
    }

    #[pyo3(signature = (token, profile, item_id, expected_revision, idempotency_key, request, source_profile=None))]
    #[allow(clippy::too_many_arguments)]
    fn assign_work_item<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        item_id: &str,
        expected_revision: i64,
        idempotency_key: &str,
        request: &Bound<'_, PyAny>,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let item_id = uuid(py, item_id)?;
        let request: AssignmentRequest = input(py, request)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.assign_work_item(
                    auth(&token, profile, source_profile),
                    item_id,
                    expected_revision,
                    idempotency_key,
                    &request,
                ))
            }),
        )
    }

    #[pyo3(signature = (token, profile, item_id, expected_revision, idempotency_key, request, source_profile=None))]
    #[allow(clippy::too_many_arguments)]
    fn delegate_work_item<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        item_id: &str,
        expected_revision: i64,
        idempotency_key: &str,
        request: &Bound<'_, PyAny>,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let item_id = uuid(py, item_id)?;
        let request: DelegateRequest = input(py, request)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.delegate_work_item(
                    auth(&token, profile, source_profile),
                    item_id,
                    expected_revision,
                    idempotency_key,
                    &request,
                ))
            }),
        )
    }

    #[pyo3(signature = (token, profile, movement, query=None, source_profile=None))]
    #[allow(clippy::too_many_arguments)]
    fn preview_caseload_move<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        movement: &Bound<'_, PyAny>,
        query: Option<&Bound<'_, PyAny>>,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let movement: CaseloadMoveRequest = input(py, movement)?;
        let query: CaseloadPreviewQuery = optional_input(py, query)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.preview_caseload_move(
                    auth(&token, profile, source_profile),
                    &movement,
                    &query,
                ))
            }),
        )
    }

    #[pyo3(signature = (token, profile, idempotency_key, request, source_profile=None))]
    #[allow(clippy::too_many_arguments)]
    fn apply_caseload_move<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        idempotency_key: &str,
        request: &Bound<'_, PyAny>,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let request: CaseloadApplyRequest = input(py, request)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.apply_caseload_move(
                    auth(&token, profile, source_profile),
                    idempotency_key,
                    &request,
                ))
            }),
        )
    }

    fn work_item_clocks<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        source_profile: &str,
        item_id: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let item_id = uuid(py, item_id)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .work_item_clocks(auth(&token, profile, Some(source_profile)), item_id),
                )
            }),
        )
    }

    fn holiday_revision<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        holiday_set: &str,
        revision: u64,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.holiday_revision(
                    auth(&token, profile, None),
                    holiday_set,
                    revision,
                ))
            }),
        )
    }

    fn create_holiday_revision<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        idempotency_key: &str,
        request: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let request: HolidaySetRevisionInput = input(py, request)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.create_holiday_revision(
                    auth(&token, profile, None),
                    idempotency_key,
                    &request,
                ))
            }),
        )
    }

    fn preview_clock_recompute<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        request: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let request: ClockRecomputeRequest = input(py, request)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .preview_clock_recompute(auth(&token, profile, None), &request),
                )
            }),
        )
    }

    fn apply_clock_recompute<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        idempotency_key: &str,
        request: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let request: ClockRecomputeApplyRequest = input(py, request)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.apply_clock_recompute(
                    auth(&token, profile, None),
                    idempotency_key,
                    &request,
                ))
            }),
        )
    }
}

#[pymodule]
fn registry_casework_client(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<CaseworkClient>()?;
    module.add(
        "CaseworkClientError",
        module.py().get_type::<CaseworkClientError>(),
    )?;
    // The two closed catalogues a caller can match on, read from the Rust
    // client so the typing stub is checked against one list, not a copy.
    module.add(
        "PROBLEM_CODES",
        CaseworkProblemCode::ALL
            .iter()
            .map(CaseworkProblemCode::code)
            .collect::<Vec<_>>(),
    )?;
    module.add(
        "VALIDATION_REASONS",
        VALIDATION_REASONS
            .into_iter()
            .map(validation_reason)
            .collect::<Vec<_>>(),
    )?;
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
