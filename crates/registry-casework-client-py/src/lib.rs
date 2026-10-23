// SPDX-License-Identifier: Apache-2.0
//! Synchronous Python binding for the canonical Registry Casework client.

#![deny(unsafe_code)]
// The canonical error carries bounded validation and recovery metadata. The
// binding keeps that typed value intact until it is projected onto Python.
#![allow(clippy::result_large_err)]

use std::time::Duration;

use casework_client_sdk::{
    AbsenceInput, AbsencesQuery, AssignmentRequest, BearerToken, BootstrapDirectoryRequest,
    CaseworkAuth, CaseworkClient as RustClient, CaseworkClientConfig,
    CaseworkClientError as RustClientError, CaseworkComplete, CaseworkProblemCode,
    CaseworkProtocolFailure, DelegateRequest, DirectoryTargetsQuery, DirectoryTeamUpdateRequest,
    HolidaySetRevisionInput, OwnReviewDecisionQuery, ReviewCancelRequest,
    ReviewCaseloadApplyRequest, ReviewCaseloadMoveRequest, ReviewClockRecomputeApplyRequest,
    ReviewClockRecomputeRequest, ReviewCreateRequest, ReviewNoteRequest, ReviewPageQuery,
    ReviewRequestAccepted, ReviewResultResponse, ReviewStaffingQuery, ReviewTaskDecisionRequest,
    ReviewTaskDraftInput, SubmissionDigest, SupervisoryReviewTaskQuery,
};
use pyo3::{
    exceptions::{PyException, PyRuntimeError},
    prelude::*,
    types::{PyBool, PyDict, PyFloat, PyInt},
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
    validation: Option<serde_json::Value>,
    transport_kind: Option<String>,
    protocol_failure: Option<&'static str>,
    outcome_unknown: bool,
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
    instance
        .setattr("outcome_unknown", mapped.outcome_unknown)
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
    let outcome_unknown = error.is_outcome_unknown();
    let mut mapped = match &error {
        RustClientError::Configuration { .. } => MappedError {
            kind: "configuration",
            message: "Casework client configuration is invalid".to_owned(),
            ..MappedError::default()
        },
        RustClientError::InvalidRequest { .. } => MappedError {
            kind: "invalid-request",
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
            validation,
        } => {
            mapped.status = Some(status);
            mapped.code = Some(code.code().to_owned());
            mapped.detail = detail;
            mapped.trace_id = trace_id;
            mapped.validation = validation.map(|value| {
                serde_json::json!({
                    "path": value.path,
                    "reason": validation_reason(value.reason),
                    "allowed": value.allowed,
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
                CaseworkProtocolFailure::HeaderBounds => "header-bounds",
                CaseworkProtocolFailure::TraceContext => "trace-context",
                CaseworkProtocolFailure::MediaType => "media-type",
                CaseworkProtocolFailure::Body => "body",
                CaseworkProtocolFailure::Problem => "problem",
                CaseworkProtocolFailure::Status => "status",
                _ => "protocol",
            });
        }
        _ => {}
    }
    mapped.outcome_unknown = outcome_unknown;
    to_py_err(py, mapped)
}

fn input<T: DeserializeOwned>(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<T> {
    let value = python_to_json(value).map_err(|error| {
        let _ = error.message();
        binding_error(
            py,
            "invalid-request",
            "Casework client arguments are invalid",
        )
    })?;
    serde_json::from_value(value).map_err(|_| {
        binding_error(
            py,
            "invalid-request",
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

fn accepted_input(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<ReviewRequestAccepted> {
    let value = python_to_json(value).map_err(|_| {
        to_py_err(
            py,
            MappedError {
                kind: "invalid-request",
                message: "the accepted review binding is invalid".to_owned(),
                validation: Some(
                    serde_json::json!({"path":"$", "reason":"binding-invalid", "allowed":[]}),
                ),
                ..MappedError::default()
            },
        )
    })?;
    casework_client_sdk::accepted_binding(value).map_err(|error| {
        to_py_err(
            py,
            MappedError {
                kind: "invalid-request",
                message: "the accepted review binding is invalid".to_owned(),
                validation: Some(
                    serde_json::json!({"path":error.path,"reason":error.reason,"allowed":[]}),
                ),
                ..MappedError::default()
            },
        )
    })
}

fn bearer(py: Python<'_>, value: &str) -> PyResult<BearerToken> {
    BearerToken::new(value.to_owned())
        .map_err(|_| binding_error(py, "invalid-request", "the bearer token is invalid"))
}

fn uuid(py: Python<'_>, value: &str) -> PyResult<Uuid> {
    Uuid::parse_str(value).map_err(|_| binding_error(py, "invalid-request", "the UUID is invalid"))
}

/// The retry ceiling as a Python integer. Only an `int` in the `u8` range
/// reaches the client, which refuses one above its own bound; a `bool` is not
/// a count.
fn mutation_retries(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<u8> {
    let invalid = || {
        binding_error(
            py,
            "configuration",
            "Casework client configuration is invalid",
        )
    };
    if value.is_instance_of::<PyBool>() {
        return Err(invalid());
    }
    value.extract::<u8>().map_err(|_| invalid())
}

fn duration(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<Duration> {
    if value.is_exact_instance_of::<PyFloat>() {
        let value = value.extract::<f64>().map_err(|_| {
            binding_error(
                py,
                "configuration",
                "Casework client configuration is invalid",
            )
        })?;
        Duration::try_from_secs_f64(value).map_err(|_| {
            binding_error(
                py,
                "configuration",
                "client timeouts must be finite non-negative seconds",
            )
        })
    } else if value.is_exact_instance_of::<PyInt>() {
        value
            .extract::<u64>()
            .map(Duration::from_secs)
            .map_err(|_| {
                binding_error(
                    py,
                    "configuration",
                    "Casework client configuration is invalid",
                )
            })
    } else {
        Err(binding_error(
            py,
            "configuration",
            "Casework client configuration is invalid",
        ))
    }
}

fn parse_maximum_response_bytes(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<u64> {
    if !value.is_exact_instance_of::<PyInt>() {
        return Err(binding_error(
            py,
            "configuration",
            "Casework client configuration is invalid",
        ));
    }
    value.extract::<u64>().map_err(|_| {
        binding_error(
            py,
            "configuration",
            "Casework client configuration is invalid",
        )
    })
}

/// The service has answered, so a mutation may already have taken effect:
/// an answer this binding cannot convert leaves the outcome unknown.
fn answer_to_python<'py>(
    py: Python<'py>,
    answer: &impl Serialize,
    trace_id: &str,
) -> PyResult<Bound<'py, PyAny>> {
    serialize_to_python(py, answer).map_err(|_| {
        to_py_err(
            py,
            MappedError {
                kind: "protocol",
                message: "Registry Casework client failed".to_owned(),
                trace_id: Some(trace_id.to_owned()),
                outcome_unknown: true,
                ..MappedError::default()
            },
        )
    })
}

fn complete<'py, T: Serialize>(
    py: Python<'py>,
    result: Result<CaseworkComplete<T>, RustClientError>,
) -> PyResult<Bound<'py, PyAny>> {
    let complete = result.map_err(|error| client_error(py, error))?;
    let converted = answer_to_python(py, &complete.value, &complete.trace_id)?;
    let value = PyDict::new(py);
    value.set_item("kind", "complete")?;
    value.set_item("value", converted)?;
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
            value.set_item(
                "value",
                answer_to_python(py, &complete.value, &complete.trace_id)?,
            )?;
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
const VALIDATION_REASONS: [casework_client_sdk::ReviewValidationReason; 17] = {
    use casework_client_sdk::ReviewValidationReason;
    [
        ReviewValidationReason::PolicyNotAllowed,
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
        ReviewValidationReason::PublicReasonRequired,
        ReviewValidationReason::PublicReasonNotDeclared,
        ReviewValidationReason::ApprovalOutcomeDiffers,
    ]
};

fn validation_reason(value: casework_client_sdk::ReviewValidationReason) -> &'static str {
    use casework_client_sdk::ReviewValidationReason;
    match value {
        ReviewValidationReason::PolicyNotAllowed => "policy-not-allowed",
        ReviewValidationReason::ReferenceInvalid => "reference-invalid",
        ReviewValidationReason::ObjectRequired => "object-required",
        ReviewValidationReason::MaximumBytesExceeded => "maximum-bytes-exceeded",
        ReviewValidationReason::MaximumDepthExceeded => "maximum-depth-exceeded",
        ReviewValidationReason::SchemaMismatch => "schema-mismatch",
        ReviewValidationReason::OutcomeNotDeclared => "outcome-not-declared",
        ReviewValidationReason::ReasonRequired => "reason-required",
        ReviewValidationReason::TextInvalid => "text-invalid",
        ReviewValidationReason::ResultNotDeclared => "result-not-declared",
        ReviewValidationReason::ResultRequired => "result-required",
        ReviewValidationReason::FieldNotDeclared => "field-not-declared",
        ReviewValidationReason::ConstraintInvalid => "constraint-invalid",
        ReviewValidationReason::ConstraintViolated => "constraint-violated",
        ReviewValidationReason::PublicReasonRequired => "public-reason-required",
        ReviewValidationReason::PublicReasonNotDeclared => "public-reason-not-declared",
        ReviewValidationReason::ApprovalOutcomeDiffers => "approval-outcome-differs",
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
    #[pyo3(signature = (base_url, attempt_timeout_seconds=None, connect_timeout_seconds=None, maximum_response_bytes=None, user_agent=None, trusted_root_certificates=None, maximum_mutation_retries=None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        base_url: &str,
        attempt_timeout_seconds: Option<&Bound<'_, PyAny>>,
        connect_timeout_seconds: Option<&Bound<'_, PyAny>>,
        maximum_response_bytes: Option<&Bound<'_, PyAny>>,
        user_agent: Option<String>,
        trusted_root_certificates: Option<Vec<u8>>,
        maximum_mutation_retries: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let base_url = Url::parse(base_url).map_err(|_| {
            binding_error(
                py,
                "configuration",
                "Casework client configuration is invalid",
            )
        })?;
        let mut config = CaseworkClientConfig::new(base_url);
        if let Some(value) = attempt_timeout_seconds {
            config = config.with_attempt_timeout(duration(py, value)?);
        }
        if let Some(value) = connect_timeout_seconds {
            config = config.with_connect_timeout(duration(py, value)?);
        }
        if let Some(value) = maximum_response_bytes {
            config = config.with_maximum_response_bytes(parse_maximum_response_bytes(py, value)?);
        }
        if let Some(value) = user_agent {
            config = config.with_user_agent(value);
        }
        if let Some(value) = trusted_root_certificates {
            config = config.with_trusted_root_certificates(value);
        }
        if let Some(value) = maximum_mutation_retries {
            config = config.with_maximum_mutation_retries(mutation_retries(py, value)?);
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
            binding_error(py, "invalid-request", "the submission digest is invalid")
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
        let accepted = accepted_input(py, accepted)?;
        let token = bearer(py, token)?;
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

    #[pyo3(signature = (token, profile, query=None))]
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
        accepted: &Bound<'_, PyAny>,
        idempotency_key: &str,
        request: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let accepted: ReviewRequestAccepted = input(py, accepted)?;
        let request: ReviewCancelRequest = input(py, request)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.cancel_review_request(
                    auth(&token, profile, None),
                    &accepted,
                    idempotency_key,
                    &request,
                ))
            }),
        )
    }

    fn review_policies<'py>(
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
                    .block_on(self.inner.review_policies(auth(&token, profile, None)))
            }),
        )
    }

    fn review_policy<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        policy_id: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .review_policy(auth(&token, profile, None), policy_id),
                )
            }),
        )
    }

    #[pyo3(signature = (token, profile, query=None, source_profile=None))]
    fn own_review_decisions<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        query: Option<&Bound<'py, PyAny>>,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let query: OwnReviewDecisionQuery = optional_input(py, query)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .own_review_decisions(auth(&token, profile, source_profile), &query),
                )
            }),
        )
    }

    #[pyo3(signature = (token, profile, query=None, source_profile=None))]
    fn review_tasks<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        query: Option<&Bound<'_, PyAny>>,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let query: ReviewStaffingQuery = optional_input(py, query)?;
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

    #[pyo3(signature = (token, profile, query=None, source_profile=None))]
    fn next_review_task<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        query: Option<&Bound<'_, PyAny>>,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let query: ReviewStaffingQuery = optional_input(py, query)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .next_review_task(auth(&token, profile, source_profile), &query),
                )
            }),
        )
    }

    #[pyo3(signature = (token, profile, query=None, source_profile=None))]
    fn review_task_holdings<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        query: Option<&Bound<'_, PyAny>>,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let query: ReviewStaffingQuery = optional_input(py, query)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .review_task_holdings(auth(&token, profile, source_profile), &query),
                )
            }),
        )
    }

    #[pyo3(signature = (token, profile, task_id, source_profile=None))]
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

    #[pyo3(signature = (token, profile, query=None, source_profile=None))]
    fn supervisory_review_tasks<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        query: Option<&Bound<'_, PyAny>>,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let query: SupervisoryReviewTaskQuery = optional_input(py, query)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .supervisory_review_tasks(auth(&token, profile, source_profile), &query),
                )
            }),
        )
    }

    #[pyo3(signature = (token, profile, task_id, source_profile=None))]
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

    #[pyo3(signature = (token, profile, task_id, *, source_profile=None))]
    fn preview_review_task_templates<'py>(
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
                    self.inner.preview_review_task_templates(
                        auth(&token, profile, source_profile),
                        task_id,
                    ),
                )
            }),
        )
    }

    #[pyo3(signature = (token, profile, task_id, *, source_profile=None))]
    fn list_review_task_grants<'py>(
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
                        .list_review_task_grants(auth(&token, profile, source_profile), task_id),
                )
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (token, profile, task_id, expected_revision, idempotency_key, approval, source_profile=None))]
    fn approve_review_task_grant<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        task_id: &str,
        expected_revision: i64,
        idempotency_key: &str,
        approval: &Bound<'_, PyAny>,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let task_id = uuid(py, task_id)?;
        let approval: casework_client_sdk::TaskApprovalRequest = input(py, approval)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.approve_review_task_grant(
                    auth(&token, profile, source_profile),
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
    #[pyo3(signature = (token, profile, task_id, expected_revision, idempotency_key, source_profile=None))]
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
    #[pyo3(signature = (token, profile, task_id, expected_revision, idempotency_key, decision, source_profile=None))]
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

    #[pyo3(signature = (token, profile, movement, source_profile=None))]
    #[allow(clippy::too_many_arguments)]
    fn preview_caseload_move<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        profile: &str,
        movement: &Bound<'_, PyAny>,
        source_profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let movement: ReviewCaseloadMoveRequest = input(py, movement)?;
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .preview_caseload_move(auth(&token, profile, source_profile), &movement),
                )
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
        let request: ReviewCaseloadApplyRequest = input(py, request)?;
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
        let request: ReviewClockRecomputeRequest = input(py, request)?;
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
        let request: ReviewClockRecomputeApplyRequest = input(py, request)?;
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

/// Compute the canonical producer submission digest locally, without I/O.
#[pyfunction]
fn submission_digest(
    py: Python<'_>,
    producer: &str,
    source_namespace: &str,
    request: &Bound<'_, PyAny>,
) -> PyResult<String> {
    let request: ReviewCreateRequest = input(py, request)?;
    casework_client_sdk::submission_digest(producer, source_namespace, &request)
        .map(|digest| digest.as_str().to_owned())
        .map_err(|_| {
            binding_error(
                py,
                "invalid-request",
                "Casework client arguments are invalid",
            )
        })
}

#[pymodule]
fn registry_casework_client(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<CaseworkClient>()?;
    module.add_function(wrap_pyfunction!(submission_digest, module)?)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// An answer the binding cannot turn into Python values.
    struct Unconvertible;

    impl Serialize for Unconvertible {
        fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("unconvertible"))
        }
    }

    #[test]
    fn an_answer_the_binding_cannot_convert_is_a_protocol_failure_with_an_unknown_outcome() {
        Python::attach(|py| {
            let error = complete(
                py,
                Ok(CaseworkComplete {
                    value: Unconvertible,
                    trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_owned(),
                }),
            )
            .expect_err("an unconvertible answer is refused");
            assert!(error.is_instance_of::<CaseworkClientError>(py));
            let error = error.value(py);
            let attribute = |name: &str| error.getattr(name).expect("the attribute is set");
            assert_eq!(attribute("kind").extract::<String>().unwrap(), "protocol");
            assert!(attribute("outcome_unknown").extract::<bool>().unwrap());
            assert!(attribute("protocol_failure").is_none());
            assert_eq!(
                attribute("trace_id").extract::<String>().unwrap(),
                "4bf92f3577b34da6a3ce929d0e0e4736"
            );
            assert_eq!(error.to_string(), "Registry Casework client failed");
        });
    }
}
