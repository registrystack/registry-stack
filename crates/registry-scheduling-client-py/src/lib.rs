// SPDX-License-Identifier: Apache-2.0
//! Synchronous Python binding for the canonical Registry Scheduling client.

#![deny(unsafe_code)]

use std::time::Duration;

use chrono::{DateTime, Utc};
use pyo3::{
    exceptions::{PyException, PyRuntimeError},
    prelude::*,
    types::{PyBool, PyDict},
};
use scheduling_client_sdk::{
    AdmissionRequest, BearerToken, CancelAppointmentRequest, CreateAppointmentRequest,
    ExternalReference, ProblemCode, RescheduleAppointmentRequest, SchedulingAuth,
    SchedulingClient as RustClient, SchedulingClientConfig,
    SchedulingClientError as RustClientError, SchedulingComplete, SchedulingProtocolFailure,
};
use serde::{de::DeserializeOwned, Serialize};
use url::Url;

mod convert;

use convert::{python_to_json, serialize_to_python};

const INVALID_ARGUMENTS: &str = "Scheduling client arguments are invalid";

pyo3::create_exception!(
    registry_scheduling_client,
    SchedulingClientError,
    PyException,
    "A stable, value-free Registry Scheduling client failure."
);

#[derive(Default)]
struct MappedError {
    kind: &'static str,
    message: String,
    code: Option<&'static str>,
    title: Option<&'static str>,
    detail: Option<&'static str>,
    status: Option<u16>,
    trace_id: Option<String>,
    transport_kind: Option<String>,
    protocol_failure: Option<&'static str>,
    outcome_unknown: bool,
}

fn to_py_err(py: Python<'_>, mapped: MappedError) -> PyErr {
    let error = SchedulingClientError::new_err(mapped.message);
    let instance = error.value(py);
    instance
        .setattr("kind", mapped.kind)
        .expect("fresh exception accepts attributes");
    instance
        .setattr("code", mapped.code)
        .expect("fresh exception accepts attributes");
    instance
        .setattr("title", mapped.title)
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
    let mut mapped = match error {
        RustClientError::Configuration { .. } => MappedError {
            kind: "configuration",
            message: "Scheduling client configuration is invalid".to_owned(),
            ..MappedError::default()
        },
        RustClientError::InvalidRequest { .. } => MappedError {
            kind: "invalid-request",
            message: INVALID_ARGUMENTS.to_owned(),
            ..MappedError::default()
        },
        RustClientError::Transport { kind } => MappedError {
            kind: "transport",
            message: "Registry Scheduling exchange did not complete".to_owned(),
            transport_kind: Some(kind.kind().to_owned()),
            ..MappedError::default()
        },
        RustClientError::Problem {
            status,
            code,
            trace_id,
        } => MappedError {
            kind: "problem",
            message: code.detail().to_owned(),
            code: Some(code.code()),
            title: Some(code.title()),
            detail: Some(code.detail()),
            status: Some(status),
            trace_id,
            ..MappedError::default()
        },
        RustClientError::Protocol {
            status,
            failure,
            trace_id,
        } => MappedError {
            kind: "protocol",
            message: "Registry Scheduling returned an invalid response".to_owned(),
            status: Some(status),
            trace_id,
            protocol_failure: Some(protocol_failure(failure)),
            ..MappedError::default()
        },
        _ => MappedError {
            kind: "protocol",
            message: "Registry Scheduling client failed".to_owned(),
            ..MappedError::default()
        },
    };
    mapped.outcome_unknown = outcome_unknown;
    to_py_err(py, mapped)
}

fn protocol_failure(failure: SchedulingProtocolFailure) -> &'static str {
    match failure {
        SchedulingProtocolFailure::HeaderBounds => "header-bounds",
        SchedulingProtocolFailure::TraceContext => "trace-context",
        SchedulingProtocolFailure::MediaType => "media-type",
        SchedulingProtocolFailure::Body => "body",
        SchedulingProtocolFailure::Problem => "problem",
        SchedulingProtocolFailure::Status => "status",
        _ => "protocol",
    }
}

fn input<T: DeserializeOwned>(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<T> {
    let value = python_to_json(value).map_err(|error| {
        let _ = error.message();
        binding_error(py, "invalid-request", INVALID_ARGUMENTS)
    })?;
    serde_json::from_value(value)
        .map_err(|_| binding_error(py, "invalid-request", INVALID_ARGUMENTS))
}

fn bearer(py: Python<'_>, value: &str) -> PyResult<BearerToken> {
    BearerToken::new(value.to_owned())
        .map_err(|_| binding_error(py, "invalid-request", "the bearer token is invalid"))
}

/// One RFC 3339 instant, normalized to UTC.
fn instant(py: Python<'_>, value: &str) -> PyResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(|_| binding_error(py, "invalid-request", INVALID_ARGUMENTS))
}

fn optional_instant(py: Python<'_>, value: Option<&str>) -> PyResult<Option<DateTime<Utc>>> {
    value.map(|value| instant(py, value)).transpose()
}

/// A page limit, refused rather than wrapped when it is outside `u32`.
fn page_limit(py: Python<'_>, value: Option<i64>) -> PyResult<Option<u32>> {
    value
        .map(|value| {
            u32::try_from(value)
                .map_err(|_| binding_error(py, "invalid-request", INVALID_ARGUMENTS))
        })
        .transpose()
}

/// The retry ceiling as a Python integer. Only an `int` in the `u8` range
/// reaches the client, which refuses one above its own bound; a `bool` is not
/// a count.
fn mutation_retries(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<u8> {
    let invalid = || {
        binding_error(
            py,
            "configuration",
            "Scheduling client configuration is invalid",
        )
    };
    if value.is_instance_of::<PyBool>() {
        return Err(invalid());
    }
    value.extract::<u8>().map_err(|_| invalid())
}

/// A timeout as a Python number of seconds. Only a finite non-negative `int`
/// or `float` reaches the client, which refuses zero; a `bool` is not a
/// duration.
fn duration(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<Duration> {
    let invalid = || {
        binding_error(
            py,
            "configuration",
            "client timeouts must be finite non-negative seconds",
        )
    };
    if value.is_instance_of::<PyBool>() {
        return Err(invalid());
    }
    let seconds = value.extract::<f64>().map_err(|_| invalid())?;
    Duration::try_from_secs_f64(seconds).map_err(|_| invalid())
}

/// The response body bound as a Python integer. Only an `int` in the `u64`
/// range reaches the client, which refuses one outside its own bounds; a
/// `bool` is not a count.
fn response_bytes(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<u64> {
    let invalid = || {
        binding_error(
            py,
            "configuration",
            "Scheduling client configuration is invalid",
        )
    };
    if value.is_instance_of::<PyBool>() {
        return Err(invalid());
    }
    value.extract::<u64>().map_err(|_| invalid())
}

fn complete<'py, T: Serialize>(
    py: Python<'py>,
    result: Result<SchedulingComplete<T>, RustClientError>,
) -> PyResult<Bound<'py, PyAny>> {
    let complete = result.map_err(|error| client_error(py, error))?;
    // The service has answered, so a mutation may already have taken effect:
    // an answer this binding cannot convert leaves the outcome unknown.
    let converted = serialize_to_python(py, &complete.value).map_err(|_| {
        to_py_err(
            py,
            MappedError {
                kind: "protocol",
                message: "Registry Scheduling client failed".to_owned(),
                trace_id: Some(complete.trace_id.clone()),
                outcome_unknown: true,
                ..MappedError::default()
            },
        )
    })?;
    let value = PyDict::new(py);
    value.set_item("kind", "complete")?;
    value.set_item("value", converted)?;
    value.set_item("trace_id", complete.trace_id)?;
    Ok(value.into_any())
}

#[pyclass(name = "SchedulingClient", module = "registry_scheduling_client")]
struct SchedulingClient {
    inner: RustClient,
    runtime: tokio::runtime::Runtime,
}

#[pymethods]
impl SchedulingClient {
    #[new]
    #[pyo3(signature = (base_url, request_timeout_seconds=None, connect_timeout_seconds=None, max_response_bytes=None, user_agent=None, trusted_root_certificates=None, max_mutation_retries=None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        base_url: &str,
        request_timeout_seconds: Option<&Bound<'_, PyAny>>,
        connect_timeout_seconds: Option<&Bound<'_, PyAny>>,
        max_response_bytes: Option<&Bound<'_, PyAny>>,
        user_agent: Option<String>,
        trusted_root_certificates: Option<Vec<u8>>,
        max_mutation_retries: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let base_url = Url::parse(base_url).map_err(|_| {
            binding_error(
                py,
                "configuration",
                "Scheduling client configuration is invalid",
            )
        })?;
        let mut config = SchedulingClientConfig::new(base_url);
        if let Some(value) = request_timeout_seconds {
            config = config.with_request_timeout(duration(py, value)?);
        }
        if let Some(value) = connect_timeout_seconds {
            config = config.with_connect_timeout(duration(py, value)?);
        }
        if let Some(value) = max_response_bytes {
            config = config.with_max_response_bytes(response_bytes(py, value)?);
        }
        if let Some(value) = user_agent {
            config = config.with_user_agent(value);
        }
        if let Some(value) = trusted_root_certificates {
            config = config.with_trusted_root_certificates(value);
        }
        if let Some(value) = max_mutation_retries {
            config = config.with_max_mutation_retries(mutation_retries(py, value)?);
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

    fn get_scheduling<'py>(&self, py: Python<'py>, token: &str) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime
                    .block_on(self.inner.get_scheduling(SchedulingAuth::new(&token)))
            }),
        )
    }

    #[pyo3(signature = (token, cursor=None))]
    fn list_services<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        cursor: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .list_services(SchedulingAuth::new(&token), cursor),
                )
            }),
        )
    }

    #[pyo3(signature = (token, cursor=None))]
    fn list_offerings<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        cursor: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .list_offerings(SchedulingAuth::new(&token), cursor),
                )
            }),
        )
    }

    #[pyo3(signature = (token, offering, *, start=None, end=None, cursor=None, limit=None))]
    #[allow(clippy::too_many_arguments)]
    fn availability<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        offering: &str,
        start: Option<&str>,
        end: Option<&str>,
        cursor: Option<&str>,
        limit: Option<i64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let start = optional_instant(py, start)?;
        let end = optional_instant(py, end)?;
        let limit = page_limit(py, limit)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.availability(
                    SchedulingAuth::new(&token),
                    offering,
                    start,
                    end,
                    cursor,
                    limit,
                ))
            }),
        )
    }

    fn explain<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        offering: &str,
        start: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let start = instant(py, start)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.explain(
                    SchedulingAuth::new(&token),
                    offering,
                    start,
                ))
            }),
        )
    }

    fn create_hold<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        idempotency_key: &str,
        request: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let request: AdmissionRequest = input(py, request)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.create_hold(
                    SchedulingAuth::new(&token),
                    idempotency_key,
                    &request,
                ))
            }),
        )
    }

    fn release_hold<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        hold_id: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .release_hold(SchedulingAuth::new(&token), hold_id),
                )
            }),
        )
    }

    fn create_appointment<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        idempotency_key: &str,
        request: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let request: CreateAppointmentRequest = input(py, request)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.create_appointment(
                    SchedulingAuth::new(&token),
                    idempotency_key,
                    &request,
                ))
            }),
        )
    }

    fn appointment_receipt<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        idempotency_key: &str,
        request: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let request: CreateAppointmentRequest = input(py, request)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.appointment_receipt(
                    SchedulingAuth::new(&token),
                    idempotency_key,
                    &request,
                ))
            }),
        )
    }

    fn get_appointment<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        appointment_id: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .get_appointment(SchedulingAuth::new(&token), appointment_id),
                )
            }),
        )
    }

    #[pyo3(signature = (token, reference, *, cursor=None, limit=None))]
    fn list_appointments<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        reference: &Bound<'_, PyAny>,
        cursor: Option<&str>,
        limit: Option<i64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let reference: ExternalReference = input(py, reference)?;
        let limit = page_limit(py, limit)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.list_appointments(
                    SchedulingAuth::new(&token),
                    &reference,
                    cursor,
                    limit,
                ))
            }),
        )
    }

    fn reschedule_appointment<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        appointment_id: &str,
        idempotency_key: &str,
        request: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let request: RescheduleAppointmentRequest = input(py, request)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.reschedule_appointment(
                    SchedulingAuth::new(&token),
                    appointment_id,
                    idempotency_key,
                    &request,
                ))
            }),
        )
    }

    fn cancel_appointment<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        appointment_id: &str,
        idempotency_key: &str,
        request: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let request: CancelAppointmentRequest = input(py, request)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.cancel_appointment(
                    SchedulingAuth::new(&token),
                    appointment_id,
                    idempotency_key,
                    &request,
                ))
            }),
        )
    }

    #[pyo3(signature = (token, appointment_id, cursor=None))]
    fn appointment_history<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        appointment_id: &str,
        cursor: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(self.inner.appointment_history(
                    SchedulingAuth::new(&token),
                    appointment_id,
                    cursor,
                ))
            }),
        )
    }

    #[pyo3(signature = (token, cursor=None))]
    fn list_resources<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        cursor: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .list_resources(SchedulingAuth::new(&token), cursor),
                )
            }),
        )
    }

    #[pyo3(signature = (token, cursor=None))]
    fn list_locations<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        cursor: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime.block_on(
                    self.inner
                        .list_locations(SchedulingAuth::new(&token), cursor),
                )
            }),
        )
    }
}

#[pymodule]
fn registry_scheduling_client(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<SchedulingClient>()?;
    module.add(
        "SchedulingClientError",
        module.py().get_type::<SchedulingClientError>(),
    )?;
    // The closed catalogue a caller can match on, read from the Rust client
    // so the typing stub is checked against one list, not a copy.
    module.add(
        "PROBLEM_CODES",
        ProblemCode::ALL
            .iter()
            .map(|code| code.code())
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
                Ok(SchedulingComplete {
                    value: Unconvertible,
                    trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_owned(),
                }),
            )
            .expect_err("an unconvertible answer is refused");
            assert!(error.is_instance_of::<SchedulingClientError>(py));
            let error = error.value(py);
            let attribute = |name: &str| error.getattr(name).expect("the attribute is set");
            assert_eq!(attribute("kind").extract::<String>().unwrap(), "protocol");
            assert!(attribute("outcome_unknown").extract::<bool>().unwrap());
            assert_eq!(
                attribute("trace_id").extract::<String>().unwrap(),
                "4bf92f3577b34da6a3ce929d0e0e4736"
            );
            assert_eq!(error.to_string(), "Registry Scheduling client failed");
        });
    }
}
