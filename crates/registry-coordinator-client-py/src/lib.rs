// SPDX-License-Identifier: Apache-2.0
//! Synchronous Python binding for the canonical Registry Coordinator client.

#![deny(unsafe_code)]

use std::time::Duration;

use coordinator_client_sdk::{
    BearerToken, CoordinatorClient as RustClient, CoordinatorClientConfig,
    CoordinatorClientError as RustClientError, CoordinatorComplete, CoordinatorProtocolFailure,
    StartRunRequest, Uuid,
};
use pyo3::{
    exceptions::{PyException, PyRuntimeError},
    prelude::*,
    types::{PyBool, PyDict},
};
use serde::{de::DeserializeOwned, Serialize};
use url::Url;

mod convert;

use convert::{python_to_json, serialize_to_python};

pyo3::create_exception!(
    registry_coordinator_client,
    CoordinatorClientError,
    PyException,
    "A stable, value-free Registry Coordinator client failure."
);

#[derive(Default)]
struct MappedError {
    kind: &'static str,
    message: &'static str,
    code: Option<String>,
    status: Option<u16>,
    transport_kind: Option<String>,
    protocol_failure: Option<&'static str>,
    outcome_unknown: bool,
}

fn to_py_err(py: Python<'_>, mapped: MappedError) -> PyErr {
    let error = CoordinatorClientError::new_err(mapped.message);
    let instance = error.value(py);
    instance
        .setattr("kind", mapped.kind)
        .expect("fresh exception accepts attributes");
    instance
        .setattr("code", mapped.code)
        .expect("fresh exception accepts attributes");
    instance
        .setattr("status", mapped.status)
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
            message,
            ..MappedError::default()
        },
    )
}

fn client_error(py: Python<'_>, error: RustClientError) -> PyErr {
    let outcome_unknown = error.is_outcome_unknown();
    let mut mapped = match error {
        RustClientError::Configuration { .. } => MappedError {
            kind: "configuration",
            message: "Coordinator client configuration is invalid",
            ..MappedError::default()
        },
        RustClientError::InvalidRequest { .. } => MappedError {
            kind: "invalid-request",
            message: "Coordinator client arguments are invalid",
            ..MappedError::default()
        },
        RustClientError::Transport { kind } => MappedError {
            kind: "transport",
            message: "Registry Coordinator exchange did not complete",
            transport_kind: Some(kind.kind().to_owned()),
            ..MappedError::default()
        },
        RustClientError::Problem { status, code } => MappedError {
            kind: "problem",
            message: "Registry Coordinator refused the request",
            code: Some(code),
            status: Some(status),
            ..MappedError::default()
        },
        RustClientError::Protocol { status, failure } => MappedError {
            kind: "protocol",
            message: "Registry Coordinator returned an invalid response",
            status: Some(status),
            protocol_failure: Some(protocol_failure(failure)),
            ..MappedError::default()
        },
        _ => MappedError {
            kind: "protocol",
            message: "Registry Coordinator client failed",
            ..MappedError::default()
        },
    };
    mapped.outcome_unknown = outcome_unknown;
    to_py_err(py, mapped)
}

fn protocol_failure(failure: CoordinatorProtocolFailure) -> &'static str {
    match failure {
        CoordinatorProtocolFailure::HeaderBounds => "header-bounds",
        CoordinatorProtocolFailure::MediaType => "media-type",
        CoordinatorProtocolFailure::Body => "body",
        CoordinatorProtocolFailure::Problem => "problem",
        CoordinatorProtocolFailure::Status => "status",
        _ => "protocol",
    }
}

fn invalid_arguments(py: Python<'_>) -> PyErr {
    binding_error(
        py,
        "invalid-request",
        "Coordinator client arguments are invalid",
    )
}

fn input<T: DeserializeOwned>(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<T> {
    let value = python_to_json(value).map_err(|error| {
        let _ = error.message();
        invalid_arguments(py)
    })?;
    serde_json::from_value(value).map_err(|_| invalid_arguments(py))
}

fn bearer(py: Python<'_>, value: &str) -> PyResult<BearerToken> {
    BearerToken::new(value.to_owned())
        .map_err(|_| binding_error(py, "invalid-request", "the bearer token is invalid"))
}

/// A run identifier in its lowercase hyphenated form, the only spelling the
/// runtime routes.
fn run_id(py: Python<'_>, value: &str) -> PyResult<Uuid> {
    Uuid::parse_str(value)
        .ok()
        .filter(|run| run.to_string() == value)
        .ok_or_else(|| binding_error(py, "invalid-request", "the run identifier is invalid"))
}

fn invalid_configuration(py: Python<'_>) -> PyErr {
    binding_error(
        py,
        "configuration",
        "Coordinator client configuration is invalid",
    )
}

/// The retry ceiling as a Python integer. Only an `int` in the `u8` range
/// reaches the client, which refuses one above its own bound; a `bool` is not
/// a count.
fn mutation_retries(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<u8> {
    if value.is_instance_of::<PyBool>() {
        return Err(invalid_configuration(py));
    }
    value.extract::<u8>().map_err(|_| invalid_configuration(py))
}

/// The list limit as a Python integer. Only an `int` in the `u32` range
/// reaches the client, which refuses one outside `1..=100`; a `bool` is not a
/// count.
fn list_limit(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<u32> {
    if value.is_instance_of::<PyBool>() {
        return Err(invalid_arguments(py));
    }
    value.extract::<u32>().map_err(|_| invalid_arguments(py))
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
    if value.is_instance_of::<PyBool>() {
        return Err(invalid_configuration(py));
    }
    value
        .extract::<u64>()
        .map_err(|_| invalid_configuration(py))
}

fn complete<'py, T: Serialize>(
    py: Python<'py>,
    result: Result<CoordinatorComplete<T>, RustClientError>,
) -> PyResult<Bound<'py, PyAny>> {
    let complete = result.map_err(|error| client_error(py, error))?;
    // The service has answered, so a mutation may already have taken effect:
    // an answer this binding cannot convert leaves the outcome unknown.
    let converted = serialize_to_python(py, &complete.value).map_err(|_| {
        to_py_err(
            py,
            MappedError {
                kind: "protocol",
                message: "Registry Coordinator client failed",
                outcome_unknown: true,
                ..MappedError::default()
            },
        )
    })?;
    let value = PyDict::new(py);
    value.set_item("kind", "complete")?;
    value.set_item("value", converted)?;
    Ok(value.into_any())
}

#[pyclass(name = "CoordinatorClient", module = "registry_coordinator_client")]
struct CoordinatorClient {
    inner: RustClient,
    runtime: tokio::runtime::Runtime,
}

#[pymethods]
impl CoordinatorClient {
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
        let base_url = Url::parse(base_url).map_err(|_| invalid_configuration(py))?;
        let mut config = CoordinatorClientConfig::new(base_url);
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

    fn start<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        idempotency_key: &str,
        request: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let request: StartRunRequest = input(py, request)?;
        complete(
            py,
            py.detach(|| {
                self.runtime
                    .block_on(self.inner.start(&token, idempotency_key, &request))
            }),
        )
    }

    fn status<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        run_id_value: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let run = run_id(py, run_id_value)?;
        complete(
            py,
            py.detach(|| self.runtime.block_on(self.inner.status(&token, run))),
        )
    }

    fn inspect<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        run_id_value: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let run = run_id(py, run_id_value)?;
        complete(
            py,
            py.detach(|| self.runtime.block_on(self.inner.inspect(&token, run))),
        )
    }

    fn reconcile<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        run_id_value: &str,
        reason: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let run = run_id(py, run_id_value)?;
        complete(
            py,
            py.detach(|| {
                self.runtime
                    .block_on(self.inner.reconcile(&token, run, reason))
            }),
        )
    }

    fn list<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        limit: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let limit = list_limit(py, limit)?;
        complete(
            py,
            py.detach(|| self.runtime.block_on(self.inner.list(&token, limit))),
        )
    }

    fn retry_same<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        run_id_value: &str,
        reason: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let run = run_id(py, run_id_value)?;
        complete(
            py,
            py.detach(|| {
                self.runtime
                    .block_on(self.inner.retry_same(&token, run, reason))
            }),
        )
    }

    fn cancel<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        run_id_value: &str,
        reason: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let run = run_id(py, run_id_value)?;
        complete(
            py,
            py.detach(|| {
                self.runtime
                    .block_on(self.inner.cancel(&token, run, reason))
            }),
        )
    }
}

#[pymodule]
fn registry_coordinator_client(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<CoordinatorClient>()?;
    module.add(
        "CoordinatorClientError",
        module.py().get_type::<CoordinatorClientError>(),
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
                Ok(CoordinatorComplete {
                    value: Unconvertible,
                }),
            )
            .expect_err("an unconvertible answer is refused");
            assert!(error.is_instance_of::<CoordinatorClientError>(py));
            let error = error.value(py);
            let attribute = |name: &str| error.getattr(name).expect("the attribute is set");
            assert_eq!(attribute("kind").extract::<String>().unwrap(), "protocol");
            assert!(attribute("outcome_unknown").extract::<bool>().unwrap());
            assert_eq!(error.to_string(), "Registry Coordinator client failed");
        });
    }
}
