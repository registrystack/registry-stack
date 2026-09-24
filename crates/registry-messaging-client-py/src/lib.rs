// SPDX-License-Identifier: Apache-2.0
//! Synchronous Python binding for the canonical Registry Messaging client.

#![deny(unsafe_code)]

use std::time::Duration;

use messaging_client_sdk::{
    BearerToken, MessagingClient as RustClient, MessagingClientConfig,
    MessagingClientError as RustClientError, MessagingComplete, MessagingProtocolFailure,
    ProblemCode, SubmitMessageRequest,
};
use pyo3::{
    exceptions::{PyException, PyRuntimeError},
    prelude::*,
    types::PyDict,
};
use serde::{de::DeserializeOwned, Serialize};
use url::Url;

mod convert;

use convert::{python_to_json, serialize_to_python};

pyo3::create_exception!(
    registry_messaging_client,
    MessagingClientError,
    PyException,
    "A stable, value-free Registry Messaging client failure."
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
}

fn to_py_err(py: Python<'_>, mapped: MappedError) -> PyErr {
    let error = MessagingClientError::new_err(mapped.message);
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
    let mapped = match error {
        RustClientError::Configuration { .. } => MappedError {
            kind: "configuration",
            message: "Messaging client configuration is invalid".to_owned(),
            ..MappedError::default()
        },
        RustClientError::InvalidRequest { .. } => MappedError {
            kind: "invalid_request",
            message: "Messaging client arguments are invalid".to_owned(),
            ..MappedError::default()
        },
        RustClientError::Transport { kind } => MappedError {
            kind: "transport",
            message: "Registry Messaging exchange did not complete".to_owned(),
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
            message: "Registry Messaging returned an invalid response".to_owned(),
            status: Some(status),
            trace_id,
            protocol_failure: Some(protocol_failure(failure)),
            ..MappedError::default()
        },
        _ => MappedError {
            kind: "protocol",
            message: "Registry Messaging client failed".to_owned(),
            ..MappedError::default()
        },
    };
    to_py_err(py, mapped)
}

fn protocol_failure(failure: MessagingProtocolFailure) -> &'static str {
    match failure {
        MessagingProtocolFailure::HeaderBounds => "header_bounds",
        MessagingProtocolFailure::TraceContext => "trace_context",
        MessagingProtocolFailure::MediaType => "media_type",
        MessagingProtocolFailure::Body => "body",
        MessagingProtocolFailure::Problem => "problem",
        MessagingProtocolFailure::Status => "status",
        _ => "protocol",
    }
}

fn input<T: DeserializeOwned>(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<T> {
    let value = python_to_json(value).map_err(|error| {
        let _ = error.message();
        binding_error(
            py,
            "invalid_request",
            "Messaging client arguments are invalid",
        )
    })?;
    serde_json::from_value(value).map_err(|_| {
        binding_error(
            py,
            "invalid_request",
            "Messaging client arguments are invalid",
        )
    })
}

fn bearer(py: Python<'_>, value: &str) -> PyResult<BearerToken> {
    BearerToken::new(value.to_owned())
        .map_err(|_| binding_error(py, "invalid_request", "the bearer token is invalid"))
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
    result: Result<MessagingComplete<T>, RustClientError>,
) -> PyResult<Bound<'py, PyAny>> {
    let complete = result.map_err(|error| client_error(py, error))?;
    let value = PyDict::new(py);
    value.set_item("kind", "complete")?;
    value.set_item("value", serialize_to_python(py, &complete.value)?)?;
    value.set_item("trace_id", complete.trace_id)?;
    Ok(value.into_any())
}

#[pyclass(name = "MessagingClient", module = "registry_messaging_client")]
struct MessagingClient {
    inner: RustClient,
    runtime: tokio::runtime::Runtime,
}

#[pymethods]
impl MessagingClient {
    #[new]
    #[pyo3(signature = (base_url, request_timeout_seconds=None, connect_timeout_seconds=None, max_response_bytes=None, user_agent=None, trusted_root_certificates=None))]
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
                "Messaging client configuration is invalid",
            )
        })?;
        let mut config = MessagingClientConfig::new(base_url);
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

    fn health<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        complete(py, py.detach(|| self.runtime.block_on(self.inner.health())))
    }

    fn ready<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        complete(py, py.detach(|| self.runtime.block_on(self.inner.ready())))
    }

    fn submit<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        idempotency_key: &str,
        request: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        let request: SubmitMessageRequest = input(py, request)?;
        complete(
            py,
            py.detach(|| {
                self.runtime
                    .block_on(self.inner.submit(&token, idempotency_key, &request))
            }),
        )
    }

    fn message<'py>(
        &self,
        py: Python<'py>,
        token: &str,
        message_id: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let token = bearer(py, token)?;
        complete(
            py,
            py.detach(|| {
                self.runtime
                    .block_on(self.inner.message(&token, message_id))
            }),
        )
    }
}

#[pymodule]
fn registry_messaging_client(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<MessagingClient>()?;
    module.add(
        "MessagingClientError",
        module.py().get_type::<MessagingClientError>(),
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
