// SPDX-License-Identifier: Apache-2.0
//! Synchronous Python binding over the bounded Registry Discovery Rust client.

use std::{collections::HashSet, time::Duration};

use discovery_client_sdk::{
    renew_unchanged_service_selection, validate_service_selection_structure,
    DiscoveryClient as CoreClient, DiscoveryClientConfig, DiscoveryClientError, DiscoveryProblem,
    EvidenceSelectionRequest, EvidenceServiceQuery, EvidenceTypeResolveRequest,
    EvidenceTypeResolveResponse, EvidenceTypeResolveSelectionExt, RelaySelectionRequest,
    RelayServiceQuery, SelectionRequest, ServiceFilters, ServiceSearchResponse,
    ServiceSearchSelectionExt, ServiceSelection,
};
use pyo3::{
    exceptions::{PyException, PyRuntimeError},
    prelude::*,
    types::{PyBool, PyBytes, PyDict, PyFloat, PyInt, PyList, PyString},
};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{Map, Value};

const MAXIMUM_CONVERSION_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_JSON_DEPTH: usize = 128;
const MAXIMUM_REQUEST_JSON_NODES: usize = 100_000;
// A valid 16 MiB result can contain far more collection nodes than a request.
const MAXIMUM_RESPONSE_JSON_NODES: usize = 3_000_000;
const MAXIMUM_REQUEST_JSON_STRING_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_RESPONSE_JSON_STRING_BYTES: usize = MAXIMUM_CONVERSION_BYTES;

pyo3::create_exception!(
    registry_discovery_client,
    DiscoveryClientErrorBase,
    PyException,
    "A bounded, value-free Registry Discovery client failure."
);

fn kind(error: &DiscoveryClientError) -> &'static str {
    match error {
        DiscoveryClientError::Configuration => "configuration",
        DiscoveryClientError::Query => "query",
        DiscoveryClientError::NoMatchingService => "no_matching_service",
        DiscoveryClientError::AmbiguousSelection => "ambiguous_selection",
        DiscoveryClientError::NoMatchingAlternative => "no_matching_alternative",
        DiscoveryClientError::AmbiguousAlternative => "ambiguous_alternative",
        DiscoveryClientError::CapabilityMismatch => "capability_mismatch",
        DiscoveryClientError::LocalAcceptanceRefused => "local_acceptance_refused",
        DiscoveryClientError::SelectionChanged => "selection_changed",
        DiscoveryClientError::Transport { .. } => "transport",
        DiscoveryClientError::Problem { .. } => "problem",
        DiscoveryClientError::Protocol => "protocol",
        _ => "client",
    }
}

fn problem_name(problem: DiscoveryProblem) -> &'static str {
    match problem {
        DiscoveryProblem::InvalidRequest => "invalid_request",
        DiscoveryProblem::NotFound => "not_found",
        DiscoveryProblem::ResultBoundExceeded => "result_bound_exceeded",
        DiscoveryProblem::Unavailable => "unavailable",
        _ => "unknown",
    }
}

fn client_error(py: Python<'_>, error: DiscoveryClientError) -> PyErr {
    let result = DiscoveryClientErrorBase::new_err(error.to_string());
    let instance = result.value(py);
    instance
        .setattr("kind", kind(&error))
        .expect("fresh exception");
    let (status, problem, transport_kind) = match error {
        DiscoveryClientError::Problem { status, problem } => {
            (Some(status), Some(problem_name(problem)), None)
        }
        DiscoveryClientError::Transport { kind } => (None, None, Some(kind.kind())),
        _ => (None, None, None),
    };
    instance.setattr("status", status).expect("fresh exception");
    instance
        .setattr("problem", problem)
        .expect("fresh exception");
    instance
        .setattr("transport_kind", transport_kind)
        .expect("fresh exception");
    result
}

#[derive(Debug)]
struct ConversionError;

struct ConversionBudget {
    nodes: usize,
    maximum_nodes: usize,
    string_bytes: usize,
    maximum_string_bytes: usize,
    active_containers: HashSet<usize>,
}

impl ConversionBudget {
    fn new(maximum_nodes: usize, maximum_string_bytes: usize) -> Self {
        Self {
            nodes: 0,
            maximum_nodes,
            string_bytes: 0,
            maximum_string_bytes,
            active_containers: HashSet::new(),
        }
    }

    fn visit(&mut self) -> Result<(), ConversionError> {
        self.nodes += 1;
        if self.nodes > self.maximum_nodes {
            return Err(ConversionError);
        }
        Ok(())
    }

    fn count_string(&mut self, value: &str) -> Result<(), ConversionError> {
        self.string_bytes = self.string_bytes.saturating_add(value.len());
        if self.string_bytes > self.maximum_string_bytes {
            return Err(ConversionError);
        }
        Ok(())
    }

    fn enter_container(&mut self, value: &Bound<'_, PyAny>) -> Result<usize, ConversionError> {
        let identity = value.as_ptr() as usize;
        if !self.active_containers.insert(identity) {
            return Err(ConversionError);
        }
        Ok(identity)
    }

    fn leave_container(&mut self, identity: usize) {
        self.active_containers.remove(&identity);
    }
}

/// Convert caller input through a deliberately small JSON bridge. It accepts
/// exact built-in JSON primitive, list, and dict values only. This rules out
/// custom encoders and conversion hooks before the value reaches the SDK.
fn python_to_json(value: &Bound<'_, PyAny>) -> Result<Value, ConversionError> {
    python_to_json_at_depth(
        value,
        1,
        &mut ConversionBudget::new(
            MAXIMUM_REQUEST_JSON_NODES,
            MAXIMUM_REQUEST_JSON_STRING_BYTES,
        ),
    )
}

fn python_response_to_json(value: &Bound<'_, PyAny>) -> Result<Value, ConversionError> {
    python_to_json_at_depth(
        value,
        1,
        &mut ConversionBudget::new(
            MAXIMUM_RESPONSE_JSON_NODES,
            MAXIMUM_RESPONSE_JSON_STRING_BYTES,
        ),
    )
}

fn python_to_json_at_depth(
    value: &Bound<'_, PyAny>,
    depth: usize,
    budget: &mut ConversionBudget,
) -> Result<Value, ConversionError> {
    if depth > MAXIMUM_JSON_DEPTH {
        return Err(ConversionError);
    }
    budget.visit()?;
    if value.is_none() {
        return Ok(Value::Null);
    }
    if value.is_exact_instance_of::<PyBool>() {
        return Ok(Value::Bool(
            value
                .cast::<PyBool>()
                .map_err(|_| ConversionError)?
                .is_true(),
        ));
    }
    if value.is_exact_instance_of::<PyInt>() {
        let integer = value.cast::<PyInt>().map_err(|_| ConversionError)?;
        let integer: i64 = integer.extract().map_err(|_| ConversionError)?;
        return Ok(Value::from(integer));
    }
    if value.is_exact_instance_of::<PyFloat>() {
        let float = value.cast::<PyFloat>().map_err(|_| ConversionError)?;
        let float: f64 = float.extract().map_err(|_| ConversionError)?;
        return serde_json::Number::from_f64(float)
            .map(Value::Number)
            .ok_or(ConversionError);
    }
    if value.is_exact_instance_of::<PyString>() {
        let text = value.cast::<PyString>().map_err(|_| ConversionError)?;
        let text = text.to_str().map_err(|_| ConversionError)?;
        budget.count_string(text)?;
        return Ok(Value::String(text.to_owned()));
    }
    if value.is_exact_instance_of::<PyList>() {
        let list = value.cast::<PyList>().map_err(|_| ConversionError)?;
        let identity = budget.enter_container(value)?;
        let result = list
            .iter()
            .map(|item| python_to_json_at_depth(&item, depth + 1, budget))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array);
        budget.leave_container(identity);
        return result;
    }
    if value.is_exact_instance_of::<PyDict>() {
        let dict = value.cast::<PyDict>().map_err(|_| ConversionError)?;
        let identity = budget.enter_container(value)?;
        let result = (|| {
            let mut object = Map::new();
            for (key, value) in dict.iter() {
                if !key.is_exact_instance_of::<PyString>() {
                    return Err(ConversionError);
                }
                let key = key
                    .cast::<PyString>()
                    .map_err(|_| ConversionError)?
                    .to_str()
                    .map_err(|_| ConversionError)?;
                budget.count_string(key)?;
                object.insert(
                    key.to_owned(),
                    python_to_json_at_depth(&value, depth + 1, budget)?,
                );
            }
            Ok(Value::Object(object))
        })();
        budget.leave_container(identity);
        return result;
    }
    Err(ConversionError)
}

fn python_to_rust<T: DeserializeOwned>(value: &Bound<'_, PyAny>) -> Result<T, ConversionError> {
    let value = python_to_json(value)?;
    deserialize_bounded(value)
}

fn python_response_to_rust<T: DeserializeOwned>(
    value: &Bound<'_, PyAny>,
) -> Result<T, ConversionError> {
    let value = python_response_to_json(value)?;
    deserialize_bounded(value)
}

fn deserialize_bounded<T: DeserializeOwned>(value: Value) -> Result<T, ConversionError> {
    let bytes = serde_json::to_vec(&value).map_err(|_| ConversionError)?;
    if bytes.len() > MAXIMUM_CONVERSION_BYTES {
        return Err(ConversionError);
    }
    serde_json::from_value(value).map_err(|_| ConversionError)
}

fn rust_to_python<'py, T: Serialize>(py: Python<'py>, value: &T) -> PyResult<Bound<'py, PyAny>> {
    let bytes = serde_json::to_vec(value).map_err(|_| protocol_error(py))?;
    if bytes.len() > MAXIMUM_CONVERSION_BYTES {
        return Err(protocol_error(py));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| protocol_error(py))?;
    py.import("json")
        .map_err(|_| protocol_error(py))?
        .call_method1("loads", (text,))
        .map_err(|_| protocol_error(py))
}

fn configuration_error(py: Python<'_>) -> PyErr {
    client_error(py, DiscoveryClientError::Configuration)
}

fn query_error(py: Python<'_>) -> PyErr {
    client_error(py, DiscoveryClientError::Query)
}

fn protocol_error(py: Python<'_>) -> PyErr {
    client_error(py, DiscoveryClientError::Protocol)
}

fn positive_duration(value: &Bound<'_, PyAny>) -> Result<Duration, ConversionError> {
    let seconds = if value.is_exact_instance_of::<PyFloat>() {
        value
            .cast::<PyFloat>()
            .map_err(|_| ConversionError)?
            .extract::<f64>()
            .map_err(|_| ConversionError)?
    } else if value.is_exact_instance_of::<PyInt>() {
        value
            .cast::<PyInt>()
            .map_err(|_| ConversionError)?
            .extract::<u64>()
            .map_err(|_| ConversionError)? as f64
    } else {
        return Err(ConversionError);
    };
    if !seconds.is_finite() || seconds <= 0.0 {
        return Err(ConversionError);
    }
    Duration::try_from_secs_f64(seconds).map_err(|_| ConversionError)
}

fn parse_maximum_response_bytes(value: &Bound<'_, PyAny>) -> Result<u64, ConversionError> {
    if !value.is_exact_instance_of::<PyInt>() {
        return Err(ConversionError);
    }
    value
        .cast::<PyInt>()
        .map_err(|_| ConversionError)?
        .extract::<u64>()
        .map_err(|_| ConversionError)
}

fn parse_trusted_root_certificates(value: &Bound<'_, PyAny>) -> Result<Vec<u8>, ConversionError> {
    if !value.is_exact_instance_of::<PyBytes>() {
        return Err(ConversionError);
    }
    let value = value.cast::<PyBytes>().map_err(|_| ConversionError)?;
    if value.as_bytes().len() > MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BYTES {
        return Err(ConversionError);
    }
    Ok(value.as_bytes().to_vec())
}

fn exact_selection<'py>(
    py: Python<'py>,
    response: &Bound<'_, PyAny>,
    request: &Bound<'_, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    let response: ServiceSearchResponse =
        python_response_to_rust(response).map_err(|_| query_error(py))?;
    let request: SelectionRequest = python_to_rust(request).map_err(|_| query_error(py))?;
    let selection = response
        .select_exact(request)
        .map_err(|error| client_error(py, error))?;
    rust_to_python(py, &selection)
}

#[pyfunction]
fn select_exact<'py>(
    py: Python<'py>,
    response: &Bound<'_, PyAny>,
    request: &Bound<'_, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    exact_selection(py, response, request)
}

fn evidence_alternative<'py>(
    py: Python<'py>,
    response: &Bound<'_, PyAny>,
    evidence_type_list_id: Option<&Bound<'_, PyAny>>,
) -> PyResult<Bound<'py, PyAny>> {
    let response: EvidenceTypeResolveResponse =
        python_response_to_rust(response).map_err(|_| query_error(py))?;
    let context = match evidence_type_list_id {
        Some(id) => {
            let id = id
                .cast::<PyString>()
                .map_err(|_| query_error(py))?
                .to_str()
                .map_err(|_| query_error(py))?;
            response.select_alternative(id)
        }
        None => response.select_only_alternative(),
    }
    .map_err(|error| client_error(py, error))?;
    rust_to_python(py, &context)
}

#[pyfunction]
#[pyo3(signature = (response, evidence_type_list_id=None))]
fn select_evidence_alternative<'py>(
    py: Python<'py>,
    response: &Bound<'_, PyAny>,
    evidence_type_list_id: Option<&Bound<'_, PyAny>>,
) -> PyResult<Bound<'py, PyAny>> {
    evidence_alternative(py, response, evidence_type_list_id)
}

#[pyfunction]
fn select_evidence_service<'py>(
    py: Python<'py>,
    response: &Bound<'_, PyAny>,
    request: &Bound<'_, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    let response: ServiceSearchResponse =
        python_response_to_rust(response).map_err(|_| query_error(py))?;
    let request: EvidenceSelectionRequest = python_to_rust(request).map_err(|_| query_error(py))?;
    let selection = response
        .select_evidence(request)
        .map_err(|error| client_error(py, error))?;
    rust_to_python(py, &selection)
}

#[pyfunction]
fn select_relay_service<'py>(
    py: Python<'py>,
    response: &Bound<'_, PyAny>,
    request: &Bound<'_, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    let response: ServiceSearchResponse =
        python_response_to_rust(response).map_err(|_| query_error(py))?;
    let request: RelaySelectionRequest = python_to_rust(request).map_err(|_| query_error(py))?;
    let selection = response
        .select_relay(request)
        .map_err(|error| client_error(py, error))?;
    rust_to_python(py, &selection)
}

#[pyfunction]
fn validate_selection_structure<'py>(
    py: Python<'py>,
    selection: &Bound<'_, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    let selection: ServiceSelection =
        python_response_to_rust(selection).map_err(|_| query_error(py))?;
    validate_service_selection_structure(&selection).map_err(|error| client_error(py, error))?;
    rust_to_python(py, &selection)
}

/// Deprecated compatibility alias for structural validation.
#[pyfunction]
fn validate_selection<'py>(
    py: Python<'py>,
    selection: &Bound<'_, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    validate_selection_structure(py, selection)
}

#[pyfunction]
fn renew_unchanged_selection<'py>(
    py: Python<'py>,
    previous: &Bound<'_, PyAny>,
    current: &Bound<'_, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    let previous: ServiceSelection =
        python_response_to_rust(previous).map_err(|_| query_error(py))?;
    let current: ServiceSelection =
        python_response_to_rust(current).map_err(|_| query_error(py))?;
    let renewed = renew_unchanged_service_selection(&previous, &current)
        .map_err(|error| client_error(py, error))?;
    rust_to_python(py, &renewed)
}

#[pyclass(
    name = "AcceptedServiceSelection",
    module = "registry_discovery_client",
    frozen,
    generic
)]
struct AcceptedServiceSelection {
    selection: ServiceSelection,
}

#[pymethods]
impl AcceptedServiceSelection {
    #[getter]
    fn endpoint_url(&self) -> &str {
        &self.selection.endpoint_url
    }

    #[getter]
    fn selection<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        rust_to_python(py, &self.selection)
    }
}

#[pyfunction]
fn accept_selection(
    py: Python<'_>,
    selection: &Bound<'_, PyAny>,
    accepts: &Bound<'_, PyAny>,
) -> PyResult<AcceptedServiceSelection> {
    let selection: ServiceSelection =
        python_response_to_rust(selection).map_err(|_| query_error(py))?;
    validate_service_selection_structure(&selection).map_err(|error| client_error(py, error))?;
    if !accepts.is_callable() {
        return Err(query_error(py));
    }
    let candidate = rust_to_python(py, &selection)?;
    let accepted = accepts.call1((candidate,))?;
    if !accepted.is_exact_instance_of::<PyBool>() {
        return Err(query_error(py));
    }
    if !accepted.extract::<bool>()? {
        return Err(client_error(
            py,
            DiscoveryClientError::LocalAcceptanceRefused,
        ));
    }
    Ok(AcceptedServiceSelection { selection })
}

#[pyclass(name = "DiscoveryClient", module = "registry_discovery_client")]
struct DiscoveryClient {
    inner: CoreClient,
    runtime: tokio::runtime::Runtime,
}

#[pymethods]
impl DiscoveryClient {
    #[new]
    #[pyo3(signature = (
        base_url,
        request_timeout_seconds=None,
        connect_timeout_seconds=None,
        maximum_response_bytes=None,
        trusted_root_certificates=None,
    ))]
    fn new(
        py: Python<'_>,
        base_url: &Bound<'_, PyAny>,
        request_timeout_seconds: Option<&Bound<'_, PyAny>>,
        connect_timeout_seconds: Option<&Bound<'_, PyAny>>,
        maximum_response_bytes: Option<&Bound<'_, PyAny>>,
        trusted_root_certificates: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        if !base_url.is_exact_instance_of::<PyString>() {
            return Err(configuration_error(py));
        }
        let base_url = base_url
            .cast::<PyString>()
            .map_err(|_| configuration_error(py))?
            .to_str()
            .map_err(|_| configuration_error(py))?;
        if base_url.len() > MAXIMUM_CONVERSION_BYTES {
            return Err(configuration_error(py));
        }
        let base_url = url::Url::parse(base_url).map_err(|_| configuration_error(py))?;
        let mut config = DiscoveryClientConfig::new(base_url);
        if let Some(timeout) = request_timeout_seconds {
            config = config.with_request_timeout(
                positive_duration(timeout).map_err(|_| configuration_error(py))?,
            );
        }
        if let Some(timeout) = connect_timeout_seconds {
            config = config.with_connect_timeout(
                positive_duration(timeout).map_err(|_| configuration_error(py))?,
            );
        }
        if let Some(maximum) = maximum_response_bytes {
            config = config.with_maximum_response_bytes(
                parse_maximum_response_bytes(maximum).map_err(|_| configuration_error(py))?,
            );
        }
        if let Some(certificates) = trusted_root_certificates {
            config = config.with_trusted_root_certificates(
                parse_trusted_root_certificates(certificates)
                    .map_err(|_| configuration_error(py))?,
            );
        }
        let inner = CoreClient::new(config).map_err(|error| client_error(py, error))?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| PyRuntimeError::new_err("the Discovery client runtime could not start"))?;
        Ok(Self { inner, runtime })
    }

    fn resolve_evidence_types<'py>(
        &self,
        py: Python<'py>,
        request: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let request: EvidenceTypeResolveRequest =
            python_to_rust(request).map_err(|_| query_error(py))?;
        let response = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.resolve_evidence_types(request))
            })
            .map_err(|error| client_error(py, error))?;
        rust_to_python(py, &response)
    }

    fn search_services<'py>(
        &self,
        py: Python<'py>,
        filters: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let filters: ServiceFilters = python_to_rust(filters).map_err(|_| query_error(py))?;
        let response = py
            .detach(|| self.runtime.block_on(self.inner.search_services(filters)))
            .map_err(|error| client_error(py, error))?;
        rust_to_python(py, &response)
    }

    fn search_evidence_services<'py>(
        &self,
        py: Python<'py>,
        query: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let query: EvidenceServiceQuery = python_to_rust(query).map_err(|_| query_error(py))?;
        let response = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.search_evidence_services(query))
            })
            .map_err(|error| client_error(py, error))?;
        rust_to_python(py, &response)
    }

    fn search_relay_services<'py>(
        &self,
        py: Python<'py>,
        query: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let query: RelayServiceQuery = python_to_rust(query).map_err(|_| query_error(py))?;
        let response = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.search_relay_services(query))
            })
            .map_err(|error| client_error(py, error))?;
        rust_to_python(py, &response)
    }

    fn select_exact<'py>(
        &self,
        py: Python<'py>,
        response: &Bound<'_, PyAny>,
        request: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        exact_selection(py, response, request)
    }

    #[pyo3(signature = (response, evidence_type_list_id=None))]
    fn select_evidence_alternative<'py>(
        &self,
        py: Python<'py>,
        response: &Bound<'_, PyAny>,
        evidence_type_list_id: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        evidence_alternative(py, response, evidence_type_list_id)
    }

    fn select_evidence_service<'py>(
        &self,
        py: Python<'py>,
        response: &Bound<'_, PyAny>,
        request: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        select_evidence_service(py, response, request)
    }

    fn select_relay_service<'py>(
        &self,
        py: Python<'py>,
        response: &Bound<'_, PyAny>,
        request: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        select_relay_service(py, response, request)
    }
}

#[pymodule]
pub fn registry_discovery_client(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<DiscoveryClient>()?;
    module.add_class::<AcceptedServiceSelection>()?;
    module.add_function(wrap_pyfunction!(select_exact, module)?)?;
    module.add_function(wrap_pyfunction!(select_evidence_alternative, module)?)?;
    module.add_function(wrap_pyfunction!(select_evidence_service, module)?)?;
    module.add_function(wrap_pyfunction!(select_relay_service, module)?)?;
    module.add_function(wrap_pyfunction!(validate_selection_structure, module)?)?;
    module.add_function(wrap_pyfunction!(validate_selection, module)?)?;
    module.add_function(wrap_pyfunction!(renew_unchanged_selection, module)?)?;
    module.add_function(wrap_pyfunction!(accept_selection, module)?)?;
    module.add(
        "DiscoveryClientError",
        module.py().get_type::<DiscoveryClientErrorBase>(),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_closed_output_maps_to_a_stable_protocol_error() {
        Python::attach(|py| {
            let value = "x".repeat(MAXIMUM_CONVERSION_BYTES + 1);
            let error = rust_to_python(py, &value).expect_err("the conversion bound rejects it");
            let instance = error.value(py);
            let kind: String = instance
                .getattr("kind")
                .expect("the exception carries its stable kind")
                .extract()
                .expect("kind is text");
            assert_eq!(kind, "protocol");
            assert_eq!(
                error.to_string(),
                "DiscoveryClientErrorBase: the Discovery response did not satisfy its closed wire contract"
            );
        });
    }
}
