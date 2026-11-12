// SPDX-License-Identifier: Apache-2.0
//! Bounded Python access to `registry-platform-yaml`.

#![deny(unsafe_code)]

mod formats;

use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyTuple};
use pyo3::IntoPyObjectExt;
use serde_json::Value;
use yaml_core::{
    ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader, Report, MAXIMUM_DIAGNOSTICS_PER_FILE,
};

#[cfg(feature = "schema")]
pub use formats::schema_documents;
pub use formats::{
    read_dev_picker_descriptor, read_dev_picker_generation, read_dev_picker_token,
    read_dev_workload_token, read_python_connection, DevPickerDescriptor, DevPickerGeneration,
    DevPickerToken, DevWorkloadToken, PythonConnection, DEV_PICKER_DESCRIPTOR_API_VERSION,
    DEV_PICKER_DESCRIPTOR_FORMAT, DEV_PICKER_DESCRIPTOR_KIND, DEV_PICKER_DESCRIPTOR_SCHEMA_FILE,
    DEV_PICKER_DESCRIPTOR_SCHEMA_ID, DEV_PICKER_GENERATION_API_VERSION,
    DEV_PICKER_GENERATION_FORMAT, DEV_PICKER_GENERATION_KIND, DEV_PICKER_GENERATION_SCHEMA_FILE,
    DEV_PICKER_GENERATION_SCHEMA_ID, DEV_PICKER_TOKEN_API_VERSION, DEV_PICKER_TOKEN_FORMAT,
    DEV_PICKER_TOKEN_KIND, DEV_PICKER_TOKEN_SCHEMA_FILE, DEV_PICKER_TOKEN_SCHEMA_ID,
    DEV_WORKLOAD_TOKEN_API_VERSION, DEV_WORKLOAD_TOKEN_KIND, DEV_WORKLOAD_TOKEN_SCHEMA_FILE,
    DEV_WORKLOAD_TOKEN_SCHEMA_ID, PYTHON_CONNECTION_API_VERSION, PYTHON_CONNECTION_KIND,
    PYTHON_CONNECTION_SCHEMA_FILE, PYTHON_CONNECTION_SCHEMA_ID,
};

const MAXIMUM_FILE_BYTES: usize = 4 * 1024;
const MAXIMUM_FORMAT_BYTES: usize = 256;

pyo3::create_exception!(
    registry_platform_yaml,
    ConfigReadError,
    PyException,
    "A configuration document was refused with value-free diagnostics."
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Argument {
    File,
    ApiVersion,
    Kind,
}

impl Argument {
    const fn name(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::ApiVersion => "api_version",
            Self::Kind => "kind",
        }
    }
}

fn validate_file(file: &str) -> Result<(), Argument> {
    if file.is_empty() || file.len() > MAXIMUM_FILE_BYTES || file.chars().any(char::is_control) {
        return Err(Argument::File);
    }
    Ok(())
}

fn validate_format_parameter(value: &str, argument: Argument) -> Result<(), Argument> {
    if value.is_empty()
        || value.len() > MAXIMUM_FORMAT_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(argument);
    }
    Ok(())
}

fn read_checked(
    contents: &[u8],
    file: &str,
    api_version: &str,
    kind: &str,
) -> Result<Value, Report> {
    if (api_version, kind) == (PYTHON_CONNECTION_API_VERSION, PYTHON_CONNECTION_KIND) {
        return read_python_connection(file, contents);
    }
    if (api_version, kind) == (DEV_WORKLOAD_TOKEN_API_VERSION, DEV_WORKLOAD_TOKEN_KIND) {
        return read_dev_workload_token(file, contents);
    }
    if (api_version, kind)
        == (
            DEV_PICKER_DESCRIPTOR_API_VERSION,
            DEV_PICKER_DESCRIPTOR_KIND,
        )
    {
        return read_dev_picker_descriptor(file, contents);
    }
    if (api_version, kind) == (DEV_PICKER_TOKEN_API_VERSION, DEV_PICKER_TOKEN_KIND) {
        return read_dev_picker_token(file, contents);
    }
    if (api_version, kind)
        == (
            DEV_PICKER_GENERATION_API_VERSION,
            DEV_PICKER_GENERATION_KIND,
        )
    {
        return read_dev_picker_generation(file, contents);
    }
    let api_versions = [ApiVersion::current(api_version)];
    let format = FormatSpec {
        kind,
        envelope: EnvelopeRule::ApiVersionKind {
            api_versions: &api_versions,
            retired_api_versions: &[],
        },
        removed_keys: &[],
    };
    Reader::new(file)
        .read(contents, &Expect::one(&format))
        .map(|document| document.to_json_value())
}

fn json_to_python<'py>(py: Python<'py>, value: &Value) -> PyResult<Bound<'py, PyAny>> {
    match value {
        Value::Null => Ok(py.None().into_bound(py)),
        Value::Bool(value) => value.into_bound_py_any(py),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                value.into_bound_py_any(py)
            } else if let Some(value) = value.as_u64() {
                value.into_bound_py_any(py)
            } else if let Some(value) = value.as_f64() {
                value.into_bound_py_any(py)
            } else {
                Err(PyValueError::new_err(
                    "a configuration number is not representable",
                ))
            }
        }
        Value::String(value) => value.as_str().into_bound_py_any(py),
        Value::Array(values) => {
            let values = values
                .iter()
                .map(|value| json_to_python(py, value))
                .collect::<PyResult<Vec<_>>>()?;
            Ok(PyList::new(py, values)?.into_any())
        }
        Value::Object(values) => {
            let result = PyDict::new(py);
            for (key, value) in values {
                result.set_item(key, json_to_python(py, value)?)?;
            }
            Ok(result.into_any())
        }
    }
}

fn config_error(py: Python<'_>, report: &Report) -> PyErr {
    debug_assert!(report.diagnostics().len() <= MAXIMUM_DIAGNOSTICS_PER_FILE + 1);
    let Value::Array(diagnostics) = report.to_json_value() else {
        unreachable!("a configuration report serializes as an array")
    };
    let diagnostics = diagnostics
        .iter()
        .map(|diagnostic| json_to_python(py, diagnostic))
        .collect::<PyResult<Vec<_>>>()
        .expect("a diagnostic has only representable JSON members");
    let diagnostics =
        PyTuple::new(py, diagnostics).expect("a bounded diagnostic tuple can be allocated");
    let error = ConfigReadError::new_err("Configuration document was refused");
    error
        .value(py)
        .setattr("diagnostics", diagnostics)
        .expect("a fresh exception accepts attributes");
    error
}

#[pyfunction(name = "read_document")]
#[pyo3(signature = (contents, *, file, api_version, kind))]
fn py_read_document(
    py: Python<'_>,
    contents: &Bound<'_, PyBytes>,
    file: &str,
    api_version: &str,
    kind: &str,
) -> PyResult<Py<PyAny>> {
    validate_file(file).map_err(|argument| {
        PyValueError::new_err(format!(
            "{} is invalid or exceeds its bound",
            argument.name()
        ))
    })?;
    validate_format_parameter(api_version, Argument::ApiVersion).map_err(|argument| {
        PyValueError::new_err(format!(
            "{} is invalid or exceeds its bound",
            argument.name()
        ))
    })?;
    validate_format_parameter(kind, Argument::Kind).map_err(|argument| {
        PyValueError::new_err(format!(
            "{} is invalid or exceeds its bound",
            argument.name()
        ))
    })?;
    let value = read_checked(contents.as_bytes(), file, api_version, kind)
        .map_err(|report| config_error(py, &report))?;
    Ok(json_to_python(py, &value)?.unbind())
}

#[cfg(test)]
mod tests;

#[pymodule]
fn registry_platform_yaml(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(py_read_document, module)?)?;
    module.add("ConfigReadError", module.py().get_type::<ConfigReadError>())?;
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
