// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

use pyo3::{
    prelude::*,
    types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple},
    IntoPyObjectExt,
};
use serde::Serialize;
use serde_json::{Map, Value};

const MAX_JSON_DEPTH: usize = 128;
const MAX_JSON_NODES: usize = 100_000;
const MAX_JSON_STRING_BYTES: usize = 4 * 1024 * 1024;

pub struct ConversionError(&'static str);

impl ConversionError {
    pub fn message(&self) -> &'static str {
        self.0
    }
}

struct ConversionBudget {
    nodes: usize,
    string_bytes: usize,
    active: HashSet<usize>,
}

impl ConversionBudget {
    fn new() -> Self {
        Self {
            nodes: 0,
            string_bytes: 0,
            active: HashSet::new(),
        }
    }

    fn visit(&mut self) -> Result<(), ConversionError> {
        self.nodes += 1;
        if self.nodes > MAX_JSON_NODES {
            return Err(ConversionError(
                "the Python object graph exceeds the conversion node bound",
            ));
        }
        Ok(())
    }

    fn count_string(&mut self, value: &str) -> Result<(), ConversionError> {
        self.string_bytes = self.string_bytes.saturating_add(value.len());
        if self.string_bytes > MAX_JSON_STRING_BYTES {
            return Err(ConversionError(
                "the Python object graph exceeds the conversion text bound",
            ));
        }
        Ok(())
    }

    fn enter(&mut self, value: &Bound<'_, PyAny>) -> Result<usize, ConversionError> {
        let identity = value.as_ptr() as usize;
        if !self.active.insert(identity) {
            return Err(ConversionError(
                "a cyclic Python object graph cannot be converted",
            ));
        }
        Ok(identity)
    }
}

pub fn python_to_json(value: &Bound<'_, PyAny>) -> Result<Value, ConversionError> {
    convert(value, 1, &mut ConversionBudget::new())
}

fn convert(
    value: &Bound<'_, PyAny>,
    depth: usize,
    budget: &mut ConversionBudget,
) -> Result<Value, ConversionError> {
    if depth > MAX_JSON_DEPTH {
        return Err(ConversionError("the Python value is nested too deeply"));
    }
    budget.visit()?;
    if value.is_none() {
        return Ok(Value::Null);
    }
    if let Ok(flag) = value.cast::<PyBool>() {
        return Ok(Value::Bool(flag.is_true()));
    }
    if let Ok(integer) = value.cast::<PyInt>() {
        if let Ok(value) = integer.extract::<i64>() {
            return Ok(Value::from(value));
        }
        if let Ok(value) = integer.extract::<u64>() {
            return Ok(Value::from(value));
        }
        return Err(ConversionError("an integer must fit in 64 bits"));
    }
    if let Ok(float) = value.cast::<PyFloat>() {
        let value = float
            .extract::<f64>()
            .map_err(|_| ConversionError("a floating-point value could not be read"))?;
        return serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or(ConversionError("a floating-point value must be finite"));
    }
    if let Ok(text) = value.cast::<PyString>() {
        let text = text
            .to_str()
            .map_err(|_| ConversionError("a string must be valid Unicode"))?;
        budget.count_string(text)?;
        return Ok(Value::String(text.to_owned()));
    }
    if let Ok(list) = value.cast::<PyList>() {
        let identity = budget.enter(value)?;
        let result = list
            .iter()
            .map(|item| convert(&item, depth + 1, budget))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array);
        budget.active.remove(&identity);
        return result;
    }
    if let Ok(tuple) = value.cast::<PyTuple>() {
        let identity = budget.enter(value)?;
        let result = tuple
            .iter()
            .map(|item| convert(&item, depth + 1, budget))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array);
        budget.active.remove(&identity);
        return result;
    }
    if let Ok(dict) = value.cast::<PyDict>() {
        let identity = budget.enter(value)?;
        let mut object = Map::new();
        let result = (|| {
            for (key, value) in dict.iter() {
                let key = key
                    .cast::<PyString>()
                    .map_err(|_| ConversionError("a mapping key must be a string"))?
                    .to_str()
                    .map_err(|_| ConversionError("a mapping key must be valid Unicode"))?;
                budget.count_string(key)?;
                object.insert(key.to_owned(), convert(&value, depth + 1, budget)?);
            }
            Ok(Value::Object(object))
        })();
        budget.active.remove(&identity);
        return result;
    }
    Err(ConversionError(
        "this Python value cannot be converted to JSON",
    ))
}

pub fn json_to_python<'py>(py: Python<'py>, value: &Value) -> PyResult<Bound<'py, PyAny>> {
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
                Err(pyo3::exceptions::PyValueError::new_err(
                    "a JSON number is not representable",
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

pub fn serialize_to_python<'py>(
    py: Python<'py>,
    value: &impl Serialize,
) -> PyResult<Bound<'py, PyAny>> {
    let value = serde_json::to_value(value).map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("an SDK result could not be serialized")
    })?;
    json_to_python(py, &value)
}
