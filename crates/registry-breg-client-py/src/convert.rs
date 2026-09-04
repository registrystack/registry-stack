// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, sync::Arc, time::Duration};

use breg_client_sdk::{
    BaseRegistryClientConfig, PrivateKeyJwt, PrivateKeyJwtConfig, StaticToken, TokenError,
    TokenProvider, MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES,
};
use pyo3::{
    prelude::*,
    types::{PyBool, PyBytes, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple},
    IntoPyObjectExt,
};
use registry_platform_crypto::PrivateJwk;
use serde::Serialize;
use serde_json::{Map, Value};
use url::Url;

const MAX_JSON_DEPTH: usize = 128;
const MAX_JSON_NODES: usize = 100_000;
const MAX_JSON_STRING_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug)]
pub struct ConversionError(String);

impl ConversionError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    pub fn message(&self) -> &str {
        &self.0
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
            return Err(ConversionError::new(
                "the Python object graph exceeds the conversion node bound",
            ));
        }
        Ok(())
    }

    fn count_string(&mut self, value: &str) -> Result<(), ConversionError> {
        self.string_bytes = self.string_bytes.saturating_add(value.len());
        if self.string_bytes > MAX_JSON_STRING_BYTES {
            return Err(ConversionError::new(
                "the Python object graph exceeds the conversion text bound",
            ));
        }
        Ok(())
    }

    fn enter(&mut self, value: &Bound<'_, PyAny>) -> Result<usize, ConversionError> {
        let identity = value.as_ptr() as usize;
        if !self.active.insert(identity) {
            return Err(ConversionError::new(
                "a cyclic Python object graph cannot be converted",
            ));
        }
        Ok(identity)
    }

    fn leave(&mut self, identity: usize) {
        self.active.remove(&identity);
    }
}

pub fn python_to_json(value: &Bound<'_, PyAny>) -> Result<Value, ConversionError> {
    python_to_json_at_depth(value, 1, &mut ConversionBudget::new())
}

fn python_to_json_at_depth(
    value: &Bound<'_, PyAny>,
    depth: usize,
    budget: &mut ConversionBudget,
) -> Result<Value, ConversionError> {
    if depth > MAX_JSON_DEPTH {
        return Err(ConversionError::new(format!(
            "a Python value nested more than {MAX_JSON_DEPTH} levels deep cannot be converted"
        )));
    }
    budget.visit()?;
    if value.is_none() {
        return Ok(Value::Null);
    }
    if let Ok(flag) = value.cast::<PyBool>() {
        return Ok(Value::Bool(flag.is_true()));
    }
    if let Ok(integer) = value.cast::<PyInt>() {
        let integer = integer
            .extract::<i64>()
            .map_err(|_| ConversionError::new("an integer value must fit in 64 bits"))?;
        return Ok(Value::from(integer));
    }
    if let Ok(float) = value.cast::<PyFloat>() {
        let float = float
            .extract::<f64>()
            .map_err(|_| ConversionError::new("a floating-point value could not be read"))?;
        return serde_json::Number::from_f64(float)
            .map(Value::Number)
            .ok_or_else(|| ConversionError::new("a floating-point value must be finite"));
    }
    if let Ok(text) = value.cast::<PyString>() {
        let text = text
            .to_str()
            .map_err(|_| ConversionError::new("a string value must be valid Unicode"))?;
        budget.count_string(text)?;
        return Ok(Value::String(text.to_owned()));
    }
    if let Ok(list) = value.cast::<PyList>() {
        let identity = budget.enter(value)?;
        let result = list
            .iter()
            .map(|item| python_to_json_at_depth(&item, depth + 1, budget))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array);
        budget.leave(identity);
        return result;
    }
    if let Ok(tuple) = value.cast::<PyTuple>() {
        let identity = budget.enter(value)?;
        let result = tuple
            .iter()
            .map(|item| python_to_json_at_depth(&item, depth + 1, budget))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array);
        budget.leave(identity);
        return result;
    }
    if let Ok(dict) = value.cast::<PyDict>() {
        let identity = budget.enter(value)?;
        let mut object = Map::new();
        let result = (|| {
            for (key, value) in dict.iter() {
                let key = key
                    .cast::<PyString>()
                    .map_err(|_| ConversionError::new("a mapping key must be a string"))?
                    .to_str()
                    .map_err(|_| ConversionError::new("a mapping key must be valid Unicode"))?;
                budget.count_string(key)?;
                object.insert(
                    key.to_owned(),
                    python_to_json_at_depth(&value, depth + 1, budget)?,
                );
            }
            Ok(Value::Object(object))
        })();
        budget.leave(identity);
        return result;
    }
    Err(ConversionError::new(
        "a value of this Python type cannot be converted",
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
                    "a JSON number could not be represented in Python",
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

fn require_only_fields(
    value: &Map<String, Value>,
    allowed: &[&str],
    what: &str,
) -> Result<(), ConversionError> {
    if value.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(ConversionError::new(format!(
            "{what} carries an unsupported field"
        )));
    }
    Ok(())
}

fn required_string(
    value: &Map<String, Value>,
    field: &str,
    what: &str,
) -> Result<String, ConversionError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| ConversionError::new(format!("{what}[\"{field}\"] must be a string")))
}

fn optional_string(
    value: &Map<String, Value>,
    field: &str,
    what: &str,
) -> Result<Option<String>, ConversionError> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(ConversionError::new(format!(
            "{what}[\"{field}\"] must be a string"
        ))),
    }
}

fn optional_i64(
    value: &Map<String, Value>,
    field: &str,
    what: &str,
) -> Result<Option<i64>, ConversionError> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_i64().map(Some).ok_or_else(|| {
            ConversionError::new(format!("{what}[\"{field}\"] must be a 64-bit integer"))
        }),
    }
}

fn optional_f64(
    value: &Map<String, Value>,
    field: &str,
    what: &str,
) -> Result<Option<f64>, ConversionError> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_f64()
            .map(Some)
            .ok_or_else(|| ConversionError::new(format!("{what}[\"{field}\"] must be a number"))),
    }
}

fn duration(value: f64, what: &str) -> Result<Duration, ConversionError> {
    Duration::try_from_secs_f64(value).map_err(|_| {
        ConversionError::new(format!(
            "{what} must be a finite non-negative number of seconds"
        ))
    })
}

pub fn authorization_from_python(
    value: Option<&Bound<'_, PyAny>>,
) -> Result<(Value, Option<Vec<u8>>), ConversionError> {
    let Some(value) = value else {
        return Ok((Value::Null, None));
    };
    let Ok(outer) = value.cast::<PyDict>() else {
        return python_to_json(value).map(|value| (value, None));
    };
    if outer.len() != 1 {
        return python_to_json(value).map(|value| (value, None));
    }
    let Some(private) = outer
        .get_item("private_key_jwt")
        .map_err(|_| ConversionError::new("authorization could not be read"))?
    else {
        return python_to_json(value).map(|value| (value, None));
    };
    let private = private
        .cast::<PyDict>()
        .map_err(|_| ConversionError::new("private_key_jwt must be a mapping"))?;
    let safe = PyDict::new(value.py());
    let mut trusted = None;
    for (key, value) in private.iter() {
        let key = key
            .cast::<PyString>()
            .map_err(|_| ConversionError::new("a mapping key must be a string"))?
            .to_str()
            .map_err(|_| ConversionError::new("a mapping key must be valid Unicode"))?;
        if key == "trusted_root_certificates" {
            if value.is_none() {
                continue;
            }
            let bytes = value.cast::<PyBytes>().map_err(|_| {
                ConversionError::new(
                "authorization[\"private_key_jwt\"][\"trusted_root_certificates\"] must be bytes",
            )
            })?;
            if bytes.as_bytes().len() > MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES {
                return Err(ConversionError::new(
                    "private-key JWT trusted roots exceed the accepted byte bound",
                ));
            }
            trusted = Some(bytes.as_bytes().to_vec());
        } else {
            safe.set_item(key, value)
                .map_err(|_| ConversionError::new("authorization could not be copied"))?;
        }
    }
    let config = python_to_json(safe.as_any())?;
    let mut result = Map::new();
    result.insert("private_key_jwt".to_owned(), config);
    Ok((Value::Object(result), trusted))
}

#[derive(Debug)]
pub enum ConfigError {
    Shape(ConversionError),
    Token(TokenError),
}

impl From<ConversionError> for ConfigError {
    fn from(value: ConversionError) -> Self {
        Self::Shape(value)
    }
}

fn private_key_jwt(value: &Value, roots: Option<Vec<u8>>) -> Result<PrivateKeyJwt, ConfigError> {
    const WHAT: &str = "authorization[\"private_key_jwt\"]";
    let value = value
        .as_object()
        .ok_or_else(|| ConversionError::new(format!("{WHAT} must be an object")))?;
    require_only_fields(
        value,
        &[
            "token_endpoint",
            "client_id",
            "client_key",
            "audience",
            "assertion_lifetime_seconds",
            "refresh_margin_seconds",
            "request_timeout_seconds",
            "connect_timeout_seconds",
            "user_agent",
        ],
        WHAT,
    )?;
    let token_endpoint = Url::parse(&required_string(value, "token_endpoint", WHAT)?)
        .map_err(|_| ConversionError::new("the private-key JWT token endpoint is invalid"))?;
    let client_id = required_string(value, "client_id", WHAT)?;
    let key = value
        .get("client_key")
        .ok_or_else(|| ConversionError::new("the private-key JWT client key is required"))?;
    let key = PrivateJwk::parse(
        &serde_json::to_string(key)
            .map_err(|_| ConversionError::new("the private-key JWT client key is invalid"))?,
    )
    .map_err(|_| ConversionError::new("the private-key JWT client key is invalid"))?;
    let mut config = PrivateKeyJwtConfig::new(token_endpoint, client_id, key);
    if let Some(value) = optional_string(value, "audience", WHAT)? {
        config = config.with_audience(value);
    }
    if let Some(value) = optional_i64(value, "assertion_lifetime_seconds", WHAT)? {
        config = config.with_assertion_lifetime_seconds(value);
    }
    if let Some(value) = optional_i64(value, "refresh_margin_seconds", WHAT)? {
        config = config.with_refresh_margin_seconds(value);
    }
    if let Some(value) = optional_f64(value, "request_timeout_seconds", WHAT)? {
        config = config.with_request_timeout(duration(value, "private-key JWT request timeout")?);
    }
    if let Some(value) = optional_f64(value, "connect_timeout_seconds", WHAT)? {
        config = config.with_connect_timeout(duration(value, "private-key JWT connect timeout")?);
    }
    if let Some(value) = optional_string(value, "user_agent", WHAT)? {
        config = config.with_user_agent(value);
    }
    if let Some(value) = roots {
        config = config.with_trusted_root_certificates(value);
    }
    PrivateKeyJwt::new(config).map_err(ConfigError::Token)
}

fn authorization_provider(
    value: &Value,
    roots: Option<Vec<u8>>,
) -> Result<Option<Arc<dyn TokenProvider>>, ConfigError> {
    match value {
        Value::Null => Ok(None),
        Value::Object(value) if value.len() == 1 => {
            if let Some(value) = value.get("static") {
                let token = value.as_str().ok_or_else(|| {
                    ConversionError::new("authorization[\"static\"] must be a string")
                })?;
                return Ok(Some(Arc::new(
                    StaticToken::new(token).map_err(ConfigError::Token)?,
                )));
            }
            if let Some(value) = value.get("private_key_jwt") {
                return Ok(Some(Arc::new(private_key_jwt(value, roots)?)));
            }
            Err(ConversionError::new(
                "authorization must contain exactly static or private_key_jwt",
            )
            .into())
        }
        _ => Err(ConversionError::new(
            "authorization must be null or a mapping containing exactly static or private_key_jwt",
        )
        .into()),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn config_from_parts(
    base_url: &str,
    authorization: &Value,
    roots: Option<Vec<u8>>,
    request_timeout_seconds: Option<f64>,
    connect_timeout_seconds: Option<f64>,
    user_agent: Option<String>,
    max_response_bytes: Option<u64>,
    trusted_root_certificates: Option<Vec<u8>>,
) -> Result<BaseRegistryClientConfig, ConfigError> {
    let base_url =
        Url::parse(base_url).map_err(|_| ConversionError::new("base_url must be a valid URL"))?;
    let mut config = BaseRegistryClientConfig::new(base_url);
    if let Some(provider) = authorization_provider(authorization, roots)? {
        config = config.with_token_provider(provider);
    }
    if let Some(value) = request_timeout_seconds {
        config = config.with_request_timeout(duration(value, "request_timeout_seconds")?);
    }
    if let Some(value) = connect_timeout_seconds {
        config = config.with_connect_timeout(duration(value, "connect_timeout_seconds")?);
    }
    if let Some(value) = user_agent {
        config = config.with_user_agent(value);
    }
    if let Some(value) = max_response_bytes {
        config = config.with_max_response_bytes(value);
    }
    if let Some(value) = trusted_root_certificates {
        config = config.with_trusted_root_certificates(value);
    }
    Ok(config)
}
