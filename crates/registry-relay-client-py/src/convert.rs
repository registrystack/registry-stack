// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, sync::Arc, time::Duration};

use pyo3::{
    prelude::*,
    types::{PyBool, PyBytes, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple},
    IntoPyObjectExt,
};
use registry_platform_crypto::PrivateJwk;
use relay_client_sdk::{
    PrivateKeyJwt, PrivateKeyJwtConfig, ProtocolFailure, RelayClientConfig, RelayClientError,
    StaticToken, TokenError, TokenProvider, MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES,
};
use serde::Serialize;
use serde_json::{Map, Value};
use url::Url;

const MAX_JSON_DEPTH: usize = 128;
const MAX_JSON_NODES: usize = 100_000;
const MAX_JSON_STRING_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConversionError {
    message: String,
}

impl ConversionError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

struct ConversionBudget {
    nodes: usize,
    string_bytes: usize,
    active_containers: HashSet<usize>,
}

impl ConversionBudget {
    fn new() -> Self {
        Self {
            nodes: 0,
            string_bytes: 0,
            active_containers: HashSet::new(),
        }
    }

    fn visit(&mut self) -> Result<(), ConversionError> {
        self.nodes += 1;
        if self.nodes > MAX_JSON_NODES {
            return Err(ConversionError::new(
                "the Python object graph exceeds the conversion size bound",
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

    fn enter_container(&mut self, value: &Bound<'_, PyAny>) -> Result<usize, ConversionError> {
        let identity = value.as_ptr() as usize;
        if !self.active_containers.insert(identity) {
            return Err(ConversionError::new(
                "a cyclic Python object graph cannot be converted",
            ));
        }
        Ok(identity)
    }

    fn leave_container(&mut self, identity: usize) {
        self.active_containers.remove(&identity);
    }
}

/// Convert only ordinary JSON-shaped Python values, under explicit graph,
/// depth, and text bounds. Container identity tracking rejects cycles before
/// they can consume the depth budget.
pub fn python_to_json(value: &Bound<'_, PyAny>) -> Result<Value, ConversionError> {
    python_to_json_at_depth(value, 1, &mut ConversionBudget::new())
}

/// Convert the authorization shape without teaching the general JSON bridge
/// about bytes. The one byte-valued field is kept outside the JSON graph and
/// handed only to the shared private-key-JWT HTTP client builder.
pub fn authorization_from_python(
    value: Option<&Bound<'_, PyAny>>,
) -> Result<(Value, Option<Vec<u8>>), ConversionError> {
    const PRIVATE_KEY_JWT_FIELDS: &[&str] = &[
        "token_endpoint",
        "client_id",
        "client_key",
        "audience",
        "assertion_lifetime_seconds",
        "refresh_margin_seconds",
        "request_timeout_seconds",
        "connect_timeout_seconds",
        "user_agent",
        "trusted_root_certificates",
    ];
    let Some(value) = value else {
        return Ok((Value::Null, None));
    };
    let Ok(outer) = value.cast::<PyDict>() else {
        return python_to_json(value).map(|value| (value, None));
    };
    if outer.len() != 1 {
        return python_to_json(value).map(|value| (value, None));
    }
    let Some(private_key_jwt) = outer
        .get_item("private_key_jwt")
        .map_err(|_| ConversionError::new("authorization could not be read"))?
    else {
        return python_to_json(value).map(|value| (value, None));
    };
    let Ok(private_key_jwt) = private_key_jwt.cast::<PyDict>() else {
        return python_to_json(value).map(|value| (value, None));
    };

    let mut budget = ConversionBudget::new();
    budget.visit()?;
    let outer_identity = budget.enter_container(value)?;
    budget.visit()?;
    let config_identity = budget.enter_container(private_key_jwt.as_any())?;
    for (key, _) in private_key_jwt.iter() {
        let key = key
            .cast::<PyString>()
            .map_err(|_| ConversionError::new("a mapping key must be a string"))?
            .to_str()
            .map_err(|_| ConversionError::new("a mapping key must be valid Unicode"))?;
        budget.count_string(key)?;
        if !PRIVATE_KEY_JWT_FIELDS.contains(&key) {
            return Err(ConversionError::new(
                "authorization[\"private_key_jwt\"] carries an unsupported field",
            ));
        }
    }
    let Some(trusted_roots) = private_key_jwt
        .get_item("trusted_root_certificates")
        .map_err(|_| ConversionError::new("authorization could not be read"))?
    else {
        return python_to_json(value).map(|value| (value, None));
    };
    let trusted_roots = trusted_roots.cast::<PyBytes>().map_err(|_| {
        ConversionError::new(
            "authorization[\"private_key_jwt\"][\"trusted_root_certificates\"] must be bytes",
        )
    })?;
    if trusted_roots.as_bytes().len() > MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES {
        return Err(ConversionError::new(
            "authorization[\"private_key_jwt\"][\"trusted_root_certificates\"] exceeds the accepted byte bound",
        ));
    }

    let mut config = Map::new();
    for (key, value) in private_key_jwt.iter() {
        let key = key
            .cast::<PyString>()
            .map_err(|_| ConversionError::new("a mapping key must be a string"))?
            .to_str()
            .map_err(|_| ConversionError::new("a mapping key must be valid Unicode"))?;
        if key != "trusted_root_certificates" {
            config.insert(
                key.to_owned(),
                python_to_json_at_depth(&value, 3, &mut budget)?,
            );
        }
    }
    budget.leave_container(config_identity);
    budget.leave_container(outer_identity);
    let mut authorization = Map::new();
    authorization.insert("private_key_jwt".into(), Value::Object(config));
    Ok((
        Value::Object(authorization),
        Some(trusted_roots.as_bytes().to_vec()),
    ))
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
        let integer: i64 = integer
            .extract()
            .map_err(|_| ConversionError::new("an integer value must fit in 64 bits"))?;
        return Ok(Value::from(integer));
    }
    if let Ok(float) = value.cast::<PyFloat>() {
        let float: f64 = float
            .extract()
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
        let identity = budget.enter_container(value)?;
        let result = list
            .iter()
            .map(|item| python_to_json_at_depth(&item, depth + 1, budget))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array);
        budget.leave_container(identity);
        return result;
    }
    if let Ok(tuple) = value.cast::<PyTuple>() {
        let identity = budget.enter_container(value)?;
        let result = tuple
            .iter()
            .map(|item| python_to_json_at_depth(&item, depth + 1, budget))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array);
        budget.leave_container(identity);
        return result;
    }
    if let Ok(dict) = value.cast::<PyDict>() {
        let identity = budget.enter_container(value)?;
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
        budget.leave_container(identity);
        return result;
    }
    Err(ConversionError::new(
        "a value of this Python type cannot be converted",
    ))
}

pub fn json_to_python<'py>(py: Python<'py>, value: &Value) -> PyResult<Bound<'py, PyAny>> {
    match value {
        Value::Null => Ok(py.None().into_bound(py)),
        Value::Bool(value) => (*value).into_bound_py_any(py),
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

fn required_object<'a>(
    value: &'a Value,
    what: &str,
) -> Result<&'a Map<String, Value>, ConversionError> {
    value
        .as_object()
        .ok_or_else(|| ConversionError::new(format!("{what} must be an object")))
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

fn duration(seconds: f64, what: &str) -> Result<Duration, ConversionError> {
    Duration::try_from_secs_f64(seconds).map_err(|_| {
        ConversionError::new(format!(
            "{what} must be a finite non-negative number of seconds"
        ))
    })
}

fn private_key_jwt(
    value: &Value,
    trusted_root_certificates: Option<Vec<u8>>,
) -> Result<PrivateKeyJwt, ConfigError> {
    const WHAT: &str = "authorization[\"private_key_jwt\"]";
    let value = required_object(value, WHAT)?;
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
    let key = serde_json::to_string(key)
        .map_err(|_| ConversionError::new("the private-key JWT client key is invalid"))?;
    let key = PrivateJwk::parse(&key)
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
    if let Some(value) = trusted_root_certificates {
        config = config.with_trusted_root_certificates(value);
    }
    PrivateKeyJwt::new(config).map_err(ConfigError::Token)
}

fn authorization_provider(
    authorization: &Value,
    private_key_jwt_trusted_root_certificates: Option<Vec<u8>>,
) -> Result<Option<Arc<dyn TokenProvider>>, ConfigError> {
    match authorization {
        Value::Null => Ok(None),
        Value::Object(value) if value.len() == 1 => {
            if let Some(value) = value.get("static") {
                let value = value.as_str().ok_or_else(|| {
                    ConversionError::new("authorization[\"static\"] must be a string")
                })?;
                return Ok(Some(Arc::new(
                    StaticToken::new(value).map_err(ConfigError::Token)?,
                )));
            }
            if let Some(value) = value.get("private_key_jwt") {
                return Ok(Some(Arc::new(private_key_jwt(
                    value,
                    private_key_jwt_trusted_root_certificates,
                )?)));
            }
            Err(ConversionError::new(
                "authorization must contain exactly static or private_key_jwt",
            )
            .into())
        }
        _ => Err(ConversionError::new(
            "authorization must be null or an object containing exactly static or private_key_jwt",
        )
        .into()),
    }
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

#[allow(clippy::too_many_arguments)]
pub fn config_from_parts(
    base_url: &str,
    authorization: &Value,
    private_key_jwt_trusted_root_certificates: Option<Vec<u8>>,
    request_timeout_seconds: Option<f64>,
    connect_timeout_seconds: Option<f64>,
    user_agent: Option<String>,
    max_response_bytes: Option<u64>,
    trusted_root_certificates: Option<Vec<u8>>,
) -> Result<RelayClientConfig, ConfigError> {
    let base_url =
        Url::parse(base_url).map_err(|_| ConversionError::new("base_url must be a valid URL"))?;
    let mut config = RelayClientConfig::new(base_url);
    if let Some(provider) =
        authorization_provider(authorization, private_key_jwt_trusted_root_certificates)?
    {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappedError {
    pub kind: &'static str,
    pub message: String,
    pub code: Option<String>,
    pub status: Option<u16>,
    pub trace_id: Option<String>,
    pub retry_after_seconds: Option<u64>,
    pub transport_kind: Option<&'static str>,
    pub token_kind: Option<&'static str>,
}

impl MappedError {
    pub fn binding(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            code: None,
            status: None,
            trace_id: None,
            retry_after_seconds: None,
            transport_kind: None,
            token_kind: None,
        }
    }
}

fn protocol_code(value: ProtocolFailure) -> &'static str {
    match value {
        ProtocolFailure::HeaderBounds => "header_bounds",
        ProtocolFailure::TraceContext => "trace_context",
        ProtocolFailure::MediaType => "media_type",
        ProtocolFailure::Body => "body",
        ProtocolFailure::Problem => "problem",
        ProtocolFailure::EntityTag => "entity_tag",
        ProtocolFailure::NotModifiedBody => "not_modified_body",
        ProtocolFailure::Status => "status",
        _ => "protocol",
    }
}

pub fn map_client_error(error: &RelayClientError) -> MappedError {
    let mut mapped = MappedError::binding(
        match error {
            RelayClientError::Configuration { .. } => "configuration",
            RelayClientError::InvalidRequest { .. } => "invalid_request",
            RelayClientError::Token(_) => "token",
            RelayClientError::Transport { .. } => "transport",
            RelayClientError::Problem { .. } => "problem",
            RelayClientError::Protocol { .. } => "protocol",
            _ => "client",
        },
        error.to_string(),
    );
    match error {
        RelayClientError::Token(error) => {
            mapped.token_kind = Some(error.kind());
            match error {
                TokenError::Transport { kind } => mapped.transport_kind = Some(kind.kind()),
                TokenError::Refused { code } => mapped.code = Some(code.as_str().to_owned()),
                TokenError::Protocol { status } => mapped.status = Some(*status),
                _ => {}
            }
        }
        RelayClientError::Transport { kind } => mapped.transport_kind = Some(kind.kind()),
        RelayClientError::Problem {
            status,
            code,
            trace_id,
            retry_after_seconds,
        } => {
            mapped.status = Some(*status);
            mapped.code = Some(code.code().to_owned());
            mapped.trace_id = Some(trace_id.as_str().to_owned());
            mapped.retry_after_seconds = *retry_after_seconds;
        }
        RelayClientError::Protocol {
            status,
            failure,
            trace_id,
        } => {
            mapped.status = Some(*status);
            mapped.code = Some(protocol_code(*failure).to_owned());
            mapped.trace_id = trace_id.as_ref().map(|value| value.as_str().to_owned());
        }
        _ => {}
    }
    mapped
}

pub fn map_config_error(error: &ConfigError) -> MappedError {
    match error {
        ConfigError::Shape(error) => MappedError::binding("configuration", error.message()),
        ConfigError::Token(error) => map_client_error(&RelayClientError::Token(*error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_conversion_rejects_cycles_and_non_finite_numbers() {
        Python::attach(|py| {
            let list = PyList::empty(py);
            list.append(&list).unwrap();
            assert!(python_to_json(list.as_any())
                .unwrap_err()
                .message()
                .contains("cyclic"));
            let nan = f64::NAN.into_bound_py_any(py).unwrap();
            assert!(python_to_json(&nan).is_err());
            let bytes = PyBytes::new(py, b"bytes stay outside the JSON bridge");
            assert!(python_to_json(bytes.as_any()).is_err());
        });
    }

    #[test]
    fn optional_authorization_accepts_none_and_static_tokens_without_rendering_them() {
        assert!(config_from_parts(
            "http://127.0.0.1:8080/prefix",
            &Value::Null,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .is_ok());
        let token = "canary-static-token";
        let config = config_from_parts(
            "http://127.0.0.1:8080/prefix",
            &serde_json::json!({"static": token}),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(!format!("{config:?}").contains(token));
    }

    #[test]
    fn authorization_object_is_exactly_one_private_key_jwt_member() {
        let error = config_from_parts(
            "http://127.0.0.1:8080",
            &serde_json::json!({"private_key_jwt": {}, "static": "canary"}),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(error, ConfigError::Shape(_)));
        assert!(!format!("{error:?}").contains("canary"));
    }

    #[test]
    fn static_authorization_uses_the_same_exactly_one_member_shape_as_node() {
        config_from_parts(
            "http://127.0.0.1:8080",
            &serde_json::json!({"static": "placeholder-token"}),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("the closed static authorization shape is accepted");

        for authorization in [
            serde_json::json!("placeholder-token"),
            serde_json::json!({"static": "placeholder-token", "private_key_jwt": {}}),
            serde_json::json!({"bearer": "placeholder-token"}),
        ] {
            assert!(config_from_parts(
                "http://127.0.0.1:8080",
                &authorization,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .is_err());
        }
    }
}
