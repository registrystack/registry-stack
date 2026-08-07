//! Python-value <-> Rust conversions for the Evidence Python binding.
//!
//! Every function here is a plain Rust function, over `serde_json::Value` or
//! PyO3's `Bound<'_, PyAny>`, so the whole conversion layer is unit-testable
//! with `cargo test` and carries no dependency on the `pyo3::pymodule`/
//! `pyclass` machinery. `src/lib.rs` is the only file in this crate that
//! defines the Python module surface; it calls into this module for every
//! conversion and reports failures through [`map_client_error`],
//! [`map_conversion_error`], and [`map_config_error`].
//!
//! Unlike the Node binding (`crates/registry-evidence-client-node`), which
//! gets a `JsUnknown` <-> `serde_json::Value` bridge for free from napi's
//! `serde-json` feature, PyO3 has no such built-in conversion, and the crate
//! deliberately does not add one (`pythonize` or similar): [`python_to_json`]
//! and [`json_to_python`] are the small explicit recursive functions that
//! stand in for it.

use std::{fmt, sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use evidence_client_sdk::{
    AssuranceProfile, Evidence, EvidenceClientConfig, EvidenceClientError, EvidenceRequestSpec,
    EvidenceResponseFormat, ExpectedOutputDocument, ExpectedSubjectDocument, JwksDocument,
    PrivateKeyJwt, PrivateKeyJwtConfig, SelectorValue, StaticToken, SubjectExpectations,
    SubjectRequest, TokenError, TokenProvider,
};
use pyo3::{
    prelude::*,
    types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple},
    IntoPyObjectExt,
};
use registry_platform_crypto::PrivateJwk;
use serde_json::{Map, Value};
use url::Url;

/// A Python-supplied value did not have the shape this binding requires.
///
/// This is distinct from [`EvidenceClientError`]: it is refused before any
/// client-level Rust type exists, so it carries its own message rather than
/// borrowing the fixed `&'static str` reason of a type that cannot describe a
/// dynamically built Python shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversionError(pub String);

impl ConversionError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for ConversionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ConversionError {}

/// Building a client configuration mixes pure shape conversion with a
/// genuine, semantically real credential construction
/// ([`PrivateKeyJwt::new`]), so a failure may come from either stage. Keeping
/// them distinct lets a caller (and a test) tell "the Python object was
/// malformed" apart from "the configuration it described is unusable."
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Shape(ConversionError),
    Client(EvidenceClientError),
}

impl From<ConversionError> for ConfigError {
    fn from(error: ConversionError) -> Self {
        Self::Shape(error)
    }
}

impl From<TokenError> for ConfigError {
    fn from(error: TokenError) -> Self {
        Self::Client(EvidenceClientError::Token(error))
    }
}

fn as_object<'a>(value: &'a Value, what: &str) -> Result<&'a Map<String, Value>, ConversionError> {
    value
        .as_object()
        .ok_or_else(|| ConversionError::new(format!("{what} must be an object")))
}

fn required_string(object: &Map<String, Value>, field: &str) -> Result<String, ConversionError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| ConversionError::new(format!("`{field}` must be a string")))
}

fn required_u64(object: &Map<String, Value>, field: &str) -> Result<u64, ConversionError> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| ConversionError::new(format!("`{field}` must be a non-negative integer")))
}

fn optional_string(
    object: &Map<String, Value>,
    field: &str,
) -> Result<Option<String>, ConversionError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(ConversionError::new(format!("`{field}` must be a string"))),
    }
}

fn optional_i64(object: &Map<String, Value>, field: &str) -> Result<Option<i64>, ConversionError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_i64().map(Some).ok_or_else(|| {
            ConversionError::new(format!("`{field}` must be an integer that fits in 64 bits"))
        }),
    }
}

fn optional_f64(object: &Map<String, Value>, field: &str) -> Result<Option<f64>, ConversionError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_f64()
            .map(Some)
            .ok_or_else(|| ConversionError::new(format!("`{field}` must be a number"))),
    }
}

fn parse_url(value: &str, what: &str) -> Result<Url, ConversionError> {
    Url::parse(value).map_err(|_| ConversionError::new(format!("{what} must be a valid URL")))
}

/// Turn a caller-supplied number of seconds into a [`Duration`].
///
/// Python's idiom for a timeout is a float number of seconds, unlike the
/// Node binding's millisecond integers. A negative, infinite, or `NaN` input,
/// and a finite value larger than the `u64::MAX` seconds a [`Duration`] holds,
/// are all refused: `Duration::try_from_secs_f64` reports every one of them as
/// an error, where `Duration::from_secs_f64` would panic.
fn duration_from_seconds(seconds: f64, what: &str) -> Result<Duration, ConversionError> {
    Duration::try_from_secs_f64(seconds).map_err(|_| {
        ConversionError::new(format!(
            "{what} must be a finite, non-negative number of seconds that a duration can hold"
        ))
    })
}

/// Turn a caller-supplied UNIX timestamp (seconds, as `datetime.timestamp()`
/// yields) into the instant [`evidence_client_sdk::EvidenceClient::verify_as_of`]
/// takes.
pub fn datetime_from_unix_seconds(seconds: f64) -> Result<DateTime<Utc>, ConversionError> {
    if !seconds.is_finite() {
        return Err(ConversionError::new(
            "a timestamp must be a finite number of seconds since the UNIX epoch",
        ));
    }
    let whole_seconds = seconds.floor();
    let nanos = ((seconds - whole_seconds) * 1_000_000_000.0).round() as u32;
    DateTime::from_timestamp(whole_seconds as i64, nanos)
        .ok_or_else(|| ConversionError::new("a timestamp is outside the representable range"))
}

/// How deep [`python_to_json`] will descend, mirroring `serde_json`'s own
/// deserialization recursion limit.
///
/// A Python value is an arbitrary object graph, not a document `serde_json`
/// already bounded on the way in: it may nest far deeper than any JSON text a
/// caller could have parsed, and it may be cyclic. One finite bound refuses
/// both, since a cycle simply descends until it reaches the bound.
const MAX_JSON_DEPTH: usize = 128;

/// Convert a Python value to a [`serde_json::Value`].
///
/// The Python `bool` type is a subtype of `int`, so a boolean value must be
/// recognized before an integer downcast is attempted; checking in the
/// opposite order would silently turn `True`/`False` into `1`/`0`.
pub fn python_to_json(value: &Bound<'_, PyAny>) -> Result<Value, ConversionError> {
    python_to_json_at_depth(value, 1)
}

/// Convert one value at a known nesting level, where the top-level value is
/// level 1 and each container's items sit one level below it.
///
/// The bound is checked before the value is inspected at all, so a graph that
/// descends past [`MAX_JSON_DEPTH`] is refused rather than followed. Nothing
/// tracks which containers have already been seen: a cycle is exactly a graph
/// that descends without end, and the bound stops it at the same level it
/// stops any other.
fn python_to_json_at_depth(
    value: &Bound<'_, PyAny>,
    depth: usize,
) -> Result<Value, ConversionError> {
    if depth > MAX_JSON_DEPTH {
        return Err(ConversionError::new(format!(
            "a value nested more than {MAX_JSON_DEPTH} levels deep cannot be converted"
        )));
    }
    if value.is_none() {
        return Ok(Value::Null);
    }
    if let Ok(flag) = value.cast::<PyBool>() {
        return Ok(Value::Bool(flag.is_true()));
    }
    if let Ok(integer) = value.cast::<PyInt>() {
        let extracted: i64 = integer
            .extract()
            .map_err(|_| ConversionError::new("an integer value must fit in 64 bits"))?;
        return Ok(Value::from(extracted));
    }
    if let Ok(float_value) = value.cast::<PyFloat>() {
        let extracted: f64 = float_value
            .extract()
            .map_err(|_| ConversionError::new("a floating-point value could not be read"))?;
        let number = serde_json::Number::from_f64(extracted)
            .ok_or_else(|| ConversionError::new("a floating-point value must be finite"))?;
        return Ok(Value::Number(number));
    }
    if let Ok(text) = value.cast::<PyString>() {
        let extracted = text
            .to_str()
            .map_err(|_| ConversionError::new("a string value must be valid Unicode"))?;
        return Ok(Value::String(extracted.to_owned()));
    }
    if let Ok(list) = value.cast::<PyList>() {
        let items = list
            .iter()
            .map(|item| python_to_json_at_depth(&item, depth + 1))
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(Value::Array(items));
    }
    if let Ok(tuple) = value.cast::<PyTuple>() {
        let items = tuple
            .iter()
            .map(|item| python_to_json_at_depth(&item, depth + 1))
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(Value::Array(items));
    }
    if let Ok(dict) = value.cast::<PyDict>() {
        let mut object = Map::new();
        for (key, value) in dict.iter() {
            let key_text: String = key
                .cast::<PyString>()
                .map_err(|_| ConversionError::new("a mapping key must be a string"))?
                .to_str()
                .map_err(|_| ConversionError::new("a mapping key must be valid Unicode"))?
                .to_owned();
            object.insert(key_text, python_to_json_at_depth(&value, depth + 1)?);
        }
        return Ok(Value::Object(object));
    }
    Err(ConversionError::new(
        "a value of this Python type cannot be converted",
    ))
}

/// Convert a [`serde_json::Value`] to a Python value.
///
/// This is how the verified [`Evidence`] payload, the policy document, and
/// every other Rust-owned document crosses to Python: through
/// [`evidence_to_json`] (or an ordinary `serde_json::to_value`) and then this
/// function, never through a conversion dependency.
pub fn json_to_python<'py>(py: Python<'py>, value: &Value) -> PyResult<Bound<'py, PyAny>> {
    match value {
        Value::Null => Ok(py.None().into_bound(py)),
        Value::Bool(flag) => (*flag).into_bound_py_any(py),
        Value::Number(number) => {
            if let Some(whole) = number.as_i64() {
                whole.into_bound_py_any(py)
            } else if let Some(whole) = number.as_u64() {
                whole.into_bound_py_any(py)
            } else if let Some(fractional) = number.as_f64() {
                fractional.into_bound_py_any(py)
            } else {
                Err(pyo3::exceptions::PyValueError::new_err(
                    "a JSON number could not be represented in Python",
                ))
            }
        }
        Value::String(text) => text.as_str().into_bound_py_any(py),
        Value::Array(items) => {
            let converted = items
                .iter()
                .map(|item| json_to_python(py, item))
                .collect::<PyResult<Vec<_>>>()?;
            Ok(PyList::new(py, converted)?.into_any())
        }
        Value::Object(object) => {
            let dict = PyDict::new(py);
            for (key, value) in object {
                dict.set_item(key, json_to_python(py, value)?)?;
            }
            Ok(dict.into_any())
        }
    }
}

/// The three scalar shapes a selector value may take on the wire, read off a
/// Python value.
///
/// A float, a mapping, `None`, and an integer literal too large for `i64` are
/// all refused here: the request contract's own numeric bound
/// (`MINIMUM_SELECTOR_INTEGER..=MAXIMUM_SELECTOR_INTEGER`) is enforced later,
/// by the real `EvidenceClient::prepare` call, once a genuine
/// `EvidenceRequestSpec` exists.
fn selector_value_from_json(value: &Value) -> Result<SelectorValue, ConversionError> {
    match value {
        Value::String(text) => Ok(SelectorValue::from(text.as_str())),
        Value::Bool(flag) => Ok(SelectorValue::from(*flag)),
        Value::Number(number) => number.as_i64().map(SelectorValue::from).ok_or_else(|| {
            ConversionError::new(
                "a selector integer value must fit in 64 bits with no fractional part",
            )
        }),
        _ => Err(ConversionError::new(
            "a selector value must be a string, an integer, or a boolean",
        )),
    }
}

fn subject_request_from_json(value: &Value) -> Result<SubjectRequest, ConversionError> {
    let object = as_object(value, "a subject request")?;
    let role = required_string(object, "role")?;
    let selector_profile = required_string(object, "selector_profile")?;
    let selector_values = match object.get("selector_values") {
        None | Some(Value::Null) => None,
        Some(Value::Object(values)) => {
            let mut pairs = Vec::with_capacity(values.len());
            for (name, value) in values {
                pairs.push((name.clone(), selector_value_from_json(value)?));
            }
            Some(pairs)
        }
        Some(_) => {
            return Err(ConversionError::new(
                "`selector_values` must be a mapping of field names to values",
            ))
        }
    };
    Ok(SubjectRequest {
        role,
        selector_profile,
        selector_values,
    })
}

/// `subject_expectations` accepts a bare sequence of `{"role", "binding"}`
/// mappings, or the literal string `"accept_first_use"`. There is no third
/// shape, matching [`SubjectExpectations`] having no third variant.
///
/// This is deliberately not Node's `{"pinned": [...]}`/`"acceptFirstUse"`
/// wrapper shape: a Python caller passing a list of expectations does not
/// need a wrapper key to name what is already the only kind of item the list
/// can hold.
pub fn subject_expectations_from_json(
    value: &Value,
) -> Result<SubjectExpectations, ConversionError> {
    match value {
        Value::String(tag) if tag == "accept_first_use" => Ok(SubjectExpectations::AcceptFirstUse),
        Value::Array(entries) => {
            let mut subjects = Vec::with_capacity(entries.len());
            for entry in entries {
                let entry = as_object(entry, "a pinned subject expectation")?;
                subjects.push(ExpectedSubjectDocument {
                    role: required_string(entry, "role")?,
                    binding: required_string(entry, "binding")?,
                });
            }
            Ok(SubjectExpectations::Pinned(subjects))
        }
        _ => Err(ConversionError::new(
            "`subject_expectations` must be \"accept_first_use\" or a sequence of {\"role\", \"binding\"} mappings",
        )),
    }
}

/// The inverse of [`subject_expectations_from_json`]. Infallible: every
/// [`SubjectExpectations`] value already came from a caller's own request, and
/// both variants have an unambiguous JSON rendering.
pub fn subject_expectations_to_json(expectations: &SubjectExpectations) -> Value {
    match expectations {
        SubjectExpectations::AcceptFirstUse => Value::String("accept_first_use".to_owned()),
        SubjectExpectations::Pinned(subjects) => Value::Array(
            subjects
                .iter()
                .map(|subject| {
                    serde_json::json!({
                        "role": subject.role,
                        "binding": subject.binding,
                    })
                })
                .collect(),
        ),
    }
}

fn expected_outputs_from_json(
    value: &Value,
) -> Result<Vec<ExpectedOutputDocument>, ConversionError> {
    serde_json::from_value(value.clone())
        .map_err(|error| ConversionError::new(format!("`expected_outputs` is invalid: {error}")))
}

fn assurance_profile_from_json(value: &Value) -> Result<AssuranceProfile, ConversionError> {
    serde_json::from_value(value.clone()).map_err(|error| {
        ConversionError::new(format!("`expected_assurance_profile` is invalid: {error}"))
    })
}

fn response_format_from_json(value: &Value) -> Result<EvidenceResponseFormat, ConversionError> {
    serde_json::from_value(value.clone()).map_err(|_| {
        ConversionError::new("`response_format` must be \"signed-jws\" or \"sd-jwt-vc\"")
    })
}

/// Build the specification [`evidence_client_sdk::EvidenceClient::prepare`]
/// validates. Only shape is checked here: an empty identifier, an
/// out-of-range count, or any other business rule is the real client's own
/// refusal, raised once a genuine `EvidenceRequestSpec` exists.
pub fn spec_from_json(value: &Value) -> Result<EvidenceRequestSpec, ConversionError> {
    let object = as_object(value, "a request specification")?;

    let subjects_json = object
        .get("subjects")
        .and_then(Value::as_array)
        .ok_or_else(|| ConversionError::new("`subjects` must be a sequence"))?;
    let subjects = subjects_json
        .iter()
        .map(subject_request_from_json)
        .collect::<Result<Vec<_>, _>>()?;

    let expected_outputs_json = object
        .get("expected_outputs")
        .ok_or_else(|| ConversionError::new("`expected_outputs` must be present"))?;
    let expected_outputs = expected_outputs_from_json(expected_outputs_json)?;

    let expected_assurance_profile_json = object
        .get("expected_assurance_profile")
        .ok_or_else(|| ConversionError::new("`expected_assurance_profile` must be present"))?;
    let expected_assurance_profile = assurance_profile_from_json(expected_assurance_profile_json)?;

    let subject_expectations_json = object
        .get("subject_expectations")
        .ok_or_else(|| ConversionError::new("`subject_expectations` must be present"))?;
    let subject_expectations = subject_expectations_from_json(subject_expectations_json)?;

    let response_format_json = object
        .get("response_format")
        .ok_or_else(|| ConversionError::new("`response_format` must be present"))?;
    let response_format = response_format_from_json(response_format_json)?;

    Ok(EvidenceRequestSpec {
        response_format,
        requirement: required_string(object, "requirement")?,
        purpose: required_string(object, "purpose")?,
        audience: required_string(object, "audience")?,
        evidence_type: required_string(object, "evidence_type")?,
        issued_by: required_string(object, "issued_by")?,
        provided_by: required_string(object, "provided_by")?,
        configuration_revision: required_string(object, "configuration_revision")?,
        expected_assurance_profile,
        subjects,
        expected_outputs,
        maximum_assertion_lifetime_seconds: required_u64(
            object,
            "maximum_assertion_lifetime_seconds",
        )?,
        clock_skew_seconds: required_u64(object, "clock_skew_seconds")?,
        subject_expectations,
    })
}

/// `token["private_key_jwt"]`'s own shape mirrors [`PrivateKeyJwtConfig`]'s
/// builder surface: one required endpoint, client identifier, and signing
/// key, plus the optional knobs the Rust type exposes for its own outbound
/// exchange with the token endpoint.
///
/// Deliberately absent: a nested `trusted_root_certificates`. The top-level
/// constructor accepts it as genuine `bytes`, bypassing the JSON bridge
/// entirely, but this nested shape arrives already folded into a
/// `serde_json::Value` by the caller in `src/lib.rs`, which has no way to
/// carry raw bytes. Supporting a second, independent trust anchor for the
/// token endpoint specifically is a real gap this task did not ask to close;
/// it is deferred rather than worked around.
fn private_key_jwt_provider_from_json(value: &Value) -> Result<PrivateKeyJwt, ConfigError> {
    let object = as_object(value, "`token[\"private_key_jwt\"]`").map_err(ConfigError::Shape)?;

    let token_endpoint = parse_url(
        &required_string(object, "token_endpoint").map_err(ConfigError::Shape)?,
        "`token[\"private_key_jwt\"][\"token_endpoint\"]`",
    )
    .map_err(ConfigError::Shape)?;
    let client_id = required_string(object, "client_id").map_err(ConfigError::Shape)?;

    let client_key_json = object.get("client_key").ok_or_else(|| {
        ConfigError::Shape(ConversionError::new(
            "`token[\"private_key_jwt\"][\"client_key\"]` must be present",
        ))
    })?;
    let client_key_text = serde_json::to_string(client_key_json).map_err(|error| {
        ConfigError::Shape(ConversionError::new(format!(
            "`token[\"private_key_jwt\"][\"client_key\"]` is invalid: {error}"
        )))
    })?;
    let client_key = PrivateJwk::parse(&client_key_text).map_err(|error| {
        ConfigError::Shape(ConversionError::new(format!(
            "`token[\"private_key_jwt\"][\"client_key\"]` is invalid: {error}"
        )))
    })?;

    let mut config = PrivateKeyJwtConfig::new(token_endpoint, client_id, client_key);
    if let Some(audience) = optional_string(object, "audience").map_err(ConfigError::Shape)? {
        config = config.with_audience(audience);
    }
    if let Some(seconds) =
        optional_i64(object, "assertion_lifetime_seconds").map_err(ConfigError::Shape)?
    {
        config = config.with_assertion_lifetime_seconds(seconds);
    }
    if let Some(seconds) =
        optional_i64(object, "refresh_margin_seconds").map_err(ConfigError::Shape)?
    {
        config = config.with_refresh_margin_seconds(seconds);
    }
    if let Some(seconds) =
        optional_f64(object, "request_timeout_seconds").map_err(ConfigError::Shape)?
    {
        let timeout = duration_from_seconds(
            seconds,
            "`token[\"private_key_jwt\"][\"request_timeout_seconds\"]`",
        )
        .map_err(ConfigError::Shape)?;
        config = config.with_request_timeout(timeout);
    }
    if let Some(seconds) =
        optional_f64(object, "connect_timeout_seconds").map_err(ConfigError::Shape)?
    {
        let timeout = duration_from_seconds(
            seconds,
            "`token[\"private_key_jwt\"][\"connect_timeout_seconds\"]`",
        )
        .map_err(ConfigError::Shape)?;
        config = config.with_connect_timeout(timeout);
    }
    if let Some(user_agent) = optional_string(object, "user_agent").map_err(ConfigError::Shape)? {
        config = config.with_user_agent(user_agent);
    }

    PrivateKeyJwt::new(config).map_err(ConfigError::from)
}

/// `token` is either a plain string, the static credential, or an object
/// carrying exactly one key, `private_key_jwt`. Distinct from Node's
/// `{"static": ...}`/`{"privateKeyJwt": ...}` shape, which wraps both cases;
/// a Python caller with a static token has no reason to name the case it
/// picked when a bare string already says so.
fn token_provider_from_json(value: &Value) -> Result<Arc<dyn TokenProvider>, ConfigError> {
    match value {
        Value::String(text) => {
            let provider = StaticToken::new(text.as_str())?;
            Ok(Arc::new(provider))
        }
        Value::Object(object) => {
            if object.len() != 1 {
                return Err(ConfigError::Shape(ConversionError::new(
                    "`token` must be a string or an object with exactly one key, \"private_key_jwt\"",
                )));
            }
            let inner = object.get("private_key_jwt").ok_or_else(|| {
                ConfigError::Shape(ConversionError::new(
                    "`token` object must carry \"private_key_jwt\"",
                ))
            })?;
            let provider = private_key_jwt_provider_from_json(inner)?;
            Ok(Arc::new(provider))
        }
        _ => Err(ConfigError::Shape(ConversionError::new(
            "`token` must be a string or an object with \"private_key_jwt\"",
        ))),
    }
}

/// Build the configuration [`evidence_client_sdk::EvidenceClient::new`]
/// validates. Only shape is checked here (a missing field, a malformed URL, a
/// malformed key); the pinned-key-set, transport, and timeout business rules
/// are the real client's own refusal, raised once a genuine
/// `EvidenceClientConfig` exists.
///
/// `trusted_root_certificates` bypasses the JSON bridge entirely: PyO3
/// auto-extracts Python `bytes` to `Vec<u8>`, so `src/lib.rs` passes it here
/// as a genuine Rust value rather than folding it into `trusted_jwks` or
/// `token`'s `serde_json::Value`.
#[allow(clippy::too_many_arguments)]
pub fn config_from_parts(
    base_url: &str,
    trusted_jwks: &Value,
    revoked_key_ids: Vec<String>,
    token: &Value,
    request_timeout_seconds: Option<f64>,
    connect_timeout_seconds: Option<f64>,
    user_agent: Option<String>,
    trusted_root_certificates: Option<Vec<u8>>,
    max_response_bytes: Option<u64>,
    max_metadata_bytes: Option<u64>,
) -> Result<EvidenceClientConfig, ConfigError> {
    let base_url = parse_url(base_url, "`base_url`").map_err(ConfigError::Shape)?;

    let trusted_jwks: JwksDocument =
        serde_json::from_value(trusted_jwks.clone()).map_err(|error| {
            ConfigError::Shape(ConversionError::new(format!(
                "`trusted_jwks` is invalid: {error}"
            )))
        })?;

    let token_provider = token_provider_from_json(token)?;

    let mut config =
        EvidenceClientConfig::new(base_url, token_provider, trusted_jwks, revoked_key_ids);

    if let Some(seconds) = request_timeout_seconds {
        let timeout = duration_from_seconds(seconds, "`request_timeout_seconds`")
            .map_err(ConfigError::Shape)?;
        config = config.with_request_timeout(timeout);
    }
    if let Some(seconds) = connect_timeout_seconds {
        let timeout = duration_from_seconds(seconds, "`connect_timeout_seconds`")
            .map_err(ConfigError::Shape)?;
        config = config.with_connect_timeout(timeout);
    }
    if let Some(user_agent) = user_agent {
        config = config.with_user_agent(user_agent);
    }
    if let Some(pem_bundle) = trusted_root_certificates {
        config = config.with_trusted_root_certificates(pem_bundle);
    }
    if let Some(max_bytes) = max_response_bytes {
        config = config.with_max_response_bytes(max_bytes);
    }
    if let Some(max_bytes) = max_metadata_bytes {
        config = config.with_max_metadata_bytes(max_bytes);
    }

    Ok(config)
}

/// The verified payload crosses to Python through this, never through
/// `Debug`.
pub fn evidence_to_json(evidence: &Evidence) -> Result<Value, ConversionError> {
    serde_json::to_value(evidence).map_err(|error| {
        ConversionError::new(format!(
            "the verified evidence payload could not be serialized: {error}"
        ))
    })
}

/// One mapped failure, ready to become a Python exception.
///
/// Unlike the Node binding, which serializes this shape into one JSON string
/// and uses it as the thrown error's `message` (so a caller can
/// `JSON.parse(error.message)`), the Python exception classes carry `kind`,
/// `status`, `code`, `operation`, `retry_after_seconds`, `transport_kind`, and
/// `token_kind` as separate attributes, and `message` is always `Display`
/// text over the source failure, never a JSON envelope. `src/lib.rs` reads
/// this struct's fields directly when constructing the exception instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedError {
    pub kind: &'static str,
    pub message: String,
    pub status: Option<u16>,
    pub code: Option<String>,
    pub operation: Option<String>,
    pub retry_after_seconds: Option<u64>,
    pub transport_kind: Option<&'static str>,
    pub token_kind: Option<&'static str>,
}

impl MappedError {
    fn bare(kind: &'static str, message: String) -> Self {
        Self {
            kind,
            message,
            status: None,
            code: None,
            operation: None,
            retry_after_seconds: None,
            transport_kind: None,
            token_kind: None,
        }
    }
}

/// A shape-level failure reports the same stable envelope every mapped
/// failure uses, so a caller need not special-case where a failure
/// originated. There is no dedicated "shape" kind among the eight the runtime
/// client defines; a Python caller that supplied an unusable shape is, from
/// the caller's side, exactly the "the client cannot be used as configured"
/// case.
pub fn map_conversion_error(error: &ConversionError) -> MappedError {
    MappedError::bare("configuration", error.to_string())
}

pub fn map_config_error(error: &ConfigError) -> MappedError {
    match error {
        ConfigError::Shape(shape) => map_conversion_error(shape),
        ConfigError::Client(client) => map_client_error(client),
    }
}

/// Map any [`EvidenceClientError`] to a [`MappedError`].
///
/// `code` is deliberately overloaded: a `Denied`/`Protocol` wire code, a
/// `Token::Refused` OAuth code, and a `Verification` failure's own kind
/// string all travel in the same field, since a caller branches on `kind`
/// first and `code` only refines it. `token_kind` is `Token`'s own analogous
/// second discriminant: every `TokenError` carries one, from
/// [`TokenError::kind`], alongside whichever further sub-fields
/// (`transport_kind`, `code`, `status`) that specific variant also carries.
///
/// `code` and `operation` are already bounded by the wrapped crate before
/// either ever reaches an `EvidenceClientError` variant
/// (`evidence_client_sdk::problem::is_contract_code` and
/// `sanitized_operation`, at most 64 bytes of lowercase snake case and 64
/// ASCII alphanumerics respectively): this function passes them through
/// unchanged rather than re-bounding them.
///
/// Never included: response bytes, a credential, a header value, a selector
/// value, or a subject binding. Every message here is `Display` text over
/// fixed, non-secret reasons; none of the eight kinds can carry one of those.
pub fn map_client_error(error: &EvidenceClientError) -> MappedError {
    let mut mapped = MappedError::bare(error.kind(), error.to_string());
    mapped.operation = error.operation().map(str::to_owned);

    match error {
        // Deliberately no `nonce_kind` field: `NonceError::NotCanonical` is
        // constructed only inside `RequestNonce::parse`'s own unit tests, so
        // this crate's production path can only ever fail here with
        // `NonceError::Entropy`, which carries nothing further to report.
        EvidenceClientError::Configuration { .. } | EvidenceClientError::Nonce(_) => {}
        EvidenceClientError::Token(token_error) => insert_token_fields(&mut mapped, token_error),
        EvidenceClientError::Transport { kind } => {
            mapped.transport_kind = Some(kind.kind());
        }
        EvidenceClientError::Denied {
            status,
            code,
            retry_after_seconds,
            ..
        } => {
            mapped.status = Some(*status);
            mapped.code = Some(code.clone());
            mapped.retry_after_seconds = *retry_after_seconds;
        }
        EvidenceClientError::NotAvailable { .. } => {}
        EvidenceClientError::Protocol {
            status,
            code,
            retry_after_seconds,
            ..
        } => {
            mapped.status = Some(*status);
            mapped.code = code.clone();
            mapped.retry_after_seconds = *retry_after_seconds;
        }
        EvidenceClientError::Verification(verification_error) => {
            mapped.code = Some(verification_error.kind().to_owned());
        }
        // `EvidenceClientError` is `#[non_exhaustive]`: a variant this crate
        // does not yet know about still maps, with only `kind`, `message`, and
        // whatever `operation()` reports for it.
        _ => {}
    }

    mapped
}

fn insert_token_fields(mapped: &mut MappedError, error: &TokenError) {
    mapped.token_kind = Some(error.kind());
    match error {
        TokenError::Unavailable | TokenError::Invalid { .. } | TokenError::Configuration { .. } => {
        }
        TokenError::Transport { kind } => {
            mapped.transport_kind = Some(kind.kind());
        }
        TokenError::Refused { code } => {
            mapped.code = Some(code.as_str().to_owned());
        }
        TokenError::Protocol { status } => {
            mapped.status = Some(*status);
        }
        // `TokenError` is `#[non_exhaustive]`.
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ed25519_dalek::SigningKey;
    use evidence_client_sdk::{NonceError, OAuthErrorCode, TransportKind};
    use pyo3::{
        types::{PyDict, PyList},
        Python,
    };
    use registry_evidence_verifier::verifier::VerificationError;

    use super::*;

    fn generated_private_jwk_json() -> Value {
        let mut seed = [0_u8; 32];
        getrandom::fill(&mut seed).expect("the host supplies randomness");
        let signing_key = SigningKey::from_bytes(&seed);
        serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "kid": "convert-test-key-1",
            "x": URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
            "d": URL_SAFE_NO_PAD.encode(signing_key.to_bytes()),
        })
    }

    fn valid_spec_json() -> Value {
        serde_json::json!({
            "response_format": "signed-jws",
            "requirement": "urn:example:requirement:v1",
            "purpose": "example-purpose",
            "audience": "urn:example:audience",
            "evidence_type": "urn:example:evidence-type:v1",
            "issued_by": "urn:example:issuer",
            "provided_by": "urn:example:provider",
            "configuration_revision": "sha256:0000000000000000000000000000000000000000000000000000000000000",
            "expected_assurance_profile": "local",
            "subjects": [
                { "role": "subject", "selector_profile": "national-id" }
            ],
            "expected_outputs": [
                { "concept": "urn:example:concept:status-holds", "form": "boolean" }
            ],
            "maximum_assertion_lifetime_seconds": 300,
            "clock_skew_seconds": 30,
            "subject_expectations": "accept_first_use",
        })
    }

    #[test]
    fn python_to_json_distinguishes_bool_from_int() {
        Python::attach(|py| {
            let true_value = true.into_bound_py_any(py).unwrap();
            assert_eq!(python_to_json(&true_value).unwrap(), Value::Bool(true));

            let false_value = false.into_bound_py_any(py).unwrap();
            assert_eq!(python_to_json(&false_value).unwrap(), Value::Bool(false));

            let one = 1_i64.into_bound_py_any(py).unwrap();
            assert_eq!(python_to_json(&one).unwrap(), Value::from(1_i64));
        });
    }

    #[test]
    fn python_to_json_converts_every_scalar_shape() {
        Python::attach(|py| {
            assert_eq!(
                python_to_json(&py.None().into_bound(py)).unwrap(),
                Value::Null
            );
            assert_eq!(
                python_to_json(&"text".into_bound_py_any(py).unwrap()).unwrap(),
                Value::String("text".to_owned())
            );
            assert_eq!(
                python_to_json(&2.5_f64.into_bound_py_any(py).unwrap()).unwrap(),
                Value::from(2.5_f64)
            );
        });
    }

    #[test]
    fn python_to_json_converts_lists_and_tuples() {
        Python::attach(|py| {
            let list = PyList::new(py, [1_i64, 2, 3]).unwrap();
            assert_eq!(
                python_to_json(&list.into_any()).unwrap(),
                Value::Array(vec![Value::from(1), Value::from(2), Value::from(3)])
            );

            let tuple = pyo3::types::PyTuple::new(py, ["a", "b"]).unwrap();
            assert_eq!(
                python_to_json(&tuple.into_any()).unwrap(),
                Value::Array(vec![
                    Value::String("a".to_owned()),
                    Value::String("b".to_owned())
                ])
            );
        });
    }

    #[test]
    fn python_to_json_converts_dicts_with_string_keys() {
        Python::attach(|py| {
            let dict = PyDict::new(py);
            dict.set_item("role", "subject").unwrap();
            dict.set_item("count", 3_i64).unwrap();
            let converted = python_to_json(&dict.into_any()).unwrap();
            assert_eq!(
                converted,
                serde_json::json!({ "role": "subject", "count": 3 })
            );
        });
    }

    #[test]
    fn python_to_json_refuses_an_unsupported_type() {
        Python::attach(|py| {
            // A built-in function object is not one of the shapes this
            // bridge understands.
            let builtins = py.import("builtins").expect("builtins imports");
            let function = builtins.getattr("len").expect("len exists");
            assert!(python_to_json(&function).is_err());
        });
    }

    /// The bound belongs to this bridge rather than to `serde_json`: nothing
    /// parsed the graph on the way in, so nothing else has limited how deep it
    /// descends. A chain at exactly the limit still converts, so the bound is
    /// pinned rather than merely known to exist.
    #[test]
    fn python_to_json_refuses_a_structure_nested_deeper_than_the_limit() {
        fn nested_lists(py: Python<'_>, depth: usize) -> Bound<'_, PyAny> {
            let mut value = PyList::empty(py).into_any();
            for _ in 1..depth {
                value = PyList::new(py, [value])
                    .expect("a list holding one item is built")
                    .into_any();
            }
            value
        }

        Python::attach(|py| {
            assert!(python_to_json(&nested_lists(py, MAX_JSON_DEPTH)).is_ok());
            assert!(python_to_json(&nested_lists(py, MAX_JSON_DEPTH + 1)).is_err());
        });
    }

    /// A Python mapping may hold itself, which no JSON document can express.
    /// The depth bound is what refuses it: the descent reaches the limit and
    /// stops, so the same check covers a cycle and a merely deep graph.
    #[test]
    fn python_to_json_refuses_a_cyclic_mapping() {
        Python::attach(|py| {
            let dict = PyDict::new(py);
            dict.set_item("self", &dict)
                .expect("a mapping holds itself");
            assert!(python_to_json(&dict.into_any()).is_err());
        });
    }

    #[test]
    fn json_to_python_round_trips_through_python_to_json() {
        Python::attach(|py| {
            let original = serde_json::json!({
                "a": 1,
                "b": [true, false, null, "text", 2.5],
                "c": { "nested": "value" },
            });
            let python_value = json_to_python(py, &original).expect("conversion succeeds");
            let round_tripped = python_to_json(&python_value).expect("conversion succeeds");
            assert_eq!(round_tripped, original);
        });
    }

    #[test]
    fn spec_from_json_accepts_a_valid_specification() {
        let spec = spec_from_json(&valid_spec_json()).expect("the specification is valid");
        assert_eq!(spec.requirement, "urn:example:requirement:v1");
        assert_eq!(spec.response_format, EvidenceResponseFormat::SignedJws);
        assert_eq!(spec.subjects.len(), 1);
        assert_eq!(spec.subjects[0].role, "subject");
        assert!(matches!(
            spec.subject_expectations,
            SubjectExpectations::AcceptFirstUse
        ));
    }

    #[test]
    fn spec_from_json_refuses_a_missing_required_string_field() {
        for field in [
            "response_format",
            "requirement",
            "purpose",
            "audience",
            "evidence_type",
            "issued_by",
            "provided_by",
            "configuration_revision",
        ] {
            let mut spec = valid_spec_json();
            spec.as_object_mut().unwrap().remove(field);
            assert!(
                spec_from_json(&spec).is_err(),
                "`{field}` should be required"
            );
        }
    }

    #[test]
    fn spec_from_json_maps_both_response_formats_and_refuses_other_values() {
        let mut spec = valid_spec_json();
        spec["response_format"] = Value::String("sd-jwt-vc".to_owned());
        assert_eq!(
            spec_from_json(&spec).unwrap().response_format,
            EvidenceResponseFormat::SdJwtVc
        );

        for value in [
            Value::String("jws".to_owned()),
            Value::String("sd_jwt_vc".to_owned()),
            Value::Null,
            Value::Bool(true),
        ] {
            let mut spec = valid_spec_json();
            spec["response_format"] = value;
            assert!(spec_from_json(&spec).is_err());
        }
    }

    #[test]
    fn spec_from_json_refuses_subjects_that_are_not_a_sequence() {
        let mut spec = valid_spec_json();
        spec["subjects"] = Value::String("not a sequence".to_owned());
        assert!(spec_from_json(&spec).is_err());
    }

    #[test]
    fn spec_from_json_refuses_an_invalid_assurance_profile() {
        let mut spec = valid_spec_json();
        spec["expected_assurance_profile"] = Value::String("not-a-real-profile".to_owned());
        assert!(spec_from_json(&spec).is_err());
    }

    #[test]
    fn spec_from_json_refuses_invalid_expected_outputs() {
        let mut spec = valid_spec_json();
        spec["expected_outputs"] = serde_json::json!([{ "concept": "x", "form": "not-a-form" }]);
        assert!(spec_from_json(&spec).is_err());
    }

    #[test]
    fn subject_expectations_from_json_accepts_both_shapes() {
        match subject_expectations_from_json(&Value::String("accept_first_use".to_owned())).unwrap()
        {
            SubjectExpectations::AcceptFirstUse => {}
            SubjectExpectations::Pinned(_) => panic!("expected accept_first_use"),
        }

        let pinned = subject_expectations_from_json(&serde_json::json!([
            { "role": "subject", "binding": "urn:evidence:subject:v1_AAAA" }
        ]))
        .unwrap();
        match pinned {
            SubjectExpectations::Pinned(subjects) => {
                assert_eq!(subjects.len(), 1);
                assert_eq!(subjects[0].role, "subject");
                assert_eq!(subjects[0].binding, "urn:evidence:subject:v1_AAAA");
            }
            SubjectExpectations::AcceptFirstUse => panic!("expected pinned subjects"),
        }
    }

    #[test]
    fn subject_expectations_from_json_refuses_anything_else() {
        for value in [
            Value::String("acceptFirstUse".to_owned()),
            Value::String("AcceptFirstUse".to_owned()),
            serde_json::json!({ "pinned": [] }),
            Value::Null,
            Value::Bool(true),
        ] {
            assert!(
                subject_expectations_from_json(&value).is_err(),
                "{value:?} should have been refused"
            );
        }
    }

    /// `SubjectExpectations` carries no `PartialEq` (it is a foreign type this
    /// crate does not own), so the round trip is proven through its JSON
    /// rendering, which does implement equality, rather than through the
    /// Rust value directly.
    #[test]
    fn subject_expectations_round_trips_through_json() {
        let accept_first_use_json =
            subject_expectations_to_json(&SubjectExpectations::AcceptFirstUse);
        let round_tripped = subject_expectations_from_json(&accept_first_use_json).unwrap();
        assert_eq!(
            subject_expectations_to_json(&round_tripped),
            accept_first_use_json
        );

        let pinned_json = subject_expectations_to_json(&SubjectExpectations::Pinned(vec![
            ExpectedSubjectDocument {
                role: "subject".to_owned(),
                binding: "urn:evidence:subject:v1_AAAA".to_owned(),
            },
        ]));
        let round_tripped = subject_expectations_from_json(&pinned_json).unwrap();
        assert_eq!(subject_expectations_to_json(&round_tripped), pinned_json);
    }

    #[test]
    fn config_from_parts_accepts_a_static_token() {
        let config = config_from_parts(
            "https://evidence.example/",
            &serde_json::json!({ "keys": [] }),
            Vec::new(),
            &Value::String("a-static-token".to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("the configuration is well-shaped");
        assert_eq!(config.base_url().as_str(), "https://evidence.example/");
    }

    #[test]
    fn config_from_parts_accepts_a_private_key_jwt_provider() {
        let token = serde_json::json!({
            "private_key_jwt": {
                "token_endpoint": "https://issuer.example/token",
                "client_id": "test-client",
                "client_key": generated_private_jwk_json(),
            }
        });
        config_from_parts(
            "https://evidence.example/",
            &serde_json::json!({ "keys": [] }),
            Vec::new(),
            &token,
            Some(5.5),
            Some(1.0),
            Some("test-agent".to_owned()),
            None,
            Some(1024),
            Some(2048),
        )
        .expect("the configuration is well-shaped");
    }

    #[test]
    fn config_from_parts_refuses_a_malformed_base_url() {
        let error = config_from_parts(
            "not a url",
            &serde_json::json!({ "keys": [] }),
            Vec::new(),
            &Value::String("token".to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(error, ConfigError::Shape(_)));
    }

    #[test]
    fn config_from_parts_refuses_a_token_object_with_the_wrong_shape() {
        let error = config_from_parts(
            "https://evidence.example/",
            &serde_json::json!({ "keys": [] }),
            Vec::new(),
            &serde_json::json!({ "static": "token" }),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(error, ConfigError::Shape(_)));
    }

    #[test]
    fn config_from_parts_refuses_a_malformed_client_key() {
        let token = serde_json::json!({
            "private_key_jwt": {
                "token_endpoint": "https://issuer.example/token",
                "client_id": "test-client",
                "client_key": { "kty": "not-a-real-key-type" },
            }
        });
        let error = config_from_parts(
            "https://evidence.example/",
            &serde_json::json!({ "keys": [] }),
            Vec::new(),
            &token,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(error, ConfigError::Shape(_)));
    }

    #[test]
    fn duration_from_seconds_refuses_negative_infinite_and_nan() {
        for seconds in [-1.0, f64::NEG_INFINITY, f64::INFINITY, f64::NAN] {
            assert!(duration_from_seconds(seconds, "`x`").is_err());
        }
        assert_eq!(
            duration_from_seconds(1.5, "`x`").unwrap(),
            Duration::from_secs_f64(1.5)
        );
    }

    /// A `Duration` holds at most `u64::MAX` whole seconds, so a perfectly
    /// finite, positive `f64` can still be too large for one. The accepted
    /// value pins that bound rather than only proving it was tightened.
    #[test]
    fn duration_from_seconds_refuses_a_value_too_large_for_a_duration() {
        for seconds in [1e300, 2e19, f64::MAX] {
            assert!(
                duration_from_seconds(seconds, "`x`").is_err(),
                "{seconds} should have been refused"
            );
        }
        assert!(duration_from_seconds(1e19, "`x`").is_ok());
    }

    #[test]
    fn datetime_from_unix_seconds_refuses_non_finite_input() {
        for seconds in [f64::NEG_INFINITY, f64::INFINITY, f64::NAN] {
            assert!(datetime_from_unix_seconds(seconds).is_err());
        }
        let parsed = datetime_from_unix_seconds(0.0).unwrap();
        assert_eq!(parsed.timestamp(), 0);
    }

    /// The discriminant is what the Python exception's `kind` attribute
    /// carries, so every one of the eight stable names must map to itself.
    /// `EvidenceClientError` is `#[non_exhaustive]` at the enum level, which
    /// only bears on match exhaustiveness (a wildcard arm is required
    /// elsewhere in this module); it does not block constructing a
    /// known variant by name, so every case below is built directly rather
    /// than through the crate's own `pub(crate)` convenience constructors.
    #[test]
    fn map_client_error_reports_every_stable_kind() {
        let cases: Vec<(EvidenceClientError, &str)> = vec![
            (
                EvidenceClientError::Configuration { reason: "unusable" },
                "configuration",
            ),
            (EvidenceClientError::Nonce(NonceError::Entropy), "nonce"),
            (EvidenceClientError::Token(TokenError::Unavailable), "token"),
            (
                EvidenceClientError::Transport {
                    kind: TransportKind::Connect,
                },
                "transport",
            ),
            (
                EvidenceClientError::Denied {
                    status: 403,
                    code: "not_authorized".to_owned(),
                    operation: None,
                    retry_after_seconds: None,
                },
                "denied",
            ),
            (
                EvidenceClientError::NotAvailable { operation: None },
                "not_available",
            ),
            (
                EvidenceClientError::Protocol {
                    status: 500,
                    code: None,
                    operation: None,
                    retry_after_seconds: None,
                },
                "protocol",
            ),
            (
                EvidenceClientError::Verification(VerificationError::Signature),
                "verification",
            ),
        ];
        for (error, expected_kind) in &cases {
            let mapped = map_client_error(error);
            assert_eq!(mapped.kind, *expected_kind);
            assert_eq!(mapped.message, error.to_string());
        }
    }

    #[test]
    fn map_client_error_carries_the_denied_fields() {
        let error = EvidenceClientError::Denied {
            status: 429,
            code: "rate_limited".to_owned(),
            operation: Some("01JQ0QZ8YHZ0000000000000AB".to_owned()),
            retry_after_seconds: Some(30),
        };
        let mapped = map_client_error(&error);
        assert_eq!(mapped.status, Some(429));
        assert_eq!(mapped.code.as_deref(), Some("rate_limited"));
        assert_eq!(
            mapped.operation.as_deref(),
            Some("01JQ0QZ8YHZ0000000000000AB")
        );
        assert_eq!(mapped.retry_after_seconds, Some(30));
    }

    #[test]
    fn map_client_error_carries_the_transport_kind() {
        let mapped = map_client_error(&EvidenceClientError::Transport {
            kind: TransportKind::ResponseTooLarge,
        });
        assert_eq!(mapped.transport_kind, Some("response_too_large"));
    }

    #[test]
    fn map_client_error_carries_the_verifier_kind_as_the_code() {
        let mapped = map_client_error(&EvidenceClientError::Verification(
            VerificationError::Signature,
        ));
        assert_eq!(mapped.kind, "verification");
        assert_eq!(mapped.code.as_deref(), Some("signature"));
    }

    /// Every one of `TokenError`'s six sub-kinds carries its own `token_kind`
    /// under the client-level "token" kind, and only its own further sub-field
    /// (`transport_kind`, `code`, or `status`) alongside it.
    #[test]
    fn map_client_error_carries_the_token_kind_and_its_own_sub_fields() {
        let unavailable = map_client_error(&EvidenceClientError::Token(TokenError::Unavailable));
        assert_eq!(unavailable.kind, "token");
        assert_eq!(unavailable.token_kind, Some("unavailable"));

        let invalid = map_client_error(&EvidenceClientError::Token(TokenError::Invalid {
            reason: "a bearer credential must be non-empty and within the accepted length",
        }));
        assert_eq!(invalid.kind, "token");
        assert_eq!(invalid.token_kind, Some("invalid_credential"));

        let configuration =
            map_client_error(&EvidenceClientError::Token(TokenError::Configuration {
                reason: "the token provider cannot be used this way",
            }));
        assert_eq!(configuration.kind, "token");
        assert_eq!(configuration.token_kind, Some("configuration"));

        let transport = map_client_error(&EvidenceClientError::Token(TokenError::Transport {
            kind: TransportKind::Timeout,
        }));
        assert_eq!(transport.token_kind, Some("transport"));
        assert_eq!(transport.transport_kind, Some("timeout"));

        let refused = map_client_error(&EvidenceClientError::Token(TokenError::Refused {
            code: OAuthErrorCode::InvalidClient,
        }));
        assert_eq!(refused.token_kind, Some("refused"));
        assert_eq!(refused.code.as_deref(), Some("invalid_client"));

        let protocol = map_client_error(&EvidenceClientError::Token(TokenError::Protocol {
            status: 500,
        }));
        assert_eq!(protocol.token_kind, Some("protocol"));
        assert_eq!(protocol.status, Some(500));
    }

    /// `code` and `operation` are already bounded upstream
    /// (`evidence_client_sdk::problem::is_contract_code` and
    /// `sanitized_operation`), so this only proves the mapping does not
    /// re-encode, truncate, or otherwise alter an already-bounded value.
    #[test]
    fn map_client_error_passes_already_bounded_code_and_operation_through_unchanged() {
        let code = "a".repeat(64);
        let operation = "B".repeat(64);
        let mapped = map_client_error(&EvidenceClientError::Denied {
            status: 401,
            code: code.clone(),
            operation: Some(operation.clone()),
            retry_after_seconds: None,
        });
        assert_eq!(mapped.code, Some(code));
        assert_eq!(mapped.operation, Some(operation));
    }

    /// Mirrors the wrapped crate's own redaction tests and the Node binding's
    /// `mapped_errors_never_carry_a_credential_key_selector_value_or_subject_binding`:
    /// plant a canary value in every place a credential, key, selector value,
    /// or subject binding legitimately reaches this crate's own conversion
    /// and error-mapping layer, and confirm the mapped failure this crate
    /// hands to `to_py_err` never repeats it. A response body never reaches
    /// this module at all (`map_client_error` never touches
    /// `RawEvidenceResponse`), so it has no case here; the wrapped crate's own
    /// test already covers it.
    ///
    /// Six arrangements. In four of them, the canary is the very value the
    /// refusing code is judging when it refuses: a bearer credential, a
    /// signing key's `d` member, an array selector value, and a bare
    /// `subject_expectations` string that is not `"accept_first_use"`. In the
    /// remaining two, the canary instead sits in a well-typed selector value
    /// or pinned subject binding while an unrelated missing-`purpose`
    /// refusal fires; those two prove only that an unrelated error does not
    /// sweep up a value merely sitting in memory, a narrower property than
    /// the first four but still worth keeping.
    ///
    /// Each arrangement first asserts on the specific error it produces, not
    /// only on the canary's absence: if a step refused for an unrelated
    /// reason instead of carrying the canary to the intended place, that
    /// assertion catches it before the canary check could pass vacuously.
    #[test]
    fn mapped_errors_never_carry_a_credential_key_selector_value_or_subject_binding() {
        const CANARY: &str = "secret-canary-value";

        fn assert_canary_absent(mapped: &MappedError) {
            assert!(
                !mapped.message.contains(CANARY),
                "leaked in message: {}",
                mapped.message
            );
            if let Some(code) = &mapped.code {
                assert!(!code.contains(CANARY), "leaked in code: {code}");
            }
            if let Some(operation) = &mapped.operation {
                assert!(
                    !operation.contains(CANARY),
                    "leaked in operation: {operation}"
                );
            }
        }

        // A bearer credential shaped exactly as a caller might submit one by
        // mistake (here, carrying a trailing newline `BearerToken` refuses):
        // the fixed refusal reason must not repeat the credential itself.
        // Carried by `TokenError::Invalid`, reached through
        // `config_from_parts` -> `token_provider_from_json` ->
        // `StaticToken::new`.
        let error = config_from_parts(
            "https://evidence.example/",
            &serde_json::json!({ "keys": [] }),
            Vec::new(),
            &Value::String(format!("{CANARY}\n")),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect_err("a newline is refused");
        assert!(matches!(
            error,
            ConfigError::Client(EvidenceClientError::Token(TokenError::Invalid { .. }))
        ));
        assert_canary_absent(&map_config_error(&error));

        // A signing key whose private component is the canary: well-shaped
        // JSON, but not a valid Ed25519 scalar, so `PrivateJwk::parse`
        // refuses it. The refusal must describe the field (`d`), never echo
        // it. Carried by that parse failure, reached through
        // `config_from_parts` -> `private_key_jwt_provider_from_json`.
        let token = serde_json::json!({
            "private_key_jwt": {
                "token_endpoint": "https://issuer.example/token",
                "client_id": "test-client",
                "client_key": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "d": CANARY,
                },
            }
        });
        let error = config_from_parts(
            "https://evidence.example/",
            &serde_json::json!({ "keys": [] }),
            Vec::new(),
            &token,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect_err("the malformed key is refused");
        assert!(matches!(error, ConfigError::Shape(_)));
        assert_canary_absent(&map_config_error(&error));

        // A selector value carrying the canary, in a specification refused
        // for an unrelated reason (a missing `purpose`): the canary is parsed
        // and held in memory (subjects are parsed before `purpose` is
        // checked) before the refusal, but the refusal itself must not
        // mention it. Carried by the missing-`purpose` `ConversionError` from
        // `spec_from_json`.
        let mut spec = valid_spec_json();
        spec["subjects"][0]["selector_values"] = serde_json::json!({ "record_reference": CANARY });
        spec.as_object_mut().unwrap().remove("purpose");
        let error = spec_from_json(&spec).expect_err("the missing `purpose` is refused");
        assert_eq!(error, ConversionError::new("`purpose` must be a string"));
        assert_canary_absent(&map_conversion_error(&error));

        // A pinned subject binding carrying the canary, in a specification
        // refused for the same unrelated reason: `subject_expectations` is
        // likewise parsed before `purpose` is checked.
        let mut spec = valid_spec_json();
        spec["subject_expectations"] = serde_json::json!([
            { "role": "subject", "binding": CANARY }
        ]);
        spec.as_object_mut().unwrap().remove("purpose");
        let error = spec_from_json(&spec).expect_err("the missing `purpose` is refused");
        assert_eq!(error, ConversionError::new("`purpose` must be a string"));
        assert_canary_absent(&map_conversion_error(&error));

        // A selector value whose offending input is the canary: an array is
        // not one of the permitted selector value shapes, so
        // `selector_value_from_json` refuses it with its own fixed message.
        // `purpose` is left in place, so this refusal, unlike the two above,
        // is caused by the canary itself rather than merely coinciding with
        // one raised for an unrelated reason.
        let mut spec = valid_spec_json();
        spec["subjects"][0]["selector_values"] =
            serde_json::json!({ "record_reference": [CANARY] });
        let error = spec_from_json(&spec).expect_err("an array selector value is refused");
        assert_eq!(
            error,
            ConversionError::new("a selector value must be a string, an integer, or a boolean")
        );
        assert_canary_absent(&map_conversion_error(&error));

        // A `subject_expectations` value whose offending input is the
        // canary: a bare string that is not `"accept_first_use"` is refused
        // by `subject_expectations_from_json`'s own fixed message. `purpose`
        // is again left in place, so the canary itself causes this refusal.
        let mut spec = valid_spec_json();
        spec["subject_expectations"] = Value::String(CANARY.to_owned());
        let error =
            spec_from_json(&spec).expect_err("a bare non-accept_first_use string is refused");
        assert_eq!(
            error,
            ConversionError::new(
                "`subject_expectations` must be \"accept_first_use\" or a sequence of {\"role\", \"binding\"} mappings"
            )
        );
        assert_canary_absent(&map_conversion_error(&error));
    }

    #[test]
    fn map_conversion_error_reports_the_configuration_kind() {
        let mapped = map_conversion_error(&ConversionError::new("a canary reason"));
        assert_eq!(mapped.kind, "configuration");
        assert_eq!(mapped.message, "a canary reason");
    }

    #[test]
    fn map_config_error_delegates_to_the_right_mapping() {
        let shape = map_config_error(&ConfigError::Shape(ConversionError::new("bad shape")));
        assert_eq!(shape.kind, "configuration");

        let client = map_config_error(&ConfigError::Client(EvidenceClientError::Token(
            TokenError::Unavailable,
        )));
        assert_eq!(client.kind, "token");
        assert_eq!(client.token_kind, Some("unavailable"));
    }

    #[test]
    fn evidence_to_json_serializes_the_verified_payload() {
        use evidence_client_sdk::{
            Evidence, EvidenceObjectType, PublicValue, SubjectBinding, SupportedValue,
        };

        let evidence = Evidence {
            schema: registry_evidence_verifier::EVIDENCE_SCHEMA_V1.to_owned(),
            assurance_profile: AssuranceProfile::Local,
            request_nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            id: "urn:example:evidence:convert-test".to_owned(),
            evidence_type_name: EvidenceObjectType::Evidence,
            supports_requirement: "urn:example:requirement:v1".to_owned(),
            is_conformant_to: "urn:example:evidence-type:v1".to_owned(),
            issued_by: "urn:example:issuer".to_owned(),
            provided_by: "urn:example:provider".to_owned(),
            issued_at: "2026-08-01T00:00:00Z".to_owned(),
            observed_at: "2026-08-01T00:00:00Z".to_owned(),
            valid_until: "2026-08-01T00:05:00Z".to_owned(),
            purpose: "example-purpose".to_owned(),
            audience: "urn:example:audience".to_owned(),
            configuration_revision: format!("sha256:{}", "0".repeat(64)),
            subjects: vec![SubjectBinding {
                role: "subject".to_owned(),
                binding: format!("urn:evidence:subject:v1_{}", "A".repeat(43)),
            }],
            supported_values: vec![SupportedValue {
                provides_value_for: "urn:example:concept:status-holds".to_owned(),
                value: PublicValue::Boolean(true),
            }],
        };

        let value = evidence_to_json(&evidence).expect("evidence serializes");
        assert_eq!(value["requestNonce"], Value::String(evidence.request_nonce));
        assert_eq!(
            value["subjects"][0]["role"],
            Value::String("subject".to_owned())
        );
    }
}
