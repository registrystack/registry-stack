//! JS-value <-> Rust conversions for the Evidence Node binding.
//!
//! Every function here is a plain Rust function over [`serde_json::Value`],
//! so the whole conversion layer is unit-testable with `cargo test` and
//! carries no dependency on `napi`. `src/lib.rs` is the only file in this
//! crate that touches the `napi`/`napi-derive` crates; it calls into this
//! module for every conversion and reports failures through
//! [`map_client_error`], [`map_conversion_error`], and [`map_config_error`].

use std::{fmt, sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use registry_evidence_client::{
    AssuranceProfile, Evidence, EvidenceClientConfig, EvidenceClientError, EvidenceRequestSpec,
    EvidenceResponseFormat, ExpectedOutputDocument, ExpectedSubjectDocument, HolderPublicKey,
    JwksDocument, PrivateKeyJwt, PrivateKeyJwtConfig, SelectorValue, StaticToken,
    SubjectExpectations, SubjectRequest, TokenError, TokenProvider,
};
use registry_platform_crypto::PrivateJwk;
use serde_json::{Map, Value};
use url::Url;

/// A JS-supplied value did not have the shape this binding requires.
///
/// This is distinct from [`EvidenceClientError`]: it is refused before any
/// client-level Rust type exists, so it carries its own message rather than
/// borrowing the fixed `&'static str` reason of a type that cannot describe a
/// dynamically built JS shape.
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
/// them distinct lets a caller (and a test) tell "the JS object was malformed"
/// apart from "the configuration it described is unusable."
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

fn required_string_array(
    object: &Map<String, Value>,
    field: &str,
) -> Result<Vec<String>, ConversionError> {
    let values = object
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| ConversionError::new(format!("`{field}` must be an array of strings")))?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| ConversionError::new(format!("`{field}` must contain only strings")))
        })
        .collect()
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

fn optional_u64(object: &Map<String, Value>, field: &str) -> Result<Option<u64>, ConversionError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or_else(|| {
            ConversionError::new(format!("`{field}` must be a non-negative integer"))
        }),
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

fn parse_url(value: &str, what: &str) -> Result<Url, ConversionError> {
    Url::parse(value).map_err(|_| ConversionError::new(format!("{what} must be a valid URL")))
}

/// Turn `verify_as_of`'s caller-supplied UNIX timestamp (milliseconds, as
/// `asOfMillis`) into the instant
/// [`registry_evidence_client::EvidenceClient::verify_as_of`] takes.
pub fn datetime_from_unix_millis(millis: f64) -> Result<DateTime<Utc>, ConversionError> {
    if !millis.is_finite() {
        return Err(ConversionError::new(
            "`asOfMillis` must be a finite number of milliseconds since the UNIX epoch",
        ));
    }
    DateTime::from_timestamp_millis(millis as i64)
        .ok_or_else(|| ConversionError::new("`asOfMillis` is not a representable instant"))
}

/// The three scalar shapes a selector value may take on the wire, read off a
/// JS value.
///
/// A float, an array, `null`, and an integer literal too large for `i64` are
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
    let selector_profile = required_string(object, "selectorProfile")?;
    let selector_values = match object.get("selectorValues") {
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
                "`selectorValues` must be an object mapping field names to values",
            ))
        }
    };
    Ok(SubjectRequest {
        role,
        selector_profile,
        selector_values,
    })
}

/// `subjectExpectations` accepts `{"pinned": [{"role", "binding"}, ...]}` or
/// the literal string `"acceptFirstUse"`. There is no third shape, matching
/// [`SubjectExpectations`] having no third variant.
pub fn subject_expectations_from_json(
    value: &Value,
) -> Result<SubjectExpectations, ConversionError> {
    match value {
        Value::String(tag) if tag == "acceptFirstUse" => Ok(SubjectExpectations::AcceptFirstUse),
        Value::Object(object) => {
            let pinned = object
                .get("pinned")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    ConversionError::new("a pinned subject expectation must carry a `pinned` array")
                })?;
            let mut subjects = Vec::with_capacity(pinned.len());
            for entry in pinned {
                let entry = as_object(entry, "a pinned subject expectation")?;
                subjects.push(ExpectedSubjectDocument {
                    role: required_string(entry, "role")?,
                    binding: required_string(entry, "binding")?,
                });
            }
            Ok(SubjectExpectations::Pinned(subjects))
        }
        _ => Err(ConversionError::new(
            "`subjectExpectations` must be \"acceptFirstUse\" or {\"pinned\": [...]}",
        )),
    }
}

/// The inverse of [`subject_expectations_from_json`]. Infallible: every
/// [`SubjectExpectations`] value already came from a caller's own request, and
/// both variants have an unambiguous JSON rendering.
pub fn subject_expectations_to_json(expectations: &SubjectExpectations) -> Value {
    match expectations {
        SubjectExpectations::AcceptFirstUse => Value::String("acceptFirstUse".to_owned()),
        SubjectExpectations::Pinned(subjects) => {
            let pinned: Vec<Value> = subjects
                .iter()
                .map(|subject| {
                    serde_json::json!({
                        "role": subject.role,
                        "binding": subject.binding,
                    })
                })
                .collect();
            serde_json::json!({ "pinned": pinned })
        }
    }
}

fn expected_outputs_from_json(
    value: &Value,
) -> Result<Vec<ExpectedOutputDocument>, ConversionError> {
    serde_json::from_value(value.clone())
        .map_err(|error| ConversionError::new(format!("`expectedOutputs` is invalid: {error}")))
}

fn assurance_profile_from_json(value: &Value) -> Result<AssuranceProfile, ConversionError> {
    serde_json::from_value(value.clone()).map_err(|error| {
        ConversionError::new(format!("`expectedAssuranceProfile` is invalid: {error}"))
    })
}

fn response_format_from_json(value: &Value) -> Result<EvidenceResponseFormat, ConversionError> {
    serde_json::from_value(value.clone()).map_err(|_| {
        ConversionError::new("`responseFormat` must be \"signed-jws\" or \"sd-jwt-vc\"")
    })
}

/// Every JWK member that carries a private key half, across the key types a
/// caller could paste one from.
///
/// [`HolderPublicKey`] is `deny_unknown_fields`, so each of these already
/// fails to deserialize. What that refusal cannot do is say why it matters: an
/// unknown member reads as a typo. A caller who pasted a whole key pair here
/// has done something materially different from mistyping a field name, and
/// gets told exactly that by the check below instead.
const PRIVATE_JWK_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "k", "oth"];

/// Read one caller-supplied holder public key.
///
/// The value is forwarded to the deployment exactly as given. Nothing about a
/// key is interpreted here: whether the key set is within the deployment's
/// batch ceiling, and whether each key is acceptable P-256 material, is the
/// wrapped client's own judgement in `prepare`, and what a key means to an
/// assertion is the deployment's.
///
/// No refusal below quotes any part of the value. The private-half refusal
/// names only the member it found, never its content, and the shape refusal
/// discards serde's own message rather than risk repeating a member's value
/// back to JS in a type error.
fn holder_key_from_json(value: &Value) -> Result<HolderPublicKey, ConversionError> {
    let object = as_object(value, "a holder key")?;
    if let Some(member) = PRIVATE_JWK_MEMBERS
        .iter()
        .find(|member| object.contains_key(**member))
    {
        return Err(ConversionError::new(format!(
            "a holder key must carry only public key material, and `{member}` is private key \
             material; send the public half of the key and keep the private half where it is"
        )));
    }
    serde_json::from_value(value.clone()).map_err(|_| {
        ConversionError::new(
            "a holder key must be a public JWK carrying `kty`, `crv`, `x`, and `y`, and at most \
             `alg` and `kid` besides",
        )
    })
}

/// `holderKeys` is the caller's own key list, in the order it wants those keys
/// answered. Absent (or `null`) is the request that presents none, which is
/// the request this binding has always sent.
fn holder_keys_from_json(
    object: &Map<String, Value>,
) -> Result<Vec<HolderPublicKey>, ConversionError> {
    match object.get("holderKeys") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(entries)) => entries.iter().map(holder_key_from_json).collect(),
        Some(_) => Err(ConversionError::new(
            "`holderKeys` must be an array of public JWKs",
        )),
    }
}

/// Build the specification [`registry_evidence_client::EvidenceClient::prepare`]
/// validates. Only shape is checked here: an empty identifier, an out-of-range
/// count, or any other business rule is the real client's own refusal, raised
/// once a genuine `EvidenceRequestSpec` exists.
pub fn spec_from_json(value: &Value) -> Result<EvidenceRequestSpec, ConversionError> {
    let object = as_object(value, "a request specification")?;

    let subjects_json = object
        .get("subjects")
        .and_then(Value::as_array)
        .ok_or_else(|| ConversionError::new("`subjects` must be an array"))?;
    let subjects = subjects_json
        .iter()
        .map(subject_request_from_json)
        .collect::<Result<Vec<_>, _>>()?;

    let expected_outputs_json = object
        .get("expectedOutputs")
        .ok_or_else(|| ConversionError::new("`expectedOutputs` must be present"))?;
    let expected_outputs = expected_outputs_from_json(expected_outputs_json)?;

    let expected_assurance_profile_json = object
        .get("expectedAssuranceProfile")
        .ok_or_else(|| ConversionError::new("`expectedAssuranceProfile` must be present"))?;
    let expected_assurance_profile = assurance_profile_from_json(expected_assurance_profile_json)?;

    let subject_expectations_json = object
        .get("subjectExpectations")
        .ok_or_else(|| ConversionError::new("`subjectExpectations` must be present"))?;
    let subject_expectations = subject_expectations_from_json(subject_expectations_json)?;

    let response_format_json = object
        .get("responseFormat")
        .ok_or_else(|| ConversionError::new("`responseFormat` must be present"))?;
    let response_format = response_format_from_json(response_format_json)?;

    Ok(EvidenceRequestSpec {
        response_format,
        requirement: required_string(object, "requirement")?,
        purpose: required_string(object, "purpose")?,
        audience: required_string(object, "audience")?,
        evidence_type: required_string(object, "evidenceType")?,
        issued_by: required_string(object, "issuedBy")?,
        provided_by: required_string(object, "providedBy")?,
        configuration_revision: required_string(object, "configurationRevision")?,
        expected_assurance_profile,
        subjects,
        holder_keys: holder_keys_from_json(object)?,
        expected_outputs,
        maximum_assertion_lifetime_seconds: required_u64(
            object,
            "maximumAssertionLifetimeSeconds",
        )?,
        clock_skew_seconds: required_u64(object, "clockSkewSeconds")?,
        subject_expectations,
    })
}

/// `token.privateKeyJwt`'s own shape mirrors [`PrivateKeyJwtConfig`]'s builder
/// surface: one required endpoint, client identifier, and signing key, plus
/// the same optional knobs the Rust type exposes for its own outbound
/// exchange with the token endpoint.
fn private_key_jwt_provider_from_json(value: &Value) -> Result<PrivateKeyJwt, ConfigError> {
    let object = as_object(value, "`token.privateKeyJwt`").map_err(ConfigError::Shape)?;

    let token_endpoint = parse_url(
        &required_string(object, "tokenEndpoint").map_err(ConfigError::Shape)?,
        "`token.privateKeyJwt.tokenEndpoint`",
    )
    .map_err(ConfigError::Shape)?;
    let client_id = required_string(object, "clientId").map_err(ConfigError::Shape)?;

    let client_key_json = object.get("clientKey").ok_or_else(|| {
        ConfigError::Shape(ConversionError::new(
            "`token.privateKeyJwt.clientKey` must be present",
        ))
    })?;
    let client_key_text = serde_json::to_string(client_key_json).map_err(|error| {
        ConfigError::Shape(ConversionError::new(format!(
            "`token.privateKeyJwt.clientKey` is invalid: {error}"
        )))
    })?;
    let client_key = PrivateJwk::parse(&client_key_text).map_err(|error| {
        ConfigError::Shape(ConversionError::new(format!(
            "`token.privateKeyJwt.clientKey` is invalid: {error}"
        )))
    })?;

    let mut config = PrivateKeyJwtConfig::new(token_endpoint, client_id, client_key);
    if let Some(audience) = optional_string(object, "audience").map_err(ConfigError::Shape)? {
        config = config.with_audience(audience);
    }
    if let Some(seconds) =
        optional_i64(object, "assertionLifetimeSeconds").map_err(ConfigError::Shape)?
    {
        config = config.with_assertion_lifetime_seconds(seconds);
    }
    if let Some(seconds) =
        optional_i64(object, "refreshMarginSeconds").map_err(ConfigError::Shape)?
    {
        config = config.with_refresh_margin_seconds(seconds);
    }
    if let Some(millis) = optional_u64(object, "requestTimeoutMs").map_err(ConfigError::Shape)? {
        config = config.with_request_timeout(Duration::from_millis(millis));
    }
    if let Some(millis) = optional_u64(object, "connectTimeoutMs").map_err(ConfigError::Shape)? {
        config = config.with_connect_timeout(Duration::from_millis(millis));
    }
    if let Some(user_agent) = optional_string(object, "userAgent").map_err(ConfigError::Shape)? {
        config = config.with_user_agent(user_agent);
    }
    if let Some(pem_bundle) =
        optional_string(object, "trustedRootCertificates").map_err(ConfigError::Shape)?
    {
        config = config.with_trusted_root_certificates(pem_bundle.into_bytes());
    }

    PrivateKeyJwt::new(config).map_err(ConfigError::from)
}

fn token_provider_from_json(
    object: &Map<String, Value>,
) -> Result<Arc<dyn TokenProvider>, ConfigError> {
    let token = object
        .get("token")
        .ok_or_else(|| ConversionError::new("`token` must be present"))
        .map_err(ConfigError::Shape)?;
    let token_object = as_object(token, "`token`").map_err(ConfigError::Shape)?;
    // Before dispatching on which provider is named: selecting the first one
    // present would let a merge of two authentication configurations, or a
    // misspelled key left beside a real one, run with a credential the caller
    // did not choose.
    if token_object.len() != 1 {
        return Err(ConfigError::Shape(ConversionError::new(
            "`token` must carry exactly one of `static` or `privateKeyJwt`",
        )));
    }

    if let Some(value) = token_object.get("static") {
        let value = value
            .as_str()
            .ok_or_else(|| ConversionError::new("`token.static` must be a string"))
            .map_err(ConfigError::Shape)?;
        let provider = StaticToken::new(value)?;
        return Ok(Arc::new(provider));
    }
    if let Some(value) = token_object.get("privateKeyJwt") {
        let provider = private_key_jwt_provider_from_json(value)?;
        return Ok(Arc::new(provider));
    }
    Err(ConfigError::Shape(ConversionError::new(
        "`token` must carry exactly one of `static` or `privateKeyJwt`",
    )))
}

/// Build the configuration [`registry_evidence_client::EvidenceClient::new`]
/// validates. Only shape is checked here (a missing field, a malformed URL, a
/// malformed key); the pinned-key-set, transport, and timeout business rules
/// are the real client's own refusal, raised once a genuine
/// `EvidenceClientConfig` exists.
pub fn config_from_json(value: &Value) -> Result<EvidenceClientConfig, ConfigError> {
    let object = as_object(value, "the client configuration").map_err(ConfigError::Shape)?;

    let base_url = parse_url(
        &required_string(object, "baseUrl").map_err(ConfigError::Shape)?,
        "`baseUrl`",
    )
    .map_err(ConfigError::Shape)?;

    let trusted_jwks_json = object
        .get("trustedJwks")
        .ok_or_else(|| ConfigError::Shape(ConversionError::new("`trustedJwks` must be present")))?;
    let trusted_jwks: JwksDocument =
        serde_json::from_value(trusted_jwks_json.clone()).map_err(|error| {
            ConfigError::Shape(ConversionError::new(format!(
                "`trustedJwks` is invalid: {error}"
            )))
        })?;
    let revoked_key_ids =
        required_string_array(object, "revokedKeyIds").map_err(ConfigError::Shape)?;

    let token_provider = token_provider_from_json(object)?;

    let mut config =
        EvidenceClientConfig::new(base_url, token_provider, trusted_jwks, revoked_key_ids);

    if let Some(millis) = optional_u64(object, "requestTimeoutMs").map_err(ConfigError::Shape)? {
        config = config.with_request_timeout(Duration::from_millis(millis));
    }
    if let Some(millis) = optional_u64(object, "connectTimeoutMs").map_err(ConfigError::Shape)? {
        config = config.with_connect_timeout(Duration::from_millis(millis));
    }
    if let Some(user_agent) = optional_string(object, "userAgent").map_err(ConfigError::Shape)? {
        config = config.with_user_agent(user_agent);
    }
    if let Some(pem_bundle) =
        optional_string(object, "trustedRootCertificates").map_err(ConfigError::Shape)?
    {
        config = config.with_trusted_root_certificates(pem_bundle.into_bytes());
    }
    if let Some(max_bytes) = optional_u64(object, "maxResponseBytes").map_err(ConfigError::Shape)? {
        config = config.with_max_response_bytes(max_bytes);
    }
    if let Some(max_bytes) = optional_u64(object, "maxMetadataBytes").map_err(ConfigError::Shape)? {
        config = config.with_max_metadata_bytes(max_bytes);
    }

    Ok(config)
}

/// The verified payload crosses to JS through this, never through `Debug`.
pub fn evidence_to_json(evidence: &Evidence) -> Result<Value, ConversionError> {
    serde_json::to_value(evidence).map_err(|error| {
        ConversionError::new(format!(
            "the verified evidence payload could not be serialized: {error}"
        ))
    })
}

/// A shape-level failure reports the same stable envelope every mapped
/// failure uses, so a caller need not special-case where a failure
/// originated. There is no dedicated "shape" kind among the eight the runtime
/// client defines; a JS caller that supplied an unusable shape is, from the
/// caller's side, exactly the "the client cannot be used as configured" case.
pub fn map_conversion_error(error: &ConversionError) -> Value {
    serde_json::json!({
        "kind": "configuration",
        "message": error.to_string(),
    })
}

pub fn map_config_error(error: &ConfigError) -> Value {
    match error {
        ConfigError::Shape(shape) => map_conversion_error(shape),
        ConfigError::Client(client) => map_client_error(client),
    }
}

/// Map any [`EvidenceClientError`] to the stable JSON envelope described in
/// the crate's `AGENTS.md`-linked design: `kind` and `message` always, plus
/// whichever of `status`, `code`, `operation`, `retryAfterSeconds`,
/// `transportKind`, and `tokenKind` the variant carries. `code` is
/// deliberately overloaded: a `Denied`/`Protocol` wire code, a
/// `Token::Refused` OAuth code, and a `Verification` failure's own kind string
/// all travel in the same member, since a caller branches on `kind` first and
/// `code` only refines it. `tokenKind` is `Token`'s own analogous second
/// discriminant: every `TokenError` carries one, from [`TokenError::kind`],
/// alongside whichever further sub-fields (`transportKind`, `code`, `status`)
/// that specific variant also carries.
///
/// Never included: response bytes, a credential, a header value, a selector
/// value, or a subject binding. Every message here is `Display` text over
/// fixed, non-secret reasons; none of the eight kinds can carry one of those.
pub fn map_client_error(error: &EvidenceClientError) -> Value {
    let mut fields = Map::new();
    fields.insert("kind".to_owned(), Value::String(error.kind().to_owned()));
    fields.insert("message".to_owned(), Value::String(error.to_string()));

    match error {
        // Deliberately no `nonceKind` field: `NonceError::NotCanonical` is
        // constructed only inside `RequestNonce::parse`'s own unit tests, so
        // this crate's production path can only ever fail here with
        // `NonceError::Entropy`, which carries nothing further to report.
        EvidenceClientError::Configuration { .. } | EvidenceClientError::Nonce(_) => {}
        EvidenceClientError::Token(token_error) => insert_token_fields(&mut fields, token_error),
        EvidenceClientError::Transport { kind } => {
            fields.insert(
                "transportKind".to_owned(),
                Value::String(kind.kind().to_owned()),
            );
        }
        EvidenceClientError::Denied {
            status,
            code,
            operation,
            retry_after_seconds,
        } => {
            fields.insert("status".to_owned(), Value::from(*status));
            fields.insert("code".to_owned(), Value::String(code.clone()));
            insert_operation(&mut fields, operation);
            insert_retry_after(&mut fields, *retry_after_seconds);
        }
        EvidenceClientError::NotAvailable { operation } => {
            insert_operation(&mut fields, operation);
        }
        EvidenceClientError::Protocol {
            status,
            code,
            operation,
            retry_after_seconds,
        } => {
            fields.insert("status".to_owned(), Value::from(*status));
            if let Some(code) = code {
                fields.insert("code".to_owned(), Value::String(code.clone()));
            }
            insert_operation(&mut fields, operation);
            insert_retry_after(&mut fields, *retry_after_seconds);
        }
        EvidenceClientError::Verification(verification_error) => {
            fields.insert(
                "code".to_owned(),
                Value::String(verification_error.kind().to_owned()),
            );
        }
        // `EvidenceClientError` is `#[non_exhaustive]`: a variant this crate
        // does not yet know about still maps, with only `kind` and `message`.
        _ => {}
    }

    Value::Object(fields)
}

fn insert_token_fields(fields: &mut Map<String, Value>, error: &TokenError) {
    fields.insert(
        "tokenKind".to_owned(),
        Value::String(error.kind().to_owned()),
    );
    match error {
        TokenError::Unavailable | TokenError::Invalid { .. } | TokenError::Configuration { .. } => {
        }
        TokenError::Transport { kind } => {
            fields.insert(
                "transportKind".to_owned(),
                Value::String(kind.kind().to_owned()),
            );
        }
        TokenError::Refused { code } => {
            fields.insert("code".to_owned(), Value::String(code.as_str().to_owned()));
        }
        TokenError::Protocol { status } => {
            fields.insert("status".to_owned(), Value::from(*status));
        }
        // `TokenError` is `#[non_exhaustive]`.
        _ => {}
    }
}

fn insert_operation(fields: &mut Map<String, Value>, operation: &Option<String>) {
    if let Some(operation) = operation {
        fields.insert("operation".to_owned(), Value::String(operation.clone()));
    }
}

fn insert_retry_after(fields: &mut Map<String, Value>, retry_after_seconds: Option<u64>) {
    if let Some(seconds) = retry_after_seconds {
        fields.insert("retryAfterSeconds".to_owned(), Value::from(seconds));
    }
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ed25519_dalek::SigningKey;
    use registry_evidence_client::{
        EvidenceObjectType, OAuthErrorCode, SubjectBinding, SubjectBindingMode, SupportedValue,
        TransportKind, VerificationError,
    };

    use super::*;

    // --- datetime_from_unix_millis ---

    #[test]
    fn a_non_finite_millis_value_is_refused() {
        for millis in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(
                datetime_from_unix_millis(millis).is_err(),
                "{millis} was accepted"
            );
        }
    }

    #[test]
    fn a_millis_value_outside_the_representable_range_is_refused() {
        assert!(datetime_from_unix_millis(f64::MAX).is_err());
    }

    #[test]
    fn a_millis_value_converts_to_the_expected_instant() {
        let parsed = datetime_from_unix_millis(1_000.0).expect("the value converts");
        assert_eq!(parsed.timestamp(), 1);
    }

    // --- selector_value_from_json ---

    #[test]
    fn a_string_selector_value_converts() {
        assert_eq!(
            selector_value_from_json(&Value::String("synthetic-record-001".to_owned())).unwrap(),
            SelectorValue::from("synthetic-record-001")
        );
    }

    #[test]
    fn a_boolean_selector_value_converts() {
        assert_eq!(
            selector_value_from_json(&Value::Bool(true)).unwrap(),
            SelectorValue::from(true)
        );
    }

    #[test]
    fn an_integer_selector_value_converts() {
        assert_eq!(
            selector_value_from_json(&serde_json::json!(7)).unwrap(),
            SelectorValue::from(7_i64)
        );
    }

    #[test]
    fn a_selector_value_outside_the_accepted_shapes_is_refused() {
        for value in [
            serde_json::json!(1.5),
            serde_json::json!([1, 2, 3]),
            Value::Null,
            // i64::MAX + 1: a valid JSON integer, but not one `i64` can hold.
            serde_json::json!(9_223_372_036_854_775_808_u64),
        ] {
            assert!(
                selector_value_from_json(&value).is_err(),
                "{value} was accepted"
            );
        }
    }

    // --- subject_expectations_from_json / _to_json ---

    #[test]
    fn accept_first_use_round_trips() {
        let value = Value::String("acceptFirstUse".to_owned());
        let expectations = subject_expectations_from_json(&value).expect("the shape is accepted");
        assert!(matches!(expectations, SubjectExpectations::AcceptFirstUse));
        assert_eq!(subject_expectations_to_json(&expectations), value);
    }

    #[test]
    fn pinned_subject_expectations_round_trip() {
        let value = serde_json::json!({
            "pinned": [{"role": "subject", "binding": "y0KMdWluZGluZw"}],
        });
        let expectations = subject_expectations_from_json(&value).expect("the shape is accepted");
        let SubjectExpectations::Pinned(subjects) = &expectations else {
            panic!("expected a pinned subject expectation");
        };
        assert_eq!(subjects.len(), 1);
        assert_eq!(subjects[0].role, "subject");
        assert_eq!(subjects[0].binding, "y0KMdWluZGluZw");
        assert_eq!(subject_expectations_to_json(&expectations), value);
    }

    #[test]
    fn a_subject_expectation_outside_the_two_accepted_shapes_is_refused() {
        for value in [
            Value::String("something-else".to_owned()),
            serde_json::json!({}),
            serde_json::json!({"pinned": [{"role": "subject"}]}),
            serde_json::json!(1),
            Value::Null,
        ] {
            assert!(
                subject_expectations_from_json(&value).is_err(),
                "{value} was accepted"
            );
        }
    }

    // --- spec_from_json ---

    fn valid_spec_json() -> Value {
        serde_json::json!({
            "responseFormat": "signed-jws",
            "requirement": "urn:example:client:requirement:status:v1",
            "purpose": "example-decision",
            "audience": "urn:example:client:audience:relying-party",
            "evidenceType": "urn:example:client:evidence-type:status:v1",
            "issuedBy": "urn:example:client:issuer",
            "providedBy": "urn:example:client:provider",
            "configurationRevision": "sha256:00",
            "expectedAssuranceProfile": "local",
            "subjects": [{
                "role": "subject",
                "selectorProfile": "record-lookup-v1",
                "selectorValues": {
                    "record_reference": "synthetic-record-001",
                },
            }],
            "expectedOutputs": [{
                "concept": "urn:example:client:concept:status-holds",
                "form": "boolean",
            }],
            "maximumAssertionLifetimeSeconds": 300,
            "clockSkewSeconds": 60,
            "subjectExpectations": "acceptFirstUse",
        })
    }

    #[test]
    fn a_well_formed_specification_converts_in_full() {
        let spec = spec_from_json(&valid_spec_json()).expect("the specification is accepted");
        assert_eq!(spec.requirement, "urn:example:client:requirement:status:v1");
        assert_eq!(spec.response_format, EvidenceResponseFormat::SignedJws);
        assert_eq!(spec.expected_assurance_profile, AssuranceProfile::Local);
        assert_eq!(spec.subjects.len(), 1);
        assert_eq!(spec.subjects[0].role, "subject");
        assert_eq!(
            spec.subjects[0].selector_values.as_ref().unwrap()[0].0,
            "record_reference"
        );
        assert_eq!(spec.expected_outputs.len(), 1);
        assert_eq!(spec.maximum_assertion_lifetime_seconds, 300);
        assert_eq!(spec.clock_skew_seconds, 60);
        assert!(matches!(
            spec.subject_expectations,
            SubjectExpectations::AcceptFirstUse
        ));
    }

    #[test]
    fn a_specification_missing_any_required_field_is_refused() {
        let required_fields = [
            "responseFormat",
            "requirement",
            "purpose",
            "audience",
            "evidenceType",
            "issuedBy",
            "providedBy",
            "configurationRevision",
            "expectedAssuranceProfile",
            "subjects",
            "expectedOutputs",
            "maximumAssertionLifetimeSeconds",
            "clockSkewSeconds",
            "subjectExpectations",
        ];
        for field in required_fields {
            let mut spec = valid_spec_json();
            spec.as_object_mut().unwrap().remove(field);
            assert!(
                spec_from_json(&spec).is_err(),
                "missing `{field}` was accepted"
            );
        }
    }

    #[test]
    fn a_specification_accepts_both_response_formats_and_refuses_other_values() {
        let mut spec = valid_spec_json();
        spec["responseFormat"] = Value::String("sd-jwt-vc".to_owned());
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
            spec["responseFormat"] = value;
            assert!(spec_from_json(&spec).is_err());
        }
    }

    // --- holder keys ---

    /// Two genuine, on-curve P-256 public points, so an accepted key here is
    /// one the wrapped client's own acceptability check would also accept
    /// rather than merely a well-shaped object.
    fn holder_key_json(index: usize) -> Value {
        let (x, y) = [
            (
                "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
                "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
            ),
            (
                "fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI_EdmmXg",
                "B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9E",
            ),
        ][index % 2];
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
            "alg": "ES256",
            "kid": format!("holder-key-{index}"),
        })
    }

    #[test]
    fn holder_keys_reach_the_specification_in_the_order_the_caller_stated() {
        let mut spec = valid_spec_json();
        spec["holderKeys"] = serde_json::json!([holder_key_json(0), holder_key_json(1)]);
        let converted = spec_from_json(&spec).expect("the specification is accepted");
        assert_eq!(converted.holder_keys.len(), 2);
        assert_eq!(
            converted.holder_keys[0].kid.as_deref(),
            Some("holder-key-0")
        );
        assert_eq!(
            converted.holder_keys[1].kid.as_deref(),
            Some("holder-key-1")
        );
        assert!(converted
            .holder_keys
            .iter()
            .all(HolderPublicKey::is_acceptable));
    }

    #[test]
    fn a_holder_key_may_omit_its_algorithm_and_identifier() {
        let mut key = holder_key_json(0);
        let object = key.as_object_mut().unwrap();
        object.remove("alg");
        object.remove("kid");
        let mut spec = valid_spec_json();
        spec["holderKeys"] = serde_json::json!([key]);
        let converted = spec_from_json(&spec).expect("the specification is accepted");
        assert_eq!(converted.holder_keys.len(), 1);
        assert!(converted.holder_keys[0].alg.is_none());
        assert!(converted.holder_keys[0].kid.is_none());
    }

    #[test]
    fn a_specification_presenting_no_holder_key_carries_an_empty_set() {
        assert!(spec_from_json(&valid_spec_json())
            .expect("the specification is accepted")
            .holder_keys
            .is_empty());

        let mut spec = valid_spec_json();
        spec["holderKeys"] = Value::Null;
        assert!(spec_from_json(&spec)
            .expect("an explicit null presents no key")
            .holder_keys
            .is_empty());

        let mut spec = valid_spec_json();
        spec["holderKeys"] = serde_json::json!([]);
        assert!(spec_from_json(&spec)
            .expect("an empty array presents no key")
            .holder_keys
            .is_empty());
    }

    /// The refusal a caller who pasted a whole key pair has to be able to act
    /// on. `deny_unknown_fields` alone would refuse `d` as an unrecognized
    /// member, which reads as a typo; this asserts the stated reason names
    /// private key material and the member carrying it, and that the private
    /// value itself is not repeated back.
    #[test]
    fn a_holder_key_carrying_a_private_member_is_refused_as_private_key_material() {
        const PRIVATE_VALUE: &str = "secret-private-scalar-value";

        for member in PRIVATE_JWK_MEMBERS {
            let mut key = holder_key_json(0);
            key[member] = Value::String(PRIVATE_VALUE.to_owned());
            let mut spec = valid_spec_json();
            spec["holderKeys"] = serde_json::json!([key]);

            let error = spec_from_json(&spec).expect_err("the private member is refused");
            assert!(
                error.0.contains("private key material"),
                "`{member}` was refused without stating why: {error}"
            );
            assert!(
                error.0.contains(&format!("`{member}`")),
                "the refusal does not name `{member}`: {error}"
            );
            assert!(
                !error.0.contains(PRIVATE_VALUE),
                "the private value leaked in: {error}"
            );
        }
    }

    #[test]
    fn a_holder_key_outside_the_public_jwk_shape_is_refused() {
        for key in [
            // An unknown member, refused structurally by
            // `deny_unknown_fields` rather than by the private-member check.
            serde_json::json!({
                "kty": "EC", "crv": "P-256", "x": "AA", "y": "BB", "use": "sig",
            }),
            serde_json::json!({ "kty": "EC", "crv": "P-256", "x": "AA" }),
            serde_json::json!("not-an-object"),
            Value::Null,
        ] {
            let mut spec = valid_spec_json();
            spec["holderKeys"] = serde_json::json!([key.clone()]);
            assert!(spec_from_json(&spec).is_err(), "{key} was accepted");
        }

        for keys in [
            serde_json::json!({}),
            Value::String("a-key".to_owned()),
            serde_json::json!(1),
        ] {
            let mut spec = valid_spec_json();
            spec["holderKeys"] = keys.clone();
            assert!(spec_from_json(&spec).is_err(), "{keys} was accepted");
        }
    }

    #[test]
    fn a_specification_that_is_not_an_object_is_refused() {
        assert!(spec_from_json(&Value::Null).is_err());
        assert!(spec_from_json(&serde_json::json!([])).is_err());
    }

    // --- config_from_json ---

    fn one_key_jwks_json() -> Value {
        serde_json::json!({
            "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "kid": "_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo",
                "alg": "ES256",
                "x": "3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4",
                "y": "GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU",
            }],
        })
    }

    /// A fresh Ed25519 signing key, generated for one test rather than
    /// committed to the tree.
    fn generated_client_key_json(key_id: &str) -> Value {
        let mut seed = [0_u8; 32];
        getrandom::fill(&mut seed).expect("the test host supplies randomness");
        let key = SigningKey::from_bytes(&seed);
        serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "kid": key_id,
            "x": URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
            "d": URL_SAFE_NO_PAD.encode(key.to_bytes()),
        })
    }

    /// A fresh ES256 signing key, in the shape `evidencectl access client add
    /// --generate-local-key` writes.
    fn generated_es256_client_key_json(key_id: &str) -> Value {
        let key = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let point = key.verifying_key().to_encoded_point(false);
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "kid": key_id,
            "x": URL_SAFE_NO_PAD.encode(point.x().expect("the public point has x")),
            "y": URL_SAFE_NO_PAD.encode(point.y().expect("the public point has y")),
            "d": URL_SAFE_NO_PAD.encode(key.to_bytes()),
        })
    }

    fn valid_config_json_with_static_token() -> Value {
        serde_json::json!({
            "baseUrl": "https://evidence.example.org",
            "trustedJwks": one_key_jwks_json(),
            "revokedKeyIds": [],
            "token": { "static": "header-safe-token" },
        })
    }

    #[test]
    fn a_configuration_with_a_static_token_converts() {
        let config =
            config_from_json(&valid_config_json_with_static_token()).expect("the config converts");
        assert_eq!(config.base_url().as_str(), "https://evidence.example.org/");
        assert_eq!(config.trusted_jwks().keys.len(), 1);
    }

    #[test]
    fn a_configuration_with_a_private_key_jwt_token_converts() {
        let config_json = serde_json::json!({
            "baseUrl": "https://evidence.example.org",
            "trustedJwks": one_key_jwks_json(),
            "revokedKeyIds": [],
            "token": {
                "privateKeyJwt": {
                    "tokenEndpoint": "https://issuer.example.org/token",
                    "clientId": "example-client",
                    "clientKey": generated_client_key_json("signing-key-1"),
                    "audience": "https://issuer.example.org/",
                },
            },
        });
        config_from_json(&config_json).expect("the config converts");
    }

    /// The client key an adopter holds is the one `evidencectl` generated for
    /// them, and that is ES256. A binding that took only EdDSA would refuse
    /// every client the tooling creates.
    #[test]
    fn a_private_key_jwt_token_accepts_an_es256_client_key() {
        let config_json = serde_json::json!({
            "baseUrl": "https://evidence.example.org",
            "trustedJwks": one_key_jwks_json(),
            "revokedKeyIds": [],
            "token": {
                "privateKeyJwt": {
                    "tokenEndpoint": "https://issuer.example.org/token",
                    "clientId": "example-client",
                    "clientKey": generated_es256_client_key_json("signing-key-es256"),
                },
            },
        });
        config_from_json(&config_json).expect("an ES256 client key converts");
    }

    #[test]
    fn a_token_naming_more_than_one_provider_is_a_shape_error() {
        // Selecting the first provider present would let a botched merge of two
        // authentication configurations run with a credential the caller did
        // not mean to send, so an over-specified `token` fails closed.
        let config_json = serde_json::json!({
            "baseUrl": "https://evidence.example.org",
            "trustedJwks": one_key_jwks_json(),
            "revokedKeyIds": [],
            "token": {
                "static": "header-safe-token",
                "privateKeyJwt": {
                    "tokenEndpoint": "https://issuer.example.org/token",
                    "clientId": "example-client",
                    "clientKey": generated_client_key_json("signing-key-1"),
                    "audience": "https://issuer.example.org/",
                },
            },
        });
        assert!(matches!(
            config_from_json(&config_json),
            Err(ConfigError::Shape(_))
        ));
    }

    #[test]
    fn a_token_carrying_a_stray_key_beside_a_provider_is_a_shape_error() {
        let mut config = valid_config_json_with_static_token();
        config["token"]["privateKyeJwt"] = Value::Null;
        assert!(matches!(
            config_from_json(&config),
            Err(ConfigError::Shape(_))
        ));
    }

    #[test]
    fn a_missing_trusted_jwks_is_a_shape_error() {
        let mut config = valid_config_json_with_static_token();
        config.as_object_mut().unwrap().remove("trustedJwks");
        assert!(matches!(
            config_from_json(&config),
            Err(ConfigError::Shape(_))
        ));
    }

    #[test]
    fn a_missing_token_is_a_shape_error() {
        let mut config = valid_config_json_with_static_token();
        config.as_object_mut().unwrap().remove("token");
        assert!(matches!(
            config_from_json(&config),
            Err(ConfigError::Shape(_))
        ));
    }

    #[test]
    fn an_unparseable_base_url_is_a_shape_error() {
        let mut config = valid_config_json_with_static_token();
        config["baseUrl"] = Value::String("not a url".to_owned());
        assert!(matches!(
            config_from_json(&config),
            Err(ConfigError::Shape(_))
        ));
    }

    #[test]
    fn a_malformed_client_key_is_a_shape_error() {
        let config_json = serde_json::json!({
            "baseUrl": "https://evidence.example.org",
            "trustedJwks": one_key_jwks_json(),
            "revokedKeyIds": [],
            "token": {
                "privateKeyJwt": {
                    "tokenEndpoint": "https://issuer.example.org/token",
                    "clientId": "example-client",
                    // Missing every member a JWK needs.
                    "clientKey": {},
                },
            },
        });
        assert!(matches!(
            config_from_json(&config_json),
            Err(ConfigError::Shape(_))
        ));
    }

    /// A well-shaped `privateKeyJwt` block can still describe a configuration
    /// `PrivateKeyJwt::new` itself refuses. That refusal is a genuine
    /// `TokenError`, surfaced as `ConfigError::Client` with `kind: "token"`,
    /// not a shape error.
    #[test]
    fn a_semantically_invalid_private_key_jwt_configuration_is_a_client_error() {
        let config_json = serde_json::json!({
            "baseUrl": "https://evidence.example.org",
            "trustedJwks": one_key_jwks_json(),
            "revokedKeyIds": [],
            "token": {
                "privateKeyJwt": {
                    "tokenEndpoint": "https://issuer.example.org/token",
                    "clientId": "example-client",
                    "clientKey": generated_client_key_json("signing-key-1"),
                    // The contract accepts 1..=300 seconds.
                    "assertionLifetimeSeconds": 0,
                },
            },
        });
        let error = config_from_json(&config_json).expect_err("the configuration is refused");
        let ConfigError::Client(client_error) = &error else {
            panic!("expected a client-level refusal, got {error:?}");
        };
        assert_eq!(client_error.kind(), "token");
        assert_eq!(map_config_error(&error)["kind"], "token");
    }

    // --- evidence_to_json ---

    fn minimal_evidence() -> Evidence {
        Evidence {
            schema: "https://registrystack.example/evidence/v1".to_owned(),
            assurance_profile: AssuranceProfile::Local,
            subject_binding: SubjectBindingMode::AudienceScoped,
            request_nonce: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned()),
            id: "urn:example:evidence:1".to_owned(),
            evidence_type_name: EvidenceObjectType::Evidence,
            supports_requirement: "urn:example:client:requirement:status:v1".to_owned(),
            is_conformant_to: "urn:example:client:evidence-type:status:v1".to_owned(),
            issued_by: "urn:example:client:issuer".to_owned(),
            provided_by: "urn:example:client:provider".to_owned(),
            issued_at: "2026-01-01T00:00:00Z".to_owned(),
            observed_at: "2026-01-01T00:00:00Z".to_owned(),
            valid_until: "2026-01-01T00:05:00Z".to_owned(),
            purpose: "example-decision".to_owned(),
            audience: Some("urn:example:client:audience:relying-party".to_owned()),
            configuration_revision: "sha256:00".to_owned(),
            subjects: vec![SubjectBinding {
                role: "subject".to_owned(),
                binding: "y0KMdWluZGluZw".to_owned(),
            }],
            supported_values: vec![SupportedValue {
                provides_value_for: "urn:example:client:concept:status-holds".to_owned(),
                value: registry_evidence_client::PublicValue::Boolean(true),
            }],
        }
    }

    /// A holder-bound counterpart to [`minimal_evidence`]: same shape, but no
    /// audience and no request nonce, and the binding mode set accordingly.
    fn minimal_holder_bound_evidence() -> Evidence {
        Evidence {
            subject_binding: SubjectBindingMode::HolderBound,
            request_nonce: None,
            audience: None,
            ..minimal_evidence()
        }
    }

    #[test]
    fn evidence_converts_to_the_expected_json_shape() {
        let json = evidence_to_json(&minimal_evidence()).expect("evidence serializes");
        // `EvidenceObjectType` has no `rename_all` of its own, so its one
        // variant serializes as the Rust identifier itself.
        assert_eq!(json["type"], "Evidence");
        assert_eq!(json["assuranceProfile"], "local");
        assert_eq!(json["subjectBinding"], "audience-scoped");
        assert_eq!(
            json["supportsRequirement"],
            "urn:example:client:requirement:status:v1"
        );
        assert_eq!(json["subjects"][0]["role"], "subject");
        assert_eq!(json["subjects"][0]["binding"], "y0KMdWluZGluZw");
        assert_eq!(
            json["supportedValues"][0]["providesValueFor"],
            "urn:example:client:concept:status-holds"
        );
        assert_eq!(json["supportedValues"][0]["value"], true);
    }

    /// A holder-bound payload names no relying party, so the JS object it
    /// converts to must carry `subjectBinding: "holder-bound"` and omit
    /// `audience` and `requestNonce` entirely rather than serializing them as
    /// `null`.
    #[test]
    fn a_holder_bound_payload_converts_with_subject_binding_and_no_audience_or_nonce() {
        let json = evidence_to_json(&minimal_holder_bound_evidence()).expect("evidence serializes");
        assert_eq!(json["subjectBinding"], "holder-bound");
        let object = json.as_object().expect("evidence serializes to an object");
        assert!(!object.contains_key("audience"));
        assert!(!object.contains_key("requestNonce"));
    }

    // --- map_client_error: one case per stable kind ---

    #[test]
    fn a_configuration_failure_carries_only_kind_and_message() {
        let error = EvidenceClientError::Configuration {
            reason: "the client cannot be used this way",
        };
        let mapped = map_client_error(&error);
        assert_eq!(mapped["kind"], "configuration");
        assert!(mapped["message"]
            .as_str()
            .unwrap()
            .contains("the client cannot be used this way"));
        assert_eq!(mapped.as_object().unwrap().len(), 2);
    }

    #[test]
    fn a_nonce_failure_carries_only_kind_and_message() {
        let error = EvidenceClientError::Nonce(registry_evidence_client::NonceError::Entropy);
        let mapped = map_client_error(&error);
        assert_eq!(mapped["kind"], "nonce");
        assert_eq!(mapped.as_object().unwrap().len(), 2);
    }

    #[test]
    fn a_transport_failure_carries_its_transport_kind() {
        let error = EvidenceClientError::Transport {
            kind: TransportKind::Timeout,
        };
        let mapped = map_client_error(&error);
        assert_eq!(mapped["kind"], "transport");
        assert_eq!(mapped["transportKind"], "timeout");
        assert_eq!(mapped.as_object().unwrap().len(), 3);
    }

    #[test]
    fn a_denied_failure_carries_status_code_operation_and_retry_after() {
        let error = EvidenceClientError::Denied {
            status: 403,
            code: "not_authorized".to_owned(),
            operation: Some("01JZZZOPERATION".to_owned()),
            retry_after_seconds: Some(30),
        };
        let mapped = map_client_error(&error);
        assert_eq!(mapped["kind"], "denied");
        assert_eq!(mapped["status"], 403);
        assert_eq!(mapped["code"], "not_authorized");
        assert_eq!(mapped["operation"], "01JZZZOPERATION");
        assert_eq!(mapped["retryAfterSeconds"], 30);
    }

    #[test]
    fn a_denied_failure_with_no_operation_or_retry_after_omits_them() {
        let error = EvidenceClientError::Denied {
            status: 403,
            code: "not_authorized".to_owned(),
            operation: None,
            retry_after_seconds: None,
        };
        let mapped = map_client_error(&error);
        assert!(mapped.get("operation").is_none());
        assert!(mapped.get("retryAfterSeconds").is_none());
    }

    #[test]
    fn a_not_available_failure_carries_only_its_operation() {
        let error = EvidenceClientError::NotAvailable {
            operation: Some("01JZZZOPERATION".to_owned()),
        };
        let mapped = map_client_error(&error);
        assert_eq!(mapped["kind"], "not_available");
        assert_eq!(mapped["operation"], "01JZZZOPERATION");
        assert_eq!(mapped.as_object().unwrap().len(), 3);
    }

    #[test]
    fn a_protocol_failure_carries_status_and_its_optional_members() {
        let error = EvidenceClientError::Protocol {
            status: 503,
            code: Some("temporarily_unavailable".to_owned()),
            operation: Some("01JZZZOPERATION".to_owned()),
            retry_after_seconds: Some(5),
        };
        let mapped = map_client_error(&error);
        assert_eq!(mapped["kind"], "protocol");
        assert_eq!(mapped["status"], 503);
        assert_eq!(mapped["code"], "temporarily_unavailable");
        assert_eq!(mapped["operation"], "01JZZZOPERATION");
        assert_eq!(mapped["retryAfterSeconds"], 5);
    }

    #[test]
    fn a_protocol_failure_with_no_code_omits_it() {
        let error = EvidenceClientError::Protocol {
            status: 200,
            code: None,
            operation: None,
            retry_after_seconds: None,
        };
        let mapped = map_client_error(&error);
        assert_eq!(mapped["status"], 200);
        assert!(mapped.get("code").is_none());
    }

    #[test]
    fn a_verification_failure_carries_its_verifier_kind_as_the_code() {
        let error = EvidenceClientError::Verification(VerificationError::Signature);
        let mapped = map_client_error(&error);
        assert_eq!(mapped["kind"], "verification");
        assert_eq!(mapped["code"], "signature");
    }

    #[test]
    fn a_token_failure_nests_its_own_sub_kind_details_under_the_token_kind() {
        let unavailable = map_client_error(&EvidenceClientError::Token(TokenError::Unavailable));
        assert_eq!(unavailable["kind"], "token");
        assert_eq!(unavailable["tokenKind"], "unavailable");
        assert_eq!(unavailable.as_object().unwrap().len(), 3);

        let invalid = map_client_error(&EvidenceClientError::Token(TokenError::Invalid {
            reason: "a bearer credential must be non-empty and within the accepted length",
        }));
        assert_eq!(invalid["kind"], "token");
        assert_eq!(invalid["tokenKind"], "invalid_credential");
        assert_eq!(invalid.as_object().unwrap().len(), 3);

        let configuration =
            map_client_error(&EvidenceClientError::Token(TokenError::Configuration {
                reason: "the token provider cannot be used this way",
            }));
        assert_eq!(configuration["kind"], "token");
        assert_eq!(configuration["tokenKind"], "configuration");
        assert_eq!(configuration.as_object().unwrap().len(), 3);

        let transport = map_client_error(&EvidenceClientError::Token(TokenError::Transport {
            kind: TransportKind::Connect,
        }));
        assert_eq!(transport["kind"], "token");
        assert_eq!(transport["tokenKind"], "transport");
        assert_eq!(transport["transportKind"], "connect");

        let refused = map_client_error(&EvidenceClientError::Token(TokenError::Refused {
            code: OAuthErrorCode::InvalidClient,
        }));
        assert_eq!(refused["kind"], "token");
        assert_eq!(refused["tokenKind"], "refused");
        assert_eq!(refused["code"], "invalid_client");

        let protocol = map_client_error(&EvidenceClientError::Token(TokenError::Protocol {
            status: 500,
        }));
        assert_eq!(protocol["kind"], "token");
        assert_eq!(protocol["tokenKind"], "protocol");
        assert_eq!(protocol["status"], 500);
    }

    /// The discriminant is what a caller branches on, so every one of the
    /// eight stable kinds is distinct.
    #[test]
    fn every_client_failure_reports_a_distinct_kind() {
        let errors = [
            EvidenceClientError::Configuration { reason: "unusable" },
            EvidenceClientError::Nonce(registry_evidence_client::NonceError::Entropy),
            EvidenceClientError::Token(TokenError::Unavailable),
            EvidenceClientError::Transport {
                kind: TransportKind::Connect,
            },
            EvidenceClientError::Denied {
                status: 403,
                code: "not_authorized".to_owned(),
                operation: None,
                retry_after_seconds: None,
            },
            EvidenceClientError::NotAvailable { operation: None },
            EvidenceClientError::Protocol {
                status: 200,
                code: None,
                operation: None,
                retry_after_seconds: None,
            },
            EvidenceClientError::Verification(VerificationError::Signature),
        ];
        let kinds: std::collections::BTreeSet<String> = errors
            .iter()
            .map(|error| map_client_error(error)["kind"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(kinds.len(), errors.len(), "two variants share a kind");
    }

    #[test]
    fn a_conversion_error_maps_to_the_configuration_kind() {
        let mapped = map_conversion_error(&ConversionError::new("bad shape"));
        assert_eq!(mapped["kind"], "configuration");
        assert_eq!(mapped["message"], "bad shape");
    }

    // --- redaction ---

    /// Mirrors the wrapped crate's own redaction tests
    /// (`debug_output_never_carries_the_credential` in `token.rs`,
    /// `debug_output_never_carries_a_response_body_or_a_credential` in
    /// `client.rs`): plant a canary value in every place a credential, key,
    /// selector value, or subject binding legitimately reaches this crate's
    /// own conversion and error-mapping layer, and confirm the mapped JSON
    /// envelope this crate hands to JS never repeats it. A response body
    /// never reaches this module at all (`map_client_error` never touches
    /// `RawEvidenceResponse`), so it has no case here; the wrapped crate's own
    /// test already covers it.
    #[test]
    fn mapped_errors_never_carry_a_credential_key_selector_value_or_subject_binding() {
        const CANARY: &str = "secret-canary-value";

        // A bearer credential shaped exactly as a caller might submit one by
        // mistake (here, carrying a trailing newline `BearerToken` refuses):
        // the fixed refusal reason must not repeat the credential itself.
        let token_error =
            StaticToken::new(format!("{CANARY}\n")).expect_err("a newline is refused");
        let mapped = map_client_error(&EvidenceClientError::Token(token_error));
        let rendered = serde_json::to_string(&mapped).expect("the envelope serializes");
        assert!(!rendered.contains(CANARY), "leaked in: {rendered}");

        // A signing key whose private component is the canary: well-shaped
        // JSON, but not a valid Ed25519 scalar, so `PrivateJwk::parse` refuses
        // it. The refusal must describe the field (`d`), never echo it.
        let config_json = serde_json::json!({
            "baseUrl": "https://evidence.example.org",
            "trustedJwks": one_key_jwks_json(),
            "revokedKeyIds": [],
            "token": {
                "privateKeyJwt": {
                    "tokenEndpoint": "https://issuer.example.org/token",
                    "clientId": "example-client",
                    "clientKey": {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "d": CANARY,
                    },
                },
            },
        });
        let error = config_from_json(&config_json).expect_err("the malformed key is refused");
        let mapped = map_config_error(&error);
        let rendered = serde_json::to_string(&mapped).expect("the envelope serializes");
        assert!(!rendered.contains(CANARY), "leaked in: {rendered}");

        // A selector value carrying the canary, in a specification refused
        // for an unrelated reason (a missing `purpose`): the canary is parsed
        // and held in memory before the refusal, but the refusal itself must
        // not mention it.
        let mut spec = valid_spec_json();
        spec["subjects"][0]["selectorValues"]["record_reference"] =
            Value::String(CANARY.to_owned());
        spec.as_object_mut().unwrap().remove("purpose");
        let error = spec_from_json(&spec).expect_err("the missing `purpose` is refused");
        let mapped = map_conversion_error(&error);
        let rendered = serde_json::to_string(&mapped).expect("the envelope serializes");
        assert!(!rendered.contains(CANARY), "leaked in: {rendered}");

        // A pinned subject binding carrying the canary, in a specification
        // refused for the same unrelated reason.
        let mut spec = valid_spec_json();
        spec["subjectExpectations"] = serde_json::json!({
            "pinned": [{ "role": "subject", "binding": CANARY }],
        });
        spec.as_object_mut().unwrap().remove("purpose");
        let error = spec_from_json(&spec).expect_err("the missing `purpose` is refused");
        let mapped = map_conversion_error(&error);
        let rendered = serde_json::to_string(&mapped).expect("the envelope serializes");
        assert!(!rendered.contains(CANARY), "leaked in: {rendered}");

        // A holder key whose private half is the canary: the refusal that
        // names that member must not repeat the half it found.
        let mut key = holder_key_json(0);
        key["d"] = Value::String(CANARY.to_owned());
        let mut spec = valid_spec_json();
        spec["holderKeys"] = serde_json::json!([key]);
        let error = spec_from_json(&spec).expect_err("the private member is refused");
        assert!(error.0.contains("private key material"));
        let mapped = map_conversion_error(&error);
        let rendered = serde_json::to_string(&mapped).expect("the envelope serializes");
        assert!(!rendered.contains(CANARY), "leaked in: {rendered}");

        // The canary as an ordinary member's value in a malformed key, so the
        // refusal comes from the shape check rather than the private-member
        // check. That message discards serde's own text for exactly this
        // reason: a serde failure can quote the value it rejected.
        let mut spec = valid_spec_json();
        spec["holderKeys"] = serde_json::json!([{ "kty": CANARY }]);
        let error = spec_from_json(&spec).expect_err("the malformed key is refused");
        let mapped = map_conversion_error(&error);
        let rendered = serde_json::to_string(&mapped).expect("the envelope serializes");
        assert!(!rendered.contains(CANARY), "leaked in: {rendered}");
    }
}
