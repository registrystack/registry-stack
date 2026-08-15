//! Python binding for the Evidence relying-party client, via PyO3.
//!
//! This is the only file in the crate that defines the `pymodule` surface;
//! every conversion lives in [`convert`] as a plain, unit-testable Rust
//! function. The client is synchronous from Python's side: it owns a private
//! current-thread tokio runtime and blocks on it for every network call,
//! releasing the GIL for the duration so other Python threads keep running.

use std::collections::BTreeMap;

use pyo3::exceptions::{PyException, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
#[cfg(test)]
use pyo3::types::PyMapping;
use pyo3::types::{PyDict, PyList, PyTuple};

// The wrapped SDK crate is `registry-evidence-client`, but this crate's own
// `[lib] name` (the Python module name the spec requires) is also
// `registry_evidence_client`, so `Cargo.toml` depends on it under the local
// alias `evidence-client-sdk` rather than its own package name. See that
// alias's own comment in `Cargo.toml` for why: it is not just tidiness here,
// since an unaliased dependency also breaks every integration test under
// `tests/` (a hard `error[E0464]`, not a `use`-path ambiguity `::` could fix).
use evidence_client_sdk::AudienceScopedRequest as RealAudienceScopedRequest;
use evidence_client_sdk::EvidenceClient as RealEvidenceClient;
use evidence_client_sdk::EvidenceClientProfile as RealEvidenceClientProfile;
use evidence_client_sdk::PreparedEvidenceRequest as RealPreparedEvidenceRequest;
use evidence_client_sdk::PreparedEvidenceRequestBatch as RealPreparedEvidenceRequestBatch;
use evidence_client_sdk::RawEvidenceRequestBatchResponse as RealRawEvidenceRequestBatchResponse;
use evidence_client_sdk::RawEvidenceResponse as RealRawEvidenceResponse;
use evidence_client_sdk::SdJwtVcBatchResponse as RealSdJwtVcBatchResponse;
use evidence_client_sdk::SubjectBindingReceipt as RealSubjectBindingReceipt;
use evidence_client_sdk::SubjectContinuity as RealSubjectContinuity;
use evidence_client_sdk::VerifiedAudienceScopedEvidence as RealVerifiedAudienceScopedEvidence;
use evidence_client_sdk::VerifiedEvidence as RealVerifiedEvidence;
use evidence_client_sdk::VerifiedEvidenceRequestBatch as RealVerifiedEvidenceRequestBatch;
use evidence_client_sdk::VerifiedEvidenceRequestBatchItem as RealVerifiedEvidenceRequestBatchItem;

mod convert;

use convert::{
    batch_spec_from_json, config_from_parts, datetime_from_unix_seconds, evidence_to_json,
    json_to_python, map_client_error, map_config_error, map_conversion_error,
    progressive_subjects_from_json, python_to_json, selector_values_from_json, spec_from_json,
    subject_expectations_to_json, MappedError,
};
use registry_platform_crypto::PrivateJwk;

// Every instance also carries a `kind` attribute, one of the eight stable
// strings `EvidenceClientError::kind` reports: "configuration", "nonce",
// "token", "transport", "denied", "not_available", "protocol", or
// "verification". Branch on `kind`, never on the rendered message, which
// this crate does not freeze.
//
// Where the failure has them, an instance also carries `status`, `code`,
// `trace_id`, `retry_after_seconds`, `transport_kind` (set for a "transport"
// failure, and for a "token" failure whose `token_kind` is "transport"), and
// `token_kind` (set only for a "token" failure).
// A "protocol" failure with `status` 401, 403, or 429 is reachable: it means
// the deployment answered outside its own contract (an uncoded refusal, or a
// response this client could not parse) rather than with a contract-coded
// problem response, which is "denied" instead.
//
// No attribute here ever carries response bytes, a credential, a header
// value, a selector value, or a subject binding.
//
// The doc string passed to each `create_exception!` call below (its fourth
// argument) is what Python sees as `__doc__`; a plain `///` comment placed
// before the macro invocation would not reach the generated type.
pyo3::create_exception!(
    registry_evidence_client,
    EvidenceClientError,
    PyException,
    "Base exception for every mapped failure this client reports. See the \
     module documentation for the attributes every instance carries. Two \
     failures escape this hierarchy entirely, since neither is a mapped \
     failure with a `kind`: the client's internal runtime failing to start, \
     which raises `RuntimeError`, and a serialization failure on a value \
     this crate itself constructed, which raises `ValueError`."
);

pyo3::create_exception!(
    registry_evidence_client,
    ConfigurationError,
    EvidenceClientError,
    "The client cannot be used as configured, or a prepared request already \
     spent the single send it allows."
);

pyo3::create_exception!(
    registry_evidence_client,
    NonceError,
    EvidenceClientError,
    "The request nonce could not be generated."
);

pyo3::create_exception!(
    registry_evidence_client,
    TokenError,
    EvidenceClientError,
    "The credential presented to the deployment could not be obtained. See \
     the `token_kind` attribute for the specific cause."
);

pyo3::create_exception!(
    registry_evidence_client,
    TransportError,
    EvidenceClientError,
    "The exchange with the deployment failed below the HTTP layer. See the \
     `transport_kind` attribute for the specific cause."
);

pyo3::create_exception!(
    registry_evidence_client,
    DeniedError,
    EvidenceClientError,
    "The deployment refused the request with a contract-coded problem \
     response. See the `status`, `code`, and `retry_after_seconds` \
     attributes."
);

pyo3::create_exception!(
    registry_evidence_client,
    NotAvailableError,
    EvidenceClientError,
    "The deployment answered that no evidence is available for this request."
);

pyo3::create_exception!(
    registry_evidence_client,
    ProtocolError,
    EvidenceClientError,
    "The deployment answered outside its contract: an uncoded refusal, or a \
     response this client could not parse. See the `status` attribute."
);

pyo3::create_exception!(
    registry_evidence_client,
    VerificationError,
    EvidenceClientError,
    "A signed response failed offline verification against the closed \
     policy. See the `code` attribute for the verifier's own kind."
);

/// Build the Python exception matching one of the eight stable kinds. Every
/// kind [`evidence_client_sdk::EvidenceClientError::kind`] can report is
/// listed; a [`MappedError`] can only carry a ninth if the wrapped crate's
/// error enum (`#[non_exhaustive]`) grows one this crate does not yet know
/// about, in which case the base class still reports it faithfully.
fn exception_for_kind(kind: &str, message: String) -> PyErr {
    match kind {
        "configuration" => ConfigurationError::new_err(message),
        "nonce" => NonceError::new_err(message),
        "token" => TokenError::new_err(message),
        "transport" => TransportError::new_err(message),
        "denied" => DeniedError::new_err(message),
        "not_available" => NotAvailableError::new_err(message),
        "protocol" => ProtocolError::new_err(message),
        "verification" => VerificationError::new_err(message),
        _ => EvidenceClientError::new_err(message),
    }
}

/// Turn a mapped failure into the matching Python exception, with every field
/// [`MappedError`] carries attached as a plain attribute. `message` is always
/// `Display` text over the source failure; none of these attributes is a JSON
/// envelope.
fn to_py_err(py: Python<'_>, mapped: &MappedError) -> PyErr {
    let error = exception_for_kind(mapped.kind, mapped.message.clone());
    let instance = error.value(py);
    macro_rules! set_attr {
        ($name:literal, $value:expr) => {
            instance
                .setattr($name, $value)
                .expect("setting an attribute on a freshly constructed exception cannot fail")
        };
    }
    set_attr!("kind", mapped.kind);
    set_attr!("status", mapped.status);
    set_attr!("code", mapped.code.as_deref());
    set_attr!("trace_id", mapped.trace_id.as_deref());
    set_attr!("retry_after_seconds", mapped.retry_after_seconds);
    set_attr!("transport_kind", mapped.transport_kind);
    set_attr!("token_kind", mapped.token_kind);
    error
}

/// A serialization failure on a value this crate itself constructed (a
/// policy document, a definitions document, a key set, a verified payload) is
/// not a caller mistake: it has no `kind` among the eight stable ones, so it
/// is reported as a plain `ValueError` rather than forced into that envelope.
fn serialization_error(what: &str, error: serde_json::Error) -> PyErr {
    PyValueError::new_err(format!("{what} could not be described: {error}"))
}

/// One request, closed and nonce-bearing, before any byte has left the
/// process.
///
/// There is no constructor exposed to Python: the only way to obtain one is
/// [`EvidenceClient::prepare`], mirroring the wrapped Rust type having no
/// public constructor either. It owns the real value directly rather than a
/// clone of it: the real type is deliberately not `Clone`, to protect its
/// interior single-send flag, and copying it here would defeat that guard.
#[pyclass(name = "PreparedEvidenceRequest", module = "registry_evidence_client")]
struct PreparedEvidenceRequest {
    inner: RealPreparedEvidenceRequest,
}

#[pymethods]
impl PreparedEvidenceRequest {
    /// The nonce this request carries. Retain it with the transaction record:
    /// re-verifying the stored response later needs the nonce from the
    /// request, not from the response.
    #[getter]
    fn request_nonce(&self) -> &str {
        self.inner.request_nonce()
    }

    /// The closed verification policy, with the subject set as `prepare` left
    /// it.
    #[getter]
    fn policy_document(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let value = serde_json::to_value(self.inner.policy_document())
            .map_err(|error| serialization_error("the policy document", error))?;
        Ok(json_to_python(py, &value)?.unbind())
    }

    /// The subject expectations this request closed with: either the literal
    /// string `"accept_first_use"`, or the sequence of `{"role", "binding"}`
    /// mappings that were pinned.
    #[getter]
    fn subject_expectations(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let value = subject_expectations_to_json(self.inner.subject_expectations());
        Ok(json_to_python(py, &value)?.unbind())
    }
}

/// One ordered request batch, with one nonce and closed policy per item,
/// before any byte has left the process.
///
/// There is no public constructor. [`EvidenceClient::prepare_batch`] is the
/// only way to obtain this opaque value, and it owns the wrapped batch's
/// single-send flag directly rather than copying it.
#[pyclass(
    name = "PreparedEvidenceRequestBatch",
    module = "registry_evidence_client"
)]
struct PreparedEvidenceRequestBatch {
    inner: RealPreparedEvidenceRequestBatch,
}

#[pymethods]
impl PreparedEvidenceRequestBatch {
    /// Independently generated item nonces in request order.
    #[getter]
    fn request_nonces(&self) -> Vec<String> {
        self.inner
            .request_nonces()
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    /// Independently closed policy documents in request order.
    #[getter]
    fn policy_documents(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let value = (0..self.inner.count())
            .map(|index| {
                serde_json::to_value(
                    self.inner
                        .policy_document(index)
                        .expect("the index comes from the batch count"),
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| serialization_error("a request batch policy document", error))?;
        Ok(json_to_python(py, &serde_json::Value::Array(value))?.unbind())
    }

    /// Subject-verification stances in request order.
    #[getter]
    fn subject_expectations(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let value = serde_json::Value::Array(
            (0..self.inner.count())
                .map(|index| {
                    subject_expectations_to_json(
                        self.inner
                            .subject_expectations(index)
                            .expect("the index comes from the batch count"),
                    )
                })
                .collect(),
        );
        Ok(json_to_python(py, &value)?.unbind())
    }

    /// Number of positional requests in this batch.
    #[getter]
    fn count(&self) -> usize {
        self.inner.count()
    }
}

/// A signed response, read but not yet judged.
///
/// There is no constructor exposed to Python; the only way to obtain one is
/// [`EvidenceClient::send`]. Its two readings are the wrapped Rust type's own,
/// and reading either one judges nothing: `verify` is what decides whether
/// these bytes are trustworthy, never Python code inspecting them.
#[pyclass(name = "RawEvidenceResponse", module = "registry_evidence_client")]
struct RawEvidenceResponse {
    inner: RealRawEvidenceResponse,
}

#[pymethods]
impl RawEvidenceResponse {
    /// The exact bytes the deployment served. Retain them with the
    /// transaction record: re-verifying later needs the bytes that were
    /// verified, not a re-serialization of them.
    #[getter]
    fn body(&self) -> &[u8] {
        self.inner.body()
    }

    /// The deployment's opaque identifier for this exchange, if the response
    /// carried one, for support correlation. Present here as well as on
    /// `VerifiedEvidence`, so a response that fails verification can still be
    /// reported against the deployment's own audit trail.
    #[getter]
    fn trace_id(&self) -> Option<&str> {
        self.inner.trace_id()
    }
}

/// Request-batch response bytes read but not yet judged.
///
/// There is no public constructor. [`EvidenceClient::send_batch`] is the
/// only way to obtain this opaque value, and only batch verification accepts
/// it back.
#[pyclass(
    name = "RawEvidenceRequestBatchResponse",
    module = "registry_evidence_client"
)]
struct RawEvidenceRequestBatchResponse {
    inner: RealRawEvidenceRequestBatchResponse,
}

#[pymethods]
impl RawEvidenceRequestBatchResponse {
    /// Response envelope bytes exactly as received.
    #[getter]
    fn body(&self) -> &[u8] {
        self.inner.body()
    }

    /// Deployment correlation identifier for the whole batch exchange.
    #[getter]
    fn trace_id(&self) -> Option<&str> {
        self.inner.trace_id()
    }
}

/// The issuance envelope answering one request that presented several holder
/// keys, read but not yet judged.
///
/// The envelope's order is the request's own: `credentials[i]` answers the key
/// the request sent as `holder_keys[i]`, one credential per key, and a caller
/// that needs that correspondence spelled out can ask for it by index with
/// `credential_for_holder_key`. There is no partial envelope: either every
/// presented key was answered or reading the envelope failed.
///
/// Reading it judges nothing. Each credential is verified individually,
/// exactly as a single credential is, and parsing this envelope is not a step
/// in that.
#[pyclass(name = "SdJwtVcBatchResponse", module = "registry_evidence_client")]
struct SdJwtVcBatchResponse {
    inner: RealSdJwtVcBatchResponse,
}

#[pymethods]
impl SdJwtVcBatchResponse {
    /// Read an envelope from the response bytes a batch exchange returned,
    /// such as `RawEvidenceResponse.body`.
    #[staticmethod]
    fn parse(py: Python<'_>, body: &[u8]) -> PyResult<Self> {
        RealSdJwtVcBatchResponse::parse(body)
            .map(|inner| Self { inner })
            .map_err(|error| to_py_err(py, &map_client_error(&error)))
    }

    /// Every credential the envelope carries, in the order the request
    /// presented its holder keys.
    #[getter]
    fn credentials(&self) -> Vec<String> {
        self.inner.credentials().to_vec()
    }

    /// How many credentials the envelope carries, which is how many holder
    /// keys the request presented.
    #[getter]
    fn count(&self) -> usize {
        self.inner.count()
    }

    /// The credential bound to the holder key the request sent at `index`, or
    /// `None` when the envelope carries no credential at that position.
    fn credential_for_holder_key(&self, index: usize) -> Option<&str> {
        self.inner.credential_for_holder_key(index)
    }
}

/// A response that satisfied every expectation.
///
/// Unlike the classes above, this is a terminal result nothing hands back
/// into a later call, so it carries plain, eagerly converted data rather than
/// protecting any interior state.
#[pyclass(name = "VerifiedEvidence", module = "registry_evidence_client")]
struct VerifiedEvidence {
    /// The verified payload, as a plain Python object graph.
    #[pyo3(get)]
    evidence: Py<PyAny>,
    /// The deployment's opaque identifier for the exchange that produced this
    /// payload, for support correlation.
    #[pyo3(get)]
    trace_id: Option<String>,
    /// The role-bound subject bindings this payload carries, as pinned
    /// expectations for a later request. Persist these after a first-use
    /// acceptance and pass them as `subject_expectations` from then on.
    #[pyo3(get)]
    pinned_subject_expectations: Py<PyAny>,
}

/// Convert a wrapped [`RealVerifiedEvidence`] into its Python-facing shape.
fn verified_evidence_to_python(
    py: Python<'_>,
    verified: &RealVerifiedEvidence,
) -> PyResult<VerifiedEvidence> {
    let evidence_value = evidence_to_json(verified.evidence())
        .map_err(|error| to_py_err(py, &map_conversion_error(&error)))?;
    let evidence = json_to_python(py, &evidence_value)?.unbind();
    let pinned_value = serde_json::to_value(verified.pinned_subject_expectations())
        .map_err(|error| serialization_error("the pinned subject expectations", error))?;
    let pinned_subject_expectations = json_to_python(py, &pinned_value)?.unbind();
    Ok(VerifiedEvidence {
        evidence,
        trace_id: verified.trace_id().map(str::to_owned),
        pinned_subject_expectations,
    })
}

/// Every ordered item of an atomically verified request-batch response.
///
/// `items` is a sequence of discriminated mappings. An available item is
/// `{"status": "available", "verified": VerifiedEvidence}`; an unresolved
/// item is exactly `{"status": "not_available"}`. No value of this class is
/// built until Rust has accepted the complete outer envelope and verified
/// every available member.
#[pyclass(
    name = "VerifiedEvidenceRequestBatch",
    module = "registry_evidence_client"
)]
struct VerifiedEvidenceRequestBatch {
    #[pyo3(get)]
    items: Py<PyAny>,
    #[pyo3(get)]
    trace_id: Option<String>,
}

fn verified_request_batch_to_python(
    py: Python<'_>,
    verified: &RealVerifiedEvidenceRequestBatch,
) -> PyResult<VerifiedEvidenceRequestBatch> {
    let items = PyList::empty(py);
    for item in verified.items() {
        let value = PyDict::new(py);
        match item {
            RealVerifiedEvidenceRequestBatchItem::Available(verified) => {
                value.set_item("status", "available")?;
                value.set_item(
                    "verified",
                    Py::new(py, verified_evidence_to_python(py, verified)?)?,
                )?;
            }
            RealVerifiedEvidenceRequestBatchItem::NotAvailable => {
                value.set_item("status", "not_available")?;
            }
        }
        items.append(value)?;
    }
    Ok(VerifiedEvidenceRequestBatch {
        items: items.into_any().unbind(),
        trace_id: verified.trace_id().map(str::to_owned),
    })
}

/// An opaque, application-owned record of a verified subject relationship.
///
/// The client never persists this value. Applications that need continuity
/// retain it next to their own account or case record and decide atomically
/// whether a first-use receipt may become the stored receipt. Its JSON has no
/// selector values or disclosed evidence.
#[pyclass(name = "SubjectBindingReceipt", module = "registry_evidence_client")]
struct SubjectBindingReceipt {
    inner: RealSubjectBindingReceipt,
}

#[pymethods]
impl SubjectBindingReceipt {
    /// Serialize this versioned opaque receipt for application-owned storage.
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|error| serialization_error("the subject binding receipt", error))
    }

    /// Read a receipt retained by the application. The strict Rust type owns
    /// schema and scope validation, not this binding.
    #[staticmethod]
    fn from_json(py: Python<'_>, document: &str) -> PyResult<Self> {
        let inner = serde_json::from_str(document).map_err(|_| {
            to_py_err(
                py,
                &map_conversion_error(&convert::ConversionError::new(
                    "a subject binding receipt is invalid",
                )),
            )
        })?;
        Ok(Self { inner })
    }
}

/// Whether this verified response was accepted without a prior application
/// receipt, or matched one the application supplied. `receipt` is intentionally
/// returned in both cases so the application may retain the opaque current
/// scope without asking the client to store it.
#[pyclass(name = "SubjectContinuity", module = "registry_evidence_client")]
struct SubjectContinuity {
    #[pyo3(get)]
    status: String,
    #[pyo3(get)]
    receipt: Py<SubjectBindingReceipt>,
}

fn subject_continuity_to_python(
    py: Python<'_>,
    continuity: &RealSubjectContinuity,
) -> PyResult<SubjectContinuity> {
    let (status, receipt) = match continuity {
        RealSubjectContinuity::FirstUse { receipt } => ("first_use", receipt),
        RealSubjectContinuity::Matched { receipt } => ("matched", receipt),
    };
    Ok(SubjectContinuity {
        status: status.to_owned(),
        receipt: Py::new(
            py,
            SubjectBindingReceipt {
                inner: receipt.clone(),
            },
        )?,
    })
}

/// A verified signed JWS assertion returned by the progressive API.
#[pyclass(name = "VerifiedAssertion", module = "registry_evidence_client")]
struct VerifiedAssertion {
    #[pyo3(get)]
    evidence: Py<PyAny>,
    #[pyo3(get)]
    trace_id: Option<String>,
    values: BTreeMap<String, evidence_client_sdk::PublicValue>,
    #[pyo3(get)]
    subject_continuity: Py<SubjectContinuity>,
    #[pyo3(get)]
    assertion: Vec<u8>,
}

#[pymethods]
impl VerifiedAssertion {
    /// An immutable mapping of published concept handles to verified values.
    /// A fresh mapping proxy is created from retained Rust data for every
    /// reading, so neither mapping assignment nor a mutated nested Python
    /// value can affect a future convenience `value` reading.
    #[getter]
    fn values(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        immutable_verified_values(py, &self.values)
    }

    /// The sole output value. Multi-output and zero-output results stay valid;
    /// use `values` for those rather than discarding an otherwise verified
    /// result because this convenience property is ambiguous.
    #[getter]
    fn value(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        sole_verified_value(py, &self.values)
    }
}

/// A verified SD-JWT VC response returned by the progressive API.
#[pyclass(
    name = "VerifiedAudienceScopedCredential",
    module = "registry_evidence_client"
)]
struct VerifiedAudienceScopedCredential {
    #[pyo3(get)]
    evidence: Py<PyAny>,
    #[pyo3(get)]
    trace_id: Option<String>,
    values: BTreeMap<String, evidence_client_sdk::PublicValue>,
    #[pyo3(get)]
    subject_continuity: Py<SubjectContinuity>,
    #[pyo3(get)]
    credential: String,
}

#[pymethods]
impl VerifiedAudienceScopedCredential {
    /// An immutable mapping of published concept handles to verified values.
    #[getter]
    fn values(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        immutable_verified_values(py, &self.values)
    }

    /// The sole output value. See [`VerifiedAssertion::value`] for the
    /// deliberate ambiguity rule shared by both response encodings.
    #[getter]
    fn value(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        sole_verified_value(py, &self.values)
    }
}

fn immutable_verified_values(
    py: Python<'_>,
    values: &BTreeMap<String, evidence_client_sdk::PublicValue>,
) -> PyResult<Py<PyAny>> {
    let value = serde_json::to_value(values)
        .map_err(|error| serialization_error("the verified values", error))?;
    immutable_json_to_python(py, &value)
}

/// Turn JSON-shaped verified output into a deeply immutable Python snapshot.
///
/// The Python binding deliberately does not expose the mutable dictionaries
/// and lists the JSON bridge creates. A caller receives mapping proxies and
/// tuples at every nesting level, while the authoritative source for each
/// later property read remains the Rust-owned verified value.
fn immutable_json_to_python(py: Python<'_>, value: &serde_json::Value) -> PyResult<Py<PyAny>> {
    let value = json_to_python(py, value)?;
    let types = PyModule::import(py, "types")?;
    freeze_python_snapshot(py, &value, &types.getattr("MappingProxyType")?)
}

fn freeze_python_snapshot(
    py: Python<'_>,
    value: &Bound<'_, PyAny>,
    mapping_proxy_type: &Bound<'_, PyAny>,
) -> PyResult<Py<PyAny>> {
    if let Ok(mapping) = value.cast::<PyDict>() {
        let frozen_mapping = PyDict::new(py);
        for (key, child) in mapping.iter() {
            frozen_mapping
                .set_item(key, freeze_python_snapshot(py, &child, mapping_proxy_type)?)?;
        }
        return mapping_proxy_type
            .call1((frozen_mapping,))
            .map(Bound::unbind);
    }
    if let Ok(list) = value.cast::<PyList>() {
        let values = list
            .iter()
            .map(|child| freeze_python_snapshot(py, &child, mapping_proxy_type))
            .collect::<PyResult<Vec<_>>>()?;
        return PyTuple::new(py, values).map(|tuple| tuple.into_any().unbind());
    }
    Ok(value.clone().unbind())
}

fn sole_verified_value(
    py: Python<'_>,
    values: &BTreeMap<String, evidence_client_sdk::PublicValue>,
) -> PyResult<Py<PyAny>> {
    if values.len() != 1 {
        return Err(to_py_err(
            py,
            &map_conversion_error(&convert::ConversionError::new(
                "the verified result does not have exactly one output; use `values` instead",
            )),
        ));
    }
    let value = values
        .values()
        .next()
        .expect("the map has exactly one value after its length was checked");
    let value = serde_json::to_value(value)
        .map_err(|error| serialization_error("the verified value", error))?;
    immutable_json_to_python(py, &value)
}

type ProgressiveResultParts = (
    Py<PyAny>,
    Option<String>,
    BTreeMap<String, evidence_client_sdk::PublicValue>,
    Py<SubjectContinuity>,
);

fn progressive_result_parts<T>(py: Python<'_>, result: &T) -> PyResult<ProgressiveResultParts>
where
    T: ProgressiveResult,
{
    let evidence = evidence_to_json(result.evidence())
        .map_err(|error| to_py_err(py, &map_conversion_error(&error)))?;
    Ok((
        json_to_python(py, &evidence)?.unbind(),
        result.trace_id().map(str::to_owned),
        result.values().clone(),
        Py::new(
            py,
            subject_continuity_to_python(py, result.subject_continuity())?,
        )?,
    ))
}

/// Shared accessors the two progressive result representations expose in the
/// Rust SDK. It exists only to keep their Python conversion byte-for-byte
/// parallel; every semantic decision has already happened in Rust.
trait ProgressiveResult {
    fn evidence(&self) -> &evidence_client_sdk::Evidence;
    fn trace_id(&self) -> Option<&str>;
    fn values(&self) -> &std::collections::BTreeMap<String, evidence_client_sdk::PublicValue>;
    fn subject_continuity(&self) -> &RealSubjectContinuity;
}

impl ProgressiveResult for evidence_client_sdk::VerifiedAssertion {
    fn evidence(&self) -> &evidence_client_sdk::Evidence {
        self.evidence()
    }
    fn trace_id(&self) -> Option<&str> {
        self.trace_id()
    }
    fn values(&self) -> &std::collections::BTreeMap<String, evidence_client_sdk::PublicValue> {
        self.values()
    }
    fn subject_continuity(&self) -> &RealSubjectContinuity {
        self.subject_continuity()
    }
}

impl ProgressiveResult for evidence_client_sdk::VerifiedAudienceScopedCredential {
    fn evidence(&self) -> &evidence_client_sdk::Evidence {
        self.evidence()
    }
    fn trace_id(&self) -> Option<&str> {
        self.trace_id()
    }
    fn values(&self) -> &std::collections::BTreeMap<String, evidence_client_sdk::PublicValue> {
        self.values()
    }
    fn subject_continuity(&self) -> &RealSubjectContinuity {
        self.subject_continuity()
    }
}

fn progressive_result_to_python(
    py: Python<'_>,
    result: RealVerifiedAudienceScopedEvidence,
) -> PyResult<Py<PyAny>> {
    match result {
        RealVerifiedAudienceScopedEvidence::Assertion(result) => {
            let (evidence, trace_id, values, subject_continuity) =
                progressive_result_parts(py, &result)?;
            Py::new(
                py,
                VerifiedAssertion {
                    evidence,
                    trace_id,
                    values,
                    subject_continuity,
                    assertion: result.assertion_bytes().to_vec(),
                },
            )
            .map(|result| result.into_any())
        }
        RealVerifiedAudienceScopedEvidence::Credential(result) => {
            let (evidence, trace_id, values, subject_continuity) =
                progressive_result_parts(py, &result)?;
            Py::new(
                py,
                VerifiedAudienceScopedCredential {
                    evidence,
                    trace_id,
                    values,
                    subject_continuity,
                    credential: result.credential().to_owned(),
                },
            )
            .map(|result| result.into_any())
        }
    }
}

/// A relying party's connection to one Evidence deployment.
///
/// The client owns a private, current-thread tokio runtime and blocks on it
/// for every asynchronous method, releasing the GIL for the duration so other
/// Python threads keep running. A current-thread runtime supports being
/// entered concurrently from more than one native thread: a second caller
/// waits for the first to yield the runtime's single core rather than racing
/// it, so two Python threads may safely call an async method on the same
/// client at once.
#[pyclass(name = "EvidenceClient", module = "registry_evidence_client")]
struct EvidenceClient {
    inner: RealEvidenceClient,
    runtime: tokio::runtime::Runtime,
}

#[pymethods]
impl EvidenceClient {
    /// Build a client for one deployment.
    ///
    /// `trusted_jwks` and `revoked_key_ids` are mandatory trust inputs: a key
    /// set or revoked-key list the verifier could never use is refused, exactly
    /// as the wrapped Rust configuration refuses it. `token` is either a static
    /// bearer string or the private-key-JWT provider's own settings; there is no
    /// caller-supplied token provider in this binding.
    ///
    /// `max_response_bytes` bounds the signed response `send` reads.
    /// `max_metadata_bytes` bounds the documents `discover` and `fetch_jwks`
    /// read, which are neither signed nor verified, and is a separate decision.
    #[new]
    #[pyo3(signature = (
        base_url,
        trusted_jwks,
        revoked_key_ids,
        token,
        request_timeout_seconds=None,
        connect_timeout_seconds=None,
        user_agent=None,
        trusted_root_certificates=None,
        max_response_bytes=None,
        max_metadata_bytes=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        base_url: &str,
        trusted_jwks: &Bound<'_, PyAny>,
        revoked_key_ids: Vec<String>,
        token: &Bound<'_, PyAny>,
        request_timeout_seconds: Option<f64>,
        connect_timeout_seconds: Option<f64>,
        user_agent: Option<String>,
        trusted_root_certificates: Option<Vec<u8>>,
        max_response_bytes: Option<u64>,
        max_metadata_bytes: Option<u64>,
    ) -> PyResult<Self> {
        let trusted_jwks_json = python_to_json(trusted_jwks)
            .map_err(|error| to_py_err(py, &map_conversion_error(&error)))?;
        let token_json =
            python_to_json(token).map_err(|error| to_py_err(py, &map_conversion_error(&error)))?;
        let config = config_from_parts(
            base_url,
            &trusted_jwks_json,
            revoked_key_ids,
            &token_json,
            request_timeout_seconds,
            connect_timeout_seconds,
            user_agent,
            trusted_root_certificates,
            max_response_bytes,
            max_metadata_bytes,
        )
        .map_err(|error| to_py_err(py, &map_config_error(&error)))?;
        let inner = py
            .detach(|| RealEvidenceClient::new(config))
            .map_err(|error| to_py_err(py, &map_client_error(&error)))?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| {
                PyRuntimeError::new_err(format!(
                    "the client's internal runtime could not start: {error}"
                ))
            })?;
        Ok(Self { inner, runtime })
    }

    /// Load a versioned application-owned client profile.
    ///
    /// The profile gives the SDK an HTTPS origin and client identity only. It
    /// does not copy server metadata, signing keys, selector profiles, or any
    /// subject relationship into Python. When `private_key_jwk` is supplied,
    /// it replaces the profile's file or environment key reference, which is
    /// the intended integration point for a deployment secret manager.
    #[staticmethod]
    #[pyo3(signature = (profile_path, private_key_jwk=None))]
    fn from_profile(
        py: Python<'_>,
        profile_path: &str,
        private_key_jwk: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let profile = RealEvidenceClientProfile::from_file(profile_path).map_err(|error| {
            // A profile path and the private-key reference are deployment
            // details. Do not turn either into part of a Python exception.
            let mapped = MappedError {
                kind: error.kind(),
                message: "the client profile could not be loaded".to_owned(),
                status: None,
                code: None,
                trace_id: None,
                retry_after_seconds: None,
                transport_kind: None,
                token_kind: None,
            };
            to_py_err(py, &mapped)
        })?;
        let inner = match private_key_jwk {
            None => RealEvidenceClient::from_profile(profile),
            Some(value) => {
                let value = python_to_json(value)
                    .map_err(|error| to_py_err(py, &map_conversion_error(&error)))?;
                let serialized = serde_json::to_string(&value)
                    .map_err(|error| serialization_error("the supplied private key", error))?;
                let key = PrivateJwk::parse(&serialized).map_err(|_| {
                    to_py_err(
                        py,
                        &map_conversion_error(&convert::ConversionError::new(
                            "the supplied private key is invalid",
                        )),
                    )
                })?;
                RealEvidenceClient::from_profile_with_key(profile, key)
            }
        }
        .map_err(|error| to_py_err(py, &map_client_error(&error)))?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| {
                PyRuntimeError::new_err(format!(
                    "the client's internal runtime could not start: {error}"
                ))
            })?;
        Ok(Self { inner, runtime })
    }

    /// Discover fresh public metadata and signing keys before the next
    /// request. This never reacts to an unknown key from a response: each
    /// request verifies with the snapshots it closed before sending.
    fn refresh_metadata(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(|| self.runtime.block_on(self.inner.refresh_metadata()))
            .map_err(|error| to_py_err(py, &map_client_error(&error)))
    }

    /// Discover, prepare, send once, and locally verify one audience-scoped
    /// assertion or credential.
    ///
    /// The keyword selectors name fields for the sole request-origin subject.
    /// Multi-role requests, or a selector whose field name collides with one
    /// of this method's parameters, use `subjects={role: {field: value}}`.
    /// Passing both shapes is refused locally rather than guessing how to
    /// merge subjects. The receipt remains application-owned and is never
    /// remembered by this client.
    #[pyo3(signature = (
        requirement,
        response_format="signed-jws",
        binding_receipt=None,
        subjects=None,
        **selectors
    ))]
    fn request(
        &self,
        py: Python<'_>,
        requirement: &str,
        response_format: &str,
        binding_receipt: Option<PyRef<'_, SubjectBindingReceipt>>,
        subjects: Option<&Bound<'_, PyAny>>,
        selectors: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Py<PyAny>> {
        let selector_json = selectors
            .map(|value| python_to_json(value.as_any()))
            .transpose()
            .map_err(|error| to_py_err(py, &map_conversion_error(&error)))?
            .unwrap_or_else(|| serde_json::json!({}));
        let selector_values = selector_values_from_json(&selector_json, "selector keywords")
            .map_err(|error| to_py_err(py, &map_conversion_error(&error)))?;
        let subject_values = subjects
            .map(python_to_json)
            .transpose()
            .map_err(|error| to_py_err(py, &map_conversion_error(&error)))?
            .map(|value| progressive_subjects_from_json(&value))
            .transpose()
            .map_err(|error| to_py_err(py, &map_conversion_error(&error)))?;
        if subject_values.is_some() && !selector_values.is_empty() {
            return Err(to_py_err(
                py,
                &map_conversion_error(&convert::ConversionError::new(
                    "use either selector keywords or `subjects`, not both",
                )),
            ));
        }
        let response_format = serde_json::from_value(serde_json::Value::String(
            response_format.to_owned(),
        ))
        .map_err(|_| {
            to_py_err(
                py,
                &map_conversion_error(&convert::ConversionError::new(
                    "`response_format` must be \"signed-jws\" or \"sd-jwt-vc\"",
                )),
            )
        })?;
        let mut request = RealAudienceScopedRequest::new(requirement.to_owned(), selector_values)
            .with_response_format(response_format);
        if let Some(subjects) = subject_values {
            request = request.with_subjects(subjects);
        }
        if let Some(receipt) = binding_receipt {
            request = request.with_binding_receipt(receipt.inner.clone());
        }
        let result = py
            .detach(|| self.runtime.block_on(self.inner.request(request)))
            .map_err(|error| to_py_err(py, &map_client_error(&error)))?;
        progressive_result_to_python(py, result)
    }

    /// Close the expectations for one request and generate its nonce.
    ///
    /// No I/O happens here, and this call is synchronous. The returned
    /// request is good for exactly one exchange: spend it with `send` or
    /// `request_and_verify`.
    fn prepare(
        &self,
        py: Python<'_>,
        spec: &Bound<'_, PyAny>,
    ) -> PyResult<PreparedEvidenceRequest> {
        let spec_json =
            python_to_json(spec).map_err(|error| to_py_err(py, &map_conversion_error(&error)))?;
        let spec = spec_from_json(&spec_json)
            .map_err(|error| to_py_err(py, &map_conversion_error(&error)))?;
        let prepared = self
            .inner
            .prepare(spec)
            .map_err(|error| to_py_err(py, &map_client_error(&error)))?;
        Ok(PreparedEvidenceRequest { inner: prepared })
    }

    /// Close one independently nonce-bound policy for every positional item
    /// in an ordered request batch. No I/O happens here, and the returned
    /// opaque batch is good for exactly one exchange.
    fn prepare_batch(
        &self,
        py: Python<'_>,
        spec: &Bound<'_, PyAny>,
    ) -> PyResult<PreparedEvidenceRequestBatch> {
        let spec_json =
            python_to_json(spec).map_err(|error| to_py_err(py, &map_conversion_error(&error)))?;
        let spec = batch_spec_from_json(&spec_json)
            .map_err(|error| to_py_err(py, &map_conversion_error(&error)))?;
        let prepared = self
            .inner
            .prepare_batch(spec)
            .map_err(|error| to_py_err(py, &map_client_error(&error)))?;
        Ok(PreparedEvidenceRequestBatch { inner: prepared })
    }

    /// Read the request shapes this requester is entitled to send.
    ///
    /// Discovery is authoring input, not a trust anchor: it never supplies
    /// verification expectations for a request already in flight.
    fn discover(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let document = py
            .detach(|| self.runtime.block_on(self.inner.discover()))
            .map_err(|error| to_py_err(py, &map_client_error(&error)))?;
        let value = serde_json::to_value(&document)
            .map_err(|error| serialization_error("the definitions document", error))?;
        Ok(json_to_python(py, &value)?.unbind())
    }

    /// Read the deployment's published verification key set, for an
    /// out-of-band pinning workflow. Verification never calls this: a key set
    /// fetched from the same origin as the response it would verify
    /// establishes nothing.
    fn fetch_jwks(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let document = py
            .detach(|| self.runtime.block_on(self.inner.fetch_jwks()))
            .map_err(|error| to_py_err(py, &map_client_error(&error)))?;
        let value = serde_json::to_value(&document)
            .map_err(|error| serialization_error("the key set", error))?;
        Ok(json_to_python(py, &value)?.unbind())
    }

    /// Send one prepared request and read the signed response.
    ///
    /// `prepared` allows exactly one send: a second call with the same object
    /// rejects with the configuration failure the wrapped client already
    /// produces, without reaching the deployment. Retrying means preparing
    /// again, for a fresh nonce.
    fn send(
        &self,
        py: Python<'_>,
        prepared: &PreparedEvidenceRequest,
    ) -> PyResult<RawEvidenceResponse> {
        let response = py
            .detach(|| self.runtime.block_on(self.inner.send(&prepared.inner)))
            .map_err(|error| to_py_err(py, &map_client_error(&error)))?;
        Ok(RawEvidenceResponse { inner: response })
    }

    /// Send one prepared request batch and read its unverified envelope. The
    /// same opaque prepared object cannot be sent twice.
    fn send_batch(
        &self,
        py: Python<'_>,
        prepared: &PreparedEvidenceRequestBatch,
    ) -> PyResult<RawEvidenceRequestBatchResponse> {
        let response = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.send_batch(&prepared.inner))
            })
            .map_err(|error| to_py_err(py, &map_client_error(&error)))?;
        Ok(RawEvidenceRequestBatchResponse { inner: response })
    }

    /// Verify a signed response against the policy its request closed, as of
    /// now. The trusted key set is the one pinned at construction, always.
    ///
    /// Unlike sending, verifying is unrestricted: it is offline, synchronous,
    /// and idempotent, so a retained response may be re-verified against a
    /// retained prepared request as often as needed, including after the
    /// single send has been spent.
    fn verify(
        &self,
        py: Python<'_>,
        prepared: &PreparedEvidenceRequest,
        response: &RawEvidenceResponse,
    ) -> PyResult<VerifiedEvidence> {
        let verified = self
            .inner
            .verify(&prepared.inner, &response.inner)
            .map_err(|error| to_py_err(py, &map_client_error(&error)))?;
        verified_evidence_to_python(py, &verified)
    }

    /// Atomically verify every available member against the closed policy at
    /// its own request position. No partial result is returned when any
    /// member fails.
    fn verify_batch(
        &self,
        py: Python<'_>,
        prepared: &PreparedEvidenceRequestBatch,
        response: &RawEvidenceRequestBatchResponse,
    ) -> PyResult<VerifiedEvidenceRequestBatch> {
        let verified = self
            .inner
            .verify_batch(&prepared.inner, &response.inner)
            .map_err(|error| to_py_err(py, &map_client_error(&error)))?;
        verified_request_batch_to_python(py, &verified)
    }

    /// Request evidence and verify it in one step. This spends the single
    /// send `prepared` allows, exactly as `send` does, so calling it twice
    /// with one prepared request fails locally on the second call.
    fn request_and_verify(
        &self,
        py: Python<'_>,
        prepared: &PreparedEvidenceRequest,
    ) -> PyResult<VerifiedEvidence> {
        let verified = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.request_and_verify(&prepared.inner))
            })
            .map_err(|error| to_py_err(py, &map_client_error(&error)))?;
        verified_evidence_to_python(py, &verified)
    }

    /// Send and atomically verify one prepared request batch in one step.
    /// Network I/O runs with the GIL detached exactly as the singular method
    /// does.
    fn request_and_verify_batch(
        &self,
        py: Python<'_>,
        prepared: &PreparedEvidenceRequestBatch,
    ) -> PyResult<VerifiedEvidenceRequestBatch> {
        let verified = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.request_and_verify_batch(&prepared.inner))
            })
            .map_err(|error| to_py_err(py, &map_client_error(&error)))?;
        verified_request_batch_to_python(py, &verified)
    }

    /// Verify a retained response as of an explicit instant, given as seconds
    /// since the UNIX epoch (the same value `datetime.timestamp()` yields).
    ///
    /// `verify` judges a response against the current clock, which is right
    /// when the response has just arrived. This variant names the instant
    /// instead, for re-verifying a retained response or replaying a retained
    /// transaction record at the instant the original decision was made.
    ///
    /// A past instant is the direction that costs something: naming a stale
    /// instant accepts an assertion whose validity interval has since
    /// elapsed, because the question asked is whether it was acceptable
    /// then, and the answer stays yes forever. A live trust decision calls
    /// `verify`, not this.
    fn verify_as_of(
        &self,
        py: Python<'_>,
        prepared: &PreparedEvidenceRequest,
        response: &RawEvidenceResponse,
        as_of_unix_seconds: f64,
    ) -> PyResult<VerifiedEvidence> {
        let now = datetime_from_unix_seconds(as_of_unix_seconds)
            .map_err(|error| to_py_err(py, &map_conversion_error(&error)))?;
        let verified = self
            .inner
            .verify_as_of(&prepared.inner, &response.inner, now)
            .map_err(|error| to_py_err(py, &map_client_error(&error)))?;
        verified_evidence_to_python(py, &verified)
    }

    /// Atomically verify a retained request-batch response as of an explicit
    /// instant, given as seconds since the UNIX epoch.
    fn verify_batch_as_of(
        &self,
        py: Python<'_>,
        prepared: &PreparedEvidenceRequestBatch,
        response: &RawEvidenceRequestBatchResponse,
        as_of_unix_seconds: f64,
    ) -> PyResult<VerifiedEvidenceRequestBatch> {
        let now = datetime_from_unix_seconds(as_of_unix_seconds)
            .map_err(|error| to_py_err(py, &map_conversion_error(&error)))?;
        let verified = self
            .inner
            .verify_batch_as_of(&prepared.inner, &response.inner, now)
            .map_err(|error| to_py_err(py, &map_client_error(&error)))?;
        verified_request_batch_to_python(py, &verified)
    }
}

// `pub` so `tests/happy_path.rs` (a separate integration-test crate) can call
// this directly rather than going through a real `import`: building a
// `PyModule` and handing it to this function is the same registration path
// Python's own import machinery would drive, so a direct call still exercises
// genuine `#[pyclass]`/`#[pymethods]` dispatch and argument marshaling, with
// none of the sequencing that `pyo3::append_to_inittab!` would need against
// this crate's `auto-initialize` dev-dependency (used by the panic-boundary
// test below).
#[pymodule]
pub fn registry_evidence_client(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<EvidenceClient>()?;
    module.add_class::<PreparedEvidenceRequest>()?;
    module.add_class::<PreparedEvidenceRequestBatch>()?;
    module.add_class::<RawEvidenceResponse>()?;
    module.add_class::<RawEvidenceRequestBatchResponse>()?;
    module.add_class::<SdJwtVcBatchResponse>()?;
    module.add_class::<VerifiedEvidence>()?;
    module.add_class::<VerifiedEvidenceRequestBatch>()?;
    module.add_class::<SubjectBindingReceipt>()?;
    module.add_class::<SubjectContinuity>()?;
    module.add_class::<VerifiedAssertion>()?;
    module.add_class::<VerifiedAudienceScopedCredential>()?;

    let py = module.py();
    module.add("EvidenceClientError", py.get_type::<EvidenceClientError>())?;
    module.add("ConfigurationError", py.get_type::<ConfigurationError>())?;
    module.add("NonceError", py.get_type::<NonceError>())?;
    module.add("TokenError", py.get_type::<TokenError>())?;
    module.add("TransportError", py.get_type::<TransportError>())?;
    module.add("DeniedError", py.get_type::<DeniedError>())?;
    module.add("NotAvailableError", py.get_type::<NotAvailableError>())?;
    module.add("ProtocolError", py.get_type::<ProtocolError>())?;
    module.add("VerificationError", py.get_type::<VerificationError>())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PyO3 wraps every generated `pymethods`/`pyfunction` entry point in
    /// `std::panic::catch_unwind`, translating an unwind into a Python
    /// `PanicException` rather than letting it cross the FFI boundary
    /// (undefined behavior). Confirmed by reading the vendored source:
    /// `pyo3-0.29.1/src/impl_/trampoline.rs` lines 289-324 (`catch_unwind` at
    /// line 301, `PanicException::from_panic_payload` at line 320) and
    /// `pyo3-0.29.1/src/panic.rs` (`PanicException` itself, at
    /// `pyo3::panic::PanicException`, not re-exported at the crate root).
    ///
    /// Aside from `to_py_err`'s `set_attr!` calls, which can only panic under
    /// allocation failure, this crate has exactly one latent panic to worry
    /// about, and it is not the client's own request nonce: that one is
    /// generated through `getrandom::fill`, which reports entropy failure as
    /// an ordinary error rather than panicking. The unguarded path is the
    /// private-key-JWT token provider's own `jti` claim, generated with
    /// `Ulid::new()`, which reaches `rand::rng()` and panics when OS entropy
    /// is unavailable, a case that provider deliberately leaves unguarded. It
    /// is reachable only in a deployment configured for private-key-JWT: a
    /// static-authorization deployment never calls that provider, so short of that
    /// same allocation-failure-only path it has no reachable panic at all. No extra guard is added here for it: this test
    /// proves the boundary already turns any such panic into an ordinary
    /// Python exception instead of a process abort.
    ///
    /// The catch must be exercised from Python code, not from a Rust `call0`:
    /// `PyErr::take` (which every pyo3 call-from-Rust helper uses to read the
    /// interpreter's error back into Rust) deliberately resumes the original
    /// panic the moment Rust re-observes a `PanicException`, exactly so a
    /// caught panic can never be silently absorbed into ordinary Rust error
    /// handling. That resuming is itself confirmation that pyo3 treats a
    /// caught panic specially; it is not this test's subject. A genuine
    /// Python caller never triggers it, since plain Python `except` clauses
    /// clear the interpreter's error state directly rather than through that
    /// Rust-side path, so this test drives the call the same way: through a
    /// `try`/`except` block executed as Python code.
    #[test]
    fn panics_cross_the_boundary_as_a_python_exception() {
        #[pyfunction]
        fn panic_for_test() {
            panic!("deliberate panic for the trampoline boundary test");
        }

        Python::attach(|py| {
            let function = wrap_pyfunction!(panic_for_test, py).expect("function wraps");
            let locals = pyo3::types::PyDict::new(py);
            locals
                .set_item("panic_for_test", function)
                .expect("locals accept the function");
            py.run(
                c"try:
    panic_for_test()
    caught = None
except BaseException as error:
    caught = type(error).__name__",
                None,
                Some(&locals),
            )
            .expect("the script itself must not raise: the panic is caught inside it");
            let caught: String = locals
                .get_item("caught")
                .expect("locals lookup succeeds")
                .expect("`caught` was assigned")
                .extract()
                .expect("`caught` is a string");
            assert_eq!(caught, "PanicException");
        });
    }

    /// `exception_for_kind`'s catch-all arm (`_ =>
    /// EvidenceClientError::new_err(message)`) is deliberate: it keeps this
    /// binding compiling and useful as the wrapped `#[non_exhaustive]` error
    /// enum grows a kind this crate does not yet know about. The same
    /// catch-all also means that renaming one of the known kind strings in an
    /// existing match arm degrades that kind to the base class silently
    /// instead of failing to compile, so this pins every one of the eight
    /// known kind strings to its own specific exception class directly.
    #[test]
    fn exception_for_kind_maps_every_known_kind_to_its_specific_class() {
        Python::attach(|py| {
            assert!(exception_for_kind("configuration", "message".to_owned())
                .is_instance_of::<ConfigurationError>(py));
            assert!(
                exception_for_kind("nonce", "message".to_owned()).is_instance_of::<NonceError>(py)
            );
            assert!(
                exception_for_kind("token", "message".to_owned()).is_instance_of::<TokenError>(py)
            );
            assert!(exception_for_kind("transport", "message".to_owned())
                .is_instance_of::<TransportError>(py));
            assert!(exception_for_kind("denied", "message".to_owned())
                .is_instance_of::<DeniedError>(py));
            assert!(exception_for_kind("not_available", "message".to_owned())
                .is_instance_of::<NotAvailableError>(py));
            assert!(exception_for_kind("protocol", "message".to_owned())
                .is_instance_of::<ProtocolError>(py));
            assert!(exception_for_kind("verification", "message".to_owned())
                .is_instance_of::<VerificationError>(py));
        });
    }

    #[test]
    fn progressive_values_are_immutable_and_value_reads_retained_verified_data() {
        Python::attach(|py| {
            let values = BTreeMap::from([(
                "structured".to_owned(),
                evidence_client_sdk::PublicValue::Structured(
                    evidence_client_sdk::StructuredValue {
                        form: evidence_client_sdk::StructuredValueForm::ReviewedStructuredValue,
                        schema: "urn:example:structured:v1".to_owned(),
                        fields: BTreeMap::from([
                            ("answer".to_owned(), serde_json::Value::Bool(true)),
                            (
                                "answers".to_owned(),
                                serde_json::json!(["yes", {"nested": true}]),
                            ),
                        ]),
                    },
                ),
            )]);
            let exposed = immutable_verified_values(py, &values).expect("values are serializable");
            let types = PyModule::import(py, "types").expect("types module imports");
            assert!(exposed
                .bind(py)
                .is_instance(&types.getattr("MappingProxyType").expect("type exists"))
                .expect("type check succeeds"));

            let locals = PyDict::new(py);
            locals
                .set_item("values", exposed.bind(py))
                .expect("locals accept values");
            py.run(
                c"try:
    values['other'] = False
except TypeError:
    outer_mutation_refused = True
else:
    outer_mutation_refused = False
nested_mapping_mutation_refused = False
try:
    values['structured']['fields']['answer'] = False
except TypeError:
    nested_mapping_mutation_refused = True
nested_list_mutation_refused = False
try:
    values['structured']['fields']['answers'].append('no')
except AttributeError:
    nested_list_mutation_refused = True
nested_list_mapping_mutation_refused = False
try:
    values['structured']['fields']['answers'][1]['nested'] = False
except TypeError:
    nested_list_mapping_mutation_refused = True",
                None,
                Some(&locals),
            )
            .expect("immutable snapshots refuse nested mutation");
            let outer_mutation_refused: bool = locals
                .get_item("outer_mutation_refused")
                .expect("locals lookup succeeds")
                .expect("script assigned outcome")
                .extract()
                .expect("outcome is boolean");
            assert!(outer_mutation_refused);
            for name in [
                "nested_mapping_mutation_refused",
                "nested_list_mutation_refused",
                "nested_list_mapping_mutation_refused",
            ] {
                let refused: bool = locals
                    .get_item(name)
                    .expect("locals lookup succeeds")
                    .expect("script assigned outcome")
                    .extract()
                    .expect("outcome is boolean");
                assert!(refused, "{name} must be refused");
            }

            let verified = sole_verified_value(py, &values).expect("one value is available");
            let verified_fields = verified
                .bind(py)
                .cast::<PyMapping>()
                .expect("verified structured value is a mapping")
                .get_item("fields")
                .expect("fields lookup succeeds")
                .cast_into::<PyMapping>()
                .expect("fields are a mapping");
            assert!(verified_fields
                .get_item("answer")
                .expect("answer lookup succeeds")
                .extract::<bool>()
                .expect("answer is boolean"));
            let answers = verified_fields
                .get_item("answers")
                .expect("answers lookup succeeds")
                .cast_into::<PyTuple>()
                .expect("answers are a tuple");
            assert_eq!(answers.len(), 2);
            assert_eq!(
                answers
                    .get_item(0)
                    .expect("first answer exists")
                    .extract::<String>()
                    .expect("first answer is text"),
                "yes"
            );
            let nested = answers
                .get_item(1)
                .expect("nested answer exists")
                .cast_into::<PyMapping>()
                .expect("nested answer is a mapping");
            assert!(nested
                .get_item("nested")
                .expect("nested lookup succeeds")
                .extract::<bool>()
                .expect("nested flag is boolean"));

            let immutable_value = sole_verified_value(py, &values).expect("one value is available");
            let locals = PyDict::new(py);
            locals
                .set_item("value", immutable_value.bind(py))
                .expect("locals accept value");
            py.run(
                c"try:
    value['fields']['answers'][0] = 'no'
except TypeError:
    value_mutation_refused = True
else:
    value_mutation_refused = False",
                None,
                Some(&locals),
            )
            .expect("immutable value test executes");
            let value_mutation_refused: bool = locals
                .get_item("value_mutation_refused")
                .expect("locals lookup succeeds")
                .expect("script assigned outcome")
                .extract()
                .expect("outcome is boolean");
            assert!(value_mutation_refused);

            let no_values = BTreeMap::new();
            let error = sole_verified_value(py, &no_values)
                .expect_err("zero values are ambiguous")
                .value(py)
                .str()
                .expect("exception renders")
                .to_string();
            assert!(error.contains("exactly one output"));

            let several_values = BTreeMap::from([
                (
                    "first".to_owned(),
                    evidence_client_sdk::PublicValue::Boolean(true),
                ),
                (
                    "second".to_owned(),
                    evidence_client_sdk::PublicValue::Boolean(false),
                ),
            ]);
            let error = sole_verified_value(py, &several_values)
                .expect_err("two values are ambiguous")
                .value(py)
                .str()
                .expect("exception renders")
                .to_string();
            assert!(error.contains("exactly one output"));

            let single_value = BTreeMap::from([(
                "sole".to_owned(),
                evidence_client_sdk::PublicValue::Boolean(true),
            )]);
            let value = sole_verified_value(py, &single_value).expect("one value is available");
            assert!(value.bind(py).is_truthy().expect("boolean reads"));
        });
    }
}
