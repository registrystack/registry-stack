//! Node.js binding for the Evidence relying-party client, via napi-rs.
//!
//! This crate is a thin `#[napi]` surface only: every JS-value <-> Rust
//! conversion lives in [`convert`], as plain functions over
//! [`serde_json::Value`] with no `napi` dependency of their own, so the
//! conversion layer is unit-testable with `cargo test`. Every Evidence
//! semantic decision (evaluation, signing, verification) is the
//! `registry-evidence-client` crate's own; this crate re-implements none of
//! it.
//!
//! `PreparedEvidenceRequest` and `RawEvidenceResponse` cross as opaque classes
//! wrapping an `Arc` around the real Rust value: neither real type is `Clone`
//! constructible from JS-supplied data (`PreparedEvidenceRequest` is
//! deliberately `!Clone` to protect its single-send flag; `RawEvidenceResponse`
//! has no public constructor at all), and both are produced by one call
//! (`prepare`, `send`) and consumed by a later one (`send`/`verify`, `verify`).
//! An `Arc` clone is cheap and, for `PreparedEvidenceRequest`, preserves the
//! identity of the interior `AtomicBool` the single-send guard checks: cloning
//! the `Arc` shares the flag rather than resetting it.
//!
//! `send` and `requestAndVerify` cannot be plain `async fn` methods that take
//! a class reference as a parameter: napi-rs's tokio bridge requires the whole
//! generated future to be `Send + 'static`, and a class reference into a JS
//! object (`Reference<T>`) is documented as not `Send`. Both methods are
//! instead ordinary (non-async) `#[napi]` functions that clone the `Arc`s they
//! need synchronously, then hand an `async move` block built from only those
//! owned clones to [`napi::Env::spawn_future`].
#![deny(unsafe_code)]

mod convert;

use std::sync::Arc;

// `napi::Result` is imported unaliased (shadowing the prelude's
// `std::result::Result`, the standard convention in napi-rs bindings):
// napi-derive detects a fallible `#[napi]` return type by checking that the
// return type's own final path segment is literally named `Result`, so an
// aliased name here would silently defeat that detection.
use napi::{
    bindgen_prelude::{Buffer, Env, PromiseRaw},
    Error as NapiError, Result,
};
use napi_derive::napi;
use registry_evidence_client::{
    EvidenceClient as RealEvidenceClient, PreparedEvidenceRequest as RealPreparedEvidenceRequest,
    RawEvidenceResponse as RealRawEvidenceResponse, VerifiedEvidence as RealVerifiedEvidence,
};

use convert::{
    config_from_json, evidence_to_json, map_client_error, map_config_error, map_conversion_error,
    spec_from_json, subject_expectations_to_json,
};

/// Every mapped failure (see `convert::map_client_error` and friends) carries
/// this JSON envelope as the thrown error's message, so a caller can
/// `JSON.parse(error.message)` and branch on `kind`. This is the one place
/// that JSON value becomes a `napi::Error`.
fn to_napi_error(value: serde_json::Value) -> NapiError {
    let message = serde_json::to_string(&value).unwrap_or_else(|_| {
        r#"{"kind":"configuration","message":"the failure could not be described"}"#.to_owned()
    });
    NapiError::from_reason(message)
}

/// A serialization failure on a value this crate itself constructed (a
/// definitions document, a policy document, a verified payload) is not a
/// caller mistake; it has no `kind` of its own among the eight stable ones, so
/// it is reported as a plain reason rather than forced into that envelope.
fn to_napi_serialization_error(what: &str, error: serde_json::Error) -> NapiError {
    NapiError::from_reason(format!("{what} could not be described: {error}"))
}

/// Run a synchronous `#[napi]` entry point, turning a caught panic into an
/// ordinary rejection instead of letting the unwind cross the FFI boundary,
/// which aborts the whole process.
///
/// napi-derive 3.6.2's generated glue carries no panic handling of its own
/// for synchronous `#[napi]` functions, so every synchronous entry point in
/// this file (the constructor, `prepare`, `verify`, `verify_as_of`, and the
/// `PreparedEvidenceRequest`/`RawEvidenceResponse` getters) routes through
/// this helper. An asynchronous entry point (`discover`, `fetch_jwks`,
/// `send`, `request_and_verify`) takes a different path: its future runs on
/// tokio, and a panic during a poll is caught by tokio's own task-level panic
/// isolation, not by this helper, then surfaces to napi as a join error that
/// the `tokio_rt`-backed async bridge detects and translates into a rejected
/// promise.
///
/// `AssertUnwindSafe` is appropriate here: every call site immediately
/// converts a caught panic into a returned `Err` and never inspects or
/// continues using whatever state the unwinding closure touched, so a
/// theoretically inconsistent intermediate state cannot leak into further
/// observable behavior.
///
/// The reported reason is fixed and never echoes the panic payload: a panic
/// is, by construction, a code path nobody validated ahead of time, so its
/// payload carries none of the redaction guarantees the rest of this crate's
/// error reporting is held to.
///
/// The asynchronous path is not held to that same guarantee, and this crate
/// does not control it: napi rejects with the panic payload downcast to
/// `&str`, falling back to the fixed literal "Panic in async function" for
/// any other payload type, including the `String` a formatted
/// `panic!("{}", x)` produces. A panic in an asynchronous entry point can
/// therefore echo its own message to JS, unlike `to_napi_panic_error` below,
/// which returns fixed prose regardless of the payload.
fn catch_panic<T>(what: &'static str, f: impl FnOnce() -> Result<T>) -> Result<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
        .unwrap_or_else(|_payload| Err(to_napi_panic_error(what)))
}

fn to_napi_panic_error(what: &'static str) -> NapiError {
    NapiError::from_reason(format!(
        "{what} failed unexpectedly and could not complete; this is a defect, not a refusal"
    ))
}

/// One request, closed and nonce-bearing, before any byte has left the
/// process.
///
/// There is no constructor exposed to JS: the only way to obtain one is
/// `EvidenceClient.prepare`, which mirrors the real type having no public
/// constructor of its own either.
#[napi]
pub struct PreparedEvidenceRequest {
    inner: Arc<RealPreparedEvidenceRequest>,
}

#[napi]
impl PreparedEvidenceRequest {
    /// The nonce this request carries. Retain it with the transaction record.
    #[napi(getter)]
    pub fn request_nonce(&self) -> Result<String> {
        catch_panic("reading the request nonce", || {
            Ok(self.inner.request_nonce().to_owned())
        })
    }

    /// The closed verification policy, with the subject set as `prepare` left
    /// it.
    #[napi(getter)]
    pub fn policy_document(&self) -> Result<serde_json::Value> {
        catch_panic("reading the policy document", || {
            serde_json::to_value(self.inner.policy_document())
                .map_err(|error| to_napi_serialization_error("the policy document", error))
        })
    }

    /// `"acceptFirstUse"` or `{ pinned: [{ role, binding }, ...] }`, exactly as
    /// this request was prepared.
    #[napi(getter)]
    pub fn subject_expectations(&self) -> Result<serde_json::Value> {
        catch_panic("reading the subject expectations", || {
            Ok(subject_expectations_to_json(
                self.inner.subject_expectations(),
            ))
        })
    }
}

/// A signed response, read but not yet judged.
///
/// There is no constructor exposed to JS: the real Rust type has no public
/// constructor either, so the only way to obtain one is `EvidenceClient.send`.
#[napi]
pub struct RawEvidenceResponse {
    inner: Arc<RealRawEvidenceResponse>,
}

#[napi]
impl RawEvidenceResponse {
    /// The signed response bytes, exactly as received. Nothing in them has
    /// been trusted yet; `verify` is what judges them.
    #[napi(getter)]
    pub fn body(&self) -> Result<Buffer> {
        catch_panic("reading the response body", || {
            Ok(self.inner.body().to_vec().into())
        })
    }

    /// The deployment's opaque identifier for this exchange, for support
    /// correlation.
    #[napi(getter)]
    pub fn operation(&self) -> Result<Option<String>> {
        catch_panic("reading the response operation", || {
            Ok(self.inner.operation().map(str::to_owned))
        })
    }
}

/// A response that satisfied every expectation.
///
/// Unlike the two classes above, this crosses as a plain object: it is a
/// terminal result nothing hands back into a later call, so there is no
/// single-send flag or unconstructible real type to protect by staying
/// opaque.
#[napi(object)]
pub struct VerifiedEvidence {
    /// The verified payload, serialized field for field with no hand mapping.
    pub evidence: serde_json::Value,
    /// The deployment's opaque identifier for the exchange that produced this
    /// payload.
    pub operation: Option<String>,
    /// The role-bound subject bindings this payload carries. Persist these
    /// after a first-use acceptance and pass them back as `subjectExpectations:
    /// { pinned: [...] }` from then on.
    pub pinned_subject_expectations: serde_json::Value,
}

fn verified_evidence_to_napi(verified: &RealVerifiedEvidence) -> Result<VerifiedEvidence> {
    let evidence = evidence_to_json(verified.evidence())
        .map_err(|error| to_napi_error(map_conversion_error(&error)))?;
    let pinned_subject_expectations = serde_json::to_value(verified.pinned_subject_expectations())
        .map_err(|error| to_napi_serialization_error("the pinned subject expectations", error))?;
    Ok(VerifiedEvidence {
        evidence,
        operation: verified.operation().map(str::to_owned),
        pinned_subject_expectations,
    })
}

/// A relying party's connection to one Evidence deployment.
#[napi]
pub struct EvidenceClient {
    inner: Arc<RealEvidenceClient>,
}

#[napi]
impl EvidenceClient {
    /// Build a client for one deployment. `trustedJwks` is mandatory; an empty
    /// key set is refused, exactly as the Rust configuration is.
    #[napi(constructor)]
    pub fn new(config: serde_json::Value) -> Result<Self> {
        catch_panic("constructing the client", || {
            let config = config_from_json(&config)
                .map_err(|error| to_napi_error(map_config_error(&error)))?;
            let client = RealEvidenceClient::new(config)
                .map_err(|error| to_napi_error(map_client_error(&error)))?;
            Ok(Self {
                inner: Arc::new(client),
            })
        })
    }

    /// Close the expectations for one request and generate its nonce. No I/O
    /// happens here. The returned request is good for exactly one exchange:
    /// spend it with `send` or `requestAndVerify`.
    #[napi]
    pub fn prepare(&self, spec: serde_json::Value) -> Result<PreparedEvidenceRequest> {
        catch_panic("preparing a request", || {
            let spec = spec_from_json(&spec)
                .map_err(|error| to_napi_error(map_conversion_error(&error)))?;
            let prepared = self
                .inner
                .prepare(spec)
                .map_err(|error| to_napi_error(map_client_error(&error)))?;
            Ok(PreparedEvidenceRequest {
                inner: Arc::new(prepared),
            })
        })
    }

    /// Read the request shapes this requester is entitled to send. Discovery
    /// is authoring input, not a trust anchor: it never supplies verification
    /// expectations for a request already in flight.
    #[napi]
    pub async fn discover(&self) -> Result<serde_json::Value> {
        let document = self
            .inner
            .discover()
            .await
            .map_err(|error| to_napi_error(map_client_error(&error)))?;
        serde_json::to_value(&document)
            .map_err(|error| to_napi_serialization_error("the definitions document", error))
    }

    /// Read the deployment's published verification key set, for an
    /// out-of-band pinning workflow. Verification never calls this: a key set
    /// fetched from the same origin as the response it would verify
    /// establishes nothing.
    #[napi]
    pub async fn fetch_jwks(&self) -> Result<serde_json::Value> {
        let document = self
            .inner
            .fetch_jwks()
            .await
            .map_err(|error| to_napi_error(map_client_error(&error)))?;
        serde_json::to_value(&document)
            .map_err(|error| to_napi_serialization_error("the key set", error))
    }

    /// Send one prepared request and read the signed response.
    ///
    /// `prepared` allows exactly one send: a second call with the same object
    /// rejects with the configuration failure the Rust layer already
    /// produces, without reaching the deployment. Retrying means preparing
    /// again, for a fresh nonce.
    #[napi(ts_return_type = "Promise<RawEvidenceResponse>")]
    pub fn send<'env>(
        &self,
        env: &'env Env,
        prepared: &PreparedEvidenceRequest,
    ) -> Result<PromiseRaw<'env, RawEvidenceResponse>> {
        let client = Arc::clone(&self.inner);
        let prepared = Arc::clone(&prepared.inner);
        env.spawn_future(async move {
            client
                .send(&prepared)
                .await
                .map(|response| RawEvidenceResponse {
                    inner: Arc::new(response),
                })
                .map_err(|error| to_napi_error(map_client_error(&error)))
        })
    }

    /// Verify a signed response against the policy its request closed, as of
    /// now. The trusted key set is the one pinned at construction, always.
    ///
    /// Unlike sending, verifying is unrestricted: it is offline and
    /// idempotent, so a retained response may be re-verified against a
    /// retained prepared request as often as needed, including after the
    /// single send has been spent.
    #[napi]
    pub fn verify(
        &self,
        prepared: &PreparedEvidenceRequest,
        response: &RawEvidenceResponse,
    ) -> Result<VerifiedEvidence> {
        catch_panic("verifying a response", || {
            let verified = self
                .inner
                .verify(&prepared.inner, &response.inner)
                .map_err(|error| to_napi_error(map_client_error(&error)))?;
            verified_evidence_to_napi(&verified)
        })
    }

    /// Request evidence and verify it in one step. This spends the single
    /// send `prepared` allows, exactly as `send` does, so calling it twice
    /// with one prepared request fails locally on the second call.
    #[napi(ts_return_type = "Promise<VerifiedEvidence>")]
    pub fn request_and_verify<'env>(
        &self,
        env: &'env Env,
        prepared: &PreparedEvidenceRequest,
    ) -> Result<PromiseRaw<'env, VerifiedEvidence>> {
        let client = Arc::clone(&self.inner);
        let prepared = Arc::clone(&prepared.inner);
        env.spawn_future(async move {
            let verified = client
                .request_and_verify(&prepared)
                .await
                .map_err(|error| to_napi_error(map_client_error(&error)))?;
            verified_evidence_to_napi(&verified)
        })
    }

    /// Verify a retained response as of an explicit instant, given as
    /// milliseconds since the Unix epoch.
    ///
    /// `verify` judges a response against the current clock, which is right
    /// when the response has just arrived. This variant names the instant
    /// instead, for re-verifying a retained response or replaying a retained
    /// transaction record at the instant the original decision was made.
    ///
    /// A past instant is the direction that costs something: naming a stale
    /// instant accepts an assertion whose validity interval has since
    /// elapsed, because the question asked is whether it was acceptable then,
    /// and the answer stays yes forever. A live trust decision calls `verify`,
    /// not this.
    #[napi]
    pub fn verify_as_of(
        &self,
        prepared: &PreparedEvidenceRequest,
        response: &RawEvidenceResponse,
        as_of_millis: f64,
    ) -> Result<VerifiedEvidence> {
        catch_panic("verifying a response as of an instant", || {
            let millis = as_of_millis as i64;
            let now = chrono::DateTime::from_timestamp_millis(millis).ok_or_else(|| {
                NapiError::from_reason("`asOfMillis` is not a representable instant".to_owned())
            })?;
            let verified = self
                .inner
                .verify_as_of(&prepared.inner, &response.inner, now)
                .map_err(|error| to_napi_error(map_client_error(&error)))?;
            verified_evidence_to_napi(&verified)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ordinary_result_passes_through_catch_panic_unchanged() {
        let ok: Result<i32> = catch_panic("a synthetic operation", || Ok(42));
        assert_eq!(ok.unwrap(), 42);

        let err: Result<i32> = catch_panic("a synthetic operation", || {
            Err(NapiError::from_reason("an ordinary refusal".to_owned()))
        });
        assert_eq!(err.unwrap_err().reason, "an ordinary refusal");
    }

    /// Proves the one hazard `catch_panic` exists to close: without it, this
    /// panic would unwind straight across the `#[napi]` boundary and abort
    /// the process rather than reject one call.
    ///
    /// The default panic hook is silenced for the duration of this test so
    /// the synthetic panic below does not print to stderr; no other test in
    /// this crate panics, so swapping the process-wide hook here does not
    /// affect any other test's output.
    #[test]
    fn a_caught_panic_becomes_an_ordinary_error_rather_than_an_abort() {
        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result: Result<()> = catch_panic("a synthetic operation", || {
            panic!("a synthetic panic carrying a canary-value that must not surface")
        });
        std::panic::set_hook(previous_hook);

        let error = result.expect_err("the panic is caught and reported as an error");
        assert!(error.reason.contains("a synthetic operation"));
        assert!(error.reason.contains("failed unexpectedly"));
        assert!(
            !error.reason.contains("canary-value"),
            "the panic payload leaked into the reported reason: {}",
            error.reason
        );
    }
}
