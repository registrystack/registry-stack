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
//! Prepared and raw singular and request-batch values cross as opaque classes
//! wrapping an `Arc` around the real Rust value. A prepared value is
//! deliberately `!Clone` to protect its single-send flag, and a raw value has
//! no public constructor at all. An `Arc` clone is cheap and preserves the
//! identity of the interior `AtomicBool` the single-send guard checks: cloning
//! the `Arc` shares the flag rather than resetting it.
//!
//! Methods that send a prepared singular or batch request cannot be plain
//! `async fn` methods that take a class reference as a parameter: napi-rs's
//! tokio bridge requires the whole generated future to be `Send + 'static`,
//! and a class reference into a JS object (`Reference<T>`) is documented as
//! not `Send`. They are instead ordinary (non-async) `#[napi]` functions that
//! clone the `Arc`s they need synchronously, then hand an `async move` block
//! built from only those owned clones to [`napi::Env::spawn_future`].
#![deny(unsafe_code)]

mod convert;

use std::{path::PathBuf, sync::Arc};

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
    AudienceScopedResult as RealAudienceScopedResult, EvidenceClient as RealEvidenceClient,
    PreparedEvidenceRequest as RealPreparedEvidenceRequest,
    PreparedEvidenceRequestBatch as RealPreparedEvidenceRequestBatch,
    RawEvidenceRequestBatchResponse as RealRawEvidenceRequestBatchResponse,
    RawEvidenceResponse as RealRawEvidenceResponse,
    SdJwtVcBatchResponse as RealSdJwtVcBatchResponse, SubjectContinuity as RealSubjectContinuity,
    VerifiedEvidence as RealVerifiedEvidence,
    VerifiedEvidenceRequestBatch as RealVerifiedEvidenceRequestBatch,
    VerifiedEvidenceRequestBatchItem as RealVerifiedEvidenceRequestBatchItem,
};

use convert::{
    audience_scoped_request_from_json, batch_spec_from_json, config_from_json,
    datetime_from_unix_millis, evidence_to_json, map_client_error, map_config_error,
    map_conversion_error, spec_from_json, subject_expectations_to_json,
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

/// One ordered request batch, with one nonce and closed policy per item,
/// before any byte has left the process.
///
/// There is no constructor exposed to JS. The only way to obtain this opaque
/// class is `EvidenceClient.prepareBatch`, and every `Arc` clone shares the
/// real batch's one-send flag rather than recreating it.
#[napi]
pub struct PreparedEvidenceRequestBatch {
    inner: Arc<RealPreparedEvidenceRequestBatch>,
}

#[napi]
impl PreparedEvidenceRequestBatch {
    /// Independently generated item nonces in request order.
    #[napi(getter)]
    pub fn request_nonces(&self) -> Result<Vec<String>> {
        catch_panic("reading the request batch nonces", || {
            Ok(self
                .inner
                .request_nonces()
                .into_iter()
                .map(str::to_owned)
                .collect())
        })
    }

    /// Independently closed policy documents in request order.
    #[napi(getter)]
    pub fn policy_documents(&self) -> Result<Vec<serde_json::Value>> {
        catch_panic("reading the request batch policy documents", || {
            (0..self.inner.count())
                .map(|index| {
                    serde_json::to_value(
                        self.inner
                            .policy_document(index)
                            .expect("the index comes from the batch count"),
                    )
                    .map_err(|error| {
                        to_napi_serialization_error("a request batch policy document", error)
                    })
                })
                .collect()
        })
    }

    /// Subject-verification stances in request order.
    #[napi(getter)]
    pub fn subject_expectations(&self) -> Result<Vec<serde_json::Value>> {
        catch_panic("reading the request batch subject expectations", || {
            Ok((0..self.inner.count())
                .map(|index| {
                    subject_expectations_to_json(
                        self.inner
                            .subject_expectations(index)
                            .expect("the index comes from the batch count"),
                    )
                })
                .collect())
        })
    }

    /// Number of positional requests in this batch.
    #[napi(getter)]
    pub fn count(&self) -> Result<u32> {
        catch_panic("reading the request batch count", || {
            Ok(u32::try_from(self.inner.count())
                .expect("a prepared request batch carries at most sixteen items"))
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

    /// The validated W3C trace identifier for this exchange. It is support
    /// correlation only, not an Evidence audit operation identity.
    #[napi(getter)]
    pub fn trace_id(&self) -> Result<Option<String>> {
        catch_panic("reading the response trace_id", || {
            Ok(self.inner.trace_id().map(str::to_owned))
        })
    }
}

/// Request-batch response bytes read but not yet judged.
///
/// The class is opaque and has no JS constructor. It can only be returned by
/// `EvidenceClient.sendBatch` and handed back to batch verification.
#[napi]
pub struct RawEvidenceRequestBatchResponse {
    inner: Arc<RealRawEvidenceRequestBatchResponse>,
}

#[napi]
impl RawEvidenceRequestBatchResponse {
    /// Response envelope bytes exactly as received.
    #[napi(getter)]
    pub fn body(&self) -> Result<Buffer> {
        catch_panic("reading the request batch response body", || {
            Ok(self.inner.body().to_vec().into())
        })
    }

    /// Deployment correlation identifier for the whole batch exchange.
    #[napi(getter)]
    pub fn trace_id(&self) -> Result<Option<String>> {
        catch_panic("reading the request batch response trace_id", || {
            Ok(self.inner.trace_id().map(str::to_owned))
        })
    }
}

/// The issuance envelope answering one request that presented several holder
/// keys, read but not yet judged.
///
/// The envelope's order is the request's own: `credentials[i]` answers the
/// key the request sent as `holderKeys[i]`, one credential per key, and a
/// caller that needs that correspondence spelled out can ask for it by index
/// with `credentialForHolderKey`. There is no partial envelope: either every
/// presented key was answered or reading the envelope failed.
///
/// Reading it judges nothing. Each credential is verified individually,
/// exactly as a single credential is, and parsing this envelope is not a step
/// in that.
#[napi]
pub struct SdJwtVcBatchResponse {
    inner: RealSdJwtVcBatchResponse,
}

#[napi]
impl SdJwtVcBatchResponse {
    /// Read an envelope from the response bytes a batch exchange returned,
    /// such as `RawEvidenceResponse.body`.
    ///
    /// This is a constructor rather than a static factory because napi-rs
    /// defines a generated static as non-writable and non-configurable on the
    /// class object, which leaves `client.js` no way to patch its throw path
    /// the way it patches every other member here. A constructor it can
    /// subclass, exactly as it already does for `EvidenceClient`.
    #[napi(constructor)]
    pub fn new(body: Buffer) -> Result<Self> {
        catch_panic("reading a batch response", || {
            let inner = RealSdJwtVcBatchResponse::parse(body.as_ref())
                .map_err(|error| to_napi_error(map_client_error(&error)))?;
            Ok(Self { inner })
        })
    }

    /// Every credential the envelope carries, in the order the request
    /// presented its holder keys.
    #[napi(getter)]
    pub fn credentials(&self) -> Result<Vec<String>> {
        catch_panic("reading the batch credentials", || {
            Ok(self.inner.credentials().to_vec())
        })
    }

    /// How many credentials the envelope carries, which is how many holder
    /// keys the request presented.
    #[napi(getter)]
    pub fn count(&self) -> Result<u32> {
        catch_panic("reading the batch count", || {
            Ok(u32::try_from(self.inner.count())
                .expect("a parsed envelope carries at most the contract's holder-key ceiling"))
        })
    }

    /// The credential bound to the holder key the request sent at `index`, or
    /// `null` when the envelope carries no credential at that position.
    #[napi]
    pub fn credential_for_holder_key(&self, index: u32) -> Result<Option<String>> {
        catch_panic("reading a batch credential by holder key", || {
            Ok(self
                .inner
                .credential_for_holder_key(index as usize)
                .map(str::to_owned))
        })
    }
}

/// A response that satisfied every expectation.
///
/// Unlike the opaque classes above, this crosses as a plain object: it is a
/// terminal result nothing hands back into a later call, so there is no
/// single-send flag or unconstructible real type to protect by staying
/// opaque.
#[napi(object)]
pub struct VerifiedEvidence {
    /// The verified payload, serialized field for field with no hand mapping.
    pub evidence: serde_json::Value,
    /// The validated W3C trace identifier for the exchange that produced this
    /// payload. It is support correlation only, not an Evidence audit operation
    /// identity.
    pub trace_id: Option<String>,
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
        trace_id: verified.trace_id().map(str::to_owned),
        pinned_subject_expectations,
    })
}

/// One ordered terminal request-batch result.
///
/// The generated TypeScript declaration is a discriminated union:
/// `{ status: "available", verified } | { status: "notAvailable" }`.
#[napi(discriminant = "status", discriminant_case = "camelCase")]
pub enum VerifiedEvidenceRequestBatchItem {
    Available { verified: VerifiedEvidence },
    NotAvailable,
}

/// Every item of an atomically verified request-batch response.
#[napi(object)]
pub struct VerifiedEvidenceRequestBatch {
    pub items: Vec<VerifiedEvidenceRequestBatchItem>,
    pub trace_id: Option<String>,
}

fn verified_request_batch_to_napi(
    verified: &RealVerifiedEvidenceRequestBatch,
) -> Result<VerifiedEvidenceRequestBatch> {
    let items = verified
        .items()
        .iter()
        .map(|item| match item {
            RealVerifiedEvidenceRequestBatchItem::Available(verified) => {
                verified_evidence_to_napi(verified)
                    .map(|verified| VerifiedEvidenceRequestBatchItem::Available { verified })
            }
            RealVerifiedEvidenceRequestBatchItem::NotAvailable => {
                Ok(VerifiedEvidenceRequestBatchItem::NotAvailable)
            }
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(VerifiedEvidenceRequestBatch {
        items,
        trace_id: verified.trace_id().map(str::to_owned),
    })
}

/// An application-owned receipt emitted after a verified audience-scoped
/// result. It is serializable but deliberately opaque to this binding: no
/// selector or disclosed value is copied into it here.
#[napi(discriminant = "status", discriminant_case = "camelCase")]
pub enum SubjectContinuity {
    FirstUse { receipt: serde_json::Value },
    Matched { receipt: serde_json::Value },
}

fn subject_continuity_to_napi(continuity: &RealSubjectContinuity) -> Result<SubjectContinuity> {
    match continuity {
        RealSubjectContinuity::FirstUse { receipt } => serde_json::to_value(receipt)
            .map(|receipt| SubjectContinuity::FirstUse { receipt })
            .map_err(|error| to_napi_serialization_error("the subject-continuity receipt", error)),
        RealSubjectContinuity::Matched { receipt } => serde_json::to_value(receipt)
            .map(|receipt| SubjectContinuity::Matched { receipt })
            .map_err(|error| to_napi_serialization_error("the subject-continuity receipt", error)),
    }
}

/// One opaque, locally verified progressive result. Its getters keep the
/// ambiguity check for `value` lazy and retain the exact artifact below the
/// FFI boundary until the caller asks for it.
#[napi]
pub struct AudienceScopedResult {
    inner: Arc<RealAudienceScopedResult>,
}

fn audience_scoped_result_to_napi(
    result: &RealAudienceScopedResult,
) -> Result<AudienceScopedResult> {
    match result {
        RealAudienceScopedResult::Assertion(verified) => Ok(AudienceScopedResult {
            inner: Arc::new(RealAudienceScopedResult::Assertion(verified.clone())),
        }),
        RealAudienceScopedResult::Credential(verified) => Ok(AudienceScopedResult {
            inner: Arc::new(RealAudienceScopedResult::Credential(verified.clone())),
        }),
    }
}

#[napi]
impl AudienceScopedResult {
    #[napi(getter)]
    pub fn response_format(&self) -> Result<String> {
        catch_panic("reading the progressive response format", || {
            Ok(match self.inner.as_ref() {
                RealAudienceScopedResult::Assertion(_) => "signed-jws",
                RealAudienceScopedResult::Credential(_) => "sd-jwt-vc",
            }
            .to_owned())
        })
    }

    #[napi(getter)]
    pub fn evidence(&self) -> Result<serde_json::Value> {
        catch_panic("reading progressive evidence", || {
            let evidence = match self.inner.as_ref() {
                RealAudienceScopedResult::Assertion(verified) => verified.evidence(),
                RealAudienceScopedResult::Credential(verified) => verified.evidence(),
            };
            evidence_to_json(evidence).map_err(|error| to_napi_error(map_conversion_error(&error)))
        })
    }

    #[napi(getter)]
    pub fn trace_id(&self) -> Result<Option<String>> {
        catch_panic("reading progressive trace_id", || {
            Ok(match self.inner.as_ref() {
                RealAudienceScopedResult::Assertion(verified) => verified.trace_id(),
                RealAudienceScopedResult::Credential(verified) => verified.trace_id(),
            }
            .map(str::to_owned))
        })
    }

    #[napi(getter)]
    pub fn assertion(&self) -> Result<Option<Buffer>> {
        catch_panic("reading progressive assertion bytes", || {
            Ok(match self.inner.as_ref() {
                RealAudienceScopedResult::Assertion(verified) => {
                    Some(verified.assertion_bytes().to_vec().into())
                }
                RealAudienceScopedResult::Credential(_) => None,
            })
        })
    }

    #[napi(getter)]
    pub fn credential(&self) -> Result<Option<String>> {
        catch_panic("reading progressive credential", || {
            Ok(match self.inner.as_ref() {
                RealAudienceScopedResult::Assertion(_) => None,
                RealAudienceScopedResult::Credential(verified) => {
                    Some(verified.credential().to_owned())
                }
            })
        })
    }

    #[napi(getter)]
    pub fn values(&self) -> Result<serde_json::Value> {
        catch_panic("reading progressive values", || {
            let values = match self.inner.as_ref() {
                RealAudienceScopedResult::Assertion(verified) => verified.values(),
                RealAudienceScopedResult::Credential(verified) => verified.values(),
            };
            serde_json::to_value(values)
                .map_err(|error| to_napi_serialization_error("the verified values", error))
        })
    }

    #[napi(getter)]
    pub fn value(&self) -> Result<serde_json::Value> {
        catch_panic("reading the progressive value", || {
            let value = match self.inner.as_ref() {
                RealAudienceScopedResult::Assertion(verified) => verified.value(),
                RealAudienceScopedResult::Credential(verified) => verified.value(),
            }
            .map_err(|error| to_napi_error(map_client_error(&error)))?;
            serde_json::to_value(value)
                .map_err(|error| to_napi_serialization_error("the verified value", error))
        })
    }

    #[napi(getter)]
    pub fn subject_continuity(&self) -> Result<SubjectContinuity> {
        catch_panic("reading progressive subject continuity", || {
            let continuity = match self.inner.as_ref() {
                RealAudienceScopedResult::Assertion(verified) => verified.subject_continuity(),
                RealAudienceScopedResult::Credential(verified) => verified.subject_continuity(),
            };
            subject_continuity_to_napi(continuity)
        })
    }
}

/// A relying party's connection to one Evidence deployment.
#[napi]
pub struct EvidenceClient {
    inner: Arc<RealEvidenceClient>,
}

#[napi]
impl EvidenceClient {
    /// Build a client for one deployment. `trustedJwks` and `revokedKeyIds` are
    /// mandatory trust inputs. A key set or revoked-key list the verifier could
    /// never use is refused, exactly as the Rust configuration refuses it.
    ///
    /// `maxResponseBytes` bounds the signed response `send` reads.
    /// `maxMetadataBytes` bounds the documents `discover` and `fetchJwks` read,
    /// which are neither signed nor verified, and is a separate decision.
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

    /// Build the progressive client from an application-owned profile. An
    /// optional private JWK is an in-memory override for a secret-manager
    /// integration; it is parsed without ever rendering its contents in an
    /// error. Profile paths and file-backed secrets remain inside the core
    /// client and are likewise redacted there.
    #[napi(factory, ts_args_type = "path: string, privateKeyJwk?: any")]
    pub fn from_profile(path: String, private_key_jwk: Option<serde_json::Value>) -> Result<Self> {
        catch_panic("constructing the client from a profile", || {
            let path = PathBuf::from(path);
            let client = match private_key_jwk {
                Some(private_key_jwk) => {
                    let private_key: registry_platform_crypto::PrivateJwk =
                        serde_json::from_value(private_key_jwk).map_err(|_| {
                            to_napi_error(serde_json::json!({
                                "kind": "configuration",
                                "message": "`privateKeyJwk` must be a valid client private JWK",
                            }))
                        })?;
                    RealEvidenceClient::from_profile_path_with_key(path, private_key)
                }
                None => RealEvidenceClient::from_profile_path(path),
            }
            .map_err(|error| to_napi_error(map_client_error(&error)))?;
            Ok(Self {
                inner: Arc::new(client),
            })
        })
    }

    /// Close the expectations for one request and generate its nonce. No I/O
    /// happens here. The returned request is good for exactly one exchange:
    /// spend it with `send` or `requestAndVerify`.
    #[napi(
        ts_args_type = "spec: { responseFormat: 'signed-jws' | 'sd-jwt-vc'; [key: string]: any }"
    )]
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

    /// Close one independently nonce-bound policy for each positional item in
    /// a multi-subject request batch. No I/O happens here, and the returned
    /// opaque batch is good for exactly one exchange.
    #[napi(
        ts_args_type = "spec: { requirement: string; purpose: string; audience: string; evidenceType: string; issuedBy: string; providedBy: string; configurationRevision: string; expectedAssuranceProfile: any; expectedOutputs: ReadonlyArray<Readonly<Record<string, any>>>; maximumAssertionLifetimeSeconds: number; clockSkewSeconds: number; items: ReadonlyArray<{ subjects: ReadonlyArray<{ role: string; selectorProfile: string; selectorValues?: Readonly<Record<string, string | number | boolean>> | null }>; subjectExpectations: 'acceptFirstUse' | { pinned: ReadonlyArray<{ role: string; binding: string }> } }> }"
    )]
    pub fn prepare_batch(&self, spec: serde_json::Value) -> Result<PreparedEvidenceRequestBatch> {
        catch_panic("preparing a request batch", || {
            let spec = batch_spec_from_json(&spec)
                .map_err(|error| to_napi_error(map_conversion_error(&error)))?;
            let prepared = self
                .inner
                .prepare_batch(spec)
                .map_err(|error| to_napi_error(map_client_error(&error)))?;
            Ok(PreparedEvidenceRequestBatch {
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

    /// Refresh the profile's public metadata under the core client's bounded,
    /// single-flight cache policy. It never substitutes a response-time key
    /// refresh for the key snapshot closed before a request.
    #[napi(ts_return_type = "Promise<void>")]
    pub fn refresh_metadata<'env>(&self, env: &'env Env) -> Result<PromiseRaw<'env, ()>> {
        let client = Arc::clone(&self.inner);
        env.spawn_future(async move {
            client
                .refresh_metadata()
                .await
                .map_err(|error| to_napi_error(map_client_error(&error)))
        })
    }

    /// Discover, prepare, send exactly once, and verify one audience-scoped
    /// request. The request object intentionally accepts only explicit
    /// selectors or explicit role maps, and the Rust core owns all definition
    /// selection, metadata trust, receipt matching, and result construction.
    #[napi(ts_return_type = "Promise<AudienceScopedResult>")]
    pub fn request<'env>(
        &self,
        env: &'env Env,
        request: serde_json::Value,
    ) -> Result<PromiseRaw<'env, AudienceScopedResult>> {
        let request = audience_scoped_request_from_json(&request)
            .map_err(|error| to_napi_error(map_conversion_error(&error)))?;
        let client = Arc::clone(&self.inner);
        env.spawn_future(async move {
            let result = client
                .request(request)
                .await
                .map_err(|error| to_napi_error(map_client_error(&error)))?;
            audience_scoped_result_to_napi(&result)
        })
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

    /// Send one prepared request batch and read its unverified envelope. The
    /// same opaque prepared object cannot be sent twice.
    #[napi(ts_return_type = "Promise<RawEvidenceRequestBatchResponse>")]
    pub fn send_batch<'env>(
        &self,
        env: &'env Env,
        prepared: &PreparedEvidenceRequestBatch,
    ) -> Result<PromiseRaw<'env, RawEvidenceRequestBatchResponse>> {
        let client = Arc::clone(&self.inner);
        let prepared = Arc::clone(&prepared.inner);
        env.spawn_future(async move {
            client
                .send_batch(&prepared)
                .await
                .map(|response| RawEvidenceRequestBatchResponse {
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

    /// Atomically verify every available member against the policy at its own
    /// request position. No partial result is returned when one member fails.
    #[napi]
    pub fn verify_batch(
        &self,
        prepared: &PreparedEvidenceRequestBatch,
        response: &RawEvidenceRequestBatchResponse,
    ) -> Result<VerifiedEvidenceRequestBatch> {
        catch_panic("verifying a request batch response", || {
            let verified = self
                .inner
                .verify_batch(&prepared.inner, &response.inner)
                .map_err(|error| to_napi_error(map_client_error(&error)))?;
            verified_request_batch_to_napi(&verified)
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

    /// Send and atomically verify one prepared request batch in one step.
    #[napi(ts_return_type = "Promise<VerifiedEvidenceRequestBatch>")]
    pub fn request_and_verify_batch<'env>(
        &self,
        env: &'env Env,
        prepared: &PreparedEvidenceRequestBatch,
    ) -> Result<PromiseRaw<'env, VerifiedEvidenceRequestBatch>> {
        let client = Arc::clone(&self.inner);
        let prepared = Arc::clone(&prepared.inner);
        env.spawn_future(async move {
            let verified = client
                .request_and_verify_batch(&prepared)
                .await
                .map_err(|error| to_napi_error(map_client_error(&error)))?;
            verified_request_batch_to_napi(&verified)
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
            let now = datetime_from_unix_millis(as_of_millis)
                .map_err(|error| to_napi_error(map_conversion_error(&error)))?;
            let verified = self
                .inner
                .verify_as_of(&prepared.inner, &response.inner, now)
                .map_err(|error| to_napi_error(map_client_error(&error)))?;
            verified_evidence_to_napi(&verified)
        })
    }

    /// Atomically verify a retained request-batch envelope as of an explicit
    /// instant, in milliseconds since the Unix epoch.
    #[napi]
    pub fn verify_batch_as_of(
        &self,
        prepared: &PreparedEvidenceRequestBatch,
        response: &RawEvidenceRequestBatchResponse,
        as_of_millis: f64,
    ) -> Result<VerifiedEvidenceRequestBatch> {
        catch_panic(
            "verifying a request batch response as of an instant",
            || {
                let now = datetime_from_unix_millis(as_of_millis)
                    .map_err(|error| to_napi_error(map_conversion_error(&error)))?;
                let verified = self
                    .inner
                    .verify_batch_as_of(&prepared.inner, &response.inner, now)
                    .map_err(|error| to_napi_error(map_client_error(&error)))?;
                verified_request_batch_to_napi(&verified)
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ordinary_result_passes_through_catch_panic_unchanged() {
        let ok: Result<i32> = catch_panic("a synthetic trace_id", || Ok(42));
        assert_eq!(ok.unwrap(), 42);

        let err: Result<i32> = catch_panic("a synthetic trace_id", || {
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
        let result: Result<()> = catch_panic("a synthetic trace_id", || {
            panic!("a synthetic panic carrying a canary-value that must not surface")
        });
        std::panic::set_hook(previous_hook);

        let error = result.expect_err("the panic is caught and reported as an error");
        assert!(error.reason.contains("a synthetic trace_id"));
        assert!(error.reason.contains("failed unexpectedly"));
        assert!(
            !error.reason.contains("canary-value"),
            "the panic payload leaked into the reported reason: {}",
            error.reason
        );
    }
}
