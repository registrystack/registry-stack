//! Product-neutral host protocols over the bounded Adapter data channel.
//!
//! A protocol compiler validates digest-pinned public configuration during
//! pure pack compilation. A compiled protocol then prepares one fresh request
//! and one single-use response verifier for every physical HTTP attempt. Raw
//! response bytes never enter an Exchange or a script.

use std::any::Any;
use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use http::{HeaderName, HeaderValue};
use registry_adapter_core::{Endpoint, HostProtocol};
use registry_platform_yaml::LocalId;
use serde_json::Value;
use thiserror::Error;
use zeroize::Zeroizing;

mod problem;

pub use problem::ExactProblemClassifier;

const MAXIMUM_ACCESS_ATTRIBUTION_BYTES: usize = 512;

/// Verified caller context that an explicitly opted-in host protocol may add
/// to its own request. The values are never placed in an Exchange or exposed
/// to Rhai.
pub struct HostAccessAttribution {
    requester: Zeroizing<String>,
    purpose: Zeroizing<String>,
}

impl HostAccessAttribution {
    /// Validate and retain immutable access attribution for one acquisition.
    pub fn try_new(requester: &str, purpose: &str) -> Result<Self, HostProtocolError> {
        if !valid_attribution_member(requester) || !valid_attribution_member(purpose) {
            return Err(HostProtocolError);
        }
        Ok(Self {
            requester: Zeroizing::new(requester.to_owned()),
            purpose: Zeroizing::new(purpose.to_owned()),
        })
    }

    /// The authorized requester identity.
    #[must_use]
    pub fn requester(&self) -> &str {
        self.requester.as_str()
    }

    /// The authorized purpose of this acquisition.
    #[must_use]
    pub fn purpose(&self) -> &str {
        self.purpose.as_str()
    }
}

fn valid_attribution_member(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAXIMUM_ACCESS_ATTRIBUTION_BYTES
        && !value.chars().any(char::is_control)
}

/// A value-free host-protocol compilation, preparation, or verification
/// refusal. Product implementations retain their own diagnostic category and
/// never pass response, request, selector, key, or credential material back
/// to the route engine.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("the selected host protocol refused the operation")]
pub struct HostProtocolError;

/// A closed, value-free reason a prepared protocol refused an HTTP response.
/// The route engine may retain this category for its embedding host, but it
/// never retains response bytes, headers, status text, or arbitrary metadata.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum HostProtocolResponseRefusal {
    #[error("the selected host protocol refused the response shape")]
    Protocol,
    #[error("the selected host protocol could not verify the response")]
    Verification,
    #[error("the response did not match the declared not-found problem")]
    DeclaredNotFoundMismatch,
}

/// Compile one named protocol's exact digest-pinned public configuration.
pub trait HostProtocolCompiler: Send + Sync {
    /// The stable LocalId used by `endpoint.hostProtocol.id`.
    fn id(&self) -> &str;

    /// Validate the endpoint shape and exact configuration bytes without
    /// credentials, TLS material, runtime bindings, or network I/O.
    fn compile(
        &self,
        endpoint: &Endpoint,
        config: &[u8],
    ) -> Result<Arc<dyn CompiledHostProtocol>, HostProtocolError>;
}

/// A closed registry supplied by the embedding product at pure pack compile
/// time. Unknown IDs fail closed rather than falling back to ordinary JSON.
#[derive(Clone, Default)]
pub struct HostProtocolRegistry {
    compilers: Arc<BTreeMap<String, Arc<dyn HostProtocolCompiler>>>,
}

impl std::fmt::Debug for HostProtocolRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostProtocolRegistry")
            .field("ids", &self.compilers.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl HostProtocolRegistry {
    /// Freeze a registry after validating every compiler ID and refusing
    /// duplicates.
    pub fn try_new(
        compilers: impl IntoIterator<Item = Arc<dyn HostProtocolCompiler>>,
    ) -> Result<Self, HostProtocolError> {
        let mut by_id = BTreeMap::new();
        for compiler in compilers {
            let id = LocalId::new(compiler.id()).map_err(|_| HostProtocolError)?;
            if by_id.insert(id.as_str().to_owned(), compiler).is_some() {
                return Err(HostProtocolError);
            }
        }
        Ok(Self {
            compilers: Arc::new(by_id),
        })
    }

    pub(crate) fn compile(
        &self,
        declaration: &HostProtocol,
        endpoint: &Endpoint,
        config: &[u8],
    ) -> Result<Arc<dyn CompiledHostProtocol>, HostProtocolError> {
        self.compilers
            .get(declaration.id.as_str())
            .ok_or(HostProtocolError)?
            .compile(endpoint, config)
    }
}

/// A protocol whose public configuration and endpoint shape have already
/// passed product review.
pub trait CompiledHostProtocol: Send + Sync {
    /// Trusted request-header names owned by this built-in protocol. Pure
    /// compilation adds these to the endpoint's request-header allowlist in
    /// the frozen transport template, and every prepared attempt must supply
    /// the exact set. A script header of the same name is not an override:
    /// the outbound header filter refuses a name that appears twice.
    fn request_header_names(&self) -> &[HeaderName] {
        &[]
    }

    /// Response headers required by verification. The egress boundary copies
    /// only these names and still applies its ordinary count and size bounds.
    fn response_header_names(&self) -> &[HeaderName];

    /// Whether the embedding host must supply authorized requester and
    /// purpose context before this protocol can execute. Unselected and
    /// unreachable endpoints do not affect a compiled program.
    fn requires_access_attribution(&self) -> bool {
        false
    }

    /// Whether this reviewed protocol permits one OAuth credential-refresh
    /// resend after a 401 response. The default refuses a second physical
    /// read; enabling it still remains subject to the auth plan's one-retry
    /// limit and the shared acquisition operation budget.
    fn allows_credential_refresh_retry(&self) -> bool {
        false
    }

    /// Whether an offline fixture may record this protocol's response as a
    /// readable JSON `body` instead of exact `rawBodyBase64` bytes. Only a
    /// protocol that verifies no signature over the response bytes may allow
    /// it; the default keeps replay byte-exact.
    fn replays_readable_body(&self) -> bool {
        false
    }

    fn validates_request_headers(&self, headers: &[(HeaderName, HeaderValue)]) -> bool {
        let expected = self.request_header_names();
        expected.len() == headers.len()
            && expected
                .iter()
                .all(|name| headers.iter().filter(|(actual, _)| actual == name).count() == 1)
    }

    /// Prepare one physical attempt. Implementations draw a fresh nonce here,
    /// after the send hook and before credentials are attached.
    fn prepare_attempt(
        &self,
        request: HostProtocolRequestContext<'_>,
        attribution: Option<&HostAccessAttribution>,
        maximum_request_bytes: usize,
    ) -> Result<PreparedHostProtocolRequest, HostProtocolError>;
}

/// Closed HTTP method visible to a selected host protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostProtocolMethod {
    Get,
    Post,
}

/// The reviewed and rendered request shape supplied to one protocol attempt.
/// This type intentionally has no `Debug`: the body can contain minimized
/// subject selectors. It carries no credentials or response data.
pub struct HostProtocolRequestContext<'a> {
    method: HostProtocolMethod,
    path: &'a str,
    has_query: bool,
    body: Option<&'a Value>,
}

impl<'a> HostProtocolRequestContext<'a> {
    pub(crate) fn new(
        method: HostProtocolMethod,
        path: &'a str,
        has_query: bool,
        body: Option<&'a Value>,
    ) -> Self {
        Self {
            method,
            path,
            has_query,
            body,
        }
    }

    #[must_use]
    pub const fn method(&self) -> HostProtocolMethod {
        self.method
    }

    #[must_use]
    pub const fn path(&self) -> &str {
        self.path
    }

    #[must_use]
    pub const fn has_query(&self) -> bool {
        self.has_query
    }

    #[must_use]
    pub const fn body(&self) -> Option<&Value> {
        self.body
    }
}

/// One fresh request body and its single-use response verifier.
pub struct PreparedHostProtocolRequest {
    body: PreparedHostProtocolBody,
    headers: Vec<(HeaderName, HeaderValue)>,
    verifier: Option<Box<dyn HostProtocolResponseVerifier>>,
}

pub(crate) struct PreparedHostProtocolParts {
    pub body: PreparedHostProtocolBody,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub verifier: Option<Box<dyn HostProtocolResponseVerifier>>,
}

/// Whether the protocol preserves the route's actual request body or replaces
/// it with sealed protocol bytes.
pub enum PreparedHostProtocolBody {
    Unchanged,
    SealedBytes(Zeroizing<Vec<u8>>),
}

impl PreparedHostProtocolRequest {
    /// Construct one prepared attempt. Header and body bounds are enforced
    /// again by the ordinary fixed-destination request template.
    #[must_use]
    pub fn new(
        body: Zeroizing<Vec<u8>>,
        headers: Vec<(HeaderName, HeaderValue)>,
        verifier: Box<dyn HostProtocolResponseVerifier>,
    ) -> Self {
        Self {
            body: PreparedHostProtocolBody::SealedBytes(body),
            headers,
            verifier: Some(verifier),
        }
    }

    /// Preserve the route's actual method and body presence while adding only
    /// trusted protocol-owned headers. The ordinary JSON, media, status, and
    /// error pipeline remains in force and no raw response bytes are exposed.
    #[must_use]
    pub fn passthrough(headers: Vec<(HeaderName, HeaderValue)>) -> Self {
        Self {
            body: PreparedHostProtocolBody::Unchanged,
            headers,
            verifier: None,
        }
    }

    /// Preserve the route's actual method and body while verifying the exact
    /// bounded wire response before any JSON becomes script-visible.
    #[must_use]
    pub fn verified_passthrough(
        headers: Vec<(HeaderName, HeaderValue)>,
        verifier: Box<dyn HostProtocolResponseVerifier>,
    ) -> Self {
        Self {
            body: PreparedHostProtocolBody::Unchanged,
            headers,
            verifier: Some(verifier),
        }
    }

    pub(crate) fn into_parts(self) -> PreparedHostProtocolParts {
        PreparedHostProtocolParts {
            body: self.body,
            headers: self.headers,
            verifier: self.verifier,
        }
    }
}

/// Verify the exact sealed wire response for one prepared attempt.
pub trait HostProtocolResponseVerifier: Send {
    fn verify(
        self: Box<Self>,
        response: HostProtocolWireResponse,
    ) -> Result<VerifiedHostProtocolResponse, HostProtocolResponseRefusal>;
}

/// Exact bounded response data available only to the selected verifier.
pub struct HostProtocolWireResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Zeroizing<Vec<u8>>,
    evaluation_instant: DateTime<Utc>,
}

impl HostProtocolWireResponse {
    pub(crate) fn new(
        status: u16,
        headers: Vec<(String, String)>,
        body: Zeroizing<Vec<u8>>,
        evaluation_instant: DateTime<Utc>,
    ) -> Self {
        Self {
            status,
            headers,
            body,
            evaluation_instant,
        }
    }

    /// The instant the host fixed for this acquisition. A host protocol
    /// verifier judges freshness and expiry against it. The signed-source
    /// verifier in `registry-evidence` is the exception: it judges an upstream
    /// assertion at the wall clock when the response is verified, because this
    /// instant precedes the assertion's own issue time.
    #[must_use]
    pub const fn evaluation_instant(&self) -> DateTime<Utc> {
        self.evaluation_instant
    }

    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    #[must_use]
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// Borrow the exact bounded body without moving it out of the response.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        self.body.as_slice()
    }

    /// Consume the exact bounded body into the verifier's product-owned
    /// decoder. No borrow can escape without an explicit copy by that trusted
    /// built-in implementation.
    #[must_use]
    pub fn into_body(self) -> Zeroizing<Vec<u8>> {
        self.body
    }
}

/// Product-typed value a verifier hands to its embedding host. The engine
/// carries it by reference and never inspects, clones the contents of, or
/// serializes it; the host downcasts it to the type it expects.
pub type HostProtocolAttachment = Arc<dyn Any + Send + Sync>;

/// Verified script-visible JSON plus optional trusted protocol validity
/// metadata and an optional opaque host attachment. The validity string and
/// the attachment stay outside the Exchange.
pub struct VerifiedHostProtocolResponse {
    body: Value,
    valid_until: Option<String>,
    keep_response_headers: bool,
    attachment: Option<HostProtocolAttachment>,
}

/// The parts of a verified response the route consumes.
pub(crate) struct VerifiedHostProtocolParts {
    pub(crate) body: Value,
    pub(crate) valid_until: Option<String>,
    pub(crate) keep_response_headers: bool,
    pub(crate) attachment: Option<HostProtocolAttachment>,
}

impl VerifiedHostProtocolResponse {
    #[must_use]
    pub fn new(body: Value, valid_until: Option<String>) -> Self {
        Self {
            body,
            valid_until,
            keep_response_headers: true,
            attachment: None,
        }
    }

    /// Prevent ordinary endpoint response headers from entering the Exchange.
    /// Trusted protocol headers have already been consumed by the verifier.
    #[must_use]
    pub fn without_response_headers(mut self) -> Self {
        self.keep_response_headers = false;
        self
    }

    /// Attach a trusted, product-typed value for the embedding host. It is
    /// never placed in an Exchange or exposed to a script.
    #[must_use]
    pub fn with_attachment(mut self, attachment: HostProtocolAttachment) -> Self {
        self.attachment = Some(attachment);
        self
    }

    pub(crate) fn into_parts(self) -> VerifiedHostProtocolParts {
        VerifiedHostProtocolParts {
            body: self.body,
            valid_until: self.valid_until,
            keep_response_headers: self.keep_response_headers,
            attachment: self.attachment,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RefusingVerifier;

    impl HostProtocolResponseVerifier for RefusingVerifier {
        fn verify(
            self: Box<Self>,
            _response: HostProtocolWireResponse,
        ) -> Result<VerifiedHostProtocolResponse, HostProtocolResponseRefusal> {
            Err(HostProtocolResponseRefusal::Protocol)
        }
    }

    #[test]
    fn access_attribution_members_hold_the_exact_byte_bound() {
        let exact = "x".repeat(MAXIMUM_ACCESS_ATTRIBUTION_BYTES);
        assert!(HostAccessAttribution::try_new(&exact, &exact).is_ok());
        let above = "x".repeat(MAXIMUM_ACCESS_ATTRIBUTION_BYTES + 1);
        assert!(HostAccessAttribution::try_new(&above, "purpose").is_err());
        assert!(HostAccessAttribution::try_new("requester", &above).is_err());
    }

    #[test]
    fn access_attribution_refuses_blank_and_control_members() {
        for value in ["", "   ", "line\nbreak", "nul\0byte"] {
            assert!(HostAccessAttribution::try_new(value, "purpose").is_err());
            assert!(HostAccessAttribution::try_new("requester", value).is_err());
        }
    }

    #[test]
    fn verified_passthrough_retains_an_unchanged_body_and_verifier() {
        let prepared = PreparedHostProtocolRequest::verified_passthrough(
            vec![(
                HeaderName::from_static("x-protocol"),
                HeaderValue::from_static("fixed"),
            )],
            Box::new(RefusingVerifier),
        );
        let parts = prepared.into_parts();
        assert!(matches!(parts.body, PreparedHostProtocolBody::Unchanged));
        assert_eq!(parts.headers.len(), 1);
        assert!(parts.verifier.is_some());
    }

    #[test]
    fn verified_response_keeps_headers_by_default_and_can_suppress_them() {
        let parts = VerifiedHostProtocolResponse::new(Value::Null, None).into_parts();
        assert!(parts.keep_response_headers);
        assert!(parts.attachment.is_none());

        let parts = VerifiedHostProtocolResponse::new(Value::Null, None)
            .without_response_headers()
            .into_parts();
        assert!(!parts.keep_response_headers);
    }

    #[test]
    fn attachment_round_trips_untouched_and_keeps_the_other_parts() {
        let attachment: HostProtocolAttachment = Arc::new(String::from("opaque"));
        let parts = VerifiedHostProtocolResponse::new(Value::Bool(true), Some("v".to_owned()))
            .without_response_headers()
            .with_attachment(Arc::clone(&attachment))
            .into_parts();
        assert_eq!(parts.body, Value::Bool(true));
        assert_eq!(parts.valid_until.as_deref(), Some("v"));
        assert!(!parts.keep_response_headers);
        let carried = parts.attachment.expect("attachment carried");
        assert!(Arc::ptr_eq(&carried, &attachment));
        assert_eq!(
            carried.downcast_ref::<String>().map(String::as_str),
            Some("opaque")
        );
    }

    #[test]
    fn wire_response_exposes_the_injected_evaluation_instant() {
        let instant = DateTime::parse_from_rfc3339("2026-11-06T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let response =
            HostProtocolWireResponse::new(200, Vec::new(), Zeroizing::new(Vec::new()), instant);
        assert_eq!(response.evaluation_instant(), instant);
    }
}
