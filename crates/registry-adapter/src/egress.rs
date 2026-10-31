// SPDX-License-Identifier: Apache-2.0

//! The deployment's outbound egress state, built once at startup
//! (`products/adapter/CONCEPT.md` sections 8.11 and 10.2).
//!
//! Every endpoint binding is compiled exactly once, before any
//! exchange: the binding's base URL pins one origin ([`PinnedOrigin`]),
//! the origin freezes one fixed destination policy carrying the
//! deployment's private-CIDR allowlist and the binding's outbound TLS,
//! the declared header allowlists freeze one [`HeaderFilter`], the
//! declared authentication kind and the binding's credential freeze one
//! [`AuthPlan`], and the plan gets the endpoint's own outbound token
//! transport. The engine reuses this state for every exchange, so a
//! plan's token cache is the deployment's and a fresh exchange's
//! budget still hits it.
//!
//! One data send rides the frozen state: the target is parsed once
//! against the pinned origin and sent unchanged, only listed exchange
//! headers travel and the credential is injected after them, redirects
//! are never followed (a 3xx raises `upstream.redirect`), every
//! refusal the egress boundary raises is the uncatchable
//! `egress.refused`, and every failure inside an admitted exchange is
//! a catchable `upstream` class.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use registry_adapter_core::ErrorClass;
use registry_adapter_core::{
    AdapterRuntimeConfig, Cidr, CredentialPlacement, Endpoint, EndpointAuthentication,
    EndpointBinding, HttpMethod, RuntimeCredential, MAXIMUM_ATTEMPT_TIMEOUT_MILLISECONDS,
};
use registry_platform_config::SecretResolver;
use registry_platform_httputil::destination::json::decode_script_json;
use registry_platform_httputil::destination::{
    CredentialDestinationPolicy, CredentialDestinationRequestTemplate, DataDestinationPolicy,
    DataDestinationRequestTemplate, DestinationAuthorizationScheme,
    DestinationAuthorizationTemplate, DestinationAuthorizationValue, DestinationDeliveryCertainty,
    DestinationProfile, DestinationRequestError, DestinationResponseError,
    DestinationResponseHeaderError, DestinationSendError, DestinationTlsMaterialError,
    OAuth2ClientCredentialsBodyFormat, QueryStringContentAcknowledgement, ScriptRequestBodyFormat,
    SideEffectingSendMethod, MAX_DESTINATION_HEADER_VALUE_BYTES, MAX_DESTINATION_OPERATION_TIMEOUT,
    MAX_DESTINATION_REQUEST_BODY_BYTES, MAX_DESTINATION_REQUEST_HEADER_BYTES,
    MAX_DESTINATION_TARGET_BYTES,
};
use registry_platform_httputil::{TransportKind, MAXIMUM_TOKEN_RESPONSE_BYTES};
use registry_platform_yaml::{BoundedU64, ExternalId, SecretReference, Url};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::auth::{
    AuthError, AuthEvent, AuthHeader, AuthKind, AuthPlan, AuthPlanFault, AuthorizeContext,
    AuthorizedCredential, ClientAssertionSigner, EndpointTls, ProtectedText, TokenBudget,
    TokenClientAuthentication, TokenRequest, TokenSend, TokenWire, TransportFailure,
    MAXIMUM_TOKEN_REQUEST_BYTES,
};
use crate::component::http::header_filter::{
    AllowlistError, HeaderFilter, InboundHeaderError, OutboundHeaderError, OutboundHeaders,
    ResponseHeaders,
};
use crate::component::http::uri::{LinkRefusal, OriginError, PinnedLink, PinnedOrigin};
use crate::replay::{ReplayFailure, ReplayTranscript};

/// Stands in the authorize context for a token transport when an
/// endpoint compiled none: the load wires a real transport for every
/// plan that acquires a token, so no plan this context serves can
/// reach a token acquisition. If one ever did, the send refuses loudly
/// as a boundary refusal instead of pretending.
struct NoTokenSend;

impl TokenSend for NoTokenSend {
    fn send<'a>(
        &'a self,
        _request: &'a TokenRequest,
    ) -> Pin<Box<dyn Future<Output = Result<TokenWire, TransportFailure>> + Send + 'a>> {
        Box::pin(async {
            Err(TransportFailure::PolicyRefused {
                journal_name: "invalid-frozen-policy",
            })
        })
    }
}

const NO_TOKEN_SEND: NoTokenSend = NoTokenSend;

struct ReplayTokenSend<'a> {
    transcript: &'a ReplayTranscript,
    endpoint: &'a str,
    path: &'a str,
}

impl TokenSend for ReplayTokenSend<'_> {
    fn send<'a>(
        &'a self,
        _request: &'a TokenRequest,
    ) -> Pin<Box<dyn Future<Output = Result<TokenWire, TransportFailure>> + Send + 'a>> {
        Box::pin(async move {
            let response = self
                .transcript
                .answer_token(self.endpoint, HttpMethod::Post, self.path)
                .map_err(|_| TransportFailure::PolicyRefused {
                    journal_name: "fixture-replay-mismatch",
                })?;
            let media_type = response
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
                .map(|(_, value)| value.clone())
                .or_else(|| {
                    response
                        .body
                        .as_ref()
                        .map(|_| "application/json".to_owned())
                });
            let body = response
                .body
                .as_ref()
                .map(|body| serde_json::to_vec(body.as_value()))
                .transpose()
                .map_err(|_| TransportFailure::PolicyRefused {
                    journal_name: "fixture-replay-response",
                })?
                .unwrap_or_default();
            Ok(TokenWire {
                status: u16::try_from(response.status.get()).map_err(|_| {
                    TransportFailure::PolicyRefused {
                        journal_name: "fixture-replay-response",
                    }
                })?,
                media_type,
                body: Zeroizing::new(body),
            })
        })
    }
}

/// Why a deployment refuses to start, in egress terms. Every rendering
/// is fixed text; none carries a binding value or a credential.
#[derive(Debug)]
pub enum EgressFault {
    /// The compiled authentication plan or the binding's TLS resolution
    /// refused the pair.
    Auth(AuthError),
    /// A declared header allowlist is not usable.
    Allowlist(AllowlistError),
    /// The binding's base URL is not a pinnable origin.
    Origin(OriginError),
    /// The fixed destination policy refused the origin or the allowlist.
    Destination(DestinationPolicyFault),
    /// A frozen request template is not usable.
    Request(DestinationRequestError),
    /// The binding's configured TLS material was refused by the platform.
    DestinationTls(DestinationTlsMaterialError),
    /// The binding raises a limit above the one the pack declares; a
    /// binding may only lower it.
    LimitAboveDeclared {
        /// The key the binding wrote, `attemptTimeoutMilliseconds` or
        /// `maximumResponseBytes`.
        key: &'static str,
    },
    /// The endpoint binding at `position` names no declared endpoint.
    BindingUnmatched {
        /// The position of the binding in the runtime config.
        position: usize,
    },
    /// The fixture transcript cannot compile the endpoint's replay state.
    Replay(ReplayFailure),
}

/// The fixed-destination refusal the platform reports at load.
pub type DestinationPolicyFault = registry_platform_httputil::destination::DestinationPolicyError;

impl fmt::Display for EgressFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth(fault) => fault.fmt(formatter),
            Self::Allowlist(fault) => fmt::Display::fmt(fault, formatter),
            Self::Origin(fault) => fault.fmt(formatter),
            Self::Destination(fault) => fault.fmt(formatter),
            Self::Request(fault) => fault.fmt(formatter),
            Self::DestinationTls(fault) => fault.fmt(formatter),
            Self::LimitAboveDeclared { key } => write!(
                formatter,
                "the binding's {key} is above the pack's declared one; a binding may only lower it"
            ),
            Self::BindingUnmatched { position } => write!(
                formatter,
                "the endpoint binding at position {position} names no declared endpoint"
            ),
            Self::Replay(fault) => fault.fmt(formatter),
        }
    }
}

impl std::error::Error for EgressFault {}

/// Why one data send did not produce a reply.
#[derive(Debug)]
pub enum EgressError {
    /// The egress boundary refused the send: the uncatchable
    /// `egress.refused`.
    Refused(EgressRefusal),
    /// The admitted send failed against the upstream: a catchable
    /// `upstream` class, with the status and the reply body when the
    /// upstream produced one.
    Upstream(UpstreamFailure),
}

impl EgressError {
    /// The error class this send outcome raises.
    #[must_use]
    pub fn class(&self) -> ErrorClass {
        match self {
            Self::Refused(_) => ErrorClass::EgressRefused,
            Self::Upstream(failure) => failure.class,
        }
    }
}

impl fmt::Display for EgressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(refusal) => refusal.fmt(formatter),
            Self::Upstream(failure) => failure.fmt(formatter),
        }
    }
}

impl std::error::Error for EgressError {}

/// Why the egress boundary refused one send. Every rendering is fixed
/// text; none carries an exchange value or a credential.
#[derive(Debug)]
pub enum EgressRefusal {
    /// The send target broke a rule of the origin pin.
    Link(LinkRefusal),
    /// A listed exchange header held an invalid, over-long, or
    /// duplicated value.
    Header(OutboundHeaderError),
    /// The frozen request template refused the rendered request.
    Request(DestinationRequestError),
    /// The fixed destination policy refused the send before any byte
    /// left: the address, its resolution answer, the configured TLS,
    /// or the frozen policy itself. The refusal carries its static
    /// journal name, so the journal detail is this fixed word and no
    /// journal site ever renders the fault.
    Destination {
        /// The platform's own refusal.
        fault: DestinationSendError,
        /// The static journal name of the refusal, from the closed
        /// mapping.
        journal_name: &'static str,
    },
    /// The credential for the send is missing or not in the shape the
    /// destination authorization carries.
    Credential,
    /// The send's declared attempt timeout is above the maximum the
    /// platform accepts; the send refuses rather than the engine
    /// silently shortening what the operator declared.
    AttemptAboveMaximum,
    /// The outgoing send did not match the offline fixture transcript.
    Replay(ReplayFailure),
}

impl EgressRefusal {
    /// The error class a refusal raises: `egress.refused`, always.
    #[must_use]
    pub const fn class(&self) -> ErrorClass {
        ErrorClass::EgressRefused
    }

    /// The fixed journal word naming the kind of refusal. It carries no
    /// value from the link, the headers, or the credential.
    #[must_use]
    pub const fn journal_name(&self) -> &'static str {
        match self {
            Self::Link(LinkRefusal::TooLong) => "link-too-long",
            Self::Link(LinkRefusal::InvalidCharacter) => "link-invalid-character",
            Self::Link(LinkRefusal::NotAbsolute) => "link-not-absolute",
            Self::Link(LinkRefusal::Unparseable) => "link-unparseable",
            Self::Link(LinkRefusal::SchemeMismatch) => "link-scheme-mismatch",
            Self::Link(LinkRefusal::Userinfo) => "link-userinfo",
            Self::Link(LinkRefusal::HostMismatch) => "link-host-mismatch",
            Self::Link(LinkRefusal::PortMismatch) => "link-port-mismatch",
            Self::Link(LinkRefusal::Fragment) => "link-fragment",
            Self::Link(LinkRefusal::QueryNotAsWritten) => "link-query-not-as-written",
            Self::Link(LinkRefusal::NonCanonicalPath) => "link-non-canonical-path",
            Self::Link(LinkRefusal::OutsideBasePath) => "link-outside-base-path",
            Self::Header(_) => "header",
            Self::Request(_) => "request",
            Self::Destination { journal_name, .. } => journal_name,
            Self::Credential => "credential",
            Self::AttemptAboveMaximum => "attempt-above-maximum",
            Self::Replay(_) => "fixture-replay-mismatch",
        }
    }
}

impl fmt::Display for EgressRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Link(fault) => fault.fmt(formatter),
            Self::Header(fault) => fault.fmt(formatter),
            Self::Request(fault) => fault.fmt(formatter),
            Self::Destination { fault, .. } => fault.fmt(formatter),
            Self::Credential => {
                formatter.write_str("the send's credential is not in a transportable shape")
            }
            Self::AttemptAboveMaximum => formatter.write_str(
                "the declared attempt timeout is above the maximum the platform accepts",
            ),
            Self::Replay(fault) => fault.fmt(formatter),
        }
    }
}

/// One upstream failure inside an admitted exchange: a catchable
/// `upstream` class, the status when the upstream produced one, the
/// reply body when it was JSON within the bound, and whether the
/// request may have reached the destination.
pub struct UpstreamFailure {
    /// The catchable class the failure raises.
    pub class: ErrorClass,
    /// The upstream status, when a response arrived.
    pub status: Option<u16>,
    /// The reply body, decoded when it was strict JSON within the
    /// bound, so a clause can read a source's error detail.
    pub body: Option<Value>,
    /// Whether the request may have been delivered, so an operator
    /// reading the journal can tell a maybe-sent POST from one the
    /// destination never saw.
    pub certainty: DestinationDeliveryCertainty,
}

impl UpstreamFailure {
    fn new(
        class: ErrorClass,
        status: Option<u16>,
        body: Option<Value>,
        certainty: DestinationDeliveryCertainty,
    ) -> Self {
        Self {
            class,
            status,
            body,
            certainty,
        }
    }

    /// The static journal name of the failure's delivery certainty, a
    /// closed fact the journal event carries.
    #[must_use]
    pub fn certainty_journal_name(&self) -> &'static str {
        match self.certainty {
            DestinationDeliveryCertainty::MaybeSent => "maybe-sent",
            DestinationDeliveryCertainty::NotSent => "not-sent",
        }
    }
}

impl fmt::Debug for UpstreamFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpstreamFailure")
            .field("class", &self.class)
            .field("status", &self.status)
            .field("certainty", &self.certainty)
            .field("body", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for UpstreamFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "the upstream send failed: {}",
            self.class.class()
        )?;
        if let Some(status) = self.status {
            write!(formatter, " (status {status})")?;
        }
        write!(formatter, "; {}", self.certainty_journal_name())
    }
}

/// One send's reply: the status (always inside the reviewed range,
/// and outside it too when the send opted out of the throw), the
/// decoded body (an empty body is JSON null), and the declared response
/// headers present on the response.
pub struct SentReply {
    /// The upstream status.
    pub status: u16,
    /// The reply body; an empty body is JSON null.
    pub body: Value,
    /// The declared response headers present on the response.
    pub headers: ResponseHeaders,
}

impl fmt::Debug for SentReply {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SentReply")
            .field("status", &self.status)
            .field("body", &"[REDACTED]")
            .field(
                "headers",
                &self
                    .headers
                    .iter()
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// The shape one `http` send declares: a read travels in the query
/// string and carries no body; a side effect travels in the body. The
/// shape makes a body on a GET unrepresentable, and the frozen template
/// refuses a POST without a body.
#[derive(Debug)]
pub enum SendShape<'a> {
    /// A read; the send travels in the query string.
    Get,
    /// A side effect; the send travels in the body.
    Post(SendBody<'a>),
}

/// The body codec one POST send carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendBodyFormat {
    /// `application/json`.
    Json,
    /// `application/x-www-form-urlencoded`.
    Form,
}

/// The request body of one POST send.
pub struct SendBody<'a> {
    /// The body codec; the transport owns the content type.
    pub format: SendBodyFormat,
    /// The rendered body bytes.
    pub bytes: &'a [u8],
}

impl fmt::Debug for SendBody<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SendBody")
            .field("format", &self.format)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// The inclusive status-code ranges one reviewed HTTP send accepts.
///
/// Camel's `okStatusCodeRange` is a comma-separated list of single codes and
/// inclusive ranges. The route compiler parses that authored spelling once;
/// live and replay transports both use this value for exact sparse
/// membership. Redirects remain a separate unconditional refusal before this
/// set is consulted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OkStatusCodeRanges {
    ranges: Vec<(u16, u16)>,
}

impl OkStatusCodeRanges {
    /// Build the status set from inclusive ranges. The route compiler supplies
    /// these entries from the already bounded authored configuration string.
    pub fn try_from_ranges(ranges: Vec<(u16, u16)>) -> Result<Self, &'static str> {
        if ranges.is_empty() {
            return Err("at least one HTTP status range is required");
        }
        if ranges.iter().any(|(low, high)| {
            !(100..=599).contains(low) || !(100..=599).contains(high) || low > high
        }) {
            return Err("HTTP status ranges must be ordered within 100 through 599");
        }
        Ok(Self { ranges })
    }

    /// Whether one exact status belongs to any declared singleton or range.
    #[must_use]
    pub fn contains(&self, status: u16) -> bool {
        self.ranges
            .iter()
            .any(|(low, high)| (*low..=*high).contains(&status))
    }
}

impl Default for OkStatusCodeRanges {
    fn default() -> Self {
        Self {
            ranges: vec![(200, 299)],
        }
    }
}

/// What one `http` send carries to the egress boundary.
pub struct OutboundSend<'a> {
    /// The send's absolute target: the filled `path` under the
    /// endpoint's base URL, or the source's pinned `httpUri` link.
    /// Parsed once against the pinned origin and sent unchanged.
    pub link: &'a str,
    /// The exchange headers on this send; only listed names travel.
    pub exchange_headers: &'a [(String, String)],
    /// The shape the send declares: a GET without a body, or a POST
    /// with one.
    pub shape: SendShape<'a>,
    /// The credential [`EndpointEgress::authorize`] produced for this
    /// send, if the endpoint's kind produces one.
    pub authorization: Option<&'a AuthHeader>,
    /// The whole outbound attempt's deadline, from the endpoint's
    /// declared attempt timeout. The platform's one-operation ceiling is
    /// the same bound `attemptTimeoutMilliseconds` is checked against at
    /// authoring; a declared attempt above it is refused, never
    /// shortened.
    pub attempt: Duration,
    /// The response byte bound, from the endpoint's declared maximum.
    pub maximum_response_bytes: usize,
    /// The reviewed status ranges of the send's `to` step.
    pub ok_status_ranges: OkStatusCodeRanges,
    /// Whether the send raises on a status outside the range; the
    /// engine converts [`UpstreamFailure`]'s status and body.
    pub throw_exception_on_failure: bool,
}

impl fmt::Debug for OutboundSend<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundSend")
            .field("link", &self.link)
            .field(
                "exchange_headers",
                &self
                    .exchange_headers
                    .iter()
                    .map(|(name, _)| name.as_str())
                    .collect::<Vec<_>>(),
            )
            .field("shape", &self.shape)
            .field("authorization", &self.authorization.map(AuthHeader::name))
            .field("attempt", &self.attempt)
            .field("maximum_response_bytes", &self.maximum_response_bytes)
            .field("ok_status_ranges", &self.ok_status_ranges)
            .field(
                "throw_exception_on_failure",
                &self.throw_exception_on_failure,
            )
            .finish()
    }
}

/// The binding's limit when it lowers the declared one, the declared one
/// when the binding is silent; a binding above the declared limit is a
/// refusal, never a shortening.
fn lowered(declared: u64, bound: Option<u64>, key: &'static str) -> Result<u64, EgressFault> {
    match bound {
        Some(value) if value > declared => Err(EgressFault::LimitAboveDeclared { key }),
        Some(value) => Ok(value),
        None => Ok(declared),
    }
}

/// One endpoint's outbound state, compiled once at startup.
struct LiveTransport {
    policy: DataDestinationPolicy,
    get_template: DataDestinationRequestTemplate,
    post_template: DataDestinationRequestTemplate,
    token_send: Option<EndpointTokenSend>,
}

enum EndpointTransport {
    Live(Box<LiveTransport>),
    Replay(Arc<ReplayTranscript>),
}

pub struct EndpointEgress {
    endpoint: ExternalId,
    plan: AuthPlan,
    filter: HeaderFilter,
    origin: PinnedOrigin,
    request_allowlist: Vec<String>,
    authorization_scheme: Option<DestinationAuthorizationScheme>,
    attempt: Duration,
    maximum_response_bytes: usize,
    transport: EndpointTransport,
}

impl EndpointEgress {
    /// Compile one endpoint binding against its declared endpoint.
    pub(crate) fn compile(
        binding: &EndpointBinding,
        declared: &Endpoint,
        config: &AdapterRuntimeConfig,
        resolver: &SecretResolver,
    ) -> Result<Self, EgressFault> {
        let attempt_milliseconds = lowered(
            declared.attempt_timeout_milliseconds.get(),
            binding
                .attempt_timeout_milliseconds
                .map(|value| value.get()),
            "attemptTimeoutMilliseconds",
        )?;
        let maximum_response_bytes = lowered(
            declared.maximum_response_bytes.get(),
            binding.maximum_response_bytes.map(|value| value.get()),
            "maximumResponseBytes",
        )?;
        let plan = AuthPlan::compile(&declared.authentication, binding)
            .map_err(|fault| EgressFault::Auth(AuthError::Plan(fault)))?;
        let filter = HeaderFilter::for_endpoint(declared).map_err(EgressFault::Allowlist)?;
        let parsed_base = binding.base_url.to_url();
        let origin = PinnedOrigin::new(parsed_base.as_ref()).map_err(EgressFault::Origin)?;
        let tls = EndpointTls::resolve(binding, config, resolver).map_err(EgressFault::Auth)?;
        let materials = tls.into_materials();
        let policy = Self::freeze_policy(
            binding,
            &origin,
            &parsed_base,
            &config.allowed_private_cidrs,
            materials.data,
        )?;
        let request_allowlist: Vec<String> = declared
            .request_headers
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect();
        let request_names: Vec<&str> = request_allowlist.iter().map(String::as_str).collect();
        let (authorization, api_key, authorization_scheme) =
            authorization_slots(plan.declared_scheme(), &declared.authentication)
                .map_err(EgressFault::Request)?;
        let api_key_header = api_key.map(|name| (name, MAX_DESTINATION_HEADER_VALUE_BYTES));
        let path_rule = path_rule(&origin);
        let get_template = script_template(
            SideEffectingSendMethod::Get(
                QueryStringContentAcknowledgement::acknowledge_content_in_access_logs(),
            ),
            &path_rule,
            &request_names,
            authorization,
            api_key_header,
        )
        .map_err(EgressFault::Request)?;
        let post_template = script_template(
            SideEffectingSendMethod::Post,
            &path_rule,
            &request_names,
            authorization,
            api_key_header,
        )
        .map_err(EgressFault::Request)?;
        // The token transport freezes beside the data policy: a plan
        // that acquires a token gets its fixed token endpoint compiled
        // into a credential destination under the same profile
        // discipline, carrying the resolved token TLS material
        // fail-closed; a plan that acquires none compiles no transport,
        // and the resolved token material has no destination to install
        // it on and is dropped inside the freeze, never shared or
        // re-parsed.
        let token_send = freeze_token_send(
            binding,
            &plan,
            &config.allowed_private_cidrs,
            materials.token,
        )?;
        Ok(Self {
            endpoint: binding.endpoint.clone(),
            plan,
            filter,
            origin,
            request_allowlist,
            authorization_scheme,
            attempt: Duration::from_millis(attempt_milliseconds),
            maximum_response_bytes: usize::try_from(maximum_response_bytes).map_err(|_| {
                EgressFault::LimitAboveDeclared {
                    key: "maximumResponseBytes",
                }
            })?,
            transport: EndpointTransport::Live(Box::new(LiveTransport {
                policy,
                get_template,
                post_template,
                token_send,
            })),
        })
    }

    /// Compile one endpoint for offline fixture replay. The resulting state
    /// contains no destination policy, TLS material, request template, token
    /// transport, or credential resolver. The synthetic binding exists only
    /// to re-run the normal declared-kind validation and is never resolved or
    /// sent.
    pub fn compile_replay(
        declared: &Endpoint,
        transcript: Arc<ReplayTranscript>,
    ) -> Result<Self, EgressFault> {
        Self::compile_replay_with_max_cache(declared, transcript, 300)
    }

    fn compile_replay_with_max_cache(
        declared: &Endpoint,
        transcript: Arc<ReplayTranscript>,
        maximum_cache_seconds: u64,
    ) -> Result<Self, EgressFault> {
        let endpoint = ExternalId::new(declared.id.as_str())
            .expect("a local endpoint id is also an external id");
        let secret = || {
            SecretReference::new("secret:env/REGISTRY_ADAPTER_REPLAY_NEVER_RESOLVE")
                .expect("fixed replay secret reference")
        };
        let token_endpoint = || -> Result<Url, EgressFault> {
            let path = transcript
                .token_path(endpoint.as_str())
                .ok_or(EgressFault::Replay(ReplayFailure::TokenMissing))?;
            Url::new(format!("http://127.0.0.1{path}"))
                .map_err(|_| EgressFault::Replay(ReplayFailure::TokenMissing))
        };
        let credential = match &declared.authentication {
            EndpointAuthentication::None {} => RuntimeCredential::None {},
            EndpointAuthentication::Basic {} => RuntimeCredential::Basic {
                username_ref: secret(),
                password_ref: secret(),
            },
            EndpointAuthentication::StaticAuthorization { .. } => {
                RuntimeCredential::StaticAuthorization {
                    token_ref: secret(),
                }
            }
            EndpointAuthentication::StaticApiKey { .. } => RuntimeCredential::StaticApiKey {
                value_ref: secret(),
            },
            EndpointAuthentication::Oauth2ClientCredentials {} => {
                RuntimeCredential::Oauth2ClientCredentials {
                    token_endpoint: token_endpoint()?,
                    client_id_ref: secret(),
                    client_secret_ref: secret(),
                    scope: None,
                    audience: None,
                    resource: None,
                    credential_placement: CredentialPlacement::FormBody,
                    maximum_cache_seconds: BoundedU64::new(maximum_cache_seconds)
                        .expect("replay cache ceiling is in the runtime bound"),
                    assumed_lifetime_seconds: None,
                }
            }
            EndpointAuthentication::Oauth2PrivateKeyJwt {} => {
                RuntimeCredential::Oauth2PrivateKeyJwt {
                    token_endpoint: token_endpoint()?,
                    client_id_ref: secret(),
                    client_assertion_key_ref: secret(),
                    client_assertion_audience: None,
                    scope: None,
                    audience: None,
                    resource: None,
                    maximum_cache_seconds: BoundedU64::new(maximum_cache_seconds)
                        .expect("replay cache ceiling is in the runtime bound"),
                    assumed_lifetime_seconds: None,
                }
            }
        };
        let binding = EndpointBinding {
            endpoint: endpoint.clone(),
            base_url: Url::new("http://127.0.0.1").expect("fixed replay loopback URL"),
            credential: Some(credential),
            anonymous_https: None,
            attempt_timeout_milliseconds: None,
            maximum_response_bytes: None,
            tls_trust_profile: None,
            mtls_identity: None,
        };
        let plan = AuthPlan::compile(&declared.authentication, &binding)
            .map_err(|fault| EgressFault::Auth(AuthError::Plan(fault)))?;
        let filter = HeaderFilter::for_endpoint(declared).map_err(EgressFault::Allowlist)?;
        let origin = PinnedOrigin::new(binding.base_url.as_str()).map_err(EgressFault::Origin)?;
        let request_allowlist = declared
            .request_headers
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect();
        Ok(Self {
            endpoint,
            plan,
            filter,
            origin,
            request_allowlist,
            authorization_scheme: None,
            attempt: Duration::from_millis(declared.attempt_timeout_milliseconds.get()),
            maximum_response_bytes: usize::try_from(declared.maximum_response_bytes.get())
                .map_err(|_| EgressFault::LimitAboveDeclared {
                    key: "maximumResponseBytes",
                })?,
            transport: EndpointTransport::Replay(transcript),
        })
    }

    /// The longest one attempt to this endpoint may take: the pack's
    /// declared timeout, lowered by the binding when it says so.
    #[must_use]
    pub const fn attempt(&self) -> Duration {
        self.attempt
    }

    /// The largest response body one send to this endpoint may take in:
    /// the pack's declared bound, lowered by the binding when it says so.
    #[must_use]
    pub const fn maximum_response_bytes(&self) -> usize {
        self.maximum_response_bytes
    }

    /// Derive the destination profile from the pinned origin and freeze
    /// the fixed policy with the deployment's private-CIDR allowlist
    /// and the binding's data TLS material, installed fail-closed.
    fn freeze_policy(
        binding: &EndpointBinding,
        origin: &PinnedOrigin,
        parsed_base: &url::Url,
        cidrs: &[Cidr],
        material: Option<registry_platform_httputil::destination::DestinationTlsMaterial>,
    ) -> Result<DataDestinationPolicy, EgressFault> {
        let profile = destination_profile(parsed_base);
        let origin_id = binding.endpoint.as_str().to_ascii_lowercase();
        let networks: Vec<_> = cidrs.iter().map(Cidr::network).collect();
        let policy =
            DataDestinationPolicy::new(&origin_id, &origin.origin_url(), profile, &networks)
                .map_err(EgressFault::Destination)?;
        let Some(material) = material else {
            return Ok(policy);
        };
        let mut policy = policy.require_configured_tls();
        policy
            .install_configured_tls(material)
            .map_err(EgressFault::DestinationTls)?;
        Ok(policy)
    }

    /// The endpoint identifier.
    #[must_use]
    pub fn endpoint(&self) -> &ExternalId {
        &self.endpoint
    }

    /// The compiled authentication plan. One plan per endpoint binding,
    /// held for the deployment's life; its token cache is shared by
    /// every exchange.
    #[must_use]
    pub fn plan(&self) -> &AuthPlan {
        &self.plan
    }

    /// The endpoint's frozen header filter.
    #[must_use]
    pub fn filter(&self) -> &HeaderFilter {
        &self.filter
    }

    /// The pinned origin the data policy is derived from.
    #[must_use]
    pub fn origin(&self) -> &PinnedOrigin {
        &self.origin
    }

    /// The declared request-header allowlist, in declaration order.
    #[must_use]
    pub fn request_allowlist(&self) -> &[String] {
        &self.request_allowlist
    }

    /// The header material for one exchange, through the endpoint's own
    /// compiled plan: the static kinds resolve their secret, and a kind
    /// that holds no plan produces none. The returned credential names
    /// the cached generation it carries, so the 401 rule can clear
    /// exactly the issuance its send rode. A token acquisition rides
    /// the endpoint's own frozen token transport.
    ///
    /// # Errors
    ///
    /// [`AuthError`], the auth layer's own vocabulary.
    pub async fn authorize(
        &self,
        budget: &mut TokenBudget,
        resolver: &SecretResolver,
        signer: &dyn ClientAssertionSigner,
        events: &mut Vec<AuthEvent>,
    ) -> Result<Option<AuthorizedCredential>, AuthError> {
        if let EndpointTransport::Replay(transcript) = &self.transport {
            return self.authorize_replay(transcript, budget, events).await;
        }
        // The load wires the real transport for every plan that
        // acquires a token; the refuser stands in for a plan that holds
        // none, and refuses loudly if a token acquisition ever reached
        // it.
        let EndpointTransport::Live(live) = &self.transport else {
            unreachable!("replay transport returned above")
        };
        let send: &dyn TokenSend = match live.token_send.as_ref() {
            Some(send) => send,
            None => &NO_TOKEN_SEND,
        };
        let mut context = AuthorizeContext {
            resolver,
            budget,
            send,
            signer,
            events,
        };
        self.plan.authorize(&mut context).await
    }

    async fn authorize_replay(
        &self,
        transcript: &ReplayTranscript,
        budget: &mut TokenBudget,
        events: &mut Vec<AuthEvent>,
    ) -> Result<Option<AuthorizedCredential>, AuthError> {
        let synthetic = || ProtectedText::from_str_value("synthetic-fixture-credential");
        let header = match self.plan.kind() {
            AuthKind::None => return Ok(None),
            AuthKind::Basic | AuthKind::StaticAuthorization => {
                AuthHeader::new("authorization", synthetic())
            }
            AuthKind::StaticApiKey => {
                let Some(crate::auth::StaticCredential::ApiKey { header_name, .. }) =
                    self.plan.static_credential()
                else {
                    return Err(AuthError::Credential);
                };
                AuthHeader::new(header_name, synthetic())
            }
            AuthKind::Oauth2ClientCredentials | AuthKind::Oauth2PrivateKeyJwt => {
                let path = transcript
                    .token_path(self.endpoint.as_str())
                    .ok_or(AuthError::Credential)?;
                let send = ReplayTokenSend {
                    transcript,
                    endpoint: self.endpoint.as_str(),
                    path,
                };
                return self
                    .plan
                    .authorize_replay(transcript.auth_capability(), budget, &send, events)
                    .await
                    .map(Some);
            }
        };
        Ok(Some(AuthorizedCredential {
            header,
            generation: None,
        }))
    }

    /// Send one data request over the frozen state.
    ///
    /// # Errors
    ///
    /// [`EgressError::Refused`] for every send the egress boundary
    /// refuses, [`EgressError::Upstream`] for every failure inside an
    /// admitted exchange.
    pub async fn send(&self, send: OutboundSend<'_>) -> Result<SentReply, EgressError> {
        // A declared attempt above the ceiling the authoring check
        // bounds `attemptTimeoutMilliseconds` with is refused, never
        // shortened (`products/adapter/CONCEPT.md` section 8.8).
        if send.attempt > Duration::from_millis(MAXIMUM_ATTEMPT_TIMEOUT_MILLISECONDS) {
            return Err(EgressError::Refused(EgressRefusal::AttemptAboveMaximum));
        }
        let outbound = self
            .filter
            .outbound(
                send.exchange_headers
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str())),
            )
            .map_err(EgressRefusal::Header)
            .map_err(EgressError::Refused)?;
        let link = self
            .origin
            .pin(send.link)
            .map_err(EgressRefusal::Link)
            .map_err(EgressError::Refused)?;

        if let EndpointTransport::Replay(transcript) = &self.transport {
            return self.send_replay(transcript, &send, &outbound, &link);
        }
        let EndpointTransport::Live(live) = &self.transport else {
            unreachable!("replay transport returned above")
        };

        let (authorization, api_key) = self
            .credential_slots(send.authorization)
            .map_err(EgressError::Refused)?;
        let (template, body_format, body) = match &send.shape {
            SendShape::Get => (&live.get_template, None, None),
            SendShape::Post(body) => {
                let format = match body.format {
                    SendBodyFormat::Json => ScriptRequestBodyFormat::Json,
                    SendBodyFormat::Form => ScriptRequestBodyFormat::Form,
                };
                (
                    &live.post_template,
                    Some(format),
                    Some(Zeroizing::new(body.bytes.to_vec())),
                )
            }
        };
        let header_values: Vec<(&str, &[u8])> = outbound
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_bytes()))
            .collect();
        let rendered = template
            .render_script(
                link.target(),
                &header_values,
                authorization,
                api_key,
                body_format,
                body,
            )
            .map_err(EgressRefusal::Request)
            .map_err(EgressError::Refused)?;

        let reply = live
            .policy
            .send(rendered, send.attempt)
            .await
            .map_err(destination_send_outcome)?;

        let status = reply.status().as_u16();
        if (300..400).contains(&status) {
            // A redirect is never followed: the answer raises
            // `upstream.redirect` whatever the reviewed range says, and
            // the response is dropped unread.
            return Err(EgressError::Upstream(UpstreamFailure::new(
                ErrorClass::UpstreamRedirect,
                Some(status),
                None,
                DestinationDeliveryCertainty::MaybeSent,
            )));
        }

        let selected = reply
            .selected_script_response_headers(self.filter.response_header_names())
            .map_err(|fault| upstream_header_outcome(&fault, status))?;
        let copied: Vec<(String, String)> = self
            .filter
            .response_header_names()
            .zip(selected)
            .filter_map(|(name, value)| value.map(|value| (name.to_owned(), value)))
            .collect();
        let headers = self.filter.inbound(copied).map_err(|fault| {
            EgressError::Upstream(UpstreamFailure::new(
                inbound_header_outcome(&fault),
                Some(status),
                None,
                DestinationDeliveryCertainty::MaybeSent,
            ))
        })?;

        let body = reply
            .read_bounded(send.maximum_response_bytes)
            .await
            .map_err(|fault| {
                EgressError::Upstream(UpstreamFailure::new(
                    response_body_outcome(&fault),
                    Some(status),
                    None,
                    DestinationDeliveryCertainty::MaybeSent,
                ))
            })?;

        let out_of_range = !send.ok_status_ranges.contains(status);
        // An empty body is JSON null; a non-JSON body raises
        // `upstream.malformed`, also under `throwExceptionOnFailure:
        // false` (`products/adapter/CONCEPT.md` section 8.11). Only an
        // out-of-range status under the throw flag answers
        // `upstream.http` without a decoded body, because the route is
        // ending anyway and the body never decoded.
        let decoded = if body.is_empty() {
            Value::Null
        } else {
            match decode_script_json(body) {
                Ok(decoded) => decoded.into_parts().0,
                Err(_) => {
                    return Err(EgressError::Upstream(UpstreamFailure::new(
                        if out_of_range && send.throw_exception_on_failure {
                            ErrorClass::UpstreamHttp
                        } else {
                            ErrorClass::UpstreamMalformed
                        },
                        Some(status),
                        None,
                        DestinationDeliveryCertainty::MaybeSent,
                    )));
                }
            }
        };

        // Under the throw flag an out-of-range status raises
        // `upstream.http` carrying the decoded body; under
        // `throwExceptionOnFailure: false` the reply returns as it is
        // and the route reads the status itself (CONCEPT 8.11).
        if out_of_range && send.throw_exception_on_failure {
            return Err(EgressError::Upstream(UpstreamFailure::new(
                ErrorClass::UpstreamHttp,
                Some(status),
                Some(decoded),
                DestinationDeliveryCertainty::MaybeSent,
            )));
        }
        Ok(SentReply {
            status,
            body: decoded,
            headers,
        })
    }

    fn send_replay(
        &self,
        transcript: &ReplayTranscript,
        send: &OutboundSend<'_>,
        outbound: &OutboundHeaders,
        link: &PinnedLink,
    ) -> Result<SentReply, EgressError> {
        let (method, body) = match &send.shape {
            SendShape::Get => (HttpMethod::Get, None),
            SendShape::Post(body) => {
                let value = match body.format {
                    SendBodyFormat::Json => serde_json::from_slice(body.bytes).map_err(|_| {
                        EgressError::Refused(EgressRefusal::Replay(ReplayFailure::Send(
                            registry_adapter_core::ReplayMismatch::BodyDigest,
                        )))
                    })?,
                    SendBodyFormat::Form => {
                        let mut object = serde_json::Map::new();
                        for (name, value) in url::form_urlencoded::parse(body.bytes) {
                            object.insert(name.into_owned(), Value::String(value.into_owned()));
                        }
                        Value::Object(object)
                    }
                };
                (HttpMethod::Post, Some(value))
            }
        };
        let headers: Vec<(&str, &str)> = outbound
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str(),
                    value
                        .to_str()
                        .expect("the outbound filter admits visible ASCII only"),
                )
            })
            .collect();
        let response = transcript
            .answer_data(
                self.endpoint.as_str(),
                method,
                link.as_url().path(),
                link.as_url().query(),
                body.as_ref(),
                &headers,
            )
            .map_err(EgressRefusal::Replay)
            .map_err(EgressError::Refused)?;
        let status = u16::try_from(response.status.get())
            .expect("a recorded status is bounded to an HTTP status");
        if (300..400).contains(&status) {
            return Err(EgressError::Upstream(UpstreamFailure::new(
                ErrorClass::UpstreamRedirect,
                Some(status),
                None,
                DestinationDeliveryCertainty::NotSent,
            )));
        }
        let headers = self
            .filter
            .inbound(
                response
                    .headers
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_bytes())),
            )
            .map_err(|fault| {
                EgressError::Upstream(UpstreamFailure::new(
                    inbound_header_outcome(&fault),
                    Some(status),
                    None,
                    DestinationDeliveryCertainty::NotSent,
                ))
            })?;
        let body = match response.body {
            Some(body) => {
                let encoded = serde_json::to_vec(body.as_value()).map_err(|_| {
                    EgressError::Upstream(UpstreamFailure::new(
                        ErrorClass::UpstreamMalformed,
                        Some(status),
                        None,
                        DestinationDeliveryCertainty::NotSent,
                    ))
                })?;
                if encoded.len() > send.maximum_response_bytes {
                    return Err(EgressError::Upstream(UpstreamFailure::new(
                        ErrorClass::UpstreamTooLarge,
                        Some(status),
                        None,
                        DestinationDeliveryCertainty::NotSent,
                    )));
                }
                body.0
            }
            None => Value::Null,
        };
        if send.throw_exception_on_failure && !send.ok_status_ranges.contains(status) {
            return Err(EgressError::Upstream(UpstreamFailure::new(
                ErrorClass::UpstreamHttp,
                Some(status),
                Some(body),
                DestinationDeliveryCertainty::NotSent,
            )));
        }
        Ok(SentReply {
            status,
            body,
            headers,
        })
    }

    /// Build the destination authorization's slots from the produced
    /// credential: the injected authorization slot for the kinds that
    /// speak one, the API-key slot for the declared header. The plan's
    /// kind and its declared scheme decide the prefix, so the header's
    /// payload is never parsed for a scheme; the platform appends both
    /// slots after the exchange's selected headers, so no exchange entry
    /// can shadow a credential.
    fn credential_slots(
        &self,
        authorization: Option<&AuthHeader>,
    ) -> Result<CredentialSlots, EgressRefusal> {
        let header = match (self.plan.kind(), authorization) {
            (AuthKind::None, _) => return Ok((None, None)),
            (AuthKind::StaticApiKey, Some(header)) => {
                return Ok((
                    None,
                    Some(Zeroizing::new(header.value().as_bytes().to_vec())),
                ));
            }
            (_, None) => return Err(EgressRefusal::Credential),
            (_, Some(header)) => header,
        };
        let payload = header.value().as_bytes();
        let value = match self.plan.kind() {
            // An OAuth2 kind presents the bearer credential its token
            // acquisition produced and the plan's cache holds.
            AuthKind::Oauth2ClientCredentials | AuthKind::Oauth2PrivateKeyJwt => {
                DestinationAuthorizationValue::bearer(payload.to_vec())
            }
            AuthKind::Basic => DestinationAuthorizationValue::basic(payload.to_vec()),
            AuthKind::StaticAuthorization => {
                let scheme = self.authorization_scheme.ok_or(EgressRefusal::Credential)?;
                DestinationAuthorizationValue::scheme_zeroizing(
                    scheme,
                    Zeroizing::new(payload.to_vec()),
                )
            }
            _ => return Err(EgressRefusal::Credential),
        };
        let value = value.map_err(|_| EgressRefusal::Credential)?;
        Ok((Some(value), None))
    }
}

/// The destination authorization's two credential slots: the injected
/// authorization value, and the API-key bytes.
type CredentialSlots = (
    Option<DestinationAuthorizationValue>,
    Option<Zeroizing<Vec<u8>>>,
);

/// The authorization and API-key slots a template freezes, from the
/// declared authentication kind and the plan's declared scheme. The
/// scheme is declared configuration: a static authorization freezes its
/// own scheme into the destination authorization, whatever scheme the
/// operator declared, and a produced header never carries one to parse.
/// `Err` when the declared scheme is not 1 to 32 HTTP token bytes, the
/// bound the platform's declared-scheme template carries.
fn authorization_slots<'a>(
    declared_scheme: Option<&'a str>,
    authentication: &'a EndpointAuthentication,
) -> Result<
    (
        DestinationAuthorizationTemplate,
        Option<&'a str>,
        Option<DestinationAuthorizationScheme>,
    ),
    DestinationRequestError,
> {
    let maximum = MAX_DESTINATION_HEADER_VALUE_BYTES;
    match authentication {
        EndpointAuthentication::None {} => {
            Ok((DestinationAuthorizationTemplate::Forbidden, None, None))
        }
        EndpointAuthentication::Basic {} => Ok((
            DestinationAuthorizationTemplate::Basic {
                max_value_bytes: maximum,
            },
            None,
            None,
        )),
        EndpointAuthentication::Oauth2ClientCredentials {}
        | EndpointAuthentication::Oauth2PrivateKeyJwt {} => Ok((
            DestinationAuthorizationTemplate::Bearer {
                max_value_bytes: maximum,
            },
            None,
            None,
        )),
        EndpointAuthentication::StaticAuthorization { .. } => {
            let scheme = declared_scheme.ok_or(DestinationRequestError::InvalidAuthorization)?;
            let frozen = DestinationAuthorizationScheme::new(scheme)?;
            Ok((
                DestinationAuthorizationTemplate::Scheme {
                    scheme: frozen,
                    max_value_bytes: maximum,
                },
                None,
                Some(frozen),
            ))
        }
        EndpointAuthentication::StaticApiKey { header_name } => Ok((
            DestinationAuthorizationTemplate::Forbidden,
            Some(header_name.as_str()),
            None,
        )),
    }
}

/// The wildcard path rule under the pinned origin's base path: every
/// target the origin pin admits is one the template accepts.
fn path_rule(origin: &PinnedOrigin) -> String {
    let base_path = origin.base_path();
    if base_path.is_empty() {
        "/**".to_owned()
    } else {
        format!("{base_path}/**")
    }
}

/// Freeze one script template: GET and POST share the declared
/// allowlists and authorization slots, and the target bound is the
/// platform's, as Messaging's provider takes it.
fn script_template(
    method: SideEffectingSendMethod,
    path_rule: &str,
    request_headers: &[&str],
    authorization: DestinationAuthorizationTemplate,
    api_key_header: Option<(&str, usize)>,
) -> Result<DataDestinationRequestTemplate, DestinationRequestError> {
    DataDestinationRequestTemplate::new_script_send(
        method,
        path_rule,
        request_headers,
        authorization,
        api_key_header,
        None,
        MAX_DESTINATION_TARGET_BYTES
            + MAX_DESTINATION_REQUEST_HEADER_BYTES
            + MAX_DESTINATION_REQUEST_BODY_BYTES,
    )
}

/// The destination profile one pinned origin freezes: HTTPS carries the
/// production address controls; plain HTTP is development on loopback
/// and one private service hop everywhere else. Under the postgres-test
/// feature an https loopback origin takes the platform's pinned
/// loopback test profile, so the TLS suites can drive the same
/// frozen-policy send against a locally terminated certificate; a
/// build without the feature serves the same origin as production.
pub(crate) fn destination_profile(parsed_base: &url::Url) -> DestinationProfile {
    #[cfg(feature = "postgres-test")]
    if parsed_base.scheme() == "https" && denotes_loopback(parsed_base) {
        return DestinationProfile::PinnedLoopbackHttpsTest;
    }
    match parsed_base.scheme() {
        "https" => DestinationProfile::ProductionHttps,
        _ if denotes_loopback(parsed_base) => DestinationProfile::LoopbackDevelopmentHttp,
        _ => DestinationProfile::PrivateServiceHttp,
    }
}

/// Whether the origin's host explicitly denotes loopback: the name
/// `localhost` or a loopback address literal, the platform's own
/// admission rule for the development profile.
pub(crate) fn denotes_loopback(origin: &url::Url) -> bool {
    match origin.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

/// Whether a destination profile admits a token endpoint: the same
/// profiles the data path serves, decided by the same predicate the
/// plan-level compile applies, so a load refusal and the frozen
/// credential policy can never disagree about one endpoint. Plain HTTP
/// stays development-only loopback, the private service hop never
/// carries a credential request, and the pinned loopback test profile
/// is admitted only under the feature that enables it.
pub(crate) fn profile_admits_token_endpoints(profile: DestinationProfile) -> bool {
    match profile {
        DestinationProfile::ProductionHttps | DestinationProfile::LoopbackDevelopmentHttp => true,
        #[cfg(feature = "postgres-test")]
        DestinationProfile::PinnedLoopbackHttpsTest => true,
        _ => false,
    }
}

/// One endpoint's wired token transport, compiled once at startup: the
/// frozen credential destination policy, the frozen request template,
/// and the origin and path the plan's fixed token endpoint names. Every
/// send renders the plan's one request shape and hands it to the frozen
/// policy, so the endpoint's token requests ride exactly the address
/// controls, TLS trust, and bounds its data requests ride.
struct EndpointTokenSend {
    policy: CredentialDestinationPolicy,
    template: CredentialDestinationRequestTemplate,
    origin: url::Url,
    path: String,
}

impl TokenSend for EndpointTokenSend {
    fn send<'a>(
        &'a self,
        request: &'a TokenRequest,
    ) -> Pin<Box<dyn Future<Output = Result<TokenWire, TransportFailure>> + Send + 'a>> {
        Box::pin(self.send_bounded(request))
    }
}

impl EndpointTokenSend {
    /// Send one rendered token request through the frozen credential
    /// destination. The inner deadline is the platform's one-operation
    /// ceiling; the auth layer's own send ceiling wraps this send, so a
    /// `TokenSend` without a working timeout cannot wedge the
    /// endpoint's single-flight window past it.
    async fn send_bounded(&self, request: &TokenRequest) -> Result<TokenWire, TransportFailure> {
        // The request this transport serves is the plan's own render:
        // its destination is the frozen origin and path, exactly. A
        // request for anything else is a programming fault, refused as
        // a frozen-shape violation, never sent.
        let refused = || TransportFailure::PolicyRefused {
            journal_name: "invalid-frozen-request",
        };
        let parsed = url::Url::parse(&request.url).map_err(|_| refused())?;
        if parsed.origin() != self.origin.origin() || parsed.path() != self.path {
            return Err(refused());
        }
        let authorization = match &request.authentication {
            TokenClientAuthentication::None => None,
            TokenClientAuthentication::BasicHeader { payload } => {
                // The platform's destination authorization owns the
                // `Basic ` prefix and appends it at render time; the
                // payload here travels without one.
                Some(
                    DestinationAuthorizationValue::basic(payload.as_bytes().to_vec())
                        .map_err(|_| refused())?,
                )
            }
        };
        let rendered = self
            .template
            .render_zeroizing(
                &[],
                &[],
                authorization,
                Some(Zeroizing::new(request.body.as_bytes().to_vec())),
            )
            .map_err(|_| refused())?;

        let reply = self
            .policy
            .send(rendered, MAX_DESTINATION_OPERATION_TIMEOUT)
            .await
            .map_err(token_send_failure)?;

        let status = reply.status().as_u16();
        if (300..400).contains(&status) {
            // A redirect is never followed: the token endpoint is a
            // fixed destination, never one a response derives. The
            // answer states the status and carries no body to read.
            return Ok(TokenWire {
                status,
                media_type: None,
                body: Zeroizing::new(Vec::new()),
            });
        }
        let media_type =
            match reply.selected_script_response_headers(std::iter::once("content-type")) {
                Ok(selected) => selected.into_iter().flatten().next(),
                Err(_) => return Err(TransportFailure::HeadUnusable),
            };
        let body = reply
            .read_bounded(MAXIMUM_TOKEN_RESPONSE_BYTES as usize)
            .await
            .map_err(token_body_failure)?;
        Ok(TokenWire {
            status,
            media_type,
            body: body.into_credential_bytes(),
        })
    }
}

/// Freeze one endpoint's token transport beside the data policy: the
/// plan's fixed token endpoint derives its own credential destination
/// under the same profile discipline the data origin takes, carrying
/// the resolved token TLS material fail-closed, and the request
/// template is one of the platform's reviewed client-credentials
/// shapes, the Basic placement riding the reviewed authorization slot
/// and every other placement riding the body alone. A plan that
/// acquires no token compiles no transport.
fn freeze_token_send(
    binding: &EndpointBinding,
    plan: &AuthPlan,
    cidrs: &[Cidr],
    material: Option<registry_platform_httputil::destination::DestinationTlsMaterial>,
) -> Result<Option<EndpointTokenSend>, EgressFault> {
    let Some(token_plan) = plan.token_plan() else {
        return Ok(None);
    };
    // The plan-level compile already refused an endpoint this profile
    // discipline does not admit; the re-check is the runtime side of
    // the authoring checks, failing closed.
    let refused_plan = || EgressFault::Auth(AuthError::Plan(AuthPlanFault::TokenEndpointNotUsable));
    let parsed = url::Url::parse(token_plan.url()).map_err(|_| refused_plan())?;
    let profile = destination_profile(&parsed);
    if !profile_admits_token_endpoints(profile) {
        return Err(refused_plan());
    }
    // The token endpoint is a fixed credential destination: its origin
    // is the endpoint the policy pins, its fixed path is the path the
    // declared endpoint carries. Clearing the parts the pin refuses
    // keeps the frozen origin exact.
    let mut origin = parsed.clone();
    origin.set_path("");
    origin.set_query(None);
    origin.set_fragment(None);
    let path = parsed.path().to_owned();
    let origin_id = binding.endpoint.as_str().to_ascii_lowercase();
    let networks: Vec<_> = cidrs.iter().map(Cidr::network).collect();
    let policy = CredentialDestinationPolicy::new(&origin_id, origin.as_str(), profile, &networks)
        .map_err(EgressFault::Destination)?;
    let policy = if let Some(material) = material {
        // The load-time resolution already refused a plain token
        // destination; this re-check keeps the freeze fail-closed the
        // same way when reached without that resolution, instead of
        // installing material a plain destination never uses.
        if parsed.scheme() != "https" {
            return Err(EgressFault::Auth(AuthError::Tls(
                crate::auth::TlsFault::PlainDestination,
            )));
        }
        let mut policy = policy.require_configured_tls();
        policy
            .install_configured_tls(material)
            .map_err(EgressFault::DestinationTls)?;
        policy
    } else {
        policy
    };
    let template = if token_plan.authenticates_by_basic_header() {
        CredentialDestinationRequestTemplate::oauth2_client_credentials_form_basic(
            &path,
            MAX_DESTINATION_HEADER_VALUE_BYTES,
            MAXIMUM_TOKEN_REQUEST_BYTES,
            MAX_DESTINATION_TARGET_BYTES
                + MAX_DESTINATION_REQUEST_HEADER_BYTES
                + MAXIMUM_TOKEN_REQUEST_BYTES,
        )
    } else {
        CredentialDestinationRequestTemplate::oauth2_client_credentials(
            &path,
            OAuth2ClientCredentialsBodyFormat::FormClientSecretBody,
            MAXIMUM_TOKEN_REQUEST_BYTES,
            MAX_DESTINATION_TARGET_BYTES
                + MAX_DESTINATION_REQUEST_HEADER_BYTES
                + MAXIMUM_TOKEN_REQUEST_BYTES,
        )
    }
    .map_err(EgressFault::Request)?;
    Ok(Some(EndpointTokenSend {
        policy,
        template,
        origin,
        path,
    }))
}

/// Where one platform send outcome lands on the token path: the one
/// partition, projected onto the token layer's transport vocabulary.
/// The same platform fault lands on the same catchable class on both
/// paths, and every boundary refusal arrives as the uncatchable policy
/// refusal carrying the same closed journal name the data path
/// journals.
fn token_send_failure(fault: DestinationSendError) -> TransportFailure {
    match partition_send_fault(fault) {
        SendFaultClass::ResolutionUnanswered
        | SendFaultClass::DeadlineBeforeConnect
        | SendFaultClass::ConnectFailed => TransportFailure::Transport(TransportKind::Connect),
        SendFaultClass::DeadlineAfterConnect => TransportFailure::Transport(TransportKind::Timeout),
        SendFaultClass::ExchangeFailed => TransportFailure::Transport(TransportKind::Exchange),
        SendFaultClass::ResponseHeadUnusable => TransportFailure::HeadUnusable,
        SendFaultClass::ResponseHeadOverBound => {
            TransportFailure::Transport(TransportKind::ResponseTooLarge)
        }
        SendFaultClass::Refused(fault) => TransportFailure::PolicyRefused {
            journal_name: destination_refusal_name(&fault),
        },
    }
}

/// Where one bounded body-read failure lands on the token path: the
/// same classes the data path raises for the same outcomes.
fn token_body_failure(fault: DestinationResponseError) -> TransportFailure {
    match fault {
        DestinationResponseError::BodyLimitTooHigh | DestinationResponseError::BodyTooLarge => {
            TransportFailure::Transport(TransportKind::ResponseTooLarge)
        }
        DestinationResponseError::BodyReadFailed => {
            TransportFailure::Transport(TransportKind::Exchange)
        }
        DestinationResponseError::DeadlineExceeded => {
            TransportFailure::Transport(TransportKind::Timeout)
        }
    }
}

/// The one partition of every platform send outcome, shared by the
/// data path and the token path: the same fault classifies the same
/// way on both, so the two paths can never disagree about what
/// happened to a send. Everything outside the catchable classes is
/// carried in [`SendFaultClass::Refused`] untouched, and both paths
/// report it as their own uncatchable refusal.
pub(crate) enum SendFaultClass {
    /// Resolution failed or returned no answers: the destination was
    /// never reached.
    ResolutionUnanswered,
    /// The deadline passed before the connection was established.
    DeadlineBeforeConnect,
    /// The deadline passed after the connection was established, while
    /// the request was being written or its response awaited.
    DeadlineAfterConnect,
    /// The connection failed before it was established.
    ConnectFailed,
    /// The connection failed after it was established, while the
    /// request was being written or its response awaited.
    ExchangeFailed,
    /// The upstream's response head was unusable: too many headers.
    ResponseHeadUnusable,
    /// The upstream's response head exceeded the platform bound.
    ResponseHeadOverBound,
    /// The frozen boundary refused the send before any byte left; the
    /// fault rides for the refusal's own rendering and journal name.
    Refused(DestinationSendError),
}

/// The one partition over [`DestinationSendError`]. Only resolution
/// failure, a missing resolver answer, the two deadline stages, the two
/// transport stages, and the two response-head faults are catchable;
/// every boundary refusal (the address policy, the resolver
/// programming checks, the configured TLS, the client build) stays in
/// [`SendFaultClass::Refused`] on both paths.
pub(crate) fn partition_send_fault(fault: DestinationSendError) -> SendFaultClass {
    match fault {
        DestinationSendError::ResolutionFailed | DestinationSendError::NoResolverAnswers => {
            SendFaultClass::ResolutionUnanswered
        }
        DestinationSendError::DeadlineExceeded => SendFaultClass::DeadlineBeforeConnect,
        DestinationSendError::DeadlineExceededAfterConnect => SendFaultClass::DeadlineAfterConnect,
        DestinationSendError::TransportFailed => SendFaultClass::ConnectFailed,
        DestinationSendError::TransportFailedAfterConnect => SendFaultClass::ExchangeFailed,
        DestinationSendError::TooManyResponseHeaders => SendFaultClass::ResponseHeadUnusable,
        DestinationSendError::ResponseHeaderBytesExceeded => SendFaultClass::ResponseHeadOverBound,
        fault => SendFaultClass::Refused(fault),
    }
}

/// Where one transport outcome lands on the data path: every refusal
/// the frozen boundary raises before or around the send is the
/// uncatchable `egress.refused`; the resolution and connect/exchange
/// stages are the catchable `upstream.connection`, a post-connect
/// deadline is `upstream.timeout`, an unusable head is
/// `upstream.malformed`, and an over-bound head is `upstream.too-large`.
/// Each failure carries its delivery certainty from the platform's own
/// classification, so the journal can tell a maybe-sent POST from a
/// request the destination never saw.
fn destination_send_outcome(fault: DestinationSendError) -> EgressError {
    let failure = |class, certainty| {
        EgressError::Upstream(UpstreamFailure::new(class, None, None, certainty))
    };
    match partition_send_fault(fault) {
        SendFaultClass::ResolutionUnanswered
        | SendFaultClass::DeadlineBeforeConnect
        | SendFaultClass::ConnectFailed => failure(
            ErrorClass::UpstreamConnection,
            DestinationDeliveryCertainty::NotSent,
        ),
        SendFaultClass::ExchangeFailed => failure(
            ErrorClass::UpstreamConnection,
            DestinationDeliveryCertainty::MaybeSent,
        ),
        SendFaultClass::DeadlineAfterConnect => failure(
            ErrorClass::UpstreamTimeout,
            DestinationDeliveryCertainty::MaybeSent,
        ),
        SendFaultClass::ResponseHeadUnusable => failure(
            ErrorClass::UpstreamMalformed,
            DestinationDeliveryCertainty::MaybeSent,
        ),
        SendFaultClass::ResponseHeadOverBound => failure(
            ErrorClass::UpstreamTooLarge,
            DestinationDeliveryCertainty::MaybeSent,
        ),
        SendFaultClass::Refused(fault) => EgressError::Refused(EgressRefusal::Destination {
            journal_name: destination_refusal_name(&fault),
            fault,
        }),
    }
}

/// The static journal name of one send refusal, from the closed
/// mapping over the platform's variants. The journal never renders a
/// refusal through its `Display` or any input-derived text: the name
/// is one fixed string per variant, so a marker secret can never ride
/// an egress refusal into the journal.
pub(crate) fn destination_refusal_name(fault: &DestinationSendError) -> &'static str {
    match fault {
        DestinationSendError::InvalidRemainingTimeout => "invalid-remaining-timeout",
        DestinationSendError::InvalidFrozenPolicy => "invalid-frozen-policy",
        DestinationSendError::InvalidFrozenRequest => "invalid-frozen-request",
        DestinationSendError::ResolutionFailed => "resolution-failed",
        DestinationSendError::ResolutionCapacityUnavailable => "resolution-capacity-unavailable",
        DestinationSendError::TooManyResolverAnswers => "too-many-resolver-answers",
        DestinationSendError::NoResolverAnswers => "no-resolver-answers",
        DestinationSendError::ResolverPortMismatch => "resolver-port-mismatch",
        DestinationSendError::ResolverAddressFamilyMismatch => "resolver-address-family-mismatch",
        DestinationSendError::LiteralOriginMismatch => "literal-origin-mismatch",
        DestinationSendError::CloudMetadataDenied => "cloud-metadata-denied",
        DestinationSendError::AlwaysDeniedAddress => "always-denied-address",
        DestinationSendError::PrivateAddressNotAllowed => "private-address-not-allowed",
        DestinationSendError::NonGlobalAddressDenied => "non-global-address-denied",
        DestinationSendError::DevelopmentAddressDenied => "development-address-denied",
        DestinationSendError::TlsMaterialUnavailable => "tls-material-unavailable",
        DestinationSendError::ClientBuildFailed => "client-build-failed",
        DestinationSendError::DeadlineExceeded => "deadline-exceeded",
        DestinationSendError::TransportFailed => "transport-failed",
        DestinationSendError::DeadlineExceededAfterConnect => "deadline-exceeded-after-connect",
        DestinationSendError::TransportFailedAfterConnect => "transport-failed-after-connect",
        DestinationSendError::TooManyResponseHeaders => "too-many-response-headers",
        DestinationSendError::ResponseHeaderBytesExceeded => "response-header-bytes-exceeded",
    }
}

/// Where one declared-response-header selection failure lands: the
/// upstream sent a field the engine cannot copy, `upstream.malformed`.
fn upstream_header_outcome(_fault: &DestinationResponseHeaderError, status: u16) -> EgressError {
    EgressError::Upstream(UpstreamFailure::new(
        ErrorClass::UpstreamMalformed,
        Some(status),
        None,
        DestinationDeliveryCertainty::MaybeSent,
    ))
}

/// Where one copied-response-header failure lands, by the filter's own
/// classification.
fn inbound_header_outcome(fault: &InboundHeaderError) -> ErrorClass {
    fault.class()
}

/// Where one bounded body-read failure lands.
fn response_body_outcome(fault: &DestinationResponseError) -> ErrorClass {
    match fault {
        DestinationResponseError::BodyLimitTooHigh | DestinationResponseError::BodyTooLarge => {
            ErrorClass::UpstreamTooLarge
        }
        DestinationResponseError::BodyReadFailed => ErrorClass::UpstreamConnection,
        DestinationResponseError::DeadlineExceeded => ErrorClass::UpstreamTimeout,
    }
}

/// The deployment's outbound egress state: one compiled entry per bound
/// endpoint, built once at startup.
pub struct Egress {
    endpoints: Vec<EndpointEgress>,
}

impl Egress {
    /// Compile the deployment's outbound state, one entry per bound
    /// endpoint, before any exchange. Loading sends nothing: a plan's
    /// token endpoint sees no request until an exchange asks for a
    /// credential.
    ///
    /// # Errors
    ///
    /// [`EgressFault`], the first refusal met, in binding order.
    pub fn load(
        endpoints: &[Endpoint],
        config: &AdapterRuntimeConfig,
        resolver: &SecretResolver,
    ) -> Result<Self, EgressFault> {
        let mut compiled = Vec::with_capacity(config.endpoints.len());
        for (position, binding) in config.endpoints.iter().enumerate() {
            let declared = endpoints
                .iter()
                .find(|endpoint| endpoint.id.as_str() == binding.endpoint.as_str())
                .ok_or(EgressFault::BindingUnmatched { position })?;
            compiled.push(EndpointEgress::compile(
                binding, declared, config, resolver,
            )?);
        }
        Ok(Self {
            endpoints: compiled,
        })
    }

    /// The compiled state of one bound endpoint.
    #[must_use]
    pub fn endpoint(&self, id: &str) -> Option<&EndpointEgress> {
        self.endpoints
            .iter()
            .find(|entry| entry.endpoint.as_str() == id)
    }

    /// How many endpoints compiled.
    #[must_use]
    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    /// Whether no endpoint compiled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    /// The compiled entries, in binding order.
    pub fn iter(&self) -> impl Iterator<Item = &EndpointEgress> {
        self.endpoints.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::UpstreamStatusAction;

    struct ReplayTestSigner;

    impl ClientAssertionSigner for ReplayTestSigner {
        fn sign_client_assertion(
            &self,
            _request: crate::auth::ClientAssertion<'_>,
        ) -> Result<ProtectedText, AuthError> {
            panic!("replay authorization must never sign a client assertion")
        }
    }

    fn replay_oauth_endpoint() -> Endpoint {
        serde_json::from_value(serde_json::json!({
            "id": "api",
            "component": "http",
            "authentication": {"type": "oauth2-client-credentials"},
            "attemptTimeoutMilliseconds": 1000,
            "maximumResponseBytes": 4096
        }))
        .expect("replay test endpoint")
    }

    fn replay_fixture(exchanges: serde_json::Value) -> registry_adapter_core::AdapterFixture {
        serde_json::from_value(serde_json::json!({
            "id": "oauth-cache-replay",
            "pack": "test-pack",
            "upstreamVersion": "1",
            "provenance": {"type": "documented", "reference": "unit test"},
            "intercepts": [
                {"type": "endpoint", "endpoint": "api"},
                {"type": "token-endpoint", "endpoint": "api"}
            ],
            "entries": [{
                "facadeRequest": {"operation": "read", "path": "/records"},
                "upstream": exchanges,
                "expected": {"type": "response", "status": 200}
            }]
        }))
        .expect("replay test fixture")
    }

    fn replay_token_exchange(token: &str) -> serde_json::Value {
        serde_json::json!({
            "request": {
                "endpoint": "api",
                "tokenRequest": true,
                "method": "POST",
                "path": "/oauth/token"
            },
            "response": {
                "status": 200,
                "body": {
                    "access_token": token,
                    "token_type": "Bearer",
                    "expires_in": 300
                }
            }
        })
    }

    fn replay_data_exchange(path: &str, status: u16) -> serde_json::Value {
        serde_json::json!({
            "request": {"endpoint": "api", "method": "GET", "path": path},
            "response": {"status": status, "body": {"ok": true}}
        })
    }

    fn replay_resolver() -> SecretResolver {
        SecretResolver::new(
            [registry_platform_config::SecretProvider::File],
            "/registry-adapter-replay-test-no-secrets",
        )
        .expect("inert replay resolver")
    }

    async fn replay_get(
        egress: &EndpointEgress,
        path: &str,
        credential: &AuthorizedCredential,
    ) -> Result<SentReply, EgressError> {
        let link = format!("http://127.0.0.1{path}");
        egress
            .send(OutboundSend {
                link: &link,
                exchange_headers: &[],
                shape: SendShape::Get,
                authorization: Some(&credential.header),
                attempt: Duration::from_secs(1),
                maximum_response_bytes: 4096,
                ok_status_ranges: OkStatusCodeRanges::default(),
                throw_exception_on_failure: false,
            })
            .await
    }

    #[tokio::test]
    async fn replay_oauth_reuses_one_cached_token_across_two_data_sends() {
        let fixture = replay_fixture(serde_json::json!([
            replay_token_exchange("first-token"),
            replay_data_exchange("/one", 200),
            replay_data_exchange("/two", 200)
        ]));
        let transcript =
            Arc::new(ReplayTranscript::new(&fixture, 0).expect("ordered replay transcript"));
        let egress =
            EndpointEgress::compile_replay(&replay_oauth_endpoint(), Arc::clone(&transcript))
                .expect("replay egress");
        let mut budget = TokenBudget::new_exchange();
        let mut events = Vec::new();
        let resolver = replay_resolver();

        let first = egress
            .authorize(&mut budget, &resolver, &ReplayTestSigner, &mut events)
            .await
            .expect("first authorization")
            .expect("OAuth credential");
        replay_get(&egress, "/one", &first)
            .await
            .expect("first data answer");
        let second = egress
            .authorize(&mut budget, &resolver, &ReplayTestSigner, &mut events)
            .await
            .expect("second authorization")
            .expect("cached OAuth credential");
        replay_get(&egress, "/two", &second)
            .await
            .expect("second data answer");

        assert!(first.generation.is_some());
        assert_eq!(first.generation, second.generation);
        assert_eq!(budget.remaining(egress.endpoint()), 1);
        assert_eq!(
            events,
            vec![
                AuthEvent::TokenRequested,
                AuthEvent::TokenIssued,
                AuthEvent::TokenCacheHit
            ]
        );
        assert_eq!(transcript.finish(), Ok(()));
    }

    #[tokio::test]
    async fn replay_oauth_unauthorized_invalidates_and_refreshes_the_sent_generation() {
        let fixture = replay_fixture(serde_json::json!([
            replay_token_exchange("first-token"),
            replay_data_exchange("/record", 401),
            replay_token_exchange("refreshed-token"),
            replay_data_exchange("/record", 200)
        ]));
        let transcript =
            Arc::new(ReplayTranscript::new(&fixture, 0).expect("ordered replay transcript"));
        let egress =
            EndpointEgress::compile_replay(&replay_oauth_endpoint(), Arc::clone(&transcript))
                .expect("replay egress");
        let mut budget = TokenBudget::new_exchange();
        let mut events = Vec::new();
        let resolver = replay_resolver();
        let mut refresh_used = false;

        let first = egress
            .authorize(&mut budget, &resolver, &ReplayTestSigner, &mut events)
            .await
            .expect("first authorization")
            .expect("OAuth credential");
        let unauthorized = replay_get(&egress, "/record", &first)
            .await
            .expect("401 answer is returned under the no-throw test send");
        assert_eq!(unauthorized.status, 401);
        assert_eq!(
            egress
                .plan()
                .on_upstream_status(401, first.generation, &mut refresh_used, &mut events,)
                .await,
            UpstreamStatusAction::RetryWithFreshCredential
        );
        let refreshed = egress
            .authorize(&mut budget, &resolver, &ReplayTestSigner, &mut events)
            .await
            .expect("refreshed authorization")
            .expect("refreshed OAuth credential");
        let accepted = replay_get(&egress, "/record", &refreshed)
            .await
            .expect("refreshed data answer");

        assert_eq!(accepted.status, 200);
        assert_ne!(first.generation, refreshed.generation);
        assert_eq!(budget.remaining(egress.endpoint()), 0);
        assert_eq!(
            events,
            vec![
                AuthEvent::TokenRequested,
                AuthEvent::TokenIssued,
                AuthEvent::TokenInvalidatedAfterUnauthorized,
                AuthEvent::TokenRequested,
                AuthEvent::TokenIssued
            ]
        );
        assert_eq!(transcript.finish(), Ok(()));
    }

    #[tokio::test]
    async fn replay_oauth_budget_refuses_a_third_uncached_token_before_consuming_it() {
        let fixture = replay_fixture(serde_json::json!([
            replay_token_exchange("first-token"),
            replay_token_exchange("second-token"),
            replay_token_exchange("must-not-be-consumed")
        ]));
        let transcript =
            Arc::new(ReplayTranscript::new(&fixture, 0).expect("ordered replay transcript"));
        let egress = EndpointEgress::compile_replay_with_max_cache(
            &replay_oauth_endpoint(),
            Arc::clone(&transcript),
            0,
        )
        .expect("replay egress");
        let mut budget = TokenBudget::new_exchange();
        let mut events = Vec::new();
        let resolver = replay_resolver();

        for _ in 0..2 {
            let credential = egress
                .authorize(&mut budget, &resolver, &ReplayTestSigner, &mut events)
                .await
                .expect("allowance remains")
                .expect("uncached OAuth credential");
            assert_eq!(credential.generation, None);
        }
        assert_eq!(
            egress
                .authorize(&mut budget, &resolver, &ReplayTestSigner, &mut events)
                .await
                .expect_err("the third token miss exceeds the exchange allowance"),
            AuthError::BudgetExhausted
        );

        assert_eq!(budget.remaining(egress.endpoint()), 0);
        assert_eq!(
            events,
            vec![
                AuthEvent::TokenRequested,
                AuthEvent::TokenIssued,
                AuthEvent::TokenRequested,
                AuthEvent::TokenIssued,
                AuthEvent::TokenBudgetExhausted
            ]
        );
        assert_eq!(transcript.finish(), Err(ReplayFailure::Leftover));
    }

    /// Every platform send fault, all unit variants, in declaration
    /// order: the partition table below is asserted over the complete
    /// list, so a variant the platform adds breaks this test at the
    /// array's length instead of silently passing. The const array
    /// itself does not refuse anything; the compile-breaking checks are
    /// the partition's exhaustive match (a new variant lands in the
    /// refusal arm and is caught by this table) and the closed journal
    /// name mapping, whose non-exhaustive match refuses to compile.
    const EVERY_SEND_FAULT: [DestinationSendError; 23] = [
        DestinationSendError::InvalidRemainingTimeout,
        DestinationSendError::InvalidFrozenPolicy,
        DestinationSendError::InvalidFrozenRequest,
        DestinationSendError::ResolutionFailed,
        DestinationSendError::ResolutionCapacityUnavailable,
        DestinationSendError::TooManyResolverAnswers,
        DestinationSendError::NoResolverAnswers,
        DestinationSendError::ResolverPortMismatch,
        DestinationSendError::ResolverAddressFamilyMismatch,
        DestinationSendError::LiteralOriginMismatch,
        DestinationSendError::CloudMetadataDenied,
        DestinationSendError::AlwaysDeniedAddress,
        DestinationSendError::PrivateAddressNotAllowed,
        DestinationSendError::NonGlobalAddressDenied,
        DestinationSendError::DevelopmentAddressDenied,
        DestinationSendError::TlsMaterialUnavailable,
        DestinationSendError::ClientBuildFailed,
        DestinationSendError::DeadlineExceeded,
        DestinationSendError::TransportFailed,
        DestinationSendError::DeadlineExceededAfterConnect,
        DestinationSendError::TransportFailedAfterConnect,
        DestinationSendError::TooManyResponseHeaders,
        DestinationSendError::ResponseHeaderBytesExceeded,
    ];

    /// The one partition classifies every platform send fault on the
    /// data path: the catchable stages raise their upstream classes,
    /// the boundary refusals (the address policy, the resolver
    /// programming checks, the configured TLS, the client build, the
    /// frozen-shape checks) raise the uncatchable refusal, and no
    /// variant is unaccounted for. The token path projects this same
    /// partition when the token send unit wires it; no second copy.
    #[test]
    fn the_one_partition_classifies_every_send_fault() {
        // The data class and delivery certainty each partition class
        // raises; only an established connection is ever maybe-sent.
        let outcome = |fault: &DestinationSendError| match destination_send_outcome(*fault) {
            EgressError::Upstream(failure) => (failure.class, failure.certainty),
            // A refusal never left the boundary; the platform's own
            // classification says the same.
            EgressError::Refused(_) => (ErrorClass::EgressRefused, fault.delivery_certainty()),
        };
        let expected: [(
            &DestinationSendError,
            ErrorClass,
            DestinationDeliveryCertainty,
        ); 23] = [
            (
                &DestinationSendError::InvalidRemainingTimeout,
                ErrorClass::EgressRefused,
                DestinationDeliveryCertainty::NotSent,
            ),
            (
                &DestinationSendError::InvalidFrozenPolicy,
                ErrorClass::EgressRefused,
                DestinationDeliveryCertainty::NotSent,
            ),
            (
                &DestinationSendError::InvalidFrozenRequest,
                ErrorClass::EgressRefused,
                DestinationDeliveryCertainty::NotSent,
            ),
            (
                &DestinationSendError::ResolutionFailed,
                ErrorClass::UpstreamConnection,
                DestinationDeliveryCertainty::NotSent,
            ),
            (
                &DestinationSendError::ResolutionCapacityUnavailable,
                ErrorClass::EgressRefused,
                DestinationDeliveryCertainty::NotSent,
            ),
            (
                &DestinationSendError::TooManyResolverAnswers,
                ErrorClass::EgressRefused,
                DestinationDeliveryCertainty::NotSent,
            ),
            (
                &DestinationSendError::NoResolverAnswers,
                ErrorClass::UpstreamConnection,
                DestinationDeliveryCertainty::NotSent,
            ),
            (
                &DestinationSendError::ResolverPortMismatch,
                ErrorClass::EgressRefused,
                DestinationDeliveryCertainty::NotSent,
            ),
            (
                &DestinationSendError::ResolverAddressFamilyMismatch,
                ErrorClass::EgressRefused,
                DestinationDeliveryCertainty::NotSent,
            ),
            (
                &DestinationSendError::LiteralOriginMismatch,
                ErrorClass::EgressRefused,
                DestinationDeliveryCertainty::NotSent,
            ),
            (
                &DestinationSendError::CloudMetadataDenied,
                ErrorClass::EgressRefused,
                DestinationDeliveryCertainty::NotSent,
            ),
            (
                &DestinationSendError::AlwaysDeniedAddress,
                ErrorClass::EgressRefused,
                DestinationDeliveryCertainty::NotSent,
            ),
            (
                &DestinationSendError::PrivateAddressNotAllowed,
                ErrorClass::EgressRefused,
                DestinationDeliveryCertainty::NotSent,
            ),
            (
                &DestinationSendError::NonGlobalAddressDenied,
                ErrorClass::EgressRefused,
                DestinationDeliveryCertainty::NotSent,
            ),
            (
                &DestinationSendError::DevelopmentAddressDenied,
                ErrorClass::EgressRefused,
                DestinationDeliveryCertainty::NotSent,
            ),
            (
                &DestinationSendError::TlsMaterialUnavailable,
                ErrorClass::EgressRefused,
                DestinationDeliveryCertainty::NotSent,
            ),
            (
                &DestinationSendError::ClientBuildFailed,
                ErrorClass::EgressRefused,
                DestinationDeliveryCertainty::NotSent,
            ),
            (
                &DestinationSendError::DeadlineExceeded,
                ErrorClass::UpstreamConnection,
                DestinationDeliveryCertainty::NotSent,
            ),
            (
                &DestinationSendError::TransportFailed,
                ErrorClass::UpstreamConnection,
                DestinationDeliveryCertainty::NotSent,
            ),
            (
                &DestinationSendError::DeadlineExceededAfterConnect,
                ErrorClass::UpstreamTimeout,
                DestinationDeliveryCertainty::MaybeSent,
            ),
            (
                &DestinationSendError::TransportFailedAfterConnect,
                ErrorClass::UpstreamConnection,
                DestinationDeliveryCertainty::MaybeSent,
            ),
            (
                &DestinationSendError::TooManyResponseHeaders,
                ErrorClass::UpstreamMalformed,
                DestinationDeliveryCertainty::MaybeSent,
            ),
            (
                &DestinationSendError::ResponseHeaderBytesExceeded,
                ErrorClass::UpstreamTooLarge,
                DestinationDeliveryCertainty::MaybeSent,
            ),
        ];
        for (fault, class, certainty) in expected {
            let (actual_class, actual_certainty) = outcome(fault);
            assert_eq!(actual_class, class, "{fault:?} on the data path");
            assert_eq!(
                actual_certainty, certainty,
                "{fault:?}'s delivery certainty"
            );
        }
        // The partition's refusal arm carries the fault untouched, so
        // the journal name is available on the refusal path.
        for fault in &EVERY_SEND_FAULT {
            let name = destination_refusal_name(fault);
            assert!(
                !name.is_empty() && name.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                "{fault:?}'s journal name {name} is a fixed kebab-case word"
            );
        }
    }

    /// The journal names are the exact closed mapping: the refusal's
    /// static name is asserted verbatim for every variant, and a marker
    /// secret never appears in any name.
    #[test]
    fn refusal_journal_names_are_the_closed_mapping() {
        const MARKER: &str = "c4b-marker-9f31ab";
        let names = [
            (
                destination_refusal_name(&DestinationSendError::InvalidRemainingTimeout),
                "invalid-remaining-timeout",
            ),
            (
                destination_refusal_name(&DestinationSendError::InvalidFrozenPolicy),
                "invalid-frozen-policy",
            ),
            (
                destination_refusal_name(&DestinationSendError::InvalidFrozenRequest),
                "invalid-frozen-request",
            ),
            (
                destination_refusal_name(&DestinationSendError::ResolutionFailed),
                "resolution-failed",
            ),
            (
                destination_refusal_name(&DestinationSendError::ResolutionCapacityUnavailable),
                "resolution-capacity-unavailable",
            ),
            (
                destination_refusal_name(&DestinationSendError::TooManyResolverAnswers),
                "too-many-resolver-answers",
            ),
            (
                destination_refusal_name(&DestinationSendError::NoResolverAnswers),
                "no-resolver-answers",
            ),
            (
                destination_refusal_name(&DestinationSendError::ResolverPortMismatch),
                "resolver-port-mismatch",
            ),
            (
                destination_refusal_name(&DestinationSendError::ResolverAddressFamilyMismatch),
                "resolver-address-family-mismatch",
            ),
            (
                destination_refusal_name(&DestinationSendError::LiteralOriginMismatch),
                "literal-origin-mismatch",
            ),
            (
                destination_refusal_name(&DestinationSendError::CloudMetadataDenied),
                "cloud-metadata-denied",
            ),
            (
                destination_refusal_name(&DestinationSendError::AlwaysDeniedAddress),
                "always-denied-address",
            ),
            (
                destination_refusal_name(&DestinationSendError::PrivateAddressNotAllowed),
                "private-address-not-allowed",
            ),
            (
                destination_refusal_name(&DestinationSendError::NonGlobalAddressDenied),
                "non-global-address-denied",
            ),
            (
                destination_refusal_name(&DestinationSendError::DevelopmentAddressDenied),
                "development-address-denied",
            ),
            (
                destination_refusal_name(&DestinationSendError::TlsMaterialUnavailable),
                "tls-material-unavailable",
            ),
            (
                destination_refusal_name(&DestinationSendError::ClientBuildFailed),
                "client-build-failed",
            ),
            (
                destination_refusal_name(&DestinationSendError::DeadlineExceeded),
                "deadline-exceeded",
            ),
            (
                destination_refusal_name(&DestinationSendError::TransportFailed),
                "transport-failed",
            ),
            (
                destination_refusal_name(&DestinationSendError::DeadlineExceededAfterConnect),
                "deadline-exceeded-after-connect",
            ),
            (
                destination_refusal_name(&DestinationSendError::TransportFailedAfterConnect),
                "transport-failed-after-connect",
            ),
            (
                destination_refusal_name(&DestinationSendError::TooManyResponseHeaders),
                "too-many-response-headers",
            ),
            (
                destination_refusal_name(&DestinationSendError::ResponseHeaderBytesExceeded),
                "response-header-bytes-exceeded",
            ),
        ];
        assert_eq!(
            names.len(),
            EVERY_SEND_FAULT.len(),
            "every variant's journal name is asserted verbatim"
        );
        for (actual, expected) in names {
            assert_eq!(actual, expected, "the journal name is the closed mapping's");
        }
        for fault in &EVERY_SEND_FAULT {
            assert!(
                !destination_refusal_name(fault).contains(MARKER),
                "no journal name carries a marker"
            );
        }
    }

    /// A refusal's journal name is a fixed word per kind, a link refusal
    /// is named by its variant, and a destination refusal keeps its own
    /// closed name.
    #[test]
    fn a_refusal_names_its_kind_with_a_fixed_word() {
        let links = [
            (LinkRefusal::TooLong, "link-too-long"),
            (LinkRefusal::InvalidCharacter, "link-invalid-character"),
            (LinkRefusal::NotAbsolute, "link-not-absolute"),
            (LinkRefusal::Unparseable, "link-unparseable"),
            (LinkRefusal::SchemeMismatch, "link-scheme-mismatch"),
            (LinkRefusal::Userinfo, "link-userinfo"),
            (LinkRefusal::HostMismatch, "link-host-mismatch"),
            (LinkRefusal::PortMismatch, "link-port-mismatch"),
            (LinkRefusal::Fragment, "link-fragment"),
            (LinkRefusal::QueryNotAsWritten, "link-query-not-as-written"),
            (LinkRefusal::NonCanonicalPath, "link-non-canonical-path"),
            (LinkRefusal::OutsideBasePath, "link-outside-base-path"),
        ];
        for (fault, name) in links {
            assert_eq!(EgressRefusal::Link(fault).journal_name(), name);
        }
        assert_eq!(EgressRefusal::Credential.journal_name(), "credential");
        assert_eq!(
            EgressRefusal::AttemptAboveMaximum.journal_name(),
            "attempt-above-maximum"
        );
        assert_eq!(
            EgressRefusal::Destination {
                fault: DestinationSendError::ResolutionFailed,
                journal_name: "resolution-failed",
            }
            .journal_name(),
            "resolution-failed"
        );
    }

    /// The token path projects the one partition exactly: every
    /// platform send fault lands on the token vocabulary at the class
    /// the data path raises for the same fault, so the two paths can
    /// never disagree about what happened to a send. The projection's
    /// own total function is the token layer's
    /// `token_transport_fault`; this asserts the pair end to end,
    /// through the classes each path reports.
    #[test]
    fn the_token_path_agrees_with_the_data_path_on_every_send_fault() {
        for fault in &EVERY_SEND_FAULT {
            let data_class = match destination_send_outcome(*fault) {
                EgressError::Upstream(failure) => failure.class.class().to_owned(),
                EgressError::Refused(_) => ErrorClass::EgressRefused.class().to_owned(),
            };
            let token_fault = crate::auth::token_transport_fault(token_send_failure(*fault));
            let token_class = AuthError::Token(token_fault).class();
            let expected = match partition_send_fault(*fault) {
                SendFaultClass::ResolutionUnanswered
                | SendFaultClass::DeadlineBeforeConnect
                | SendFaultClass::ConnectFailed => "upstream.connection",
                SendFaultClass::DeadlineAfterConnect => "upstream.timeout",
                SendFaultClass::ExchangeFailed => "upstream.connection",
                SendFaultClass::ResponseHeadUnusable => "upstream.malformed",
                SendFaultClass::ResponseHeadOverBound => "upstream.too-large",
                SendFaultClass::Refused(_) => "egress.refused",
            };
            assert_eq!(data_class, expected, "{fault:?} on the data path");
            assert_eq!(token_class, expected, "{fault:?} on the token path");
        }
    }

    /// The token refusal's journal detail is the same closed word the
    /// data path journals for the same platform fault, a catchable
    /// fault never arrives as a refusal, and no refusal name ever
    /// carries a value: a marker secret cannot ride a token egress
    /// refusal into the journal.
    #[test]
    fn the_token_refusal_carries_the_data_paths_journal_word() {
        const MARKER: &str = "c4b-marker-9f31ab";
        for fault in &EVERY_SEND_FAULT {
            let token = token_send_failure(*fault);
            if matches!(partition_send_fault(*fault), SendFaultClass::Refused(_)) {
                let TransportFailure::PolicyRefused { journal_name } = token else {
                    panic!("a boundary refusal projects to the policy refusal: {fault:?}");
                };
                let data_name = match destination_send_outcome(*fault) {
                    EgressError::Refused(EgressRefusal::Destination { journal_name, .. }) => {
                        journal_name
                    }
                    other => panic!("a boundary refusal refuses on the data path: {other:?}"),
                };
                assert_eq!(journal_name, data_name, "{fault:?}'s journal word");
                assert!(
                    !journal_name.contains(MARKER) && !journal_name.is_empty(),
                    "{journal_name} is a fixed word carrying no value"
                );
            } else {
                assert!(
                    !matches!(token, TransportFailure::PolicyRefused { .. }),
                    "{fault:?} is catchable and never a refusal"
                );
            }
        }
    }

    /// The destination profile follows the pinned origin: HTTPS is
    /// production, plain HTTP is development on loopback and a private
    /// service hop everywhere else, matching the platform's own
    /// loopback admission rule.
    #[test]
    fn the_destination_profile_follows_the_pinned_origin() {
        let https = url::Url::parse("https://records.example.internal:8443/").expect("parsed");
        let loopback = url::Url::parse("http://127.0.0.1:8080/").expect("parsed");
        let localhost = url::Url::parse("http://localhost:8080/").expect("parsed");
        let private = url::Url::parse("http://10.0.0.7:8080/").expect("parsed");
        let public_name = url::Url::parse("http://upstream.example.invalid:80/").expect("parsed");
        assert_eq!(
            destination_profile(&https),
            DestinationProfile::ProductionHttps
        );
        assert_eq!(
            destination_profile(&loopback),
            DestinationProfile::LoopbackDevelopmentHttp
        );
        assert_eq!(
            destination_profile(&localhost),
            DestinationProfile::LoopbackDevelopmentHttp
        );
        assert_eq!(
            destination_profile(&private),
            DestinationProfile::PrivateServiceHttp
        );
        assert_eq!(
            destination_profile(&public_name),
            DestinationProfile::PrivateServiceHttp
        );
    }

    /// Under the postgres-test feature an https loopback origin takes
    /// the platform's pinned loopback test profile, so the TLS suites
    /// drive the same frozen-policy send against locally terminated
    /// certificates; a named https origin stays production even under
    /// the feature, and without the feature the loopback origin would
    /// be production too.
    #[cfg(feature = "postgres-test")]
    #[test]
    fn the_pinned_loopback_https_profile_serves_only_under_its_feature() {
        let loopback = url::Url::parse("https://127.0.0.1:8443/").expect("parsed");
        assert_eq!(
            destination_profile(&loopback),
            DestinationProfile::PinnedLoopbackHttpsTest
        );
        let named = url::Url::parse("https://records.example.internal:8443/").expect("parsed");
        assert_eq!(
            destination_profile(&named),
            DestinationProfile::ProductionHttps
        );
        assert!(profile_admits_token_endpoints(
            DestinationProfile::PinnedLoopbackHttpsTest
        ));
    }

    /// The token endpoint admission is the profile predicate the
    /// egress layer serves: the profiles the token transport freezes
    /// admit, every other profile refuses, fail-closed.
    #[test]
    fn the_profile_predicate_admits_exactly_the_served_profiles() {
        assert!(profile_admits_token_endpoints(
            DestinationProfile::ProductionHttps
        ));
        assert!(profile_admits_token_endpoints(
            DestinationProfile::LoopbackDevelopmentHttp
        ));
        assert!(!profile_admits_token_endpoints(
            DestinationProfile::PrivateServiceHttp
        ));
        assert!(!profile_admits_token_endpoints(
            DestinationProfile::LocalPrivateDevelopmentHttp
        ));
    }

    /// The declared-scheme slots a static authorization freezes: the
    /// plan's declared scheme travels into the template whatever it
    /// spells, and a scheme outside the platform's token bound refuses
    /// the load instead of failing closed at the first send.
    #[test]
    fn declared_scheme_slots_carry_the_declared_scheme() {
        let authentication = EndpointAuthentication::StaticAuthorization { scheme: None };
        let (template, api_key, frozen) =
            authorization_slots(Some("Bearer"), &authentication).expect("bearer slots");
        assert!(api_key.is_none());
        assert_eq!(
            frozen.as_ref().map(DestinationAuthorizationScheme::as_str),
            Some("Bearer")
        );
        assert!(matches!(
            template,
            DestinationAuthorizationTemplate::Scheme { .. }
        ));
        let (_, _, frozen) = authorization_slots(Some("ApiToken"), &authentication)
            .expect("a declared scheme freezes");
        assert_eq!(
            frozen.as_ref().map(DestinationAuthorizationScheme::as_str),
            Some("ApiToken")
        );
        let overlong_scheme = "a".repeat(33);
        let overlong = authorization_slots(Some(&overlong_scheme), &authentication);
        assert_eq!(
            overlong.unwrap_err(),
            DestinationRequestError::InvalidAuthorization
        );
        // A static authorization whose plan declares no scheme is a
        // compile fault, not a send-time surprise.
        assert_eq!(
            authorization_slots(None, &authentication).unwrap_err(),
            DestinationRequestError::InvalidAuthorization
        );
    }

    /// A token endpoint that is not https refuses TLS material at the
    /// freeze too: the load-time resolution owns the refusal, and this
    /// re-check keeps the install fail-closed when the freeze is reached
    /// without that resolution, instead of installing material a plain
    /// destination never uses.
    #[test]
    fn a_plain_token_endpoint_refuses_tls_material_at_install() {
        use crate::auth::TlsFault;
        use registry_adapter_core::{CredentialPlacement, RuntimeCredential};
        use registry_platform_yaml::{BoundedU64, SecretReference, Url};
        let binding = EndpointBinding {
            endpoint: ExternalId::new("case-api").expect("id"),
            base_url: Url::new("https://cases.example.invalid").expect("url"),
            credential: Some(RuntimeCredential::Oauth2ClientCredentials {
                token_endpoint: Url::new("http://127.0.0.1:9999/token").expect("url"),
                client_id_ref: SecretReference::new("secret:env/CLIENT_ID")
                    .expect("secret reference"),
                client_secret_ref: SecretReference::new("secret:env/CLIENT_SECRET")
                    .expect("secret reference"),
                scope: None,
                audience: None,
                resource: None,
                credential_placement: CredentialPlacement::BasicHeader,
                maximum_cache_seconds: BoundedU64::new(3600).expect("cache"),
                assumed_lifetime_seconds: None,
            }),
            anonymous_https: None,
            tls_trust_profile: None,
            mtls_identity: None,
            attempt_timeout_milliseconds: None,
            maximum_response_bytes: None,
        };
        let plan = AuthPlan::compile(
            &EndpointAuthentication::Oauth2ClientCredentials {},
            &binding,
        )
        .expect("the plan compiles");
        let material = registry_platform_httputil::destination::DestinationTlsMaterial::from_pem(
            Some(crate::auth::tls::tests::ROOT_CERTIFICATE_PEM.as_bytes()),
            None,
        )
        .expect("material");
        let fault = freeze_token_send(&binding, &plan, &[], Some(material))
            .err()
            .expect("a plain token endpoint refuses TLS material");
        assert!(
            matches!(
                fault,
                EgressFault::Auth(AuthError::Tls(TlsFault::PlainDestination))
            ),
            "{fault:?}"
        );
    }
}
