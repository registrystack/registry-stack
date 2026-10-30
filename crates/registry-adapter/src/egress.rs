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
use std::time::Duration;

use registry_adapter_core::ErrorClass;
use registry_adapter_core::{
    AdapterRuntimeConfig, Cidr, Endpoint, EndpointAuthentication, EndpointBinding,
    MAXIMUM_ATTEMPT_TIMEOUT_MILLISECONDS,
};
use registry_platform_config::SecretResolver;
use registry_platform_httputil::destination::json::decode_script_json;
use registry_platform_httputil::destination::{
    DataDestinationPolicy, DataDestinationRequestTemplate, DestinationAuthorizationScheme,
    DestinationAuthorizationTemplate, DestinationAuthorizationValue, DestinationDeliveryCertainty,
    DestinationProfile, DestinationRequestError, DestinationResponseError,
    DestinationResponseHeaderError, DestinationSendError, DestinationTlsMaterialError,
    QueryStringContentAcknowledgement, ScriptRequestBodyFormat, SideEffectingSendMethod,
    MAX_DESTINATION_HEADER_VALUE_BYTES, MAX_DESTINATION_REQUEST_BODY_BYTES,
    MAX_DESTINATION_REQUEST_HEADER_BYTES, MAX_DESTINATION_TARGET_BYTES,
};
use registry_platform_yaml::ExternalId;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::auth::{
    AuthError, AuthEvent, AuthHeader, AuthKind, AuthPlan, AuthorizeContext, AuthorizedCredential,
    ClientAssertionSigner, EndpointTls, TokenBudget, TokenRequest, TokenSend, TokenWire,
    TransportFailure,
};
use crate::component::http::header_filter::{
    AllowlistError, HeaderFilter, InboundHeaderError, OutboundHeaderError, ResponseHeaders,
};
use crate::component::http::uri::{LinkRefusal, OriginError, PinnedOrigin};

/// Stands in the authorize context for the token send this build does
/// not wire: the load refuses every token plan, so no plan this
/// context serves can reach a token acquisition. If one ever did, the
/// send refuses loudly instead of pretending.
struct UnwiredTokenSend;

impl TokenSend for UnwiredTokenSend {
    fn send<'a>(
        &'a self,
        _request: &'a TokenRequest,
    ) -> Pin<Box<dyn Future<Output = Result<TokenWire, TransportFailure>> + Send + 'a>> {
        Box::pin(async { Err(TransportFailure::PolicyRefused) })
    }
}

const UNWIRED_TOKEN_SEND: UnwiredTokenSend = UnwiredTokenSend;

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
    /// The endpoint's kind acquires a token, and this build does not
    /// wire the token send yet: the deployment refuses to start, so the
    /// gap is visible at startup and never at a first request.
    TokenSendUnwired,
    /// The endpoint binding at `position` names no declared endpoint.
    BindingUnmatched {
        /// The position of the binding in the runtime config.
        position: usize,
    },
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
            Self::TokenSendUnwired => {
                formatter.write_str("the endpoint's token send is not wired in this build")
            }
            Self::BindingUnmatched { position } => write!(
                formatter,
                "the endpoint binding at position {position} names no declared endpoint"
            ),
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
}

impl EgressRefusal {
    /// The error class a refusal raises: `egress.refused`, always.
    #[must_use]
    pub const fn class(&self) -> ErrorClass {
        ErrorClass::EgressRefused
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
    /// The reviewed status range of the send's `to` step, inclusive.
    pub ok_status_range: (u16, u16),
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
            .field("ok_status_range", &self.ok_status_range)
            .field(
                "throw_exception_on_failure",
                &self.throw_exception_on_failure,
            )
            .finish()
    }
}

/// One endpoint's outbound state, compiled once at startup.
pub struct EndpointEgress {
    endpoint: ExternalId,
    plan: AuthPlan,
    filter: HeaderFilter,
    origin: PinnedOrigin,
    policy: DataDestinationPolicy,
    request_allowlist: Vec<String>,
    authorization_scheme: Option<DestinationAuthorizationScheme>,
    get_template: DataDestinationRequestTemplate,
    post_template: DataDestinationRequestTemplate,
}

impl EndpointEgress {
    /// Compile one endpoint binding against its declared endpoint.
    fn compile(
        binding: &EndpointBinding,
        declared: &Endpoint,
        config: &AdapterRuntimeConfig,
        resolver: &SecretResolver,
    ) -> Result<Self, EgressFault> {
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
        // The token send is the unit after the first real read: until
        // it is wired, an endpoint whose kind acquires a token refuses
        // the load, so the gap is visible at startup and never at a
        // first request. The resolved token material has no destination
        // to install it on and is dropped, never shared or re-parsed.
        if plan.token_plan().is_some() {
            drop(materials.token);
            return Err(EgressFault::TokenSendUnwired);
        }
        Ok(Self {
            endpoint: binding.endpoint.clone(),
            plan,
            filter,
            origin,
            policy,
            request_allowlist,
            authorization_scheme,
            get_template,
            post_template,
        })
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
    /// exactly the issuance its send rode.
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
        // The load refuses every token plan, so the only plans this
        // endpoint serves are the static kinds; the unwired send stands
        // in for the token transport the next unit wires, and refuses
        // loudly if a token plan ever reached it.
        let mut context = AuthorizeContext {
            resolver,
            budget,
            send: &UNWIRED_TOKEN_SEND,
            signer,
            events,
        };
        self.plan.authorize(&mut context).await
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

        let (authorization, api_key) = self
            .credential_slots(send.authorization)
            .map_err(EgressError::Refused)?;
        let (template, body_format, body) = match &send.shape {
            SendShape::Get => (&self.get_template, None, None),
            SendShape::Post(body) => {
                let format = match body.format {
                    SendBodyFormat::Json => ScriptRequestBodyFormat::Json,
                    SendBodyFormat::Form => ScriptRequestBodyFormat::Form,
                };
                (
                    &self.post_template,
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

        let reply = self
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

        let (low, high) = send.ok_status_range;
        let out_of_range = status < low || status > high;
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
            // An OAuth2 kind never reaches a data send while the token
            // send is unwired: the load refuses the plan, and even a
            // wired plan could not serve a header here without a token.
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
/// and one private service hop everywhere else.
fn destination_profile(parsed_base: &url::Url) -> DestinationProfile {
    match parsed_base.scheme() {
        "https" => DestinationProfile::ProductionHttps,
        _ if denotes_loopback(parsed_base) => DestinationProfile::LoopbackDevelopmentHttp,
        _ => DestinationProfile::PrivateServiceHttp,
    }
}

/// Whether the origin's host explicitly denotes loopback: the name
/// `localhost` or a loopback address literal, the platform's own
/// admission rule for the development profile.
fn denotes_loopback(origin: &url::Url) -> bool {
    match origin.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
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
}
