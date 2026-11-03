// SPDX-License-Identifier: Apache-2.0

//! The endpoint's two header allowlists, Camel's `HeaderFilterStrategy`
//! in both directions (`products/adapter/CONCEPT.md` section 8.11.4).
//!
//! A [`HeaderFilter`] is built once per endpoint from its
//! `requestHeaders` and `responseHeaders` and its authentication's
//! api-key header name. Construction refuses every name that may never
//! cross the boundary, so a filter that exists cannot emit one: the
//! runtime never assumes `adapterctl check` ran (section 5.5) and
//! repeats each rule `check` enforces.
//!
//! - [`HeaderFilter::outbound`] selects the exchange headers sent
//!   upstream: only listed names, compared without case. A listed header
//!   absent from the exchange is not sent; engine headers and facade
//!   inputs are exchange headers like any other and go out only when
//!   listed. A value that is not a strict RFC 9110 field value is
//!   refused with the uncatchable `egress.refused`, never sent, trimmed,
//!   or re-encoded.
//! - [`HeaderFilter::inbound`] copies the declared upstream response
//!   headers onto the exchange under their declared names. A declared
//!   header the upstream repeats, or sends with a value that is not
//!   visible ASCII, is `upstream.malformed`.
//!
//! # Credentials
//!
//! Credentials are injected after this filter (section 10.2). The
//! filtered request set, [`OutboundHeaders`], carries only allowlisted
//! names, and the allowlist structurally excludes every reserved name of
//! section 8.11.4 (`Authorization`, `Proxy-*`, `Cookie`, `Host`, the
//! framing and hop-by-hop headers) and the endpoint's own api-key
//! header. The type has no public constructor and no mutation, so the
//! credential an injector appends is never already present and no
//! exchange header can replace or shadow it.
//!
//! # Errors
//!
//! Every error is value-free (CFG-SEC-3): it names the list and the
//! allowlist position, never a header value, because values carry
//! personal data and credentials.

use std::fmt;

use ::http::{HeaderName, HeaderValue};
use registry_adapter_core::{
    is_engine_header_name, is_facade_input_header_name, is_header_token, is_reserved_header_name,
    Endpoint, EndpointAuthentication, ErrorClass,
};
use registry_platform_httputil::destination::{
    is_script_visible_response_header_name, is_script_writable_request_header_name,
    MAX_DESTINATION_HEADER_VALUE_BYTES, MAX_DESTINATION_REQUEST_HEADERS,
};

/// Which of the endpoint's two allowlists an error concerns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderSide {
    /// `requestHeaders`: exchange headers sent upstream.
    Request,
    /// `responseHeaders`: upstream headers copied onto the exchange.
    Response,
}

impl fmt::Display for HeaderSide {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Request => "requestHeaders",
            Self::Response => "responseHeaders",
        })
    }
}

/// Why an endpoint's allowlists were refused when the filter was built.
///
/// `index` is the position in the named list; the name itself is never
/// carried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllowlistError {
    /// The name is not an RFC 9110 token.
    NotAToken {
        /// The list.
        side: HeaderSide,
        /// The position in the list.
        index: usize,
    },
    /// The name is never allowlistable (section 8.11.4).
    Reserved {
        /// The list.
        side: HeaderSide,
        /// The position in the list.
        index: usize,
    },
    /// The name is the endpoint's own api-key header, compared without
    /// case.
    ApiKeyHeader {
        /// The list.
        side: HeaderSide,
        /// The position in the list.
        index: usize,
    },
    /// The name repeats an earlier entry of the same list, compared
    /// without case.
    Duplicate {
        /// The list.
        side: HeaderSide,
        /// The position of the repeat.
        index: usize,
    },
    /// A response header name the engine places on the exchange itself:
    /// an upstream may not write a `Camel*` header.
    EngineHeader {
        /// The position in `responseHeaders`.
        index: usize,
    },
    /// A facade input name of section 8.11.1, refused in
    /// `responseHeaders`: an upstream value never stands in for a
    /// validated caller input. The request side may list a facade input,
    /// which sends the caller's own value upstream.
    FacadeInput {
        /// The position in `responseHeaders`.
        index: usize,
    },
    /// The platform transport refuses the name on this side:
    /// `Content-Type` and the forwarding, encoding, and signing headers
    /// it owns on a request; authentication challenges, infrastructure,
    /// and tracing headers on a response.
    TransportRefused {
        /// The list.
        side: HeaderSide,
        /// The position in the list.
        index: usize,
    },
    /// The list is longer than the transport's header bound.
    TooMany {
        /// The list.
        side: HeaderSide,
        /// The bound, `MAX_DESTINATION_REQUEST_HEADERS`.
        maximum: usize,
    },
}

impl fmt::Display for AllowlistError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAToken { side, index } => {
                write!(formatter, "{side} entry {index} is not an RFC 9110 token")
            }
            Self::Reserved { side, index } => {
                write!(formatter, "{side} entry {index} is a reserved header name")
            }
            Self::ApiKeyHeader { side, index } => write!(
                formatter,
                "{side} entry {index} is the endpoint's api-key header"
            ),
            Self::Duplicate { side, index } => write!(
                formatter,
                "{side} entry {index} repeats an earlier entry, compared without case"
            ),
            Self::EngineHeader { index } => write!(
                formatter,
                "responseHeaders entry {index} is a Camel engine header"
            ),
            Self::FacadeInput { index } => write!(
                formatter,
                "responseHeaders entry {index} is a facade input name"
            ),
            Self::TransportRefused { side, index } => write!(
                formatter,
                "{side} entry {index} is a header the transport never carries on this side"
            ),
            Self::TooMany { side, maximum } => {
                write!(formatter, "{side} lists more than {maximum} headers")
            }
        }
    }
}

impl std::error::Error for AllowlistError {}

/// Why the exchange headers could not be sent; always the uncatchable
/// `egress.refused`.
///
/// A value that would split, truncate, or be reinterpreted on the wire
/// is a breach of the egress boundary, not a condition a route recovers
/// from, so no clause may handle it (section 8.7).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundHeaderError {
    /// The value of the listed header at `index` is not a strict field
    /// value: a control (CR, LF, NUL, DEL), a byte outside visible
    /// ASCII, or leading or trailing whitespace.
    InvalidValue {
        /// The position in `requestHeaders`.
        index: usize,
    },
    /// The value is longer than `MAX_DESTINATION_HEADER_VALUE_BYTES`.
    ValueTooLong {
        /// The position in `requestHeaders`.
        index: usize,
    },
    /// The exchange holds two entries for the listed name, compared
    /// without case; neither is picked.
    Duplicate {
        /// The position in `requestHeaders`.
        index: usize,
    },
}

impl OutboundHeaderError {
    /// The error class the send raises: `egress.refused`.
    #[must_use]
    pub const fn class(&self) -> ErrorClass {
        ErrorClass::EgressRefused
    }
}

impl fmt::Display for OutboundHeaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidValue { index } => write!(
                formatter,
                "requestHeaders entry {index} has a value that is not a valid field value"
            ),
            Self::ValueTooLong { index } => write!(
                formatter,
                "requestHeaders entry {index} has a value longer than \
                 {MAX_DESTINATION_HEADER_VALUE_BYTES} bytes"
            ),
            Self::Duplicate { index } => write!(
                formatter,
                "requestHeaders entry {index} is set more than once on the exchange"
            ),
        }
    }
}

impl std::error::Error for OutboundHeaderError {}

/// Why a declared upstream response header could not be copied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboundHeaderError {
    /// The upstream sent the declared header more than once.
    Repeated {
        /// The position in `responseHeaders`.
        index: usize,
    },
    /// The value is not visible ASCII with internal spaces and tabs.
    InvalidValue {
        /// The position in `responseHeaders`.
        index: usize,
    },
    /// The value is longer than `MAX_DESTINATION_HEADER_VALUE_BYTES`.
    ValueTooLong {
        /// The position in `responseHeaders`.
        index: usize,
    },
}

impl InboundHeaderError {
    /// The error class the send raises: `upstream.too-large` for an
    /// over-long value, `upstream.malformed` otherwise. Both are
    /// catchable: the upstream misbehaved, the boundary held.
    #[must_use]
    pub const fn class(&self) -> ErrorClass {
        match self {
            Self::ValueTooLong { .. } => ErrorClass::UpstreamTooLarge,
            Self::Repeated { .. } | Self::InvalidValue { .. } => ErrorClass::UpstreamMalformed,
        }
    }
}

impl fmt::Display for InboundHeaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Repeated { index } => write!(
                formatter,
                "the upstream repeated the header at responseHeaders entry {index}"
            ),
            Self::InvalidValue { index } => write!(
                formatter,
                "the upstream sent an invalid value for responseHeaders entry {index}"
            ),
            Self::ValueTooLong { index } => write!(
                formatter,
                "the upstream sent a value longer than {MAX_DESTINATION_HEADER_VALUE_BYTES} \
                 bytes for responseHeaders entry {index}"
            ),
        }
    }
}

impl std::error::Error for InboundHeaderError {}

/// One endpoint's request and response header allowlists, validated.
#[derive(Clone, Debug)]
pub struct HeaderFilter {
    /// `requestHeaders`, as wire names.
    request: Vec<HeaderName>,
    /// `responseHeaders`: the declared spelling the exchange carries, and
    /// the wire name it is matched against.
    response: Vec<(String, HeaderName)>,
}

impl HeaderFilter {
    /// Build the filter from an endpoint declaration: its
    /// `requestHeaders`, its `responseHeaders`, and, for a
    /// `static-api-key` endpoint, its `headerName`.
    ///
    /// # Errors
    ///
    /// Every refusal of [`HeaderFilter::new`].
    pub fn for_endpoint(endpoint: &Endpoint) -> Result<Self, AllowlistError> {
        let api_key = match &endpoint.authentication {
            EndpointAuthentication::StaticApiKey { header_name } => Some(header_name.as_str()),
            _ => None,
        };
        Self::new(
            endpoint.request_headers.iter().map(|name| name.as_str()),
            endpoint.response_headers.iter().map(|name| name.as_str()),
            api_key,
        )
    }

    /// Build the filter from the two allowlists and the endpoint's
    /// api-key header name, if it has one.
    ///
    /// # Errors
    ///
    /// In either list, a name that is not an RFC 9110 token, a reserved
    /// name of section 8.11.4, the api-key header name, a repeat of an
    /// earlier entry compared without case, or more than
    /// `MAX_DESTINATION_REQUEST_HEADERS` entries; in `responseHeaders`,
    /// also a `Camel*` engine header name and a facade input name; and
    /// a name the platform transport refuses on that side, so a filter
    /// that builds is one the transport carries.
    pub fn new<R, S>(
        request_headers: impl IntoIterator<Item = R>,
        response_headers: impl IntoIterator<Item = S>,
        api_key_header: Option<&str>,
    ) -> Result<Self, AllowlistError>
    where
        R: AsRef<str>,
        S: AsRef<str>,
    {
        let request = allowlist(HeaderSide::Request, request_headers, api_key_header)?
            .into_iter()
            .map(|(_, name)| name)
            .collect();
        let response = allowlist(HeaderSide::Response, response_headers, api_key_header)?;
        Ok(Self { request, response })
    }

    /// The declared response header names, in declaration order, as the
    /// endpoint wrote them; the selection a transport reads from the
    /// upstream response.
    pub fn response_header_names(&self) -> impl ExactSizeIterator<Item = &str> {
        self.response.iter().map(|(declared, _)| declared.as_str())
    }

    /// Select the exchange headers sent upstream, in allowlist order.
    ///
    /// `exchange` is every header on the exchange as a name and its
    /// string value; the `http` component stringifies a non-string
    /// header before calling. Only listed names are kept; every other
    /// header, including any credential name, is dropped because it is
    /// not listed.
    ///
    /// # Errors
    ///
    /// [`OutboundHeaderError`], class `egress.refused`, when a listed
    /// header has an invalid or over-long value or appears more than
    /// once on the exchange.
    pub fn outbound<N, V>(
        &self,
        exchange: impl IntoIterator<Item = (N, V)>,
    ) -> Result<OutboundHeaders, OutboundHeaderError>
    where
        N: AsRef<str>,
        V: AsRef<str>,
    {
        let mut selected: Vec<Option<HeaderValue>> = vec![None; self.request.len()];
        for (name, value) in exchange {
            let Some(index) = position(&self.request, name.as_ref()) else {
                continue;
            };
            if selected[index].is_some() {
                return Err(OutboundHeaderError::Duplicate { index });
            }
            let value = value.as_ref().as_bytes();
            if value.len() > MAX_DESTINATION_HEADER_VALUE_BYTES {
                return Err(OutboundHeaderError::ValueTooLong { index });
            }
            if !is_strict_field_value(value) {
                return Err(OutboundHeaderError::InvalidValue { index });
            }
            let value = HeaderValue::from_bytes(value)
                .map_err(|_| OutboundHeaderError::InvalidValue { index })?;
            selected[index] = Some(value);
        }
        Ok(OutboundHeaders(
            self.request
                .iter()
                .zip(selected)
                .filter_map(|(name, value)| value.map(|value| (name.clone(), value)))
                .collect(),
        ))
    }

    /// Copy the declared upstream response headers, in declaration
    /// order, under their declared names.
    ///
    /// `upstream` is every response field line as a name and its raw
    /// value bytes; undeclared fields are ignored whatever they hold.
    ///
    /// # Errors
    ///
    /// [`InboundHeaderError`] when the upstream repeats a declared
    /// header (`upstream.malformed`), sends one with a value that is not
    /// visible ASCII (`upstream.malformed`), or sends one longer than
    /// the transport bound (`upstream.too-large`).
    pub fn inbound<N, V>(
        &self,
        upstream: impl IntoIterator<Item = (N, V)>,
    ) -> Result<ResponseHeaders, InboundHeaderError>
    where
        N: AsRef<str>,
        V: AsRef<[u8]>,
    {
        let mut copied: Vec<Option<String>> = vec![None; self.response.len()];
        for (name, value) in upstream {
            let Some(index) = self
                .response
                .iter()
                .position(|(_, wire)| wire.as_str().eq_ignore_ascii_case(name.as_ref()))
            else {
                continue;
            };
            if copied[index].is_some() {
                return Err(InboundHeaderError::Repeated { index });
            }
            let value = value.as_ref();
            if value.len() > MAX_DESTINATION_HEADER_VALUE_BYTES {
                return Err(InboundHeaderError::ValueTooLong { index });
            }
            if !is_strict_field_value(value) {
                return Err(InboundHeaderError::InvalidValue { index });
            }
            let value = String::from_utf8(value.to_vec())
                .map_err(|_| InboundHeaderError::InvalidValue { index })?;
            copied[index] = Some(value);
        }
        Ok(ResponseHeaders(
            self.response
                .iter()
                .zip(copied)
                .filter_map(|((declared, _), value)| value.map(|value| (declared.clone(), value)))
                .collect(),
        ))
    }
}

/// The exchange headers selected for one upstream send, in allowlist
/// order.
///
/// Only [`HeaderFilter::outbound`] builds one, and nothing mutates it:
/// its names are a subset of `requestHeaders`, which never holds a
/// reserved name or the endpoint's api-key header, so the credential the
/// `http` component injects afterwards is never already present and
/// cannot be shadowed or replaced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundHeaders(Vec<(HeaderName, HeaderValue)>);

impl OutboundHeaders {
    /// The selected headers, in allowlist order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&HeaderName, &HeaderValue)> {
        self.0.iter().map(|(name, value)| (name, value))
    }

    /// How many headers are selected.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no header is selected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The declared upstream response headers present on one response, in
/// declaration order, each under its declared name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseHeaders(Vec<(String, String)>);

impl ResponseHeaders {
    /// The copied headers as `(declared name, value)`.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&str, &str)> {
        self.0
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }

    /// How many headers were copied.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no declared header was present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Validate one allowlist, returning each declared name with its wire
/// form.
fn allowlist<T: AsRef<str>>(
    side: HeaderSide,
    names: impl IntoIterator<Item = T>,
    api_key_header: Option<&str>,
) -> Result<Vec<(String, HeaderName)>, AllowlistError> {
    let mut validated: Vec<(String, HeaderName)> = Vec::new();
    for (index, name) in names.into_iter().enumerate() {
        if index == MAX_DESTINATION_REQUEST_HEADERS {
            return Err(AllowlistError::TooMany {
                side,
                maximum: MAX_DESTINATION_REQUEST_HEADERS,
            });
        }
        let name = name.as_ref();
        if !is_header_token(name) {
            return Err(AllowlistError::NotAToken { side, index });
        }
        if is_reserved_header_name(name) {
            return Err(AllowlistError::Reserved { side, index });
        }
        if api_key_header.is_some_and(|api_key| api_key.eq_ignore_ascii_case(name)) {
            return Err(AllowlistError::ApiKeyHeader { side, index });
        }
        if side == HeaderSide::Response && is_engine_header_name(name) {
            return Err(AllowlistError::EngineHeader { index });
        }
        if side == HeaderSide::Response && is_facade_input_header_name(name) {
            return Err(AllowlistError::FacadeInput { index });
        }
        let carried = match side {
            HeaderSide::Request => is_script_writable_request_header_name(name),
            HeaderSide::Response => is_script_visible_response_header_name(name),
        };
        if !carried {
            return Err(AllowlistError::TransportRefused { side, index });
        }
        if validated
            .iter()
            .any(|(declared, _)| declared.eq_ignore_ascii_case(name))
        {
            return Err(AllowlistError::Duplicate { side, index });
        }
        let wire = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| AllowlistError::NotAToken { side, index })?;
        validated.push((name.to_owned(), wire));
    }
    Ok(validated)
}

/// The allowlist position of an exchange header name, compared without
/// case.
fn position(list: &[HeaderName], name: &str) -> Option<usize> {
    list.iter()
        .position(|listed| listed.as_str().eq_ignore_ascii_case(name))
}

/// Whether bytes are a field value the engine sends or copies: visible
/// ASCII (RFC 9110 section 5.5 `VCHAR`) with spaces and tabs only
/// between visible characters. Empty is valid. `obs-text` is refused:
/// upstreams disagree on whether it is Latin-1 or UTF-8.
fn is_strict_field_value(value: &[u8]) -> bool {
    let visible = |byte: &u8| (0x21..=0x7e).contains(byte);
    let blank = |byte: &u8| matches!(byte, b' ' | b'\t');
    value.iter().all(|byte| visible(byte) || blank(byte))
        && value.first().is_none_or(visible)
        && value.last().is_none_or(visible)
}
