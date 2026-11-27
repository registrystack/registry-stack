//! The request and response rules every token-endpoint client in this module
//! shares.
//!
//! The signed-assertion client and the client-secret client both post a form to
//! an endpoint the integrator named, read a bounded answer, and decide between a
//! refusal and a token response. Those steps live here once, so the two clients
//! cannot apply different rules to the same wire exchange.

use std::time::{Duration, Instant};

use bytes::Bytes;
use reqwest::header::{HeaderMap, ACCEPT, CONTENT_TYPE};
use serde::{de::DeserializeOwned, Deserialize, Deserializer};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    read_bounded, validate_response_headers_without_peer_policy, FetchUrlError, FetchUrlPolicy,
};

use super::{
    outbound,
    token::{OAuthErrorCode, TokenError},
};

/// How one client reaches its endpoints.
#[derive(Clone, Copy)]
pub(super) struct Transport<'a> {
    pub(super) http: &'a reqwest::Client,
    pub(super) fetch_url_policy: Option<&'a FetchUrlPolicy>,
    pub(super) request_timeout: Duration,
    pub(super) connect_timeout: Duration,
    pub(super) user_agent: Option<&'a str>,
    pub(super) trusted_root_certificates: Option<&'a [u8]>,
}

/// What the server answered: the status and headers, with the body left on the
/// wire until a caller asks for it.
///
/// A caller that needs only the status drops the answer, so it never waits on a
/// body it would ignore.
pub(super) struct Answer {
    pub(super) status: u16,
    media_type: Option<String>,
    response: reqwest::Response,
}

impl Answer {
    /// Read the body within the token response bound. The status arrived before
    /// the body did, and for a refusal it is the whole of what would have been
    /// reported anyway, so only a body of a success is a transport failure.
    async fn read(self) -> Result<(u16, Option<String>, Zeroizing<Vec<u8>>), TokenError> {
        let Self {
            status,
            media_type,
            response,
        } = self;
        match read_bounded(response, MAXIMUM_TOKEN_RESPONSE_BYTES).await {
            // The body may carry a credential, so its buffer is wiped when it is
            // dropped.
            Ok(body) => Ok((status, media_type, Zeroizing::new(body))),
            Err(_) if !(200..300).contains(&status) => Err(TokenError::Protocol { status }),
            Err(error) => Err(TokenError::Transport {
                kind: outbound::read_failure_kind(&error),
            }),
        }
    }

    /// Read a refusal, or the error for a status that is no refusal either.
    pub(super) async fn into_refusal(self) -> TokenError {
        match self.read().await {
            Ok((status, media_type, body)) => declined(status, media_type.as_deref(), &body),
            Err(error) => error,
        }
    }

    /// Read a token response: exactly a 200 in the one JSON media type, whose
    /// body is the response object. Anything else is a refusal or a protocol
    /// failure.
    pub(super) async fn into_token_response<T: DeserializeOwned>(self) -> Result<T, TokenError> {
        let (status, media_type, body) = self.read().await?;
        if !(200..300).contains(&status) {
            return Err(declined(status, media_type.as_deref(), &body));
        }
        if status != 200
            || !media_type
                .as_deref()
                .is_some_and(|value| essence(value).eq_ignore_ascii_case(JSON_MEDIA_TYPE))
        {
            return Err(TokenError::Protocol { status });
        }
        serde_json::from_slice(&body).map_err(|_| TokenError::Protocol { status })
    }
}

/// One form POST to `endpoint`, its response headers checked within the header
/// bounds. The body is read by whoever consumes the [`Answer`].
///
/// The body is moved into the request without a plain copy, so the buffer the
/// HTTP client holds is wiped when the request ends. Buffers inside the HTTP
/// stack (TLS records, socket buffers) are out of reach.
pub(super) async fn post_form(
    transport: Transport<'_>,
    endpoint: &Url,
    body: Zeroizing<String>,
) -> Result<Answer, TokenError> {
    let request = if let Some(policy) = transport.fetch_url_policy {
        let validated = policy
            .validate_dns_pinned_for_immediate_fetch_with_timeout(
                endpoint,
                transport.connect_timeout,
            )
            .await
            .map_err(token_fetch_policy_failure)?;
        validated
            .immediate_post_with_outbound_options(
                transport.request_timeout,
                transport.connect_timeout,
                transport.user_agent,
                transport.trusted_root_certificates,
            )
            .map_err(token_fetch_policy_failure)?
    } else {
        transport.http.post(endpoint.clone())
    };
    let response = request
        .header(CONTENT_TYPE, FORM_MEDIA_TYPE)
        .header(ACCEPT, JSON_MEDIA_TYPE)
        .body(wiped_body(body))
        .send()
        .await
        .map_err(|error| TokenError::Transport {
            kind: outbound::send_failure_kind(&error),
        })?;
    let status = response.status().as_u16();
    if validate_response_headers_without_peer_policy(response.headers()).is_err() {
        return Err(TokenError::Protocol { status });
    }
    let media_type = exact_content_type(response.headers()).map(str::to_owned);
    Ok(Answer {
        status,
        media_type,
        response,
    })
}

/// Move the form's bytes into a request body that wipes them when the last
/// reference to it is dropped.
fn wiped_body(mut body: Zeroizing<String>) -> reqwest::Body {
    let bytes = Zeroizing::new(std::mem::take(&mut *body).into_bytes());
    reqwest::Body::from(Bytes::from_owner(bytes))
}

/// The refusals a code redemption's inputs share, made before any request.
pub(super) fn check_redemption_inputs(
    code: &str,
    redirect_uri: &Url,
    code_verifier: &str,
) -> Result<(), TokenError> {
    if code.is_empty()
        || code.len() > MAXIMUM_AUTHORIZATION_CODE_BYTES
        || !code.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(TokenError::Invalid {
            reason: "the authorization code must be bounded non-empty visible ASCII",
        });
    }
    // RFC 7636 section 4.1: 43 to 128 unreserved characters.
    if !(43..=128).contains(&code_verifier.len())
        || !code_verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte))
    {
        return Err(TokenError::Invalid {
            reason: "the code verifier must be 43 to 128 unreserved characters",
        });
    }
    if redirect_uri.cannot_be_a_base() || redirect_uri.fragment().is_some() {
        return Err(TokenError::Invalid {
            reason: "the redirect URI must be an absolute URI without a fragment",
        });
    }
    Ok(())
}

/// A token response must name a bearer token type.
pub(super) fn require_bearer(token_type: &str, status: u16) -> Result<(), TokenError> {
    if token_type.eq_ignore_ascii_case(BEARER_TOKEN_TYPE) {
        Ok(())
    } else {
        Err(TokenError::Protocol { status })
    }
}

/// The cache deadline of a stated `expires_in`, and whether the issuer stated
/// one at all. The outer `Option` is member presence, so a stated `null` has
/// spoken.
///
/// Silence, an already-elapsed lifetime, and a null one all leave the deadline
/// absent, and silence does not mean what the other two mean to a caller that
/// holds a deadline of its own to fall back on. A longer lifetime than is
/// trusted is clamped before the deadline arithmetic.
pub(super) fn lifetime_deadline(
    expires_in: Option<Option<i64>>,
    monotonic_now: Instant,
) -> (bool, Option<Instant>) {
    let deadline = expires_in
        .flatten()
        .filter(|seconds| *seconds > 0)
        .map(|seconds| seconds.min(MAXIMUM_CACHED_TOKEN_LIFETIME_SECONDS))
        // What reaches this point is within
        // 1..=MAXIMUM_CACHED_TOKEN_LIFETIME_SECONDS, so the deadline is an
        // instant at most a day ahead of the reading it is built on.
        .map(|seconds| monotonic_now + Duration::from_secs(seconds.unsigned_abs()));
    (expires_in.is_some(), deadline)
}

/// Longest an issuer's stated `expires_in` is trusted for, when deciding how
/// long to cache the credential it came with.
///
/// `expires_in` is a remote-controlled value. An authorization server that
/// reports one far longer than any real access token lives, whether by a bug
/// or by intent, must not be able to keep a credential cached, and therefore
/// live in memory, for the life of the process with no way for the integrator
/// to evict it. Re-acquiring a token earlier than an issuer's stated lifetime
/// requires is always safe, so clamping to 86400 seconds (24 hours) cannot
/// break a correct deployment.
pub const MAXIMUM_CACHED_TOKEN_LIFETIME_SECONDS: i64 = 86_400;
// Ties the doc comment above to the constant, so the two cannot drift apart.
const _: () = assert!(MAXIMUM_CACHED_TOKEN_LIFETIME_SECONDS == 86_400);

/// Longest authorization code this provider will present. Codes are short
/// opaque strings; the bound keeps a redirect parameter from growing the form.
pub(super) const MAXIMUM_AUTHORIZATION_CODE_BYTES: usize = 4 * 1024;
pub(super) const FORM_MEDIA_TYPE: &str = "application/x-www-form-urlencoded";
pub(super) const JSON_MEDIA_TYPE: &str = "application/json";

/// The only token type an `Authorization: Bearer` request can present. Compared
/// without case, as RFC 6749 section 5.1 requires.
pub(super) const BEARER_TOKEN_TYPE: &str = "bearer";

/// Longest token response this provider will read. A token response is a small
/// JSON object; anything larger is not one.
///
/// Authorization servers may use this value to reject registered authority
/// that could only produce a response this provider would refuse.
pub const MAXIMUM_TOKEN_RESPONSE_BYTES: u64 = 16 * 1024;

/// The error response of RFC 6749 section 5.2 and RFC 8707 section 2.
///
/// Only the code is read. `error_description` and `error_uri` are server-authored
/// text about a failed authentication attempt, so they stay in the buffer this
/// exchange is about to drop.
#[derive(Deserialize)]
struct DeclinedToken {
    error: String,
}

/// Map a refused token request onto the code it reported.
///
/// RFC 6749 section 5.2 and RFC 8707 section 2 put token request refusals at
/// 400, while an RFC 6749 client-authentication failure may use 401. Any other
/// status is the server reporting something about itself, which is not a
/// statement this client can act on as a refusal. A body is read as a refusal
/// only when it arrives in the media type the request asked for; an intermediary
/// answering in some other media type, or none at all, never reached the
/// authorization server's own refusal logic, so it is reported as a protocol
/// failure instead.
pub(super) fn declined(status: u16, media_type: Option<&str>, body: &[u8]) -> TokenError {
    if !matches!(status, 400 | 401)
        || !media_type.is_some_and(|value| essence(value).eq_ignore_ascii_case(JSON_MEDIA_TYPE))
    {
        return TokenError::Protocol { status };
    }
    match serde_json::from_slice::<DeclinedToken>(body) {
        Ok(declined) => TokenError::Refused {
            code: OAuthErrorCode::from_wire(&declined.error),
        },
        Err(_) => TokenError::Protocol { status },
    }
}

/// The media type without its parameters.
pub(super) fn essence(value: &str) -> &str {
    value.split(';').next().unwrap_or_default().trim()
}

pub(super) fn exact_content_type(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().ok(),
        _ => None,
    }
}

pub(super) fn token_fetch_policy_failure(error: FetchUrlError) -> TokenError {
    match error {
        FetchUrlError::Dns { .. } | FetchUrlError::NoAddresses => TokenError::Transport {
            kind: super::TransportKind::Connect,
        },
        FetchUrlError::ValidationTimeout { .. } => TokenError::Transport {
            kind: super::TransportKind::Timeout,
        },
        FetchUrlError::ValidationTask(_) => TokenError::Transport {
            kind: super::TransportKind::Exchange,
        },
        FetchUrlError::ClientBuild(_) | FetchUrlError::OutboundClientBuild(_) => {
            TokenError::Configuration {
                reason: "the DNS-pinned token endpoint client could not be built",
            }
        }
        _ => TokenError::Configuration {
            reason: "the token endpoint is not permitted by the outbound fetch policy",
        },
    }
}

/// The transport refusals both clients make about an endpoint a secret travels
/// to: it carries no credentials or fragment, and is reached over https or over
/// HTTP on a loopback host. Each caller words the two refusals for its own
/// endpoints.
pub(super) fn check_endpoint(
    endpoint: &Url,
    carrying_userinfo_or_fragment: &'static str,
    unprotected_transport: &'static str,
) -> Result<(), TokenError> {
    let refuse = |reason: &'static str| TokenError::Configuration { reason };
    if !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(refuse(carrying_userinfo_or_fragment));
    }
    if !outbound::transport_protects_the_credential(endpoint) {
        return Err(refuse(unprotected_transport));
    }
    Ok(())
}

/// A string member of a response that is wiped when dropped, so a token a
/// client rejects on any path is not left behind in freed memory. The JSON
/// reader's own scratch buffer for escaped strings is out of reach.
pub(super) struct WipedString(Zeroizing<String>);

impl WipedString {
    /// The string, moved out so its new owner wipes it.
    pub(super) fn into_inner(mut self) -> String {
        std::mem::take(&mut *self.0)
    }

    pub(super) fn into_zeroizing(self) -> Zeroizing<String> {
        self.0
    }
}

impl<'de> Deserialize<'de> for WipedString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|value| Self(Zeroizing::new(value)))
    }
}

/// The error for a token the server sent that the client cannot use. That is
/// the server's fault, not the caller's input, so it is a protocol failure for
/// whichever client read the answer.
pub(super) fn unusable_token(status: u16) -> impl Fn(TokenError) -> TokenError + Copy {
    move |_| TokenError::Protocol { status }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_response_content_type_must_appear_exactly_once() {
        let mut headers = HeaderMap::new();
        assert_eq!(exact_content_type(&headers), None);
        headers.append(CONTENT_TYPE, "application/json".parse().expect("header"));
        assert_eq!(exact_content_type(&headers), Some("application/json"));
        headers.append(CONTENT_TYPE, "application/json".parse().expect("header"));
        assert_eq!(exact_content_type(&headers), None);
    }
}
