//! The request and response rules every token-endpoint client in this module
//! shares.
//!
//! The signed-assertion client and the client-secret client both post a form to
//! an endpoint the integrator named, read a bounded answer, and decide between a
//! refusal and a token response. Those steps live here once, so the two clients
//! cannot apply different rules to the same wire exchange.

use std::time::{Duration, Instant};

use bytes::Bytes;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::de::DeserializeOwned;
use url::Url;
use zeroize::Zeroizing;

use crate::{read_bounded, validate_response_headers_without_peer_policy, FetchUrlPolicy};

use super::{
    outbound,
    private_key_jwt::{
        declined, essence, exact_content_type, token_fetch_policy_failure, BEARER_TOKEN_TYPE,
        FORM_MEDIA_TYPE, JSON_MEDIA_TYPE, MAXIMUM_AUTHORIZATION_CODE_BYTES,
        MAXIMUM_CACHED_TOKEN_LIFETIME_SECONDS, MAXIMUM_TOKEN_RESPONSE_BYTES,
    },
    token::TokenError,
    TransportKind,
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

/// What the server answered, before it is read as a token response or a
/// refusal.
pub(super) struct Answer {
    pub(super) status: u16,
    media_type: Option<String>,
    /// The body, or why it could not be read. A caller that needs only the
    /// status never looks at it.
    body: Result<Zeroizing<Vec<u8>>, TransportKind>,
}

impl Answer {
    /// The body of an answer the caller must read. The status arrived before
    /// the body did, and for a refusal it is the whole of what would have been
    /// reported anyway, so only a body of a success is a transport failure.
    fn body(&self) -> Result<&[u8], TokenError> {
        match &self.body {
            Ok(body) => Ok(body),
            Err(_) if !(200..300).contains(&self.status) => Err(TokenError::Protocol {
                status: self.status,
            }),
            Err(kind) => Err(TokenError::Transport { kind: *kind }),
        }
    }

    /// Read a refusal, or the error for a status that is no refusal either.
    pub(super) fn into_refusal(self) -> TokenError {
        match self.body() {
            Ok(body) => declined(self.status, self.media_type.as_deref(), body),
            Err(error) => error,
        }
    }

    /// Read a token response: exactly a 200 in the one JSON media type, whose
    /// body is the response object. Anything else is a refusal or a protocol
    /// failure.
    pub(super) fn into_token_response<T: DeserializeOwned>(self) -> Result<T, TokenError> {
        let status = self.status;
        let body = self.body()?;
        if !(200..300).contains(&status) {
            return Err(declined(status, self.media_type.as_deref(), body));
        }
        if status != 200
            || !self
                .media_type
                .as_deref()
                .is_some_and(|value| essence(value).eq_ignore_ascii_case(JSON_MEDIA_TYPE))
        {
            return Err(TokenError::Protocol { status });
        }
        serde_json::from_slice(body).map_err(|_| TokenError::Protocol { status })
    }
}

/// One form POST to `endpoint`, its response read within the token response
/// bound.
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
    let body = read_bounded(response, MAXIMUM_TOKEN_RESPONSE_BYTES)
        .await
        // The response may carry a credential, so its buffer is wiped when the
        // answer is dropped.
        .map(Zeroizing::new)
        .map_err(|error| outbound::read_failure_kind(&error));
    Ok(Answer {
        status,
        media_type,
        body,
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
