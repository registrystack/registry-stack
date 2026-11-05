// SPDX-License-Identifier: Apache-2.0

//! Offline fixture replay state.
//!
//! A replay transcript is the only outbound transport available to a
//! replay-loaded adapter. It owns one fixture entry's ordered exchanges and
//! consumes exactly one exchange for every token or data send. It performs no
//! I/O and never resolves a credential.

use std::fmt;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use registry_adapter_core::{
    answer_send, AdapterFixture, ErrorClass, HttpMethod, RecordedExchange, RecordedHeaders,
    RecordedResponse, ReplayMismatch, Send,
};
use tokio::sync::Mutex as AsyncMutex;
use zeroize::Zeroizing;

use std::pin::Pin;

use crate::exchange::{Exchange, WriteClaim, MAX_IDEMPOTENCY_KEY_BYTES};
use crate::route::RouteFailure;

/// A sealed marker that only this module can construct: the exchange's
/// simulated write slot accepts nothing else, so the in-memory write
/// state of offline replay reaches an exchange only through
/// [`ReplayWriteContext::install`].
pub(crate) struct ReplayWriteCapability(());

/// A deterministic nonce capability that only offline replay can construct.
/// Production cursor sealing never receives one and keeps using OS randomness.
pub struct ReplayCursorNonce(pub [u8; 24]);

impl ReplayCursorNonce {
    pub(crate) fn into_bytes(self) -> [u8; 24] {
        self.0
    }
}

pub const REPLAY_DEPLOYMENT: &str = "fixture-replay-v1";
pub const REPLAY_CURSOR_ISSUER: &str = "https://fixture-replay.invalid";
pub const REPLAY_CURSOR_SUBJECT: &str = "synthetic-fixture-caller";
pub const REPLAY_CURSOR_CLIENT: &str = "fixture-replay-client";
pub const REPLAY_CURSOR_CLOCK_SECONDS: u64 = 1_700_000_000;
pub const REPLAY_CURSOR_KEY_BYTE: u8 = 0x52;
/// The fixed source key generation of every replayed write, so a fixture can
/// pin the derived source key byte-for-byte.
pub const REPLAY_SOURCE_KEY_GENERATION: &str = "00000000000000000000000000000000";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplayWriteState {
    Ready,
    Claimed { effect_started: bool, eager: bool },
    UnsupportedIncomplete,
    Released,
}

/// Replay-only state for exercising the real idempotent-consumer processor.
/// It proves route control flow, never PostgreSQL durability or duplicate-key
/// behavior.
#[derive(Debug)]
pub struct ReplayWriteContext {
    state: AsyncMutex<ReplayWriteState>,
}

impl ReplayWriteContext {
    /// Install a fresh simulated write state on one replay exchange and
    /// return it for the terminal check. An exchange that already holds
    /// a real custody capability or a simulation refuses with `facade`.
    pub fn install(exchange: &mut Exchange) -> Result<Arc<Self>, RouteFailure> {
        let context = Arc::new(Self {
            state: AsyncMutex::new(ReplayWriteState::Ready),
        });
        exchange.install_replay_write(context.clone(), ReplayWriteCapability(()))?;
        Ok(context)
    }
}

/// The simulated capability behind the engine's custody seam: route
/// control flow only, never PostgreSQL durability or duplicate-key
/// behavior.
impl crate::exchange::WriteCustody for ReplayWriteContext {
    fn claim<'a>(
        &'a self,
        key: &'a str,
        eager: bool,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = Result<WriteClaim, RouteFailure>>
                + std::marker::Send
                + 'a,
        >,
    > {
        Box::pin(async move { ReplayWriteContext::claim(self, key, eager).await })
    }

    fn before_effect<'a>(
        &'a self,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), RouteFailure>> + std::marker::Send + 'a>>
    {
        Box::pin(async move { ReplayWriteContext::before_upstream_effect(self).await })
    }

    fn before_resume_step<'a>(
        &'a self,
        _ordinal: u32,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), RouteFailure>> + std::marker::Send + 'a>>
    {
        Box::pin(async move { ReplayWriteContext::before_upstream_effect(self).await })
    }

    fn checkpoint_resume_step<'a>(
        &'a self,
        _ordinal: u32,
        _bindings: Vec<crate::ResumeValue>,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), RouteFailure>> + std::marker::Send + 'a>>
    {
        Box::pin(async { Ok(()) })
    }

    fn mark_definitive_source_rejection<'a>(
        &'a self,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), RouteFailure>> + std::marker::Send + 'a>>
    {
        Box::pin(async move { ReplayWriteContext::mark_definitive_source_rejection(self).await })
    }

    fn source_key_generation(&self) -> Option<String> {
        Some(REPLAY_SOURCE_KEY_GENERATION.to_owned())
    }

    fn mark_unsupported_incomplete<'a>(
        &'a self,
    ) -> Pin<
        Box<dyn std::future::Future<Output = Result<bool, RouteFailure>> + std::marker::Send + 'a>,
    > {
        Box::pin(async move {
            ReplayWriteContext::mark_unsupported_incomplete(self)
                .await
                .map(|()| true)
        })
    }

    fn complete<'a>(
        &'a self,
        succeeded: bool,
        remove_on_failure: bool,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), RouteFailure>> + std::marker::Send + 'a>>
    {
        Box::pin(
            async move { ReplayWriteContext::complete(self, succeeded, remove_on_failure).await },
        )
    }
}

impl ReplayWriteContext {
    async fn claim(&self, key: &str, eager: bool) -> Result<WriteClaim, RouteFailure> {
        if key.is_empty() || key.len() > MAX_IDEMPOTENCY_KEY_BYTES || key.contains('\0') {
            return Err(RouteFailure::of(ErrorClass::FacadeInvalidField));
        }
        let mut state = self.state.lock().await;
        if *state != ReplayWriteState::Ready {
            return Err(RouteFailure::of(ErrorClass::Facade));
        }
        *state = ReplayWriteState::Claimed {
            effect_started: false,
            eager,
        };
        Ok(WriteClaim::Execute)
    }

    pub(crate) async fn before_upstream_effect(&self) -> Result<(), RouteFailure> {
        let mut state = self.state.lock().await;
        let ReplayWriteState::Claimed { effect_started, .. } = &mut *state else {
            return Err(RouteFailure::of(ErrorClass::Facade));
        };
        *effect_started = true;
        Ok(())
    }

    async fn mark_definitive_source_rejection(&self) -> Result<(), RouteFailure> {
        let state = self.state.lock().await;
        if matches!(
            *state,
            ReplayWriteState::Claimed {
                effect_started: true,
                ..
            }
        ) {
            Ok(())
        } else {
            Err(RouteFailure::of(ErrorClass::Facade))
        }
    }

    async fn complete(&self, succeeded: bool, remove_on_failure: bool) -> Result<(), RouteFailure> {
        let mut state = self.state.lock().await;
        match *state {
            ReplayWriteState::Claimed {
                effect_started: false,
                eager,
            } if !succeeded && (!eager || remove_on_failure) => {
                *state = ReplayWriteState::Released;
                Ok(())
            }
            ReplayWriteState::Claimed { .. } | ReplayWriteState::UnsupportedIncomplete => Ok(()),
            ReplayWriteState::Ready | ReplayWriteState::Released => {
                Err(RouteFailure::of(ErrorClass::Facade))
            }
        }
    }

    pub(crate) async fn mark_unsupported_incomplete(&self) -> Result<(), RouteFailure> {
        let mut state = self.state.lock().await;
        let ReplayWriteState::Claimed { effect_started, .. } = &mut *state else {
            return Err(RouteFailure::of(ErrorClass::Facade));
        };
        *effect_started = true;
        *state = ReplayWriteState::UnsupportedIncomplete;
        Ok(())
    }

    pub async fn is_unsupported_incomplete(&self) -> bool {
        *self.state.lock().await == ReplayWriteState::UnsupportedIncomplete
    }

    pub async fn was_claimed(&self) -> bool {
        matches!(
            *self.state.lock().await,
            ReplayWriteState::Claimed { .. }
                | ReplayWriteState::UnsupportedIncomplete
                | ReplayWriteState::Released
        )
    }
}

/// A fixture could not be driven as its transcript declares.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayFailure {
    /// The requested fixture entry does not exist.
    EntryMissing,
    /// The core send contract did not match the next recorded exchange.
    Send(ReplayMismatch),
    /// The outgoing header names or values differ from the recording.
    Header,
    /// The outgoing headers are not in the recording's normalized order.
    HeaderOrder,
    /// Replay ended before every recorded exchange was consumed.
    Leftover,
    /// An OAuth endpoint has no recorded token request.
    TokenMissing,
    /// A host-protocol response recorded neither `rawBodyBase64` nor `body`.
    ProtocolBodyMissing,
    /// A host protocol that verifies exact response bytes was given a
    /// readable `body` instead of `rawBodyBase64`.
    ProtocolBodyNotRaw,
    /// A recorded `rawBodyBase64` is not valid base64.
    ProtocolBodyInvalid,
    /// A recorded host-protocol response exceeds the endpoint byte bound.
    ProtocolBodyTooLarge,
    /// An endpoint without a host protocol recorded `rawBodyBase64`.
    RawBodyOnOrdinaryEndpoint,
}

impl fmt::Display for ReplayFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EntryMissing => "the fixture entry does not exist",
            Self::Send(ReplayMismatch::NotIntercepted) => {
                "the fixture does not intercept the outgoing send"
            }
            Self::Send(ReplayMismatch::Exhausted) => {
                "the route made more sends than the fixture recorded"
            }
            Self::Send(ReplayMismatch::Endpoint) => {
                "the outgoing endpoint differs from the next recorded send"
            }
            Self::Send(ReplayMismatch::TokenRequest) => {
                "the outgoing send kind differs from the next recorded send"
            }
            Self::Send(ReplayMismatch::Method) => {
                "the outgoing method differs from the next recorded send"
            }
            Self::Send(ReplayMismatch::Path) => {
                "the outgoing path differs from the next recorded send"
            }
            Self::Send(ReplayMismatch::Query) => {
                "the outgoing query differs from the next recorded send"
            }
            Self::Send(ReplayMismatch::BodyDigest) => {
                "the outgoing body digest differs from the next recorded send"
            }
            Self::Header => {
                "the outgoing header names or values differ from the next recorded send"
            }
            Self::HeaderOrder => "the outgoing header order differs from the next recorded send",
            Self::Leftover => "the route made fewer sends than the fixture recorded",
            Self::TokenMissing => "the OAuth endpoint has no recorded token request",
            Self::ProtocolBodyMissing => {
                "the recorded host-protocol response has no body; record it as `rawBodyBase64`, or as a JSON `body` when the protocol verifies no signature"
            }
            Self::ProtocolBodyNotRaw => {
                "this host protocol verifies the exact response bytes; record the response as `rawBodyBase64`, not `body`"
            }
            Self::ProtocolBodyInvalid => "the recorded `rawBodyBase64` is not valid base64",
            Self::ProtocolBodyTooLarge => {
                "the recorded host-protocol response is larger than the endpoint `maximumResponseBytes`"
            }
            Self::RawBodyOnOrdinaryEndpoint => {
                "this endpoint has no host protocol, so record its response as a JSON `body`, not `rawBodyBase64`"
            }
        })
    }
}

impl std::error::Error for ReplayFailure {}

#[derive(Debug)]
struct ReplayState {
    cursor: usize,
    first_failure: Option<ReplayFailure>,
}

enum ReplayRequestHeaders<'a> {
    Ordered(&'a [(&'a str, &'a str)]),
    ByName(&'a [(&'a str, &'a str)]),
}

/// One fixture entry's bounded, ordered, network-free outbound transcript.
#[derive(Debug)]
pub struct ReplayTranscript {
    intercepts: Vec<registry_adapter_core::Intercept>,
    exchanges: Vec<RecordedExchange>,
    state: Mutex<ReplayState>,
}

/// Proof that synthetic credential material is being produced only for an
/// offline fixture transcript. The field is private to this module, so live
/// runtime construction cannot select replay authorization.
#[derive(Clone, Copy)]
pub(crate) struct ReplayAuthCapability(());

pub(crate) struct RecordedProtocolResponse {
    pub status: u16,
    pub headers: RecordedHeaders,
    pub body: Zeroizing<Vec<u8>>,
}

pub(crate) struct ProtocolReplaySend<'a> {
    pub endpoint: &'a str,
    pub method: HttpMethod,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub body: Option<&'a serde_json::Value>,
    pub headers: &'a [(&'a str, &'a str)],
    pub maximum_response_bytes: usize,
    /// The selected protocol verifies no signature over the response bytes,
    /// so a fixture may record its JSON response as a readable `body`.
    pub readable_body: bool,
}

impl ReplayTranscript {
    /// Build one sealed transcript directly from an already checked fixture
    /// closure. Evidence package checks use this form because they have no
    /// facade request or response envelope to fabricate.
    #[must_use]
    pub fn from_exchanges(
        intercepts: Vec<registry_adapter_core::Intercept>,
        exchanges: Vec<RecordedExchange>,
    ) -> Self {
        Self {
            intercepts,
            exchanges,
            state: Mutex::new(ReplayState {
                cursor: 0,
                first_failure: None,
            }),
        }
    }

    /// Select one fixture entry for execution.
    ///
    /// # Errors
    ///
    /// [`ReplayFailure::EntryMissing`] when `entry_index` is outside the
    /// suite.
    pub fn new(fixture: &AdapterFixture, entry_index: usize) -> Result<Self, ReplayFailure> {
        let entry = fixture
            .entries
            .get(entry_index)
            .ok_or(ReplayFailure::EntryMissing)?;
        Ok(Self::from_exchanges(
            fixture.intercepts.clone(),
            entry.upstream.clone(),
        ))
    }

    pub(crate) const fn auth_capability(&self) -> ReplayAuthCapability {
        ReplayAuthCapability(())
    }

    /// Answer one ordinary endpoint send from the next recorded exchange.
    /// The headers are compared after ASCII-lowercasing their names, with
    /// their values and order unchanged.
    pub fn answer_data(
        &self,
        endpoint: &str,
        method: HttpMethod,
        path: &str,
        query: Option<&str>,
        body: Option<&serde_json::Value>,
        headers: &[(&str, &str)],
    ) -> Result<RecordedResponse, ReplayFailure> {
        let response = self.answer(
            Send {
                endpoint,
                token_request: false,
                method,
                path,
                query,
                body,
            },
            Some(ReplayRequestHeaders::Ordered(headers)),
        )?;
        if response.raw_body_base64.is_some() {
            return Err(self.remember_failure(ReplayFailure::RawBodyOnOrdinaryEndpoint));
        }
        Ok(response)
    }

    /// Answer one selected host-protocol send with exact bounded wire bytes.
    /// The encoded-length check runs before allocating the decoded buffer. A
    /// protocol that verifies no signature may replay a readable JSON `body`,
    /// answered as its compact JSON bytes.
    pub(crate) fn answer_protocol(
        &self,
        send: ProtocolReplaySend<'_>,
    ) -> Result<RecordedProtocolResponse, ReplayFailure> {
        let response = self.answer(
            Send {
                endpoint: send.endpoint,
                token_request: false,
                method: send.method,
                path: send.path,
                query: send.query,
                body: send.body,
            },
            Some(ReplayRequestHeaders::ByName(send.headers)),
        )?;
        let body = match (response.raw_body_base64.as_deref(), response.body.as_ref()) {
            // The fixture reader refuses a response that records both forms.
            (Some(encoded), _) => {
                let maximum_encoded = send
                    .maximum_response_bytes
                    .checked_add(2)
                    .and_then(|value| value.checked_div(3))
                    .and_then(|value| value.checked_mul(4))
                    .ok_or_else(|| self.remember_failure(ReplayFailure::ProtocolBodyTooLarge))?;
                if encoded.len() > maximum_encoded {
                    return Err(self.remember_failure(ReplayFailure::ProtocolBodyTooLarge));
                }
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(|_| self.remember_failure(ReplayFailure::ProtocolBodyInvalid))?
            }
            (None, Some(_)) if !send.readable_body => {
                return Err(self.remember_failure(ReplayFailure::ProtocolBodyNotRaw));
            }
            (None, Some(readable)) => serde_json::to_vec(readable.as_value())
                .map_err(|_| self.remember_failure(ReplayFailure::ProtocolBodyInvalid))?,
            (None, None) => {
                return Err(self.remember_failure(ReplayFailure::ProtocolBodyMissing));
            }
        };
        if body.len() > send.maximum_response_bytes {
            return Err(self.remember_failure(ReplayFailure::ProtocolBodyTooLarge));
        }
        Ok(RecordedProtocolResponse {
            status: response.status.get() as u16,
            headers: response.headers,
            body: Zeroizing::new(body),
        })
    }

    /// Answer one token send without accepting or comparing credential
    /// headers or a credential-bearing body. Replay matches the endpoint,
    /// method, path, and send position only.
    pub fn answer_token(
        &self,
        endpoint: &str,
        method: HttpMethod,
        path: &str,
    ) -> Result<RecordedResponse, ReplayFailure> {
        self.answer(
            Send {
                endpoint,
                token_request: true,
                method,
                path,
                query: None,
                body: None,
            },
            None,
        )
    }

    /// The path of this endpoint's first recorded token request. Replay
    /// uses it to compile a synthetic token plan without reading a runtime
    /// credential or destination.
    pub(crate) fn token_path(&self, endpoint: &str) -> Option<&str> {
        self.exchanges
            .iter()
            .find(|exchange| {
                exchange.request.token_request && exchange.request.endpoint.as_str() == endpoint
            })
            .map(|exchange| exchange.request.path.as_str())
    }

    pub fn records_endpoint(&self, endpoint: &str) -> bool {
        self.exchanges
            .iter()
            .any(|exchange| exchange.request.endpoint.as_str() == endpoint)
    }

    fn answer(
        &self,
        send: Send<'_>,
        headers: Option<ReplayRequestHeaders<'_>>,
    ) -> Result<RecordedResponse, ReplayFailure> {
        let mut state = self.state.lock().expect("replay state mutex poisoned");
        if let Some(failure) = state.first_failure {
            return Err(failure);
        }
        let recorded_headers = self
            .exchanges
            .get(state.cursor)
            .map(|exchange| &exchange.request.headers);
        let answer = answer_send(&self.intercepts, &self.exchanges, &mut state.cursor, &send)
            .map_err(ReplayFailure::Send);
        let answer = match answer {
            Ok(answer) => answer.clone(),
            Err(failure) => {
                state.first_failure = Some(failure);
                return Err(failure);
            }
        };
        if let (Some(actual), Some(expected)) = (headers, recorded_headers) {
            let matched = match actual {
                ReplayRequestHeaders::Ordered(headers) => match_headers(expected, headers),
                ReplayRequestHeaders::ByName(headers) => match_protocol_headers(expected, headers),
            };
            if let Err(failure) = matched {
                state.first_failure = Some(failure);
                return Err(failure);
            }
        }
        Ok(answer)
    }

    fn remember_failure(&self, failure: ReplayFailure) -> ReplayFailure {
        let mut state = self.state.lock().expect("replay state mutex poisoned");
        state.first_failure.get_or_insert(failure);
        failure
    }

    /// Require the route to have consumed the complete transcript.
    ///
    /// # Errors
    ///
    /// The first send mismatch, or [`ReplayFailure::Leftover`] when the
    /// route completed before consuming every recorded exchange.
    pub fn finish(&self) -> Result<(), ReplayFailure> {
        let state = self.state.lock().expect("replay state mutex poisoned");
        if let Some(failure) = state.first_failure {
            return Err(failure);
        }
        if state.cursor != self.exchanges.len() {
            return Err(ReplayFailure::Leftover);
        }
        Ok(())
    }
}

/// A sealed protocol owns its header set, while recordings are name maps.
/// Match each case-insensitive name exactly once and retain exact values.
fn match_protocol_headers(
    expected: &RecordedHeaders,
    actual: &[(&str, &str)],
) -> Result<(), ReplayFailure> {
    if expected.len() != actual.len() {
        return Err(ReplayFailure::Header);
    }
    let mut remaining = std::collections::BTreeMap::new();
    for (name, value) in expected {
        if remaining
            .insert(name.to_ascii_lowercase(), value.as_str())
            .is_some()
        {
            return Err(ReplayFailure::Header);
        }
    }
    for (name, value) in actual {
        if remaining.remove(&name.to_ascii_lowercase()) != Some(*value) {
            return Err(ReplayFailure::Header);
        }
    }
    Ok(())
}

/// Whether the headers a send carried match the recorded header set,
/// in order and by value: the transcript's own matching rule, shared by
/// the write capability's checks and the replay runner's assertions.
pub(crate) fn match_headers(
    expected: &RecordedHeaders,
    actual: &[(&str, &str)],
) -> Result<(), ReplayFailure> {
    if expected.len() != actual.len() {
        return Err(ReplayFailure::Header);
    }
    for ((expected_name, expected_value), (actual_name, actual_value)) in
        expected.iter().zip(actual)
    {
        if !expected_name.eq_ignore_ascii_case(actual_name) {
            let same_members = expected.iter().all(|(name, value)| {
                actual.iter().any(|(actual_name, actual_value)| {
                    name.eq_ignore_ascii_case(actual_name) && value == actual_value
                })
            });
            return Err(if same_members {
                ReplayFailure::HeaderOrder
            } else {
                ReplayFailure::Header
            });
        }
        if expected_value != actual_value {
            return Err(ReplayFailure::Header);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn definitive_source_rejection_is_inert_but_requires_a_started_effect() {
        let before_effect = ReplayWriteContext {
            state: AsyncMutex::new(ReplayWriteState::Ready),
        };
        before_effect
            .claim("fixture-key", true)
            .await
            .expect("the fixture write is claimed");
        assert!(before_effect
            .mark_definitive_source_rejection()
            .await
            .is_err());

        let after_effect = ReplayWriteContext {
            state: AsyncMutex::new(ReplayWriteState::Ready),
        };
        after_effect
            .claim("fixture-key", true)
            .await
            .expect("the fixture write is claimed");
        after_effect
            .before_upstream_effect()
            .await
            .expect("the source attempt starts");
        after_effect
            .mark_definitive_source_rejection()
            .await
            .expect("the terminal non-effect is accepted");
        after_effect
            .complete(false, true)
            .await
            .expect("the failed fixture route completes");

        assert!(after_effect.was_claimed().await);
    }

    fn raw_transcript(wire: &[u8]) -> ReplayTranscript {
        raw_transcript_with_headers(wire, serde_json::json!({}))
    }

    fn raw_transcript_with_headers(wire: &[u8], headers: serde_json::Value) -> ReplayTranscript {
        let intercepts = serde_json::from_value(serde_json::json!([
            {"type": "endpoint", "endpoint": "register"}
        ]))
        .expect("intercepts");
        let exchanges = serde_json::from_value(serde_json::json!([{
            "request": {
                "endpoint": "register",
                "method": "POST",
                "path": "/v1/evidence",
                "body": {"requestNonce": "fixed-fixture-nonce"},
                "headers": headers
            },
            "response": {
                "status": 200,
                "rawBodyBase64": base64::engine::general_purpose::STANDARD.encode(wire)
            }
        }]))
        .expect("raw exchange");
        ReplayTranscript::from_exchanges(intercepts, exchanges)
    }

    #[test]
    fn protocol_replay_preserves_exact_wire_bytes_and_bounds_before_decode() {
        let wire = b" \n {\"signed\" : true} \n ";
        let request = serde_json::json!({"requestNonce": "fixed-fixture-nonce"});
        let transcript = raw_transcript(wire);
        let response = transcript
            .answer_protocol(ProtocolReplaySend {
                endpoint: "register",
                method: HttpMethod::Post,
                path: "/v1/evidence",
                query: None,
                body: Some(&request),
                headers: &[],
                maximum_response_bytes: wire.len(),
                readable_body: false,
            })
            .expect("exact raw response");
        assert_eq!(response.body.as_slice(), wire);
        transcript.finish().expect("complete transcript");

        let bounded = raw_transcript(wire);
        assert!(matches!(
            bounded.answer_protocol(ProtocolReplaySend {
                endpoint: "register",
                method: HttpMethod::Post,
                path: "/v1/evidence",
                query: None,
                body: Some(&request),
                headers: &[],
                maximum_response_bytes: wire.len() - 1,
                readable_body: false,
            }),
            Err(ReplayFailure::ProtocolBodyTooLarge)
        ));
    }

    #[test]
    fn protocol_replay_matches_distinct_header_names_independently_of_transport_order() {
        let transcript = raw_transcript_with_headers(
            b"{}",
            serde_json::json!({
                "registry-access-purpose":"eligibility",
                "registry-access-requester":"verified-requester"
            }),
        );
        let request = serde_json::json!({"requestNonce":"fixed-fixture-nonce"});
        transcript
            .answer_protocol(ProtocolReplaySend {
                endpoint: "register",
                method: HttpMethod::Post,
                path: "/v1/evidence",
                query: None,
                body: Some(&request),
                headers: &[
                    ("Registry-Access-Requester", "verified-requester"),
                    ("registry-access-purpose", "eligibility"),
                ],
                maximum_response_bytes: 64,
                readable_body: false,
            })
            .expect("a recorded header map does not prescribe HTTP field order");
        transcript
            .finish()
            .expect("the exact exchange was consumed");
    }

    #[test]
    fn protocol_replay_refuses_duplicate_missing_extra_and_changed_header_values() {
        let cases: &[&[(&str, &str)]] = &[
            &[("registry-access-requester", "verified-requester")],
            &[
                ("registry-access-purpose", "eligibility"),
                ("registry-access-requester", "wrong"),
            ],
            &[
                ("registry-access-purpose", "eligibility"),
                ("registry-access-requester", "verified-requester"),
                ("x-extra", "extra"),
            ],
            &[
                ("registry-access-purpose", "eligibility"),
                ("Registry-Access-Purpose", "eligibility"),
            ],
        ];
        for headers in cases {
            let transcript = raw_transcript_with_headers(
                b"{}",
                serde_json::json!({
                    "registry-access-purpose":"eligibility",
                    "registry-access-requester":"verified-requester"
                }),
            );
            let request = serde_json::json!({"requestNonce":"fixed-fixture-nonce"});
            assert!(transcript
                .answer_protocol(ProtocolReplaySend {
                    endpoint: "register",
                    method: HttpMethod::Post,
                    path: "/v1/evidence",
                    query: None,
                    body: Some(&request),
                    headers,
                    maximum_response_bytes: 64,
                    readable_body: false,
                })
                .is_err());
            assert!(transcript.finish().is_err());
        }
    }

    #[test]
    fn ordinary_replay_cannot_decode_a_raw_protocol_body() {
        let wire = b"{\"signed\":true}";
        let request = serde_json::json!({"requestNonce": "fixed-fixture-nonce"});
        let transcript = raw_transcript(wire);
        assert!(matches!(
            transcript.answer_data(
                "register",
                HttpMethod::Post,
                "/v1/evidence",
                None,
                Some(&request),
                &[],
            ),
            Err(ReplayFailure::RawBodyOnOrdinaryEndpoint)
        ));
    }

    fn protocol_transcript(response: serde_json::Value) -> ReplayTranscript {
        let intercepts = serde_json::from_value(serde_json::json!([
            {"type": "endpoint", "endpoint": "register"}
        ]))
        .expect("intercepts");
        let exchanges = serde_json::from_value(serde_json::json!([{
            "request": {"endpoint": "register", "method": "GET", "path": "/v1/records/r-1"},
            "response": response
        }]))
        .expect("protocol exchange");
        ReplayTranscript::from_exchanges(intercepts, exchanges)
    }

    fn answer_lookup(
        transcript: &ReplayTranscript,
        readable_body: bool,
        maximum_response_bytes: usize,
    ) -> Result<RecordedProtocolResponse, ReplayFailure> {
        transcript.answer_protocol(ProtocolReplaySend {
            endpoint: "register",
            method: HttpMethod::Get,
            path: "/v1/records/r-1",
            query: None,
            body: None,
            headers: &[],
            maximum_response_bytes,
            readable_body,
        })
    }

    #[test]
    fn a_readable_body_answers_a_protocol_that_verifies_no_signature() {
        let problem = serde_json::json!({"type": "urn:example:not-found", "status": 404});
        let transcript =
            protocol_transcript(serde_json::json!({"status": 404, "body": problem.clone()}));
        let response = answer_lookup(&transcript, true, 1024).expect("a readable lookup body");
        assert_eq!(response.status, 404);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&response.body).expect("JSON bytes"),
            problem
        );
        transcript.finish().expect("complete transcript");

        let signed = protocol_transcript(serde_json::json!({"status": 404, "body": problem}));
        assert!(matches!(
            answer_lookup(&signed, false, 1024),
            Err(ReplayFailure::ProtocolBodyNotRaw)
        ));
        let small = protocol_transcript(serde_json::json!({"status": 200, "body": {"a": "bb"}}));
        assert!(matches!(
            answer_lookup(&small, true, 4),
            Err(ReplayFailure::ProtocolBodyTooLarge)
        ));
    }

    #[test]
    fn each_protocol_body_fault_names_its_own_cause() {
        let missing = protocol_transcript(serde_json::json!({"status": 204}));
        assert_eq!(
            answer_lookup(&missing, false, 64).err(),
            Some(ReplayFailure::ProtocolBodyMissing)
        );
        let invalid =
            protocol_transcript(serde_json::json!({"status": 200, "rawBodyBase64": "not base64!"}));
        assert_eq!(
            answer_lookup(&invalid, false, 64).err(),
            Some(ReplayFailure::ProtocolBodyInvalid)
        );
        let causes = [
            ReplayFailure::ProtocolBodyMissing,
            ReplayFailure::ProtocolBodyNotRaw,
            ReplayFailure::ProtocolBodyInvalid,
            ReplayFailure::ProtocolBodyTooLarge,
            ReplayFailure::RawBodyOnOrdinaryEndpoint,
        ]
        .map(|failure| failure.to_string());
        let distinct = causes.iter().collect::<std::collections::BTreeSet<_>>();
        assert_eq!(distinct.len(), causes.len(), "{causes:?}");
        assert!(causes[0].contains("rawBodyBase64") && causes[0].contains("`body`"));
        assert!(causes[1].contains("rawBodyBase64"));
        assert!(causes[3].contains("maximumResponseBytes"));
        assert!(causes[4].contains("`body`"));
    }
}
