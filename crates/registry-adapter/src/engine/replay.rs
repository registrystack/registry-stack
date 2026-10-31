// SPDX-License-Identifier: Apache-2.0

//! Offline fixture replay state.
//!
//! A replay transcript is the only outbound transport available to a
//! replay-loaded adapter. It owns one fixture entry's ordered exchanges and
//! consumes exactly one exchange for every token or data send. It performs no
//! I/O and never resolves a credential.

use std::fmt;
use std::sync::{Arc, Mutex};

use registry_adapter_core::{
    answer_send, AdapterFixture, ErrorClass, HttpMethod, RecordedExchange, RecordedHeaders,
    RecordedResponse, ReplayMismatch, Send,
};
use tokio::sync::Mutex as AsyncMutex;

use std::pin::Pin;

use crate::engine::exchange::{WriteClaim, MAX_IDEMPOTENCY_KEY_BYTES};
use crate::engine::route::RouteFailure;

/// A sealed marker that permits only this module's runner to install the
/// in-memory write state used by offline replay.
pub(crate) struct ReplayWriteCapability(pub(crate) ());

/// A deterministic nonce capability that only offline replay can construct.
/// Production cursor sealing never receives one and keeps using OS randomness.
pub(crate) struct ReplayCursorNonce(pub(crate) [u8; 24]);

impl ReplayCursorNonce {
    pub(crate) fn into_bytes(self) -> [u8; 24] {
        self.0
    }
}

pub(crate) const REPLAY_DEPLOYMENT: &str = "fixture-replay-v1";
pub(crate) const REPLAY_CURSOR_ISSUER: &str = "https://fixture-replay.invalid";
pub(crate) const REPLAY_CURSOR_SUBJECT: &str = "synthetic-fixture-caller";
pub(crate) const REPLAY_CURSOR_CLOCK_SECONDS: u64 = 1_700_000_000;
pub(crate) const REPLAY_CURSOR_KEY_BYTE: u8 = 0x52;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplayWriteState {
    Ready,
    Claimed { effect_started: bool },
    UnsupportedIncomplete,
    Released,
}

/// Replay-only state for exercising the real idempotent-consumer processor.
/// It proves route control flow, never PostgreSQL durability or duplicate-key
/// behavior.
#[derive(Debug)]
pub(crate) struct ReplayWriteContext {
    state: AsyncMutex<ReplayWriteState>,
}

impl ReplayWriteContext {
    pub(crate) fn new(_capability: ReplayWriteCapability) -> Arc<Self> {
        Arc::new(Self {
            state: AsyncMutex::new(ReplayWriteState::Ready),
        })
    }
}

/// The simulated capability behind the engine's custody seam: route
/// control flow only, never PostgreSQL durability or duplicate-key
/// behavior.
impl crate::engine::exchange::WriteCustody for ReplayWriteContext {
    fn claim<'a>(
        &'a self,
        key: &'a str,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = Result<WriteClaim, RouteFailure>>
                + std::marker::Send
                + 'a,
        >,
    > {
        Box::pin(async move { ReplayWriteContext::claim(self, key).await })
    }

    fn before_effect<'a>(
        &'a self,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), RouteFailure>> + std::marker::Send + 'a>>
    {
        Box::pin(async move { ReplayWriteContext::before_upstream_effect(self).await })
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

    fn release_before_effect<'a>(
        &'a self,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), RouteFailure>> + std::marker::Send + 'a>>
    {
        Box::pin(async move { ReplayWriteContext::release_before_effect(self).await })
    }
}

impl ReplayWriteContext {
    async fn claim(&self, key: &str) -> Result<WriteClaim, RouteFailure> {
        if key.is_empty() || key.len() > MAX_IDEMPOTENCY_KEY_BYTES || key.contains('\0') {
            return Err(RouteFailure::of(ErrorClass::FacadeInvalidField));
        }
        let mut state = self.state.lock().await;
        if *state != ReplayWriteState::Ready {
            return Err(RouteFailure::of(ErrorClass::Facade));
        }
        *state = ReplayWriteState::Claimed {
            effect_started: false,
        };
        Ok(WriteClaim::Execute)
    }

    pub(crate) async fn before_upstream_effect(&self) -> Result<(), RouteFailure> {
        let mut state = self.state.lock().await;
        let ReplayWriteState::Claimed { effect_started } = &mut *state else {
            return Err(RouteFailure::of(ErrorClass::Facade));
        };
        *effect_started = true;
        Ok(())
    }

    pub(crate) async fn release_before_effect(&self) -> Result<(), RouteFailure> {
        let mut state = self.state.lock().await;
        match *state {
            ReplayWriteState::Claimed {
                effect_started: false,
            } => {
                *state = ReplayWriteState::Released;
                Ok(())
            }
            ReplayWriteState::Claimed {
                effect_started: true,
            } => Ok(()),
            ReplayWriteState::Ready
            | ReplayWriteState::UnsupportedIncomplete
            | ReplayWriteState::Released => Err(RouteFailure::of(ErrorClass::Facade)),
        }
    }

    pub(crate) async fn mark_unsupported_incomplete(&self) -> Result<(), RouteFailure> {
        let mut state = self.state.lock().await;
        let ReplayWriteState::Claimed { effect_started } = &mut *state else {
            return Err(RouteFailure::of(ErrorClass::Facade));
        };
        *effect_started = true;
        *state = ReplayWriteState::UnsupportedIncomplete;
        Ok(())
    }

    pub(crate) async fn is_unsupported_incomplete(&self) -> bool {
        *self.state.lock().await == ReplayWriteState::UnsupportedIncomplete
    }

    pub(crate) async fn was_claimed(&self) -> bool {
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
        })
    }
}

impl std::error::Error for ReplayFailure {}

#[derive(Debug)]
struct ReplayState {
    cursor: usize,
    first_failure: Option<ReplayFailure>,
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

impl ReplayTranscript {
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
        Ok(Self {
            intercepts: fixture.intercepts.clone(),
            exchanges: entry.upstream.clone(),
            state: Mutex::new(ReplayState {
                cursor: 0,
                first_failure: None,
            }),
        })
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
        self.answer(
            Send {
                endpoint,
                token_request: false,
                method,
                path,
                query,
                body,
            },
            Some(headers),
        )
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

    pub(crate) fn records_endpoint(&self, endpoint: &str) -> bool {
        self.exchanges
            .iter()
            .any(|exchange| exchange.request.endpoint.as_str() == endpoint)
    }

    fn answer(
        &self,
        send: Send<'_>,
        headers: Option<&[(&str, &str)]>,
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
            if let Err(failure) = match_headers(expected, actual) {
                state.first_failure = Some(failure);
                return Err(failure);
            }
        }
        Ok(answer)
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
