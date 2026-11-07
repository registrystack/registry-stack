// SPDX-License-Identifier: Apache-2.0
//! Channel policy and the session context a presentation answers.

use registry_platform_crypto::SigningAlgorithm;
use serde::Deserialize;
use std::fmt;

/// Issuer signature algorithms a channel may accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum IssuerAlgorithm {
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "EdDSA")]
    EdDsa,
}

impl IssuerAlgorithm {
    pub(crate) const fn signing_algorithm(self) -> SigningAlgorithm {
        match self {
            Self::Es256 => SigningAlgorithm::Es256,
            Self::EdDsa => SigningAlgorithm::EdDsa,
        }
    }
}

fn default_kb_iat_window() -> u32 {
    120
}

fn default_clock_skew() -> u32 {
    60
}

fn default_algorithms() -> Vec<IssuerAlgorithm> {
    vec![IssuerAlgorithm::Es256, IssuerAlgorithm::EdDsa]
}

/// What one channel accepts.
///
/// Whether key binding is required is a policy value stated explicitly; it is
/// never inferred from whether a key-binding JWT arrived (RFC 9901 section 7.3).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelPolicy {
    /// Credential types (`vct`) the channel accepts. An empty list accepts none.
    pub vct: Vec<String>,
    /// Whether the presentation must carry a valid key-binding JWT.
    pub key_binding_required: bool,
    /// How far before `received_at` a key-binding JWT `iat` may lie, in seconds.
    #[serde(default = "default_kb_iat_window")]
    pub kb_iat_window_seconds: u32,
    /// Tolerance applied to `exp`, `nbf`, `iat` and the key-binding window's
    /// future edge, in seconds.
    #[serde(default = "default_clock_skew")]
    pub clock_skew_seconds: u32,
    /// Issuer signature algorithms accepted. An empty list accepts none.
    #[serde(default = "default_algorithms")]
    pub issuer_algorithms: Vec<IssuerAlgorithm>,
}

impl ChannelPolicy {
    /// A policy with the default window, skew and algorithms.
    #[must_use]
    pub fn new(vct: Vec<String>, key_binding_required: bool) -> Self {
        Self {
            vct,
            key_binding_required,
            kb_iat_window_seconds: default_kb_iat_window(),
            clock_skew_seconds: default_clock_skew(),
            issuer_algorithms: default_algorithms(),
        }
    }
}

/// The wallet session a presentation must answer.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionContext {
    /// The session nonce the key-binding JWT must carry.
    pub nonce: String,
    /// The full prefixed `client_id` (for example `x509_san_dns:verifier.example`)
    /// the key-binding JWT `aud` must equal.
    pub client_id: String,
    /// When the wallet response arrived, in Unix seconds.
    pub received_at: i64,
}

impl fmt::Debug for SessionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionContext")
            .field("nonce", &"[redacted]")
            .field("client_id", &self.client_id)
            .field("received_at", &self.received_at)
            .finish()
    }
}
