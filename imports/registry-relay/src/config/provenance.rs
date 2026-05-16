// SPDX-License-Identifier: Apache-2.0
//! Wave 3 provenance configuration.
//!
//! See `decisions/wave-3-data-provenance.md` Section 5 for the full
//! contract. The shape here mirrors the spec verbatim. The top-level
//! type is optional in [`crate::config::Config`] so existing wave-0 /
//! wave-2 deployments keep loading without change.
//!
//! Validation lives in [`crate::config::validate`]. This module owns
//! the data model only.

use std::time::Duration;

use serde::Deserialize;
use time::OffsetDateTime;

/// Top-level provenance block. When `enabled = false` (the default) the
/// wave is invisible: no routes are mounted, no Accept negotiation
/// runs, no audit events fire.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_accepted_media_types")]
    pub accepted_media_types: Vec<String>,
    pub schema_base_url: String,
    pub context_base_url: String,
    pub claim_validity: ClaimValidity,
    pub issuer: IssuerConfig,
}

fn default_accepted_media_types() -> Vec<String> {
    vec![
        "application/vc+jwt".to_string(),
        "application/jwt".to_string(),
    ]
}

/// Validity windows per claim type. Operators tune these via config.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimValidity {
    #[serde(with = "humantime_serde")]
    pub verify_result: Duration,
    #[serde(with = "humantime_serde")]
    pub aggregate_result: Duration,
    #[serde(with = "humantime_serde")]
    pub entity_record: Duration,
}

/// Issuer identity mode. `gateway` self-issues under the gateway's DID;
/// `delegated` signs under a ministry's DID using a key the gateway
/// controls. Tagged on `mode:` per spec §6.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum IssuerConfig {
    Gateway(GatewayIssuerConfig),
    Delegated(DelegatedIssuerConfig),
}

/// Gateway-mode issuer: data_gate hosts `/.well-known/did.json` and
/// signs every VC with its own key.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayIssuerConfig {
    pub did: String,
    pub verification_method_id: String,
    pub signer: SignerConfig,
    #[serde(default)]
    pub retired_keys: Vec<RetiredKeyConfig>,
}

/// Delegated-mode issuer: signs under a ministry DID; the ministry
/// hosts its own DID Document including the gateway's `kid`. data_gate
/// does NOT host `/.well-known/did.json` in this mode.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegatedIssuerConfig {
    pub ministry_did: String,
    pub verification_method_id: String,
    pub signer: SignerConfig,
    #[serde(default)]
    pub retired_keys: Vec<RetiredKeyConfig>,
}

/// Signer backend. `software` reads a private JWK from an env var;
/// `kms` defers signing to a KMS provider.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum SignerConfig {
    Software(SoftwareSignerConfig),
    Kms(KmsSignerConfig),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareSignerConfig {
    /// Environment variable name carrying the private JWK (JSON).
    pub jwk_env: String,
    /// JWS signing algorithm. EdDSA or ES256.
    pub signing_algorithm: ProvenanceAlgorithm,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KmsSignerConfig {
    pub provider: KmsProvider,
    pub key_id: String,
    pub signing_algorithm: ProvenanceAlgorithm,
}

/// KMS provider tag. Only AWS KMS is named in V1, and only as an
/// interface stub; the in-tree V1 impl is a mock used by tests.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum KmsProvider {
    AwsKms,
    /// Test-only mock backend.
    Mock,
}

/// JWS algorithm. EdDSA == Ed25519 (recommended default); ES256 ==
/// NIST P-256.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProvenanceAlgorithm {
    EdDSA,
    ES256,
}

impl ProvenanceAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            ProvenanceAlgorithm::EdDSA => "EdDSA",
            ProvenanceAlgorithm::ES256 => "ES256",
        }
    }
}

/// One retired signing key. Stays in the DID Document until every VC
/// it signed has expired, then is fully removed.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetiredKeyConfig {
    pub verification_method_id: String,
    /// Environment variable name carrying the **public** JWK only.
    pub jwk_env: String,
    /// Moment after which signing with this key stopped.
    #[serde(with = "time::serde::rfc3339")]
    pub retired_after: OffsetDateTime,
}
