// SPDX-License-Identifier: Apache-2.0
//! Data provenance configuration.
//!
//! The top-level type is optional in [`crate::config::Config`] so
//! deployments without provenance keep loading without change.
//!
//! Validation lives in [`crate::config::validate`]. This module owns
//! the data model only.

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use time::OffsetDateTime;

/// Top-level provenance block. When `enabled = false` (the default),
/// no provenance routes are mounted, no Accept negotiation runs, and
/// no provenance audit events fire.
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

/// Gateway-mode issuer: registry-relay hosts `/.well-known/did.json` and
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
/// hosts its own DID Document including the gateway's `kid`. registry-relay
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

/// Signer backend. V1 supports local `software` env-var material and
/// `file_watch` material reloaded from a local JWK file. Other variants
/// are reserved so future remote signers can plug into the provenance
/// signer boundary without changing the issuer model.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum SignerConfig {
    Software(SoftwareSignerConfig),
    FileWatch(FileWatchSignerConfig),
    /// Reserved for a future remote signer backend. Config validation
    /// rejects this variant in V1 so operators do not accidentally
    /// deploy an unsupported KMS path.
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
pub struct FileWatchSignerConfig {
    /// Local file path carrying the private JWK (JSON).
    pub path: PathBuf,
    /// JWS signing algorithm. V1 supports EdDSA.
    pub signing_algorithm: ProvenanceAlgorithm,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KmsSignerConfig {
    pub provider: KmsProvider,
    pub key_id: String,
    pub signing_algorithm: ProvenanceAlgorithm,
}

/// KMS provider tag reserved for future remote signer backends.
/// Parsed for forward-compatible diagnostics, but rejected by V1
/// validation.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum KmsProvider {
    AwsKms,
}

/// JWS algorithm. V1 production signing supports EdDSA == Ed25519.
/// ES256 == NIST P-256 is reserved for a future signer backend.
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
