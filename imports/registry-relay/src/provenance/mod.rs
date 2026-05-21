// SPDX-License-Identifier: Apache-2.0
//! Data provenance: signed claims over verify, aggregate, and entity
//! responses.
//!
//! Module layout:
//!
//! * [`signer`]: [`Signer`] trait + error types.
//! * [`signers`]: concrete implementations (software in V1).
//! * [`jwt_vc`]: VC-JWT envelope encoder (VCDM 2.0).
//! * [`jwt_receipt`]: evidence-verification compact JWT receipt encoder.
//! * [`claim`]: per-claim-type `credentialSubject` builders.
//! * [`did_web`]: gateway-mode DID Document builder.
//! * [`resources`]: in-tree bytes for schemas and JSON-LD contexts.
//! * [`negotiate`]: `Accept` content negotiation.
//!
//! [`ProvenanceState`] is the runtime handle held by the HTTP layer:
//! one instance per process, constructed from a parsed
//! [`crate::config::ProvenanceConfig`] and the configured signer.
//! Handlers ask it to produce a [`SignedVc`] for the response that
//! would otherwise be served as plain JSON.

use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;

use crate::config::{IssuerConfig, ProvenanceConfig, RetiredKeyConfig, SignerConfig};

pub mod claim;
pub mod did_web;
pub mod jwt_receipt;
pub mod jwt_vc;
pub mod negotiate;
pub mod publicschema;
pub mod resources;
pub mod signer;
pub mod signers;

pub use jwt_receipt::{
    EvidenceVerificationReceiptInputs, SignedReceipt, EVIDENCE_VERIFICATION_RECEIPT_MEDIA_TYPE,
    EVIDENCE_VERIFICATION_RECEIPT_TYPE,
};
pub use jwt_vc::{ClaimType, SignedEnvelope, VcCredentialProfile, VcEnvelopeInputs};
pub use negotiate::{negotiate, NegotiationOutcome};
pub use signer::{Signer, SignerError, SigningAlgorithm};

const MAX_EVIDENCE_VERIFICATION_RECEIPT_VALIDITY: Duration = Duration::from_secs(5 * 60);

/// Issuer mode resolved at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerMode {
    /// Gateway hosts `/.well-known/did.json` and signs under its own DID.
    Gateway,
    /// Ministry hosts the DID Document; the gateway holds a delegated key.
    Delegated,
}

/// Validity windows per claim type. Pulled from
/// [`crate::config::ClaimValidity`] at startup so the orchestrator
/// holds the durations directly.
#[derive(Debug, Clone)]
pub struct ResolvedClaimValidity {
    pub verify_result: Duration,
    pub aggregate_result: Duration,
    pub entity_record: Duration,
}

/// Pre-built URL helpers. Storing the bases (rather than re-building
/// strings on every request) keeps the hot path allocation-light.
#[derive(Debug, Clone)]
pub struct ResolvedUrls {
    pub provenance_context_url: String,
    pub schema_base_url: String,
}

impl ResolvedUrls {
    fn schema_url_for(&self, claim_type: ClaimType) -> String {
        format!(
            "{}/{}",
            self.schema_base_url.trim_end_matches('/'),
            claim_type.schema_path()
        )
    }
}

/// One retired signing key resolved from configuration. Carries only
/// the public JWK (the private `d` component never leaves the
/// operator's secret store, even at startup) plus the moment after
/// which the key stopped issuing fresh credentials. The DID Document
/// handler surfaces every entry as a `verificationMethod` so consumers
/// can resolve old `kid`s while their credentials are still valid.
#[derive(Clone, Debug)]
pub struct ResolvedRetiredKey {
    pub verification_method_id: String,
    pub public_jwk: serde_json::Value,
    pub retired_after: OffsetDateTime,
}

/// Resolved provenance configuration: post-validation, post-signer
/// construction. The HTTP layer holds one [`ResolvedProvenanceConfig`]
/// behind an [`Arc`] inside [`ProvenanceState`].
pub struct ResolvedProvenanceConfig {
    pub enabled: bool,
    pub mode: IssuerMode,
    pub issuer_did: String,
    pub verification_method_id: String,
    pub accepted_media_types: Vec<String>,
    pub claim_validity: ResolvedClaimValidity,
    pub urls: ResolvedUrls,
    pub signer: Arc<dyn Signer>,
    /// Retired signing keys kept in the DID Document so older VCs can
    /// still be verified. Empty when the operator never rotated keys.
    pub retired_keys: Vec<ResolvedRetiredKey>,
}

impl std::fmt::Debug for ResolvedProvenanceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedProvenanceConfig")
            .field("enabled", &self.enabled)
            .field("mode", &self.mode)
            .field("issuer_did", &self.issuer_did)
            .field("verification_method_id", &self.verification_method_id)
            .field("accepted_media_types", &self.accepted_media_types)
            .field("claim_validity", &self.claim_validity)
            .field("urls", &self.urls)
            .field("retired_keys", &self.retired_keys)
            .finish_non_exhaustive()
    }
}

/// Runtime state injected as an axum `Extension` on protected routes.
/// Wraps [`ResolvedProvenanceConfig`] behind an [`Arc`] so handlers
/// can clone the handle cheaply.
///
/// The `clock` field returns the current time. Production code leaves it
/// as the default (`OffsetDateTime::now_utc`); tests pin it to a fixed
/// instant so retired-key expiry logic is deterministic.
#[derive(Clone)]
pub struct ProvenanceState {
    inner: Arc<ResolvedProvenanceConfig>,
    pub clock: fn() -> OffsetDateTime,
}

impl std::fmt::Debug for ProvenanceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

impl ProvenanceState {
    /// Wrap a resolved config in an `Arc`, using the wall clock.
    #[must_use]
    pub fn new(inner: ResolvedProvenanceConfig) -> Self {
        Self {
            inner: Arc::new(inner),
            clock: OffsetDateTime::now_utc,
        }
    }

    /// Wrap a resolved config with an injected clock. Used in tests to
    /// pin `now` so retired-key filtering is deterministic.
    #[must_use]
    pub fn new_with_clock(inner: ResolvedProvenanceConfig, clock: fn() -> OffsetDateTime) -> Self {
        Self {
            inner: Arc::new(inner),
            clock,
        }
    }

    /// Borrow the underlying config.
    #[must_use]
    pub fn config(&self) -> &ResolvedProvenanceConfig {
        &self.inner
    }

    /// Convenience: is provenance enabled in this process?
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.inner.enabled
    }
}

/// Per-request issuance inputs gathered by the handler.
///
/// The handler owns the plain response value and the audit-shaped
/// metadata; this orchestrator owns the VC envelope, JWT timestamps,
/// and signer call.
#[derive(Debug, Clone)]
pub struct IssuanceContext {
    pub claim_type: ClaimType,
    pub subject_uri: String,
    pub credential_subject: serde_json::Value,
    pub issued_at: OffsetDateTime,
}

/// Per-request inputs gathered by the evidence-verification HTTP handler
/// when the caller negotiated a signed receipt.
#[derive(Debug, Clone)]
pub struct EvidenceVerificationReceiptContext {
    pub subject: String,
    pub audience: String,
    pub verification_id: String,
    pub decision: String,
    pub requirement: Option<String>,
    pub evidence_type: String,
    pub evidence_offering: String,
    pub issuing_authority: serde_json::Value,
    pub jurisdiction: Option<serde_json::Value>,
    pub level_of_assurance: Option<String>,
    pub dataset: String,
    pub entity: String,
    pub purpose_declared: Option<String>,
    pub checked_at: String,
    pub claim_salt: String,
    pub claim_hash: String,
    pub evidence_hash: Option<String>,
    pub cccev_evidence: serde_json::Value,
    pub issued_at: OffsetDateTime,
}

/// Output of [`ProvenanceState::issue`]. The handler emits the
/// compact JWS on the wire and forwards the metadata to the audit
/// layer via [`crate::audit::ProvenanceIssuanceExt`].
#[derive(Debug, Clone)]
pub struct SignedVc {
    pub compact_jws: String,
    pub jti: String,
    pub claim_type: ClaimType,
    pub credential_type: String,
    pub subject_uri: String,
    pub issuer_did: String,
    pub verification_method_id: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
}

/// Issuance-time error. Maps to the runtime taxonomy
/// (`provenance.signer_unavailable`, `provenance.issuance_failed`).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IssueError {
    /// The signing backend rejected the request.
    #[error("signer unavailable")]
    SignerUnavailable,
    /// Generic envelope construction or sign failure. Carries no
    /// payload bytes; the orchestrator logs the underlying cause.
    #[error("issuance failed")]
    IssuanceFailed,
}

impl ProvenanceState {
    /// Issue a signed VC for the given context.
    ///
    /// Validity is `issued_at + claim_validity.<type>`.
    pub fn issue(&self, ctx: IssuanceContext) -> Result<SignedVc, IssueError> {
        self.issue_with_profile(ctx, None)
    }

    /// Issue a signed VC with optional profile overrides for the VC
    /// type, context, and schema URL.
    pub fn issue_with_profile(
        &self,
        ctx: IssuanceContext,
        profile: Option<VcCredentialProfile>,
    ) -> Result<SignedVc, IssueError> {
        let cfg = &self.inner;
        let window = match ctx.claim_type {
            ClaimType::VerifyResult => cfg.claim_validity.verify_result,
            ClaimType::AggregateResult => cfg.claim_validity.aggregate_result,
            ClaimType::EntityRecord => cfg.claim_validity.entity_record,
        };
        let valid_until = ctx
            .issued_at
            .checked_add(time::Duration::try_from(window).map_err(|err| {
                tracing::error!(error = %err, "provenance.validity_overflow");
                IssueError::IssuanceFailed
            })?)
            .ok_or_else(|| {
                tracing::error!("provenance.validity_add_overflow");
                IssueError::IssuanceFailed
            })?;
        let envelope_inputs = VcEnvelopeInputs {
            claim_type: ctx.claim_type,
            issuer_did: cfg.issuer_did.clone(),
            verification_method_id: cfg.verification_method_id.clone(),
            subject_uri: ctx.subject_uri,
            credential_subject: ctx.credential_subject,
            provenance_context_url: cfg.urls.provenance_context_url.clone(),
            credential_schema_url: cfg.urls.schema_url_for(ctx.claim_type),
            issued_at: ctx.issued_at,
            valid_until,
        };
        let envelope = jwt_vc::encode_with_profile(cfg.signer.as_ref(), envelope_inputs, profile)
            .map_err(|err| {
            map_encode_error(&err);
            match err {
                jwt_vc::EncodeError::Signer(SignerError::Unavailable) => {
                    IssueError::SignerUnavailable
                }
                _ => IssueError::IssuanceFailed,
            }
        })?;
        Ok(SignedVc {
            compact_jws: envelope.compact_jws,
            jti: envelope.jti,
            claim_type: envelope.claim_type,
            credential_type: envelope.credential_type,
            subject_uri: envelope.subject_uri,
            issuer_did: envelope.issuer_did,
            verification_method_id: envelope.verification_method_id,
            iat: envelope.iat,
            nbf: envelope.nbf,
            exp: envelope.exp,
        })
    }

    /// Issue a signed evidence-verification JWT receipt.
    ///
    /// The v1 receipt uses the existing verify-result validity window, capped
    /// at five minutes so server-to-server evidence receipts stay short-lived.
    pub fn issue_evidence_verification_receipt(
        &self,
        ctx: EvidenceVerificationReceiptContext,
    ) -> Result<SignedReceipt, IssueError> {
        let cfg = &self.inner;
        let validity = cfg
            .claim_validity
            .verify_result
            .min(MAX_EVIDENCE_VERIFICATION_RECEIPT_VALIDITY);
        let valid_until = ctx
            .issued_at
            .checked_add(time::Duration::try_from(validity).map_err(|err| {
                tracing::error!(error = %err, "provenance.evidence_verification.validity_overflow");
                IssueError::IssuanceFailed
            })?)
            .ok_or_else(|| {
                tracing::error!("provenance.evidence_verification.validity_add_overflow");
                IssueError::IssuanceFailed
            })?;
        let receipt = jwt_receipt::encode(
            cfg.signer.as_ref(),
            EvidenceVerificationReceiptInputs {
                issuer: cfg.issuer_did.clone(),
                subject: ctx.subject,
                audience: ctx.audience,
                issued_at: ctx.issued_at,
                valid_until,
                verification_id: ctx.verification_id,
                decision: ctx.decision,
                requirement: ctx.requirement,
                evidence_type: ctx.evidence_type,
                evidence_offering: ctx.evidence_offering,
                issuing_authority: ctx.issuing_authority,
                jurisdiction: ctx.jurisdiction,
                level_of_assurance: ctx.level_of_assurance,
                dataset: ctx.dataset,
                entity: ctx.entity,
                purpose_declared: ctx.purpose_declared,
                checked_at: ctx.checked_at,
                claim_salt: ctx.claim_salt,
                claim_hash: ctx.claim_hash,
                evidence_hash: ctx.evidence_hash,
                cccev_evidence: ctx.cccev_evidence,
            },
        )
        .map_err(|err| {
            map_receipt_encode_error(&err);
            match err {
                jwt_receipt::EncodeError::Signer(SignerError::Unavailable) => {
                    IssueError::SignerUnavailable
                }
                _ => IssueError::IssuanceFailed,
            }
        })?;
        Ok(receipt)
    }
}

fn map_encode_error(err: &jwt_vc::EncodeError) {
    match err {
        jwt_vc::EncodeError::Signer(SignerError::Unavailable) => {
            tracing::warn!(event = "provenance.signer_unavailable");
        }
        jwt_vc::EncodeError::Signer(other) => {
            tracing::error!(event = "provenance.sign_failed", error = %other);
        }
        jwt_vc::EncodeError::TimestampFormat => {
            tracing::error!(event = "provenance.timestamp_format_failed");
        }
    }
}

fn map_receipt_encode_error(err: &jwt_receipt::EncodeError) {
    match err {
        jwt_receipt::EncodeError::Signer(SignerError::Unavailable) => {
            tracing::warn!(event = "provenance.evidence_verification.signer_unavailable");
        }
        jwt_receipt::EncodeError::Signer(other) => {
            tracing::error!(
                event = "provenance.evidence_verification.sign_failed",
                error = %other
            );
        }
    }
}

/// Errors emitted by [`build_resolved_provenance_config`]. The HTTP
/// startup path bubbles these via stderr; runtime never sees them.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BuildStateError {
    /// The configured signer could not be loaded (env var missing,
    /// JWK malformed, KMS provider unsupported, ...).
    #[error("signer construction failed: {0}")]
    SignerLoad(#[from] SignerError),
}

/// Build a [`ResolvedProvenanceConfig`] from validated configuration.
///
/// Returns `Ok(None)` when the operator omitted the `provenance` block
/// or set `enabled = false`. Disabled provenance
/// must not load signer secrets or retired-key material: it is runtime
/// invisible until the operator explicitly enables it.
pub fn build_resolved_provenance_config(
    cfg: Option<&ProvenanceConfig>,
) -> Result<Option<ResolvedProvenanceConfig>, BuildStateError> {
    let Some(cfg) = cfg else {
        return Ok(None);
    };
    if !cfg.enabled {
        return Ok(None);
    }
    let (mode, issuer_did, verification_method_id, signer_cfg, retired_cfgs) = match &cfg.issuer {
        IssuerConfig::Gateway(gw) => (
            IssuerMode::Gateway,
            gw.did.clone(),
            gw.verification_method_id.clone(),
            &gw.signer,
            &gw.retired_keys,
        ),
        IssuerConfig::Delegated(d) => (
            IssuerMode::Delegated,
            d.ministry_did.clone(),
            d.verification_method_id.clone(),
            &d.signer,
            &d.retired_keys,
        ),
    };
    let signer: Arc<dyn Signer> = build_signer(signer_cfg, verification_method_id.clone())?;
    let retired_keys = load_retired_keys(retired_cfgs)?;
    let urls = ResolvedUrls {
        provenance_context_url: format!(
            "{}/provenance/v1.jsonld",
            cfg.context_base_url.trim_end_matches('/')
        ),
        schema_base_url: cfg.schema_base_url.trim_end_matches('/').to_string(),
    };
    Ok(Some(ResolvedProvenanceConfig {
        enabled: cfg.enabled,
        mode,
        issuer_did,
        verification_method_id,
        accepted_media_types: cfg.accepted_media_types.clone(),
        claim_validity: ResolvedClaimValidity {
            verify_result: cfg.claim_validity.verify_result,
            aggregate_result: cfg.claim_validity.aggregate_result,
            entity_record: cfg.claim_validity.entity_record,
        },
        urls,
        signer,
        retired_keys,
    }))
}

/// Resolve each configured retired key by reading the public JWK from
/// its `jwk_env` env var. A missing or malformed env var surfaces as
/// `SignerError::KeyLoad` so the orchestrator fails closed at startup
/// (we never silently drop a retired key, otherwise the DID Document
/// could not verify already-issued credentials).
fn load_retired_keys(
    cfgs: &[RetiredKeyConfig],
) -> Result<Vec<ResolvedRetiredKey>, BuildStateError> {
    cfgs.iter()
        .map(|entry| {
            // The structured log emits the actual env var name and
            // verification method id; the static `reason` keeps the
            // error variant identifiable to operators without
            // allocating at startup.
            let raw = std::env::var(&entry.jwk_env).map_err(|_| {
                tracing::error!(
                    code = "provenance.config.retired_key_env_missing",
                    jwk_env = %entry.jwk_env,
                    verification_method_id = %entry.verification_method_id,
                    "retired key env var is unset or not utf-8",
                );
                BuildStateError::SignerLoad(SignerError::KeyLoad {
                    reason: "retired key env var unset or not utf-8",
                })
            })?;
            let mut jwk: serde_json::Value = serde_json::from_str(&raw).map_err(|err| {
                tracing::error!(
                    code = "provenance.config.retired_key_jwk_parse_failed",
                    verification_method_id = %entry.verification_method_id,
                    error = %err,
                    "retired key jwk parse failed",
                );
                BuildStateError::SignerLoad(SignerError::KeyLoad {
                    reason: "retired key jwk parse failed",
                })
            })?;
            // The retired key is published in the DID Document; the
            // operator may stash the full keypair in the env var, but
            // we must strip the private `d` before exposing it.
            if let serde_json::Value::Object(ref mut map) = jwk {
                map.remove("d");
                // Make sure the JWK carries a `kid` matching the
                // verification method id so consumers can resolve by
                // `kid` without cross-referencing the DID Document.
                map.entry("kid".to_string()).or_insert_with(|| {
                    serde_json::Value::String(entry.verification_method_id.clone())
                });
            }
            Ok(ResolvedRetiredKey {
                verification_method_id: entry.verification_method_id.clone(),
                public_jwk: jwk,
                retired_after: entry.retired_after,
            })
        })
        .collect()
}

fn build_signer(
    cfg: &SignerConfig,
    verification_method_id: String,
) -> Result<Arc<dyn Signer>, SignerError> {
    match cfg {
        SignerConfig::Software(software) => {
            let signer =
                signers::software::SoftwareSigner::from_config(software, verification_method_id)?;
            Ok(Arc::new(signer))
        }
        SignerConfig::Kms(_) => Err(SignerError::KeyLoad {
            reason: "kms signer unsupported in V1",
        }),
    }
}
