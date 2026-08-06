//! Fail-closed native Evidence audit with a durable keyed JSONL chain.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Error as IoError, ErrorKind},
    path::{Path, PathBuf},
    sync::Arc,
};

#[cfg(test)]
use std::io::{Seek, SeekFrom, Write};
#[cfg(test)]
use std::sync::atomic::Ordering;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
pub use registry_platform_audit::segmented_audit_paths as audit_segment_paths;
use registry_platform_audit::{
    verify_segmented_audit_chain, visit_stopped_segmented_audit_chain, AuditChainHasher,
    AuditEnvelope, AuditError, AuditHashSecret, AuditKeyHasher, AuditProfile,
    DurableSegmentedAuditLog,
};
use registry_platform_crypto::canonicalize_json;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::config::AssuranceProfile;

const AUDIT_SCHEMA: &str = "registry.evidence.audit/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditPhase {
    AccessAttempt,
    DisclosureRelease,
    Denial,
    TransientFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditDecision {
    Authorized,
    Released,
    NoMatch,
    Ambiguous,
    FactMissing,
    DependencyFailure,
    EvaluationFailure,
    SigningFailure,
}

/// Closed non-secret response-protection mode resolved with authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResponseProtection {
    Signed,
    Unsigned,
    SdJwtVc,
}

impl ResponseProtection {
    /// Report whether release under this mode is cryptographically protected
    /// and therefore records the signing key identifier.
    pub fn is_signed(self) -> bool {
        matches!(self, Self::Signed | Self::SdJwtVc)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorityKind {
    Statutory,
    Organizational,
    Consent,
    Delegated,
    ExplicitRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditAuthority {
    pub kind: AuthorityKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_pseudonym: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditSubject {
    pub role: String,
    pub selector_profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector_bundle_pseudonym: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceAuditEvent {
    pub schema: String,
    pub assurance_profile: AssuranceProfile,
    pub event_id: String,
    pub occurred_at: String,
    pub operation: String,
    pub phase: AuditPhase,
    pub requirement: String,
    pub bundle_revision: String,
    pub purpose: String,
    pub requester_pseudonym: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_pseudonym: Option<String>,
    pub authority: AuditAuthority,
    pub subjects: Vec<AuditSubject>,
    pub response_protection: ResponseProtection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapter_id: Option<String>,
    pub decision: AuditDecision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disclosed_concepts: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe_error_category: Option<String>,
    pub duration_milliseconds: u64,
}

impl EvidenceAuditEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        assurance_profile: AssuranceProfile,
        operation: String,
        phase: AuditPhase,
        requirement: String,
        bundle_revision: String,
        purpose: String,
        requester_pseudonym: String,
        authority: AuditAuthority,
        subjects: Vec<AuditSubject>,
        response_protection: ResponseProtection,
        decision: AuditDecision,
        duration_milliseconds: u64,
    ) -> Self {
        Self {
            schema: AUDIT_SCHEMA.to_owned(),
            assurance_profile,
            event_id: format!("urn:ulid:{}", ulid::Ulid::new()),
            occurred_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            operation,
            phase,
            requirement,
            bundle_revision,
            purpose,
            requester_pseudonym,
            actor_pseudonym: None,
            authority,
            subjects,
            response_protection,
            source_id: None,
            adapter_id: None,
            decision,
            disclosed_concepts: None,
            evidence_id: None,
            signing_key_id: None,
            safe_error_category: None,
            duration_milliseconds,
        }
    }

    pub fn validate_phase_fields(&self) -> Result<(), EvidenceAuditError> {
        let any_release_field = self.disclosed_concepts.is_some() || self.evidence_id.is_some();
        let all_release_fields = self.disclosed_concepts.is_some() && self.evidence_id.is_some();
        if (self.phase == AuditPhase::DisclosureRelease && !all_release_fields)
            || (self.phase != AuditPhase::DisclosureRelease && any_release_field)
        {
            return Err(EvidenceAuditError::InvalidEvent);
        }
        // A signing key identity exists exactly for cryptographically
        // protected disclosure release.
        let signing_key_required =
            self.phase == AuditPhase::DisclosureRelease && self.response_protection.is_signed();
        if self.signing_key_id.is_some() != signing_key_required {
            return Err(EvidenceAuditError::InvalidEvent);
        }
        let phase_decision_is_native = matches!(
            (self.phase, self.decision),
            (AuditPhase::AccessAttempt, AuditDecision::Authorized)
                | (AuditPhase::DisclosureRelease, AuditDecision::Released)
                | (
                    AuditPhase::Denial,
                    AuditDecision::NoMatch | AuditDecision::Ambiguous | AuditDecision::FactMissing
                )
                | (
                    AuditPhase::TransientFailure,
                    AuditDecision::DependencyFailure
                        | AuditDecision::EvaluationFailure
                        | AuditDecision::SigningFailure
                )
        );
        let concepts_are_valid = self.disclosed_concepts.as_ref().is_none_or(|concepts| {
            concepts.len() <= 16
                && concepts.iter().all(|concept| valid_uri(concept))
                && concepts.iter().collect::<BTreeSet<_>>().len() == concepts.len()
        });
        if self.schema != AUDIT_SCHEMA
            || !phase_decision_is_native
            || !valid_uri(&self.event_id)
            || chrono::DateTime::parse_from_rfc3339(&self.occurred_at).is_err()
            || !valid_uri(&self.requirement)
            || !valid_revision(&self.bundle_revision)
            || !valid_purpose(&self.purpose, 128)
            || !valid_pseudonym(&self.requester_pseudonym)
            || self
                .actor_pseudonym
                .as_ref()
                .is_some_and(|value| !valid_pseudonym(value))
            || self
                .authority
                .grant_pseudonym
                .as_ref()
                .is_some_and(|value| !valid_pseudonym(value))
            || self.subjects.is_empty()
            || self.subjects.len() > 8
            || !(16..=128).contains(&self.operation.len())
            || self.subjects.iter().any(|subject| {
                !valid_local_name(&subject.role, 64)
                    || !valid_local_name(&subject.selector_profile, 128)
                    || subject
                        .selector_bundle_pseudonym
                        .as_ref()
                        .is_some_and(|value| !valid_pseudonym(value))
            })
            || self
                .source_id
                .as_ref()
                .is_some_and(|value| !valid_local_name(value, 128))
            || self
                .adapter_id
                .as_ref()
                .is_some_and(|value| !valid_local_name(value, 128))
            || !concepts_are_valid
            || self
                .evidence_id
                .as_ref()
                .is_some_and(|value| !valid_uri(value))
            || self.signing_key_id.as_ref().is_some_and(|value| {
                value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)
            })
            || self
                .safe_error_category
                .as_ref()
                .is_some_and(|value| !valid_local_name(value, 128))
            || self.duration_milliseconds > 86_400_000
        {
            return Err(EvidenceAuditError::InvalidEvent);
        }
        Ok(())
    }
}

fn valid_uri(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && url::Url::parse(value).is_ok()
}

fn valid_revision(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn valid_purpose(value: &str, maximum: usize) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= maximum
        && bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b':' | b'-')
        })
}

fn valid_local_name(value: &str, maximum: usize) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= maximum
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn valid_pseudonym(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("hmac-sha256:v") else {
        return false;
    };
    let Some((version, digest)) = rest.split_once(':') else {
        return false;
    };
    !version.is_empty()
        && !version.starts_with('0')
        && version.bytes().all(|byte| byte.is_ascii_digit())
        && digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[derive(Debug, Error)]
pub enum EvidenceAuditError {
    #[error("audit configuration is invalid")]
    Configuration,
    #[error("audit event is invalid")]
    InvalidEvent,
    #[error("audit initialization or write failed")]
    Audit(#[from] AuditError),
    /// A span of sealed history is absent. Reported separately from a hash
    /// break so an operator can tell deliberate archival from tampering.
    #[error("audit chain is missing sealed segment {sequence}")]
    SegmentMissing { sequence: u64 },
}

/// The chain's on-disk footprint, sealed segments and the active segment
/// together.
///
/// Rotation never deletes a sealed segment, so this only falls when an
/// operator archives one. That is why it is measured by walking the segment
/// directory rather than accumulated in a counter: a counter would keep
/// reporting bytes an operator had already reclaimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditStorageUsage {
    pub segments: usize,
    pub bytes: u64,
}

pub struct EvidenceAuditLog {
    sink: Arc<DurableSegmentedAuditLog>,
    key_hasher: AuditKeyHasher,
    key_version: u32,
}

impl std::fmt::Debug for EvidenceAuditLog {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvidenceAuditLog")
            .field("path", &self.sink.path())
            .field("key_version", &self.key_version)
            .finish_non_exhaustive()
    }
}

impl EvidenceAuditLog {
    pub async fn initialize(
        path: impl Into<PathBuf>,
        maximum_file_bytes: u64,
        master_secret: Vec<u8>,
        key_version: u32,
    ) -> Result<Self, EvidenceAuditError> {
        if maximum_file_bytes == 0 || key_version == 0 {
            return Err(EvidenceAuditError::Configuration);
        }
        let path = path.into();
        if !path.is_absolute() {
            return Err(AuditError::Io(IoError::new(
                ErrorKind::InvalidInput,
                "audit path must be absolute",
            ))
            .into());
        }
        if !path.parent().is_some_and(Path::is_dir) {
            return Err(AuditError::Io(IoError::new(
                ErrorKind::NotFound,
                "audit parent directory is unavailable",
            ))
            .into());
        }
        let profile = AuditProfile::production_from_secret_bytes(Zeroizing::new(master_secret))?;
        let chain_hasher = profile.chain_hasher();
        let key_hasher = profile.key_hasher();
        let sink = Arc::new(
            DurableSegmentedAuditLog::initialize(path, maximum_file_bytes, chain_hasher).await?,
        );
        Ok(Self {
            sink,
            key_hasher,
            key_version,
        })
    }

    pub fn pseudonym(
        &self,
        class: &str,
        scope: &str,
        protected_input: &[u8],
    ) -> Result<String, EvidenceAuditError> {
        if protected_input.is_empty() {
            return Err(EvidenceAuditError::InvalidEvent);
        }
        let transient = URL_SAFE_NO_PAD.encode(protected_input);
        let digest = self
            .key_hasher
            .audit_reference_hash(class, scope, &transient)
            .map_err(|_| EvidenceAuditError::InvalidEvent)?;
        let digest = digest
            .strip_prefix("hmac-sha256:")
            .ok_or(EvidenceAuditError::InvalidEvent)?;
        Ok(format!("hmac-sha256:v{}:{digest}", self.key_version))
    }

    /// Measure the chain's footprint for the capacity gauge.
    ///
    /// This walks the audit directory, so it runs on the blocking pool: the
    /// number of sealed segments grows without bound and the caller is a
    /// scrape handler on the async runtime. A segment that disappears midway
    /// through the walk is skipped rather than failing the read, because an
    /// operator archiving history concurrently is expected, not an error.
    pub async fn storage_usage(&self) -> Result<AuditStorageUsage, EvidenceAuditError> {
        let path = self.sink.path().to_path_buf();
        tokio::task::spawn_blocking(move || {
            let segments = audit_segment_paths(&path)?;
            let mut bytes = 0u64;
            let mut counted = 0usize;
            for segment in &segments {
                match std::fs::symlink_metadata(segment) {
                    Ok(metadata) => {
                        counted += 1;
                        bytes = bytes.saturating_add(metadata.len());
                    }
                    Err(error) if error.kind() == ErrorKind::NotFound => {}
                    Err(error) => return Err(AuditError::Io(error)),
                }
            }
            Ok(AuditStorageUsage {
                segments: counted,
                bytes,
            })
        })
        .await
        .map_err(|error| AuditError::Io(IoError::other(error)))?
        .map_err(EvidenceAuditError::from)
    }

    pub async fn append(
        &self,
        event: EvidenceAuditEvent,
    ) -> Result<AuditEnvelope, EvidenceAuditError> {
        event.validate_phase_fields()?;
        let record = serde_json::to_value(event).map_err(AuditError::Json)?;
        self.sink
            .append_record(record)
            .await
            .map_err(EvidenceAuditError::Audit)
    }

    pub async fn ready(&self) -> bool {
        self.sink.ready().await
    }

    /// Durable writes performed so far, for proving that concurrent appends
    /// share them rather than each paying an `fsync`.
    #[cfg(test)]
    pub(crate) fn durable_writes(&self) -> usize {
        usize::try_from(self.sink.durable_writes()).unwrap_or(usize::MAX)
    }

    #[cfg(test)]
    fn startup_verifications(&self) -> u64 {
        self.sink.startup_verifications()
    }
}

/// Result of an out-of-band verification pass over a whole audit chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditChainSummary {
    /// Segments actually replayed.
    pub segments: usize,
    pub records: usize,
    pub head: Option<[u8; 32]>,
    /// Sequence of the oldest and newest sealed segments, absent when the chain
    /// has never rotated.
    pub first_sequence: Option<u64>,
    pub last_sequence: Option<u64>,
    /// Whether the active segment was replayed. False when a running writer
    /// holds the chain, in which case only sealed history was proven.
    pub active_verified: bool,
}

pub const LOCAL_AUDIT_OPERATION_VIEW_SCHEMA_V1: &str = "registry.evidence.local-audit-operation/v1";

/// Minimized verified view of one native audit operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalAuditOperationView {
    schema: &'static str,
    operation: String,
    events: Vec<LocalAuditOperationEvent>,
    #[serde(skip)]
    assurance_profile: AssuranceProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalAuditOperationEvent {
    occurred_at: String,
    phase: AuditPhase,
    decision: AuditDecision,
    requirement: String,
    purpose: String,
    requester_pseudonym: String,
    response_protection: ResponseProtection,
    #[serde(skip_serializing_if = "Option::is_none")]
    disclosed_concepts: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_id: Option<String>,
}

#[derive(Clone, Copy)]
struct LocalAuditInspectionBounds {
    maximum_segments: usize,
    maximum_records: usize,
    maximum_output_bytes: usize,
}

impl LocalAuditInspectionBounds {
    const DEFAULT: Self = Self {
        maximum_segments: 1024,
        maximum_records: 10_000,
        maximum_output_bytes: 256 * 1024,
    };
}

struct PendingLocalOperation {
    event: EvidenceAuditEvent,
    view: LocalAuditOperationEvent,
}

#[derive(Default)]
struct LocalAuditCollector {
    bounds: Option<LocalAuditInspectionBounds>,
    records: usize,
    pending: BTreeMap<String, PendingLocalOperation>,
    completed: BTreeSet<String>,
    last_operation: Option<String>,
    last_completed: Option<LocalAuditOperationView>,
}

impl LocalAuditCollector {
    fn new(bounds: LocalAuditInspectionBounds) -> Self {
        Self {
            bounds: Some(bounds),
            ..Self::default()
        }
    }

    fn collect(&mut self, envelope: AuditEnvelope) -> Result<(), AuditError> {
        let bounds = self.bounds.ok_or_else(invalid_audit_data)?;
        self.records = self.records.checked_add(1).ok_or_else(file_size_error)?;
        if self.records > bounds.maximum_records {
            return Err(file_size_error());
        }
        let event: EvidenceAuditEvent =
            serde_json::from_value(envelope.record).map_err(|_| invalid_audit_data())?;
        event
            .validate_phase_fields()
            .map_err(|_| invalid_audit_data())?;
        let operation = event.operation.clone();
        self.last_operation = Some(operation.clone());
        let view = LocalAuditOperationEvent::from(&event);

        if event.phase == AuditPhase::AccessAttempt {
            if self.completed.contains(&operation)
                || self
                    .pending
                    .insert(operation, PendingLocalOperation { event, view })
                    .is_some()
            {
                return Err(invalid_audit_data());
            }
            return Ok(());
        }

        let access = self
            .pending
            .remove(&operation)
            .ok_or_else(invalid_audit_data)?;
        if !coherent_operation_pair(&access.event, &event)
            || !self.completed.insert(operation.clone())
        {
            return Err(invalid_audit_data());
        }
        self.last_completed = Some(LocalAuditOperationView {
            schema: LOCAL_AUDIT_OPERATION_VIEW_SCHEMA_V1,
            operation,
            events: vec![access.view, view],
            assurance_profile: access.event.assurance_profile,
        });
        Ok(())
    }

    fn finish(mut self) -> Result<LocalAuditOperationView, EvidenceAuditError> {
        let bounds = self.bounds.take().ok_or(EvidenceAuditError::InvalidEvent)?;
        let last = self
            .last_operation
            .take()
            .ok_or(EvidenceAuditError::InvalidEvent)?;
        let view = if let Some(pending) = self.pending.remove(&last) {
            LocalAuditOperationView {
                schema: LOCAL_AUDIT_OPERATION_VIEW_SCHEMA_V1,
                operation: last,
                events: vec![pending.view],
                assurance_profile: pending.event.assurance_profile,
            }
        } else {
            self.last_completed
                .take()
                .filter(|completed| completed.operation == last)
                .ok_or(EvidenceAuditError::InvalidEvent)?
        };
        if view.events.first().is_none_or(|event| {
            event.phase != AuditPhase::AccessAttempt || event.decision != AuditDecision::Authorized
        }) || view.assurance_profile != AssuranceProfile::Local
        {
            return Err(EvidenceAuditError::InvalidEvent);
        }
        let serialized = serde_json::to_value(&view).map_err(AuditError::Json)?;
        if canonicalize_json(&serialized)
            .map_err(|_| invalid_audit_data())?
            .len()
            > bounds.maximum_output_bytes
        {
            return Err(EvidenceAuditError::Configuration);
        }
        Ok(view)
    }
}

impl From<&EvidenceAuditEvent> for LocalAuditOperationEvent {
    fn from(event: &EvidenceAuditEvent) -> Self {
        Self {
            occurred_at: event.occurred_at.clone(),
            phase: event.phase,
            decision: event.decision,
            requirement: event.requirement.clone(),
            purpose: event.purpose.clone(),
            requester_pseudonym: event.requester_pseudonym.clone(),
            response_protection: event.response_protection,
            disclosed_concepts: event.disclosed_concepts.clone(),
            evidence_id: event.evidence_id.clone(),
        }
    }
}

fn coherent_operation_pair(access: &EvidenceAuditEvent, terminal: &EvidenceAuditEvent) -> bool {
    let occurred_in_order = chrono::DateTime::parse_from_rfc3339(&access.occurred_at)
        .ok()
        .zip(chrono::DateTime::parse_from_rfc3339(&terminal.occurred_at).ok())
        .is_some_and(|(access, terminal)| access <= terminal);
    occurred_in_order
        && access.operation == terminal.operation
        && access.assurance_profile == terminal.assurance_profile
        && access.requirement == terminal.requirement
        && access.bundle_revision == terminal.bundle_revision
        && access.purpose == terminal.purpose
        && access.requester_pseudonym == terminal.requester_pseudonym
        && access.actor_pseudonym == terminal.actor_pseudonym
        && access.authority == terminal.authority
        && access.subjects == terminal.subjects
        && access.response_protection == terminal.response_protection
        && access.source_id == terminal.source_id
        && access.adapter_id == terminal.adapter_id
}

/// Verify the whole stopped local chain and derive the last operation from the
/// exact verified envelopes in that one replay.
pub fn verified_last_local_audit_operation(
    path: &Path,
    chain_secret: &AuditHashSecret,
) -> Result<LocalAuditOperationView, EvidenceAuditError> {
    verified_last_local_audit_operation_with_bounds(
        path,
        chain_secret,
        LocalAuditInspectionBounds::DEFAULT,
    )
}

fn verified_last_local_audit_operation_with_bounds(
    path: &Path,
    chain_secret: &AuditHashSecret,
    bounds: LocalAuditInspectionBounds,
) -> Result<LocalAuditOperationView, EvidenceAuditError> {
    if bounds.maximum_segments == 0
        || bounds.maximum_records == 0
        || bounds.maximum_output_bytes == 0
    {
        return Err(EvidenceAuditError::Configuration);
    }

    let hasher = AuditChainHasher::keyed(chain_secret.clone());
    let mut collector = LocalAuditCollector::new(bounds);
    visit_stopped_segmented_audit_chain(
        path,
        &hasher,
        bounds.maximum_segments,
        bounds.maximum_records,
        |envelope| collector.collect(envelope),
    )
    .map_err(map_platform_audit_error)?;
    collector.finish()
}

/// Verify every retained segment, including the active segment when no writer is running.
pub fn verify_audit_chain(
    path: &Path,
    chain_secret: &AuditHashSecret,
) -> Result<AuditChainSummary, EvidenceAuditError> {
    let summary =
        verify_segmented_audit_chain(path, &AuditChainHasher::keyed(chain_secret.clone()))
            .map_err(map_platform_audit_error)?;
    Ok(AuditChainSummary {
        segments: summary.segments,
        records: summary.records,
        head: summary.last_hash,
        first_sequence: summary.first_sequence,
        last_sequence: summary.last_sequence,
        active_verified: summary.active_verified,
    })
}

fn map_platform_audit_error(error: AuditError) -> EvidenceAuditError {
    match error {
        AuditError::SegmentMissing { sequence } => EvidenceAuditError::SegmentMissing { sequence },
        error => EvidenceAuditError::Audit(error),
    }
}

fn invalid_audit_data() -> AuditError {
    AuditError::Io(IoError::new(
        ErrorKind::InvalidData,
        "audit record is invalid",
    ))
}

fn file_size_error() -> AuditError {
    AuditError::Io(IoError::other("audit file size bound exceeded"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(log: &EvidenceAuditLog) -> EvidenceAuditEvent {
        EvidenceAuditEvent::new(
            AssuranceProfile::EvidenceGrade,
            "01K1EXAMPLE0000000000000000".to_string(),
            AuditPhase::AccessAttempt,
            "urn:example:requirement:v1".to_string(),
            format!("sha256:{}", "0".repeat(64)),
            "casework".to_string(),
            log.pseudonym("requester-v1", "urn:example:trust", b"principal-canary")
                .expect("pseudonym builds"),
            AuditAuthority {
                kind: AuthorityKind::Statutory,
                grant_pseudonym: None,
            },
            vec![AuditSubject {
                role: "subject".to_string(),
                selector_profile: "person-v1".to_string(),
                selector_bundle_pseudonym: Some(
                    log.pseudonym("subject-v1", "casework", b"selector-canary")
                        .expect("pseudonym builds"),
                ),
            }],
            ResponseProtection::Signed,
            AuditDecision::Authorized,
            5,
        )
    }

    #[test]
    fn frozen_audit_fixture_matches_native_event_shape_and_phase_rules() {
        let fixture: serde_json::Value = serde_norway::from_slice(include_bytes!(
            "../../../products/evidence/fixtures/conformance/audit-events.yaml"
        ))
        .expect("frozen audit fixture parses");
        assert_eq!(
            fixture["fixture"],
            serde_json::json!("registry.evidence.audit-events/v1")
        );
        assert_eq!(fixture["synthetic_only"], serde_json::json!(true));

        let access = EvidenceAuditEvent {
            schema: AUDIT_SCHEMA.to_owned(),
            assurance_profile: AssuranceProfile::EvidenceGrade,
            event_id: "urn:example:fixture:audit:access-001".to_owned(),
            occurred_at: "2026-08-02T00:00:00Z".to_owned(),
            operation: "fixture-operation-00000001".to_owned(),
            phase: AuditPhase::AccessAttempt,
            requirement: "urn:example:fixture:requirement:property:v1".to_owned(),
            bundle_revision:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
            purpose: "fixture-procedure".to_owned(),
            requester_pseudonym:
                "hmac-sha256:v1:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_owned(),
            actor_pseudonym: None,
            authority: AuditAuthority {
                kind: AuthorityKind::Statutory,
                grant_pseudonym: None,
            },
            subjects: vec![AuditSubject {
                role: "subject".to_owned(),
                selector_profile: "opaque-record-v1".to_owned(),
                selector_bundle_pseudonym: Some(
                    "hmac-sha256:v1:2222222222222222222222222222222222222222222222222222222222222222"
                        .to_owned(),
                ),
            }],
            response_protection: ResponseProtection::Signed,
            source_id: Some("source-a".to_owned()),
            adapter_id: Some("adapter-a".to_owned()),
            decision: AuditDecision::Authorized,
            disclosed_concepts: None,
            evidence_id: None,
            signing_key_id: None,
            safe_error_category: None,
            duration_milliseconds: 2,
        };
        access
            .validate_phase_fields()
            .expect("fixture access event satisfies native phase rules");
        assert_eq!(
            serde_json::to_value(&access).expect("access event serializes"),
            fixture["access_attempt"]
        );

        let mut release = access.clone();
        release.event_id = "urn:example:fixture:audit:release-001".to_owned();
        release.occurred_at = "2026-08-02T00:00:01Z".to_owned();
        release.phase = AuditPhase::DisclosureRelease;
        release.decision = AuditDecision::Released;
        release.disclosed_concepts = Some(vec!["urn:example:fixture:concept:boolean-a".to_owned()]);
        release.evidence_id = Some("urn:example:fixture:evidence:001".to_owned());
        release.signing_key_id = Some("_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo".to_owned());
        release.duration_milliseconds = 12;
        release
            .validate_phase_fields()
            .expect("fixture release event satisfies native phase rules");
        assert_eq!(
            serde_json::to_value(&release).expect("release event serializes"),
            fixture["disclosure_release"]
        );

        let mut unsigned_release = release.clone();
        unsigned_release.event_id = "urn:example:fixture:audit:release-002".to_owned();
        unsigned_release.occurred_at = "2026-08-02T00:00:02Z".to_owned();
        unsigned_release.response_protection = ResponseProtection::Unsigned;
        unsigned_release.signing_key_id = None;
        unsigned_release
            .validate_phase_fields()
            .expect("fixture unsigned release event satisfies native phase rules");
        assert_eq!(
            serde_json::to_value(&unsigned_release).expect("unsigned release event serializes"),
            fixture["unsigned_disclosure_release"]
        );
        unsigned_release.signing_key_id =
            Some("_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo".to_owned());
        assert!(matches!(
            unsigned_release.validate_phase_fields(),
            Err(EvidenceAuditError::InvalidEvent)
        ));

        let mut signed_release_without_key = release.clone();
        signed_release_without_key.signing_key_id = None;
        assert!(matches!(
            signed_release_without_key.validate_phase_fields(),
            Err(EvidenceAuditError::InvalidEvent)
        ));

        let mut release_fields_on_access = access;
        release_fields_on_access.disclosed_concepts = release.disclosed_concepts.clone();
        release_fields_on_access.evidence_id = release.evidence_id.clone();
        release_fields_on_access.signing_key_id = release.signing_key_id.clone();
        assert!(matches!(
            release_fields_on_access.validate_phase_fields(),
            Err(EvidenceAuditError::InvalidEvent)
        ));
        release.evidence_id = None;
        assert!(matches!(
            release.validate_phase_fields(),
            Err(EvidenceAuditError::InvalidEvent)
        ));

        assert_eq!(
            fixture["order"],
            serde_json::json!({
                "access_attempt_durable_before": ["credential-resolution", "source-access"],
                "disclosure_release_durable_after": ["signing"],
                "disclosure_release_durable_before": ["response-release"]
            })
        );
        assert_eq!(
            fixture["negative"],
            serde_json::json!([
                "raw-principal",
                "raw-actor-or-grant",
                "raw-selector-value",
                "separate-field-hash",
                "plain-sha256-subject-hash",
                "base64url-reencoded-audit-hmac",
                "globally-stable-subject-pseudonym",
                "source-or-supported-value",
                "credential-token-or-private-key",
                "candidate-count-score-hint-or-comparison",
                "release-fields-on-access-event",
                "missing-release-fields-on-release-event",
                "signing-key-on-unsigned-release-event",
                "missing-signing-key-on-signed-release-event",
                "request-nonce-in-any-event"
            ])
        );
    }

    #[tokio::test]
    async fn audit_is_durable_keyed_and_redacted() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = EvidenceAuditLog::initialize(
            &path,
            64 * 1024,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("audit initializes");
        assert_eq!(log.startup_verifications(), 1);
        assert!(log.ready().await, "an empty verified chain is ready");
        log.append(event(&log)).await.expect("event appends");
        assert!(log.ready().await);
        assert_eq!(
            log.startup_verifications(),
            1,
            "steady-state appends and readiness must not rescan the audit file"
        );

        let contents = std::fs::read_to_string(&path).expect("audit reads");
        assert!(!contents.contains("principal-canary"));
        assert!(!contents.contains("selector-canary"));
        assert!(contents.contains("hmac-sha256:v1:"));
        assert!(!contents.contains("hmac-sha256:v1:hmac-sha256:"));
        assert!(contents.ends_with('\n'));

        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .and_then(|mut file| file.write_all(b"{}\n"))
            .expect("tamper audit file");
        assert!(!log.ready().await, "readiness detects chain tampering");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_appends_extend_one_keyed_chain_without_forking() {
        // Every evaluation shares one `EvidenceAuditLog` through an `Arc`, so many
        // requests can append at once. The keyed chain must serialize each event's
        // prev-hash read with its durable write: if two appends observed the same
        // tail hash in parallel they would fork the chain and surface as a
        // `ChainForkDetected` error (a spurious 503) or a broken linkage. Drive a
        // burst of concurrent appends across worker threads and prove each one
        // succeeds and the resulting chain still verifies end to end.
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = Arc::new(
            EvidenceAuditLog::initialize(
                &path,
                256 * 1024,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes"),
        );

        const CONCURRENCY: usize = 16;
        let mut handles = Vec::with_capacity(CONCURRENCY);
        for _ in 0..CONCURRENCY {
            let log = Arc::clone(&log);
            handles.push(tokio::spawn(async move {
                let event = event(log.as_ref());
                log.append(event).await
            }));
        }
        for handle in handles {
            handle
                .await
                .expect("append task joins")
                .expect("a concurrent append never forks the keyed chain");
        }

        assert!(
            log.ready().await,
            "the chain verifies after concurrent appends"
        );
        assert_eq!(
            log.startup_verifications(),
            1,
            "concurrent appends extend the chain incrementally without rescanning it"
        );
        let lines = std::fs::read_to_string(&path)
            .expect("audit reads")
            .lines()
            .count();
        assert_eq!(
            lines, CONCURRENCY,
            "every concurrent append is durably recorded exactly once"
        );

        // Release the single-writer sink lock before reopening: the sink holds an
        // exclusive lock for one writer per file, so a fresh reader can only
        // re-verify the chain once this handle is dropped.
        drop(log);

        // A fresh reader re-verifies the whole keyed chain from disk, proving the
        // prev-hash linkage stayed consistent under concurrent appends.
        let reopened = EvidenceAuditLog::initialize(
            &path,
            256 * 1024,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("a chain grown under concurrency verifies on restart");
        assert!(
            reopened.ready().await,
            "the reopened chain verifies end to end"
        );
    }

    #[tokio::test]
    async fn restart_verifies_a_nonempty_keyed_chain_before_accepting_appends() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        {
            let log = EvidenceAuditLog::initialize(
                &path,
                64 * 1024,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes");
            log.append(event(&log)).await.expect("event appends");
        }

        let restarted = EvidenceAuditLog::initialize(
            &path,
            64 * 1024,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("a valid nonempty chain verifies on restart");
        assert!(restarted.ready().await);
        assert_eq!(restarted.startup_verifications(), 1);
        restarted
            .append(event(&restarted))
            .await
            .expect("verified restarted chain accepts an append");
    }

    #[tokio::test]
    async fn restart_rejects_same_length_chain_corruption() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        {
            let log = EvidenceAuditLog::initialize(
                &path,
                64 * 1024,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes");
            log.append(event(&log)).await.expect("event appends");
        }

        let mut external = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("audit file opens for corruption");
        external
            .seek(SeekFrom::Start(0))
            .and_then(|_| external.write_all(b"["))
            .and_then(|_| external.sync_all())
            .expect("same-length corruption persists");

        assert!(
            EvidenceAuditLog::initialize(
                &path,
                64 * 1024,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .is_err(),
            "restart must reject a corrupted keyed chain"
        );
    }

    #[tokio::test]
    async fn restart_rejects_a_truncated_final_record() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        {
            let log = EvidenceAuditLog::initialize(
                &path,
                64 * 1024,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes");
            log.append(event(&log)).await.expect("event appends");
        }

        let original_length = std::fs::metadata(&path)
            .expect("audit metadata reads")
            .len();
        assert!(original_length > 8, "fixture record has truncation room");
        let external = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("audit file opens for truncation");
        external
            .set_len(original_length - 8)
            .and_then(|_| external.sync_all())
            .expect("truncation persists");

        assert!(
            EvidenceAuditLog::initialize(
                &path,
                64 * 1024,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .is_err(),
            "restart must reject a truncated keyed chain"
        );
    }

    #[tokio::test]
    async fn restart_rejects_the_wrong_audit_key() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        {
            let log = EvidenceAuditLog::initialize(
                &path,
                64 * 1024,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes");
            log.append(event(&log)).await.expect("event appends");
        }

        assert!(
            EvidenceAuditLog::initialize(
                &path,
                64 * 1024,
                b"fedcba9876543210fedcba9876543210".to_vec(),
                1,
            )
            .await
            .is_err(),
            "restart must reject a keyed chain under a different audit secret"
        );
    }

    #[tokio::test]
    async fn replacement_master_cannot_append_to_an_existing_evidence_epoch() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let original = b"original-evidence-audit-master-32-bytes";
        let replacement = b"replacement-audit-master-is-also-32-bytes";
        {
            let log = EvidenceAuditLog::initialize(&path, 64 * 1024, original.to_vec(), 1)
                .await
                .expect("original audit epoch initializes");
            log.append(event(&log)).await.expect("event appends");
        }

        assert!(verify_audit_chain(&path, &chain_secret(replacement)).is_err());
        assert!(
            EvidenceAuditLog::initialize(&path, 64 * 1024, replacement.to_vec(), 1)
                .await
                .is_err(),
            "replacement master bytes cannot append under the existing epoch configuration"
        );
        assert!(verify_audit_chain(&path, &chain_secret(original)).is_ok());
    }

    #[tokio::test]
    async fn archived_and_fresh_evidence_audit_epochs_verify_independently() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let archived_path = directory.path().join("audit-epoch-1.jsonl");
        let fresh_path = directory.path().join("audit-epoch-2.jsonl");
        let archived_master = b"archived-evidence-audit-master-32-bytes";
        let fresh_master = b"fresh-evidence-audit-master-value-32-bytes";

        {
            let archived = EvidenceAuditLog::initialize(
                &archived_path,
                64 * 1024,
                archived_master.to_vec(),
                1,
            )
            .await
            .expect("archived epoch initializes");
            archived
                .append(event(&archived))
                .await
                .expect("archived event appends");
        }
        {
            let fresh =
                EvidenceAuditLog::initialize(&fresh_path, 64 * 1024, fresh_master.to_vec(), 2)
                    .await
                    .expect("fresh epoch initializes");
            fresh
                .append(event(&fresh))
                .await
                .expect("fresh event appends");
        }

        assert!(verify_audit_chain(&archived_path, &chain_secret(archived_master)).is_ok());
        assert!(verify_audit_chain(&fresh_path, &chain_secret(fresh_master)).is_ok());
        assert!(verify_audit_chain(&archived_path, &chain_secret(fresh_master)).is_err());
        assert!(verify_audit_chain(&fresh_path, &chain_secret(archived_master)).is_err());
    }

    #[tokio::test]
    async fn same_length_external_mutation_fails_readiness_and_future_appends() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = EvidenceAuditLog::initialize(
            &path,
            64 * 1024,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("audit initializes");
        log.append(event(&log)).await.expect("event appends");

        std::thread::sleep(std::time::Duration::from_millis(2));
        let mut external = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("audit file opens for mutation");
        external
            .seek(SeekFrom::Start(0))
            .and_then(|_| external.write_all(b"["))
            .and_then(|_| external.sync_all())
            .expect("same-length mutation persists");

        assert!(!log.ready().await);
        assert!(log.append(event(&log)).await.is_err());
        assert_eq!(log.startup_verifications(), 1);
    }

    #[tokio::test]
    async fn invalid_release_shape_and_size_limit_fail_closed() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log =
            EvidenceAuditLog::initialize(&path, 1, b"0123456789abcdef0123456789abcdef".to_vec(), 1)
                .await
                .expect("audit initializes");
        assert!(log.append(event(&log)).await.is_err());

        let mut invalid = event(&log);
        invalid.phase = AuditPhase::DisclosureRelease;
        assert!(matches!(
            log.append(invalid).await,
            Err(EvidenceAuditError::InvalidEvent)
        ));
    }

    #[tokio::test]
    async fn second_writer_is_rejected() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let first = EvidenceAuditLog::initialize(
            &path,
            64 * 1024,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("first initializes");
        let second = EvidenceAuditLog::initialize(
            &path,
            64 * 1024,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await;
        assert!(second.is_err());
        drop(first);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pathname_replacement_never_redirects_the_pinned_audit_writer() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let displaced = directory.path().join("displaced.jsonl");
        let log = EvidenceAuditLog::initialize(
            &path,
            64 * 1024,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("audit initializes");

        std::fs::rename(&path, &displaced).expect("initialized file is displaced");
        std::fs::write(&path, b"replacement-canary\n").expect("replacement is created");
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("replacement mode is owner-only");

        assert!(log.append(event(&log)).await.is_err());
        assert!(!log.ready().await);
        assert_eq!(
            std::fs::read_to_string(&path).expect("replacement reads"),
            "replacement-canary\n"
        );
        assert_eq!(
            std::fs::read_to_string(&displaced).expect("pinned file reads"),
            ""
        );
    }

    fn chain_secret(master: &[u8]) -> AuditHashSecret {
        let profile = AuditProfile::production_from_secret_bytes(Zeroizing::new(master.to_vec()))
            .expect("audit profile builds");
        match profile.chain_hasher() {
            AuditChainHasher::Keyed(secret) => secret,
            AuditChainHasher::UnkeyedDevOnly => panic!("production profile must be keyed"),
        }
    }

    fn audit_secret() -> AuditHashSecret {
        chain_secret(b"0123456789abcdef0123456789abcdef")
    }

    fn local_access(log: &EvidenceAuditLog, operation: &str) -> EvidenceAuditEvent {
        let mut event = EvidenceAuditEvent::new(
            AssuranceProfile::Local,
            operation.to_owned(),
            AuditPhase::AccessAttempt,
            "urn:example:requirement:age-bracket:v1".to_owned(),
            format!("sha256:{}", "a".repeat(64)),
            "benefit:eligibility".to_owned(),
            log.pseudonym(
                "requester-v1",
                "urn:example:trust",
                b"raw-requester-token-canary",
            )
            .expect("requester pseudonym builds"),
            AuditAuthority {
                kind: AuthorityKind::Delegated,
                grant_pseudonym: Some(
                    log.pseudonym("grant-v1", "urn:example:trust", b"raw-grant-token-canary")
                        .expect("grant pseudonym builds"),
                ),
            },
            vec![AuditSubject {
                role: "subject".to_owned(),
                selector_profile: "person-v1".to_owned(),
                selector_bundle_pseudonym: Some(
                    log.pseudonym(
                        "subject-v1",
                        "benefit:eligibility",
                        b"person-id-raw-selector-canary",
                    )
                    .expect("subject pseudonym builds"),
                ),
            }],
            ResponseProtection::Signed,
            AuditDecision::Authorized,
            4,
        );
        event.actor_pseudonym = Some(
            log.pseudonym("actor-v1", "urn:example:trust", b"raw-actor-token-canary")
                .expect("actor pseudonym builds"),
        );
        event.source_id = Some("source-private-canary".to_owned());
        event.adapter_id = Some("adapter-private-canary".to_owned());
        event
    }

    fn local_release(access: &EvidenceAuditEvent) -> EvidenceAuditEvent {
        let mut release = access.clone();
        release.event_id = format!("urn:ulid:{}", ulid::Ulid::new());
        release.occurred_at = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::milliseconds(1))
            .expect("timestamp advances")
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        release.phase = AuditPhase::DisclosureRelease;
        release.decision = AuditDecision::Released;
        release.disclosed_concepts = Some(vec!["urn:example:concept:age-bracket".to_owned()]);
        release.evidence_id = Some(format!("urn:example:evidence:{}", ulid::Ulid::new()));
        release.signing_key_id = Some("local-signing-key-1".to_owned());
        release.duration_milliseconds = 19;
        release
    }

    async fn append_local_operation(log: &EvidenceAuditLog, operation: &str) {
        let access = local_access(log, operation);
        let release = local_release(&access);
        log.append(access).await.expect("access event appends");
        log.append(release).await.expect("release event appends");
    }

    #[tokio::test]
    async fn local_inspection_returns_one_closed_two_phase_view() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = EvidenceAuditLog::initialize(
            &path,
            64 * 1024,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("audit initializes");
        let operation = "local-operation-0000000000000001";
        append_local_operation(&log, operation).await;
        drop(log);

        let view = verified_last_local_audit_operation(&path, &audit_secret())
            .expect("stopped local chain verifies");
        let value = serde_json::to_value(view).expect("view serializes");
        assert_eq!(
            value
                .as_object()
                .expect("view is an object")
                .keys()
                .collect::<Vec<_>>(),
            ["events", "operation", "schema"]
        );
        assert_eq!(
            value["schema"],
            serde_json::json!(LOCAL_AUDIT_OPERATION_VIEW_SCHEMA_V1)
        );
        assert_eq!(value["operation"], serde_json::json!(operation));
        let events = value["events"].as_array().expect("events are an array");
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0]
                .as_object()
                .expect("access is an object")
                .keys()
                .collect::<Vec<_>>(),
            [
                "decision",
                "occurredAt",
                "phase",
                "purpose",
                "requesterPseudonym",
                "requirement",
                "responseProtection",
            ]
        );
        assert_eq!(events[0]["phase"], serde_json::json!("access-attempt"));
        assert_eq!(events[0]["decision"], serde_json::json!("authorized"));
        assert_eq!(
            events[1]
                .as_object()
                .expect("release is an object")
                .keys()
                .collect::<Vec<_>>(),
            [
                "decision",
                "disclosedConcepts",
                "evidenceId",
                "occurredAt",
                "phase",
                "purpose",
                "requesterPseudonym",
                "requirement",
                "responseProtection",
            ]
        );
        assert_eq!(events[1]["phase"], serde_json::json!("disclosure-release"));
        assert_eq!(events[1]["decision"], serde_json::json!("released"));

        let rendered = serde_json::to_string(&value).expect("view renders");
        for forbidden in [
            "assuranceProfile",
            "actorPseudonym",
            "grantPseudonym",
            "subjects",
            "selectorProfile",
            "selectorBundlePseudonym",
            "sourceId",
            "adapterId",
            "durationMilliseconds",
            "signingKeyId",
            "bundleRevision",
            "raw-requester-token-canary",
            "raw-grant-token-canary",
            "raw-actor-token-canary",
            "person-id-raw-selector-canary",
            "source-private-canary",
            "adapter-private-canary",
        ] {
            assert!(!rendered.contains(forbidden), "view disclosed {forbidden}");
        }
    }

    #[tokio::test]
    async fn local_inspection_selects_the_last_verified_native_operation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = EvidenceAuditLog::initialize(
            &path,
            64 * 1024,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("audit initializes");
        append_local_operation(&log, "local-operation-0000000000000001").await;
        append_local_operation(&log, "local-operation-0000000000000002").await;
        drop(log);

        let value = serde_json::to_value(
            verified_last_local_audit_operation(&path, &audit_secret())
                .expect("stopped local chain verifies"),
        )
        .expect("view serializes");
        assert_eq!(
            value["operation"],
            serde_json::json!("local-operation-0000000000000002")
        );
        assert_eq!(value["events"].as_array().map(Vec::len), Some(2));
    }

    #[tokio::test]
    async fn local_inspection_verifies_the_full_rotated_keyed_chain() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = EvidenceAuditLog::initialize(
            &path,
            4096,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("audit initializes");
        for index in 0..12 {
            append_local_operation(&log, &format!("local-operation-{index:016}")).await;
        }
        drop(log);
        assert!(
            audit_segment_paths(&path)
                .expect("segments enumerate")
                .len()
                > 2,
            "fixture rotates through sealed history"
        );

        let value = serde_json::to_value(
            verified_last_local_audit_operation(&path, &audit_secret())
                .expect("the full keyed chain verifies"),
        )
        .expect("view serializes");
        assert_eq!(
            value["operation"],
            serde_json::json!("local-operation-0000000000000011")
        );
    }

    #[tokio::test]
    async fn local_inspection_rejects_tampering_wrong_secret_and_live_writer() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let live_path = directory.path().join("live.jsonl");
        let live = EvidenceAuditLog::initialize(
            &live_path,
            64 * 1024,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("audit initializes");
        append_local_operation(&live, "local-operation-0000000000000001").await;
        assert!(
            verified_last_local_audit_operation(&live_path, &audit_secret()).is_err(),
            "a live writer fails rather than yielding a partial view"
        );
        drop(live);

        let wrong = AuditHashSecret::new(b"abcdef0123456789abcdef0123456789".to_vec())
            .expect("wrong secret builds");
        assert!(
            verified_last_local_audit_operation(&live_path, &wrong).is_err(),
            "a wrong secret yields no view"
        );

        rewrite_segment_line(&live_path, 0, corrupt_line);
        assert!(
            verified_last_local_audit_operation(&live_path, &audit_secret()).is_err(),
            "tampered keyed history yields no view"
        );
    }

    #[tokio::test]
    async fn local_inspection_rejects_missing_history_and_active_segment() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = EvidenceAuditLog::initialize(
            &path,
            4096,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("audit initializes");
        for index in 0..12 {
            append_local_operation(&log, &format!("local-operation-{index:016}")).await;
        }
        drop(log);
        let segments = audit_segment_paths(&path).expect("segments enumerate");
        assert!(segments.len() > 3, "fixture has a middle sealed segment");
        std::fs::remove_file(&segments[1]).expect("middle segment is removed");
        assert!(matches!(
            verified_last_local_audit_operation(&path, &audit_secret()),
            Err(EvidenceAuditError::SegmentMissing { sequence: 2 })
        ));

        let active_path = directory.path().join("missing-active.jsonl");
        let active = EvidenceAuditLog::initialize(
            &active_path,
            64 * 1024,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("audit initializes");
        append_local_operation(&active, "local-operation-0000000000000001").await;
        drop(active);
        std::fs::remove_file(&active_path).expect("active segment is removed");
        assert!(
            verified_last_local_audit_operation(&active_path, &audit_secret()).is_err(),
            "an absent active segment yields no view"
        );
    }

    #[tokio::test]
    async fn local_inspection_rejects_a_keyed_but_invalid_native_event() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = EvidenceAuditLog::initialize(
            &directory.path().join("pseudonyms.jsonl"),
            64 * 1024,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("pseudonym helper initializes");
        let mut invalid = local_access(&log, "local-operation-0000000000000001");
        invalid.decision = AuditDecision::Released;
        drop(log);
        let hasher = AuditChainHasher::keyed(audit_secret());
        let envelope = AuditEnvelope::new_with_hasher(
            serde_json::to_value(invalid).expect("invalid event serializes"),
            None,
            &hasher,
        )
        .expect("invalid native event is still keyed");
        std::fs::write(&path, envelope.to_jsonl().expect("envelope renders"))
            .expect("audit writes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("audit mode is owner-only");
        }

        assert!(
            verified_last_local_audit_operation(&path, &audit_secret()).is_err(),
            "a valid chain hash cannot bless a non-native event"
        );
    }

    #[tokio::test]
    async fn local_inspection_fails_instead_of_truncating_at_any_bound() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = EvidenceAuditLog::initialize(
            &path,
            4096,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("audit initializes");
        for index in 0..4 {
            append_local_operation(&log, &format!("local-operation-{index:016}")).await;
        }
        drop(log);
        let defaults = LocalAuditInspectionBounds::DEFAULT;
        for bounds in [
            LocalAuditInspectionBounds {
                maximum_segments: 1,
                ..defaults
            },
            LocalAuditInspectionBounds {
                maximum_records: 1,
                ..defaults
            },
            LocalAuditInspectionBounds {
                maximum_output_bytes: 1,
                ..defaults
            },
        ] {
            assert!(
                verified_last_local_audit_operation_with_bounds(&path, &audit_secret(), bounds)
                    .is_err(),
                "a bound failure yields no truncated view"
            );
        }
    }

    /// Change one byte of a record without changing its length, so the record
    /// no longer matches the hash the chain recorded for it.
    fn corrupt_line(line: &str) -> String {
        let mut bytes = line.as_bytes().to_vec();
        for byte in bytes.iter_mut() {
            if byte.is_ascii_lowercase() {
                *byte = if *byte == b'z' { b'y' } else { *byte + 1 };
                break;
            }
        }
        String::from_utf8(bytes).expect("a corrupted record stays UTF-8")
    }

    fn rewrite_segment_line(path: &Path, index: usize, rewrite: impl Fn(&str) -> String) {
        let contents = std::fs::read_to_string(path).expect("segment reads");
        let mut lines: Vec<String> = contents.lines().map(str::to_owned).collect();
        lines[index] = rewrite(&lines[index]);
        let mut rewritten = lines.join("\n");
        rewritten.push('\n');
        std::fs::write(path, rewritten).expect("segment rewrites");
    }

    /// Readiness reports on the chain, not on how busy the writer is. The
    /// fingerprint it compares is the one the writer advances on every append,
    /// so a probe that read it outside the writer's lock would see the
    /// service's own traffic as external mutation and flap under load.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn readiness_holds_while_appends_are_in_flight() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = Arc::new(
            EvidenceAuditLog::initialize(
                &path,
                1024 * 1024,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes"),
        );

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut writers = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let log = Arc::clone(&log);
            let stop = Arc::clone(&stop);
            writers.spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    log.append(event(&log)).await.expect("event appends");
                }
            });
        }

        // Probe often enough to land inside a durable write rather than only in
        // the gaps between them, which is the window the race lives in.
        let mut probes = 0usize;
        let mut unready = 0usize;
        for _ in 0..200 {
            if log.ready().await {
                probes += 1;
            } else {
                unready += 1;
            }
            tokio::task::yield_now().await;
        }
        stop.store(true, Ordering::Relaxed);
        while let Some(result) = writers.join_next().await {
            result.expect("writer task joins");
        }

        assert_eq!(
            unready, 0,
            "readiness stayed true through {probes} probes but reported unready {unready} times while the service was writing its own audit records"
        );
    }

    /// The point of group commit: appends that arrive while a durable write is
    /// in flight join the next one instead of each paying their own `fsync`.
    #[tokio::test]
    async fn concurrent_appends_share_durable_writes() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = Arc::new(
            EvidenceAuditLog::initialize(
                &path,
                1024 * 1024,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes"),
        );

        const APPENDS: usize = 64;
        let mut appends = tokio::task::JoinSet::new();
        for _ in 0..APPENDS {
            let log = Arc::clone(&log);
            appends.spawn(async move { log.append(event(&log)).await.expect("event appends") });
        }
        let mut hashes = Vec::new();
        while let Some(result) = appends.join_next().await {
            hashes.push(result.expect("append task joins").record_hash);
        }
        hashes.sort_unstable();
        hashes.dedup();
        assert_eq!(
            hashes.len(),
            APPENDS,
            "every concurrent append gets its own chain position"
        );

        let writes = log.durable_writes();
        assert!(
            writes < APPENDS,
            "concurrent appends must share durable writes, saw {writes} for {APPENDS} records"
        );
        drop(log);

        let summary = verify_audit_chain(&path, &audit_secret()).expect("chain verifies");
        assert_eq!(
            summary.records, APPENDS,
            "batching must not drop or duplicate a record"
        );
        assert!(summary.active_verified);
    }

    /// A durable write that fails leaves the in-memory head ahead of the disk,
    /// so the sink must refuse everything afterwards rather than chain onto a
    /// record that was never written.
    #[tokio::test]
    async fn a_failed_durable_write_poisons_the_sink_instead_of_forking_the_chain() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = EvidenceAuditLog::initialize(
            &path,
            1024 * 1024,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("audit initializes");
        log.append(event(&log)).await.expect("event appends");
        assert!(log.ready().await);

        // Truncating through a second handle leaves the writer's pinned handle
        // valid but the file no longer the one it fingerprinted.
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("external truncation opens");

        let failed = log.append(event(&log)).await;
        assert!(
            failed.is_err(),
            "an externally modified file fails the write"
        );

        let after = log.append(event(&log)).await;
        assert!(
            after.is_err(),
            "the sink stays failed rather than continuing on a head the disk never received"
        );
        assert!(
            !log.ready().await,
            "a poisoned sink never reports itself ready again"
        );
    }

    /// Callers wait for a batch they did not write, so a batch that fails has
    /// to hand every one of them the failure. Waiting on a durable write that
    /// will never arrive would hang the request that asked for the audit
    /// record, which is a worse outcome than refusing it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_poisoned_sink_fails_concurrent_waiters_instead_of_hanging_them() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = Arc::new(
            EvidenceAuditLog::initialize(
                &path,
                1024 * 1024,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes"),
        );
        log.append(event(&log)).await.expect("event appends");
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("external truncation opens");
        assert!(
            log.append(event(&log)).await.is_err(),
            "an externally modified file fails the write"
        );

        let mut waiters = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let log = Arc::clone(&log);
            waiters.spawn(async move { log.append(event(&log)).await });
        }
        let outcomes = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let mut outcomes = Vec::new();
            while let Some(result) = waiters.join_next().await {
                outcomes.push(result.expect("append task joins"));
            }
            outcomes
        })
        .await
        .expect("a poisoned sink answers every waiter rather than hanging one");

        assert_eq!(outcomes.len(), 32);
        assert!(
            outcomes.iter().all(Result::is_err),
            "every waiter is told the chain stopped, none is handed a position that was never written"
        );
    }

    #[tokio::test]
    async fn storage_usage_counts_every_segment_and_grows_across_rotation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = EvidenceAuditLog::initialize(
            &path,
            4096,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("audit initializes");

        let empty = log.storage_usage().await.expect("usage reads");
        assert_eq!(
            empty.segments, 1,
            "the active segment counts before any append"
        );
        assert_eq!(empty.bytes, 0);

        log.append(event(&log)).await.expect("event appends");
        let single = log.storage_usage().await.expect("usage reads");
        assert_eq!(single.segments, 1);
        assert!(single.bytes > 0, "an appended record occupies bytes");

        const RECORDS: usize = 24;
        for _ in 0..RECORDS {
            log.append(event(&log)).await.expect("event appends");
        }

        let rolled = log.storage_usage().await.expect("usage reads");
        assert!(
            rolled.segments > 1,
            "a bound smaller than the appended volume must roll at least once"
        );
        assert_eq!(
            rolled.segments,
            audit_segment_paths(&path)
                .expect("segments enumerate")
                .len(),
            "usage counts sealed segments as well as the active one"
        );
        assert!(
            rolled.bytes > single.bytes,
            "sealed history keeps counting toward the footprint after rotation"
        );

        // Retention is the operator's, so archiving a sealed segment must show
        // up as a smaller footprint rather than being masked by a counter that
        // only ever accumulates.
        let segments = audit_segment_paths(&path).expect("segments enumerate");
        let oldest = segments.first().expect("rotation sealed a segment");
        let archived = std::fs::metadata(oldest).expect("sealed metadata").len();
        std::fs::remove_file(oldest).expect("sealed segment archives away");

        let pruned = log.storage_usage().await.expect("usage reads");
        assert_eq!(pruned.segments, rolled.segments - 1);
        assert_eq!(pruned.bytes, rolled.bytes - archived);
    }

    /// Append past the per-segment bound and prove the sealed segment and the
    /// active segment are one chain, not two independent ones.
    #[tokio::test]
    async fn appends_rotate_into_sealed_segments_and_the_chain_spans_the_seam() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = EvidenceAuditLog::initialize(
            &path,
            4096,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("audit initializes");

        const RECORDS: usize = 24;
        for _ in 0..RECORDS {
            log.append(event(&log)).await.expect("event appends");
        }

        let segments = audit_segment_paths(&path).expect("segments enumerate");
        assert!(
            segments.len() > 1,
            "a bound smaller than the appended volume must roll at least once"
        );
        assert_eq!(
            segments.last().expect("an active segment exists"),
            &path,
            "the configured path stays the active segment"
        );
        assert!(
            log.ready().await,
            "the chain stays ready across its own rotation"
        );

        // Against a live writer the verifier proves sealed history only, rather
        // than racing an in-flight append and calling a partial line corruption.
        let live = verify_audit_chain(&path, &audit_secret())
            .expect("sealed history verifies while the writer runs");
        assert!(!live.active_verified);
        assert_eq!(live.segments, segments.len() - 1);
        drop(log);

        let summary = verify_audit_chain(&path, &audit_secret())
            .expect("the chain verifies across every seam");
        assert!(summary.active_verified);
        assert_eq!(summary.records, RECORDS, "no record is lost to rotation");
        assert_eq!(summary.segments, segments.len());
        assert_eq!(summary.first_sequence, Some(1));
        assert_eq!(summary.last_sequence, Some(segments.len() as u64 - 1));
    }

    /// Rotation must never be reachable ahead of the pinned-path check, or an
    /// external rename would be laundered into a legitimate-looking seal.
    #[tokio::test]
    async fn pathname_replacement_is_rejected_even_when_the_append_would_rotate() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = EvidenceAuditLog::initialize(
            &path,
            4096,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("audit initializes");
        // Fill the active segment so the next append is one that would rotate.
        while std::fs::metadata(&path)
            .expect("active segment reads")
            .len()
            == 0
            || audit_segment_paths(&path)
                .expect("segments enumerate")
                .len()
                < 2
        {
            log.append(event(&log)).await.expect("event appends");
        }
        let sealed_before = audit_segment_paths(&path)
            .expect("segments enumerate")
            .len();

        let displaced = directory.path().join("displaced.jsonl");
        std::fs::rename(&path, &displaced).expect("the active segment is renamed away");
        std::fs::write(&path, "").expect("a replacement is planted");

        assert!(
            log.append(event(&log)).await.is_err(),
            "an append must not continue onto a replaced pathname, rotation or not"
        );
        assert!(!log.ready().await);
        assert_eq!(
            audit_segment_paths(&path)
                .expect("segments enumerate")
                .len(),
            sealed_before,
            "a rejected append must not seal anything"
        );
    }

    /// A gap in sealed history is reported as a missing segment, not as a hash
    /// break, so an operator can tell archival from tampering.
    #[tokio::test]
    async fn an_archived_middle_segment_is_reported_as_missing_not_as_corruption() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        {
            let log = EvidenceAuditLog::initialize(
                &path,
                2048,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes");
            for _ in 0..48 {
                log.append(event(&log)).await.expect("event appends");
            }
        }
        let segments = audit_segment_paths(&path).expect("segments enumerate");
        assert!(
            segments.len() >= 4,
            "the fixture needs a sealed segment that is neither first nor last"
        );
        std::fs::remove_file(&segments[1]).expect("a middle segment is archived away");

        assert!(
            matches!(
                verify_audit_chain(&path, &audit_secret()),
                Err(EvidenceAuditError::SegmentMissing { sequence: 2 })
            ),
            "a gap must name the absent sequence rather than look like tampering"
        );
    }

    /// A restart after rotation must resume the sealed chain rather than
    /// starting a second one.
    #[tokio::test]
    async fn a_restart_after_rotation_continues_from_the_sealed_tail() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        const BEFORE: usize = 24;
        {
            let log = EvidenceAuditLog::initialize(
                &path,
                4096,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes");
            for _ in 0..BEFORE {
                log.append(event(&log)).await.expect("event appends");
            }
            assert!(
                audit_segment_paths(&path)
                    .expect("segments enumerate")
                    .len()
                    > 1
            );
        }

        let restarted = EvidenceAuditLog::initialize(
            &path,
            4096,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("a rotated chain verifies on restart");
        restarted
            .append(event(&restarted))
            .await
            .expect("a restarted rotated chain accepts an append");
        drop(restarted);

        let summary = verify_audit_chain(&path, &audit_secret())
            .expect("the chain verifies after a restart across a seam");
        assert_eq!(summary.records, BEFORE + 1);
    }

    /// Crashing between the rename and the creation of the replacement leaves
    /// no active segment. Restart must recover the chain head from the sealed
    /// tail instead of silently beginning a new chain at genesis.
    #[tokio::test]
    async fn a_missing_active_segment_recovers_from_the_sealed_tail() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        const BEFORE: usize = 24;
        {
            let log = EvidenceAuditLog::initialize(
                &path,
                4096,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes");
            for _ in 0..BEFORE {
                log.append(event(&log)).await.expect("event appends");
            }
        }
        let segments = audit_segment_paths(&path).expect("segments enumerate");
        assert!(segments.len() > 1, "the fixture must have rolled");
        let sealed_records: usize = segments[..segments.len() - 1]
            .iter()
            .map(|segment| {
                std::fs::read_to_string(segment)
                    .expect("sealed segment reads")
                    .lines()
                    .count()
            })
            .sum();
        std::fs::remove_file(&path).expect("the active segment is lost to a crash");

        let restarted = EvidenceAuditLog::initialize(
            &path,
            4096,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("a missing active segment is recreated");
        restarted
            .append(event(&restarted))
            .await
            .expect("appends resume after the active segment is lost");
        drop(restarted);

        let summary = verify_audit_chain(&path, &audit_secret())
            .expect("the recovered chain still spans its seams");
        assert_eq!(
            summary.records,
            sealed_records + 1,
            "the record written after recovery continues sealed history, and the \
             records lost with the active segment are not silently replaced"
        );
        assert!(
            summary.records < BEFORE + 1,
            "the fixture must actually have lost the active segment's records"
        );
        assert!(
            summary.head.is_some(),
            "the recovered chain continues rather than restarting at genesis"
        );
    }

    /// The chain head is recovered from the last record of the newest sealed
    /// segment, so corrupting that record is caught at startup.
    #[tokio::test]
    async fn a_corrupt_sealed_tail_is_rejected_at_startup() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        {
            let log = EvidenceAuditLog::initialize(
                &path,
                4096,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes");
            for _ in 0..24 {
                log.append(event(&log)).await.expect("event appends");
            }
        }

        let segments = audit_segment_paths(&path).expect("segments enumerate");
        let newest_sealed = segments[segments.len() - 2].clone();
        let sealed_lines = std::fs::read_to_string(&newest_sealed)
            .expect("sealed segment reads")
            .lines()
            .count();
        rewrite_segment_line(&newest_sealed, sealed_lines - 1, corrupt_line);

        assert!(
            EvidenceAuditLog::initialize(
                &path,
                4096,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .is_err(),
            "a corrupt sealed tail must not be accepted as the chain head"
        );
    }

    /// Boot-time verification deliberately covers only the active segment and
    /// the sealed tail it chains to, so history is bounded rather than replayed
    /// from genesis. This pins the accepted cost: corruption inside an already
    /// sealed segment starts the service and is caught by the out-of-band
    /// verifier instead.
    #[tokio::test]
    async fn sealed_segment_corruption_passes_startup_and_fails_the_verifier() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        {
            let log = EvidenceAuditLog::initialize(
                &path,
                4096,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes");
            for _ in 0..24 {
                log.append(event(&log)).await.expect("event appends");
            }
        }

        let segments = audit_segment_paths(&path).expect("segments enumerate");
        let oldest_sealed = segments[0].clone();
        assert!(
            std::fs::read_to_string(&oldest_sealed)
                .expect("sealed segment reads")
                .lines()
                .count()
                > 1,
            "the corrupted record must not be the sealed tail"
        );
        rewrite_segment_line(&oldest_sealed, 0, corrupt_line);

        let restarted = EvidenceAuditLog::initialize(
            &path,
            4096,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("startup does not replay sealed history");
        assert!(restarted.ready().await);
        drop(restarted);

        assert!(
            verify_audit_chain(&path, &audit_secret()).is_err(),
            "the out-of-band verifier is what catches sealed-segment corruption"
        );
    }
}
