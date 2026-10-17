//! Separately governed target authority with one durable activation commit.
//!
//! A running process captures one validated snapshot. Activating another
//! snapshot prepares the next controlled restart; it never changes in-flight
//! authority or bypasses live authenticated task-grant checks.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

use registry_platform_config::{is_sha256_label, sha256_uri};
use registry_platform_crypto::{canonicalize_json, domain_separated_sha256};
use registry_platform_yaml::{ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::audit::EvidenceAuditLog;
use crate::config::{AuthorityProfile, EvidenceConfig, OrderedMap};

pub const AUTHORITY_API_VERSION: &str =
    "id.registrystack.org/formats/evidence/compiled-target-authority/v1alpha1";
pub const AUTHORITY_KIND: &str = "EvidenceCompiledTargetAuthority";
pub const AUTHORITY_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: AUTHORITY_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(AUTHORITY_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};
const STATE_API_VERSION: &str = "id.registrystack.org/formats/evidence/authority-state/v1alpha1";
const STATE_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: "EvidenceAuthorityState",
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(STATE_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};
const REVISION_DOMAIN: &[u8] = b"registry.evidence.target-authority/v1\0";
const STATE_FILE: &str = "authority-state.json";
const MAX_STATE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ACTIVATIONS: usize = 4096;

/// The same complete authority model is compiled for local and production
/// targets. Definition references in this compiled document are Requirement
/// URIs; the authoring compiler resolves local definition names once.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityDocument {
    pub target: String,
    pub project: String,
    pub access_profiles: OrderedMap<AuthorityProfile>,
}

#[derive(Debug, Error)]
pub enum AuthorityError {
    #[error("{}", .0.render_human())]
    Refused(Box<registry_platform_yaml::Report>),
    #[error("target authority is unavailable; activate a valid authority document before startup")]
    Unavailable,
    #[error("target authority document is invalid; check its envelope and complete grant tuples")]
    InvalidDocument,
    #[error("target authority exceeds a package ceiling or names another project")]
    OutsideCeiling,
    #[error("target authority activation is not for this package and target; activate it again for the selected package")]
    BindingMismatch,
    #[error("target authority storage is invalid; use an owned directory with no group or world write access")]
    UnsafeStorage,
    #[error("target authority activation could not be committed durably; inspect the active revision before retrying")]
    CommitFailed,
    #[error("target authority activation history reached its storage bound")]
    HistoryFull,
    #[error("target authority audit delivery failed; inspect history and retry the activation")]
    AuditFailed,
}

impl AuthorityDocument {
    pub fn parse(file: &str, bytes: &[u8]) -> Result<Self, AuthorityError> {
        Reader::new(file)
            .decode::<Self>(bytes, &Expect::one(&AUTHORITY_FORMAT))
            .map(|decoded| decoded.value)
            .map_err(|report| AuthorityError::Refused(Box::new(report)))
    }

    pub fn validate_for(
        &self,
        target: &str,
        config: &EvidenceConfig,
    ) -> Result<(), AuthorityError> {
        if !local_id(&self.target)
            || !local_id(&self.project)
            || self.target != target
            || config.project.as_deref() != Some(self.project.as_str())
        {
            return Err(AuthorityError::BindingMismatch);
        }
        // Absence must never turn a portable definition into an unrestricted
        // target grant. The normalized compiler declares every dimension.
        if config.requirements.iter().any(|definition| {
            definition.grant_ceiling.is_none() || definition.representations.is_none()
        }) {
            return Err(AuthorityError::OutsideCeiling);
        }
        let mut effective = config.clone();
        effective.authority_profiles = self.access_profiles.clone();
        effective
            .validate()
            .map_err(|_| AuthorityError::OutsideCeiling)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityActivation {
    pub sequence: u64,
    pub package_digest: String,
    pub authority_revision: String,
    pub authority_digest: String,
    pub activated_at: String,
    pub document: AuthorityDocument,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthorityState {
    activations: Vec<AuthorityActivation>,
    #[serde(default)]
    audit: Vec<ActivationAudit>,
}

/// Minimal activation audit committed atomically with authority history.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActivationAudit {
    pub schema: String,
    pub activation_id: String,
    #[serde(default)]
    pub delivered: bool,
    /// Internal retry binding, never copied into the configured audit sink.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) retry_context_digest: Option<String>,
    pub sequence: u64,
    pub recorded_at: String,
    pub outcome: ActivationOutcome,
    pub package_digest: String,
    pub authority_revision: String,
    pub authority_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activation_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_reference_hash: Option<String>,
}
#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActivationOutcome {
    Applied,
    Refused,
}

/// Inspect minimal events without disclosing authority grants or operator references.
pub fn activation_audit(root: &Path) -> Result<Vec<ActivationAudit>, AuthorityError> {
    let _root = check_root(root)?;
    Ok(read_state(root)?.audit)
}

/// A validated immutable copy, retained for the complete process lifetime.
#[derive(Debug, Clone)]
pub struct AuthoritySnapshot {
    active: AuthorityActivation,
}

impl AuthoritySnapshot {
    pub fn revision(&self) -> &str {
        &self.active.authority_revision
    }
    pub fn digest(&self) -> &str {
        &self.active.authority_digest
    }
    pub fn sequence(&self) -> u64 {
        self.active.sequence
    }
    pub fn profiles(&self) -> &OrderedMap<AuthorityProfile> {
        &self.active.document.access_profiles
    }

    pub fn effective_grant_digest(
        &self,
        config: &EvidenceConfig,
    ) -> Result<String, AuthorityError> {
        let ceilings = config
            .requirements
            .iter()
            .map(|definition| {
                serde_json::json!({
                    "requirement": definition.id,
                    "grantCeiling": definition.grant_ceiling,
                    "purposes": definition.purposes,
                    "subjects": definition.subject_roles,
                    "representations": definition.representations,
                    "subjectBinding": definition.subject_binding_mode(),
                })
            })
            .collect::<Vec<_>>();
        digest_value(&serde_json::json!({"ceilings":ceilings,"accessProfiles":self.profiles()}))
    }
}

fn local_id(value: &str) -> bool {
    registry_platform_yaml::LocalId::new(value).is_ok()
}

fn digest_value(value: &serde_json::Value) -> Result<String, AuthorityError> {
    canonicalize_json(value)
        .map(|bytes| sha256_uri(&bytes))
        .map_err(|_| AuthorityError::InvalidDocument)
}

fn document_identity(document: &AuthorityDocument) -> Result<(String, String), AuthorityError> {
    let value = serde_json::to_value(document).map_err(|_| AuthorityError::InvalidDocument)?;
    let bytes = canonicalize_json(&value).map_err(|_| AuthorityError::InvalidDocument)?;
    let revision = domain_separated_sha256(REVISION_DOMAIN, &bytes);
    let mut label = String::from("sha256:");
    for byte in revision {
        use std::fmt::Write as _;
        let _ = write!(label, "{byte:02x}");
    }
    Ok((label, sha256_uri(&bytes)))
}

fn check_root(root: &Path) -> Result<File, AuthorityError> {
    if !root.is_absolute() {
        return Err(AuthorityError::UnsafeStorage);
    }
    let metadata = fs::symlink_metadata(root).map_err(|_| AuthorityError::Unavailable)?;
    if !metadata.is_dir()
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(AuthorityError::UnsafeStorage);
    }
    File::open(root).map_err(|_| AuthorityError::UnsafeStorage)
}

fn read_state(root: &Path) -> Result<AuthorityState, AuthorityError> {
    let mut file = crate::bundle::open_no_follow(&root.join(STATE_FILE))
        .map_err(|_| AuthorityError::Unavailable)?;
    let metadata = file.metadata().map_err(|_| AuthorityError::Unavailable)?;
    if !metadata.is_file()
        || metadata.len() > MAX_STATE_BYTES
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(AuthorityError::UnsafeStorage);
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AuthorityError::Unavailable)?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(AuthorityError::HistoryFull);
    }
    // The shared YAML reader enforces duplicate-member rejection, the closed
    // generated envelope and the same limits as every read-back format.
    let state = Reader::new(STATE_FILE)
        .decode::<AuthorityState>(&bytes, &Expect::one(&STATE_FORMAT))
        .map_err(|_| AuthorityError::InvalidDocument)?
        .value;
    if (state.activations.is_empty() && state.audit.is_empty())
        || state.activations.len() > MAX_ACTIVATIONS
        || state.audit.len() > MAX_ACTIVATIONS
    {
        return Err(AuthorityError::InvalidDocument);
    }
    for (index, activation) in state.activations.iter().enumerate() {
        let (revision, digest) = document_identity(&activation.document)?;
        if activation.sequence != index as u64 + 1
            || activation.authority_revision != revision
            || activation.authority_digest != digest
            || !is_sha256_label(&activation.package_digest)
            || chrono::DateTime::parse_from_rfc3339(&activation.activated_at).is_err()
        {
            return Err(AuthorityError::InvalidDocument);
        }
    }
    for (index, event) in state.audit.iter().enumerate() {
        if event.schema != "evidence-activation-audit/v1"
            || event.activation_id.parse::<ulid::Ulid>().is_err()
            || event
                .retry_context_digest
                .as_ref()
                .is_some_and(|digest| !is_sha256_label(digest))
            || event.sequence != index as u64 + 1
            || !is_sha256_label(&event.package_digest)
            || !is_sha256_label(&event.authority_digest)
            || !is_sha256_label(&event.authority_revision)
            || event.operator_reference_hash.as_ref().is_some_and(|hash| {
                hash.strip_prefix("hmac-sha256:").is_none_or(|digest| {
                    digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
            })
            || chrono::DateTime::parse_from_rfc3339(&event.recorded_at).is_err()
        {
            return Err(AuthorityError::InvalidDocument);
        }
        match (event.outcome, event.activation_sequence) {
            (ActivationOutcome::Applied, Some(sequence)) => {
                let active = sequence
                    .checked_sub(1)
                    .and_then(|index| usize::try_from(index).ok())
                    .and_then(|index| state.activations.get(index))
                    .ok_or(AuthorityError::InvalidDocument)?;
                if active.authority_revision != event.authority_revision
                    || active.authority_digest != event.authority_digest
                    || active.package_digest != event.package_digest
                {
                    return Err(AuthorityError::InvalidDocument);
                }
            }
            (ActivationOutcome::Refused, None) => {}
            _ => return Err(AuthorityError::InvalidDocument),
        }
    }
    Ok(state)
}

/// Capture and validate the active snapshot before any identity credentials or
/// source effects. A running process does not reread this mutable store.
pub fn load(
    root: &Path,
    target: &str,
    config: &EvidenceConfig,
    package_digest: &str,
) -> Result<AuthoritySnapshot, AuthorityError> {
    let _root = check_root(root)?;
    let active = read_state(root)?
        .activations
        .pop()
        .ok_or(AuthorityError::Unavailable)?;
    if active.package_digest != package_digest {
        return Err(AuthorityError::BindingMismatch);
    }
    active.document.validate_for(target, config)?;
    Ok(AuthoritySnapshot { active })
}

/// Read only the durable committed history. Prepared temporary files are never
/// considered activations and cannot become effective after a partial write.
pub fn history(root: &Path) -> Result<Vec<AuthorityActivation>, AuthorityError> {
    let _root = check_root(root)?;
    Ok(read_state(root)?.activations)
}

/// Validate completely, then atomically commit the active snapshot and history
/// as one document. A repeated exact activation is idempotent. One file lock
/// serializes concurrent operators, and every acknowledged activation is fsynced.
#[cfg(test)]
pub(crate) fn activate(
    root: &Path,
    target: &str,
    config: &EvidenceConfig,
    package_digest: &str,
    document: &AuthorityDocument,
) -> Result<AuthoritySnapshot, AuthorityError> {
    activate_with_sync(
        root,
        target,
        config,
        package_digest,
        document,
        &mut File::sync_all,
    )
}

/// Deliver activation records through the configured platform audit boundary.
/// The state retains pending records before delivery. A failed append leaves the
/// committed authority inspectable and the same record available to retry.
pub async fn activate_with_operator(
    root: &Path,
    target: &str,
    config: &EvidenceConfig,
    package_digest: &str,
    document: &AuthorityDocument,
    operator_reference: Option<&str>,
    audit: &EvidenceAuditLog,
) -> Result<AuthoritySnapshot, AuthorityError> {
    if !root.is_absolute() {
        return Err(AuthorityError::UnsafeStorage);
    }
    fs::create_dir_all(root).map_err(|_| AuthorityError::UnsafeStorage)?;
    check_root(root)?;
    // Serialize delivery and its acknowledgement across operator processes.
    // Acquire off the async executor so another operator can finish its append.
    let root_owned = root.to_owned();
    let _delivery_lock =
        tokio::task::spawn_blocking(move || locked_file(&root_owned, "activation-delivery.lock"))
            .await
            .map_err(|_| AuthorityError::CommitFailed)??;
    let result = activate_recorded_with_sync(
        root,
        target,
        config,
        package_digest,
        document,
        operator_reference.map(|reference| (reference, audit)),
        &mut File::sync_all,
    );
    if !root.join(STATE_FILE).exists() {
        return result;
    }
    // Protect acknowledgement against an independent history writer too.
    let root_owned = root.to_owned();
    let _state_lock =
        tokio::task::spawn_blocking(move || locked_file(&root_owned, "authority.lock"))
            .await
            .map_err(|_| AuthorityError::CommitFailed)??;
    let mut state = read_state(root)?;
    for index in 0..state.audit.len() {
        if !state.audit[index].delivered {
            audit
                .append_activation(&state.audit[index])
                .await
                .map_err(|_| AuthorityError::AuditFailed)?;
            state.audit[index].delivered = true;
            commit_state(root, &check_root(root)?, &state, &mut File::sync_all)?;
        }
    }
    result
}

fn locked_file(root: &Path, name: &str) -> Result<File, AuthorityError> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(root.join(name))
        .map_err(|_| AuthorityError::UnsafeStorage)?;
    let metadata = lock.metadata().map_err(|_| AuthorityError::UnsafeStorage)?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(AuthorityError::UnsafeStorage);
    }
    fs2::FileExt::lock_exclusive(&lock).map_err(|_| AuthorityError::CommitFailed)?;
    Ok(lock)
}

/// The committed file and every directory entry naming it must be durable
/// before acknowledgement. Repeating this barrier is necessary on retries:
/// an earlier rename can be visible even when its directory sync failed.
fn sync_committed(
    root: &Path,
    directory: &File,
    sync: &mut impl FnMut(&File) -> std::io::Result<()>,
) -> Result<(), AuthorityError> {
    let committed = crate::bundle::open_no_follow(&root.join(STATE_FILE))
        .map_err(|_| AuthorityError::CommitFailed)?;
    sync(&committed).map_err(|_| AuthorityError::CommitFailed)?;
    sync(directory).map_err(|_| AuthorityError::CommitFailed)?;
    // Activation may have created the store and ancestors. Syncing their
    // parent entries also covers a retry after a previous incomplete barrier.
    if let Some(parent) = root.parent() {
        for ancestor in parent.ancestors() {
            let parent = File::open(ancestor).map_err(|_| AuthorityError::CommitFailed)?;
            sync(&parent).map_err(|_| AuthorityError::CommitFailed)?;
        }
    }
    Ok(())
}

#[cfg(test)]
fn activate_with_sync(
    root: &Path,
    target: &str,
    config: &EvidenceConfig,
    package_digest: &str,
    document: &AuthorityDocument,
    sync: &mut impl FnMut(&File) -> std::io::Result<()>,
) -> Result<AuthoritySnapshot, AuthorityError> {
    activate_recorded_with_sync(root, target, config, package_digest, document, None, sync)
}

fn activate_recorded_with_sync(
    root: &Path,
    target: &str,
    config: &EvidenceConfig,
    package_digest: &str,
    document: &AuthorityDocument,
    operator: Option<(&str, &EvidenceAuditLog)>,
    sync: &mut impl FnMut(&File) -> std::io::Result<()>,
) -> Result<AuthoritySnapshot, AuthorityError> {
    if operator.is_some_and(|(value, _)| {
        value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)
    }) {
        return Err(AuthorityError::InvalidDocument);
    }
    let validation = document.validate_for(target, config);
    if !is_sha256_label(package_digest) {
        return Err(AuthorityError::BindingMismatch);
    }
    if !root.is_absolute() {
        return Err(AuthorityError::UnsafeStorage);
    }
    fs::create_dir_all(root).map_err(|_| AuthorityError::UnsafeStorage)?;
    let directory = check_root(root)?;
    let _lock = locked_file(root, "authority.lock")?;
    let mut state = if root.join(STATE_FILE).exists() {
        read_state(root)?
    } else {
        AuthorityState {
            activations: Vec::new(),
            audit: Vec::new(),
        }
    };
    let (revision, digest) = document_identity(document)?;
    let validation = validation.and_then(|()| {
        if state.activations.last().is_some_and(|active| {
            active.document.target != target || active.document.project != document.project
        }) {
            Err(AuthorityError::BindingMismatch)
        } else {
            Ok(())
        }
    });
    let existing = state
        .activations
        .last()
        .filter(|active| {
            active.package_digest == package_digest && active.authority_revision == revision
        })
        .cloned();
    if validation.is_ok()
        && existing.as_ref().is_some_and(|active| {
            state.audit.iter().any(|event| {
                event.activation_sequence == Some(active.sequence)
                    && event.outcome == ActivationOutcome::Applied
            })
        })
    {
        sync_committed(root, &directory, sync)?;
        return load(root, target, config, package_digest);
    }
    // Refusal is an attempt, not an active snapshot. Reuse only the latest
    // undelivered attempt under the same validation inputs; a delivered refusal
    // or a changed binding/package/configuration remains a new attempt.
    let retry_context_digest = if validation.is_err() {
        let context = serde_json::to_value((
            target,
            config,
            state.activations.last().map(|active| {
                (
                    &active.package_digest,
                    &active.authority_revision,
                    active.sequence,
                )
            }),
        ))
        .map_err(|_| AuthorityError::InvalidDocument)?;
        Some(digest_value(&context)?)
    } else {
        None
    };
    if validation.is_err()
        && state.audit.last().is_some_and(|event| {
            !event.delivered
                && event.outcome == ActivationOutcome::Refused
                && event.package_digest == package_digest
                && event.authority_digest == digest
                && event.retry_context_digest == retry_context_digest
        })
    {
        sync_committed(root, &directory, sync)?;
        return Err(validation.expect_err("matching retry is refused"));
    }
    if state.audit.len() >= MAX_ACTIVATIONS
        || (validation.is_ok() && existing.is_none() && state.activations.len() >= MAX_ACTIVATIONS)
    {
        return Err(AuthorityError::HistoryFull);
    }
    let active = if validation.is_ok() {
        Some(existing.unwrap_or_else(|| {
            let active = AuthorityActivation {
                sequence: state.activations.len() as u64 + 1,
                package_digest: package_digest.to_owned(),
                authority_revision: revision.clone(),
                authority_digest: digest.clone(),
                activated_at: chrono::Utc::now().to_rfc3339(),
                document: document.clone(),
            };
            state.activations.push(active.clone());
            active
        }))
    } else {
        None
    };
    let activation_id = ulid::Ulid::generate().to_string();
    let operator_reference_hash = operator
        .map(|(reference, audit)| {
            audit
                .activation_operator_reference(&activation_id, reference)
                .map_err(|_| AuthorityError::AuditFailed)
        })
        .transpose()?;
    state.audit.push(ActivationAudit {
        schema: "evidence-activation-audit/v1".to_owned(),
        activation_id,
        delivered: false,
        retry_context_digest,
        sequence: state.audit.len() as u64 + 1,
        recorded_at: chrono::Utc::now().to_rfc3339(),
        outcome: if validation.is_ok() {
            ActivationOutcome::Applied
        } else {
            ActivationOutcome::Refused
        },
        package_digest: package_digest.to_owned(),
        authority_revision: revision,
        authority_digest: digest,
        activation_sequence: active.as_ref().map(|active| active.sequence),
        operator_reference_hash,
    });
    commit_state(root, &directory, &state, sync)?;
    validation?;
    let active = active.ok_or(AuthorityError::CommitFailed)?;
    let captured = load(root, target, config, package_digest)?;
    if captured.revision() != active.authority_revision || captured.sequence() != active.sequence {
        return Err(AuthorityError::CommitFailed);
    }
    Ok(captured)
}

fn commit_state(
    root: &Path,
    directory: &File,
    state: &AuthorityState,
    sync: &mut impl FnMut(&File) -> std::io::Result<()>,
) -> Result<(), AuthorityError> {
    let mut value = serde_json::to_value(state).map_err(|_| AuthorityError::InvalidDocument)?;
    let members = value
        .as_object_mut()
        .ok_or(AuthorityError::InvalidDocument)?;
    members.insert("apiVersion".to_owned(), STATE_API_VERSION.into());
    members.insert("kind".to_owned(), "EvidenceAuthorityState".into());
    let bytes = canonicalize_json(&value).map_err(|_| AuthorityError::InvalidDocument)?;
    // The shared reader's document bound also applies on the write side, so
    // an acknowledged activation can always be captured again at startup.
    if bytes.len() > registry_platform_yaml::MAXIMUM_DOCUMENT_BYTES {
        return Err(AuthorityError::HistoryFull);
    }
    let temporary = root.join(format!(".authority-{}.tmp", ulid::Ulid::generate()));
    let result = (|| {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| AuthorityError::CommitFailed)?;
        output
            .write_all(&bytes)
            .map_err(|_| AuthorityError::CommitFailed)?;
        sync(&output).map_err(|_| AuthorityError::CommitFailed)?;
        fs::rename(&temporary, root.join(STATE_FILE)).map_err(|_| AuthorityError::CommitFailed)?;
        sync_committed(root, directory, sync)
    })();
    if temporary.exists() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AuthorityKind, GrantCeiling, ResponseFormat, SubjectBindingMode, ValueOrigin,
    };
    use std::sync::Arc;

    fn fixture() -> (EvidenceConfig, AuthorityDocument, String) {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("retained bounded runtime fixture");
        config.project = Some("standalone-evidence".to_owned());
        for profile in config.authority_profiles.values_mut() {
            profile.actor_kind = Some(registry_platform_oidc::ActorKind::Service);
        }
        let authority = AuthorityDocument {
            target: "local".to_owned(),
            project: "standalone-evidence".to_owned(),
            access_profiles: config.authority_profiles.clone(),
        };
        config.authority_profiles = OrderedMap::default();
        for definition in &mut config.requirements {
            definition.question = Some("Is the subject an adult?".to_owned());
            definition.grant_ceiling = Some(GrantCeiling {
                authorities: vec![AuthorityKind::Statutory],
                actor_kinds: vec![registry_platform_oidc::ActorKind::Service],
                value_origins: vec![ValueOrigin::Request],
                audiences: vec!["urn:example:audience:relying-party".to_owned()],
            });
            definition.representations = Some(vec![ResponseFormat::SignedJws]);
        }
        let package = sha256_uri(b"synthetic-package");
        (config, authority, package)
    }

    fn test_activation_audit() -> EvidenceAuditLog {
        EvidenceAuditLog::with_writer(
            registry_platform_audit::AuditWriter::from_line_sink(Box::new(Vec::<u8>::new())),
            b"activation-audit-key-canary-32-bytes".to_vec(),
            1,
        )
        .unwrap()
    }

    #[test]
    fn omitted_profile_actor_retains_the_per_definition_actor_ceiling() {
        let (config, mut document, _) = fixture();
        for profile in document.access_profiles.values_mut() {
            profile.actor_kind = None;
        }
        document
            .validate_for("local", &config)
            .expect("an omitted profile actor leaves request-time ceiling checks intact");
        for profile in document.access_profiles.values_mut() {
            profile.actor_kind = Some(registry_platform_oidc::ActorKind::Human);
        }
        assert!(
            matches!(
                document.validate_for("local", &config),
                Err(AuthorityError::OutsideCeiling)
            ),
            "an explicit actor outside the definition ceiling is still refused"
        );
    }

    #[test]
    fn authority_activation_writes_a_correlated_audit_record() {
        let (config, document, package) = fixture();
        let root = tempfile::tempdir().unwrap();
        let active = activate(root.path(), "local", &config, &package, &document).unwrap();
        let events =
            activation_audit(root.path()).expect("successful activation has durable audit");
        let audit = serde_json::to_string(&events).unwrap();
        let events = serde_json::to_value(&events).unwrap();
        let events = events.as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["schema"], "evidence-activation-audit/v1");
        assert_eq!(events[0]["authorityRevision"], active.revision());
        assert_eq!(events[0]["activationSequence"], active.sequence());
        assert!(!audit.contains("requesterTags"));
        assert!(!audit.contains("grants"));
    }

    #[tokio::test]
    async fn refusal_is_audited_without_activation_and_operator_reference_is_hashed() {
        let (config, document, package) = fixture();
        let audit = test_activation_audit();
        let root = tempfile::tempdir().unwrap();
        let mut refused = document.clone();
        refused.project = "other-project".to_owned();
        assert!(matches!(
            activate_with_operator(
                root.path(),
                "local",
                &config,
                &package,
                &refused,
                Some("operator-reference-canary"),
                &audit
            )
            .await,
            Err(AuthorityError::BindingMismatch)
        ));
        assert!(history(root.path()).unwrap().is_empty());
        assert!(matches!(
            load(root.path(), "local", &config, &package),
            Err(AuthorityError::Unavailable)
        ));
        let active = activate_with_operator(
            root.path(),
            "local",
            &config,
            &package,
            &document,
            Some("operator-reference-canary"),
            &audit,
        )
        .await
        .unwrap();
        let events = activation_audit(root.path()).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].outcome, ActivationOutcome::Refused);
        assert_eq!(events[0].activation_sequence, None);
        assert_eq!(events[1].activation_sequence, Some(active.sequence()));
        assert_eq!(
            events[1].operator_reference_hash,
            Some(
                audit
                    .activation_operator_reference(
                        &events[1].activation_id,
                        "operator-reference-canary"
                    )
                    .unwrap()
            )
        );
        let bytes = fs::read_to_string(root.path().join(STATE_FILE)).unwrap();
        assert!(!bytes.contains("operator-reference-canary"));
        // Identical retries retain one correlated success event.
        activate_with_operator(
            root.path(),
            "local",
            &config,
            &package,
            &document,
            Some("retry-reference-canary"),
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(activation_audit(root.path()).unwrap().len(), 2);
    }

    #[tokio::test]
    async fn activation_uses_configured_audit_sink_and_scopes_operator_references() {
        let (config, document, package) = fixture();
        let root = tempfile::tempdir().unwrap();
        let sink = tempfile::tempdir().unwrap();
        let path = sink.path().join("audit.jsonl");
        let audit = crate::audit::EvidenceAuditLog::initialize(
            registry_platform_audit::AuditDestination::File(
                registry_platform_audit::FileDestination::new(&path).unwrap(),
            ),
            b"activation-audit-key-canary-32-bytes".to_vec(),
            1,
        )
        .await
        .unwrap();
        activate_with_operator(
            root.path(),
            "local",
            &config,
            &package,
            &document,
            Some("operator-reference-canary"),
            &audit,
        )
        .await
        .unwrap();
        let lines = fs::read_to_string(&path).unwrap();
        assert!(
            !lines.is_empty(),
            "activation must reach the configured platform audit sink"
        );
        let first: serde_json::Value = serde_json::from_str(lines.lines().next().unwrap()).unwrap();
        assert_eq!(first["schema"], "evidence-activation-audit/v1");
        let mut refused = document.clone();
        refused.project = "another-project".to_owned();
        assert!(activate_with_operator(
            root.path(),
            "local",
            &config,
            &package,
            &refused,
            Some("operator-reference-canary"),
            &audit
        )
        .await
        .is_err());
        let events = activation_audit(root.path()).unwrap();
        assert_ne!(
            events[0].operator_reference_hash,
            events[1].operator_reference_hash
        );
        assert!(!fs::read_to_string(path)
            .unwrap()
            .contains("operator-reference-canary"));
    }

    #[tokio::test]
    async fn configured_audit_failure_preserves_pending_record_for_retry() {
        struct RefusingSink;
        impl Write for RefusingSink {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("audit sink failure canary"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let (config, document, package) = fixture();
        let root = tempfile::tempdir().unwrap();
        let refusing = EvidenceAuditLog::with_writer(
            registry_platform_audit::AuditWriter::from_line_sink(Box::new(RefusingSink)),
            b"activation-audit-key-canary-32-bytes".to_vec(),
            1,
        )
        .unwrap();
        assert!(matches!(
            activate_with_operator(
                root.path(),
                "local",
                &config,
                &package,
                &document,
                Some("operator-reference-canary"),
                &refusing
            )
            .await,
            Err(AuthorityError::AuditFailed)
        ));
        assert_eq!(history(root.path()).unwrap().len(), 1);
        let pending = activation_audit(root.path()).unwrap();
        assert!(!pending[0].delivered);
        let sink = tempfile::tempdir().unwrap();
        let path = sink.path().join("audit.jsonl");
        let recovered = EvidenceAuditLog::initialize(
            registry_platform_audit::AuditDestination::File(
                registry_platform_audit::FileDestination::new(&path).unwrap(),
            ),
            b"activation-audit-key-canary-32-bytes".to_vec(),
            1,
        )
        .await
        .unwrap();
        for _ in 0..2 {
            activate_with_operator(
                root.path(),
                "local",
                &config,
                &package,
                &document,
                Some("retry-reference-canary"),
                &recovered,
            )
            .await
            .unwrap();
        }
        let delivered = activation_audit(root.path()).unwrap();
        assert_eq!(delivered.len(), 1);
        assert!(delivered[0].delivered);
        assert_eq!(delivered[0].activation_id, pending[0].activation_id);
        assert_eq!(
            delivered[0].operator_reference_hash,
            pending[0].operator_reference_hash
        );
        assert_eq!(history(root.path()).unwrap().len(), 1);
        let lines = fs::read_to_string(path).unwrap();
        assert_eq!(lines.lines().count(), 1);
        let entry: serde_json::Value = serde_json::from_str(lines.trim()).unwrap();
        assert_eq!(entry["correlation"], pending[0].activation_id);
        assert_eq!(entry["phase"], "response");
        assert_eq!(entry["record"]["activationSequence"], 1);
        assert_eq!(
            entry["record"]["authorityRevision"],
            pending[0].authority_revision
        );
        assert!(entry["record"].get("schema").is_none());
    }

    #[tokio::test]
    async fn refused_activation_retry_preserves_pending_identity_and_reference() {
        struct RefusingSink;
        impl Write for RefusingSink {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("audit sink failure canary"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let (config, mut document, package) = fixture();
        document.project = "other-project".into();
        let root = tempfile::tempdir().unwrap();
        let refusing = EvidenceAuditLog::with_writer(
            registry_platform_audit::AuditWriter::from_line_sink(Box::new(RefusingSink)),
            b"activation-audit-key-canary-32-bytes".to_vec(),
            1,
        )
        .unwrap();
        for _ in 0..2 {
            assert!(matches!(
                activate_with_operator(
                    root.path(),
                    "local",
                    &config,
                    &package,
                    &document,
                    Some("operator-reference-canary"),
                    &refusing
                )
                .await,
                Err(AuthorityError::AuditFailed)
            ));
        }
        let pending = activation_audit(root.path()).unwrap();
        assert_eq!(
            pending.len(),
            1,
            "an undelivered refused retry must not allocate another event"
        );
        let path = root.path().join("audit.jsonl");
        let recovered = EvidenceAuditLog::initialize(
            registry_platform_audit::AuditDestination::File(
                registry_platform_audit::FileDestination::new(&path).unwrap(),
            ),
            b"activation-audit-key-canary-32-bytes".to_vec(),
            1,
        )
        .await
        .unwrap();
        assert!(matches!(
            activate_with_operator(
                root.path(),
                "local",
                &config,
                &package,
                &document,
                Some("retry-reference-canary"),
                &recovered
            )
            .await,
            Err(AuthorityError::BindingMismatch)
        ));
        let delivered = activation_audit(root.path()).unwrap();
        assert_eq!(delivered.len(), 1);
        assert!(delivered[0].delivered);
        assert_eq!(delivered[0].activation_id, pending[0].activation_id);
        assert_eq!(
            delivered[0].operator_reference_hash,
            pending[0].operator_reference_hash
        );
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 1);
        assert!(history(root.path()).unwrap().is_empty());
        // A later attempt after successful delivery remains a distinct refusal.
        assert!(matches!(
            activate_with_operator(
                root.path(),
                "local",
                &config,
                &package,
                &document,
                Some("next-reference-canary"),
                &recovered
            )
            .await,
            Err(AuthorityError::BindingMismatch)
        ));
        let events = activation_audit(root.path()).unwrap();
        assert_eq!(events.len(), 2);
        assert_ne!(events[0].activation_id, events[1].activation_id);
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 2);
    }

    #[test]
    fn refused_retry_with_changed_validation_inputs_is_a_distinct_attempt() {
        let (config, mut document, package) = fixture();
        document.project = "other-project".into();
        for change in ["target", "configuration", "package", "document"] {
            let root = tempfile::tempdir().unwrap();
            assert!(activate(root.path(), "local", &config, &package, &document).is_err());
            let mut next_config = config.clone();
            let mut next_document = document.clone();
            let mut next_package = package.clone();
            let mut target = "local";
            match change {
                "target" => target = "another-target",
                "configuration" => next_config.project = Some("changed-project".into()),
                "package" => next_package = sha256_uri(b"changed-package-canary"),
                "document" => next_document.project = "third-project".into(),
                _ => unreachable!(),
            }
            assert!(activate(
                root.path(),
                target,
                &next_config,
                &next_package,
                &next_document
            )
            .is_err());
            let events = activation_audit(root.path()).unwrap();
            assert_eq!(events.len(), 2, "{change} is not the same pending attempt");
            assert_ne!(events[0].activation_id, events[1].activation_id);
            assert!(events.iter().all(|event| !event.delivered));
        }
    }

    #[tokio::test]
    async fn audit_commit_failure_never_acknowledges_an_activation() {
        let (config, document, package) = fixture();
        let audit = test_activation_audit();
        let root = tempfile::tempdir().unwrap();
        assert!(matches!(
            activate_recorded_with_sync(
                root.path(),
                "local",
                &config,
                &package,
                &document,
                None,
                &mut |_| Err(std::io::Error::other("injected audit sync failure"))
            ),
            Err(AuthorityError::CommitFailed)
        ));
        assert!(!root.path().join(STATE_FILE).exists());
        activate_with_operator(
            root.path(),
            "local",
            &config,
            &package,
            &document,
            Some("operator-canary"),
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(history(root.path()).unwrap().len(), 1);
        assert_eq!(activation_audit(root.path()).unwrap().len(), 1);
        let path = root.path().join(STATE_FILE);
        let mut state: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        state["audit"][0]["activationSequence"] = 999.into();
        fs::write(path, serde_json::to_vec(&state).unwrap()).unwrap();
        assert!(matches!(
            load(root.path(), "local", &config, &package),
            Err(AuthorityError::InvalidDocument)
        ));
    }

    #[test]
    fn authority_activation_is_atomic_idempotent_and_keeps_durable_history() {
        let (config, document, package) = fixture();
        let root = tempfile::tempdir().unwrap();
        let first = activate(root.path(), "local", &config, &package, &document).unwrap();
        let again = activate(root.path(), "local", &config, &package, &document).unwrap();
        assert_eq!(first.revision(), again.revision());
        assert_eq!(again.sequence(), 1);
        assert_eq!(history(root.path()).unwrap().len(), 1);
        let mut changed = document.clone();
        for profile in changed.access_profiles.values_mut() {
            profile.requester_tags =
                registry_platform_yaml::UniqueList::new(vec!["narrower-service".to_owned()])
                    .unwrap();
        }
        let next = activate(root.path(), "local", &config, &package, &changed).unwrap();
        assert_ne!(first.revision(), next.revision());
        assert_eq!(next.sequence(), 2);
        assert_eq!(
            history(root.path()).unwrap()[0].authority_revision,
            first.revision()
        );
        // A partially written candidate has no relationship to the one commit
        // point. Restart always reads the preceding complete committed state.
        fs::write(root.path().join(".authority-uncommitted.tmp"), b"truncated").unwrap();
        assert_eq!(
            load(root.path(), "local", &config, &package)
                .unwrap()
                .revision(),
            next.revision()
        );
    }

    #[test]
    fn activation_retry_requires_durable_state_and_parent_entries() {
        let (config, document, package) = fixture();
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("new-parent/new-store");
        let mut fail_directory_sync = |file: &File| {
            if file.metadata()?.is_dir() {
                Err(std::io::Error::other("injected directory sync failure"))
            } else {
                file.sync_all()
            }
        };
        assert!(matches!(
            activate_with_sync(
                &root,
                "local",
                &config,
                &package,
                &document,
                &mut fail_directory_sync
            ),
            Err(AuthorityError::CommitFailed)
        ));
        // The rename is visible but has not been acknowledged as durable.
        assert_eq!(history(&root).unwrap().len(), 1);
        assert!(
            matches!(
                activate_with_sync(
                    &root,
                    "local",
                    &config,
                    &package,
                    &document,
                    &mut fail_directory_sync
                ),
                Err(AuthorityError::CommitFailed)
            ),
            "an identical retry must not bypass the failed durability barrier"
        );
        let mut files_synced = 0;
        let mut directories_synced = 0;
        let mut sync = |file: &File| {
            if file.metadata()?.is_dir() {
                directories_synced += 1;
            } else {
                files_synced += 1;
            }
            file.sync_all()
        };
        let active =
            activate_with_sync(&root, "local", &config, &package, &document, &mut sync).unwrap();
        assert_eq!(active.sequence(), 1);
        assert_eq!(history(&root).unwrap().len(), 1);
        assert_eq!(files_synced, 1, "retry syncs the committed state file");
        assert_eq!(
            directories_synced,
            root.ancestors().count(),
            "store and every parent entry are durable before acknowledgement"
        );
        assert_eq!(
            load(&root, "local", &config, &package).unwrap().revision(),
            active.revision()
        );
    }

    #[test]
    fn invalid_or_out_of_ceiling_authority_never_replaces_active_snapshot() {
        let (config, document, package) = fixture();
        let root = tempfile::tempdir().unwrap();
        let active = activate(root.path(), "local", &config, &package, &document).unwrap();
        let before = history(root.path()).unwrap();
        let mut invalid = document.clone();
        for profile in invalid.access_profiles.values_mut() {
            profile.kind = AuthorityKind::Consent;
        }
        assert!(matches!(
            activate(root.path(), "local", &config, &package, &invalid),
            Err(AuthorityError::OutsideCeiling)
        ));
        assert_eq!(history(root.path()).unwrap(), before);
        assert_eq!(
            activation_audit(root.path())
                .unwrap()
                .last()
                .unwrap()
                .outcome,
            ActivationOutcome::Refused
        );
        assert_eq!(
            load(root.path(), "local", &config, &package)
                .unwrap()
                .revision(),
            active.revision()
        );
        assert_eq!(history(root.path()).unwrap().len(), 1);
    }

    #[test]
    fn authority_activation_serializes_concurrent_writers() {
        let (config, document, package) = fixture();
        let root = Arc::new(tempfile::tempdir().unwrap());
        let mut threads = Vec::new();
        for index in 0..6 {
            let root = Arc::clone(&root);
            let config = config.clone();
            let package = package.clone();
            let mut document = document.clone();
            for profile in document.access_profiles.values_mut() {
                profile.requester_tags =
                    registry_platform_yaml::UniqueList::new(vec![format!("service-{index}")])
                        .unwrap();
            }
            threads.push(std::thread::spawn(move || {
                activate(root.path(), "local", &config, &package, &document)
                    .unwrap()
                    .sequence()
            }));
        }
        let mut sequences = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        sequences.sort();
        assert_eq!(sequences, vec![1, 2, 3, 4, 5, 6]);
        let committed = history(root.path()).unwrap();
        assert_eq!(committed.len(), 6);
        assert_eq!(
            load(root.path(), "local", &config, &package)
                .unwrap()
                .revision(),
            committed.last().unwrap().authority_revision
        );
    }

    #[test]
    fn authority_snapshot_is_process_pinned_and_package_bound() {
        let (config, document, package) = fixture();
        let root = tempfile::tempdir().unwrap();
        let first = activate(root.path(), "local", &config, &package, &document).unwrap();
        let mut changed = document.clone();
        for profile in changed.access_profiles.values_mut() {
            profile.requester_tags =
                registry_platform_yaml::UniqueList::new(vec!["next-process".to_owned()]).unwrap();
        }
        let next = activate(root.path(), "local", &config, &package, &changed).unwrap();
        assert_ne!(first.revision(), next.revision());
        assert_eq!(first.profiles(), &document.access_profiles);
        assert!(matches!(
            load(root.path(), "local", &config, &sha256_uri(b"other-package")),
            Err(AuthorityError::BindingMismatch)
        ));
        assert!(matches!(
            load(root.path(), "other-target", &config, &package),
            Err(AuthorityError::BindingMismatch)
        ));
    }

    #[test]
    fn target_grants_cannot_widen_any_definition_ceiling() {
        let (config, document, _) = fixture();
        let mutate = |change: fn(&mut AuthorityProfile)| {
            let mut candidate = document.clone();
            for profile in candidate.access_profiles.values_mut() {
                change(profile);
            }
            assert!(candidate.validate_for("local", &config).is_err());
        };
        mutate(|profile| profile.kind = AuthorityKind::Organizational);
        mutate(|profile| profile.actor_kind = Some(registry_platform_oidc::ActorKind::Agent));
        mutate(|profile| profile.actor_kind = Some(registry_platform_oidc::ActorKind::Human));
        mutate(|profile| profile.grants[0].purpose = "another-purpose".to_owned());
        mutate(|profile| profile.grants[0].response_formats = vec![ResponseFormat::UnsignedJson]);
        mutate(|profile| {
            profile.grants[0].subject_binding_modes = vec![SubjectBindingMode::HolderBound]
        });
        mutate(|profile| profile.grants[0].subjects[0].role = "another-role".to_owned());
        mutate(|profile| {
            profile.grants[0].subjects[0].selector_profile = "another-selector".to_owned()
        });
        mutate(|profile| {
            profile.grants[0].subjects[0].value_origin = ValueOrigin::AuthenticatedContext
        });
        mutate(|profile| profile.grants[0].subjects.clear());
        mutate(|profile| profile.grants[0].requirement = "adult-status".to_owned());
    }

    #[test]
    fn authority_storage_rejects_symlinks_and_unsafe_permissions() {
        let (config, document, package) = fixture();
        let root = tempfile::tempdir().unwrap();
        activate(root.path(), "local", &config, &package, &document).unwrap();
        fs::set_permissions(
            root.path().join(STATE_FILE),
            fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert!(matches!(
            load(root.path(), "local", &config, &package),
            Err(AuthorityError::UnsafeStorage)
        ));
        fs::set_permissions(
            root.path().join(STATE_FILE),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let alias_root = root.path().join("alias");
        std::os::unix::fs::symlink(root.path(), &alias_root).unwrap();
        assert!(matches!(
            load(&alias_root, "local", &config, &package),
            Err(AuthorityError::UnsafeStorage)
        ));
    }

    #[test]
    fn authority_reader_rejects_old_envelopes_and_duplicate_members() {
        let old = b"apiVersion: id.registrystack.org/formats/evidence/access-policy/v1alpha1\nkind: EvidenceAccessPolicy\n";
        assert!(AuthorityDocument::parse("authority.yaml", old).is_err());
        let duplicate = format!("apiVersion: {AUTHORITY_API_VERSION}\nkind: {AUTHORITY_KIND}\ntarget: local\ntarget: other\nproject: standalone-evidence\naccessProfiles: {{}}\n");
        assert!(AuthorityDocument::parse("authority.yaml", duplicate.as_bytes()).is_err());
    }
}
