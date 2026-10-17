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

use crate::audit::{
    ActivationOutcome, ActivationRequestRecord, EvidenceAuditError, EvidenceAuditLog,
};
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
    #[error("target authority revision {revision} is already active for this package as sequence {sequence}; nothing needs activating")]
    AlreadyActive { revision: String, sequence: u64 },
    #[error("operator reference must be 1 to 256 bytes with no control characters")]
    InvalidOperatorReference,
}

/// A refused, failed, or unaudited `evidence authority activate`.
#[derive(Debug, Error)]
pub enum ActivationError {
    #[error(transparent)]
    Authority(#[from] AuthorityError),
    /// The audit destination refused the `request` entry, so the activation
    /// never took the authority lock and nothing changed.
    #[error("the audit destination did not accept the activation's request entry")]
    RequestUnaudited(#[source] EvidenceAuditError),
    /// The activation did not commit, and the audit destination also refused
    /// the `response` entry that would have recorded why.
    #[error("{cause}; the audit destination also did not accept the activation's response entry")]
    ResponseUnaudited { cause: AuthorityError },
    /// The activation committed, but the audit destination did not accept its
    /// `response` entry. This is never a failed activation.
    #[error(
        "target authority revision {revision} ({digest}) is active as sequence {sequence}, but the audit destination did not accept the activation's response entry; restore the audit destination, then confirm the activation with `evidence authority history --runtime-config FILE`"
    )]
    AppliedUnaudited {
        revision: String,
        digest: String,
        sequence: u64,
    },
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
    if state.activations.is_empty() || state.activations.len() > MAX_ACTIVATIONS {
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
/// as one document. An exact repeat of the active package and revision is
/// refused as already active. One file lock serializes concurrent operators,
/// and every acknowledged activation is fsynced. It writes no audit record;
/// the operator command audits through [`activate_with_operator`].
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

/// Audit, validate, and commit one activation as the operator command does.
///
/// The `request` entry is accepted before the authority lock is taken; a
/// refused request leaves the authority store untouched. The commit is the
/// same single atomic history document [`activate`] writes, and refusals never
/// touch it. The `response` entry follows: `applied` with the activation
/// sequence, `refused` for a validation refusal, or `failed` for a commit
/// failure. A crash between the commit and the response leaves a request
/// with no response, and authority history says what happened. A response
/// the destination refuses after the commit is reported as
/// [`ActivationError::AppliedUnaudited`], never as a failed activation.
pub async fn activate_with_operator(
    root: &Path,
    target: &str,
    config: &EvidenceConfig,
    package_digest: &str,
    document: &AuthorityDocument,
    operator_reference: Option<&str>,
    audit: &EvidenceAuditLog,
) -> Result<AuthoritySnapshot, ActivationError> {
    if operator_reference.is_some_and(|value| {
        value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)
    }) {
        return Err(AuthorityError::InvalidOperatorReference.into());
    }
    if !is_sha256_label(package_digest) {
        return Err(AuthorityError::BindingMismatch.into());
    }
    let (revision, digest) = document_identity(document)?;
    let activation_id = ulid::Ulid::generate().to_string();
    let operator_reference_hash = operator_reference
        .map(|reference| audit.activation_operator_reference(&activation_id, reference))
        .transpose()
        .map_err(ActivationError::RequestUnaudited)?;
    audit
        .activation_request(&ActivationRequestRecord {
            activation_id: activation_id.clone(),
            package_digest: package_digest.to_owned(),
            authority_revision: revision,
            authority_digest: digest,
            operator_reference_hash,
        })
        .await
        .map_err(ActivationError::RequestUnaudited)?;
    // The authority lock is a blocking file lock; take it off the executor.
    let committed = {
        let root = root.to_owned();
        let target = target.to_owned();
        let config = config.clone();
        let package_digest = package_digest.to_owned();
        let document = document.clone();
        tokio::task::spawn_blocking(move || {
            activate(&root, &target, &config, &package_digest, &document)
        })
        .await
        .unwrap_or(Err(AuthorityError::CommitFailed))
    };
    let (outcome, sequence) = match &committed {
        Ok(snapshot) => (ActivationOutcome::Applied, Some(snapshot.sequence())),
        Err(AuthorityError::CommitFailed) => (ActivationOutcome::Failed, None),
        Err(_) => (ActivationOutcome::Refused, None),
    };
    let response = audit
        .activation_response(&activation_id, outcome, sequence)
        .await;
    match (committed, response) {
        (Ok(snapshot), Ok(())) => Ok(snapshot),
        (Ok(snapshot), Err(_)) => Err(ActivationError::AppliedUnaudited {
            revision: snapshot.revision().to_owned(),
            digest: snapshot.digest().to_owned(),
            sequence: snapshot.sequence(),
        }),
        (Err(cause), Ok(())) => Err(cause.into()),
        (Err(cause), Err(_)) => Err(ActivationError::ResponseUnaudited { cause }),
    }
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

fn activate_with_sync(
    root: &Path,
    target: &str,
    config: &EvidenceConfig,
    package_digest: &str,
    document: &AuthorityDocument,
    sync: &mut impl FnMut(&File) -> std::io::Result<()>,
) -> Result<AuthoritySnapshot, AuthorityError> {
    document.validate_for(target, config)?;
    if !is_sha256_label(package_digest) {
        return Err(AuthorityError::BindingMismatch);
    }
    if !root.is_absolute() {
        return Err(AuthorityError::UnsafeStorage);
    }
    fs::create_dir_all(root).map_err(|_| AuthorityError::UnsafeStorage)?;
    let directory = check_root(root)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(root.join("authority.lock"))
        .map_err(|_| AuthorityError::UnsafeStorage)?;
    let lock_metadata = lock.metadata().map_err(|_| AuthorityError::UnsafeStorage)?;
    if !lock_metadata.is_file()
        || lock_metadata.permissions().mode() & 0o022 != 0
        || lock_metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(AuthorityError::UnsafeStorage);
    }
    fs2::FileExt::lock_exclusive(&lock).map_err(|_| AuthorityError::CommitFailed)?;
    let mut state = if root.join(STATE_FILE).exists() {
        read_state(root)?
    } else {
        AuthorityState {
            activations: Vec::new(),
        }
    };
    let (revision, digest) = document_identity(document)?;
    if let Some(active) = state.activations.last() {
        if active.document.target != target || active.document.project != document.project {
            return Err(AuthorityError::BindingMismatch);
        }
        if active.package_digest == package_digest && active.authority_revision == revision {
            // A retry after a failed durability barrier must still complete
            // it before reporting what is active.
            sync_committed(root, &directory, sync)?;
            return Err(AuthorityError::AlreadyActive {
                revision,
                sequence: active.sequence,
            });
        }
    }
    if state.activations.len() >= MAX_ACTIVATIONS {
        return Err(AuthorityError::HistoryFull);
    }
    let active = AuthorityActivation {
        sequence: state.activations.len() as u64 + 1,
        package_digest: package_digest.to_owned(),
        authority_revision: revision,
        authority_digest: digest,
        activated_at: chrono::Utc::now().to_rfc3339(),
        document: document.clone(),
    };
    state.activations.push(active.clone());
    let mut value = serde_json::to_value(&state).map_err(|_| AuthorityError::InvalidDocument)?;
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
        sync_committed(root, &directory, sync)?;
        let captured = load(root, target, config, package_digest)?;
        if captured.revision() != active.authority_revision
            || captured.sequence() != active.sequence
        {
            return Err(AuthorityError::CommitFailed);
        }
        Ok(captured)
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
    fn authority_activation_is_atomic_refuses_a_repeat_and_keeps_durable_history() {
        let (config, document, package) = fixture();
        let root = tempfile::tempdir().unwrap();
        let first = activate(root.path(), "local", &config, &package, &document).unwrap();
        match activate(root.path(), "local", &config, &package, &document) {
            Err(AuthorityError::AlreadyActive { revision, sequence }) => {
                assert_eq!(revision, first.revision());
                assert_eq!(sequence, 1);
            }
            other => panic!("an exact repeat must be refused as already active: {other:?}"),
        }
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
        assert!(
            matches!(
                activate_with_sync(&root, "local", &config, &package, &document, &mut sync),
                Err(AuthorityError::AlreadyActive { sequence: 1, .. })
            ),
            "the completed barrier reports the visible activation as already active"
        );
        let committed = history(&root).unwrap();
        assert_eq!(committed.len(), 1);
        assert_eq!(files_synced, 1, "retry syncs the committed state file");
        assert_eq!(
            directories_synced,
            root.ancestors().count(),
            "store and every parent entry are durable before acknowledgement"
        );
        assert_eq!(
            load(&root, "local", &config, &package).unwrap().revision(),
            committed[0].authority_revision
        );
    }

    #[test]
    fn invalid_or_out_of_ceiling_authority_never_replaces_active_snapshot() {
        let (config, document, package) = fixture();
        let root = tempfile::tempdir().unwrap();
        let active = activate(root.path(), "local", &config, &package, &document).unwrap();
        let before = fs::read(root.path().join(STATE_FILE)).unwrap();
        let mut invalid = document.clone();
        for profile in invalid.access_profiles.values_mut() {
            profile.kind = AuthorityKind::Consent;
        }
        assert!(matches!(
            activate(root.path(), "local", &config, &package, &invalid),
            Err(AuthorityError::OutsideCeiling)
        ));
        assert_eq!(fs::read(root.path().join(STATE_FILE)).unwrap(), before);
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

    /// An audit sink that keeps every accepted line and refuses every line
    /// after the first `accepted` ones.
    #[derive(Clone)]
    struct RecordingSink {
        lines: Arc<std::sync::Mutex<Vec<u8>>>,
        written: Arc<std::sync::Mutex<usize>>,
        accepted: usize,
    }

    impl Write for RecordingSink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let mut written = self.written.lock().unwrap();
            if *written >= self.accepted {
                return Err(std::io::Error::other("audit sink refusal canary"));
            }
            *written += bytes.iter().filter(|byte| **byte == b'\n').count();
            self.lines.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl RecordingSink {
        fn accepting(accepted: usize) -> (Self, EvidenceAuditLog) {
            let sink = Self {
                lines: Arc::default(),
                written: Arc::default(),
                accepted,
            };
            let log = EvidenceAuditLog::with_writer(
                registry_platform_audit::AuditWriter::from_line_sink(Box::new(sink.clone())),
                b"activation-audit-key-canary-32-bytes".to_vec(),
                1,
            )
            .unwrap();
            (sink, log)
        }

        fn entries(&self) -> Vec<serde_json::Value> {
            String::from_utf8(self.lines.lock().unwrap().clone())
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }
    }

    fn narrowed(document: &AuthorityDocument, tag: &str) -> AuthorityDocument {
        let mut changed = document.clone();
        for profile in changed.access_profiles.values_mut() {
            profile.requester_tags =
                registry_platform_yaml::UniqueList::new(vec![tag.to_owned()]).unwrap();
        }
        changed
    }

    #[tokio::test]
    async fn applied_activation_writes_a_correlated_request_and_response() {
        let (config, document, package) = fixture();
        let root = tempfile::tempdir().unwrap();
        let (sink, audit) = RecordingSink::accepting(usize::MAX);
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
        let entries = sink.entries();
        assert_eq!(entries.len(), 2);
        let (request, response) = (&entries[0], &entries[1]);
        assert_eq!(request["schema"], "evidence-activation-audit/v1");
        assert_eq!(request["phase"], "request");
        assert_eq!(response["phase"], "response");
        assert_eq!(request["correlation"], response["correlation"]);
        assert_eq!(request["record"]["activationId"], request["correlation"]);
        assert_eq!(request["record"]["packageDigest"], package);
        assert_eq!(request["record"]["authorityRevision"], active.revision());
        assert_eq!(request["record"]["authorityDigest"], active.digest());
        assert_eq!(
            request["record"]["operatorReferenceHash"],
            audit
                .activation_operator_reference(
                    request["correlation"].as_str().unwrap(),
                    "operator-reference-canary"
                )
                .unwrap()
        );
        assert_eq!(response["record"]["outcome"], "applied");
        assert_eq!(response["record"]["activationSequence"], 1);
        let text = String::from_utf8(sink.lines.lock().unwrap().clone()).unwrap();
        assert!(!text.contains("operator-reference-canary"));
        assert!(!text.contains("requesterTags"));
        assert!(!text.contains("grants"));
        let state = fs::read_to_string(root.path().join(STATE_FILE)).unwrap();
        assert!(!state.contains("operator-reference-canary"));
        assert!(!state.contains("activationId"));
    }

    #[tokio::test]
    async fn refused_request_entry_leaves_authority_state_untouched() {
        let (config, document, package) = fixture();
        let root = tempfile::tempdir().unwrap();
        let store = root.path().join("store");
        let (_, refusing) = RecordingSink::accepting(0);
        assert!(matches!(
            activate_with_operator(&store, "local", &config, &package, &document, None, &refusing)
                .await,
            Err(ActivationError::RequestUnaudited(_))
        ));
        assert!(
            !store.exists(),
            "a refused request creates no authority store"
        );
        let active = activate(&store, "local", &config, &package, &document).unwrap();
        let before = fs::read(store.join(STATE_FILE)).unwrap();
        assert!(matches!(
            activate_with_operator(
                &store,
                "local",
                &config,
                &package,
                &narrowed(&document, "next-service"),
                None,
                &refusing
            )
            .await,
            Err(ActivationError::RequestUnaudited(_))
        ));
        assert_eq!(fs::read(store.join(STATE_FILE)).unwrap(), before);
        assert_eq!(
            load(&store, "local", &config, &package).unwrap().revision(),
            active.revision()
        );
    }

    #[tokio::test]
    async fn validation_refusals_are_audited_and_never_fill_history() {
        let (config, document, package) = fixture();
        let root = tempfile::tempdir().unwrap();
        let (sink, audit) = RecordingSink::accepting(usize::MAX);
        let mut other_project = document.clone();
        other_project.project = "other-project".to_owned();
        assert!(matches!(
            activate_with_operator(
                root.path(),
                "local",
                &config,
                &package,
                &other_project,
                None,
                &audit
            )
            .await,
            Err(ActivationError::Authority(AuthorityError::BindingMismatch))
        ));
        let entries = sink.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["phase"], "request");
        assert_eq!(entries[1]["phase"], "response");
        assert_eq!(entries[0]["correlation"], entries[1]["correlation"]);
        assert_eq!(entries[1]["record"]["outcome"], "refused");
        assert!(entries[1]["record"]["activationSequence"].is_null());
        assert!(
            !root.path().join(STATE_FILE).exists(),
            "a refusal never writes authority state"
        );

        activate_with_operator(
            root.path(),
            "local",
            &config,
            &package,
            &document,
            None,
            &audit,
        )
        .await
        .unwrap();
        let before = fs::read(root.path().join(STATE_FILE)).unwrap();
        // More refusals than the history bound holds leave history alone.
        for _ in 0..=MAX_ACTIVATIONS {
            assert!(activate_with_operator(
                root.path(),
                "local",
                &config,
                &package,
                &other_project,
                None,
                &audit
            )
            .await
            .is_err());
        }
        assert!(matches!(
            activate_with_operator(
                root.path(),
                "local",
                &config,
                &package,
                &document,
                None,
                &audit
            )
            .await,
            Err(ActivationError::Authority(AuthorityError::AlreadyActive {
                sequence: 1,
                ..
            }))
        ));
        assert_eq!(fs::read(root.path().join(STATE_FILE)).unwrap(), before);
        let next = activate_with_operator(
            root.path(),
            "local",
            &config,
            &package,
            &narrowed(&document, "next-service"),
            None,
            &audit,
        )
        .await
        .expect("refusals never consume the activation history bound");
        assert_eq!(next.sequence(), 2);
        let entries = sink.entries();
        let outcomes = entries
            .iter()
            .filter(|entry| entry["phase"] == "response")
            .map(|entry| entry["record"]["outcome"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(outcomes.len(), MAX_ACTIVATIONS + 5);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| *outcome == "applied")
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn response_refused_after_commit_reports_applied_unaudited() {
        let (config, document, package) = fixture();
        let root = tempfile::tempdir().unwrap();
        let (sink, audit) = RecordingSink::accepting(1);
        let error = activate_with_operator(
            root.path(),
            "local",
            &config,
            &package,
            &document,
            None,
            &audit,
        )
        .await
        .unwrap_err();
        let committed = history(root.path()).unwrap();
        assert_eq!(committed.len(), 1);
        match &error {
            ActivationError::AppliedUnaudited {
                revision,
                digest,
                sequence,
            } => {
                assert_eq!(revision, &committed[0].authority_revision);
                assert_eq!(digest, &committed[0].authority_digest);
                assert_eq!(*sequence, 1);
            }
            other => panic!("a committed activation is never reported as failed: {other:?}"),
        }
        assert!(error
            .to_string()
            .contains("evidence authority history --runtime-config"));
        let entries = sink.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["phase"], "request");
    }

    #[tokio::test]
    async fn audited_activations_stay_serialized_by_the_authority_lock() {
        let (config, document, package) = fixture();
        let root = Arc::new(tempfile::tempdir().unwrap());
        let (sink, audit) = RecordingSink::accepting(usize::MAX);
        let audit = Arc::new(audit);
        let mut tasks = Vec::new();
        for index in 0..6 {
            let root = Arc::clone(&root);
            let audit = Arc::clone(&audit);
            let config = config.clone();
            let package = package.clone();
            let document = narrowed(&document, &format!("service-{index}"));
            tasks.push(tokio::spawn(async move {
                activate_with_operator(
                    root.path(),
                    "local",
                    &config,
                    &package,
                    &document,
                    None,
                    &audit,
                )
                .await
                .unwrap()
                .sequence()
            }));
        }
        let mut sequences = Vec::new();
        for task in tasks {
            sequences.push(task.await.unwrap());
        }
        sequences.sort();
        assert_eq!(sequences, vec![1, 2, 3, 4, 5, 6]);
        assert_eq!(history(root.path()).unwrap().len(), 6);
        let mut applied = sink
            .entries()
            .iter()
            .filter(|entry| entry["phase"] == "response")
            .map(|entry| entry["record"]["activationSequence"].as_u64().unwrap())
            .collect::<Vec<_>>();
        applied.sort();
        assert_eq!(applied, vec![1, 2, 3, 4, 5, 6]);
    }
}
