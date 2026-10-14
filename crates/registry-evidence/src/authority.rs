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
/// as one document. A repeated exact activation is idempotent. One file lock
/// serializes concurrent operators, and every acknowledged activation is fsynced.
pub fn activate(
    root: &Path,
    target: &str,
    config: &EvidenceConfig,
    package_digest: &str,
    document: &AuthorityDocument,
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
            return Ok(AuthoritySnapshot {
                active: active.clone(),
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
        output
            .sync_all()
            .map_err(|_| AuthorityError::CommitFailed)?;
        fs::rename(&temporary, root.join(STATE_FILE)).map_err(|_| AuthorityError::CommitFailed)?;
        directory
            .sync_all()
            .map_err(|_| AuthorityError::CommitFailed)?;
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
        mutate(|profile| profile.actor_kind = None);
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
