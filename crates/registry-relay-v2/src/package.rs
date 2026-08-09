// SPDX-License-Identifier: Apache-2.0
//! Deterministic sealed package construction from one compiled Registry.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};

use registry_platform_canonical_json::canonicalize_json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::artifacts::{generate_artifacts, ArtifactSet, GeneratedArtifact};
use crate::compiler::{compile_contract_with_governed_files, GovernedFileSet};
use crate::contract::{RegistryContract, Visibility};
use crate::model::{CompileProfile, CompiledRegistry, ObservedSourceSchema};

const PACKAGE_VERSION: &str = "relay.registrystack.org/package/v1alpha1";
const MAX_AUTHORED_FILES: usize = 256;
const MAX_AUTHORED_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PACKAGE_FILES: usize = 1_024;
const MAX_PACKAGE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageManifest {
    pub package_version: String,
    pub package_revision: String,
    pub contract_revision: String,
    pub source_schema_fingerprints: BTreeMap<String, String>,
    pub source_schemas: BTreeMap<String, ObservedSourceSchema>,
    pub artifacts: Vec<PackageArtifact>,
    pub files: Vec<PackageFile>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageArtifact {
    pub id: String,
    pub path: String,
    pub media_type: String,
    pub visibility: Visibility,
    pub operation_identifier: Option<String>,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub media_type: String,
    pub visibility: Visibility,
    pub generated: bool,
}

#[derive(Debug, Error)]
pub enum PackageError {
    #[error("the project closure is unsafe")]
    UnsafeClosure,
    #[error("the project closure exceeds package bounds")]
    ClosureBound,
    #[error("the package destination is not empty")]
    DestinationExists,
    #[error("a package file could not be read")]
    Read,
    #[error("the sealed package could not be written")]
    Write,
    #[error("the package manifest could not be canonicalized")]
    CanonicalJson,
    #[error("the sealed package failed verification")]
    Verification,
}

#[derive(Clone, Debug)]
pub struct VerifiedPackage {
    pub manifest: PackageManifest,
    pub contract: RegistryContract,
    pub registry: CompiledRegistry,
    pub artifacts: ArtifactSet,
}

/// Construct a new package directory. Existing destinations are refused so a
/// failed run can never leave a mixture of package revisions.
pub fn build_package(
    project_root: &Path,
    output_dir: &Path,
    contract: &RegistryContract,
    compiled: &CompiledRegistry,
    artifacts: &ArtifactSet,
) -> Result<PackageManifest, PackageError> {
    if output_dir.exists() {
        return Err(PackageError::DestinationExists);
    }
    let authored = capture_governed_closure(project_root, contract)?;
    let mut files = Vec::new();
    let registry_bytes = read_regular(&project_root.join("registry.yaml"))?;
    files.push(file_entry(
        "registry.yaml",
        &registry_bytes,
        "application/yaml",
        Visibility::OperatorOnly,
        false,
    ));
    for (relative, content) in &authored {
        files.push(file_entry(
            &format!("governed/{relative}"),
            content,
            media_type(relative),
            Visibility::OperatorOnly,
            false,
        ));
    }
    for artifact in &artifacts.artifacts {
        files.push(file_entry(
            &format!("generated/{}", artifact.path),
            &artifact.content,
            &artifact.media_type,
            artifact.visibility,
            true,
        ));
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));

    let packaged_artifacts = artifacts
        .artifacts
        .iter()
        .map(|artifact| PackageArtifact {
            id: artifact.id.clone(),
            path: format!("generated/{}", artifact.path),
            media_type: artifact.media_type.clone(),
            visibility: artifact.visibility,
            operation_identifier: artifact.operation_identifier.clone(),
            sha256: artifact.sha256.clone(),
        })
        .collect::<Vec<_>>();
    let source_schema_fingerprints = compiled
        .sources
        .iter()
        .map(|source| {
            (
                source.id.clone(),
                source.expected_schema_fingerprint.clone(),
            )
        })
        .collect();
    let source_schemas = compiled
        .sources
        .iter()
        .map(|source| {
            source
                .observed_schema
                .clone()
                .map(|schema| (source.id.clone(), schema))
                .ok_or(PackageError::Verification)
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let unsigned = UnsignedManifest {
        package_version: PACKAGE_VERSION,
        contract_revision: &compiled.contract_revision,
        source_schema_fingerprints: &source_schema_fingerprints,
        source_schemas: &source_schemas,
        artifacts: &packaged_artifacts,
        files: &files,
    };
    let manifest_value = serde_json::to_value(unsigned).map_err(|_| PackageError::CanonicalJson)?;
    let manifest_bytes =
        canonicalize_json(&manifest_value).map_err(|_| PackageError::CanonicalJson)?;
    let package_revision = digest(&manifest_bytes);
    let manifest = PackageManifest {
        package_version: PACKAGE_VERSION.into(),
        package_revision,
        contract_revision: compiled.contract_revision.clone(),
        source_schema_fingerprints,
        source_schemas,
        artifacts: packaged_artifacts,
        files,
    };
    let final_manifest = canonicalize_json(
        &serde_json::to_value(&manifest).map_err(|_| PackageError::CanonicalJson)?,
    )
    .map_err(|_| PackageError::CanonicalJson)?;

    fs::create_dir(output_dir).map_err(|_| PackageError::Write)?;
    let write_result = (|| {
        write_new_file(&output_dir.join("registry.yaml"), &registry_bytes)?;
        for (relative, content) in &authored {
            write_new_file(&output_dir.join("governed").join(relative), content)?;
        }
        for artifact in &artifacts.artifacts {
            write_generated(output_dir, artifact)?;
        }
        write_new_file(&output_dir.join("relay-package.json"), &final_manifest)
    })();
    if write_result.is_err() {
        // Do not remove a partially written directory here. A caller can
        // inspect it, and a subsequent package attempt will refuse it rather
        // than silently overwriting evidence.
        return Err(PackageError::Write);
    }
    harden_package_permissions(output_dir)?;
    Ok(manifest)
}

/// Load and verify a sealed package before any listener, issuer, audit sink,
/// or SQLite source is activated.
pub fn load_package(package_path: &Path) -> Result<VerifiedPackage, PackageError> {
    reject_symlink_path(package_path)?;
    let package_metadata = fs::symlink_metadata(package_path).map_err(|_| PackageError::Read)?;
    if !package_metadata.is_dir() || !safe_permissions(&package_metadata) {
        return Err(PackageError::Verification);
    }
    let manifest_path = package_path.join("relay-package.json");
    let manifest_metadata = fs::symlink_metadata(&manifest_path).map_err(|_| PackageError::Read)?;
    if !manifest_metadata.is_file()
        || manifest_metadata.len() > MAX_MANIFEST_BYTES
        || !safe_permissions(&manifest_metadata)
    {
        return Err(PackageError::Verification);
    }
    let manifest_bytes = read_regular(&manifest_path)?;
    let manifest: PackageManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|_| PackageError::Verification)?;
    if manifest.package_version != PACKAGE_VERSION
        || manifest.files.is_empty()
        || manifest.files.len() > MAX_PACKAGE_FILES
    {
        return Err(PackageError::Verification);
    }
    let canonical_manifest = canonicalize_json(
        &serde_json::to_value(&manifest).map_err(|_| PackageError::CanonicalJson)?,
    )
    .map_err(|_| PackageError::CanonicalJson)?;
    if canonical_manifest != manifest_bytes {
        return Err(PackageError::Verification);
    }
    let unsigned = UnsignedManifest {
        package_version: PACKAGE_VERSION,
        contract_revision: &manifest.contract_revision,
        source_schema_fingerprints: &manifest.source_schema_fingerprints,
        source_schemas: &manifest.source_schemas,
        artifacts: &manifest.artifacts,
        files: &manifest.files,
    };
    let unsigned_bytes = canonicalize_json(
        &serde_json::to_value(unsigned).map_err(|_| PackageError::CanonicalJson)?,
    )
    .map_err(|_| PackageError::CanonicalJson)?;
    if digest(&unsigned_bytes) != manifest.package_revision {
        return Err(PackageError::Verification);
    }

    let mut listed = BTreeSet::new();
    let mut loaded = BTreeMap::new();
    let mut total = manifest_bytes.len() as u64;
    for entry in &manifest.files {
        validate_relative(&entry.path)?;
        if !listed.insert(entry.path.as_str()) {
            return Err(PackageError::Verification);
        }
        reject_relative_symlinks(package_path, Path::new(&entry.path))?;
        let path = package_path.join(&entry.path);
        let metadata = fs::symlink_metadata(&path).map_err(|_| PackageError::Read)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || !safe_permissions(&metadata)
            || metadata.len() != entry.size
        {
            return Err(PackageError::Verification);
        }
        total = total
            .checked_add(metadata.len())
            .ok_or(PackageError::ClosureBound)?;
        if total > MAX_PACKAGE_BYTES {
            return Err(PackageError::ClosureBound);
        }
        let content = read_regular(&path)?;
        if digest(&content) != entry.sha256 {
            return Err(PackageError::Verification);
        }
        loaded.insert(entry.path.clone(), content);
    }
    let actual = enumerate_package_files(package_path)?;
    let mut expected = listed
        .iter()
        .map(|path| (*path).to_owned())
        .collect::<BTreeSet<_>>();
    expected.insert("relay-package.json".into());
    if actual != expected {
        return Err(PackageError::Verification);
    }

    let registry_entry = manifest
        .files
        .iter()
        .filter(|entry| entry.path == "registry.yaml")
        .collect::<Vec<_>>();
    if registry_entry.len() != 1
        || registry_entry[0].generated
        || registry_entry[0].visibility != Visibility::OperatorOnly
    {
        return Err(PackageError::Verification);
    }
    let contract_bytes = loaded
        .get("registry.yaml")
        .ok_or(PackageError::Verification)?;
    let contract_text =
        std::str::from_utf8(contract_bytes).map_err(|_| PackageError::Verification)?;
    let contract =
        RegistryContract::parse_yaml(contract_text).map_err(|_| PackageError::Verification)?;
    let governed = loaded
        .iter()
        .filter_map(|(path, content)| {
            path.strip_prefix("governed/")
                .map(|relative| (relative.to_owned(), content.clone()))
        })
        .collect::<GovernedFileSet>();
    if manifest.source_schemas.keys().collect::<BTreeSet<_>>()
        != manifest
            .source_schema_fingerprints
            .keys()
            .collect::<BTreeSet<_>>()
        || manifest.source_schemas.iter().any(|(id, schema)| {
            schema.source != *id || schema.fingerprint != manifest.source_schema_fingerprints[id]
        })
    {
        return Err(PackageError::Verification);
    }
    let observed = manifest
        .source_schemas
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let registry = compile_contract_with_governed_files(
        &contract,
        &observed,
        CompileProfile::Production,
        &governed,
    )
    .map_err(|_| PackageError::Verification)?;
    if registry.contract_revision != manifest.contract_revision
        || registry
            .sources
            .iter()
            .map(|source| {
                (
                    source.id.clone(),
                    source.expected_schema_fingerprint.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>()
            != manifest.source_schema_fingerprints
    {
        return Err(PackageError::Verification);
    }

    let regenerated = generate_artifacts(&registry).map_err(|_| PackageError::Verification)?;
    let expected_artifacts = regenerated
        .artifacts
        .iter()
        .map(|artifact| PackageArtifact {
            id: artifact.id.clone(),
            path: format!("generated/{}", artifact.path),
            media_type: artifact.media_type.clone(),
            visibility: artifact.visibility,
            operation_identifier: artifact.operation_identifier.clone(),
            sha256: artifact.sha256.clone(),
        })
        .collect::<Vec<_>>();
    if expected_artifacts != manifest.artifacts {
        return Err(PackageError::Verification);
    }
    let mut artifacts = regenerated;
    for artifact in &mut artifacts.artifacts {
        let packaged_path = format!("generated/{}", artifact.path);
        let packaged = loaded
            .get(&packaged_path)
            .ok_or(PackageError::Verification)?;
        if packaged != &artifact.content {
            return Err(PackageError::Verification);
        }
        // Retain bytes read from the sealed package after reproducing them.
        artifact.content.clone_from(packaged);
    }
    Ok(VerifiedPackage {
        manifest,
        contract,
        registry,
        artifacts,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedManifest<'a> {
    package_version: &'static str,
    contract_revision: &'a str,
    source_schema_fingerprints: &'a BTreeMap<String, String>,
    source_schemas: &'a BTreeMap<String, ObservedSourceSchema>,
    artifacts: &'a [PackageArtifact],
    files: &'a [PackageFile],
}

fn capture_governed_closure(
    project_root: &Path,
    contract: &RegistryContract,
) -> Result<BTreeMap<String, Vec<u8>>, PackageError> {
    let mut references = BTreeSet::new();
    references.insert(contract.registry.identifier_lifecycle_policy_ref.as_str());
    references.insert(contract.classifications.provenance_ref.as_str());
    for alignment in &contract.semantics.alignments {
        references.insert(alignment.profile_ref.as_str());
    }
    for resource in &contract.resources {
        references.insert(resource.record_context.lifecycle_state.codelist.as_str());
        for (_, property) in resource.properties.iter() {
            if let Some(codelist) = property.codelist.as_deref() {
                references.insert(codelist);
            }
        }
        for processing in &resource.processing_descriptions {
            references.insert(processing.legal_basis_ref.as_str());
            references.insert(processing.dpv_profile_ref.as_str());
        }
    }
    if references.len() > MAX_AUTHORED_FILES {
        return Err(PackageError::ClosureBound);
    }
    let root = project_root
        .canonicalize()
        .map_err(|_| PackageError::Read)?;
    let mut captured = BTreeMap::new();
    let mut total = 0_u64;
    for reference in references {
        validate_relative(reference)?;
        reject_relative_symlinks(&root, Path::new(reference))?;
        let path = root.join(reference);
        let metadata = fs::symlink_metadata(&path).map_err(|_| PackageError::Read)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(PackageError::UnsafeClosure);
        }
        let canonical = path.canonicalize().map_err(|_| PackageError::Read)?;
        if !canonical.starts_with(&root) {
            return Err(PackageError::UnsafeClosure);
        }
        total = total
            .checked_add(metadata.len())
            .ok_or(PackageError::ClosureBound)?;
        if total > MAX_AUTHORED_BYTES {
            return Err(PackageError::ClosureBound);
        }
        captured.insert(reference.to_owned(), read_regular(&canonical)?);
    }
    Ok(captured)
}

fn validate_relative(value: &str) -> Result<(), PackageError> {
    let path = Path::new(value);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(PackageError::UnsafeClosure);
    }
    Ok(())
}

fn read_regular(path: &Path) -> Result<Vec<u8>, PackageError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| PackageError::Read)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(PackageError::UnsafeClosure);
    }
    fs::read(path).map_err(|_| PackageError::Read)
}

fn reject_symlink_path(path: &Path) -> Result<(), PackageError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| PackageError::Read)?
            .join(path)
    };
    let effective_user = current_effective_user();
    let component_count = absolute.components().count();
    let mut current = std::path::PathBuf::new();
    for (index, component) in absolute.components().enumerate() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata)
                if metadata.file_type().is_symlink()
                    || !metadata.is_dir()
                    || !safe_ancestor_permissions(&metadata, effective_user)
                    || index + 1 == component_count && !safe_permissions(&metadata) =>
            {
                return Err(PackageError::UnsafeClosure);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(PackageError::Read);
            }
            Err(_) => return Err(PackageError::Read),
        }
    }
    Ok(())
}

fn reject_relative_symlinks(root: &Path, relative: &Path) -> Result<(), PackageError> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(PackageError::UnsafeClosure);
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current).map_err(|_| PackageError::Read)?;
        if metadata.file_type().is_symlink() {
            return Err(PackageError::UnsafeClosure);
        }
    }
    Ok(())
}

fn enumerate_package_files(root: &Path) -> Result<BTreeSet<String>, PackageError> {
    fn visit(
        root: &Path,
        directory: &Path,
        files: &mut BTreeSet<String>,
    ) -> Result<(), PackageError> {
        let metadata = fs::symlink_metadata(directory).map_err(|_| PackageError::Read)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() || !safe_permissions(&metadata) {
            return Err(PackageError::Verification);
        }
        for entry in fs::read_dir(directory).map_err(|_| PackageError::Read)? {
            let entry = entry.map_err(|_| PackageError::Read)?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|_| PackageError::Read)?;
            if metadata.file_type().is_symlink() || !safe_permissions(&metadata) {
                return Err(PackageError::Verification);
            }
            if metadata.is_dir() {
                visit(root, &path, files)?;
            } else if metadata.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| PackageError::UnsafeClosure)?;
                let relative = relative.to_str().ok_or(PackageError::UnsafeClosure)?;
                validate_relative(relative)?;
                if !files.insert(relative.to_owned()) || files.len() > MAX_PACKAGE_FILES + 1 {
                    return Err(PackageError::ClosureBound);
                }
            } else {
                return Err(PackageError::Verification);
            }
        }
        Ok(())
    }

    let mut files = BTreeSet::new();
    visit(root, root, &mut files)?;
    Ok(files)
}

#[cfg(unix)]
fn safe_permissions(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    trusted_unix_owner_and_mode(
        metadata.uid(),
        metadata.permissions().mode(),
        current_effective_user(),
        false,
    )
}

#[cfg(not(unix))]
fn safe_permissions(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn safe_ancestor_permissions(metadata: &fs::Metadata, effective_user: u32) -> bool {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    trusted_unix_owner_and_mode(
        metadata.uid(),
        metadata.permissions().mode(),
        effective_user,
        true,
    )
}

#[cfg(not(unix))]
fn safe_ancestor_permissions(_metadata: &fs::Metadata, _effective_user: u32) -> bool {
    false
}

#[cfg(unix)]
fn trusted_unix_owner_and_mode(
    owner: u32,
    mode: u32,
    effective_user: u32,
    allow_root_sticky: bool,
) -> bool {
    let trusted_owner = owner == 0 || owner == effective_user;
    let not_writable_by_others = mode & 0o022 == 0;
    let protected_shared_ancestor = allow_root_sticky && owner == 0 && mode & 0o1000 != 0;
    trusted_owner && (not_writable_by_others || protected_shared_ancestor)
}

#[cfg(unix)]
fn current_effective_user() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(not(unix))]
fn current_effective_user() -> u32 {
    0
}

#[cfg(unix)]
fn harden_package_permissions(root: &Path) -> Result<(), PackageError> {
    use std::os::unix::fs::PermissionsExt;

    fn visit(path: &Path) -> Result<(), PackageError> {
        let metadata = fs::symlink_metadata(path).map_err(|_| PackageError::Write)?;
        if metadata.file_type().is_symlink() {
            return Err(PackageError::UnsafeClosure);
        }
        let mode = if metadata.is_dir() { 0o755 } else { 0o644 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|_| PackageError::Write)?;
        if metadata.is_dir() {
            for entry in fs::read_dir(path).map_err(|_| PackageError::Write)? {
                visit(&entry.map_err(|_| PackageError::Write)?.path())?;
            }
        }
        Ok(())
    }
    visit(root)
}

#[cfg(not(unix))]
fn harden_package_permissions(_root: &Path) -> Result<(), PackageError> {
    Ok(())
}

fn write_generated(root: &Path, artifact: &GeneratedArtifact) -> Result<(), PackageError> {
    validate_relative(&artifact.path)?;
    write_new_file(
        &root.join("generated").join(&artifact.path),
        &artifact.content,
    )
}

fn write_new_file(path: &Path, content: &[u8]) -> Result<(), PackageError> {
    if path.exists() {
        return Err(PackageError::Write);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| PackageError::Write)?;
    }
    fs::write(path, content).map_err(|_| PackageError::Write)
}

fn file_entry(
    path: &str,
    content: &[u8],
    media_type: &str,
    visibility: Visibility,
    generated: bool,
) -> PackageFile {
    PackageFile {
        path: path.into(),
        size: content.len() as u64,
        sha256: digest(content),
        media_type: media_type.into(),
        visibility,
        generated,
    }
}

fn digest(content: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(content)))
}

fn media_type(path: &str) -> &'static str {
    match Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
    {
        Some("json") | Some("jsonld") => "application/json",
        Some("ttl") => "text/turtle",
        _ => "application/yaml",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_references_cannot_escape() {
        assert!(validate_relative("governance/review.yaml").is_ok());
        assert!(validate_relative("../outside.yaml").is_err());
        assert!(validate_relative("/absolute.yaml").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn governed_capture_rejects_intermediate_symlinks() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("temporary project");
        let project = temporary.path().join("project");
        let governed = crate::compiler::tests::governed_files();
        for (relative, content) in &governed {
            let relative = Path::new(relative);
            let path = if relative.starts_with("governance") {
                project.join("real-governance").join(
                    relative
                        .strip_prefix("governance")
                        .expect("governance prefix"),
                )
            } else {
                project.join(relative)
            };
            fs::create_dir_all(path.parent().expect("governed parent"))
                .expect("governed directory");
            fs::write(path, content).expect("governed file");
        }
        symlink(project.join("real-governance"), project.join("governance"))
            .expect("intermediate symlink");
        let contract = RegistryContract::parse_yaml(crate::compiler::tests::valid_contract())
            .expect("strict contract");

        assert!(matches!(
            capture_governed_closure(&project, &contract),
            Err(PackageError::UnsafeClosure)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn package_trust_rejects_foreign_owners_and_limits_the_sticky_exception() {
        let effective_user = 1000;
        assert!(trusted_unix_owner_and_mode(
            effective_user,
            0o100644,
            effective_user,
            false
        ));
        assert!(trusted_unix_owner_and_mode(
            0,
            0o040755,
            effective_user,
            false
        ));
        assert!(!trusted_unix_owner_and_mode(
            effective_user + 1,
            0o100644,
            effective_user,
            false
        ));
        assert!(trusted_unix_owner_and_mode(
            0,
            0o041777,
            effective_user,
            true
        ));
        assert!(!trusted_unix_owner_and_mode(
            0,
            0o041777,
            effective_user,
            false
        ));
        assert!(!trusted_unix_owner_and_mode(
            effective_user,
            0o041777,
            effective_user,
            true
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_package_below_a_writable_ancestor_is_rejected() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempfile::tempdir().expect("temporary root");
        let root = temporary.path().canonicalize().expect("canonical root");
        let writable = root.join("writable");
        let package = writable.join("package");
        fs::create_dir_all(&package).expect("package path");
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o777))
            .expect("ancestor becomes unsafe");

        assert!(matches!(
            reject_symlink_path(&package),
            Err(PackageError::UnsafeClosure)
        ));
    }

    #[test]
    fn sealed_package_reproduces_and_tampering_is_refused() {
        let temporary = tempfile::tempdir().expect("temporary project");
        let project = temporary.path().join("project");
        fs::create_dir(&project).expect("project directory");
        fs::write(
            project.join("registry.yaml"),
            crate::compiler::tests::valid_contract(),
        )
        .expect("registry contract");
        let governed = crate::compiler::tests::governed_files();
        for (relative, content) in &governed {
            let path = project.join(relative);
            fs::create_dir_all(path.parent().expect("parent")).expect("governed directory");
            fs::write(path, content).expect("governed file");
        }
        let contract = RegistryContract::parse_yaml(crate::compiler::tests::valid_contract())
            .expect("strict contract");
        let registry = compile_contract_with_governed_files(
            &contract,
            &[crate::compiler::tests::observed_schema()],
            CompileProfile::Production,
            &governed,
        )
        .expect("compiled Registry");
        let artifacts = generate_artifacts(&registry).expect("artifacts");
        let output = temporary.path().join("package");
        let manifest = build_package(&project, &output, &contract, &registry, &artifacts)
            .expect("sealed package");
        // macOS places temporary directories below `/var`, which is itself a
        // symlink. The production loader correctly refuses paths containing
        // symlink traversal, so exercise it with the resolved package path.
        let resolved_output = output.canonicalize().expect("resolved package path");
        let verified = load_package(&resolved_output).expect("verified package");
        assert_eq!(verified.manifest, manifest);
        assert_eq!(verified.registry, registry);

        let artifact = &manifest.artifacts[0];
        fs::write(output.join(&artifact.path), b"tampered").expect("tamper fixture");
        assert!(load_package(&resolved_output).is_err());
    }
}
