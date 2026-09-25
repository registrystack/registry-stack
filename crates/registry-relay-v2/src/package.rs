// SPDX-License-Identifier: Apache-2.0
//! Deterministic Relay packages from one compiled Registry, written and
//! verified in the shared Registry Stack package format.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};

use registry_platform_canonical_json::canonicalize_json;
use registry_platform_config::package::{
    self as shared, is_envelope_file, PackageLimits, SUM_FILE,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::artifacts::{
    generate_artifacts, ArtifactAccessBinding, ArtifactSet, OperationArtifactBindings,
};
use crate::compiler::{
    compile_contract_with_governed_files, referenced_governed_files, GovernedFileSet,
};
use crate::contract::{RegistryContract, Visibility};
use crate::model::{
    CompileProfile, CompiledClassificationReview, CompiledRegistry, ObservedSourceSchema,
};

/// The command that builds a Relay package, named in every refusal.
pub const PACKAGE_COMMAND: &str = "relayctl package";
/// The field a runtime refusal names instead of the configured directory.
const PACKAGE_ROOT_FIELD: &str = "package.root";
/// The self-hashing manifest earlier packages carried instead of `SHA256SUMS`.
const RETIRED_MANIFEST_PATH: &str = "relay-package.json";
const REGISTRY_PATH: &str = "registry.yaml";
const COMPILED_REGISTRY_PATH: &str = "compiled/registry.json";
const GOVERNED_PREFIX: &str = "governed/";
const GENERATED_PREFIX: &str = "generated/";
const MAX_AUTHORED_FILES: usize = 256;
const MAX_AUTHORED_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PACKAGE_FILES: usize = 1_024;
const MAX_PACKAGE_BYTES: u64 = 64 * 1024 * 1024;

/// The bounds a Relay package is written and verified under.
#[must_use]
pub fn package_limits() -> PackageLimits {
    PackageLimits {
        max_files: MAX_PACKAGE_FILES,
        max_file_bytes: MAX_PACKAGE_BYTES,
        max_total_bytes: MAX_PACKAGE_BYTES,
        ..PackageLimits::default()
    }
}

/// What `relayctl package` wrote, or would write under `--dry-run`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageSummary {
    /// The `sha256:` digest of the package's `SHA256SUMS`, the value
    /// `package.expectedDigest` pins.
    pub package_digest: String,
    pub revision: Option<String>,
    pub dry_run: bool,
    pub contract_revision: String,
    pub source_schema_fingerprints: BTreeMap<String, String>,
    /// Every Relay file of the package; `SHA256SUMS` and `REVISION` are the
    /// shared format's own.
    pub files: Vec<PackageFile>,
    /// The exposure of every generated artifact, as the runtime derives it
    /// from the compiled Registry. The package does not store it.
    pub artifacts: Vec<PackageArtifact>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageFile {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageArtifact {
    pub id: String,
    pub path: String,
    pub media_type: String,
    pub visibility: Visibility,
    pub operation_identifier: Option<String>,
    pub access_binding: Option<ArtifactAccessBinding>,
    pub sha256: String,
}

#[derive(Debug, Error)]
pub enum PackageError {
    #[error("the project closure is unsafe")]
    UnsafeClosure,
    #[error("the project closure exceeds package bounds")]
    ClosureBound,
    #[error("a package file could not be read")]
    Read,
    #[error("the package could not be written")]
    Write,
    #[error("the package manifest could not be canonicalized")]
    CanonicalJson,
    #[error("the compiled project could not be packaged")]
    Verification,
    /// The shared package format refused the directory: a missing
    /// `SHA256SUMS`, a changed, missing, or extra file, or a bound.
    #[error("{0}")]
    Package(#[from] shared::PackageError),
    #[error(
        "the package at {PACKAGE_ROOT_FIELD} holds {RETIRED_MANIFEST_PATH}, which Relay no \
         longer reads; rebuild the package with `{PACKAGE_COMMAND}`, which writes {SUM_FILE}"
    )]
    RetiredManifest,
    #[error(
        "the package at {PACKAGE_ROOT_FIELD}, or a directory above it, holds a symbolic link or \
         special file, is not owned by the effective user or root, or is writable by others; \
         deploy the package built by `{PACKAGE_COMMAND}` read-only"
    )]
    UnsafePermissions,
    #[error(
        "the package at {PACKAGE_ROOT_FIELD} changed while it was read ({path}); deploy the \
         whole package built by `{PACKAGE_COMMAND}` and restart"
    )]
    ChangedWhileRead { path: String },
    #[error(
        "the package at {PACKAGE_ROOT_FIELD} does not hold the files its compiled registry \
         names{}; rebuild it with `{PACKAGE_COMMAND}`",
        describe_contents(.missing, .extra)
    )]
    Contents {
        missing: Vec<String>,
        extra: Vec<String>,
    },
    #[error(
        "the package at {PACKAGE_ROOT_FIELD} holds {path}, which its registry.yaml and governed \
         files do not reproduce; rebuild it with `{PACKAGE_COMMAND}`"
    )]
    Derivation { path: String },
}

fn describe_contents(missing: &[String], extra: &[String]) -> String {
    let mut described = String::new();
    for (label, paths) in [("missing", missing), ("extra", extra)] {
        if !paths.is_empty() {
            described.push_str(&format!("; {label}: {}", paths.join(", ")));
        }
    }
    described
}

/// A package whose every byte matched its `SHA256SUMS` and whose compiled
/// registry and generated artifacts were reproduced from its sources.
#[derive(Clone, Debug)]
pub struct VerifiedPackage {
    /// The `sha256:` digest of `SHA256SUMS`.
    pub digest: String,
    pub revision: Option<String>,
    pub contract: RegistryContract,
    pub registry: CompiledRegistry,
    pub artifacts: ArtifactSet,
}

impl VerifiedPackage {
    /// The source schemas the package was compiled against, by source.
    #[must_use]
    pub fn source_schemas(&self) -> BTreeMap<String, ObservedSourceSchema> {
        self.registry
            .sources
            .iter()
            .filter_map(|source| {
                source
                    .observed_schema
                    .clone()
                    .map(|schema| (source.id.clone(), schema))
            })
            .collect()
    }
}

/// Construct a package of one compiled project. With `output_dir`, write it
/// into that new directory; without, report the digest it would have. An
/// existing destination is refused so a run can never mix package contents.
pub fn build_package(
    project_root: &Path,
    output_dir: Option<&Path>,
    revision: Option<&str>,
    contract: &RegistryContract,
    compiled: &CompiledRegistry,
    artifacts: &ArtifactSet,
) -> Result<PackageSummary, PackageError> {
    let authored = capture_governed_closure(
        project_root,
        contract,
        compiled.classification_review.as_ref(),
    )?;
    let registry_bytes = read_regular(&project_root.join(REGISTRY_PATH))?;
    let packaged_contract = RegistryContract::parse_yaml(
        std::str::from_utf8(&registry_bytes).map_err(|_| PackageError::Verification)?,
    )
    .map_err(|_| PackageError::Verification)?;
    if packaged_contract != *contract {
        return Err(PackageError::Verification);
    }
    validate_build_inputs(contract, compiled, artifacts, &authored)?;

    let mut files = BTreeMap::new();
    files.insert(REGISTRY_PATH.to_owned(), registry_bytes);
    for (relative, content) in authored {
        files.insert(format!("{GOVERNED_PREFIX}{relative}"), content);
    }
    files.insert(
        COMPILED_REGISTRY_PATH.to_owned(),
        canonical_compiled(compiled)?,
    );
    for artifact in &artifacts.artifacts {
        files.insert(
            format!("{GENERATED_PREFIX}{}", artifact.path),
            artifact.content.clone(),
        );
    }

    let limits = package_limits();
    let (package_digest, revision) = match output_dir {
        None => (
            shared::plan_package(project_root, &files, revision, &limits, PACKAGE_COMMAND)?,
            revision.map(str::to_owned),
        ),
        Some(output_dir) => {
            let written =
                shared::write_package(output_dir, &files, revision, &limits, PACKAGE_COMMAND)?;
            harden_package_permissions(output_dir)?;
            (
                written.digest().to_owned(),
                written.revision().map(str::to_owned),
            )
        }
    };
    Ok(PackageSummary {
        package_digest,
        revision,
        dry_run: output_dir.is_none(),
        contract_revision: compiled.contract_revision.clone(),
        source_schema_fingerprints: compiled
            .sources
            .iter()
            .map(|source| {
                (
                    source.id.clone(),
                    source.expected_schema_fingerprint.clone(),
                )
            })
            .collect(),
        files: files
            .iter()
            .map(|(path, content)| PackageFile {
                path: path.clone(),
                sha256: digest(content),
                bytes: content.len() as u64,
            })
            .collect(),
        artifacts: artifacts
            .artifacts
            .iter()
            .map(|artifact| PackageArtifact {
                id: artifact.id.clone(),
                path: format!("{GENERATED_PREFIX}{}", artifact.path),
                media_type: artifact.media_type.clone(),
                visibility: artifact.visibility,
                operation_identifier: artifact.operation_identifier.clone(),
                access_binding: artifact.access_binding.clone(),
                sha256: artifact.sha256.clone(),
            })
            .collect(),
    })
}

fn canonical_compiled(compiled: &CompiledRegistry) -> Result<Vec<u8>, PackageError> {
    canonicalize_json(&serde_json::to_value(compiled).map_err(|_| PackageError::CanonicalJson)?)
        .map_err(|_| PackageError::CanonicalJson)
}

fn validate_build_inputs(
    contract: &RegistryContract,
    compiled: &CompiledRegistry,
    artifacts: &ArtifactSet,
    governed: &GovernedFileSet,
) -> Result<(), PackageError> {
    if artifacts.contract_revision != compiled.contract_revision
        || !compiled_matches_contract(compiled, contract)
    {
        return Err(PackageError::Verification);
    }
    let observed = observed_source_schemas(compiled).ok_or(PackageError::Verification)?;
    verify_compiled_derivation(contract, compiled, governed, &observed)?;
    verify_artifact_derivation(compiled, artifacts)?;
    if !valid_artifact_set(compiled, artifacts) {
        return Err(PackageError::Verification);
    }
    Ok(())
}

fn compiled_matches_contract(compiled: &CompiledRegistry, contract: &RegistryContract) -> bool {
    compiled.contract_id == contract.metadata.id
        && compiled.contract_version == contract.metadata.version
        && compiled.registry_identifier == contract.registry.registry_identifier
}

/// The schema each source was compiled against, when every source records
/// one that names it.
fn observed_source_schemas(compiled: &CompiledRegistry) -> Option<Vec<ObservedSourceSchema>> {
    compiled
        .sources
        .iter()
        .map(|source| {
            source.observed_schema.clone().filter(|schema| {
                schema.source == source.id
                    && schema.fingerprint == source.expected_schema_fingerprint
            })
        })
        .collect()
}

/// Every artifact has a unique identifier and safe relative path, and every
/// ownership and operation binding is exactly the one the Registry declares.
fn valid_artifact_set(compiled: &CompiledRegistry, artifacts: &ArtifactSet) -> bool {
    let expected_operation_access_profiles = operation_access_profile_pairs(compiled);
    let expected_fixed_operations = fixed_statistical_operations(compiled);
    let mut artifact_ids = BTreeSet::new();
    let mut artifact_paths = BTreeSet::new();
    for artifact in &artifacts.artifacts {
        if validate_relative(&artifact.path).is_err()
            || !artifact_ids.insert(artifact.id.as_str())
            || !artifact_paths.insert(artifact.path.as_str())
            || artifact.sha256 != digest(&artifact.content)
            || !valid_artifact_access_binding(
                artifact.visibility,
                artifact.operation_identifier.as_deref(),
                artifact.access_binding.as_ref(),
                &expected_operation_access_profiles,
                &expected_fixed_operations,
            )
        {
            return false;
        }
    }
    valid_operation_artifact_bindings(
        &artifacts.operation_bindings,
        &expected_operation_access_profiles,
        &artifact_paths,
    )
}

fn verify_compiled_derivation(
    contract: &RegistryContract,
    compiled: &CompiledRegistry,
    governed: &GovernedFileSet,
    observed: &[ObservedSourceSchema],
) -> Result<(), PackageError> {
    let reproduced = compile_contract_with_governed_files(
        contract,
        observed,
        CompileProfile::Production,
        governed,
    )
    .map_err(|_| PackageError::Verification)?;
    if reproduced != *compiled {
        return Err(PackageError::Verification);
    }
    Ok(())
}

fn verify_artifact_derivation(
    compiled: &CompiledRegistry,
    artifacts: &ArtifactSet,
) -> Result<(), PackageError> {
    // The package digest is an integrity digest, not an authenticity proof. A
    // caller can recalculate it, so acceptance must reproduce every artifact
    // byte and its release metadata from the already rederived Registry.
    let reproduced = generate_artifacts(compiled).map_err(|_| PackageError::Verification)?;
    if reproduced != *artifacts {
        return Err(PackageError::Verification);
    }
    Ok(())
}

/// Load and verify a package before any listener, issuer, audit sink, or
/// SQLite source is activated.
///
/// The shared format proves every byte matches `SHA256SUMS`. Relay then
/// proves the files are exactly the ones its compiled registry names, and
/// reproduces the compiled registry from `registry.yaml`, the governed files,
/// and the recorded source schemas, and every generated artifact from the
/// compiled registry.
pub fn load_package(package_path: &Path) -> Result<VerifiedPackage, PackageError> {
    match reject_symlink_path(package_path) {
        // An absent root is refused by the shared format, naming the command.
        Ok(()) | Err(PackageError::Read) => {}
        Err(_) => return Err(PackageError::UnsafePermissions),
    }
    if fs::symlink_metadata(package_path.join(RETIRED_MANIFEST_PATH)).is_ok() {
        return Err(PackageError::RetiredManifest);
    }
    let verified = shared::verify_package(package_path, &package_limits(), PACKAGE_COMMAND)
        .map_err(|error| error.naming_root_as(PACKAGE_ROOT_FIELD))?;

    // The shared format hashes bytes only; Relay also requires every entry to
    // be owned by the effective user or root and not writable by others.
    let present = enumerate_package_files(package_path)?;
    let listed = verified
        .files()
        .chain(std::iter::once(SUM_FILE))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if let Some(path) = present.symmetric_difference(&listed).next() {
        return Err(PackageError::ChangedWhileRead { path: path.clone() });
    }

    // Read each file once more and hold exactly the bytes that were verified.
    let mut loaded = BTreeMap::new();
    for path in verified.files().filter(|path| !is_envelope_file(path)) {
        let content =
            read_regular(&package_path.join(path)).map_err(|_| PackageError::ChangedWhileRead {
                path: path.to_owned(),
            })?;
        if verified.file_digest(path).as_deref() != Some(digest(&content).as_str()) {
            return Err(PackageError::ChangedWhileRead {
                path: path.to_owned(),
            });
        }
        loaded.insert(path.to_owned(), content);
    }

    let required = [REGISTRY_PATH, COMPILED_REGISTRY_PATH];
    let missing = required
        .iter()
        .filter(|path| !loaded.contains_key(**path))
        .map(|path| (*path).to_owned())
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(PackageError::Contents {
            missing,
            extra: Vec::new(),
        });
    }
    let derivation = |path: &str| PackageError::Derivation {
        path: path.to_owned(),
    };
    let contract = std::str::from_utf8(&loaded[REGISTRY_PATH])
        .ok()
        .and_then(|text| RegistryContract::parse_yaml(text).ok())
        .ok_or_else(|| derivation(REGISTRY_PATH))?;
    let compiled_bytes = &loaded[COMPILED_REGISTRY_PATH];
    let registry = serde_json::from_slice::<CompiledRegistry>(compiled_bytes)
        .ok()
        .filter(|registry| {
            canonical_compiled(registry).is_ok_and(|bytes| bytes == *compiled_bytes)
                && compiled_matches_contract(registry, &contract)
        })
        .ok_or_else(|| derivation(COMPILED_REGISTRY_PATH))?;
    let artifacts =
        generate_artifacts(&registry).map_err(|_| derivation(COMPILED_REGISTRY_PATH))?;

    let expected = required
        .iter()
        .map(|path| (*path).to_owned())
        .chain(
            registry
                .governed_files
                .iter()
                .map(|file| format!("{GOVERNED_PREFIX}{}", file.path)),
        )
        .chain(
            artifacts
                .artifacts
                .iter()
                .map(|artifact| format!("{GENERATED_PREFIX}{}", artifact.path)),
        )
        .collect::<BTreeSet<_>>();
    let found = loaded.keys().cloned().collect::<BTreeSet<_>>();
    if expected != found {
        return Err(PackageError::Contents {
            missing: expected.difference(&found).cloned().collect(),
            extra: found.difference(&expected).cloned().collect(),
        });
    }

    let governed = loaded
        .iter()
        .filter_map(|(path, content)| {
            path.strip_prefix(GOVERNED_PREFIX)
                .map(|relative| (relative.to_owned(), content.clone()))
        })
        .collect::<GovernedFileSet>();
    if let Some(file) = registry.governed_files.iter().find(|file| {
        governed
            .get(&file.path)
            .is_none_or(|content| digest(content) != file.sha256)
    }) {
        return Err(derivation(&format!("{GOVERNED_PREFIX}{}", file.path)));
    }
    let observed =
        observed_source_schemas(&registry).ok_or_else(|| derivation(COMPILED_REGISTRY_PATH))?;
    verify_compiled_derivation(&contract, &registry, &governed, &observed)
        .map_err(|_| derivation(COMPILED_REGISTRY_PATH))?;

    if artifacts.contract_revision != registry.contract_revision
        || !valid_artifact_set(&registry, &artifacts)
    {
        return Err(derivation(COMPILED_REGISTRY_PATH));
    }
    for artifact in &artifacts.artifacts {
        let path = format!("{GENERATED_PREFIX}{}", artifact.path);
        if loaded[&path] != artifact.content {
            return Err(derivation(&path));
        }
    }
    Ok(VerifiedPackage {
        digest: verified.digest().to_owned(),
        revision: verified.revision().map(str::to_owned),
        contract,
        registry,
        artifacts,
    })
}

fn valid_operation_artifact_bindings(
    bindings: &[OperationArtifactBindings],
    expected_operation_access_profiles: &BTreeSet<(&str, &str)>,
    artifact_paths: &BTreeSet<&str>,
) -> bool {
    let mut bound_operation_access_profiles = BTreeSet::new();
    for binding in bindings {
        let pair = (
            binding.operation_identifier.as_str(),
            binding.access_profile_identifier.as_str(),
        );
        if !expected_operation_access_profiles.contains(&pair)
            || !bound_operation_access_profiles.insert(pair)
            || [
                binding.vocabulary_path.as_str(),
                binding.context_path.as_str(),
                binding.access_profile_schema_path.as_str(),
                binding.access_profile_shacl_path.as_str(),
                binding.classification_path.as_str(),
                binding.processing_path.as_str(),
            ]
            .iter()
            .any(|path| !artifact_paths.contains(path))
        {
            return false;
        }
    }
    bound_operation_access_profiles == *expected_operation_access_profiles
}

fn operation_access_profile_pairs(registry: &CompiledRegistry) -> BTreeSet<(&str, &str)> {
    registry
        .resources
        .iter()
        .flat_map(|resource| resource.operations.iter())
        .flat_map(|operation| {
            operation
                .access_profiles
                .iter()
                .map(|access_profile| (operation.identifier.as_str(), access_profile.id.as_str()))
        })
        .collect()
}

fn fixed_statistical_operations(registry: &CompiledRegistry) -> BTreeSet<String> {
    registry
        .statistical_datasets
        .iter()
        .map(|dataset| dataset.operation_identifier())
        .collect()
}

fn valid_artifact_access_binding(
    visibility: Visibility,
    operation_identifier: Option<&str>,
    access_binding: Option<&ArtifactAccessBinding>,
    record_bindings: &BTreeSet<(&str, &str)>,
    fixed_operations: &BTreeSet<String>,
) -> bool {
    match (visibility, operation_identifier, access_binding) {
        (
            Visibility::OperationBound,
            Some(operation),
            Some(ArtifactAccessBinding::AccessProfile { identifier }),
        ) => record_bindings.contains(&(operation, identifier.as_str())),
        (
            Visibility::OperationBound,
            Some(operation),
            Some(ArtifactAccessBinding::FixedOperation),
        ) => fixed_operations.contains(operation),
        (
            Visibility::Public | Visibility::OperatorOnly,
            Some(operation),
            Some(ArtifactAccessBinding::FixedOperation),
        ) => fixed_operations.contains(operation),
        (Visibility::Public | Visibility::OperatorOnly, None, None) => true,
        _ => false,
    }
}

fn capture_governed_closure(
    project_root: &Path,
    contract: &RegistryContract,
    review: Option<&CompiledClassificationReview>,
) -> Result<BTreeMap<String, Vec<u8>>, PackageError> {
    let mut references = referenced_governed_files(contract);
    if let Some(review) = review {
        references.insert(review.rationale_ref.as_str());
        if let Some(generated) = &review.generated_identification {
            references.insert(generated.report_ref.as_str());
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
            return Err(PackageError::UnsafePermissions);
        }
        for entry in fs::read_dir(directory).map_err(|_| PackageError::Read)? {
            let entry = entry.map_err(|_| PackageError::Read)?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|_| PackageError::Read)?;
            if metadata.file_type().is_symlink() || !safe_permissions(&metadata) {
                return Err(PackageError::UnsafePermissions);
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
                return Err(PackageError::UnsafePermissions);
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

fn digest(content: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(content)))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        temporary: tempfile::TempDir,
        project: std::path::PathBuf,
        contract: RegistryContract,
        registry: CompiledRegistry,
        artifacts: ArtifactSet,
    }

    impl Fixture {
        fn new() -> Self {
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
            Self {
                temporary,
                project,
                contract,
                registry,
                artifacts,
            }
        }

        /// Build a package named `name` and return its resolved path. macOS
        /// places temporary directories below `/var`, which is itself a
        /// symlink, and the loader refuses symlink traversal.
        fn package(
            &self,
            name: &str,
            revision: Option<&str>,
        ) -> (std::path::PathBuf, PackageSummary) {
            let output = self.temporary.path().join(name);
            let summary = self
                .build(Some(&output), revision, &self.registry, &self.artifacts)
                .expect("package builds");
            (
                output.canonicalize().expect("resolved package path"),
                summary,
            )
        }

        fn build(
            &self,
            output: Option<&Path>,
            revision: Option<&str>,
            registry: &CompiledRegistry,
            artifacts: &ArtifactSet,
        ) -> Result<PackageSummary, PackageError> {
            build_package(
                &self.project,
                output,
                revision,
                &self.contract,
                registry,
                artifacts,
            )
        }
    }

    /// Rewrite `SHA256SUMS` over whatever the directory now holds, as a
    /// forger who can recompute digests would.
    fn reseal(package_path: &Path) {
        fs::remove_file(package_path.join(SUM_FILE)).expect("sum file removes");
        shared::write_sum_file(package_path, None, &package_limits(), PACKAGE_COMMAND)
            .expect("forged sum file writes");
    }

    fn refusal(package_path: &Path) -> String {
        load_package(package_path)
            .expect_err("the package is refused")
            .to_string()
    }

    #[test]
    fn package_limits_bound_files_and_bytes() {
        let limits = package_limits();
        assert_eq!(limits.max_files, MAX_PACKAGE_FILES);
        assert_eq!(limits.max_total_bytes, MAX_PACKAGE_BYTES);
        let files = (0..=MAX_PACKAGE_FILES)
            .map(|index| (format!("generated/{index}.json"), Vec::new()))
            .collect::<BTreeMap<_, _>>();
        let error = shared::plan_package(Path::new("."), &files, None, &limits, PACKAGE_COMMAND)
            .expect_err("one file too many");
        assert!(matches!(
            error.kind(),
            shared::PackageErrorKind::Bound { .. }
        ));
    }

    #[test]
    fn a_package_is_the_shared_format_and_reproduces() {
        let fixture = Fixture::new();
        let (package_path, summary) = fixture.package("package", None);
        let sums = fs::read(package_path.join(SUM_FILE)).expect("sum file");
        assert_eq!(summary.package_digest, digest(&sums));
        assert!(!summary.dry_run);
        assert!(!package_path.join(RETIRED_MANIFEST_PATH).exists());
        assert!(summary
            .files
            .iter()
            .any(|file| file.path == COMPILED_REGISTRY_PATH));
        assert_eq!(
            summary
                .source_schema_fingerprints
                .keys()
                .collect::<Vec<_>>(),
            fixture
                .registry
                .sources
                .iter()
                .map(|source| &source.id)
                .collect::<Vec<_>>()
        );

        let verified = load_package(&package_path).expect("verified package");
        assert_eq!(verified.digest, summary.package_digest);
        assert_eq!(verified.revision, None);
        assert_eq!(verified.registry, fixture.registry);
        assert_eq!(verified.artifacts, fixture.artifacts);
        assert_eq!(
            verified.source_schemas().into_values().collect::<Vec<_>>(),
            [crate::compiler::tests::observed_schema()]
        );

        let (_again, again) = fixture.package("again", None);
        assert_eq!(again.package_digest, summary.package_digest);
        let planned = fixture
            .build(None, None, &fixture.registry, &fixture.artifacts)
            .expect("dry run");
        assert!(planned.dry_run);
        assert_eq!(planned.package_digest, summary.package_digest);
        assert_eq!(planned.files, summary.files);

        let (revised_path, revised) = fixture.package("revised", Some("release 7"));
        assert_ne!(revised.package_digest, summary.package_digest);
        assert_eq!(revised.revision.as_deref(), Some("release 7"));
        assert_eq!(
            load_package(&revised_path)
                .expect("revised package")
                .revision
                .as_deref(),
            Some("release 7")
        );

        let error = fixture
            .build(
                Some(&fixture.temporary.path().join("package")),
                None,
                &fixture.registry,
                &fixture.artifacts,
            )
            .expect_err("an existing output is refused");
        assert!(
            matches!(&error, PackageError::Package(error)
                if matches!(error.kind(), shared::PackageErrorKind::OutputExists)),
            "{error}"
        );
    }

    #[test]
    fn a_changed_missing_or_extra_file_is_refused_by_name() {
        let fixture = Fixture::new();
        let (package_path, summary) = fixture.package("package", None);
        let artifact = summary
            .files
            .iter()
            .find(|file| file.path.starts_with(GENERATED_PREFIX))
            .expect("generated file")
            .path
            .clone();

        let original = fs::read(package_path.join(&artifact)).expect("artifact bytes");
        fs::write(package_path.join(&artifact), b"changed").expect("change a file");
        let message = refusal(&package_path);
        assert!(
            message.contains(&format!("changed: {artifact}")),
            "{message}"
        );
        assert!(message.contains("package.root"), "{message}");
        assert!(message.contains(PACKAGE_COMMAND), "{message}");
        assert!(
            !message.contains(&*package_path.to_string_lossy()),
            "{message}"
        );
        fs::write(package_path.join(&artifact), &original).expect("restore");

        fs::remove_file(package_path.join(REGISTRY_PATH)).expect("remove a file");
        let message = refusal(&package_path);
        assert!(message.contains("missing: registry.yaml"), "{message}");
        assert!(message.contains(PACKAGE_COMMAND), "{message}");
        fs::write(
            package_path.join(REGISTRY_PATH),
            crate::compiler::tests::valid_contract(),
        )
        .expect("restore");

        fs::write(package_path.join("notes.txt"), b"extra").expect("add a file");
        let message = refusal(&package_path);
        assert!(message.contains("extra: notes.txt"), "{message}");
        assert!(message.contains(PACKAGE_COMMAND), "{message}");
        fs::remove_file(package_path.join("notes.txt")).expect("remove the extra file");

        load_package(&package_path).expect("the restored package verifies");
    }

    #[test]
    fn a_directory_that_is_not_a_package_is_refused_with_the_command() {
        let fixture = Fixture::new();
        let project = fixture.project.canonicalize().expect("resolved project");
        let message = refusal(&project);
        assert!(message.contains("has no SHA256SUMS"), "{message}");
        assert!(message.contains(PACKAGE_COMMAND), "{message}");

        let (package_path, _) = fixture.package("package", None);
        fs::write(package_path.join(RETIRED_MANIFEST_PATH), b"{}").expect("retired manifest");
        let message = refusal(&package_path);
        assert!(message.contains(RETIRED_MANIFEST_PATH), "{message}");
        assert!(message.contains(PACKAGE_COMMAND), "{message}");
    }

    #[test]
    fn a_resealed_package_must_hold_exactly_what_its_registry_names() {
        let fixture = Fixture::new();

        let (package_path, _) = fixture.package("extra", None);
        fs::write(package_path.join("governed/unreferenced.yaml"), b"x: 1\n")
            .expect("unreferenced governed file");
        reseal(&package_path);
        let message = refusal(&package_path);
        assert!(
            message.contains("extra: governed/unreferenced.yaml"),
            "{message}"
        );

        let (package_path, summary) = fixture.package("missing", None);
        let artifact = summary
            .files
            .iter()
            .find(|file| file.path.starts_with(GENERATED_PREFIX))
            .expect("generated file")
            .path
            .clone();
        fs::remove_file(package_path.join(&artifact)).expect("remove an artifact");
        reseal(&package_path);
        let message = refusal(&package_path);
        assert!(
            message.contains(&format!("missing: {artifact}")),
            "{message}"
        );
    }

    #[test]
    fn a_resealed_package_must_reproduce_its_compiled_registry_and_artifacts() {
        let fixture = Fixture::new();

        let (package_path, _) = fixture.package("forged-compiled-registry", None);
        let compiled_path = package_path.join(COMPILED_REGISTRY_PATH);
        let mut forged: CompiledRegistry =
            serde_json::from_slice(&fs::read(&compiled_path).expect("compiled Registry bytes"))
                .expect("compiled Registry parses");
        forged.registry_name = "Forged Registry semantics".into();
        fs::write(
            &compiled_path,
            canonical_compiled(&forged).expect("forged bytes"),
        )
        .expect("forged Registry writes");
        reseal(&package_path);
        let message = refusal(&package_path);
        assert!(
            message.contains(&format!("holds {COMPILED_REGISTRY_PATH}")),
            "{message}"
        );
        assert!(message.contains(PACKAGE_COMMAND), "{message}");

        let (package_path, _) = fixture.package("non-canonical-registry", None);
        let compiled_path = package_path.join(COMPILED_REGISTRY_PATH);
        let mut bytes = fs::read(&compiled_path).expect("compiled Registry bytes");
        bytes.push(b'\n');
        fs::write(&compiled_path, bytes).expect("non-canonical Registry writes");
        reseal(&package_path);
        assert!(refusal(&package_path).contains(COMPILED_REGISTRY_PATH));

        let (package_path, summary) = fixture.package("forged-artifact", None);
        let artifact = summary
            .files
            .iter()
            .find(|file| file.path.starts_with(GENERATED_PREFIX))
            .expect("generated file")
            .path
            .clone();
        let mut content = fs::read(package_path.join(&artifact)).expect("artifact bytes");
        content.extend_from_slice(b"tampered");
        fs::write(package_path.join(&artifact), content).expect("forged artifact writes");
        reseal(&package_path);
        let message = refusal(&package_path);
        assert!(message.contains(&format!("holds {artifact}")), "{message}");

        let (package_path, _) = fixture.package("forged-governed", None);
        let governed = fixture
            .registry
            .governed_files
            .first()
            .expect("governed file");
        let governed_path = format!("{GOVERNED_PREFIX}{}", governed.path);
        let mut content = fs::read(package_path.join(&governed_path)).expect("governed bytes");
        content.extend_from_slice(b"\n# tampered\n");
        fs::write(package_path.join(&governed_path), content).expect("forged governed writes");
        reseal(&package_path);
        let message = refusal(&package_path);
        assert!(
            message.contains(&format!("holds {governed_path}")),
            "{message}"
        );
    }

    #[test]
    fn inconsistent_build_inputs_are_refused() {
        let fixture = Fixture::new();
        let artifacts = &fixture.artifacts;
        let registry = &fixture.registry;
        let refused = |registry: &CompiledRegistry, artifacts: &ArtifactSet| {
            matches!(
                fixture.build(None, None, registry, artifacts),
                Err(PackageError::Verification)
            )
        };

        let mut mismatched = artifacts.clone();
        mismatched.contract_revision = "sha256:mismatched".into();
        assert!(refused(registry, &mismatched));

        let mut tampered = artifacts.clone();
        let artifact = tampered.artifacts.first_mut().expect("generated artifact");
        artifact.content.extend_from_slice(b"tampered");
        artifact.sha256 = digest(&artifact.content);
        assert!(refused(registry, &tampered));

        let mut tampered = artifacts.clone();
        let artifact = tampered.artifacts.first_mut().expect("generated artifact");
        artifact.visibility = match artifact.visibility {
            Visibility::OperatorOnly => Visibility::Public,
            Visibility::Public | Visibility::OperationBound => Visibility::OperatorOnly,
        };
        assert!(refused(registry, &tampered));

        let mut tampered = artifacts.clone();
        let binding = tampered
            .operation_bindings
            .first_mut()
            .expect("operation artifact binding");
        binding.context_path = binding.vocabulary_path.clone();
        assert!(refused(registry, &tampered));

        let mut mismatched_registry = registry.clone();
        mismatched_registry.registry_name = "Different Registry semantics".into();
        assert!(refused(&mismatched_registry, artifacts));
    }

    #[test]
    fn package_references_cannot_escape() {
        assert!(validate_relative("governance/review.yaml").is_ok());
        assert!(validate_relative("../outside.yaml").is_err());
        assert!(validate_relative("/absolute.yaml").is_err());
    }

    #[test]
    fn multi_access_profile_package_bindings_are_exactly_closed() {
        let yaml = crate::compiler::tests::valid_contract()
            .replace(
                "read:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}",
                "read:\n        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}\n          alternate: {access: public, disclosureProfile: public}\n      list:\n        defaultAccessProfile: listing\n        accessProfiles:\n          listing: {access: public, disclosureProfile: public}\n        filters: []\n        allowUnfiltered: true\n        orderBy: [name]\n        pagination: {defaultPageSize: 1, maximumPageSize: 10}",
            )
            .replace("operationRefs: [read]", "operationRefs: [read, list]");
        let contract = RegistryContract::parse_yaml(&yaml).expect("strict multi-profile contract");
        let governed = crate::compiler::tests::governed_files_for(&contract);
        let registry = compile_contract_with_governed_files(
            &contract,
            &[crate::compiler::tests::observed_schema()],
            CompileProfile::Production,
            &governed,
        )
        .expect("multi-profile Registry compiles");
        let artifacts = generate_artifacts(&registry).expect("multi-profile artifacts generate");
        let expected = operation_access_profile_pairs(&registry);
        let artifact_paths = artifacts
            .artifacts
            .iter()
            .map(|artifact| artifact.path.as_str())
            .collect::<BTreeSet<_>>();

        assert_eq!(expected.len(), 3);
        assert!(valid_operation_artifact_bindings(
            &artifacts.operation_bindings,
            &expected,
            &artifact_paths,
        ));

        let mut missing = artifacts.operation_bindings.clone();
        missing.pop();
        assert!(!valid_operation_artifact_bindings(
            &missing,
            &expected,
            &artifact_paths,
        ));

        let mut duplicate = artifacts.operation_bindings.clone();
        duplicate.push(duplicate[0].clone());
        assert!(!valid_operation_artifact_bindings(
            &duplicate,
            &expected,
            &artifact_paths,
        ));

        let mut cross_operation = artifacts.operation_bindings.clone();
        let listing_access_profile = cross_operation
            .iter()
            .find(|binding| binding.operation_identifier.ends_with(".list"))
            .expect("list binding")
            .access_profile_identifier
            .clone();
        let read_binding = cross_operation
            .iter_mut()
            .find(|binding| binding.operation_identifier.ends_with(".read"))
            .expect("read binding");
        read_binding.access_profile_identifier = listing_access_profile;
        assert!(!valid_operation_artifact_bindings(
            &cross_operation,
            &expected,
            &artifact_paths,
        ));

        let temporary = tempfile::tempdir().expect("temporary project");
        let project = temporary.path().join("project");
        fs::create_dir(&project).expect("project directory");
        fs::write(project.join("registry.yaml"), &yaml).expect("registry contract");
        for (relative, content) in &governed {
            let path = project.join(relative);
            fs::create_dir_all(path.parent().expect("governed parent"))
                .expect("governed directory");
            fs::write(path, content).expect("governed file");
        }
        let package_path = temporary.path().join("package");
        build_package(
            &project,
            Some(&package_path),
            None,
            &contract,
            &registry,
            &artifacts,
        )
        .expect("multi-profile package builds");
        let verified = load_package(
            &package_path
                .canonicalize()
                .expect("multi-profile package resolves"),
        )
        .expect("multi-profile package loads");
        assert_eq!(verified.artifacts, artifacts);
        assert_eq!(verified.artifacts.operation_bindings.len(), 3);
    }

    #[test]
    fn statistical_structure_artifacts_are_exactly_bound_in_a_package() {
        let yaml = crate::compiler::tests::statistical_contract()
            .replace(
                "    access: public\n    query:",
                "    access: {scope: statistics:read}\n    query:",
            )
            .replace(
                "statisticalDatasets: public",
                "statisticalDatasets: operation-bound",
            );
        let contract = RegistryContract::parse_yaml(&yaml).expect("protected statistics contract");
        let governed = crate::compiler::tests::governed_files_for(&contract);
        let registry = compile_contract_with_governed_files(
            &contract,
            &[crate::compiler::tests::statistical_observed_schema()],
            CompileProfile::Production,
            &governed,
        )
        .expect("protected statistics Registry compiles");
        let artifacts = generate_artifacts(&registry).expect("statistical artifacts generate");

        let temporary = tempfile::tempdir().expect("temporary project");
        let project = temporary.path().join("project");
        fs::create_dir(&project).expect("project directory");
        fs::write(project.join("registry.yaml"), &yaml).expect("registry contract");
        for (relative, content) in &governed {
            let path = project.join(relative);
            fs::create_dir_all(path.parent().expect("governed parent"))
                .expect("governed directory");
            fs::write(path, content).expect("governed file");
        }

        let package_path = temporary.path().join("package");
        build_package(
            &project,
            Some(&package_path),
            None,
            &contract,
            &registry,
            &artifacts,
        )
        .expect("statistical package builds");
        let operation_identifier = registry.statistical_datasets[0].operation_identifier();
        let record_bindings = BTreeSet::new();
        let fixed_operations = fixed_statistical_operations(&registry);
        for visibility in [Visibility::Public, Visibility::OperatorOnly] {
            assert!(valid_artifact_access_binding(
                visibility,
                Some(&operation_identifier),
                Some(&ArtifactAccessBinding::FixedOperation),
                &record_bindings,
                &fixed_operations,
            ));
        }
        for id in [
            "labour-rates-sdmx-dataflow-structure",
            "labour-rates-sdmx-datastructure-structure",
        ] {
            let packaged = artifacts
                .artifacts
                .iter()
                .find(|artifact| artifact.id == id)
                .unwrap_or_else(|| panic!("missing {id}"));
            assert_eq!(packaged.visibility, Visibility::OperationBound);
            assert_eq!(
                packaged.operation_identifier.as_deref(),
                Some(operation_identifier.as_str())
            );
            assert_eq!(
                packaged.access_binding,
                Some(ArtifactAccessBinding::FixedOperation)
            );
            assert_eq!(
                fs::read(package_path.join(GENERATED_PREFIX).join(&packaged.path))
                    .expect("packaged structure bytes"),
                packaged.content
            );
        }

        let verified = load_package(
            &package_path
                .canonicalize()
                .expect("statistical package resolves"),
        )
        .expect("statistical package loads");
        assert_eq!(verified.artifacts, artifacts);
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
            capture_governed_closure(&project, &contract, None),
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
}
