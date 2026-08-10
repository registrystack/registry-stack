// SPDX-License-Identifier: Apache-2.0
//! Deterministic sealed package construction from one compiled Registry.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};

use registry_platform_canonical_json::canonicalize_json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::artifacts::{
    generate_artifacts, ArtifactAccessBinding, ArtifactSet, GeneratedArtifact,
    OperationArtifactBindings,
};
use crate::compiler::{
    compile_contract_with_governed_files, referenced_governed_files, GovernedFileSet,
};
use crate::contract::{RegistryContract, Visibility};
use crate::model::{
    CompileProfile, CompiledClassificationReview, CompiledRegistry, ObservedSourceSchema,
};

const PACKAGE_VERSION: &str = "relay.registrystack.org/package/v1alpha3";
const COMPILED_REGISTRY_PATH: &str = "compiled/registry.json";
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
    pub operation_artifact_bindings: Vec<OperationArtifactBindings>,
    pub files: Vec<PackageFile>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageArtifact {
    pub id: String,
    pub path: String,
    pub media_type: String,
    pub visibility: Visibility,
    /// Ownership is retained for operation-bound Record artifacts and every
    /// statistical structure artifact, including public or operator-only ones.
    pub operation_identifier: Option<String>,
    /// The closed ownership mechanism paired with `operation_identifier`.
    pub access_binding: Option<ArtifactAccessBinding>,
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
    let authored = capture_governed_closure(
        project_root,
        contract,
        compiled.classification_review.as_ref(),
    )?;
    let registry_bytes = read_regular(&project_root.join("registry.yaml"))?;
    let packaged_contract = RegistryContract::parse_yaml(
        std::str::from_utf8(&registry_bytes).map_err(|_| PackageError::Verification)?,
    )
    .map_err(|_| PackageError::Verification)?;
    if packaged_contract != *contract {
        return Err(PackageError::Verification);
    }
    validate_build_inputs(contract, compiled, artifacts, &authored)?;
    let mut files = Vec::new();
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
    let compiled_bytes = canonicalize_json(
        &serde_json::to_value(compiled).map_err(|_| PackageError::CanonicalJson)?,
    )
    .map_err(|_| PackageError::CanonicalJson)?;
    files.push(file_entry(
        COMPILED_REGISTRY_PATH,
        &compiled_bytes,
        "application/json",
        Visibility::OperatorOnly,
        true,
    ));
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
            access_binding: artifact.access_binding.clone(),
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
        operation_artifact_bindings: &artifacts.operation_bindings,
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
        operation_artifact_bindings: artifacts.operation_bindings.clone(),
        files,
    };
    let final_manifest = canonicalize_json(
        &serde_json::to_value(&manifest).map_err(|_| PackageError::CanonicalJson)?,
    )
    .map_err(|_| PackageError::CanonicalJson)?;
    validate_package_bounds(&manifest.files, final_manifest.len())?;

    fs::create_dir(output_dir).map_err(|_| PackageError::Write)?;
    let write_result = (|| {
        write_new_file(&output_dir.join("registry.yaml"), &registry_bytes)?;
        for (relative, content) in &authored {
            write_new_file(&output_dir.join("governed").join(relative), content)?;
        }
        write_new_file(&output_dir.join(COMPILED_REGISTRY_PATH), &compiled_bytes)?;
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

fn validate_package_bounds(
    files: &[PackageFile],
    manifest_bytes: usize,
) -> Result<(), PackageError> {
    if files.len() > MAX_PACKAGE_FILES {
        return Err(PackageError::ClosureBound);
    }
    let manifest_bytes = u64::try_from(manifest_bytes).map_err(|_| PackageError::ClosureBound)?;
    if manifest_bytes > MAX_MANIFEST_BYTES {
        return Err(PackageError::ClosureBound);
    }
    let total = files.iter().try_fold(manifest_bytes, |total, file| {
        total
            .checked_add(file.size)
            .ok_or(PackageError::ClosureBound)
    })?;
    if total > MAX_PACKAGE_BYTES {
        return Err(PackageError::ClosureBound);
    }
    Ok(())
}

fn validate_build_inputs(
    contract: &RegistryContract,
    compiled: &CompiledRegistry,
    artifacts: &ArtifactSet,
    governed: &GovernedFileSet,
) -> Result<(), PackageError> {
    if artifacts.contract_revision != compiled.contract_revision
        || compiled.contract_id != contract.metadata.id
        || compiled.contract_version != contract.metadata.version
        || compiled.registry_identifier != contract.registry.registry_identifier
    {
        return Err(PackageError::Verification);
    }
    let observed = compiled
        .sources
        .iter()
        .map(|source| {
            source
                .observed_schema
                .clone()
                .ok_or(PackageError::Verification)
        })
        .collect::<Result<Vec<_>, _>>()?;
    verify_compiled_derivation(contract, compiled, governed, &observed)?;
    verify_artifact_derivation(compiled, artifacts)?;
    let expected_operation_access_profiles = operation_access_profile_pairs(compiled);
    let expected_fixed_operations = fixed_statistical_operations(compiled);
    let mut artifact_ids = BTreeSet::new();
    let mut artifact_paths = BTreeSet::new();
    for artifact in &artifacts.artifacts {
        validate_relative(&artifact.path)?;
        if !artifact_ids.insert(artifact.id.as_str())
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
            return Err(PackageError::Verification);
        }
    }
    if !valid_operation_artifact_bindings(
        &artifacts.operation_bindings,
        &expected_operation_access_profiles,
        &artifact_paths,
    ) {
        return Err(PackageError::Verification);
    }
    Ok(())
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
    // `packageRevision` is an integrity digest, not an authenticity proof. A
    // caller can recalculate it, so acceptance must reproduce every artifact
    // byte and its release metadata from the already rederived Registry.
    let reproduced = generate_artifacts(compiled).map_err(|_| PackageError::Verification)?;
    if reproduced != *artifacts {
        return Err(PackageError::Verification);
    }
    Ok(())
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
        operation_artifact_bindings: &manifest.operation_artifact_bindings,
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

    let compiled_entry = manifest
        .files
        .iter()
        .filter(|entry| entry.path == COMPILED_REGISTRY_PATH)
        .collect::<Vec<_>>();
    if compiled_entry.len() != 1
        || !compiled_entry[0].generated
        || compiled_entry[0].visibility != Visibility::OperatorOnly
        || compiled_entry[0].media_type != "application/json"
    {
        return Err(PackageError::Verification);
    }
    let compiled_bytes = loaded
        .get(COMPILED_REGISTRY_PATH)
        .ok_or(PackageError::Verification)?;
    let compiled_value: serde_json::Value =
        serde_json::from_slice(compiled_bytes).map_err(|_| PackageError::Verification)?;
    if canonicalize_json(&compiled_value).map_err(|_| PackageError::CanonicalJson)?
        != *compiled_bytes
    {
        return Err(PackageError::Verification);
    }
    let registry: CompiledRegistry =
        serde_json::from_value(compiled_value).map_err(|_| PackageError::Verification)?;
    let reproduced_compiled = canonicalize_json(
        &serde_json::to_value(&registry).map_err(|_| PackageError::CanonicalJson)?,
    )
    .map_err(|_| PackageError::CanonicalJson)?;
    if reproduced_compiled != *compiled_bytes {
        return Err(PackageError::Verification);
    }
    if registry.contract_revision != manifest.contract_revision
        || registry.contract_id != contract.metadata.id
        || registry.contract_version != contract.metadata.version
        || registry.registry_identifier != contract.registry.registry_identifier
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

    let governed = loaded
        .iter()
        .filter_map(|(path, content)| {
            path.strip_prefix("governed/")
                .map(|relative| (relative.to_owned(), content.clone()))
        })
        .collect::<GovernedFileSet>();
    let observed = manifest
        .source_schemas
        .values()
        .cloned()
        .collect::<Vec<_>>();
    verify_compiled_derivation(&contract, &registry, &governed, &observed)?;

    let governed_paths = registry
        .governed_files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<BTreeSet<_>>();
    let loaded_governed_paths = loaded
        .keys()
        .filter_map(|path| path.strip_prefix("governed/"))
        .collect::<BTreeSet<_>>();
    if governed_paths != loaded_governed_paths
        || registry.governed_files.iter().any(|file| {
            loaded
                .get(&format!("governed/{}", file.path))
                .is_none_or(|content| digest(content) != file.sha256)
        })
    {
        return Err(PackageError::Verification);
    }

    let expected_operation_access_profiles = operation_access_profile_pairs(&registry);
    let expected_fixed_operations = fixed_statistical_operations(&registry);
    let mut artifact_ids = BTreeSet::new();
    let mut artifact_paths = BTreeSet::new();
    let mut generated_artifacts = Vec::with_capacity(manifest.artifacts.len());
    for artifact in &manifest.artifacts {
        let relative_path = artifact
            .path
            .strip_prefix("generated/")
            .ok_or(PackageError::Verification)?;
        if relative_path.is_empty()
            || !artifact_ids.insert(artifact.id.as_str())
            || !artifact_paths.insert(relative_path)
            || !valid_artifact_access_binding(
                artifact.visibility,
                artifact.operation_identifier.as_deref(),
                artifact.access_binding.as_ref(),
                &expected_operation_access_profiles,
                &expected_fixed_operations,
            )
        {
            return Err(PackageError::Verification);
        }
        let file_entries = manifest
            .files
            .iter()
            .filter(|entry| entry.path == artifact.path)
            .collect::<Vec<_>>();
        if file_entries.len() != 1
            || !file_entries[0].generated
            || file_entries[0].media_type != artifact.media_type
            || file_entries[0].visibility != artifact.visibility
            || file_entries[0].sha256 != artifact.sha256
        {
            return Err(PackageError::Verification);
        }
        let content = loaded
            .get(&artifact.path)
            .ok_or(PackageError::Verification)?
            .clone();
        generated_artifacts.push(GeneratedArtifact {
            id: artifact.id.clone(),
            path: relative_path.to_owned(),
            media_type: artifact.media_type.clone(),
            visibility: artifact.visibility,
            operation_identifier: artifact.operation_identifier.clone(),
            access_binding: artifact.access_binding.clone(),
            sha256: artifact.sha256.clone(),
            content,
        });
    }
    let loaded_generated_paths = loaded
        .keys()
        .filter_map(|path| path.strip_prefix("generated/"))
        .collect::<BTreeSet<_>>();
    if artifact_paths != loaded_generated_paths
        || !valid_operation_artifact_bindings(
            &manifest.operation_artifact_bindings,
            &expected_operation_access_profiles,
            &artifact_paths,
        )
    {
        return Err(PackageError::Verification);
    }
    let artifacts = ArtifactSet {
        contract_revision: registry.contract_revision.clone(),
        artifacts: generated_artifacts,
        operation_bindings: manifest.operation_artifact_bindings.clone(),
    };
    verify_artifact_derivation(&registry, &artifacts)?;
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
    operation_artifact_bindings: &'a [OperationArtifactBindings],
    files: &'a [PackageFile],
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

    fn bounded_file(size: u64) -> PackageFile {
        PackageFile {
            path: "bounded-fixture".into(),
            size,
            sha256: digest(b""),
            media_type: "application/octet-stream".into(),
            visibility: Visibility::OperatorOnly,
            generated: true,
        }
    }

    #[test]
    fn package_file_count_bound_matches_the_loader() {
        let files = vec![bounded_file(0); MAX_PACKAGE_FILES];
        assert!(validate_package_bounds(&files, 1).is_ok());

        let files = vec![bounded_file(0); MAX_PACKAGE_FILES + 1];
        assert!(matches!(
            validate_package_bounds(&files, 1),
            Err(PackageError::ClosureBound)
        ));
    }

    #[test]
    fn package_manifest_byte_bound_matches_the_loader() {
        let files = [bounded_file(0)];
        assert!(validate_package_bounds(
            &files,
            usize::try_from(MAX_MANIFEST_BYTES).expect("manifest cap fits usize")
        )
        .is_ok());
        assert!(matches!(
            validate_package_bounds(
                &files,
                usize::try_from(MAX_MANIFEST_BYTES + 1).expect("manifest cap plus one fits usize")
            ),
            Err(PackageError::ClosureBound)
        ));
    }

    #[test]
    fn package_total_byte_bound_matches_the_loader() {
        let at_cap = [bounded_file(MAX_PACKAGE_BYTES - 1)];
        assert!(validate_package_bounds(&at_cap, 1).is_ok());

        let above_cap = [bounded_file(MAX_PACKAGE_BYTES)];
        assert!(matches!(
            validate_package_bounds(&above_cap, 1),
            Err(PackageError::ClosureBound)
        ));
    }

    fn reseal_manifest(package_path: &Path, manifest: &mut PackageManifest) {
        let unsigned = UnsignedManifest {
            package_version: PACKAGE_VERSION,
            contract_revision: &manifest.contract_revision,
            source_schema_fingerprints: &manifest.source_schema_fingerprints,
            source_schemas: &manifest.source_schemas,
            artifacts: &manifest.artifacts,
            operation_artifact_bindings: &manifest.operation_artifact_bindings,
            files: &manifest.files,
        };
        let unsigned_bytes = canonicalize_json(
            &serde_json::to_value(unsigned).expect("unsigned manifest serializes"),
        )
        .expect("unsigned manifest canonicalizes");
        manifest.package_revision = digest(&unsigned_bytes);
        let manifest_bytes =
            canonicalize_json(&serde_json::to_value(manifest).expect("sealed manifest serializes"))
                .expect("sealed manifest canonicalizes");
        fs::write(package_path.join("relay-package.json"), manifest_bytes)
            .expect("forged manifest writes");
    }

    fn assert_resealed_package_rejected(
        root: &Path,
        project: &Path,
        name: &str,
        contract: &RegistryContract,
        registry: &CompiledRegistry,
        artifacts: &ArtifactSet,
        mutate: impl FnOnce(&Path, &mut PackageManifest),
    ) {
        let package_path = root.join(name);
        let mut manifest = build_package(project, &package_path, contract, registry, artifacts)
            .expect("forgery fixture");
        mutate(&package_path, &mut manifest);
        reseal_manifest(&package_path, &mut manifest);
        assert!(matches!(
            load_package(
                &package_path
                    .canonicalize()
                    .expect("forged package resolves")
            ),
            Err(PackageError::Verification)
        ));
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
        let manifest = build_package(&project, &package_path, &contract, &registry, &artifacts)
            .expect("multi-profile package builds");
        let verified = load_package(
            &package_path
                .canonicalize()
                .expect("multi-profile package resolves"),
        )
        .expect("multi-profile package loads");
        assert_eq!(verified.manifest, manifest);
        assert_eq!(verified.artifacts.operation_bindings.len(), 3);
    }

    #[test]
    fn statistical_structure_artifacts_are_exactly_bound_in_v1alpha3_package() {
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
        let manifest = build_package(&project, &package_path, &contract, &registry, &artifacts)
            .expect("statistical package builds");
        assert_eq!(manifest.package_version, PACKAGE_VERSION);
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
            let packaged = manifest
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
            let generated = artifacts
                .artifacts
                .iter()
                .find(|artifact| artifact.id == id)
                .expect("generated structure artifact");
            assert_eq!(
                fs::read(package_path.join(&packaged.path)).expect("packaged structure bytes"),
                generated.content
            );
        }
        let manifest_value = serde_json::to_value(&manifest).expect("manifest serializes");
        assert!(manifest_value["artifacts"]
            .as_array()
            .expect("package artifacts")
            .iter()
            .filter(|artifact| {
                artifact["id"] == "labour-rates-sdmx-dataflow-structure"
                    || artifact["id"] == "labour-rates-sdmx-datastructure-structure"
            })
            .all(|artifact| artifact.get("accessProfileIdentifier").is_none()));

        let verified = load_package(
            &package_path
                .canonicalize()
                .expect("statistical package resolves"),
        )
        .expect("statistical package loads");
        assert_eq!(verified.manifest, manifest);
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
        let mut mismatched_artifacts = artifacts.clone();
        mismatched_artifacts.contract_revision = "sha256:mismatched".into();
        assert!(matches!(
            build_package(
                &project,
                &temporary.path().join("rejected-package"),
                &contract,
                &registry,
                &mismatched_artifacts,
            ),
            Err(PackageError::Verification)
        ));
        let mut tampered_artifact_bytes = artifacts.clone();
        let tampered_artifact = tampered_artifact_bytes
            .artifacts
            .first_mut()
            .expect("generated artifact");
        tampered_artifact.content.extend_from_slice(b"tampered");
        tampered_artifact.sha256 = digest(&tampered_artifact.content);
        assert!(matches!(
            build_package(
                &project,
                &temporary.path().join("rejected-artifact-bytes"),
                &contract,
                &registry,
                &tampered_artifact_bytes,
            ),
            Err(PackageError::Verification)
        ));
        let mut tampered_artifact_visibility = artifacts.clone();
        let tampered_artifact = tampered_artifact_visibility
            .artifacts
            .first_mut()
            .expect("generated artifact");
        tampered_artifact.visibility = match tampered_artifact.visibility {
            Visibility::OperatorOnly => Visibility::Public,
            Visibility::Public | Visibility::OperationBound => Visibility::OperatorOnly,
        };
        assert!(matches!(
            build_package(
                &project,
                &temporary.path().join("rejected-artifact-visibility"),
                &contract,
                &registry,
                &tampered_artifact_visibility,
            ),
            Err(PackageError::Verification)
        ));
        let mut tampered_artifact_binding = artifacts.clone();
        let binding = tampered_artifact_binding
            .operation_bindings
            .first_mut()
            .expect("operation artifact binding");
        binding.context_path = binding.vocabulary_path.clone();
        assert!(matches!(
            build_package(
                &project,
                &temporary.path().join("rejected-artifact-binding"),
                &contract,
                &registry,
                &tampered_artifact_binding,
            ),
            Err(PackageError::Verification)
        ));
        let mut mismatched_registry = registry.clone();
        mismatched_registry.registry_name = "Different Registry semantics".into();
        assert!(matches!(
            build_package(
                &project,
                &temporary.path().join("rejected-compiled-registry"),
                &contract,
                &mismatched_registry,
                &artifacts,
            ),
            Err(PackageError::Verification)
        ));
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
        assert_eq!(verified.artifacts, artifacts);
        assert!(manifest
            .files
            .iter()
            .any(|file| file.path == COMPILED_REGISTRY_PATH));
        assert_eq!(
            manifest.operation_artifact_bindings,
            artifacts.operation_bindings
        );
        let serialized_manifest = serde_json::to_value(&manifest).expect("manifest serializes");
        assert!(serialized_manifest["artifacts"]
            .as_array()
            .expect("artifact array")
            .iter()
            .filter(|artifact| artifact["operationIdentifier"].is_string())
            .all(|artifact| artifact.get("accessBinding").is_some()
                && artifact.get("accessProfileIdentifier").is_none()
                && artifact.get("representationIdentifier").is_none()));

        assert_resealed_package_rejected(
            temporary.path(),
            &project,
            "forged-compiled-registry",
            &contract,
            &registry,
            &artifacts,
            |package_path, manifest| {
                let compiled_path = package_path.join(COMPILED_REGISTRY_PATH);
                let mut forged: CompiledRegistry = serde_json::from_slice(
                    &fs::read(&compiled_path).expect("compiled Registry bytes"),
                )
                .expect("compiled Registry parses");
                forged.registry_name = "Forged Registry semantics".into();
                let forged_bytes = canonicalize_json(
                    &serde_json::to_value(forged).expect("forged Registry serializes"),
                )
                .expect("forged Registry canonicalizes");
                fs::write(&compiled_path, &forged_bytes).expect("forged Registry writes");
                let file = manifest
                    .files
                    .iter_mut()
                    .find(|file| file.path == COMPILED_REGISTRY_PATH)
                    .expect("compiled Registry package file");
                file.size = forged_bytes.len() as u64;
                file.sha256 = digest(&forged_bytes);
            },
        );
        assert_resealed_package_rejected(
            temporary.path(),
            &project,
            "forged-artifact-content",
            &contract,
            &registry,
            &artifacts,
            |package_path, manifest| {
                let artifact = manifest.artifacts.first_mut().expect("generated artifact");
                let file_path = artifact.path.clone();
                let mut content = fs::read(package_path.join(&file_path)).expect("artifact bytes");
                content.extend_from_slice(b"tampered");
                fs::write(package_path.join(&file_path), &content).expect("forged artifact bytes");
                let content_digest = digest(&content);
                artifact.sha256 = content_digest.clone();
                let file = manifest
                    .files
                    .iter_mut()
                    .find(|file| file.path == file_path)
                    .expect("generated package file");
                file.size = content.len() as u64;
                file.sha256 = content_digest;
            },
        );
        assert_resealed_package_rejected(
            temporary.path(),
            &project,
            "forged-artifact-visibility",
            &contract,
            &registry,
            &artifacts,
            |_package_path, manifest| {
                let artifact = manifest.artifacts.first_mut().expect("generated artifact");
                let file_path = artifact.path.clone();
                let visibility = match artifact.visibility {
                    Visibility::OperatorOnly => Visibility::Public,
                    Visibility::Public | Visibility::OperationBound => Visibility::OperatorOnly,
                };
                artifact.visibility = visibility;
                manifest
                    .files
                    .iter_mut()
                    .find(|file| file.path == file_path)
                    .expect("generated package file")
                    .visibility = visibility;
            },
        );
        assert_resealed_package_rejected(
            temporary.path(),
            &project,
            "forged-swapped-binding",
            &contract,
            &registry,
            &artifacts,
            |_package_path, manifest| {
                let binding = manifest
                    .operation_artifact_bindings
                    .first_mut()
                    .expect("operation artifact binding");
                let vocabulary_path = binding.vocabulary_path.clone();
                binding.vocabulary_path = binding.context_path.clone();
                binding.context_path = vocabulary_path;
            },
        );
        assert_resealed_package_rejected(
            temporary.path(),
            &project,
            "forged-repeated-binding",
            &contract,
            &registry,
            &artifacts,
            |_package_path, manifest| {
                let binding = manifest
                    .operation_artifact_bindings
                    .first_mut()
                    .expect("operation artifact binding");
                binding.context_path = binding.vocabulary_path.clone();
            },
        );

        let compiled_path = output.join(COMPILED_REGISTRY_PATH);
        let compiled_bytes = fs::read(&compiled_path).expect("compiled Registry bytes");
        fs::write(&compiled_path, b"{}").expect("tamper compiled Registry");
        assert!(load_package(&resolved_output).is_err());
        fs::write(&compiled_path, compiled_bytes).expect("restore compiled Registry");

        let artifact = &manifest.artifacts[0];
        fs::write(output.join(&artifact.path), b"tampered").expect("tamper fixture");
        assert!(load_package(&resolved_output).is_err());
    }
}
