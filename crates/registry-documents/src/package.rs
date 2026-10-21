// SPDX-License-Identifier: Apache-2.0

//! The deployed package: one `documents.yaml`, verified against its
//! `SHA256SUMS` and the digest the runtime document pins, then decoded and
//! held to the deployment's storage ceiling.

use std::path::Path;

use registry_documents_core::DocumentsProject;
use registry_platform_config::package::is_envelope_file;
use registry_platform_config::{
    sha256_uri, PackageDigestMismatch, PackageError, PackageErrorKind, PackageLimits,
    VerifiedPackage,
};
use registry_platform_yaml::Report;
use thiserror::Error;

use crate::config::RuntimeConfig;

pub use registry_documents_core::PROJECT_FILE;

/// How an operator builds a package by hand: there is no packaging verb yet.
pub const PACKAGE_COMMAND: &str = "sha256sum documents.yaml > SHA256SUMS";

/// The largest `documents.yaml` a package may hold.
pub const MAXIMUM_PROJECT_FILE_BYTES: usize = 1024 * 1024;

#[must_use]
pub fn package_limits() -> PackageLimits {
    PackageLimits {
        max_file_bytes: MAXIMUM_PROJECT_FILE_BYTES as u64,
        ..PackageLimits::default()
    }
}

/// Why the deployed package was refused.
#[derive(Debug, Error)]
pub enum PackageLoadError {
    #[error("{0}")]
    Digest(PackageDigestMismatch),
    #[error("{0}")]
    Package(PackageError),
    #[error("the package at package.root must hold exactly {PROJECT_FILE} besides SHA256SUMS and REVISION; build it with `{PACKAGE_COMMAND}`")]
    Contents,
    #[error("{PROJECT_FILE} in the package at package.root changed after it was verified; deploy the whole package again")]
    FileChanged,
    #[error("{PROJECT_FILE} in the package at package.root was refused\n{}", .0.render_human().trim_end())]
    Project(Report),
    #[error("documentPolicies.{policy}.mandatoryRestrictions.maximumDocumentBytes is above storage.maximumDocumentBytes; lower the policy maximum or raise the deployment ceiling")]
    PolicyAboveCeiling { policy: String },
}

impl PackageLoadError {
    /// The stable refusal code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Digest(_) => "documents.package.digest-mismatch",
            Self::Package(_) => "documents.package.invalid",
            Self::Contents => "documents.package.unexpected-contents",
            Self::FileChanged => "documents.package.file-changed",
            Self::Project(_) => "documents.package.project-refused",
            Self::PolicyAboveCeiling { .. } => "documents.package.policy-above-ceiling",
        }
    }

    /// The runtime-document member the refusal concerns, as a JSON pointer.
    #[must_use]
    pub const fn pointer(&self) -> &'static str {
        match self {
            Self::Digest(_) => "/package/expectedDigest",
            Self::PolicyAboveCeiling { .. } => "/storage/maximumDocumentBytes",
            Self::Package(_) | Self::Contents | Self::FileChanged | Self::Project(_) => {
                "/package/root"
            }
        }
    }
}

/// The project a verified package holds, and the package digest.
#[derive(Debug)]
pub struct LoadedPackage {
    pub digest: String,
    pub project: DocumentsProject,
}

/// Verify the package `config` names, decode its project, and refuse any
/// policy whose maximum document size is above the deployment ceiling.
pub fn load_package(config: &RuntimeConfig) -> Result<LoadedPackage, PackageLoadError> {
    let verified = config
        .package
        .verify_package(&package_limits(), PACKAGE_COMMAND)
        .map_err(|error| match error.kind() {
            PackageErrorKind::DigestMismatch(mismatch) => {
                PackageLoadError::Digest(mismatch.clone())
            }
            _ => PackageLoadError::Package(error.naming_root_as("package.root")),
        })?;
    let listed = verified
        .files()
        .filter(|path| !is_envelope_file(path))
        .collect::<Vec<_>>();
    if listed != [PROJECT_FILE] {
        return Err(PackageLoadError::Contents);
    }
    let bytes = capture_verified_file(&config.package.root, &verified)?;
    let project = DocumentsProject::decode(PROJECT_FILE, &bytes)
        .map_err(PackageLoadError::Project)?
        .value;
    let ceiling = config.storage.maximum_document_bytes();
    if let Some((policy, _)) = project
        .document_policies
        .iter()
        .find(|(_, policy)| policy.mandatory_restrictions.maximum_document_bytes.get() > ceiling)
    {
        return Err(PackageLoadError::PolicyAboveCeiling {
            policy: policy.to_string(),
        });
    }
    Ok(LoadedPackage {
        digest: verified.digest().to_owned(),
        project,
    })
}

/// The project file's bytes, read again and held to the digest the package
/// verification recorded, so a file swapped after verification is refused.
fn capture_verified_file(
    root: &Path,
    verified: &VerifiedPackage,
) -> Result<Vec<u8>, PackageLoadError> {
    let path = root.join(PROJECT_FILE);
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| PackageLoadError::FileChanged)?;
    if !metadata.file_type().is_file() || metadata.len() > MAXIMUM_PROJECT_FILE_BYTES as u64 {
        return Err(PackageLoadError::FileChanged);
    }
    let bytes = std::fs::read(&path).map_err(|_| PackageLoadError::FileChanged)?;
    if verified.file_digest(PROJECT_FILE).as_deref() != Some(sha256_uri(&bytes).as_str()) {
        return Err(PackageLoadError::FileChanged);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use registry_platform_config::write_package;

    use super::*;

    pub(crate) const STARTER_PROJECT: &str =
        include_str!("../../../products/documents/examples/starter/documents.yaml");

    fn runtime_with(package: &Path, expected_digest: Option<&str>, storage: &str) -> RuntimeConfig {
        let mut text = crate::config::tests::STARTER_RUNTIME.to_owned();
        let start = text.find("package:\n").expect("a package block");
        let end = start
            + text[start..]
                .find("\nlistener:")
                .expect("the listener block");
        let mut block = format!("package:\n  root: {}\n", package.display());
        if let Some(digest) = expected_digest {
            block.push_str(&format!("  expectedDigest: \"{digest}\"\n"));
        }
        text.replace_range(start..=end, &block);
        let start = text.find("storage:\n").expect("a storage block");
        let end = start
            + text[start..]
                .find("\ncontentVerification:")
                .expect("the verifier block");
        text.replace_range(start..=end, storage);
        let directory = package.parent().expect("a parent directory");
        let path = directory.join("runtime.yaml");
        std::fs::write(&path, text).unwrap();
        RuntimeConfig::loader()
            .load::<RuntimeConfig>(&path)
            .unwrap_or_else(|error| panic!("the runtime document loads: {error}"))
            .config
    }

    fn write(package: &Path, files: BTreeMap<String, Vec<u8>>) {
        write_package(package, &files, None, &package_limits(), PACKAGE_COMMAND).unwrap();
    }

    const DATABASE_STORAGE: &str = "storage:\n  type: database\n";

    #[test]
    fn the_starter_package_loads() {
        let temp =
            tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
        let package = temp.path().join("package");
        write(
            &package,
            BTreeMap::from([(PROJECT_FILE.to_owned(), STARTER_PROJECT.as_bytes().to_vec())]),
        );
        let loaded = load_package(&runtime_with(&package, None, DATABASE_STORAGE)).unwrap();
        assert_eq!(loaded.project.document_policies.len(), 3);
        assert!(loaded.digest.starts_with("sha256:"));
    }

    #[test]
    fn a_package_digest_mismatch_is_refused_in_the_shared_shape() {
        let temp =
            tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
        let package = temp.path().join("package");
        write(
            &package,
            BTreeMap::from([(PROJECT_FILE.to_owned(), STARTER_PROJECT.as_bytes().to_vec())]),
        );
        let found = sha256_uri(&std::fs::read(package.join("SHA256SUMS")).unwrap());
        let expected = format!("sha256:{}", "0".repeat(64));
        assert_ne!(expected, found);
        let error =
            load_package(&runtime_with(&package, Some(&expected), DATABASE_STORAGE)).unwrap_err();
        assert_eq!(error.code(), "documents.package.digest-mismatch");
        assert_eq!(error.pointer(), "/package/expectedDigest");
        assert_eq!(
            error.to_string(),
            format!(
                "package.expectedDigest is {expected} but the package at package.root is {found}; \
                 deploy the pinned package or update package.expectedDigest"
            )
        );
    }

    #[test]
    fn a_package_with_another_file_is_refused() {
        let temp =
            tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
        let package = temp.path().join("package");
        write(
            &package,
            BTreeMap::from([
                (PROJECT_FILE.to_owned(), STARTER_PROJECT.as_bytes().to_vec()),
                ("extra.yaml".to_owned(), b"x: 1\n".to_vec()),
            ]),
        );
        let error = load_package(&runtime_with(&package, None, DATABASE_STORAGE)).unwrap_err();
        assert_eq!(error.code(), "documents.package.unexpected-contents");
    }

    #[test]
    fn a_policy_above_the_deployment_ceiling_is_refused_at_startup() {
        let temp =
            tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
        let package = temp.path().join("package");
        write(
            &package,
            BTreeMap::from([(PROJECT_FILE.to_owned(), STARTER_PROJECT.as_bytes().to_vec())]),
        );
        let lowered = "storage:\n  type: database\n  maximumDocumentBytes: 1048576\n";
        let error = load_package(&runtime_with(&package, None, lowered)).unwrap_err();
        assert_eq!(error.code(), "documents.package.policy-above-ceiling");
        assert_eq!(error.pointer(), "/storage/maximumDocumentBytes");
        assert!(error
            .to_string()
            .contains("documentPolicies.citizen-delivery."));
    }
}
