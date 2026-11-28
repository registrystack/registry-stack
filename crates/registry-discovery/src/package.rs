// SPDX-License-Identifier: Apache-2.0
//! Bounded reading of verified Discovery packages.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read as _;
use std::path::Path;

use registry_platform_config::package::is_envelope_file;
use registry_platform_config::{
    sha256_uri, PackageConfig, PackageError, PackageLimits, VerifiedPackage,
};
use thiserror::Error;

use crate::{
    parse_index, DiscoveryIndex, IndexError, INDEX_FILE, MAXIMUM_INDEX_BYTES,
    MAXIMUM_PACKAGE_BYTES, MAXIMUM_PACKAGE_DEPTH, MAXIMUM_PACKAGE_FILES, PACKAGE_COMMAND,
};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StartupError {
    /// The shared loader refused the runtime file; the message is the
    /// reader's human diagnostics, which name the file, the position, and
    /// the fix and never carry a configured value.
    #[error("the Discovery runtime configuration was refused:\n{0}")]
    RuntimeRefused(String),
    #[error("the Discovery runtime configuration is invalid")]
    RuntimeInvalid,
    #[error("{0}")]
    Package(#[from] PackageError),
    #[error(
        "the Discovery package at package.root has invalid contents{details}; rebuild it with \
         `discoveryctl package`"
    )]
    PackageContents { details: String },
    #[error(
        "the Discovery package file {path} changed after package verification; redeploy the whole \
         directory built by `discoveryctl package`"
    )]
    PackageFileChanged { path: String },
    #[error(
        "the Discovery package file discovery-index.json is invalid; rebuild the package with \
         `discoveryctl package`"
    )]
    PackageIndexInvalid,
    #[error(
        "the Discovery package contains a retired Relay service; remove Relay origins and rebuild \
         it with `discoveryctl package`"
    )]
    PackageIndexRetiredService,
    #[error(
        "the Discovery package file discovery-index.json was built before the index carried \
         apiVersion and kind; rebuild the package with `discoveryctl package`, then update \
         package.expectedDigest if you pin it"
    )]
    PackageIndexRetiredHeader,
    #[error("the Discovery index could not be loaded")]
    IndexLoad,
    #[error("the Discovery index is invalid")]
    IndexInvalid,
    #[error("the Discovery listener could not be started")]
    Listener,
    #[error("the Discovery shutdown signal failed")]
    Shutdown,
}

pub(crate) fn load_runtime_package(
    package: &PackageConfig,
) -> Result<(DiscoveryIndex, VerifiedPackage), StartupError> {
    let verified = package
        .verify_package(&package_limits(), PACKAGE_COMMAND)
        .map_err(|error| error.naming_root_as("package.root"))?;
    let index = load_verified_index(&package.root, &verified)?;
    Ok((index, verified))
}

pub fn load_index(path: &Path) -> Result<DiscoveryIndex, StartupError> {
    let bytes = bounded_regular_file(path, MAXIMUM_INDEX_BYTES)?;
    parse_index(&bytes).map_err(|_| StartupError::IndexInvalid)
}

/// The bounds for the one-index Discovery package and optional revision.
#[must_use]
pub fn package_limits() -> PackageLimits {
    PackageLimits {
        max_files: MAXIMUM_PACKAGE_FILES,
        max_file_bytes: MAXIMUM_INDEX_BYTES,
        max_total_bytes: MAXIMUM_PACKAGE_BYTES,
        max_depth: MAXIMUM_PACKAGE_DEPTH,
        ..PackageLimits::default()
    }
}

/// Capture and parse the exact index bytes named by an already verified
/// package. The second digest check binds the bytes consumed by the directory
/// to the `SHA256SUMS` entry retained in `verified`.
pub fn load_verified_index(
    root: &Path,
    verified: &VerifiedPackage,
) -> Result<DiscoveryIndex, StartupError> {
    let expected = BTreeSet::from([INDEX_FILE.to_owned()]);
    let found = verified
        .files()
        .filter(|path| !is_envelope_file(path))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if found != expected {
        let mut details = String::new();
        let missing = expected.difference(&found).cloned().collect::<Vec<_>>();
        let extra = found.difference(&expected).cloned().collect::<Vec<_>>();
        if !missing.is_empty() {
            details.push_str(&format!("; missing: {}", missing.join(", ")));
        }
        if !extra.is_empty() {
            details.push_str(&format!("; extra: {}", extra.join(", ")));
        }
        return Err(StartupError::PackageContents { details });
    }
    let path = root.join(INDEX_FILE);
    let bytes = bounded_regular_file(&path, MAXIMUM_INDEX_BYTES).map_err(|_| {
        StartupError::PackageFileChanged {
            path: INDEX_FILE.to_owned(),
        }
    })?;
    if verified.file_digest(INDEX_FILE).as_deref() != Some(sha256_uri(&bytes).as_str()) {
        return Err(StartupError::PackageFileChanged {
            path: INDEX_FILE.to_owned(),
        });
    }
    parse_index(&bytes).map_err(|error| match error {
        IndexError::RetiredServiceKind => StartupError::PackageIndexRetiredService,
        IndexError::RetiredHeader => StartupError::PackageIndexRetiredHeader,
        _ => StartupError::PackageIndexInvalid,
    })
}

fn bounded_regular_file(path: &Path, maximum: u64) -> Result<Vec<u8>, StartupError> {
    let scanned = fs::symlink_metadata(path).map_err(|_| StartupError::IndexLoad)?;
    if scanned.file_type().is_symlink()
        || !scanned.is_file()
        || scanned.len() == 0
        || scanned.len() > maximum
    {
        return Err(StartupError::IndexLoad);
    }
    let file = fs::File::open(path).map_err(|_| StartupError::IndexLoad)?;
    let opened = file.metadata().map_err(|_| StartupError::IndexLoad)?;
    let current = fs::symlink_metadata(path).map_err(|_| StartupError::IndexLoad)?;
    if current.file_type().is_symlink()
        || !current.is_file()
        || !same_file(&scanned, &opened)
        || !same_file(&opened, &current)
    {
        return Err(StartupError::IndexLoad);
    }
    read_opened_regular_file(file, &opened, maximum)
}

fn read_opened_regular_file(
    file: fs::File,
    opened: &fs::Metadata,
    maximum: u64,
) -> Result<Vec<u8>, StartupError> {
    let capacity = usize::try_from(opened.len()).map_err(|_| StartupError::IndexLoad)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve(capacity)
        .map_err(|_| StartupError::IndexLoad)?;
    let mut reader = file.take(maximum.saturating_add(1));
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| StartupError::IndexLoad)?;
    let after = reader
        .get_ref()
        .metadata()
        .map_err(|_| StartupError::IndexLoad)?;
    if bytes.is_empty()
        || u64::try_from(bytes.len()).map_or(true, |length| length > maximum)
        || !same_file(opened, &after)
        || u64::try_from(bytes.len()).ok() != Some(after.len())
    {
        return Err(StartupError::IndexLoad);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
}

#[cfg(not(unix))]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_capture_refuses_growth_beyond_the_read_limit() {
        use std::io::Write as _;

        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join(INDEX_FILE);
        fs::write(&path, b"12").unwrap();
        let file = fs::File::open(&path).unwrap();
        let opened = file.metadata().unwrap();
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"3")
            .unwrap();

        assert_eq!(
            read_opened_regular_file(file, &opened, 2),
            Err(StartupError::IndexLoad)
        );
    }
}
