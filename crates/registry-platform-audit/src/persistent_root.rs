// SPDX-License-Identifier: Apache-2.0
//! Containment proof for an operator-declared persistent audit root.

use std::path::{Component, Path, PathBuf};

use thiserror::Error;

/// Why a configured audit destination could not be proven to resolve inside an
/// operator-declared persistent root.
///
/// Messages stay value free so operators can act on a failure without a
/// deployment leaking configured locations into shared logs.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum PersistentRootFault {
    /// The declared root is not an existing absolute directory.
    #[error("the declared audit root is not an existing absolute directory")]
    Root,
    /// The configured destination could not be resolved to a real location.
    #[error("the configured audit destination could not be resolved")]
    Destination,
    /// The configured destination resolves outside the declared root.
    #[error("the configured audit destination resolves outside the declared audit root")]
    Outside,
}

/// Proves that `destination` resolves at or below `root` after realpath-style
/// canonicalization of both sides.
///
/// The caller supplies the destination its own configuration contract already
/// resolved, and the operator supplies the root that storage is declared
/// persistent under. A destination that is not absolute is refused rather than
/// resolved here, because only the caller knows what it resolves against.
/// Symlinks are followed before the comparison so a link planted inside the
/// root cannot redirect the audit chain onto ephemeral storage. Any resolution
/// error fails closed.
pub fn require_audit_under(destination: &Path, root: &Path) -> Result<(), PersistentRootFault> {
    let root = canonical_root(root)?;
    let destination = canonical_destination(destination)?;
    if destination == root || destination.starts_with(&root) {
        Ok(())
    } else {
        Err(PersistentRootFault::Outside)
    }
}

/// Canonicalizes the declared root, which must already exist as a directory.
fn canonical_root(root: &Path) -> Result<PathBuf, PersistentRootFault> {
    if !root.is_absolute() {
        return Err(PersistentRootFault::Root);
    }
    let canonical = root.canonicalize().map_err(|_| PersistentRootFault::Root)?;
    if !canonical.is_dir() {
        return Err(PersistentRootFault::Root);
    }
    Ok(canonical)
}

/// Resolves the destination as far as the filesystem allows.
///
/// The sink file and its directories are commonly created on first write, so
/// the deepest existing ancestor is canonicalized and the remaining components
/// are appended. Those components are rejected unless they can only descend.
fn canonical_destination(destination: &Path) -> Result<PathBuf, PersistentRootFault> {
    // Resolving a relative destination would mean guessing a base directory
    // that belongs to the caller's configuration contract. An empty path is
    // not absolute either, so the same rule refuses it.
    if !destination.is_absolute() {
        return Err(PersistentRootFault::Destination);
    }

    let mut descending = PathBuf::new();
    for component in destination.components() {
        match component {
            // `Components` already drops interior `.`; `..` would let the tail
            // climb back out of the root after canonicalization.
            Component::ParentDir | Component::CurDir => {
                return Err(PersistentRootFault::Destination)
            }
            other => descending.push(other.as_os_str()),
        }
    }

    let existing = descending
        .ancestors()
        // `symlink_metadata` does not follow the final link, so a dangling
        // symlink counts as existing and then fails canonicalization below.
        .find(|candidate| candidate.symlink_metadata().is_ok())
        .ok_or(PersistentRootFault::Destination)?;
    let tail = descending
        .strip_prefix(existing)
        .map_err(|_| PersistentRootFault::Destination)?;
    let canonical = existing
        .canonicalize()
        .map_err(|_| PersistentRootFault::Destination)?;
    Ok(canonical.join(tail))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::Path};
    use tempfile::tempdir;

    #[test]
    fn a_destination_under_the_declared_root_is_accepted() {
        let root = tempdir().expect("temporary root");
        let destination = root.path().join("segments").join("audit.jsonl");

        assert_eq!(Ok(()), require_audit_under(&destination, root.path()));
    }

    #[test]
    fn the_declared_root_itself_is_accepted() {
        let root = tempdir().expect("temporary root");

        assert_eq!(Ok(()), require_audit_under(root.path(), root.path()));
    }

    #[test]
    fn a_destination_outside_the_declared_root_is_refused() {
        let root = tempdir().expect("temporary root");
        let elsewhere = tempdir().expect("temporary ephemeral directory");
        let destination = elsewhere.path().join("audit.jsonl");

        assert_eq!(
            Err(PersistentRootFault::Outside),
            require_audit_under(&destination, root.path())
        );
    }

    #[test]
    fn a_sibling_sharing_a_name_prefix_is_refused() {
        let parent = tempdir().expect("temporary parent");
        let root = parent.path().join("audit");
        let sibling = parent.path().join("audit-decoy");
        fs::create_dir(&root).expect("declared root");
        fs::create_dir(&sibling).expect("sibling directory");

        assert_eq!(
            Err(PersistentRootFault::Outside),
            require_audit_under(&sibling.join("audit.jsonl"), &root)
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_inside_the_root_cannot_escape_it() {
        let root = tempdir().expect("temporary root");
        let ephemeral = tempdir().expect("temporary ephemeral directory");
        let destination = root.path().join("audit.jsonl");
        fs::write(ephemeral.path().join("audit.jsonl"), b"").expect("ephemeral sink");
        std::os::unix::fs::symlink(ephemeral.path().join("audit.jsonl"), &destination)
            .expect("escaping symlink");

        assert_eq!(
            Err(PersistentRootFault::Outside),
            require_audit_under(&destination, root.path())
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_parent_directory_cannot_escape_the_root() {
        let root = tempdir().expect("temporary root");
        let ephemeral = tempdir().expect("temporary ephemeral directory");
        let segments = root.path().join("segments");
        std::os::unix::fs::symlink(ephemeral.path(), &segments).expect("escaping symlink");

        assert_eq!(
            Err(PersistentRootFault::Outside),
            require_audit_under(&segments.join("audit.jsonl"), root.path())
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_fails_closed() {
        let root = tempdir().expect("temporary root");
        let destination = root.path().join("audit.jsonl");
        std::os::unix::fs::symlink(root.path().join("missing"), &destination)
            .expect("dangling symlink");

        assert_eq!(
            Err(PersistentRootFault::Destination),
            require_audit_under(&destination, root.path())
        );
    }

    #[test]
    fn a_parent_traversal_component_is_refused() {
        let root = tempdir().expect("temporary root");
        let destination = root.path().join("..").join("audit.jsonl");

        assert_eq!(
            Err(PersistentRootFault::Destination),
            require_audit_under(&destination, root.path())
        );
    }

    #[test]
    fn an_empty_destination_is_refused() {
        let root = tempdir().expect("temporary root");

        assert_eq!(
            Err(PersistentRootFault::Destination),
            require_audit_under(Path::new(""), root.path())
        );
    }

    #[test]
    fn a_relative_destination_is_refused() {
        let root = tempdir().expect("temporary root");

        assert_eq!(
            Err(PersistentRootFault::Destination),
            require_audit_under(Path::new("audit.jsonl"), root.path())
        );
    }

    #[test]
    fn a_relative_declared_root_is_refused() {
        assert_eq!(
            Err(PersistentRootFault::Root),
            require_audit_under(
                Path::new("/var/lib/registry/audit.jsonl"),
                Path::new("var/lib")
            )
        );
    }

    #[test]
    fn a_missing_declared_root_is_refused() {
        let root = tempdir().expect("temporary root");
        let missing = root.path().join("missing");

        assert_eq!(
            Err(PersistentRootFault::Root),
            require_audit_under(&missing.join("audit.jsonl"), &missing)
        );
    }

    #[test]
    fn a_declared_root_that_is_not_a_directory_is_refused() {
        let root = tempdir().expect("temporary root");
        let file = root.path().join("audit.jsonl");
        fs::write(&file, b"").expect("regular file");

        assert_eq!(
            Err(PersistentRootFault::Root),
            require_audit_under(&file, &file)
        );
    }

    #[test]
    fn faults_describe_the_failure_without_naming_a_path() {
        for fault in [
            PersistentRootFault::Root,
            PersistentRootFault::Destination,
            PersistentRootFault::Outside,
        ] {
            let message = fault.to_string();
            assert!(
                !message.contains('/'),
                "fault message names a path: {message}"
            );
            assert!(!message.is_empty());
        }
    }
}
