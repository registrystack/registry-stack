// SPDX-License-Identifier: Apache-2.0
//! Containment: the single answer to "may the server open this path?".
//!
//! Every document family the server indexes reads files an author placed under a project root,
//! and every one of them meets the same hazard: a path that reads as if it sits inside the root
//! while resolving somewhere else. A `..` component, an absolute path, and a symbolic link at any
//! depth all lead out the same way, and a link planted in a checked-out repository is the cheapest
//! way to make an editor read a file its author never opened. One implementation answers the
//! question for every family, because a second one drifts from this one exactly where the drift is
//! hardest to see.

use std::{
    fs,
    path::{Component, Path},
};

use anyhow::{Context, Result};

/// Whether a path under `root` is a directory the server may descend into.
pub(crate) fn secure_directory(root: &Path, path: &Path) -> Result<bool> {
    Ok(secure_path_metadata(root, path)?.is_some_and(|metadata| metadata.is_dir()))
}

/// The metadata of a path under `root` that is a regular file the server may read, if it is one.
pub(crate) fn secure_regular_file(root: &Path, path: &Path) -> Result<Option<fs::Metadata>> {
    Ok(secure_path_metadata(root, path)?.filter(|metadata| metadata.file_type().is_file()))
}

/// Whether a path names a regular file the server may read from `root`. Errors read as "no": a
/// path the server cannot prove contained is a path it does not open.
pub(crate) fn is_safe_authored_file(root: &Path, path: &Path) -> bool {
    secure_regular_file(root, path).is_ok_and(|metadata| metadata.is_some())
}

/// Whether a path is a regular file, following nothing to decide it.
///
/// This is the question asked of a name before a root exists to contain it, so it cannot go through
/// the walk above. A path that is itself a symbolic link is not a plain file, whatever it points
/// at: a link is how a directory borrows a shape it does not have, and a borrowed shape must not
/// declare a project root that the server will then read files from.
pub(crate) fn plain_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
}

/// Whether a path is a directory, following nothing to decide it, for the same reason.
pub(crate) fn plain_directory(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_dir())
}

/// The metadata of `path`, but only once the walk from `root` down to it has proved that every
/// layer is an ordinary directory entry and that the result still resolves inside `root`.
fn secure_path_metadata(root: &Path, path: &Path) -> Result<Option<fs::Metadata>> {
    let Ok(relative) = path.strip_prefix(root) else {
        return Ok(None);
    };
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Ok(None);
    }

    let mut candidate = root.to_path_buf();
    let mut metadata = fs::symlink_metadata(root)
        .with_context(|| format!("failed to inspect project root {}", root.display()))?;
    for component in relative.components() {
        candidate.push(component.as_os_str());
        metadata = match fs::symlink_metadata(&candidate) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("failed to inspect a project path"),
        };
        if metadata.file_type().is_symlink() {
            return Ok(None);
        }
    }

    let canonical = candidate
        .canonicalize()
        .context("failed to prove project path containment")?;
    if !canonical.starts_with(root) || canonical != candidate {
        return Ok(None);
    }
    Ok(Some(metadata))
}
