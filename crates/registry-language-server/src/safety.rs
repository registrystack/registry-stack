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
    io::{self, Read as _},
    path::{Component, Path},
};

use anyhow::{Context, Result};

/// Whether a path under `root` is a directory the server may descend into.
pub(crate) fn secure_directory(root: &Path, path: &Path) -> Result<bool> {
    Ok(secure_path_metadata(root, path)?.is_some_and(|metadata| metadata.is_dir()))
}

/// A path under `root` opened as a regular file the server may read, if it is one.
pub(crate) fn secure_regular_file(root: &Path, path: &Path) -> Result<Option<SecureRegularFile>> {
    open_secure_regular_file(root, path)
}

/// A regular, singly linked file opened without following any name in its path.
///
/// The descriptor stays attached to the decision that admitted it. Reading through this value is
/// what prevents a path checked as one file from being replaced with another before the bytes are
/// read.
pub(crate) struct SecureRegularFile {
    file: fs::File,
    metadata: fs::Metadata,
}

impl SecureRegularFile {
    /// Read no more than `maximum_bytes` from this same descriptor.
    ///
    /// The metadata check avoids paying to read a file already known to be too large. The bounded
    /// read is still required because an authored file can grow after it is opened.
    pub(crate) fn read_bounded(mut self, maximum_bytes: u64) -> io::Result<SecureFileRead> {
        if self.metadata.len() > maximum_bytes {
            return Ok(SecureFileRead::TooLarge);
        }
        let mut bytes = Vec::new();
        self.file
            .by_ref()
            .take(maximum_bytes.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum_bytes {
            return Ok(SecureFileRead::TooLarge);
        }
        Ok(SecureFileRead::Bytes(bytes))
    }
}

/// The bounded result of reading a [`SecureRegularFile`].
pub(crate) enum SecureFileRead {
    Bytes(Vec<u8>),
    TooLarge,
}

/// Whether a path names a regular file the server may read from `root`. Errors read as "no": a
/// path the server cannot prove contained is a path it does not open.
pub(crate) fn is_safe_authored_file(root: &Path, path: &Path) -> bool {
    secure_regular_file(root, path).is_ok_and(|file| file.is_some())
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

/// Opens a regular file relative to a held directory descriptor on the platforms Evidence ships
/// on. Every ancestor and the leaf are opened with `NOFOLLOW`, and each next name is resolved from
/// the descriptor for the directory just admitted. Renaming or replacing a path after one step
/// therefore cannot redirect a later step.
#[cfg(unix)]
fn open_secure_regular_file(root: &Path, path: &Path) -> Result<Option<SecureRegularFile>> {
    use std::os::unix::fs::MetadataExt as _;

    use rustix::fs::{Mode, OFlags};

    let Some(components) = secure_relative_components(root, path) else {
        return Ok(None);
    };
    let Some((file_name, directories)) = components.split_last() else {
        return Ok(None);
    };

    let Some(mut directory) = open_path(
        || {
            rustix::fs::open(
                root,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
                Mode::empty(),
            )
        },
        "failed to open project root",
    )?
    else {
        return Ok(None);
    };
    for component in directories {
        let Some(next) = open_path(
            || {
                rustix::fs::openat(
                    &directory,
                    component.as_os_str(),
                    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
                    Mode::empty(),
                )
            },
            "failed to open a project directory",
        )?
        else {
            return Ok(None);
        };
        directory = next;
    }

    let Some(descriptor) = open_path(
        || {
            rustix::fs::openat(
                &directory,
                file_name.as_os_str(),
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            )
        },
        "failed to open a project file",
    )?
    else {
        return Ok(None);
    };
    let file = fs::File::from(descriptor);
    let metadata = file
        .metadata()
        .context("failed to inspect an opened project file")?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Ok(None);
    }
    Ok(Some(SecureRegularFile { file, metadata }))
}

#[cfg(unix)]
fn open_path(
    open: impl FnOnce() -> rustix::io::Result<std::os::fd::OwnedFd>,
    context: &'static str,
) -> Result<Option<std::os::fd::OwnedFd>> {
    match open() {
        Ok(descriptor) => Ok(Some(descriptor)),
        Err(error) if absent_or_unsafe(error) => Ok(None),
        Err(error) => Err(std::io::Error::from(error)).context(context),
    }
}

#[cfg(unix)]
fn absent_or_unsafe(error: rustix::io::Errno) -> bool {
    error == rustix::io::Errno::NOENT
        || error == rustix::io::Errno::NOTDIR
        || error == rustix::io::Errno::LOOP
        || error == rustix::io::Errno::NXIO
        || error == rustix::io::Errno::NODEV
}

/// The non-Unix fallback still reads from the descriptor it inspected. Descriptor-relative,
/// no-follow traversal is not available through the standard library there, so the path walk is
/// the same best-effort containment check this server used before descriptor-backed reads.
#[cfg(not(unix))]
fn open_secure_regular_file(root: &Path, path: &Path) -> Result<Option<SecureRegularFile>> {
    let Some(metadata) =
        secure_path_metadata(root, path)?.filter(|metadata| metadata.file_type().is_file())
    else {
        return Ok(None);
    };
    let file = fs::File::open(path).context("failed to open a project file")?;
    let opened_metadata = file
        .metadata()
        .context("failed to inspect an opened project file")?;
    if !opened_metadata.is_file() || opened_metadata.len() != metadata.len() {
        return Ok(None);
    }
    Ok(Some(SecureRegularFile {
        file,
        metadata: opened_metadata,
    }))
}

fn secure_relative_components<'a>(root: &Path, path: &'a Path) -> Option<Vec<Component<'a>>> {
    let relative = path.strip_prefix(root).ok()?;
    let components = relative.components().collect::<Vec<_>>();
    components
        .iter()
        .all(|component| matches!(component, Component::Normal(_)))
        .then_some(components)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, relative: &str, contents: &[u8]) -> std::path::PathBuf {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().expect("fixture path has a parent")).unwrap();
        fs::write(&path, contents).unwrap();
        path
    }

    #[cfg(unix)]
    #[test]
    fn rejects_hard_links_symbolic_links_and_non_regular_files() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let original = write(&root, "questions/original.yaml", b"id: original\n");
        let hard_link = root.join("questions/hard-link.yaml");
        fs::hard_link(&original, &hard_link).unwrap();
        let symbolic_link = root.join("questions/symbolic-link.yaml");
        symlink(&original, &symbolic_link).unwrap();
        let directory = root.join("questions/directory.yaml");
        fs::create_dir(&directory).unwrap();

        assert!(secure_regular_file(&root, &original).unwrap().is_none());
        assert!(secure_regular_file(&root, &hard_link).unwrap().is_none());
        assert!(secure_regular_file(&root, &symbolic_link)
            .unwrap()
            .is_none());
        assert!(secure_regular_file(&root, &directory).unwrap().is_none());
    }

    #[test]
    fn bounded_read_refuses_a_file_that_grows_after_it_is_opened() {
        use std::{fs::OpenOptions, io::Write as _};

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let path = write(&root, "questions/question.yaml", b"short");
        let opened = secure_regular_file(&root, &path).unwrap().unwrap();
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"-now-too-large")
            .unwrap();

        assert!(matches!(
            opened.read_bounded(8).unwrap(),
            SecureFileRead::TooLarge
        ));
    }

    #[cfg(unix)]
    #[test]
    fn reads_the_opened_descriptor_when_the_path_is_replaced() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let path = write(&root, "questions/question.yaml", b"opened-file");
        let opened = secure_regular_file(&root, &path).unwrap().unwrap();
        fs::rename(&path, root.join("questions/displaced.yaml")).unwrap();
        fs::write(&path, b"replacement").unwrap();

        let SecureFileRead::Bytes(bytes) = opened.read_bounded(64).unwrap() else {
            panic!("the opened file is within the byte ceiling");
        };
        assert_eq!(bytes, b"opened-file");
    }
}
