// SPDX-License-Identifier: Apache-2.0

//! The owner-only filesystem boundary for a development session's state:
//! directories are mode 0700, files are mode 0600 with one link, and
//! nothing is followed through a symbolic link.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

fn unsafe_state() -> io::Error {
    io::Error::other("local state must use owner-only directories and single-link files")
}

/// Create `path` as a private directory unless it exists, then check it.
pub(super) fn directory(path: &Path) -> io::Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    check(path, true)
}

/// Refuse a path that is not owned by this user, is readable by anyone
/// else, is a symbolic link, or, for a file, has more than one link.
pub(super) fn check(path: &Path, directory: bool) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
        || (directory && !metadata.is_dir())
        || (!directory && (!metadata.is_file() || metadata.nlink() != 1))
    {
        return Err(unsafe_state());
    }
    Ok(())
}

/// Create a new private file holding `bytes`; an existing file is refused.
pub(super) fn create(path: &Path, bytes: &[u8]) -> io::Result<()> {
    check(path.parent().ok_or_else(unsafe_state)?, true)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Replace a private file atomically.
pub(super) fn replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if fs::symlink_metadata(path).is_ok() {
        check(path, false)?;
    }
    let parent = path.parent().ok_or_else(unsafe_state)?;
    let temporary = parent.join(format!(".replace-{}", uuid::Uuid::new_v4().simple()));
    create(&temporary, bytes)?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    File::open(parent)?.sync_all()
}

/// Read a private file of at most `maximum` bytes.
pub(super) fn read(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    check(path, false)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(io::Error::other("local state exceeds its size limit"));
    }
    Ok(bytes)
}

/// An exclusive advisory lock, held until the value drops.
pub(super) struct Lock {
    _file: File,
}

/// Take the exclusive lock at `path` without waiting.
pub(super) fn lock(path: &Path) -> io::Result<Option<Lock>> {
    match create(path, b"") {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    check(path, false)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(Some(Lock { _file: file })),
        Err(rustix::io::Errno::WOULDBLOCK) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_is_owner_only_and_never_overwritten_by_create() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("state");
        directory(&dir).unwrap();
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let file = dir.join("secret");
        create(&file, b"one").unwrap();
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(create(&file, b"two").is_err());
        replace(&file, b"two").unwrap();
        assert_eq!(read(&file, 16).unwrap(), b"two");
        assert!(read(&file, 2).is_err());
    }

    #[test]
    fn a_shared_or_linked_path_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("state");
        directory(&dir).unwrap();
        let file = dir.join("secret");
        create(&file, b"one").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read(&file, 16).is_err());
        let link = dir.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(check(&link, false).is_err());
    }

    #[test]
    fn a_second_lock_is_refused_while_the_first_is_held() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("dev.lock");
        let held = lock(&path).unwrap();
        assert!(held.is_some());
        assert!(lock(&path).unwrap().is_none());
        drop(held);
        assert!(lock(&path).unwrap().is_some());
    }
}
