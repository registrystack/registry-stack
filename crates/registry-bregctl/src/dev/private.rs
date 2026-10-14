// SPDX-License-Identifier: Apache-2.0
//! Small owner-only filesystem boundary for retained local development state.

use anyhow::{bail, Context, Result};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

pub(super) fn directory(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .context("cannot create private local directory")?;
    }
    check(path, true)
}

pub(super) fn check(path: &Path, directory: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path).context("local state path is missing")?;
    check_metadata(&metadata, directory)
}

pub(super) fn check_metadata(metadata: &fs::Metadata, directory: bool) -> Result<()> {
    if metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
        || (directory && !metadata.is_dir())
        || (!directory && (!metadata.is_file() || metadata.nlink() != 1))
    {
        bail!("local state must use ordinary owner-only directories and single-link files");
    }
    Ok(())
}

pub(super) fn read(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    check(path, false)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    let before = fs::symlink_metadata(path)?;
    let opened = file.metadata()?;
    if before.ino() != opened.ino() || before.dev() != opened.dev() {
        bail!("local state changed while opening it");
    }
    let mut bytes = Vec::new();
    (&mut file).take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        bail!("local state exceeds its size limit");
    }
    Ok(bytes)
}

pub(super) fn create(path: &Path, bytes: &[u8]) -> Result<()> {
    check(
        path.parent()
            .context("local output needs a parent directory")?,
        true,
    )?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .context("local credential or state output already exists or cannot be created")?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(super) fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        check(path, false)?;
    }
    let parent = path.parent().context("state requires a parent directory")?;
    check(parent, true)?;
    let temporary = parent.join(format!(".state-{}", uuid::Uuid::new_v4()));
    create(&temporary, bytes)?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    File::open(parent)?.sync_all()?;
    Ok(())
}

pub(super) struct Lock {
    _file: File,
}
pub(super) fn lock(path: &Path) -> Result<Lock> {
    if !path.exists() {
        match create(path, b"") {
            Ok(()) => (),
            Err(_) if path.exists() => (),
            Err(error) => return Err(error),
        }
    }
    check(path, false)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .context("another local lifecycle operation or supervisor is active")?;
    Ok(Lock { _file: file })
}

pub(super) fn validate_tree(root: &Path) -> Result<()> {
    check(root, true)?;
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            validate_tree(&path)?;
        } else if path.file_name().is_some_and(|name| name == "control.sock") {
            use std::os::unix::fs::FileTypeExt;
            if !metadata.file_type().is_socket()
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o077 != 0
            {
                bail!("local control socket ownership is invalid");
            }
        } else {
            check(&path, false)?;
        }
    }
    Ok(())
}
