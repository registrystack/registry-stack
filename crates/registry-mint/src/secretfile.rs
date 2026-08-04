//! Bounded, owner-only reads of private key material.
//!
//! Mint holds an access-token signing key and an audit HMAC key. Client
//! registrations carry public keys only, so this module is deliberately small
//! and is the single file-read boundary for private material.

use std::{fs, os::unix::fs::MetadataExt, path::Path};

use thiserror::Error;
use zeroize::Zeroizing;

/// Upper bound on a Mint secret file, generous for any supported JWK or HMAC key.
pub const MAX_SECRET_BYTES: u64 = 64 * 1024;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SecretFileError {
    #[error("the secret file is unavailable")]
    Unavailable,
    #[error("the secret file is not a regular, single-link, owner-only file")]
    Unsafe,
    #[error("the secret file is too large")]
    TooLarge,
    #[error("the secret file could not be read")]
    Read,
    #[error("the secret file is not valid UTF-8")]
    InvalidValue,
}

/// Read a secret file that must be a regular file, owned by the running user,
/// unreadable by group and other, and reachable without traversing a symlink.
///
/// `symlink_metadata` is used rather than `metadata` so a symlink fails the
/// regular-file check instead of being silently followed to its target. The
/// link count is pinned to one so a hard link created by another user cannot
/// alias the same inode under weaker permissions.
pub fn read_owner_only(path: &Path) -> Result<Zeroizing<String>, SecretFileError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| SecretFileError::Unavailable)?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(SecretFileError::Unsafe);
    }
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(SecretFileError::Unsafe);
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(SecretFileError::Unsafe);
    }
    if metadata.len() > MAX_SECRET_BYTES {
        return Err(SecretFileError::TooLarge);
    }
    let bytes = Zeroizing::new(fs::read(path).map_err(|_| SecretFileError::Read)?);
    let text = std::str::from_utf8(&bytes).map_err(|_| SecretFileError::InvalidValue)?;
    Ok(Zeroizing::new(text.trim().to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, os::unix::fs::PermissionsExt};

    fn write_key(directory: &Path, name: &str, mode: u32) -> std::path::PathBuf {
        let path = directory.join(name);
        let mut file = fs::File::create(&path).expect("create key file");
        file.write_all(b"  key-material  ").expect("write key file");
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("set mode");
        path
    }

    #[test]
    fn owner_only_files_are_read_and_trimmed() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = write_key(directory.path(), "signing.jwk", 0o600);
        let value = read_owner_only(&path).expect("owner-only file reads");
        assert_eq!(&*value, "key-material");
    }

    #[test]
    fn group_or_world_readable_files_are_rejected() {
        let directory = tempfile::tempdir().expect("temp dir");
        for mode in [0o640, 0o604, 0o644, 0o660] {
            let path = write_key(directory.path(), &format!("key-{mode:o}.jwk"), mode);
            assert_eq!(
                read_owner_only(&path),
                Err(SecretFileError::Unsafe),
                "mode {mode:o} must be rejected"
            );
        }
    }

    #[test]
    fn symlinked_and_hard_linked_secrets_are_rejected() {
        let directory = tempfile::tempdir().expect("temp dir");
        let target = write_key(directory.path(), "target.jwk", 0o600);

        let symlink = directory.path().join("symlink.jwk");
        std::os::unix::fs::symlink(&target, &symlink).expect("create symlink");
        assert_eq!(read_owner_only(&symlink), Err(SecretFileError::Unsafe));

        let hard_link = directory.path().join("hard.jwk");
        fs::hard_link(&target, &hard_link).expect("create hard link");
        assert_eq!(read_owner_only(&hard_link), Err(SecretFileError::Unsafe));
        assert_eq!(read_owner_only(&target), Err(SecretFileError::Unsafe));
    }

    #[test]
    fn directories_and_missing_paths_are_rejected() {
        let directory = tempfile::tempdir().expect("temp dir");
        assert_eq!(
            read_owner_only(directory.path()),
            Err(SecretFileError::Unsafe)
        );
        assert_eq!(
            read_owner_only(&directory.path().join("absent.jwk")),
            Err(SecretFileError::Unavailable)
        );
    }
}
