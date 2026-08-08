//! Bounded, owner-only reads of the client key this service authenticates with.
//!
//! The service holds exactly one piece of private material: the key that signs
//! its client assertion to Mint. It holds no Evidence signing key and no holder
//! key, so this module is the whole private-material read boundary and is
//! deliberately small.

use std::{fs, os::unix::fs::MetadataExt, path::Path};

use thiserror::Error;
use zeroize::Zeroizing;

/// Upper bound on the client key file, generous for any supported JWK.
pub const MAX_SECRET_BYTES: u64 = 64 * 1024;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SecretFileError {
    #[error("the client key file is unavailable")]
    Unavailable,
    #[error("the client key file is not a regular, single-link, owner-only file")]
    Unsafe,
    #[error("the client key file is too large")]
    TooLarge,
    #[error("the client key file could not be read")]
    Read,
    #[error("the client key file is not valid UTF-8")]
    InvalidValue,
}

/// Read a private key file that must be a regular file, owned by the running
/// user, unreadable by group and other, and reachable without traversing a
/// symlink.
///
/// `symlink_metadata` is used rather than `metadata` so a symlink fails the
/// regular-file check instead of being silently followed to its target. The
/// link count is pinned to one so a hard link created by another user cannot
/// alias the same inode under weaker permissions. No error carries any part of
/// the file's content.
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
    use std::{fs, io::Write, os::unix::fs::PermissionsExt, path::Path};

    fn write_key(directory: &Path, name: &str, mode: u32) -> std::path::PathBuf {
        let path = directory.join(name);
        let mut file = fs::File::create(&path).expect("create the key file");
        file.write_all(b"  key-material  ")
            .expect("write the key file");
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("set the mode");
        path
    }

    #[test]
    fn an_owner_only_file_is_read_and_trimmed() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = write_key(directory.path(), "delivery-client.jwk.json", 0o600);
        let value = read_owner_only(&path).expect("an owner-only file reads");
        assert_eq!(&*value, "key-material");
    }

    #[test]
    fn a_file_anyone_else_can_read_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        for mode in [0o640, 0o604, 0o644, 0o660] {
            let path = write_key(directory.path(), &format!("key-{mode:o}.json"), mode);
            assert_eq!(
                read_owner_only(&path),
                Err(SecretFileError::Unsafe),
                "mode {mode:o} must be refused"
            );
        }
    }

    #[test]
    fn a_symlinked_or_hard_linked_secret_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let target = write_key(directory.path(), "target.json", 0o600);

        let link = directory.path().join("link.json");
        std::os::unix::fs::symlink(&target, &link).expect("create the symlink");
        assert_eq!(read_owner_only(&link), Err(SecretFileError::Unsafe));

        let hard = directory.path().join("hard.json");
        fs::hard_link(&target, &hard).expect("create the hard link");
        assert_eq!(read_owner_only(&hard), Err(SecretFileError::Unsafe));
    }

    #[test]
    fn a_missing_file_reports_that_it_is_unavailable() {
        let directory = tempfile::tempdir().expect("temp dir");
        assert_eq!(
            read_owner_only(&directory.path().join("absent.json")),
            Err(SecretFileError::Unavailable)
        );
    }

    #[test]
    fn an_oversized_file_is_refused_before_it_is_read() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("large.json");
        fs::write(&path, vec![b'0'; (MAX_SECRET_BYTES + 1) as usize])
            .expect("write the oversized file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("set the mode");
        assert_eq!(read_owner_only(&path), Err(SecretFileError::TooLarge));
    }

    #[test]
    fn the_error_never_carries_the_material_it_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = write_key(directory.path(), "world.json", 0o644);
        let error = read_owner_only(&path).expect_err("a world-readable file is refused");
        let rendered = format!("{error} {error:?}");
        assert!(!rendered.contains("key-material"), "rendered: {rendered}");
    }
}
