//! Bounded, owner-only reads of the client key this service authenticates with.
//!
//! The service holds exactly one piece of private material: the key that signs
//! its client assertion to Mint. It holds no Evidence signing key and no holder
//! key, so this module is the whole private-material read boundary and is
//! deliberately small.

use std::{fs, io::Read, os::unix::fs::MetadataExt, path::Path};

use rustix::fs::{Mode, OFlags};
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
/// user, unreadable by group and other, and not itself a symlink.
///
/// Open without following a final symlink, then validate and read that same
/// descriptor. Replacing the path after validation cannot substitute another
/// file. The read remains bounded if the opened file grows after validation.
pub fn read_owner_only(path: &Path) -> Result<Zeroizing<String>, SecretFileError> {
    read_validated_file(open_owner_only(path)?)
}

fn open_owner_only(path: &Path) -> Result<fs::File, SecretFileError> {
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::LOOP {
            SecretFileError::Unsafe
        } else {
            SecretFileError::Unavailable
        }
    })?;
    let file = fs::File::from(descriptor);
    let metadata = file.metadata().map_err(|_| SecretFileError::Read)?;
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
    Ok(file)
}

fn read_validated_file(file: fs::File) -> Result<Zeroizing<String>, SecretFileError> {
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_SECRET_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SecretFileError::Read)?;
    if bytes.len() as u64 > MAX_SECRET_BYTES {
        return Err(SecretFileError::TooLarge);
    }
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

    #[test]
    fn a_replaced_path_cannot_substitute_the_validated_file() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = write_key(directory.path(), "original.json", 0o600);
        let file = open_owner_only(&path).expect("validate the original file");
        fs::rename(&path, directory.path().join("held.json")).expect("move original");
        fs::write(&path, b"replacement-material").expect("replace the path");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("set mode");

        assert_eq!(
            &*read_validated_file(file).expect("read the validated descriptor"),
            "key-material"
        );
        assert_eq!(read_owner_only(&path), Err(SecretFileError::Unsafe));
    }

    #[test]
    fn a_symlink_replacement_cannot_redirect_the_validated_read() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = write_key(directory.path(), "original.json", 0o600);
        let file = open_owner_only(&path).expect("validate the original file");
        fs::rename(&path, directory.path().join("held.json")).expect("move original");
        let target = directory.path().join("replacement.json");
        fs::write(&target, b"replacement-material").expect("write replacement");
        std::os::unix::fs::symlink(&target, &path).expect("replace with symlink");

        assert_eq!(
            &*read_validated_file(file).expect("read the validated descriptor"),
            "key-material"
        );
        assert_eq!(read_owner_only(&path), Err(SecretFileError::Unsafe));
    }

    #[test]
    fn growth_after_validation_is_refused_by_the_bounded_read() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = write_key(directory.path(), "growing.json", 0o600);
        let file = open_owner_only(&path).expect("validate the short file");
        fs::write(&path, vec![b'x'; (MAX_SECRET_BYTES + 1) as usize])
            .expect("grow the opened file");
        assert_eq!(read_validated_file(file), Err(SecretFileError::TooLarge));
    }

    #[test]
    fn exact_size_limit_reads_but_larger_files_are_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = write_key(directory.path(), "bounded.json", 0o400);
        // Reopen for writing only while constructing the fixture.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("set mode");
        fs::write(&path, vec![b'x'; MAX_SECRET_BYTES as usize]).expect("write exact limit");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).expect("set mode");
        assert_eq!(
            read_owner_only(&path).expect("exact limit reads").len() as u64,
            MAX_SECRET_BYTES
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("set mode");
        fs::write(&path, vec![b'x'; (MAX_SECRET_BYTES + 1) as usize]).expect("write over limit");
        assert_eq!(read_owner_only(&path), Err(SecretFileError::TooLarge));
    }

    #[test]
    fn invalid_utf8_is_refused_without_the_file_contents() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = write_key(directory.path(), "invalid.json", 0o600);
        fs::write(&path, [0xff]).expect("write invalid UTF-8");
        assert_eq!(read_owner_only(&path), Err(SecretFileError::InvalidValue));
    }

    #[test]
    fn a_fifo_is_refused_without_waiting_for_a_writer() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("fifo");
        assert!(std::process::Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(&path)
            .status()
            .expect("run mkfifo")
            .success());
        assert_eq!(read_owner_only(&path), Err(SecretFileError::Unsafe));
    }
}
