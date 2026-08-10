use std::fs::{self, File, Metadata};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::Instant;

use sha2::{Digest as _, Sha256};

use crate::{ErrorKind, SqliteError};

const DIGEST_CHUNK_BYTES: usize = 64 * 1024;
const SNAPSHOT_SIDECARS: [&str; 2] = ["-wal", "-journal"];

#[derive(Debug, Clone)]
struct FileIdentity(Metadata);

impl PartialEq for FileIdentity {
    fn eq(&self, other: &Self) -> bool {
        same_file(&self.0, &other.0)
    }
}
impl Eq for FileIdentity {}

/// A read-only immutable snapshot captured and digested at startup.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CapturedSnapshot {
    path: PathBuf,
    digest: String,
    identity: FileIdentity,
}

impl CapturedSnapshot {
    pub fn capture(path: impl AsRef<Path>) -> Result<Self, SqliteError> {
        let path = path.as_ref();
        let scanned = fs::symlink_metadata(path)
            .map_err(|_| SqliteError::new(ErrorKind::DatabaseUnavailable))?;
        if scanned.file_type().is_symlink() {
            return Err(SqliteError::new(ErrorKind::DatabaseSymlink));
        }
        if !scanned.is_file() {
            return Err(SqliteError::new(ErrorKind::DatabaseNotFile));
        }
        let filesystem_read_only = filesystem_read_only(path)?;
        if !filesystem_read_only && metadata_is_writable(&scanned) {
            return Err(SqliteError::new(ErrorKind::DatabaseWritable));
        }
        refuse_sidecars(path)?;
        let (digest, identity) = digest_stable(path, &scanned, filesystem_read_only, None)?;
        refuse_sidecars(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            digest,
            identity,
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn confirm_still_bound(&self) -> Result<(), SqliteError> {
        refuse_sidecars(&self.path)?;
        let current = fs::symlink_metadata(&self.path)
            .map_err(|_| SqliteError::new(ErrorKind::DatabaseUnavailable))?;
        if current.file_type().is_symlink()
            || !current.is_file()
            || FileIdentity(current) != self.identity
        {
            return Err(SqliteError::new(ErrorKind::DatabaseReplaced));
        }
        Ok(())
    }

    /// Re-read the bound snapshot and prove that its exact captured bytes are
    /// still present. This is intended for readiness probes, where the extra
    /// I/O is acceptable and identity checks alone are not a sufficient proof
    /// that an immutable deployment input has not drifted.
    pub fn verify_unchanged(&self) -> Result<(), SqliteError> {
        self.verify_unchanged_until(None)
    }

    pub(crate) fn verify_unchanged_before(&self, deadline: Instant) -> Result<(), SqliteError> {
        self.verify_unchanged_until(Some(deadline))
    }

    // Per-read verification closes drift between readiness probes. A process
    // cannot exclude a privileged writer changing and restoring bytes entirely
    // between the two hashes, so snapshot deployments still require the
    // captured file to be immutable outside this process, preferably through a
    // read-only mount.
    fn verify_unchanged_until(&self, deadline: Option<Instant>) -> Result<(), SqliteError> {
        ensure_before_deadline(deadline)?;
        refuse_sidecars(&self.path)?;
        let scanned = fs::symlink_metadata(&self.path)
            .map_err(|_| SqliteError::new(ErrorKind::DatabaseUnavailable))?;
        if scanned.file_type().is_symlink()
            || !scanned.is_file()
            || !same_live_file(&self.identity.0, &scanned)
        {
            return Err(SqliteError::new(ErrorKind::DatabaseReplaced));
        }
        let filesystem_read_only = filesystem_read_only(&self.path)?;
        let (digest, identity) =
            digest_stable(&self.path, &scanned, filesystem_read_only, deadline)?;
        refuse_sidecars(&self.path)?;
        ensure_before_deadline(deadline)?;
        if !same_live_file(&self.identity.0, &identity.0) {
            return Err(SqliteError::new(ErrorKind::DatabaseReplaced));
        }
        if identity != self.identity || digest != self.digest {
            return Err(SqliteError::new(ErrorKind::DatabaseChanged));
        }
        Ok(())
    }
}

/// A live database bound to one path identity for the process lifetime.
///
/// File contents may change, including through WAL, but replacing the main
/// database path is refused until restart.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LiveDatabaseFile {
    path: PathBuf,
    identity: FileIdentity,
}

impl LiveDatabaseFile {
    pub fn bind(path: impl AsRef<Path>) -> Result<Self, SqliteError> {
        let path = path.as_ref();
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| SqliteError::new(ErrorKind::DatabaseUnavailable))?;
        if metadata.file_type().is_symlink() {
            return Err(SqliteError::new(ErrorKind::DatabaseSymlink));
        }
        if !metadata.is_file() {
            return Err(SqliteError::new(ErrorKind::DatabaseNotFile));
        }
        Ok(Self {
            path: path.to_path_buf(),
            identity: FileIdentity(metadata),
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn confirm_still_bound(&self) -> Result<(), SqliteError> {
        let current = fs::symlink_metadata(&self.path)
            .map_err(|_| SqliteError::new(ErrorKind::DatabaseUnavailable))?;
        if current.file_type().is_symlink()
            || !current.is_file()
            || !same_live_file(&self.identity.0, &current)
        {
            return Err(SqliteError::new(ErrorKind::DatabaseReplaced));
        }
        Ok(())
    }
}

fn refuse_sidecars(path: &Path) -> Result<(), SqliteError> {
    for suffix in SNAPSHOT_SIDECARS {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(suffix);
        if fs::symlink_metadata(PathBuf::from(sidecar)).is_ok() {
            return Err(SqliteError::new(ErrorKind::UncheckpointedSidecar));
        }
    }
    Ok(())
}

fn digest_stable(
    path: &Path,
    scanned: &Metadata,
    fs_read_only: bool,
    deadline: Option<Instant>,
) -> Result<(String, FileIdentity), SqliteError> {
    ensure_before_deadline(deadline)?;
    let mut file = open_no_follow(path)?;
    let opened = file
        .metadata()
        .map_err(|_| SqliteError::new(ErrorKind::DatabaseUnavailable))?;
    if !opened.is_file() || !same_file(scanned, &opened) {
        return Err(SqliteError::new(ErrorKind::DatabaseReplaced));
    }
    if !fs_read_only && metadata_is_writable(&opened) {
        return Err(SqliteError::new(ErrorKind::DatabaseWritable));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; DIGEST_CHUNK_BYTES];
    let mut read_total = 0_u64;
    loop {
        ensure_before_deadline(deadline)?;
        let read = file
            .read(&mut buffer)
            .map_err(|_| SqliteError::new(ErrorKind::DatabaseUnavailable))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        read_total = read_total
            .checked_add(
                u64::try_from(read).map_err(|_| SqliteError::new(ErrorKind::DatabaseChanged))?,
            )
            .ok_or_else(|| SqliteError::new(ErrorKind::DatabaseChanged))?;
    }
    ensure_before_deadline(deadline)?;
    let after = file
        .metadata()
        .map_err(|_| SqliteError::new(ErrorKind::DatabaseUnavailable))?;
    if !same_file(&opened, &after) || after.len() != read_total {
        return Err(SqliteError::new(ErrorKind::DatabaseChanged));
    }
    Ok((
        sha256_label(hasher.finalize().as_slice()),
        FileIdentity(opened),
    ))
}

fn ensure_before_deadline(deadline: Option<Instant>) -> Result<(), SqliteError> {
    if deadline.is_some_and(|value| Instant::now() >= value) {
        Err(SqliteError::new(ErrorKind::TimeBudgetExceeded))
    } else {
        Ok(())
    }
}

fn sha256_label(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut label = String::with_capacity(7 + bytes.len() * 2);
    label.push_str("sha256:");
    for byte in bytes {
        label.push(char::from(HEX[usize::from(byte >> 4)]));
        label.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    label
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> Result<File, SqliteError> {
    use rustix::fs::{Mode, OFlags};
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| SqliteError::new(ErrorKind::DatabaseUnavailable))?;
    Ok(File::from(fd))
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> Result<File, SqliteError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| SqliteError::new(ErrorKind::DatabaseUnavailable))?;
    if metadata.file_type().is_symlink() {
        return Err(SqliteError::new(ErrorKind::DatabaseSymlink));
    }
    File::open(path).map_err(|_| SqliteError::new(ErrorKind::DatabaseUnavailable))
}

#[cfg(unix)]
fn filesystem_read_only(path: &Path) -> Result<bool, SqliteError> {
    use rustix::fs::{statvfs, StatVfsMountFlags};
    Ok(statvfs(path)
        .map_err(|_| SqliteError::new(ErrorKind::DatabaseUnavailable))?
        .f_flag
        .contains(StatVfsMountFlags::RDONLY))
}

#[cfg(not(unix))]
fn filesystem_read_only(_path: &Path) -> Result<bool, SqliteError> {
    Ok(false)
}

#[cfg(unix)]
fn same_file(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.permissions().mode() == right.permissions().mode()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.len() == right.len()
        && left.permissions().readonly() == right.permissions().readonly()
        && left.modified().ok() == right.modified().ok()
}

#[cfg(unix)]
fn same_live_file(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(unix)]
fn metadata_is_writable(metadata: &Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    metadata.permissions().mode() & 0o222 != 0
}

#[cfg(not(unix))]
fn metadata_is_writable(metadata: &Metadata) -> bool {
    !metadata.permissions().readonly()
}

#[cfg(not(unix))]
fn same_live_file(left: &Metadata, right: &Metadata) -> bool {
    left.created().ok() == right.created().ok()
}
