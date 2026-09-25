//! The one package format every Registry Stack runtime serves.
//!
//! A package is a directory a product's `package` command produces. Its root
//! holds `SHA256SUMS`, one line per file in the `sha256sum` text format
//! (`<64 lowercase hex digits><two spaces><relative path>`), sorted by path,
//! and optionally `REVISION`, one free-text line the operator chose (for
//! example a source-control revision). `REVISION` is listed and hashed like
//! every other file; `SHA256SUMS` lists everything but itself. The package
//! digest is the `sha256:` label of the `SHA256SUMS` bytes, which is what
//! `package.expectedDigest` pins.
//!
//! Only file bytes are hashed. File modes, owners and timestamps are not:
//! copying tools, source control and image layers do not carry them the same
//! way on every platform, so hashing them would give one package several
//! digests. Line endings are not normalized either, because the digest names
//! the exact bytes a runtime reads.
//!
//! [`write_sum_file`] finishes a directory a product has populated;
//! [`verify_package`] recomputes every digest at startup and refuses a
//! changed, missing or extra file by name. Both refuse symbolic links and
//! special files anywhere in the package and bound what they read.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

use crate::blocks::{PackageConfig, PackageDigestMismatch};
use crate::{hex_lower, sha256_uri};

/// The file listing every other file's SHA-256.
pub const SUM_FILE: &str = "SHA256SUMS";
/// The optional file holding the package revision.
pub const REVISION_FILE: &str = "REVISION";
/// The longest revision a package records, in bytes.
pub const MAX_REVISION_BYTES: usize = 256;

const HEX_DIGITS: usize = 64;
const SEPARATOR: &str = "  ";
const READ_CHUNK: usize = 64 * 1024;

/// Bounds on what a package may hold. A product may narrow them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageLimits {
    /// Files listed in `SHA256SUMS`, `REVISION` included.
    pub max_files: usize,
    /// Bytes of any one file.
    pub max_file_bytes: u64,
    /// Bytes of every listed file together.
    pub max_total_bytes: u64,
    /// Path components of any one file, its own name included.
    pub max_depth: usize,
    /// Bytes of any one relative path.
    pub max_path_bytes: usize,
}

impl Default for PackageLimits {
    fn default() -> Self {
        Self {
            max_files: 4_096,
            max_file_bytes: 64 * 1024 * 1024,
            max_total_bytes: 256 * 1024 * 1024,
            max_depth: 16,
            max_path_bytes: 512,
        }
    }
}

/// A package whose every file matched its `SHA256SUMS` line when it was read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPackage {
    digest: String,
    revision: Option<String>,
    files: BTreeMap<String, String>,
}

impl VerifiedPackage {
    /// The `sha256:` label of the `SHA256SUMS` bytes.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// The recorded revision, when the package has one.
    #[must_use]
    pub fn revision(&self) -> Option<&str> {
        self.revision.as_deref()
    }

    /// Every listed path, in `SHA256SUMS` order.
    pub fn files(&self) -> impl Iterator<Item = &str> {
        self.files.keys().map(String::as_str)
    }

    /// The `sha256:` label a listed file had when it was verified.
    #[must_use]
    pub fn file_digest(&self, path: &str) -> Option<String> {
        self.files.get(path).map(|hex| format!("sha256:{hex}"))
    }
}

/// Whether `path` names a file the package format owns rather than the
/// product. Product loaders that enumerate a package skip these.
#[must_use]
pub fn is_envelope_file(path: &str) -> bool {
    path == SUM_FILE || path == REVISION_FILE
}

/// A revision is one printable line of at most [`MAX_REVISION_BYTES`] bytes
/// without leading or trailing whitespace.
pub fn check_revision(revision: &str) -> Result<(), &'static str> {
    if revision.is_empty() || revision.len() > MAX_REVISION_BYTES {
        return Err("a revision is 1 to 256 bytes");
    }
    if revision.chars().any(char::is_control) {
        return Err("a revision is one line without control characters");
    }
    if revision.trim() != revision {
        return Err("a revision has no leading or trailing whitespace");
    }
    Ok(())
}

impl PackageConfig {
    /// Verify the package at `package.root` and, when `package.expectedDigest`
    /// is set, that its digest is the pinned one. `fix` is the command that
    /// builds the package, named in every refusal.
    pub fn verify_package(
        &self,
        limits: &PackageLimits,
        fix: &str,
    ) -> Result<VerifiedPackage, PackageError> {
        let package = verify_package(&self.root, limits, fix)?;
        self.verify_digest(package.digest())
            .map_err(|mismatch| PackageError::new(&self.root, fix, mismatch.into()))?;
        Ok(package)
    }
}

/// Finish a populated package directory: write `REVISION` when `revision` is
/// given, then `SHA256SUMS` over every file, and return the verified result.
///
/// The directory must not hold either file already; a package is written once.
pub fn write_sum_file(
    root: &Path,
    revision: Option<&str>,
    limits: &PackageLimits,
    fix: &str,
) -> Result<VerifiedPackage, PackageError> {
    let refuse = |kind| PackageError::new(root, fix, kind);
    check_root(root).map_err(refuse)?;
    for reserved in [SUM_FILE, REVISION_FILE] {
        if fs::symlink_metadata(root.join(reserved)).is_ok() {
            return Err(refuse(PackageErrorKind::Reserved {
                path: reserved.to_owned(),
            }));
        }
    }
    if let Some(revision) = revision {
        check_revision(revision).map_err(|reason| refuse(PackageErrorKind::Revision { reason }))?;
    }
    // Walk before writing so a refused tree leaves the directory untouched.
    let mut walked = walk(root, limits).map_err(refuse)?;
    if let Some(empty) = walked.empty_directories.into_iter().next() {
        return Err(refuse(PackageErrorKind::UnsafeEntry {
            path: empty,
            reason: "is an empty directory",
        }));
    }
    if let Some(revision) = revision {
        write_new(root, REVISION_FILE, format!("{revision}\n").as_bytes()).map_err(refuse)?;
        walked.files.insert(REVISION_FILE.to_owned());
    }
    check_file_count(walked.files.len(), limits).map_err(refuse)?;
    let mut total = 0_u64;
    let mut sums = String::new();
    for path in &walked.files {
        let (hex, length) = hash_file(root, path, limits, None).map_err(refuse)?;
        total = add_bytes(total, length, limits).map_err(refuse)?;
        push_sum_line(&mut sums, &hex, path);
    }
    write_new(root, SUM_FILE, sums.as_bytes()).map_err(refuse)?;
    verify_package(root, limits, fix)
}

/// The digest a package of exactly `files` and `revision` would have, without
/// writing anything. `files` maps relative paths to their bytes and never
/// holds `SHA256SUMS` or `REVISION`; `root` names the project or output in
/// refusals.
pub fn plan_package(
    root: &Path,
    files: &BTreeMap<String, Vec<u8>>,
    revision: Option<&str>,
    limits: &PackageLimits,
    fix: &str,
) -> Result<String, PackageError> {
    let sums = plan_sum_file(files, revision, limits)
        .map_err(|kind| PackageError::new(root, fix, kind))?;
    Ok(sha256_uri(sums.as_bytes()))
}

/// Write `files` and `revision` as a package into `output`, a directory that
/// must not exist yet, and return the verified result. A failed write removes
/// the directory it created.
pub fn write_package(
    output: &Path,
    files: &BTreeMap<String, Vec<u8>>,
    revision: Option<&str>,
    limits: &PackageLimits,
    fix: &str,
) -> Result<VerifiedPackage, PackageError> {
    let refuse = |kind| PackageError::new(output, fix, kind);
    plan_sum_file(files, revision, limits).map_err(refuse)?;
    if fs::symlink_metadata(output).is_ok() {
        return Err(refuse(PackageErrorKind::OutputExists));
    }
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|_| {
            refuse(PackageErrorKind::Io {
                path: "..".to_owned(),
            })
        })?;
    }
    fs::create_dir(output).map_err(|_| refuse(PackageErrorKind::OutputExists))?;
    let written = (|| {
        for (relative, bytes) in files {
            if let Some((directory, _)) = relative.rsplit_once('/') {
                fs::create_dir_all(output.join(directory)).map_err(|_| {
                    refuse(PackageErrorKind::Io {
                        path: format!("{directory}/"),
                    })
                })?;
            }
            write_new(output, relative, bytes).map_err(refuse)?;
        }
        write_sum_file(output, revision, limits, fix)
    })();
    if written.is_err() {
        // Only the directory this call created is removed; a failure to
        // remove it leaves an incomplete package the verifier refuses.
        let _ = fs::remove_dir_all(output);
    }
    written
}

/// Check `files` and `revision` as [`write_sum_file`] would and render the
/// `SHA256SUMS` text they produce.
fn plan_sum_file(
    files: &BTreeMap<String, Vec<u8>>,
    revision: Option<&str>,
    limits: &PackageLimits,
) -> Result<String, PackageErrorKind> {
    if files.is_empty() {
        return Err(PackageErrorKind::Empty);
    }
    let revision_bytes = revision
        .map(|revision| {
            check_revision(revision)
                .map(|()| format!("{revision}\n").into_bytes())
                .map_err(|reason| PackageErrorKind::Revision { reason })
        })
        .transpose()?;
    let mut entries = BTreeMap::new();
    let mut folded = BTreeMap::new();
    for (path, bytes) in files {
        if is_envelope_file(path) {
            return Err(PackageErrorKind::Reserved { path: path.clone() });
        }
        entries.insert(path.as_str(), bytes.as_slice());
    }
    if let Some(bytes) = &revision_bytes {
        entries.insert(REVISION_FILE, bytes.as_slice());
    }
    check_file_count(entries.len(), limits)?;
    let mut total = 0_u64;
    let mut sums = String::new();
    for (path, bytes) in &entries {
        check_path(path, limits)?;
        // A file cannot also be a directory, and two names that differ only
        // in letter case collide on a case-insensitive filesystem.
        let mut prefix = String::new();
        for component in path.split('/') {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            let is_file = prefix.len() == path.len();
            if let Some((previous, previous_is_file)) =
                folded.insert(prefix.to_ascii_lowercase(), (prefix.clone(), is_file))
            {
                if previous != prefix || previous_is_file || is_file {
                    return Err(PackageErrorKind::UnsafeEntry {
                        path: (*path).to_owned(),
                        reason: if previous == prefix {
                            "is both a file and a directory"
                        } else {
                            "differs from another name only in letter case"
                        },
                    });
                }
            }
        }
        let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if length > limits.max_file_bytes {
            return Err(PackageErrorKind::Bound {
                path: Some((*path).to_owned()),
                reason: "a file is larger than the package allows",
            });
        }
        total = add_bytes(total, length, limits)?;
        push_sum_line(&mut sums, &hex_lower(&Sha256::digest(bytes)), path);
    }
    Ok(sums)
}

fn push_sum_line(sums: &mut String, hex: &str, path: &str) {
    sums.push_str(hex);
    sums.push_str(SEPARATOR);
    sums.push_str(path);
    sums.push('\n');
}

/// Recompute every digest of the package at `root` and compare it with
/// `SHA256SUMS`. A changed, missing or extra file is refused by name, all of
/// them in one refusal. `fix` is the command that builds the package.
pub fn verify_package(
    root: &Path,
    limits: &PackageLimits,
    fix: &str,
) -> Result<VerifiedPackage, PackageError> {
    let refuse = |kind| PackageError::new(root, fix, kind);
    check_root(root).map_err(refuse)?;
    let sums = read_sum_file(root, limits).map_err(refuse)?;
    let listed = parse_sum_file(&sums, limits).map_err(refuse)?;
    let walked = walk(root, limits).map_err(refuse)?;

    let mut changed = Vec::new();
    let mut missing = Vec::new();
    let mut total = 0_u64;
    let mut revision_bytes = None;
    for (path, expected) in &listed {
        if !walked.files.contains(path) {
            missing.push(path.clone());
            continue;
        }
        let keep = (path == REVISION_FILE).then_some(&mut revision_bytes);
        let (found, length) = hash_file(root, path, limits, keep).map_err(refuse)?;
        total = add_bytes(total, length, limits).map_err(refuse)?;
        if &found != expected {
            changed.push(path.clone());
        }
    }
    let mut extra = walked
        .files
        .iter()
        .filter(|path| !listed.contains_key(*path))
        .cloned()
        .chain(walked.empty_directories)
        .collect::<Vec<_>>();
    extra.sort();
    if !changed.is_empty() || !missing.is_empty() || !extra.is_empty() {
        return Err(refuse(PackageErrorKind::Mismatch {
            changed,
            missing,
            extra,
        }));
    }
    let revision = revision_bytes
        .map(|bytes| parse_revision(&bytes))
        .transpose()
        .map_err(|reason| refuse(PackageErrorKind::Revision { reason }))?;
    Ok(VerifiedPackage {
        digest: sha256_uri(&sums),
        revision,
        files: listed,
    })
}

/// Why a package was refused, and which package.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub struct PackageError {
    root: PathBuf,
    fix: String,
    kind: PackageErrorKind,
}

/// The refusal itself. Paths are relative to the package root; a directory
/// ends in `/`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PackageErrorKind {
    /// `package.root` is absent, not a directory, or a symbolic link.
    RootInvalid { reason: &'static str },
    /// The package directory has no `SHA256SUMS`.
    SumFileMissing,
    /// `SHA256SUMS` is not in the package format; `line` counts from 1.
    SumFileInvalid { line: usize, reason: &'static str },
    /// The directory holds something other than what `SHA256SUMS` lists.
    Mismatch {
        changed: Vec<String>,
        missing: Vec<String>,
        extra: Vec<String>,
    },
    /// An entry the format cannot carry: a link, a special file, a name that
    /// does not travel between platforms.
    UnsafeEntry { path: String, reason: &'static str },
    /// A reserved file already exists where a package is being written.
    Reserved { path: String },
    /// The directory a package is written into already exists.
    OutputExists,
    /// The revision is not one printable line.
    Revision { reason: &'static str },
    /// The package exceeds a bound.
    Bound {
        path: Option<String>,
        reason: &'static str,
    },
    /// A file could not be read or written.
    Io { path: String },
    /// There is nothing to package.
    Empty,
    /// The package is not the one `package.expectedDigest` pins.
    DigestMismatch(PackageDigestMismatch),
}

impl From<PackageDigestMismatch> for PackageErrorKind {
    fn from(mismatch: PackageDigestMismatch) -> Self {
        Self::DigestMismatch(mismatch)
    }
}

impl PackageError {
    fn new(root: &Path, fix: &str, kind: PackageErrorKind) -> Self {
        Self {
            root: root.to_path_buf(),
            fix: fix.to_owned(),
            kind,
        }
    }

    #[must_use]
    pub fn kind(&self) -> &PackageErrorKind {
        &self.kind
    }

    /// The package directory the refusal is about.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl fmt::Display for PackageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let root = self.root.display();
        let fix = &self.fix;
        match &self.kind {
            PackageErrorKind::RootInvalid { reason } => write!(
                formatter,
                "the package at {root} {reason}; build a package with `{fix}` and place its \
                 directory there"
            ),
            PackageErrorKind::SumFileMissing => write!(
                formatter,
                "the directory at {root} has no {SUM_FILE}, so it is not a package; build one \
                 with `{fix}`"
            ),
            PackageErrorKind::SumFileInvalid { line, reason } => write!(
                formatter,
                "the package at {root} has an invalid {SUM_FILE} at line {line}: {reason}; \
                 rebuild the package with `{fix}`"
            ),
            PackageErrorKind::Mismatch {
                changed,
                missing,
                extra,
            } => {
                write!(
                    formatter,
                    "the package at {root} does not match its {SUM_FILE}"
                )?;
                for (label, paths) in [("changed", changed), ("missing", missing), ("extra", extra)]
                {
                    if !paths.is_empty() {
                        write!(formatter, "; {label}: {}", paths.join(", "))?;
                    }
                }
                write!(
                    formatter,
                    "; rebuild the package with `{fix}` and deploy the whole directory"
                )
            }
            PackageErrorKind::UnsafeEntry { path, reason } => write!(
                formatter,
                "the package at {root} holds {path}, which {reason}; a package holds only \
                 regular files, rebuild it with `{fix}`"
            ),
            PackageErrorKind::Reserved { path } => write!(
                formatter,
                "{root} already holds {path}; `{fix}` writes a package into a new directory"
            ),
            PackageErrorKind::OutputExists => write!(
                formatter,
                "{root} already exists; `{fix}` writes a package into a new directory"
            ),
            PackageErrorKind::Revision { reason } => write!(
                formatter,
                "the package revision at {root} is refused: {reason}; pass one printable line \
                 as the revision to `{fix}`"
            ),
            PackageErrorKind::Bound { path, reason } => {
                write!(formatter, "the package at {root} is refused: {reason}")?;
                if let Some(path) = path {
                    write!(formatter, " ({path})")?;
                }
                write!(
                    formatter,
                    "; reduce the project and rebuild it with `{fix}`"
                )
            }
            PackageErrorKind::Io { path } => write!(
                formatter,
                "the package at {root} could not read or write {path}; check that the file is \
                 accessible and rebuild the package with `{fix}` if it is damaged"
            ),
            PackageErrorKind::Empty => write!(
                formatter,
                "the package at {root} holds no files; build it with `{fix}`"
            ),
            PackageErrorKind::DigestMismatch(mismatch) => write!(formatter, "{mismatch}"),
        }
    }
}

fn check_root(root: &Path) -> Result<(), PackageErrorKind> {
    let metadata = fs::symlink_metadata(root).map_err(|_| PackageErrorKind::RootInvalid {
        reason: "does not exist or cannot be read",
    })?;
    if metadata.file_type().is_symlink() {
        return Err(PackageErrorKind::RootInvalid {
            reason: "is a symbolic link",
        });
    }
    if !metadata.is_dir() {
        return Err(PackageErrorKind::RootInvalid {
            reason: "is not a directory",
        });
    }
    Ok(())
}

struct Walked {
    files: BTreeSet<String>,
    empty_directories: Vec<String>,
}

/// Every regular file under `root` except `SHA256SUMS` at the root, and every
/// directory that holds no file at any depth.
fn walk(root: &Path, limits: &PackageLimits) -> Result<Walked, PackageErrorKind> {
    let mut walked = Walked {
        files: BTreeSet::new(),
        empty_directories: Vec::new(),
    };
    // Directories and files together; a tree of empty directories is bounded
    // as well as a tree of files.
    let mut entries = 0_usize;
    let entry_bound = limits.max_files.saturating_mul(2).saturating_add(1);
    visit(root, "", limits, &mut walked, &mut entries, entry_bound)?;
    if walked.files.is_empty() && walked.empty_directories.is_empty() {
        return Err(PackageErrorKind::Empty);
    }
    check_file_count(walked.files.len(), limits)?;
    Ok(walked)
}

fn visit(
    directory: &Path,
    prefix: &str,
    limits: &PackageLimits,
    walked: &mut Walked,
    entries: &mut usize,
    entry_bound: usize,
) -> Result<usize, PackageErrorKind> {
    let unreadable = || PackageErrorKind::Io {
        path: if prefix.is_empty() {
            ".".to_owned()
        } else {
            format!("{prefix}/")
        },
    };
    let mut files_below = 0_usize;
    let mut folded = BTreeSet::new();
    for entry in fs::read_dir(directory).map_err(|_| unreadable())? {
        let entry = entry.map_err(|_| unreadable())?;
        *entries += 1;
        if *entries > entry_bound {
            return Err(PackageErrorKind::Bound {
                path: None,
                reason: "the package holds more entries than it allows",
            });
        }
        let name = entry.file_name();
        let relative = match name.to_str() {
            Some(name) if prefix.is_empty() => name.to_owned(),
            Some(name) => format!("{prefix}/{name}"),
            None => {
                return Err(PackageErrorKind::UnsafeEntry {
                    path: format!("{prefix}/{}", name.to_string_lossy()),
                    reason: "has a name that is not UTF-8",
                })
            }
        };
        if prefix.is_empty() && relative == SUM_FILE {
            continue;
        }
        check_path(&relative, limits)?;
        if !folded.insert(relative.to_ascii_lowercase()) {
            return Err(PackageErrorKind::UnsafeEntry {
                path: relative,
                reason: "differs from another name only in letter case",
            });
        }
        let file_type = entry.file_type().map_err(|_| PackageErrorKind::Io {
            path: relative.clone(),
        })?;
        if file_type.is_symlink() {
            return Err(PackageErrorKind::UnsafeEntry {
                path: relative,
                reason: "is a symbolic link",
            });
        }
        if file_type.is_dir() {
            let below = visit(
                &entry.path(),
                &relative,
                limits,
                walked,
                entries,
                entry_bound,
            )?;
            if below == 0 {
                walked.empty_directories.push(format!("{relative}/"));
            }
            files_below += below;
        } else if file_type.is_file() {
            walked.files.insert(relative);
            files_below += 1;
        } else {
            return Err(PackageErrorKind::UnsafeEntry {
                path: relative,
                reason: "is not a regular file or directory",
            });
        }
    }
    Ok(files_below)
}

/// A relative path the sum file can carry unescaped and every supported
/// platform can store.
fn check_path(path: &str, limits: &PackageLimits) -> Result<(), PackageErrorKind> {
    if path.len() > limits.max_path_bytes {
        return Err(PackageErrorKind::Bound {
            path: Some(path.to_owned()),
            reason: "a path is longer than the package allows",
        });
    }
    if path.split('/').count() > limits.max_depth {
        return Err(PackageErrorKind::Bound {
            path: Some(path.to_owned()),
            reason: "a path is nested deeper than the package allows",
        });
    }
    let unsafe_entry = |reason| {
        Err(PackageErrorKind::UnsafeEntry {
            path: path.escape_debug().to_string(),
            reason,
        })
    };
    if path.chars().any(char::is_control) {
        return unsafe_entry("has a control character in its name");
    }
    if path.contains('\\') {
        return unsafe_entry("has a backslash in its name");
    }
    if path
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return unsafe_entry("is not a plain relative path");
    }
    Ok(())
}

fn check_file_count(count: usize, limits: &PackageLimits) -> Result<(), PackageErrorKind> {
    if count > limits.max_files {
        return Err(PackageErrorKind::Bound {
            path: None,
            reason: "the package holds more files than it allows",
        });
    }
    Ok(())
}

fn add_bytes(total: u64, length: u64, limits: &PackageLimits) -> Result<u64, PackageErrorKind> {
    total
        .checked_add(length)
        .filter(|total| *total <= limits.max_total_bytes)
        .ok_or(PackageErrorKind::Bound {
            path: None,
            reason: "the package is larger than it allows",
        })
}

fn sum_file_bound(limits: &PackageLimits) -> u64 {
    let line = HEX_DIGITS + SEPARATOR.len() + limits.max_path_bytes + 1;
    u64::try_from(limits.max_files.saturating_mul(line)).unwrap_or(u64::MAX)
}

fn read_sum_file(root: &Path, limits: &PackageLimits) -> Result<Vec<u8>, PackageErrorKind> {
    let path = root.join(SUM_FILE);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(PackageErrorKind::SumFileMissing)
        }
        Err(_) => {
            return Err(PackageErrorKind::Io {
                path: SUM_FILE.to_owned(),
            })
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(PackageErrorKind::UnsafeEntry {
            path: SUM_FILE.to_owned(),
            reason: "is not a regular file",
        });
    }
    let bound = sum_file_bound(limits);
    let mut bytes = Vec::new();
    read_bounded(root, SUM_FILE, bound, |chunk| {
        bytes.extend_from_slice(chunk)
    })
    .map_err(|error| match error {
        PackageErrorKind::Bound { .. } => PackageErrorKind::Bound {
            path: Some(SUM_FILE.to_owned()),
            reason: "SHA256SUMS is larger than the package allows",
        },
        other => other,
    })?;
    Ok(bytes)
}

fn parse_sum_file(
    bytes: &[u8],
    limits: &PackageLimits,
) -> Result<BTreeMap<String, String>, PackageErrorKind> {
    let invalid = |line, reason| PackageErrorKind::SumFileInvalid { line, reason };
    let text = std::str::from_utf8(bytes).map_err(|_| invalid(1, "it is not UTF-8"))?;
    if text.is_empty() {
        return Err(invalid(1, "it lists no files"));
    }
    let Some(body) = text.strip_suffix('\n') else {
        let line = text.split('\n').count();
        return Err(invalid(line, "the last line does not end with a line feed"));
    };
    let mut listed = BTreeMap::new();
    let mut previous: Option<&str> = None;
    for (index, line) in body.split('\n').enumerate() {
        let number = index + 1;
        if listed.len() >= limits.max_files {
            return Err(invalid(
                number,
                "it lists more files than the package allows",
            ));
        }
        let (hex, path) = line
            .split_at_checked(HEX_DIGITS)
            .ok_or_else(|| invalid(number, "a line is not a digest, two spaces and a path"))?;
        let path = path
            .strip_prefix(SEPARATOR)
            .ok_or_else(|| invalid(number, "a line is not a digest, two spaces and a path"))?;
        if !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid(number, "a digest is not 64 lowercase hex digits"));
        }
        if path == SUM_FILE {
            return Err(invalid(number, "SHA256SUMS lists itself"));
        }
        check_path(path, limits)
            .map_err(|_| invalid(number, "a path is not a plain relative path"))?;
        if previous.is_some_and(|previous| previous >= path) {
            return Err(invalid(number, "paths are not sorted or a path repeats"));
        }
        previous = Some(path);
        listed.insert(path.to_owned(), hex.to_owned());
    }
    Ok(listed)
}

/// Hash one listed file in bounded chunks. `keep` receives the bytes when the
/// caller also needs them.
fn hash_file(
    root: &Path,
    relative: &str,
    limits: &PackageLimits,
    keep: Option<&mut Option<Vec<u8>>>,
) -> Result<(String, u64), PackageErrorKind> {
    let mut hasher = Sha256::new();
    let mut kept = keep.as_ref().map(|_| Vec::new());
    let length = read_bounded(root, relative, limits.max_file_bytes, |chunk| {
        hasher.update(chunk);
        if let Some(kept) = kept.as_mut() {
            kept.extend_from_slice(chunk);
        }
    })
    .map_err(|error| match error {
        PackageErrorKind::Bound { .. } => PackageErrorKind::Bound {
            path: Some(relative.to_owned()),
            reason: "a file is larger than the package allows",
        },
        other => other,
    })?;
    if let Some(keep) = keep {
        *keep = kept;
    }
    Ok((hex_lower(&hasher.finalize()), length))
}

/// Read `relative` under `root` without following a link, at most `bound`
/// bytes, and refuse a file whose identity or size changed during the read.
fn read_bounded(
    root: &Path,
    relative: &str,
    bound: u64,
    mut sink: impl FnMut(&[u8]),
) -> Result<u64, PackageErrorKind> {
    let path = root.join(relative);
    let io = || PackageErrorKind::Io {
        path: relative.to_owned(),
    };
    let scanned = fs::symlink_metadata(&path).map_err(|_| io())?;
    if scanned.file_type().is_symlink() {
        return Err(PackageErrorKind::UnsafeEntry {
            path: relative.to_owned(),
            reason: "is a symbolic link",
        });
    }
    if !scanned.is_file() {
        return Err(PackageErrorKind::UnsafeEntry {
            path: relative.to_owned(),
            reason: "is not a regular file",
        });
    }
    if scanned.len() > bound {
        return Err(PackageErrorKind::Bound {
            path: Some(relative.to_owned()),
            reason: "a file is larger than the package allows",
        });
    }
    let file = open_no_follow(&path).map_err(|_| io())?;
    let opened = file.metadata().map_err(|_| io())?;
    if !opened.is_file() || !same_file(&scanned, &opened) {
        return Err(changed_during_read(relative));
    }
    let mut reader = file.take(bound.saturating_add(1));
    let mut buffer = vec![0_u8; READ_CHUNK];
    let mut length = 0_u64;
    loop {
        let read = reader.read(&mut buffer).map_err(|_| io())?;
        if read == 0 {
            break;
        }
        length += read as u64;
        if length > bound {
            return Err(PackageErrorKind::Bound {
                path: Some(relative.to_owned()),
                reason: "a file is larger than the package allows",
            });
        }
        sink(&buffer[..read]);
    }
    let after = reader.get_ref().metadata().map_err(|_| io())?;
    if !same_file(&opened, &after) || length != after.len() {
        return Err(changed_during_read(relative));
    }
    Ok(length)
}

fn changed_during_read(relative: &str) -> PackageErrorKind {
    PackageErrorKind::UnsafeEntry {
        path: relative.to_owned(),
        reason: "changed while it was read",
    }
}

fn open_no_follow(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC).bits() as i32,
        );
    }
    options.open(path)
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

fn write_new(root: &Path, relative: &str, bytes: &[u8]) -> Result<(), PackageErrorKind> {
    let io = || PackageErrorKind::Io {
        path: relative.to_owned(),
    };
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join(relative))
        .map_err(|_| io())?;
    file.write_all(bytes).map_err(|_| io())?;
    file.sync_all().map_err(|_| io())
}

fn parse_revision(bytes: &[u8]) -> Result<String, &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "REVISION is not UTF-8")?;
    let revision = text
        .strip_suffix('\n')
        .ok_or("REVISION does not end with a line feed")?;
    check_revision(revision)?;
    Ok(revision.to_owned())
}

#[cfg(test)]
#[path = "package_tests.rs"]
mod tests;
