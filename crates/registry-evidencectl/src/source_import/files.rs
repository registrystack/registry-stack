//! Bounded local files and the lock shared by import and build entry points.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read as _, Write as _},
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _},
    path::{Component, Path, PathBuf},
};

use anyhow::{anyhow, bail, Context as _, Result};
use registry_evidence_authoring::layout::{MAX_OPENAPI_BYTES, OPENAPI_FILE};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub(super) const MAX_FILE_BYTES: u64 = 1024 * 1024;
pub(super) const MAX_PROJECT_BYTES: usize = 64 * 1024 * 1024;
pub(super) const MAX_PROJECT_FILES: usize = 4096;
/// The largest source-import baseline document.
///
/// The baseline holds the accepted local content of the project once and the
/// last upstream bytes of every installed source beside it, so it is sized as
/// a small multiple of the project it describes rather than as one file.
pub(super) const MAX_STATE_BYTES: u64 = (MAX_PROJECT_BYTES * 4) as u64;
/// The largest source-import transaction journal.
///
/// A journal records the content before and after every operation it applies,
/// and the baseline document is one of them, so it is sized as twice the
/// baseline.
pub(super) const MAX_JOURNAL_BYTES: u64 = MAX_STATE_BYTES * 2;
pub(super) const STATE_PATH: &str = ".evidence/source-imports/state.json";
pub(super) const JOURNAL_PATH: &str = ".evidence/source-imports/transaction.json";
const AUTHORED_DIRECTORIES: &[&str] = &[
    "questions",
    "sources",
    "selectors",
    "schemas",
    "adapters",
    "derivations",
    "fixtures",
    "codelists",
    "queries",
    "public-keys",
];
const AUTHORED_FILES: &[&str] = &["evidence-project.yaml", "source.openapi.yaml"];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Contents {
    pub text: String,
    pub mode: u32,
}

/// A process-held lock shared by all authored-project readers and import
/// writers. Its owner-private temporary location also works for read-only
/// projects which have never used source import.
pub(crate) struct ProjectLock {
    pub(super) root: PathBuf,
    _file: File,
}

impl ProjectLock {
    pub(crate) fn acquire(project: &Path) -> Result<Self> {
        let root = plain_directory(project)?;
        let uid = rustix::process::geteuid().as_raw();
        // A per-process TMPDIR override must not create a second lock namespace
        // for the same authored project. The tooling already requires Unix.
        let locks = Path::new("/tmp").join(format!("registry-evidencectl-source-locks-{uid}"));
        private_directory(&locks)?;
        let key = digest(root.as_os_str().as_encoded_bytes());
        let descriptor = rustix::fs::open(
            locks.join(format!("{key}.lock")),
            rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .context("opening the authored-project lock")?;
        let file = File::from(descriptor);
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != uid
            || metadata.permissions().mode() & 0o7777 != 0o600
        {
            bail!("authored-project lock must be an owner-only plain file");
        }
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).context(
            "another build or source import is using this project; retry after it finishes",
        )?;
        let guard = Self { root, _file: file };
        super::recover(&guard)?;
        Ok(guard)
    }
}

/// The largest the content at a project-relative path may legitimately be.
///
/// The authoring form gives each part of a project its own ceiling. The
/// retained OpenAPI description is the one authored file that may be far larger
/// than an artifact, and the baseline and journal are this tool's own state
/// documents rather than authored files. Reading any of them under a bound
/// meant for another would let a file grow far past what its own kind allows.
pub(super) fn authored_bound(relative: &str) -> u64 {
    match relative {
        OPENAPI_FILE => MAX_OPENAPI_BYTES,
        STATE_PATH => MAX_STATE_BYTES,
        JOURNAL_PATH => MAX_JOURNAL_BYTES,
        _ => MAX_FILE_BYTES,
    }
}

pub(super) fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(super) fn plain_directory(path: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspecting directory {}", path.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("expected a plain local directory: {}", path.display());
    }
    fs::canonicalize(path).context("resolving local directory")
}

pub(super) fn private_directory(path: &Path) -> Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).context("creating source-import state directory"),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        bail!("source-import state and lock directories must be plain owner-only directories");
    }
    Ok(())
}

pub(super) fn ensure_state_directory(root: &Path) -> Result<()> {
    // .evidence is already the product's local state directory. Do not impose
    // its mode on ordinary existing projects; the import subdirectory is private.
    let evidence = root.join(".evidence");
    if !evidence.exists() {
        fs::DirBuilder::new().mode(0o700).create(&evidence)?;
    }
    plain_directory(&evidence)?;
    private_directory(&evidence.join("source-imports"))?;
    validate_state_directories(root)?;
    sync_directory(&evidence)?;
    sync_directory(root)
}

fn validate_state_directories(root: &Path) -> Result<()> {
    let uid = rustix::process::geteuid().as_raw();
    // Protect the directory entries as well as the private leaf. A writable
    // .evidence or project parent could otherwise replace a checked journal
    // subtree between its inspection and replay.
    for path in [
        root.to_path_buf(),
        root.join(".evidence"),
        root.join(".evidence/source-imports"),
    ] {
        let metadata =
            fs::symlink_metadata(&path).context("inspecting source-import state ownership")?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != uid
            || metadata.permissions().mode() & 0o022 != 0
        {
            bail!("source-import recovery requires owned plain state directories without group or other write permission");
        }
    }
    let metadata = fs::symlink_metadata(root.join(".evidence/source-imports"))?;
    if metadata.permissions().mode() & 0o7777 != 0o700 {
        bail!("source-import state directory must be owner-only (0700)");
    }
    Ok(())
}

/// Existing import recovery grants the tool a write capability. Verify the
/// provenance of that capability before reading or replaying any journal.
/// Projects with no journal have no new ownership or write requirement.
pub(super) fn validate_recovery_state(root: &Path) -> Result<bool> {
    match fs::symlink_metadata(root.join(JOURNAL_PATH)) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("inspecting source-import recovery journal"),
    }
    validate_state_directories(root)?;
    for relative in [JOURNAL_PATH, STATE_PATH] {
        let metadata = match fs::symlink_metadata(root.join(relative)) {
            Ok(metadata) => metadata,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && relative == STATE_PATH =>
            {
                continue
            }
            Err(error) => return Err(error).context("inspecting source-import recovery file"),
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.nlink() != 1
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o7777 != 0o600
        {
            bail!("source-import recovery journal and baseline must be owned plain files with mode 0600");
        }
    }
    Ok(true)
}

pub(super) fn safe_relative(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 240
        && !value.contains('\\')
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && Path::new(value)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

pub(super) fn artifact_path(value: &str) -> Result<()> {
    if !safe_relative(value) {
        bail!("export artifact path must be a safe relative path");
    }
    let (directory, name) = value
        .split_once('/')
        .ok_or_else(|| anyhow!("artifact path needs its authoring directory"))?;
    let suffix = match directory {
        "sources" | "selectors" | "schemas" => ".yaml",
        "adapters" => ".rhai",
        _ => bail!(
            "exports may contain only ordinary source, selector, schema and adapter artifacts"
        ),
    };
    let stem = name
        .strip_suffix(suffix)
        .ok_or_else(|| anyhow!("artifact extension does not match its authoring directory"))?;
    if stem.is_empty()
        || stem.len() > 128
        || !stem.as_bytes()[0].is_ascii_lowercase()
        || !stem.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        bail!("export artifact names must be bounded lowercase authoring names");
    }
    Ok(())
}

pub(super) fn read(root: &Path, relative: &str, maximum: u64) -> Result<Option<Contents>> {
    if !safe_relative(relative) {
        bail!("local artifact path must be safe and relative");
    }
    let mut parent = root.to_path_buf();
    let path = Path::new(relative);
    for component in path.parent().into_iter().flat_map(Path::components) {
        parent.push(component);
        match fs::symlink_metadata(&parent) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => bail!("artifact parents must be plain directories"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("inspecting artifact parent"),
        }
    }
    let descriptor = match rustix::fs::open(
        root.join(relative),
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error).context("opening plain local artifact"),
    };
    let mut file = File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > maximum {
        bail!("local artifact must be a bounded plain file");
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        bail!("local artifact exceeds its byte bound");
    }
    Ok(Some(Contents {
        text: String::from_utf8(bytes).context("source-import artifacts must be UTF-8 text")?,
        mode: metadata.permissions().mode() & 0o777,
    }))
}

pub(super) fn snapshot(root: &Path) -> Result<BTreeMap<String, Contents>> {
    let mut result = BTreeMap::new();
    let mut bytes = 0;
    for relative in AUTHORED_FILES {
        if let Some(content) = read(root, relative, authored_bound(relative))? {
            bytes += content.text.len();
            result.insert((*relative).to_owned(), content);
        }
    }
    for relative in AUTHORED_DIRECTORIES {
        collect(root, relative, 0, &mut result, &mut bytes)?;
    }
    if bytes > MAX_PROJECT_BYTES {
        bail!("authoring project exceeds the 64 MiB source-update snapshot bound");
    }
    Ok(result)
}

fn collect(
    root: &Path,
    relative: &str,
    depth: usize,
    result: &mut BTreeMap<String, Contents>,
    bytes: &mut usize,
) -> Result<()> {
    if depth > 16 {
        bail!("authoring artifact nesting exceeds the source-update bound");
    }
    let directory = root.join(relative);
    match fs::symlink_metadata(&directory) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => bail!("authoring artifacts must be held in plain directories"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("inspecting authored directory"),
    }
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("artifact names must be UTF-8"))?;
        let relative = format!("{relative}/{name}");
        if entry.file_type()?.is_dir() {
            collect(root, &relative, depth + 1, result, bytes)?;
        } else {
            let content = read(root, &relative, authored_bound(&relative))?
                .ok_or_else(|| anyhow!("authoring artifact changed while taking its snapshot"))?;
            *bytes += content.text.len();
            if *bytes > MAX_PROJECT_BYTES || result.len() >= MAX_PROJECT_FILES {
                bail!("authoring project exceeds source-update snapshot bounds");
            }
            result.insert(relative, content);
        }
    }
    Ok(())
}

pub(super) fn write(root: &Path, relative: &str, content: Option<&Contents>) -> Result<()> {
    // Reading first checks every existing parent and refuses links and special
    // files before either replacement or deletion.
    read(root, relative, authored_bound(relative))?;
    let destination = root.join(relative);
    if let Some(content) = content {
        let parent = destination
            .parent()
            .ok_or_else(|| anyhow!("artifact has no directory"))?;
        fs::create_dir_all(parent)?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(content.mode & 0o777))?;
        temporary.write_all(content.text.as_bytes())?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(&destination)
            .map_err(|error| error.error)
            .context("replacing local artifact")?;
        sync_directory(parent)?;
    } else if destination.exists() {
        fs::remove_file(&destination)?;
        sync_directory(destination.parent().expect("relative artifact has parent"))?;
    }
    Ok(())
}

pub(super) fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?
        .sync_all()
        .context("persisting local directory")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(root: &Path) {
        fs::create_dir_all(root.join("questions")).expect("question directory");
    }

    fn oversized(bytes: u64) -> String {
        "y".repeat(bytes as usize + 1)
    }

    #[test]
    fn authored_bound_sizes_each_path_by_its_own_kind() {
        assert_eq!(authored_bound("questions/one.yaml"), MAX_FILE_BYTES);
        assert_eq!(authored_bound("evidence-project.yaml"), MAX_FILE_BYTES);
        assert_eq!(authored_bound(OPENAPI_FILE), MAX_OPENAPI_BYTES);
        assert_eq!(authored_bound(STATE_PATH), MAX_STATE_BYTES);
        assert_eq!(authored_bound(JOURNAL_PATH), MAX_JOURNAL_BYTES);
    }

    #[test]
    fn snapshot_refuses_an_artifact_past_the_single_file_bound() {
        let directory = tempfile::tempdir().expect("temporary project");
        let root = directory.path();
        project(root);
        fs::write(root.join("questions/one.yaml"), oversized(MAX_FILE_BYTES))
            .expect("oversized question");
        let Err(error) = snapshot(root) else {
            panic!("an oversized question is refused");
        };
        assert!(
            error.to_string().contains("bounded plain file"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn snapshot_accepts_a_description_past_the_single_file_bound() {
        let directory = tempfile::tempdir().expect("temporary project");
        let root = directory.path();
        project(root);
        let description = oversized(MAX_FILE_BYTES);
        fs::write(root.join(OPENAPI_FILE), &description).expect("large description");
        let taken = snapshot(root).expect("the description keeps its own bound");
        assert_eq!(
            taken.get(OPENAPI_FILE).map(|content| content.text.len()),
            Some(description.len())
        );
    }

    #[test]
    fn write_refuses_a_destination_past_the_single_file_bound() {
        let directory = tempfile::tempdir().expect("temporary project");
        let root = directory.path();
        project(root);
        fs::write(root.join("questions/one.yaml"), oversized(MAX_FILE_BYTES))
            .expect("oversized question");
        let replacement = Contents {
            text: "id: one\n".to_owned(),
            mode: 0o600,
        };
        let Err(error) = write(root, "questions/one.yaml", Some(&replacement)) else {
            panic!("an oversized destination is refused");
        };
        assert!(
            error.to_string().contains("bounded plain file"),
            "unexpected error: {error}"
        );
    }
}
