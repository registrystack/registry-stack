//! Bounded immutable project snapshots, preserving descriptor custody across path replacement.
use crate::authored;
use anyhow::{Context as _, Result};
use registry_evidence_authoring::layout::{
    ACCESS_DIRECTORY, FIXTURES_DIRECTORY, MAX_DERIVATION_BYTES, MAX_OPENAPI_BYTES,
    MAX_SOURCE_ARTIFACT_BYTES, OPENAPI_FILE, SCHEMAS_DIRECTORY,
};
use registry_platform_yaml::{Diagnostic, Report, Severity, MAXIMUM_DOCUMENT_BYTES};
use std::{
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{self, Read as _},
    os::unix::{
        ffi::OsStrExt as _,
        fs::{symlink, DirBuilderExt as _, MetadataExt as _, PermissionsExt as _},
    },
    path::{Path, PathBuf},
};
const TARGETS_DIRECTORY: &str = "targets";
const MOCKS_DIRECTORY: &str = "mocks";
const MAX_SNAPSHOT_ENTRIES: usize = 1024;
const MAX_SNAPSHOT_DEPTH: usize = 16;
#[derive(Debug)]
pub(crate) struct ProjectSnapshot {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    directories: Vec<PathBuf>,
}

impl ProjectSnapshot {
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
}

impl Drop for ProjectSnapshot {
    fn drop(&mut self) {
        for directory in &self.directories {
            let _ = fs::set_permissions(directory, fs::Permissions::from_mode(0o700));
        }
    }
}

/// How much of one captured file the snapshot keeps.
#[derive(Clone, Copy)]
enum Bound {
    /// A file the shared reader reads: kept up to one byte past the reader's
    /// document limit, so an oversized document is refused by the reader,
    /// with `yaml.too-large`, like every other configuration file.
    ForReader,
    /// Any other project file, refused above this many bytes.
    Refuse(u64),
}

#[derive(Clone, Copy)]
enum Selection {
    All,
    Yaml,
}

/// The snapshot being captured: its root, every directory created under it,
/// and the number of files, links and directories copied below its root.
struct Capture {
    root: PathBuf,
    directories: Vec<PathBuf>,
    entries: usize,
}

impl Capture {
    fn record_entry(&mut self, relative: &Path) -> Result<()> {
        if relative.components().count() > MAX_SNAPSHOT_DEPTH
            || self.entries >= MAX_SNAPSHOT_ENTRIES
        {
            return Err(InspectionDiagnostic::at(relative, Inspection::TreeTooLarge).into());
        }
        self.entries += 1;
        Ok(())
    }
}

pub(crate) fn capture_project(project: &Path) -> Result<ProjectSnapshot> {
    let metadata = fs::symlink_metadata(project)
        .with_context(|| format!("inspecting project root {}", project.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(InspectionDiagnostic {
            path: String::new(),
            condition: Inspection::NotDirectory,
        }
        .into());
    }
    let temporary_root = std::env::temp_dir()
        .canonicalize()
        .context("resolving the private project snapshot parent")?;
    capture_project_in(project, &temporary_root).map_err(|error| {
        if let Some(refusal) = error.downcast_ref::<InspectionDiagnostic>() {
            Report::new(vec![refusal.diagnostic_in(project)]).into()
        } else {
            error
        }
    })
}

fn capture_project_in(project: &Path, temporary_root: &Path) -> Result<ProjectSnapshot> {
    use rustix::fs::{Mode, OFlags};

    let project_descriptor = rustix::fs::open(
        project,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(io::Error::from)
    .context("opening the authoring project without following links")?;
    let temporary = tempfile::Builder::new()
        .prefix("evidencectl-project-snapshot-")
        .tempdir_in(temporary_root)
        .context("creating private project snapshot")?;
    let root = temporary.path().join("project");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .context("creating private project snapshot root")?;
    let mut capture = Capture {
        directories: vec![root.clone()],
        root,
        entries: 0,
    };

    for (relative, bound) in [
        (
            registry_evidence_authoring::project::PROJECT_FILE,
            Bound::ForReader,
        ),
        (OPENAPI_FILE, Bound::Refuse(MAX_OPENAPI_BYTES)),
    ] {
        capture_snapshot_entry_at(
            &project_descriptor,
            &mut capture,
            OsStr::new(relative),
            Path::new(relative),
            bound,
        )?;
    }
    for (relative, bound) in [
        ("functions", Bound::Refuse(MAX_DERIVATION_BYTES)),
        (SCHEMAS_DIRECTORY, Bound::Refuse(MAX_SOURCE_ARTIFACT_BYTES)),
        (FIXTURES_DIRECTORY, Bound::Refuse(MAX_SOURCE_ARTIFACT_BYTES)),
        ("adapters", Bound::Refuse(MAX_SOURCE_ARTIFACT_BYTES)),
        ("queries", Bound::Refuse(MAX_SOURCE_ARTIFACT_BYTES)),
        ("codelists", Bound::Refuse(MAX_SOURCE_ARTIFACT_BYTES)),
    ] {
        capture_directory_at(
            &project_descriptor,
            &mut capture,
            OsStr::new(relative),
            Path::new(relative),
            bound,
            Selection::All,
        )?;
    }
    capture_access(&project_descriptor, &mut capture)?;
    for directory in [TARGETS_DIRECTORY, MOCKS_DIRECTORY] {
        capture_directory_at(
            &project_descriptor,
            &mut capture,
            OsStr::new(directory),
            Path::new(directory),
            Bound::ForReader,
            Selection::Yaml,
        )?;
    }
    capture_root_yaml(&project_descriptor, &mut capture)?;

    let Capture {
        root,
        mut directories,
        entries: _,
    } = capture;
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    let snapshot = ProjectSnapshot {
        _temporary: temporary,
        root,
        directories,
    };
    for directory in &snapshot.directories {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o500)).with_context(|| {
            format!("sealing project snapshot directory {}", directory.display())
        })?;
    }
    Ok(snapshot)
}

fn capture_access(project: &rustix::fd::OwnedFd, capture: &mut Capture) -> Result<()> {
    let relative = Path::new(ACCESS_DIRECTORY);
    let Some(access) = open_snapshot_directory(project, OsStr::new(ACCESS_DIRECTORY), relative)?
    else {
        return Ok(());
    };
    capture.record_entry(relative)?;
    let destination = capture.root.join(relative);
    fs::DirBuilder::new().mode(0o700).create(&destination)?;
    capture.directories.push(destination);
    capture_directory_at(
        &access,
        capture,
        OsStr::new("clients"),
        &relative.join("clients"),
        Bound::ForReader,
        Selection::All,
    )?;
    Ok(())
}

fn capture_directory_at(
    parent: &rustix::fd::OwnedFd,
    capture: &mut Capture,
    name: &OsStr,
    relative: &Path,
    bound: Bound,
    selection: Selection,
) -> Result<()> {
    let Some(directory) = open_snapshot_directory(parent, name, relative)? else {
        return Ok(());
    };
    capture.record_entry(relative)?;
    let destination = capture.root.join(relative);
    fs::DirBuilder::new().mode(0o700).create(&destination)?;
    capture.directories.push(destination);
    capture_directory_contents(&directory, capture, relative, bound, selection)
}

fn capture_directory_contents(
    directory: &rustix::fd::OwnedFd,
    capture: &mut Capture,
    relative: &Path,
    bound: Bound,
    selection: Selection,
) -> Result<()> {
    let names = directory_entries(
        directory,
        relative,
        MAX_SNAPSHOT_ENTRIES.saturating_sub(capture.entries) + 1,
        |name| {
            if matches!(selection, Selection::All) {
                return Ok(true);
            }
            Ok(
                snapshot_entry_type(directory, name)?.is_some_and(|file_type| {
                    file_type.is_dir() || file_type.is_symlink() || is_yaml_name(name)
                }),
            )
        },
    )?;
    for name in names {
        let entry_relative = relative.join(&name);
        let Some(file_type) = snapshot_entry_type(directory, &name)? else {
            continue;
        };
        if file_type.is_dir() {
            capture_directory_at(directory, capture, &name, &entry_relative, bound, selection)?;
            continue;
        }
        // Targets and mocks retain YAML documents and every link for authoring
        // validation. Public keys and mock bodies remain with their consumers.
        if matches!(selection, Selection::All) || file_type.is_symlink() || is_yaml_name(&name) {
            capture_snapshot_entry_at(directory, capture, &name, &entry_relative, bound)?;
        }
    }
    Ok(())
}

/// Relevant names, sorted, without `.` and `..`. The caller allows one name
/// beyond its remaining capture budget so the exact-limit refusal stays at the
/// entry. Larger listings are refused here without retaining ignored names.
fn directory_entries(
    directory: &rustix::fd::OwnedFd,
    relative: &Path,
    maximum: usize,
    mut include: impl FnMut(&OsStr) -> Result<bool>,
) -> Result<Vec<OsString>> {
    let mut entries = Vec::new();
    for entry in rustix::fs::Dir::read_from(directory).map_err(io::Error::from)? {
        let entry = entry.map_err(io::Error::from)?;
        let name = OsStr::from_bytes(entry.file_name().to_bytes());
        if name == "." || name == ".." || !include(name)? {
            continue;
        }
        if entries.len() >= maximum {
            return Err(InspectionDiagnostic::at(relative, Inspection::TreeTooLarge).into());
        }
        entries.push(name.to_owned());
    }
    entries.sort();
    Ok(entries)
}

fn snapshot_entry_type(
    directory: &rustix::fd::OwnedFd,
    name: &OsStr,
) -> Result<Option<rustix::fs::FileType>> {
    use rustix::fs::{AtFlags, FileType};

    match rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(metadata) => Ok(Some(FileType::from_raw_mode(metadata.st_mode))),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(io::Error::from(error)).context("inspecting project snapshot input"),
    }
}

/// Whether a file name is a YAML file's, by its extension.
fn is_yaml_name(name: &OsStr) -> bool {
    matches!(
        Path::new(name).extension().and_then(OsStr::to_str),
        Some("yaml" | "yml")
    )
}

/// Capture the YAML files at the project root other than the marker and the
/// OpenAPI description, so the check can identify each by its envelope.
fn capture_root_yaml(project: &rustix::fd::OwnedFd, capture: &mut Capture) -> Result<()> {
    let entries = directory_entries(
        project,
        Path::new(""),
        MAX_SNAPSHOT_ENTRIES.saturating_sub(capture.entries) + 1,
        |name| {
            if name == registry_evidence_authoring::project::PROJECT_FILE
                || name == OPENAPI_FILE
                || !is_yaml_name(name)
            {
                return Ok(false);
            }
            Ok(snapshot_entry_type(project, name)?.is_some_and(|file_type| !file_type.is_dir()))
        },
    )?;
    for entry in entries {
        let Some(file_type) = snapshot_entry_type(project, &entry)? else {
            continue;
        };
        if file_type.is_dir() {
            continue;
        }
        capture_snapshot_entry_at(
            project,
            capture,
            &entry,
            Path::new(&entry),
            Bound::ForReader,
        )?;
    }
    Ok(())
}

fn open_snapshot_directory(
    parent: &rustix::fd::OwnedFd,
    name: &OsStr,
    relative: &Path,
) -> Result<Option<rustix::fd::OwnedFd>> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};

    let metadata = match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(metadata) => metadata,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => {
            return Err(io::Error::from(error)).context("inspecting project snapshot directory")
        }
    };
    if !FileType::from_raw_mode(metadata.st_mode).is_dir() {
        return Err(InspectionDiagnostic::at(relative, Inspection::NotPlain).into());
    }

    match rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    ) {
        Ok(directory) => Ok(Some(directory)),
        Err(error) => Err(snapshot_open_error(error, relative, "directory")),
    }
}

fn snapshot_open_error(
    error: rustix::io::Errno,
    relative: &Path,
    input_kind: &str,
) -> anyhow::Error {
    if snapshot_open_race(error) {
        InspectionDiagnostic::at(relative, Inspection::Changed).into()
    } else {
        anyhow::Error::new(io::Error::from(error)).context(format!(
            "opening project snapshot {input_kind} {}",
            relative.display()
        ))
    }
}

fn snapshot_open_race(error: rustix::io::Errno) -> bool {
    matches!(
        error,
        rustix::io::Errno::NOENT | rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR
    )
}

fn capture_snapshot_entry_at(
    parent: &rustix::fd::OwnedFd,
    capture: &mut Capture,
    name: &OsStr,
    relative: &Path,
    bound: Bound,
) -> Result<()> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};

    let metadata = match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(metadata) => metadata,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(error) => {
            return Err(io::Error::from(error)).context("inspecting project snapshot input")
        }
    };
    let destination = capture.root.join(relative);
    let file_type = FileType::from_raw_mode(metadata.st_mode);
    capture.record_entry(relative)?;
    if file_type.is_symlink() {
        let target = rustix::fs::readlinkat(parent, name, Vec::new()).map_err(io::Error::from)?;
        symlink(OsStr::from_bytes(target.to_bytes()), &destination)?;
    } else if file_type.is_dir() {
        fs::DirBuilder::new().mode(0o700).create(&destination)?;
        capture.directories.push(destination);
    } else if file_type.is_file() {
        let descriptor = match rustix::fs::openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(error) => return Err(snapshot_open_error(error, relative, "input")),
        };
        let bytes = read_bounded_descriptor(descriptor, bound, relative)?;
        fs::write(&destination, bytes)?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o400))?;
    } else {
        return Err(InspectionDiagnostic::at(relative, Inspection::NotPlain).into());
    }
    Ok(())
}

/// A project entry the check refuses before reading it as an authored
/// document, named by its path inside the project.
#[derive(Debug)]
struct InspectionDiagnostic {
    path: String,
    condition: Inspection,
}

#[derive(Clone, Copy, Debug)]
enum Inspection {
    /// The project root is a link or not a directory.
    NotDirectory,
    /// An entry is a link, a hard-linked file, or a special file.
    NotPlain,
    /// A file is larger than its directory takes.
    TooLarge,
    /// The captured tree exceeds its depth or total entry ceiling.
    TreeTooLarge,
    /// An entry changed while the project was being captured.
    Changed,
}

impl InspectionDiagnostic {
    fn at(relative: &Path, condition: Inspection) -> Self {
        Self {
            path: relative.to_string_lossy().into_owned(),
            condition,
        }
    }

    fn parts(&self) -> (&'static str, &'static str, &'static str) {
        match self.condition {
            Inspection::NotDirectory => (
                "evidence.project.not-directory",
                "the project path is not a plain directory",
                "Pass the path of the project directory itself, not a link to it or a file.",
            ),
            Inspection::NotPlain => (
                "evidence.project.not-plain-file",
                "the project entry is a link, a hard-linked file, or a special file",
                "Replace the entry with a plain file or directory of its own inside the project.",
            ),
            Inspection::TooLarge => (
                "evidence.project.file-too-large",
                "the file is larger than its project directory takes",
                "Split or reduce the file; the authoring project reference lists each directory's limit.",
            ),
            Inspection::TreeTooLarge => (
                "evidence.project.tree-too-large",
                "the project snapshot exceeds its entry or depth limit",
                "Reduce captured project assets to at most 1024 files, links and directories, with paths of at most 16 components inside the project.",
            ),
            Inspection::Changed => (
                "evidence.project.changed",
                "the project entry changed while the project was being read",
                "Rerun the command once nothing else is writing to the project.",
            ),
        }
    }

    /// The diagnostic, naming the entry by its path inside the project.
    fn diagnostic(&self) -> Diagnostic {
        let (code, message, action) = self.parts();
        authored::file_diagnostic(Severity::Error, code, None, &self.path, "", message, action)
    }

    /// The diagnostic, naming the entry from the project path as given.
    fn diagnostic_in(&self, project: &Path) -> Diagnostic {
        let report = authored::rebase(Report::new(vec![self.diagnostic()]), project);
        report
            .into_diagnostics()
            .pop()
            .expect("one diagnostic was rebased")
    }
}

impl std::fmt::Display for InspectionDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.parts().1)
    }
}

impl std::error::Error for InspectionDiagnostic {}

fn read_bounded_descriptor(
    descriptor: rustix::fd::OwnedFd,
    bound: Bound,
    relative: &Path,
) -> Result<Vec<u8>> {
    let mut file = File::from(descriptor);
    let metadata = file.metadata().context("inspecting authored input")?;
    read_bounded_file(&mut file, &metadata, bound, relative)
}

fn read_bounded_file(
    file: &mut File,
    metadata: &fs::Metadata,
    bound: Bound,
    relative: &Path,
) -> Result<Vec<u8>> {
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(InspectionDiagnostic::at(relative, Inspection::NotPlain).into());
    }
    let limit = match bound {
        Bound::ForReader => u64::try_from(MAXIMUM_DOCUMENT_BYTES)
            .unwrap_or(u64::MAX)
            .saturating_add(1),
        Bound::Refuse(maximum) => {
            if metadata.len() > maximum {
                return Err(InspectionDiagnostic::at(relative, Inspection::TooLarge).into());
            }
            maximum.saturating_add(1)
        }
    };
    let mut bytes = Vec::new();
    file.by_ref()
        .take(limit)
        .read_to_end(&mut bytes)
        .context("reading authored input")?;
    let after = file.metadata().context("reinspecting authored input")?;
    // Detect ordinary in-place editor writes. Path replacement may unlink the
    // captured inode without changing its bytes, so neither ctime nor link count
    // determines content stability. This is not an atomic whole-project capture.
    if metadata.len() != after.len()
        || metadata.mtime() != after.mtime()
        || metadata.mtime_nsec() != after.mtime_nsec()
    {
        return Err(InspectionDiagnostic::at(relative, Inspection::Changed).into());
    }
    if let Bound::Refuse(maximum) = bound {
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
            return Err(InspectionDiagnostic::at(relative, Inspection::TooLarge).into());
        }
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    fn temporary() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }
    fn put_marker(root: &Path) {
        fs::write(root.join("evidence.yaml"), "kind: EvidenceProject\n").unwrap();
    }
    fn is_operational(error: &anyhow::Error) -> bool {
        error
            .chain()
            .any(|cause| cause.downcast_ref::<io::Error>().is_some())
    }

    #[test]
    fn project_snapshot_refuses_in_place_changes_after_descriptor_inspection() {
        for replacement in ["id: x\n", "id: extended\n", "id: second\n"] {
            for bound in [Bound::ForReader, Bound::Refuse(1024)] {
                let temporary = temporary();
                let input = temporary.path().join("evidence.yaml");
                fs::write(&input, "id: first!\n").unwrap();
                let mut file = File::open(&input).unwrap();
                let before_write = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1);
                file.set_times(fs::FileTimes::new().set_modified(before_write))
                    .unwrap();
                let metadata = file.metadata().unwrap();

                // Deterministically place an in-place editor save inside the
                // capture interval, after inspection and before the bounded read.
                fs::write(&input, replacement).unwrap();
                let after_write = before_write + std::time::Duration::from_secs(1);
                file.set_times(fs::FileTimes::new().set_modified(after_write))
                    .unwrap();
                let error =
                    read_bounded_file(&mut file, &metadata, bound, Path::new("evidence.yaml"))
                        .unwrap_err();
                let refusal = error.downcast_ref::<InspectionDiagnostic>().unwrap();
                assert_eq!(refusal.diagnostic().code, "evidence.project.changed");
                assert_eq!(refusal.path, "evidence.yaml");
                assert!(!is_operational(&error));
                assert!(!error.to_string().contains(replacement.trim()));
            }
        }
    }

    #[test]
    fn project_snapshot_reads_captured_inode_after_editor_path_replacement() {
        for bound in [Bound::ForReader, Bound::Refuse(1024)] {
            let temporary = temporary();
            let input = temporary.path().join("evidence.yaml");
            let replacement = temporary.path().join("editor-save.yaml");
            fs::write(&input, "id: captured\n").unwrap();
            let mut file = File::open(&input).unwrap();
            let metadata = file.metadata().unwrap();
            fs::write(&replacement, "id: replacement\n").unwrap();
            fs::rename(&replacement, &input).unwrap();

            assert_eq!(
                read_bounded_file(&mut file, &metadata, bound, Path::new("evidence.yaml")).unwrap(),
                b"id: captured\n"
            );
            assert_eq!(fs::read(&input).unwrap(), b"id: replacement\n");
        }
    }

    #[test]
    fn project_snapshot_cleanup_removes_sealed_success_and_partial_refusal_trees() {
        let temporary = temporary();
        let project = temporary.path().join("project");
        fs::create_dir_all(project.join("functions")).unwrap();
        put_marker(&project);

        let snapshot = capture_project_in(&project, temporary.path()).unwrap();
        let snapshot_path = snapshot._temporary.path().to_path_buf();
        assert!(snapshot_path.exists());
        drop(snapshot);
        assert!(!snapshot_path.exists());

        fs::write(
            project.join("functions/oversized.rhai"),
            vec![b'x'; usize::try_from(MAX_DERIVATION_BYTES).unwrap() + 1],
        )
        .unwrap();
        assert!(capture_project_in(&project, temporary.path()).is_err());
        assert!(fs::read_dir(temporary.path()).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("evidencectl-project-snapshot-")));
    }

    #[test]
    fn project_snapshot_yaml_selection_preserves_documents_and_links_only() {
        let temporary = temporary();
        let project = temporary.path().join("project");
        fs::create_dir(&project).unwrap();
        put_marker(&project);
        for directory in [TARGETS_DIRECTORY, MOCKS_DIRECTORY] {
            let nested = project.join(directory).join("local/nested");
            fs::create_dir_all(&nested).unwrap();
            for name in ["document.yaml", "document.yml"] {
                fs::write(nested.join(name), "kind: Example\n").unwrap();
            }
            fs::write(nested.join("body.json"), "{}").unwrap();
            fs::write(nested.join("public.pem"), "public key fixture").unwrap();
            symlink("missing", nested.join("linked.pem")).unwrap();
        }

        let snapshot = capture_project_in(&project, temporary.path()).unwrap();
        for directory in [TARGETS_DIRECTORY, MOCKS_DIRECTORY] {
            let nested = snapshot.root().join(directory).join("local/nested");
            for name in ["document.yaml", "document.yml"] {
                assert_eq!(
                    fs::read_to_string(nested.join(name)).unwrap(),
                    "kind: Example\n"
                );
            }
            assert!(!nested.join("body.json").exists());
            assert!(!nested.join("public.pem").exists());
            assert_eq!(
                fs::read_link(nested.join("linked.pem")).unwrap(),
                Path::new("missing")
            );
        }
    }

    #[test]
    fn project_snapshot_listing_is_sorted_and_refuses_before_retaining_excess_names() {
        use rustix::fs::{Mode, OFlags};

        let temporary = temporary();
        for name in ["c.yaml", "a.yaml", "b.yaml", "ignored.body"] {
            fs::write(temporary.path().join(name), "fixture").unwrap();
        }
        let directory = rustix::fs::open(
            temporary.path(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let names = directory_entries(&directory, Path::new("targets"), 3, |name| {
            Ok(is_yaml_name(name))
        })
        .unwrap();
        assert_eq!(names, ["a.yaml", "b.yaml", "c.yaml"].map(OsString::from));

        fs::write(temporary.path().join("d.yaml"), "fixture").unwrap();
        fs::write(temporary.path().join("e.yaml"), "fixture").unwrap();
        let mut relevant_names = 0;
        let error = directory_entries(&directory, Path::new("targets"), 3, |name| {
            if is_yaml_name(name) {
                relevant_names += 1;
                Ok(true)
            } else {
                Ok(false)
            }
        })
        .unwrap_err();
        // Three retained names and one excess name trigger refusal immediately,
        // without collecting the remainder or returning a truncated success.
        assert_eq!(relevant_names, 4);
        let refusal = error.downcast_ref::<InspectionDiagnostic>().unwrap();
        assert!(matches!(refusal.condition, Inspection::TreeTooLarge));
        assert_eq!(refusal.path, "targets");
    }

    #[test]
    fn project_snapshot_many_ignored_files_do_not_consume_the_capture_budget() {
        let temporary = temporary();
        let project = temporary.path().join("project");
        fs::create_dir_all(project.join(TARGETS_DIRECTORY)).unwrap();
        fs::create_dir(project.join(MOCKS_DIRECTORY)).unwrap();
        put_marker(&project);
        for directory in ["", TARGETS_DIRECTORY, MOCKS_DIRECTORY] {
            for index in 0..MAX_SNAPSHOT_ENTRIES + 5 {
                fs::write(
                    project.join(directory).join(format!("{index:04}.body")),
                    "ignored",
                )
                .unwrap();
            }
            fs::write(
                project.join(directory).join("document.yaml"),
                "kind: Example\n",
            )
            .unwrap();
        }
        // Root directories with YAML names are also outside the root document
        // selection; target/mock links remain selected despite their extension.
        fs::create_dir(project.join("ignored.yaml")).unwrap();
        symlink("missing", project.join("targets/linked.pem")).unwrap();
        symlink("missing", project.join("mocks/linked.body")).unwrap();

        let snapshot = capture_project_in(&project, temporary.path()).unwrap();
        for directory in ["", TARGETS_DIRECTORY, MOCKS_DIRECTORY] {
            let captured = snapshot.root().join(directory);
            assert!(captured.join("document.yaml").exists());
            assert!(!captured.join("0000.body").exists());
        }
        assert!(!snapshot.root().join("ignored.yaml").exists());
        for link in ["targets/linked.pem", "mocks/linked.body"] {
            assert_eq!(
                fs::read_link(snapshot.root().join(link)).unwrap(),
                Path::new("missing")
            );
        }
    }

    #[test]
    fn project_snapshot_depth_limit_applies_to_assets_targets_and_mocks() {
        for directory in ["functions", TARGETS_DIRECTORY, MOCKS_DIRECTORY] {
            let temporary = temporary();
            let project = temporary.path().join("project");
            let mut relative = PathBuf::from(directory);
            for _ in 1..MAX_SNAPSHOT_DEPTH - 1 {
                relative.push("nested");
            }
            fs::create_dir_all(project.join(&relative)).unwrap();
            put_marker(&project);
            fs::write(
                project.join(&relative).join("document.yaml"),
                "kind: Example\n",
            )
            .unwrap();
            let snapshot = capture_project_in(&project, temporary.path()).unwrap();
            assert!(snapshot
                .root()
                .join(&relative)
                .join("document.yaml")
                .exists());
            drop(snapshot);

            relative.push("nested");
            fs::create_dir(project.join(&relative)).unwrap();
            relative.push("document.yaml");
            fs::write(project.join(&relative), "kind: Example\n").unwrap();
            let error = capture_project_in(&project, temporary.path()).unwrap_err();
            let refusal = error.downcast_ref::<InspectionDiagnostic>().unwrap();
            assert!(matches!(refusal.condition, Inspection::TreeTooLarge));
            assert_eq!(refusal.path, relative.to_string_lossy());
            assert!(!is_operational(&error));
            assert!(fs::read_dir(temporary.path()).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("evidencectl-project-snapshot-")));
        }
    }

    #[test]
    fn project_snapshot_entry_limit_is_shared_by_assets_targets_mocks_and_root_yaml() {
        let temporary = temporary();
        let project = temporary.path().join("project");
        fs::create_dir_all(project.join("functions")).unwrap();
        fs::create_dir(project.join(TARGETS_DIRECTORY)).unwrap();
        fs::create_dir(project.join(MOCKS_DIRECTORY)).unwrap();
        put_marker(&project);
        // Marker, three directories, two YAML documents and one retained link.
        for index in 0..MAX_SNAPSHOT_ENTRIES - 7 {
            fs::write(project.join(format!("functions/{index:04}.rhai")), "()").unwrap();
        }
        fs::write(
            project.join("targets/target.yaml"),
            "kind: EvidenceTarget\n",
        )
        .unwrap();
        fs::write(project.join("mocks/source.yml"), "kind: EvidenceMockPlan\n").unwrap();
        symlink("missing", project.join("targets/linked.pem")).unwrap();

        let snapshot = capture_project_in(&project, temporary.path()).unwrap();
        assert!(snapshot.root().join("targets/target.yaml").exists());
        assert!(snapshot.root().join("mocks/source.yml").exists());
        drop(snapshot);

        fs::write(project.join("extra.yaml"), "kind: Example\n").unwrap();
        let error = capture_project(&project).unwrap_err();
        let diagnostic = &error.downcast_ref::<Report>().unwrap().diagnostics()[0];
        assert_eq!(diagnostic.code, "evidence.project.tree-too-large");
        assert!(diagnostic
            .source
            .as_ref()
            .unwrap()
            .file
            .ends_with("/extra.yaml"));
    }

    #[test]
    fn project_snapshot_entry_limit_counts_empty_directories() {
        let temporary = temporary();
        let project = temporary.path().join("project");
        fs::create_dir_all(project.join(TARGETS_DIRECTORY)).unwrap();
        put_marker(&project);
        for index in 0..MAX_SNAPSHOT_ENTRIES - 2 {
            fs::create_dir(project.join(format!("targets/{index:04}"))).unwrap();
        }
        let snapshot = capture_project_in(&project, temporary.path()).unwrap();
        drop(snapshot);

        fs::create_dir(project.join(MOCKS_DIRECTORY)).unwrap();
        let error = capture_project_in(&project, temporary.path()).unwrap_err();
        let refusal = error.downcast_ref::<InspectionDiagnostic>().unwrap();
        assert!(matches!(refusal.condition, Inspection::TreeTooLarge));
        assert_eq!(refusal.path, MOCKS_DIRECTORY);
    }

    #[test]
    fn symlinked_access_parent_cannot_disclose_external_client_names() {
        const CANARY: &str = "EXTERNAL_CLIENT_NAME_CANARY";
        let temporary = temporary();
        let project = temporary.path().join("project");
        let outside = temporary.path().join("outside");
        fs::create_dir_all(project.join("functions")).unwrap();
        fs::create_dir_all(outside.join("clients")).unwrap();
        put_marker(&project);
        fs::write(outside.join(format!("clients/{CANARY}.yaml")), CANARY).unwrap();
        symlink(&outside, project.join("access")).unwrap();

        let error = capture_project(&project).unwrap_err();
        let report = error.downcast_ref::<Report>().unwrap();
        assert_eq!(
            report.diagnostics()[0].code,
            "evidence.project.not-plain-file"
        );
        assert!(report.diagnostics()[0]
            .source
            .as_ref()
            .unwrap()
            .file
            .ends_with("/access"));
        assert!(!error.to_string().contains(CANARY));
    }

    #[test]
    fn snapshot_open_errors_preserve_custody_and_operational_classification() {
        for error in [
            rustix::io::Errno::NOENT,
            rustix::io::Errno::LOOP,
            rustix::io::Errno::NOTDIR,
        ] {
            let error = snapshot_open_error(error, Path::new("functions"), "directory");
            assert!(!is_operational(&error));
            assert!(error.downcast_ref::<InspectionDiagnostic>().is_some());
        }

        for error in [rustix::io::Errno::ACCESS, rustix::io::Errno::IO] {
            let error = snapshot_open_error(error, Path::new("functions"), "directory");
            assert!(is_operational(&error));
            assert!(error.downcast_ref::<InspectionDiagnostic>().is_none());
        }
    }

    #[test]
    fn opened_directory_snapshot_cannot_escape_after_path_replacement() {
        use rustix::fs::{Mode, OFlags};

        const CANARY: &str = "EXTERNAL_DIRECTORY_CANARY";
        let temporary = temporary();
        let project = temporary.path().join("project");
        let outside = temporary.path().join("outside");
        let snapshot = temporary.path().join("snapshot");
        fs::create_dir_all(project.join("functions")).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::create_dir_all(snapshot.join("functions")).unwrap();
        fs::write(project.join("functions/captured.yaml"), "id: captured\n").unwrap();
        fs::write(outside.join(format!("{CANARY}.yaml")), CANARY).unwrap();
        let project_descriptor = rustix::fs::open(
            &project,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let functions = open_snapshot_directory(
            &project_descriptor,
            OsStr::new("functions"),
            Path::new("functions"),
        )
        .unwrap()
        .unwrap();
        fs::rename(
            project.join("functions"),
            project.join("captured-functions"),
        )
        .unwrap();
        symlink(&outside, project.join("functions")).unwrap();

        let mut capture = Capture {
            root: snapshot.clone(),
            directories: vec![snapshot.clone(), snapshot.join("functions")],
            entries: 0,
        };
        capture_directory_contents(
            &functions,
            &mut capture,
            Path::new("functions"),
            Bound::ForReader,
            Selection::All,
        )
        .unwrap();

        assert!(snapshot.join("functions/captured.yaml").exists());
        assert!(!snapshot.join(format!("functions/{CANARY}.yaml")).exists());
        assert_eq!(capture.entries, 1);
    }
}
