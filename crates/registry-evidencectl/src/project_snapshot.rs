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
        ffi::{OsStrExt as _, OsStringExt as _},
        fs::{symlink, DirBuilderExt as _, MetadataExt as _, PermissionsExt as _},
    },
    path::{Path, PathBuf},
};
const TARGETS_DIRECTORY: &str = "targets";
const MOCKS_DIRECTORY: &str = "mocks";
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

/// The snapshot being captured: its root, every directory created under it,
/// and the number of plain files copied.
struct Capture {
    root: PathBuf,
    directories: Vec<PathBuf>,
    files: usize,
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
        files: 0,
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
        capture_flat_directory_at(
            &project_descriptor,
            &mut capture,
            OsStr::new(relative),
            Path::new(relative),
            bound,
        )?;
    }
    capture_access(&project_descriptor, &mut capture)?;
    for directory in [TARGETS_DIRECTORY, MOCKS_DIRECTORY] {
        capture_yaml_tree_at(
            &project_descriptor,
            &mut capture,
            OsStr::new(directory),
            Path::new(directory),
        )?;
    }
    capture_root_yaml(&project_descriptor, &mut capture)?;

    let Capture {
        root,
        mut directories,
        files: _,
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
    let destination = capture.root.join(relative);
    fs::DirBuilder::new().mode(0o700).create(&destination)?;
    capture.directories.push(destination);
    capture_flat_directory_at(
        &access,
        capture,
        OsStr::new("clients"),
        &relative.join("clients"),
        Bound::ForReader,
    )?;
    Ok(())
}

fn capture_flat_directory_at(
    parent: &rustix::fd::OwnedFd,
    capture: &mut Capture,
    name: &OsStr,
    relative: &Path,
    bound: Bound,
) -> Result<()> {
    let Some(directory) = open_snapshot_directory(parent, name, relative)? else {
        return Ok(());
    };
    let destination = capture.root.join(relative);
    fs::DirBuilder::new().mode(0o700).create(&destination)?;
    capture.directories.push(destination);
    capture_directory_contents(&directory, capture, relative, bound)
}

fn capture_directory_contents(
    directory: &rustix::fd::OwnedFd,
    capture: &mut Capture,
    relative: &Path,
    bound: Bound,
) -> Result<()> {
    for name in directory_entries(directory)? {
        let entry_relative = relative.join(&name);
        if entry_relative.components().count() > 16 || capture.files > 1024 {
            return Err(InspectionDiagnostic::at(&entry_relative, Inspection::TooLarge).into());
        }
        let metadata = rustix::fs::statat(directory, &name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(io::Error::from)?;
        if rustix::fs::FileType::from_raw_mode(metadata.st_mode).is_dir() {
            capture_flat_directory_at(directory, capture, &name, &entry_relative, bound)?;
            continue;
        }
        capture_snapshot_entry_at(directory, capture, &name, &entry_relative, bound)?;
    }
    Ok(())
}

/// The names `directory` holds, sorted, without `.` and `..`.
fn directory_entries(directory: &rustix::fd::OwnedFd) -> Result<Vec<OsString>> {
    let mut entries = rustix::fs::Dir::read_from(directory)
        .map_err(io::Error::from)?
        .map(|entry| {
            entry
                .map(|entry| OsString::from_vec(entry.file_name().to_bytes().to_vec()))
                .map_err(io::Error::from)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    entries.retain(|name| name != "." && name != "..");
    entries.sort();
    Ok(entries)
}

/// Whether a file name is a YAML file's, by its extension.
fn is_yaml_name(name: &OsStr) -> bool {
    matches!(
        Path::new(name).extension().and_then(OsStr::to_str),
        Some("yaml" | "yml")
    )
}

/// Capture the YAML files of `targets/` or `mocks/`, at any depth, with every
/// link there, so the check reads each YAML file by its envelope and refuses
/// each link. Other files, such as public keys and mock response bodies, are
/// read by the commands that use them and are not copied.
fn capture_yaml_tree_at(
    parent: &rustix::fd::OwnedFd,
    capture: &mut Capture,
    name: &OsStr,
    relative: &Path,
) -> Result<()> {
    use rustix::fs::{AtFlags, FileType};

    let Some(directory) = open_snapshot_directory(parent, name, relative)? else {
        return Ok(());
    };
    let destination = capture.root.join(relative);
    fs::DirBuilder::new().mode(0o700).create(&destination)?;
    capture.directories.push(destination);
    for entry in directory_entries(&directory)? {
        let entry_relative = relative.join(&entry);
        let metadata = match rustix::fs::statat(&directory, &entry, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(metadata) => metadata,
            Err(rustix::io::Errno::NOENT) => continue,
            Err(error) => {
                return Err(io::Error::from(error)).context("inspecting project snapshot input")
            }
        };
        let file_type = FileType::from_raw_mode(metadata.st_mode);
        if file_type.is_dir() {
            capture_yaml_tree_at(&directory, capture, &entry, &entry_relative)?;
        } else if file_type.is_symlink() || is_yaml_name(&entry) {
            capture_snapshot_entry_at(
                &directory,
                capture,
                &entry,
                &entry_relative,
                Bound::ForReader,
            )?;
        }
    }
    Ok(())
}

/// Capture the YAML files at the project root other than the marker and the
/// OpenAPI description, so the check can identify each by its envelope.
fn capture_root_yaml(project: &rustix::fd::OwnedFd, capture: &mut Capture) -> Result<()> {
    use rustix::fs::{AtFlags, FileType};

    for entry in directory_entries(project)? {
        if entry == registry_evidence_authoring::project::PROJECT_FILE
            || entry == OPENAPI_FILE
            || !is_yaml_name(&entry)
        {
            continue;
        }
        let metadata = match rustix::fs::statat(project, &entry, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(metadata) => metadata,
            Err(rustix::io::Errno::NOENT) => continue,
            Err(error) => {
                return Err(io::Error::from(error)).context("inspecting project snapshot input")
            }
        };
        if FileType::from_raw_mode(metadata.st_mode).is_dir() {
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
        capture.files += 1;
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
            files: 0,
        };
        capture_directory_contents(
            &functions,
            &mut capture,
            Path::new("functions"),
            Bound::ForReader,
        )
        .unwrap();

        assert!(snapshot.join("functions/captured.yaml").exists());
        assert!(!snapshot.join(format!("functions/{CANARY}.yaml")).exists());
        assert_eq!(capture.files, 1);
    }
}
