//! Confined reads and create-only publication for source-mock artifacts.

use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fs::File,
    io::{Read as _, Write as _},
    os::{fd::OwnedFd, unix::fs::MetadataExt as _},
    path::{Component, Path, PathBuf},
};

use anyhow::{bail, Context as _, Result};
use registry_evidence_authoring::layout::MAX_OPENAPI_BYTES;
use rustix::{
    fs::{AtFlags, Mode, OFlags, RenameFlags},
    io::Errno,
};
#[cfg(test)]
use serde_json::Value;
#[cfg(test)]
use std::collections::BTreeMap;

use super::plan::{validate_relative_path, MAX_PATH_BYTES};

pub(super) const MAX_MOCK_BODY_BYTES: u64 = 512 * 1024;
pub(super) const MAX_PUBLICATION_FILES: usize = 1024;
pub(super) const MAX_PUBLICATION_FILE_BYTES: usize = MAX_OPENAPI_BYTES as usize;
pub(super) const MAX_PUBLICATION_TOTAL_BYTES: usize = 64 * 1024 * 1024;

const DIRECTORY_MODE: Mode = Mode::from_raw_mode(0o755);
const FILE_MODE: Mode = Mode::from_raw_mode(0o644);
const STAGE_ATTEMPTS: usize = 16;
const STAGE_PREFIX: &str = ".evidencectl-source-mock-stage-";

/// One already-validated artifact to publish relative to a mock root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PublicationFile {
    pub relative_path: PathBuf,
    pub bytes: Vec<u8>,
}

impl PublicationFile {
    pub fn new(relative_path: impl Into<PathBuf>, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            relative_path: relative_path.into(),
            bytes: bytes.into(),
        }
    }
}

/// Read an explicitly supplied OpenAPI file without following its leaf if it
/// is a symlink. Project-relative reads should use [`read_confined`] instead.
#[cfg(test)]
pub(super) fn read_openapi(path: &Path) -> Result<Vec<u8>> {
    read_bounded_regular(path, MAX_OPENAPI_BYTES, "OpenAPI document")
}

/// Read one bounded regular file without following a symlink at the leaf.
#[cfg(test)]
pub(super) fn read_bounded_regular(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>> {
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .with_context(|| format!("opening {label}"))?;
    read_descriptor(descriptor, maximum, label)
}

/// Read a path by walking every component beneath an explicitly held root.
/// No ancestor or leaf symlink is followed.
pub(super) fn read_confined(
    root: &Path,
    relative_path: &Path,
    maximum: u64,
    label: &str,
) -> Result<Vec<u8>> {
    let relative = relative_text(relative_path, label)?;
    validate_relative_path(&relative, label)?;
    let root = open_directory(root, label)?;
    let (parent, leaf) = open_parent(&root, relative_path, false, None, label)?
        .context("confined file parent does not exist")?;
    let descriptor = rustix::fs::openat(
        &parent,
        &leaf,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .with_context(|| format!("opening confined {label}"))?;
    read_descriptor(descriptor, maximum, label)
}

/// Resolve an OpenAPI reference relative to the config while confining the
/// normalized result to the explicitly supplied project root. This is the one
/// path surface that admits `..`; body and dataset paths do not.
pub(super) fn resolve_openapi_reference(
    project_root: &Path,
    config_path: &Path,
    configured: &str,
) -> Result<PathBuf> {
    if configured.is_empty()
        || configured.len() > MAX_PATH_BYTES
        || configured.contains('\\')
        || configured.chars().any(char::is_control)
        || Path::new(configured).is_absolute()
        || configured
            .split('/')
            .any(|part| part.is_empty() || part == ".")
    {
        bail!("openapi must be a bounded config-relative path");
    }

    let config_relative = if config_path.is_absolute() {
        config_path
            .strip_prefix(project_root)
            .context("mock config is outside the held project root")?
    } else {
        config_path
    };
    let config_text = relative_text(config_relative, "mock config")?;
    validate_relative_path(&config_text, "mock config")?;

    let mut components = config_relative
        .parent()
        .into_iter()
        .flat_map(Path::components)
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_os_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    for component in Path::new(configured).components() {
        match component {
            Component::Normal(part) => components.push(part.to_os_string()),
            Component::ParentDir => {
                if components.pop().is_none() {
                    bail!("openapi escapes the held project root");
                }
            }
            _ => bail!("openapi must be a normalized config-relative path"),
        }
    }
    if components.is_empty() {
        bail!("openapi must name a file beneath the held project root");
    }
    Ok(components.iter().collect())
}

pub(super) fn read_openapi_reference(
    project_root: &Path,
    config_path: &Path,
    configured: &str,
) -> Result<Vec<u8>> {
    let relative = resolve_openapi_reference(project_root, config_path, configured)?;
    read_confined(
        project_root,
        &relative,
        MAX_OPENAPI_BYTES,
        "OpenAPI document",
    )
}

/// Stable JSON bytes shared by generated files and ephemeral HTTP responses.
#[cfg(test)]
pub(super) fn stable_pretty_json(value: &Value) -> Result<Vec<u8>> {
    let canonical = sort_json(value);
    let mut bytes = serde_json::to_vec_pretty(&canonical).context("serializing JSON body")?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_MOCK_BODY_BYTES {
        bail!("JSON body exceeds the standalone byte limit");
    }
    Ok(bytes)
}

/// Publish a complete initial mock tree beside an absent destination and then
/// atomically rename the root without replacement.
pub(super) fn publish_initial_tree(
    output_config_path: &Path,
    files: &[PublicationFile],
) -> Result<Vec<PathBuf>> {
    let files = checked_files(files)?;
    let root = output_config_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .context("output config must be inside a mock root")?;
    let root_name = normal_leaf(root, "mock root")?;
    let parent_path = root
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let config_name = normal_leaf(output_config_path, "output config")?;
    if files
        .iter()
        .filter(|file| file.relative_path == Path::new(&config_name))
        .count()
        != 1
    {
        bail!("initial publication must contain the output config exactly once");
    }

    let parent = open_directory(parent_path, "mock root parent")?;
    ensure_absent(&parent, &root_name, "mock root")?;
    let (stage_name, stage) = create_stage(&parent)?;
    let mut published_root = false;
    let result: Result<Vec<PathBuf>> = (|| {
        populate_tree(&stage, &files)?;
        rustix::fs::fsync(&stage).context("persisting staged mock tree")?;
        rustix::fs::renameat_with(
            &parent,
            &stage_name,
            &parent,
            &root_name,
            RenameFlags::NOREPLACE,
        )
        .context("publishing mock root without replacement")?;
        published_root = true;
        rustix::fs::fsync(&parent).context("persisting mock-root publication")?;
        Ok(files
            .iter()
            .map(|file| file.relative_path.clone())
            .collect())
    })();
    if result.is_err() {
        let cleanup_name = if published_root {
            &root_name
        } else {
            &stage_name
        };
        remove_staged_tree(&parent, cleanup_name, &stage, &files);
    }
    result
}

/// Create every missing body without replacing any author-owned path. Once a
/// body is visible, a later failure preserves it; rerunning fills only the
/// bodies that are still missing.
pub(super) fn publish_missing(root: &Path, files: &[PublicationFile]) -> Result<Vec<PathBuf>> {
    publish_missing_with(root, files, |_, _| Ok(()))
}

fn publish_missing_with<F>(
    root_path: &Path,
    files: &[PublicationFile],
    mut before_publish: F,
) -> Result<Vec<PathBuf>>
where
    F: FnMut(usize, &PublicationFile) -> Result<()>,
{
    let files = checked_files(files)?;
    let root = open_directory(root_path, "mock root")?;
    for file in &files {
        ensure_destination_absent(&root, &file.relative_path)?;
    }
    let (stage_name, stage) = create_stage(&root)?;
    if let Err(error) = populate_tree(&stage, &files) {
        remove_staged_tree(&root, &stage_name, &stage, &files);
        return Err(error);
    }

    let mut published = Vec::new();
    let result: Result<()> = (|| {
        for (index, file) in files.iter().enumerate() {
            before_publish(index, file)?;
            let (destination_parent, leaf) =
                open_parent(&root, &file.relative_path, true, None, "body destination")?
                    .expect("create mode returns a parent");
            let (stage_parent, stage_leaf) =
                open_parent(&stage, &file.relative_path, false, None, "staged body")?
                    .expect("staged parent exists");
            rustix::fs::renameat_with(
                &stage_parent,
                &stage_leaf,
                &destination_parent,
                &leaf,
                RenameFlags::NOREPLACE,
            )
            .context("publishing body without replacement")?;
            published.push(file.relative_path.clone());
            rustix::fs::fsync(&destination_parent).context("persisting body publication")?;
        }
        Ok(())
    })();

    if let Err(error) = result {
        remove_staged_tree(&root, &stage_name, &stage, &files);
        return Err(error).context(
            "body publication stopped; any bodies already created were preserved and a rerun will complete the missing set",
        );
    }
    remove_staged_tree(&root, &stage_name, &stage, &files);
    rustix::fs::fsync(&root).context("persisting completed body publication")?;
    Ok(published)
}

fn read_descriptor(descriptor: OwnedFd, maximum: u64, label: &str) -> Result<Vec<u8>> {
    let mut file = File::from(descriptor);
    let before = file
        .metadata()
        .with_context(|| format!("inspecting {label}"))?;
    if !before.is_file() || before.len() > maximum {
        bail!("{label} must be a bounded regular file");
    }
    let capacity = usize::try_from(before.len())
        .unwrap_or(0)
        .min(maximum as usize);
    let mut bytes = Vec::with_capacity(capacity);
    std::io::Read::by_ref(&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {label}"))?;
    if bytes.len() as u64 > maximum {
        bail!("{label} exceeds its byte limit");
    }
    let after = file
        .metadata()
        .with_context(|| format!("rechecking {label}"))?;
    if file_identity(&before) != file_identity(&after) || after.len() != bytes.len() as u64 {
        bail!("{label} changed while it was read");
    }
    Ok(bytes)
}

fn file_identity(metadata: &std::fs::Metadata) -> (u64, u64, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

fn open_directory(path: &Path, label: &str) -> Result<OwnedFd> {
    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .with_context(|| format!("opening {label} as a plain directory"))
}

fn open_parent(
    root: &OwnedFd,
    path: &Path,
    create: bool,
    mut created: Option<&mut Vec<PathBuf>>,
    label: &str,
) -> Result<Option<(OwnedFd, OsString)>> {
    let components = normal_components(path, label)?;
    let (leaf, ancestors) = components.split_last().context("path must name a file")?;
    let mut current = rustix::fs::openat(
        root,
        ".",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )?;
    let mut walked = PathBuf::new();
    for component in ancestors {
        walked.push(component);
        match rustix::fs::openat(
            &current,
            component,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        ) {
            Ok(next) => current = next,
            Err(Errno::NOENT) if !create => return Ok(None),
            Err(Errno::NOENT) => {
                match rustix::fs::mkdirat(&current, component, DIRECTORY_MODE) {
                    Ok(()) => {
                        if let Some(paths) = created.as_deref_mut() {
                            paths.push(walked.clone());
                        }
                    }
                    Err(Errno::EXIST) => {}
                    Err(error) => return Err(error).context("creating publication directory"),
                }
                current = rustix::fs::openat(
                    &current,
                    component,
                    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
                    Mode::empty(),
                )
                .context("opening publication directory")?;
            }
            Err(error) => return Err(error).with_context(|| format!("walking {label}")),
        }
    }
    Ok(Some((current, leaf.clone())))
}

fn populate_tree(root: &OwnedFd, files: &[PublicationFile]) -> Result<()> {
    let mut created = Vec::new();
    for publication in files {
        let (parent, leaf) = open_parent(
            root,
            &publication.relative_path,
            true,
            Some(&mut created),
            "staged artifact",
        )?
        .expect("create mode returns a parent");
        let descriptor = rustix::fs::openat(
            &parent,
            &leaf,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            FILE_MODE,
        )
        .context("creating staged artifact")?;
        let mut file = File::from(descriptor);
        file.write_all(&publication.bytes)
            .context("writing staged artifact")?;
        file.sync_all().context("persisting staged artifact")?;
    }
    Ok(())
}

fn ensure_destination_absent(root: &OwnedFd, path: &Path) -> Result<()> {
    let Some((parent, leaf)) = open_parent(root, path, false, None, "body destination")? else {
        return Ok(());
    };
    ensure_absent(&parent, &leaf, "body destination")
}

fn ensure_absent(parent: &OwnedFd, leaf: &OsStr, label: &str) -> Result<()> {
    match rustix::fs::openat(
        parent,
        leaf,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(_) => bail!("{label} already exists"),
        Err(Errno::NOENT) => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspecting {label}")),
    }
}

fn create_stage(parent: &OwnedFd) -> Result<(OsString, OwnedFd)> {
    for _ in 0..STAGE_ATTEMPTS {
        let mut random = [0_u8; 12];
        getrandom::fill(&mut random).context("generating a staging name")?;
        let name = OsString::from(format!("{STAGE_PREFIX}{}", hex::encode(random)));
        match rustix::fs::mkdirat(parent, &name, DIRECTORY_MODE) {
            Ok(()) => {
                let descriptor = rustix::fs::openat(
                    parent,
                    &name,
                    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
                    Mode::empty(),
                )?;
                return Ok((name, descriptor));
            }
            Err(Errno::EXIST) => continue,
            Err(error) => return Err(error).context("creating publication staging directory"),
        }
    }
    bail!("could not allocate a unique publication staging directory")
}

fn checked_files(files: &[PublicationFile]) -> Result<Vec<PublicationFile>> {
    if files.is_empty() || files.len() > MAX_PUBLICATION_FILES {
        bail!("publication must contain a bounded non-empty file set");
    }
    let mut total = 0usize;
    let mut paths = BTreeSet::new();
    for file in files {
        let text = relative_text(&file.relative_path, "publication path")?;
        validate_relative_path(&text, "publication path")?;
        if file.bytes.len() > MAX_PUBLICATION_FILE_BYTES {
            bail!("publication file exceeds its byte limit");
        }
        total = total
            .checked_add(file.bytes.len())
            .context("publication byte count overflow")?;
        if total > MAX_PUBLICATION_TOTAL_BYTES {
            bail!("publication exceeds its total byte limit");
        }
        if !paths.insert(file.relative_path.clone()) {
            bail!("publication repeats a path");
        }
    }
    for path in &paths {
        let mut ancestor = path.parent();
        while let Some(candidate) = ancestor {
            if !candidate.as_os_str().is_empty() && paths.contains(candidate) {
                bail!("publication contains a file/directory path collision");
            }
            ancestor = candidate.parent();
        }
    }
    let mut checked = files.to_vec();
    checked.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(checked)
}

/// Remove only the random directory held by `stage`, using known publication
/// paths and directory descriptors so a concurrent path replacement cannot
/// redirect cleanup outside the staging tree.
fn remove_staged_tree(
    parent: &OwnedFd,
    stage_name: &OsStr,
    stage: &OwnedFd,
    files: &[PublicationFile],
) {
    for file in files.iter().rev() {
        if let Ok(Some((directory, leaf))) = open_parent(
            stage,
            &file.relative_path,
            false,
            None,
            "staged cleanup path",
        ) {
            let _ = rustix::fs::unlinkat(&directory, &leaf, AtFlags::empty());
        }
    }

    let mut directories = BTreeSet::new();
    for file in files {
        let mut parent = file.relative_path.parent();
        while let Some(path) = parent {
            if !path.as_os_str().is_empty() {
                directories.insert(path.to_path_buf());
            }
            parent = path.parent();
        }
    }
    let mut directories = directories.into_iter().collect::<Vec<_>>();
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for path in directories {
        if let Ok(Some((directory, leaf))) =
            open_parent(stage, &path, false, None, "staged cleanup directory")
        {
            let _ = rustix::fs::unlinkat(&directory, &leaf, AtFlags::REMOVEDIR);
        }
    }
    let _ = rustix::fs::fsync(stage);
    let _ = rustix::fs::unlinkat(parent, stage_name, AtFlags::REMOVEDIR);
    let _ = rustix::fs::fsync(parent);
}

#[cfg(test)]
fn sort_json(value: &Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| (key.clone(), sort_json(value)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(sort_json).collect()),
        scalar => scalar.clone(),
    }
}

fn relative_text(path: &Path, label: &str) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .with_context(|| format!("{label} must be UTF-8"))
}

fn normal_components(path: &Path, label: &str) -> Result<Vec<OsString>> {
    let text = relative_text(path, label)?;
    validate_relative_path(&text, label)?;
    Ok(path
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_os_string()),
            _ => None,
        })
        .collect())
}

fn normal_leaf(path: &Path, label: &str) -> Result<OsString> {
    path.file_name()
        .filter(|leaf| !leaf.is_empty())
        .map(OsStr::to_os_string)
        .with_context(|| format!("{label} must have a normal final component"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;

    fn artifact(path: &str, bytes: &[u8]) -> PublicationFile {
        PublicationFile::new(path, bytes)
    }

    #[test]
    fn stable_json_sorts_every_object_and_has_one_newline() {
        let bytes = stable_pretty_json(&json!({"z": 1, "a": {"y": 2, "b": 3}})).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "{\n  \"a\": {\n    \"b\": 3,\n    \"y\": 2\n  },\n  \"z\": 1\n}\n"
        );
    }

    #[test]
    fn bounded_reads_preserve_exact_bytes_and_refuse_leaf_symlinks() {
        let temporary = tempdir().unwrap();
        let original = temporary.path().join("source.yaml");
        let bytes = b"openapi: 3.1.0 # retained\n";
        std::fs::write(&original, bytes).unwrap();
        assert_eq!(read_openapi(&original).unwrap(), bytes);

        let link = temporary.path().join("linked.yaml");
        symlink(&original, &link).unwrap();
        assert!(read_openapi(&link).is_err());
        assert!(read_bounded_regular(&original, 2, "test file").is_err());
        assert!(read_bounded_regular(temporary.path(), 100, "test file").is_err());
    }

    #[test]
    fn config_parent_reference_is_confined_and_descriptor_walked() {
        let temporary = tempdir().unwrap();
        std::fs::create_dir(temporary.path().join("mocks")).unwrap();
        std::fs::write(temporary.path().join("source.openapi.yaml"), b"spec\n").unwrap();
        assert_eq!(
            resolve_openapi_reference(
                temporary.path(),
                &temporary.path().join("mocks/source.yaml"),
                "../source.openapi.yaml",
            )
            .unwrap(),
            PathBuf::from("source.openapi.yaml")
        );
        assert_eq!(
            read_openapi_reference(
                temporary.path(),
                &temporary.path().join("mocks/source.yaml"),
                "../source.openapi.yaml",
            )
            .unwrap(),
            b"spec\n"
        );
        assert!(resolve_openapi_reference(
            temporary.path(),
            &temporary.path().join("mocks/source.yaml"),
            "../../escape.yaml",
        )
        .is_err());

        std::fs::create_dir(temporary.path().join("outside")).unwrap();
        std::fs::write(temporary.path().join("outside/spec.yaml"), b"outside").unwrap();
        symlink(
            temporary.path().join("outside"),
            temporary.path().join("linked"),
        )
        .unwrap();
        assert!(read_confined(
            temporary.path(),
            Path::new("linked/spec.yaml"),
            100,
            "test file",
        )
        .is_err());
        symlink(
            temporary.path().join("source.openapi.yaml"),
            temporary.path().join("spec-link.yaml"),
        )
        .unwrap();
        assert!(read_confined(
            temporary.path(),
            Path::new("spec-link.yaml"),
            100,
            "test file",
        )
        .is_err());
    }

    #[test]
    fn initial_tree_is_exact_and_create_only() {
        let temporary = tempdir().unwrap();
        let config = temporary.path().join("mocks/source.yaml");
        let files = [
            artifact("source.yaml", b"version: 1\n"),
            artifact("cases/get/sample.json", b"{ \"exact\": true }\n"),
        ];
        let published = publish_initial_tree(&config, &files).unwrap();
        assert_eq!(
            published,
            vec![
                PathBuf::from("cases/get/sample.json"),
                PathBuf::from("source.yaml")
            ]
        );
        assert_eq!(std::fs::read(&config).unwrap(), b"version: 1\n");
        assert_eq!(
            std::fs::read(temporary.path().join("mocks/cases/get/sample.json")).unwrap(),
            b"{ \"exact\": true }\n"
        );
        assert!(publish_initial_tree(&config, &files).is_err());
        assert_eq!(std::fs::read(&config).unwrap(), b"version: 1\n");
    }

    #[test]
    fn invalid_initial_input_leaves_no_root() {
        let temporary = tempdir().unwrap();
        let config = temporary.path().join("mocks/source.yaml");
        let files = [
            artifact("source.yaml", b"config"),
            artifact("../escape", b"bad"),
        ];
        assert!(publish_initial_tree(&config, &files).is_err());
        assert!(!temporary.path().join("mocks").exists());
    }

    #[test]
    fn missing_publication_preserves_existing_even_when_empty() {
        let temporary = tempdir().unwrap();
        std::fs::create_dir(temporary.path().join("mocks")).unwrap();
        let existing = temporary.path().join("mocks/cases/existing.json");
        std::fs::create_dir_all(existing.parent().unwrap()).unwrap();
        std::fs::write(&existing, b"").unwrap();
        let files = [
            artifact("cases/new.json", b"new\n"),
            artifact("cases/existing.json", b"replacement\n"),
        ];
        assert!(publish_missing(&temporary.path().join("mocks"), &files).is_err());
        assert_eq!(std::fs::read(existing).unwrap(), b"");
        assert!(!temporary.path().join("mocks/cases/new.json").exists());
    }

    #[test]
    fn handled_commit_error_preserves_the_valid_published_subset_for_rerun() {
        let temporary = tempdir().unwrap();
        let root = temporary.path().join("mocks");
        std::fs::create_dir(&root).unwrap();
        let files = [
            artifact("a/one.json", b"one"),
            artifact("b/two.json", b"two"),
        ];
        let result = publish_missing_with(&root, &files, |index, file| {
            if index == 1 {
                let path = root.join(&file.relative_path);
                std::fs::create_dir_all(path.parent().unwrap())?;
                std::fs::write(path, b"racer")?;
            }
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read(root.join("a/one.json")).unwrap(), b"one");
        assert_eq!(std::fs::read(root.join("b/two.json")).unwrap(), b"racer");
        assert!(format!("{:#}", result.unwrap_err()).contains("a rerun will complete"));
        assert!(!std::fs::read_dir(&root).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(STAGE_PREFIX)
        }));
        std::fs::remove_file(root.join("b/two.json")).unwrap();
        assert_eq!(
            publish_missing(&root, &[artifact("b/two.json", b"two")]).unwrap(),
            vec![PathBuf::from("b/two.json")]
        );
        assert_eq!(std::fs::read(root.join("a/one.json")).unwrap(), b"one");
        assert_eq!(std::fs::read(root.join("b/two.json")).unwrap(), b"two");
    }

    #[test]
    fn handled_commit_error_preserves_a_concurrently_edited_published_file() {
        let temporary = tempdir().unwrap();
        let root = temporary.path().join("mocks");
        std::fs::create_dir(&root).unwrap();
        let files = [
            artifact("a/one.json", b"one"),
            artifact("b/two.json", b"two"),
        ];
        let result = publish_missing_with(&root, &files, |index, file| {
            if index == 1 {
                std::fs::write(root.join("a/one.json"), b"author edit")?;
                let path = root.join(&file.relative_path);
                std::fs::create_dir_all(path.parent().unwrap())?;
                std::fs::write(path, b"racer")?;
            }
            Ok(())
        });

        assert!(result.is_err());
        assert_eq!(
            std::fs::read(root.join("a/one.json")).unwrap(),
            b"author edit"
        );
        assert_eq!(std::fs::read(root.join("b/two.json")).unwrap(), b"racer");
    }

    #[test]
    fn handled_commit_error_preserves_a_concurrently_replaced_published_file() {
        let temporary = tempdir().unwrap();
        let root = temporary.path().join("mocks");
        std::fs::create_dir(&root).unwrap();
        let files = [
            artifact("a/one.json", b"one"),
            artifact("b/two.json", b"two"),
        ];
        let result = publish_missing_with(&root, &files, |index, file| {
            if index == 1 {
                let replacement = root.join("replacement.json");
                std::fs::write(&replacement, b"author replacement")?;
                std::fs::rename(replacement, root.join("a/one.json"))?;
                let path = root.join(&file.relative_path);
                std::fs::create_dir_all(path.parent().unwrap())?;
                std::fs::write(path, b"racer")?;
            }
            Ok(())
        });

        assert!(result.is_err());
        assert_eq!(
            std::fs::read(root.join("a/one.json")).unwrap(),
            b"author replacement"
        );
        assert_eq!(std::fs::read(root.join("b/two.json")).unwrap(), b"racer");
    }

    #[test]
    fn missing_publication_refuses_symlink_ancestors() {
        let temporary = tempdir().unwrap();
        let root = temporary.path().join("mocks");
        let outside = temporary.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        symlink(&outside, root.join("cases")).unwrap();
        assert!(publish_missing(&root, &[artifact("cases/a.json", b"body")]).is_err());
        assert!(!outside.join("a.json").exists());
    }

    #[test]
    fn held_root_and_output_parent_refuse_symlinks_at_the_trust_anchor() {
        let temporary = tempdir().unwrap();
        let real = temporary.path().join("real");
        std::fs::create_dir(&real).unwrap();
        symlink(&real, temporary.path().join("linked")).unwrap();

        assert!(read_confined(
            &temporary.path().join("linked"),
            Path::new("missing"),
            100,
            "test file",
        )
        .is_err());
        assert!(publish_initial_tree(
            &temporary.path().join("linked/mocks/source.yaml"),
            &[artifact("source.yaml", b"version: 1\n")],
        )
        .is_err());
        assert!(!real.join("mocks").exists());
    }
}
