// SPDX-License-Identifier: Apache-2.0
//! Collision-safe project-local editor configuration for Relay V2.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};

use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

const EDITOR_ROOT: &str = ".relay-v2-editor";
const MANIFEST_PATH: &str = ".relay-v2-editor/manifest.json";
const MANIFEST_FORMAT: &str = "registry.relay-v2.editor-manifest";
const MANIFEST_VERSION: u8 = 1;
const MAX_MANAGED_BYTES: u64 = 1024 * 1024;

struct SchemaEntry {
    name: &'static str,
    filename: &'static str,
    glob: &'static str,
    document: &'static str,
}

const SCHEMAS: [SchemaEntry; 2] = [
    SchemaEntry {
        name: "registry",
        filename: "registry.schema.json",
        glob: "registry.yaml",
        document: include_str!("../schemas/authoring/registry.schema.json"),
    },
    SchemaEntry {
        name: "runtime",
        filename: "runtime.schema.json",
        glob: "runtime.yaml",
        document: include_str!("../schemas/authoring/runtime.schema.json"),
    },
];

#[derive(Debug, Args)]
pub(crate) struct EditorArgs {
    /// Relay V2 authoring project; defaults to the current directory.
    #[arg(default_value = ".")]
    pub(crate) project: PathBuf,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EditorSetupReport {
    schema_version: &'static str,
    status: &'static str,
    project_directory: String,
    files: Vec<String>,
}

impl EditorSetupReport {
    pub(crate) fn render_human(&self) -> String {
        let mut output = format!(
            "Editor schema mappings are {} for {}.\n",
            self.status, self.project_directory
        );
        for file in &self.files {
            output.push_str("  ");
            output.push_str(file);
            output.push('\n');
        }
        output
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct EditorManifest {
    format: String,
    version: u8,
    relayctl_version: String,
    schemas: Vec<ManifestSchema>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ManifestSchema {
    kind: String,
    path: String,
    file_glob: String,
    sha256: String,
}

struct ManagedFile {
    relative: PathBuf,
    bytes: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
enum TargetState {
    Missing,
    Existing(Vec<u8>),
}

struct Publication {
    target: PathBuf,
    backup: Option<PathBuf>,
    expected: Vec<u8>,
    installed: bool,
}

#[cfg(test)]
std::thread_local! {
    static TEST_TARGET_CHANGE: std::cell::RefCell<Option<(PathBuf, Vec<u8>)>> = const {
        std::cell::RefCell::new(None)
    };
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum EditorError {
    #[error("the project directory is not a Relay V2 authoring root with a regular registry.yaml")]
    NotProject,
    #[error("editor setup found files it does not own and changed nothing: {0}")]
    Conflict(String),
    #[error("editor setup refused a symbolic link at {0}")]
    Symlink(String),
    #[error("editor setup could not read the managed project state")]
    Read,
    #[error("editor setup could not publish its complete managed file set")]
    Write,
    #[error("editor setup publication failed; recoverable transaction files remain at {0}")]
    Recovery(String),
    #[error("editor setup could not render its deterministic configuration")]
    Render,
}

pub(crate) fn setup_project_editor(project: &Path) -> Result<EditorSetupReport, EditorError> {
    let root = project
        .canonicalize()
        .map_err(|_| EditorError::NotProject)?;
    require_project(&root)?;
    let files = managed_files()?;
    let prior = managed_prior(&root, &files)?;
    let states = preflight(&root, &files, prior.as_ref())?;

    let staging = tempfile::Builder::new()
        .prefix(".relay-v2-editor-transaction-")
        .tempdir_in(&root)
        .map_err(|_| EditorError::Write)?;
    for file in &files {
        let staged = staging.path().join(&file.relative);
        if let Some(parent) = staged.parent() {
            fs::create_dir_all(parent).map_err(|_| EditorError::Write)?;
        }
        fs::write(&staged, &file.bytes).map_err(|_| EditorError::Write)?;
    }

    if publish(&root, staging.path(), &files, &states).is_err() {
        let recovery = staging.keep();
        return Err(EditorError::Recovery(
            recovery.to_string_lossy().into_owned(),
        ));
    }
    let mut paths = files
        .iter()
        .map(|file| portable(&file.relative))
        .collect::<Vec<_>>();
    paths.sort();
    Ok(EditorSetupReport {
        schema_version: "relayctl.editor.v1",
        status: "configured",
        project_directory: root.to_string_lossy().into_owned(),
        files: paths,
    })
}

fn require_project(root: &Path) -> Result<(), EditorError> {
    let marker = root.join("registry.yaml");
    let metadata = fs::symlink_metadata(&marker).map_err(|_| EditorError::NotProject)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(EditorError::NotProject);
    }
    Ok(())
}

fn managed_files() -> Result<Vec<ManagedFile>, EditorError> {
    let mut files = SCHEMAS
        .iter()
        .map(|schema| ManagedFile {
            relative: PathBuf::from(EDITOR_ROOT)
                .join("schemas")
                .join(schema.filename),
            bytes: schema.document.as_bytes().to_vec(),
        })
        .collect::<Vec<_>>();
    let manifest = EditorManifest {
        format: MANIFEST_FORMAT.to_owned(),
        version: MANIFEST_VERSION,
        relayctl_version: env!("CARGO_PKG_VERSION").to_owned(),
        schemas: SCHEMAS
            .iter()
            .map(|schema| ManifestSchema {
                kind: schema.name.to_owned(),
                path: format!("schemas/{}", schema.filename),
                file_glob: schema.glob.to_owned(),
                sha256: digest(schema.document.as_bytes()),
            })
            .collect(),
    };
    files.push(ManagedFile {
        relative: PathBuf::from(MANIFEST_PATH),
        bytes: pretty(&manifest)?,
    });
    files.extend(editor_configuration_files(&manifest.schemas)?);
    Ok(files)
}

fn editor_configuration_files(schemas: &[ManifestSchema]) -> Result<Vec<ManagedFile>, EditorError> {
    let mappings = schemas
        .iter()
        .map(|schema| {
            (
                format!("./{EDITOR_ROOT}/{}", schema.path),
                schema.file_glob.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    Ok(vec![
        ManagedFile {
            relative: PathBuf::from(".vscode/settings.json"),
            bytes: pretty(&json!({"yaml.schemas": mappings.clone()}))?,
        },
        ManagedFile {
            relative: PathBuf::from(".vscode/extensions.json"),
            bytes: pretty(&json!({"recommendations": ["redhat.vscode-yaml"]}))?,
        },
        ManagedFile {
            relative: PathBuf::from(".zed/settings.json"),
            bytes: pretty(&json!({
                "lsp": {
                    "yaml-language-server": {
                        "settings": {"yaml": {"schemas": mappings}}
                    }
                }
            }))?,
        },
    ])
}

fn pretty(value: &impl Serialize) -> Result<Vec<u8>, EditorError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|_| EditorError::Render)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn managed_prior(
    root: &Path,
    current_files: &[ManagedFile],
) -> Result<Option<BTreeMap<PathBuf, Vec<u8>>>, EditorError> {
    let path = root.join(MANIFEST_PATH);
    let Some(bytes) = read_regular_bounded(root, &path)? else {
        return Ok(None);
    };
    let current_manifest = current_files
        .iter()
        .find(|file| file.relative == Path::new(MANIFEST_PATH))
        .expect("managed files contain the manifest");
    if bytes == current_manifest.bytes {
        return Ok(None);
    }
    let manifest: EditorManifest = serde_json::from_slice(&bytes).map_err(|_| EditorError::Read)?;
    if manifest.format != MANIFEST_FORMAT || manifest.version != MANIFEST_VERSION {
        return Err(EditorError::Read);
    }
    if manifest.relayctl_version.is_empty()
        || manifest.relayctl_version.len() > 128
        || !manifest.relayctl_version.bytes().all(
            |byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'+'),
        )
    {
        return Err(EditorError::Read);
    }
    let mut listed = BTreeSet::new();
    for schema in &manifest.schemas {
        let known = SCHEMAS.iter().any(|entry| {
            schema.kind == entry.name
                && schema.path == format!("schemas/{}", entry.filename)
                && schema.file_glob == entry.glob
        });
        if !known || !is_digest(&schema.sha256) || !listed.insert(schema.kind.as_str()) {
            return Err(EditorError::Read);
        }
    }

    let current_by_path = current_files
        .iter()
        .map(|file| (file.relative.clone(), file.bytes.as_slice()))
        .collect::<BTreeMap<_, _>>();
    let mut allowed = BTreeMap::from([(PathBuf::from(MANIFEST_PATH), bytes)]);
    for schema in &manifest.schemas {
        let relative = PathBuf::from(EDITOR_ROOT).join(&schema.path);
        if let Some(actual) = read_regular_bounded(root, &root.join(&relative))? {
            if digest(&actual) != schema.sha256 {
                return Err(EditorError::Read);
            }
            allowed.insert(relative, actual);
        }
    }
    for prior_file in editor_configuration_files(&manifest.schemas)? {
        let current = current_by_path
            .get(&prior_file.relative)
            .expect("managed files contain every editor configuration target");
        if let Some(actual) = read_regular_bounded(root, &root.join(&prior_file.relative))? {
            if actual != prior_file.bytes && actual.as_slice() != *current {
                return Err(EditorError::Conflict(portable(&prior_file.relative)));
            }
            allowed.insert(prior_file.relative, actual);
        }
    }
    Ok(Some(allowed))
}

fn preflight(
    root: &Path,
    files: &[ManagedFile],
    prior: Option<&BTreeMap<PathBuf, Vec<u8>>>,
) -> Result<Vec<TargetState>, EditorError> {
    let mut conflicts = BTreeSet::new();
    let mut states = Vec::with_capacity(files.len());
    for file in files {
        reject_symlink_ancestors(root, &file.relative)?;
        let target = root.join(&file.relative);
        let Some(actual) = read_regular_bounded(root, &target)? else {
            states.push(TargetState::Missing);
            continue;
        };
        let owned = actual == file.bytes
            || (file.relative == Path::new(MANIFEST_PATH) && prior.is_some())
            || prior
                .and_then(|files| files.get(&file.relative))
                .is_some_and(|expected| actual == *expected);
        if !owned {
            conflicts.insert(portable(&file.relative));
        }
        states.push(TargetState::Existing(actual));
    }
    if conflicts.is_empty() {
        Ok(states)
    } else {
        Err(EditorError::Conflict(
            conflicts.into_iter().collect::<Vec<_>>().join(", "),
        ))
    }
}

fn publish(
    root: &Path,
    staging: &Path,
    files: &[ManagedFile],
    states: &[TargetState],
) -> Result<(), EditorError> {
    let backup_root = staging.join("backups");
    let mut publications = Vec::<Publication>::new();
    let mut created_directories = Vec::new();

    for (file, expected) in files.iter().zip(states) {
        if !state_unchanged(expected, &inspect_target(root, &file.relative)?) {
            return Err(EditorError::Conflict(portable(&file.relative)));
        }
    }

    for (file, expected) in files.iter().zip(states) {
        if matches!(expected, TargetState::Existing(bytes) if bytes == &file.bytes) {
            continue;
        }
        let target = root.join(&file.relative);
        let Some(parent) = target.parent() else {
            return Err(EditorError::Write);
        };
        if ensure_directories(root, parent, &mut created_directories).is_err() {
            rollback(&mut publications, &created_directories)?;
            return Err(EditorError::Write);
        }
        if !state_unchanged(expected, &inspect_target(root, &file.relative)?) {
            rollback(&mut publications, &created_directories)?;
            return Err(EditorError::Conflict(portable(&file.relative)));
        }
        maybe_change_target(root, &file.relative)?;

        let backup = if matches!(expected, TargetState::Existing(_)) {
            let backup = backup_root.join(&file.relative);
            if let Some(parent) = backup.parent() {
                if fs::create_dir_all(parent).is_err() {
                    rollback(&mut publications, &created_directories)?;
                    return Err(EditorError::Write);
                }
            }
            if fs::rename(&target, &backup).is_err() {
                rollback(&mut publications, &created_directories)?;
                return Err(EditorError::Write);
            }
            Some(backup)
        } else {
            None
        };
        publications.push(Publication {
            target: target.clone(),
            backup,
            expected: file.bytes.clone(),
            installed: false,
        });
        if let (TargetState::Existing(expected), Some(backup)) = (
            expected,
            publications
                .last()
                .expect("publication was recorded")
                .backup
                .as_ref(),
        ) {
            let actual = fs::read(backup).map_err(|_| EditorError::Read)?;
            if &actual != expected {
                rollback(&mut publications, &created_directories)?;
                return Err(EditorError::Conflict(portable(&file.relative)));
            }
        }
        if fs::hard_link(staging.join(&file.relative), &target).is_err() {
            rollback(&mut publications, &created_directories)?;
            return Err(EditorError::Write);
        }
        publications
            .last_mut()
            .expect("publication was recorded")
            .installed = true;
    }
    Ok(())
}

fn rollback(
    publications: &mut [Publication],
    created_directories: &[PathBuf],
) -> Result<(), EditorError> {
    let mut failed = false;
    for publication in publications.iter_mut().rev() {
        if publication.installed {
            match fs::read(&publication.target) {
                Ok(actual) if actual == publication.expected => {
                    if fs::remove_file(&publication.target).is_err() {
                        failed = true;
                        continue;
                    }
                    publication.installed = false;
                }
                _ => {
                    failed = true;
                    continue;
                }
            }
        }
        if let Some(backup) = &publication.backup {
            if fs::hard_link(backup, &publication.target).is_err() {
                failed = true;
            }
        }
    }
    for directory in created_directories.iter().rev() {
        if fs::remove_dir(directory).is_err() {
            failed = true;
        }
    }
    if failed {
        Err(EditorError::Write)
    } else {
        Ok(())
    }
}

fn inspect_target(root: &Path, relative: &Path) -> Result<TargetState, EditorError> {
    reject_symlink_ancestors(root, relative)?;
    Ok(match read_regular_bounded(root, &root.join(relative))? {
        Some(bytes) => TargetState::Existing(bytes),
        None => TargetState::Missing,
    })
}

fn state_unchanged(expected: &TargetState, actual: &TargetState) -> bool {
    match (expected, actual) {
        (TargetState::Missing, TargetState::Missing) => true,
        (TargetState::Existing(expected), TargetState::Existing(actual)) => expected == actual,
        _ => false,
    }
}

fn ensure_directories(
    root: &Path,
    directory: &Path,
    created: &mut Vec<PathBuf>,
) -> Result<(), EditorError> {
    let relative = directory
        .strip_prefix(root)
        .map_err(|_| EditorError::Write)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(EditorError::Write);
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(EditorError::Symlink(current.to_string_lossy().into_owned()));
            }
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => return Err(EditorError::Write),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match fs::create_dir(&current) {
                    Ok(()) => created.push(current.clone()),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        let metadata =
                            fs::symlink_metadata(&current).map_err(|_| EditorError::Write)?;
                        if metadata.file_type().is_symlink() {
                            return Err(EditorError::Symlink(
                                current.to_string_lossy().into_owned(),
                            ));
                        }
                        if !metadata.is_dir() {
                            return Err(EditorError::Write);
                        }
                    }
                    Err(_) => return Err(EditorError::Write),
                }
            }
            Err(_) => return Err(EditorError::Write),
        }
    }
    Ok(())
}

#[cfg(test)]
fn maybe_change_target(root: &Path, relative: &Path) -> Result<(), EditorError> {
    TEST_TARGET_CHANGE.with(|change| {
        let requested = change.borrow_mut().take();
        if let Some((changed, bytes)) = requested {
            if changed == relative {
                fs::write(root.join(relative), bytes).map_err(|_| EditorError::Write)?;
            } else {
                *change.borrow_mut() = Some((changed, bytes));
            }
        }
        Ok(())
    })
}

#[cfg(not(test))]
fn maybe_change_target(_root: &Path, _relative: &Path) -> Result<(), EditorError> {
    Ok(())
}

fn read_regular_bounded(root: &Path, path: &Path) -> Result<Option<Vec<u8>>, EditorError> {
    if !path.starts_with(root) {
        return Err(EditorError::Read);
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(EditorError::Read),
    };
    if metadata.file_type().is_symlink() {
        return Err(EditorError::Symlink(path.to_string_lossy().into_owned()));
    }
    if !metadata.is_file() || metadata.len() > MAX_MANAGED_BYTES {
        return Err(EditorError::Read);
    }
    fs::read(path).map(Some).map_err(|_| EditorError::Read)
}

fn reject_symlink_ancestors(root: &Path, relative: &Path) -> Result<(), EditorError> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(EditorError::Read);
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(EditorError::Symlink(current.to_string_lossy().into_owned()));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => return Err(EditorError::Read),
        }
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn is_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn portable(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project() -> tempfile::TempDir {
        let project = tempfile::tempdir().unwrap();
        fs::write(
            project.path().join("registry.yaml"),
            "kind: RegistryContract\n",
        )
        .unwrap();
        project
    }

    #[test]
    fn setup_writes_both_schemas_and_both_editor_mappings_idempotently() {
        let project = project();
        let first = setup_project_editor(project.path()).unwrap();
        let second = setup_project_editor(project.path()).unwrap();
        assert_eq!(first.files, second.files);
        for expected in [
            ".relay-v2-editor/schemas/registry.schema.json",
            ".relay-v2-editor/schemas/runtime.schema.json",
            ".relay-v2-editor/manifest.json",
            ".vscode/extensions.json",
            ".vscode/settings.json",
            ".zed/settings.json",
        ] {
            assert!(project.path().join(expected).is_file(), "{expected}");
        }
        let extensions: serde_json::Value = serde_json::from_slice(
            &fs::read(project.path().join(".vscode/extensions.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(extensions["recommendations"], json!(["redhat.vscode-yaml"]));
    }

    #[test]
    fn an_authored_settings_file_stops_the_complete_publication() {
        let project = project();
        fs::create_dir(project.path().join(".vscode")).unwrap();
        fs::write(
            project.path().join(".vscode/settings.json"),
            b"{\"editor.tabSize\": 4}\n",
        )
        .unwrap();
        let error = setup_project_editor(project.path()).unwrap_err();
        assert!(matches!(error, EditorError::Conflict(_)));
        assert!(!project.path().join(EDITOR_ROOT).exists());
        assert!(!project.path().join(".zed/settings.json").exists());
    }

    #[test]
    fn a_prior_manifest_cannot_authorize_customized_settings() {
        let project = project();
        setup_project_editor(project.path()).unwrap();
        let settings_path = project.path().join(".vscode/settings.json");
        let authored = b"{\"editor.tabSize\": 4}\n";
        fs::write(&settings_path, authored).unwrap();

        let manifest_path = project.path().join(MANIFEST_PATH);
        let mut manifest: EditorManifest =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest.relayctl_version = "0.18.0".to_owned();
        fs::write(&manifest_path, pretty(&manifest).unwrap()).unwrap();

        let error = setup_project_editor(project.path()).unwrap_err();
        assert!(matches!(error, EditorError::Conflict(_)));
        assert_eq!(fs::read(settings_path).unwrap(), authored);
    }

    #[test]
    fn a_prior_manifest_from_a_smaller_schema_catalog_is_refreshed() {
        let project = project();
        setup_project_editor(project.path()).unwrap();

        let manifest_path = project.path().join(MANIFEST_PATH);
        let mut manifest: EditorManifest =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest.relayctl_version = "0.18.0".to_owned();
        manifest.schemas.retain(|schema| schema.kind == "registry");
        fs::write(&manifest_path, pretty(&manifest).unwrap()).unwrap();
        fs::remove_file(
            project
                .path()
                .join(".relay-v2-editor/schemas/runtime.schema.json"),
        )
        .unwrap();
        for file in editor_configuration_files(&manifest.schemas).unwrap() {
            fs::write(project.path().join(file.relative), file.bytes).unwrap();
        }

        setup_project_editor(project.path()).unwrap();

        assert!(project
            .path()
            .join(".relay-v2-editor/schemas/runtime.schema.json")
            .is_file());
        let current = managed_files().unwrap();
        for file in current {
            assert_eq!(
                fs::read(project.path().join(&file.relative)).unwrap(),
                file.bytes
            );
        }
    }

    #[test]
    fn a_destination_appearing_after_preflight_is_preserved() {
        let project = project();
        let relative = PathBuf::from(".zed/settings.json");
        let concurrent = b"{\"concurrent\":true}\n".to_vec();
        TEST_TARGET_CHANGE.with(|change| {
            *change.borrow_mut() = Some((relative.clone(), concurrent.clone()));
        });

        let error = setup_project_editor(project.path()).unwrap_err();

        assert!(matches!(error, EditorError::Recovery(_)));
        assert_eq!(fs::read(project.path().join(relative)).unwrap(), concurrent);
        assert!(!project.path().join(EDITOR_ROOT).exists());
        assert!(!project.path().join(".vscode/settings.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_editor_ancestor_is_refused_without_writing_outside() {
        let project = project();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), project.path().join(".vscode")).unwrap();

        let error = setup_project_editor(project.path()).unwrap_err();

        assert!(matches!(error, EditorError::Symlink(_)));
        assert!(fs::read_dir(outside.path()).unwrap().next().is_none());
        assert!(!project.path().join(EDITOR_ROOT).exists());
    }
}
