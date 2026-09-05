//! Project-local editor configuration for an Evidence authoring project.
//!
//! An adopter writes YAML long before they run anything, and a stock YAML
//! language server can already tell them a key is misspelled or a required one
//! is missing. All it needs is a schema and a mapping from file glob to schema.
//! This writes both into the project, together with a manifest recording what
//! it wrote, so a later run can tell its own output apart from an author's.
//!
//! The schemas are the committed artifact generated from
//! `registry-evidence-authoring`, embedded at build time. Nothing here decides
//! what the authoring form is; that stays with the crate that owns the model.
//!
//! # Writing into a directory someone else owns
//!
//! Every file below is inside a project a human is editing, which makes
//! publication the delicate part rather than the content. Three rules carry it.
//!
//! A file that exists and does not match either what this run would write or
//! what a previous run recorded writing is a conflict, and a conflict stops the
//! command before anything is touched: an author who customized their editor
//! settings gets them back unchanged and a sentence saying so, never a silent
//! replacement.
//!
//! Publication is staged. Every file is written into a private transaction
//! directory first, every destination is re-inspected immediately before it is
//! taken, and the destination is claimed with a hard link, which fails rather
//! than replaces if something appeared there in between. A fault anywhere in
//! the sequence rolls the whole set back to what preflight saw, and a rollback
//! that cannot complete leaves its backups in place and says where they are.
//!
//! Symlinks are refused outright, at the target and at every ancestor. A
//! symlinked ancestor is how a write inside a project turns into a write
//! outside one, and this command has no reason to follow one.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write as _,
    path::{Component, Path, PathBuf},
    process::ExitCode,
};

use anyhow::{anyhow, bail, Context as _, Result};
use clap::Args;
use registry_evidence_authoring::{
    layout::{OPENAPI_FILE, QUESTIONS_DIRECTORY},
    PROJECT_MARKER_FILE,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};

/// The directory this command owns inside a project.
const EDITOR_ROOT: &str = ".evidence-editor";
/// The catalogue of what a run wrote, relative to the project root.
const EDITOR_MANIFEST_PATH: &str = ".evidence-editor/manifest.json";
/// The manifest's format name. A manifest that does not carry it is not one of
/// ours, and is treated as an author's file rather than as ours to replace.
const EDITOR_MANIFEST_FORMAT: &str = "registry.evidence.editor-manifest";
const EDITOR_MANIFEST_VERSION: u8 = 1;
/// The largest file this command will read back from a project. A managed file
/// is a few kilobytes; anything larger is not something to load into memory to
/// compare.
const MAX_EDITOR_FILE_BYTES: u64 = 1024 * 1024;
/// The report's own format name, so a script reading it can tell versions apart.
const EDITOR_REPORT_SCHEMA_VERSION: &str = "evidencectl.editor.v1";
/// The mode a published file carries. This is generated, non-secret
/// configuration meant to be read and committed beside the rest of a project,
/// so it matches what `evidencectl new` writes rather than the owner-only
/// discipline key material is held to. Publication hard links the staged file,
/// which shares its inode, so the staged name carries the same mode inside a
/// transaction directory only its owner can enter.
#[cfg(unix)]
const EDITOR_FILE_MODE: u32 = 0o644;
/// The mode a directory published inside the project carries, for the same
/// reason: an editor that cannot enter `.vscode` reads no mapping from it.
#[cfg(unix)]
const EDITOR_DIRECTORY_MODE: u32 = 0o755;
/// The mode of the transaction directory and its staging tree. A half-written
/// set of files is nobody's business but this run's.
#[cfg(unix)]
const EDITOR_TRANSACTION_MODE: u32 = 0o700;

/// One authored document kind an editor can be pointed at, the schema that
/// describes it, and the files it applies to.
struct EditorSchema {
    name: &'static str,
    filename: &'static str,
    file_glob: &'static str,
    document: &'static str,
}

// yaml-language-server treats a portable fileMatch pattern as a suffix match by
// prepending `**/`, so these globs must stay specific enough that they cannot
// claim an unrelated YAML file elsewhere in an adopter's worktree. Exact
// worktree-root matching would need an editor extension, because neither the
// VS Code nor the Zed settings surface exposes a project-root token.
//
// The catalogue holds only the document kinds a Rust type stands behind. The
// other authored parts of a project (sources, selectors, derivations, answer
// schemas, fixtures, access policies) get no mapping, because a schema written
// by hand for one of them would drift from the checks the moment either moved.
const EDITOR_SCHEMA_CATALOG: [EditorSchema; 2] = [
    EditorSchema {
        name: "project-marker",
        filename: "project-marker.schema.json",
        file_glob: "evidence-project.yaml",
        document: include_str!("../schemas/authoring/project-marker.schema.json"),
    },
    EditorSchema {
        name: "question",
        filename: "question.schema.json",
        file_glob: "questions/*.yaml",
        document: include_str!("../schemas/authoring/question.schema.json"),
    },
];

#[derive(Debug, Args)]
pub struct EditorArgs {
    /// Evidence project directory; defaults to the current directory.
    ///
    /// This command needs an editable project: one holding questions/ and
    /// sources/ beside evidence-project.yaml.
    #[arg(long, default_value = ".")]
    pub project: PathBuf,
}

/// What one run wrote, for an author reading the terminal or a script reading
/// JSON.
#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EditorSetupReport {
    pub schema_version: &'static str,
    pub status: &'static str,
    pub project_directory: String,
    pub files: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EditorManifest {
    format: String,
    version: u8,
    evidencectl_version: String,
    schemas: Vec<EditorManifestSchema>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EditorManifestSchema {
    kind: String,
    path: String,
    file_glob: String,
    sha256: String,
}

struct EditorFile {
    relative_path: PathBuf,
    bytes: Vec<u8>,
}

/// What preflight found at one destination.
#[derive(Debug, PartialEq, Eq)]
enum EditorTargetState {
    Missing,
    Existing(Vec<u8>),
    /// Present, but not a bounded regular file: a directory, a device, or
    /// something too large to compare.
    Conflict,
    Symlink(PathBuf),
}

/// The files a previous run of this command recorded writing, and which are
/// therefore ours to refresh rather than an author's to keep.
struct ManagedPriorEditor {
    allowed_existing: BTreeMap<PathBuf, Vec<u8>>,
}

struct EditorPublication {
    target: PathBuf,
    backup: Option<PathBuf>,
    expected: Vec<u8>,
    installed: bool,
}

static EDITOR_TRANSACTION_COUNTER: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
std::thread_local! {
    static EDITOR_TEST_PUBLISH_FAILURE_AFTER: std::cell::Cell<Option<usize>> = const {
        std::cell::Cell::new(None)
    };
    static EDITOR_TEST_ROLLBACK_FAILURE: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    static EDITOR_TEST_TARGET_CHANGE: std::cell::RefCell<Option<(PathBuf, Vec<u8>)>> = const {
        std::cell::RefCell::new(None)
    };
}

pub fn run(args: EditorArgs) -> Result<ExitCode> {
    let report = setup_project_editor(&args.project)?;
    println!(
        "Editor schema mappings are {} for {}.",
        report.status, report.project_directory
    );
    for file in &report.files {
        println!("  {file}");
    }
    Ok(ExitCode::SUCCESS)
}

/// Write the project-local schemas and editor settings, or explain why not.
///
/// # Errors
///
/// Returns an error when the directory is not an authoring project, when a
/// managed destination holds something this command did not write, or when
/// publication faults. A faulted run is rolled back to what preflight saw.
pub fn setup_project_editor(project_directory: &Path) -> Result<EditorSetupReport> {
    let root = canonical_root(project_directory)?;
    require_authoring_project_root(&root)?;
    let files = editor_files()?;
    let prior = managed_prior_editor(&root, &files)?;

    let mut states = Vec::with_capacity(files.len());
    let mut conflicts = BTreeSet::new();
    let mut symlinks = BTreeSet::new();
    for file in &files {
        validate_relative_editor_path(&file.relative_path)?;
        let target = root.join(&file.relative_path);
        if !target.starts_with(&root) {
            bail!("generated editor path escapes the project root");
        }
        let state = inspect_editor_target(&root, &target)?;
        match &state {
            EditorTargetState::Existing(actual)
                if actual != &file.bytes
                    && !prior.as_ref().is_some_and(|prior| {
                        prior.allowed_existing.get(&file.relative_path) == Some(actual)
                    }) =>
            {
                conflicts.insert(file.relative_path.clone());
            }
            EditorTargetState::Conflict => {
                conflicts.insert(file.relative_path.clone());
            }
            EditorTargetState::Symlink(path) => {
                symlinks.insert(path.clone());
            }
            EditorTargetState::Missing | EditorTargetState::Existing(_) => {}
        }
        states.push(state);
    }

    if !conflicts.is_empty() || !symlinks.is_empty() {
        let mut causes = Vec::new();
        if !conflicts.is_empty() {
            causes.push(format!("conflicting files: {}", display_paths(&conflicts)));
        }
        if !symlinks.is_empty() {
            causes.push(format!(
                "symlink targets or ancestors are not allowed: {}",
                display_paths(&symlinks)
            ));
        }
        bail!(
            "editor setup preflight failed; {}; no files were changed. Keep these files and install the Evidence schema mappings by hand, or restore the expected generated files before rerunning the command",
            causes.join("; ")
        );
    }

    publish_editor_files(&root, &files, &states)?;

    Ok(EditorSetupReport {
        schema_version: EDITOR_REPORT_SCHEMA_VERSION,
        status: "configured",
        project_directory: root.display().to_string(),
        files: files
            .iter()
            .map(|file| file.relative_path.display().to_string())
            .collect(),
    })
}

fn canonical_root(root: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(root)
        .with_context(|| format!("failed to stat project {}", root.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("project root must be a real directory");
    }
    root.canonicalize()
        .with_context(|| format!("failed to canonicalize {}", root.display()))
}

/// What makes this a project rather than any directory, and this command writes
/// into whatever it is pointed at, so it asks first.
///
/// The marker is the direct answer, and one that is present must be a plain
/// file. A root that carries none is answered by the pair every authoring
/// project has always carried, one OpenAPI description and a directory of
/// questions, because a project the compiler accepts must not have to be
/// migrated before an editor will read it.
fn require_authoring_project_root(root: &Path) -> Result<()> {
    let path = root.join(PROJECT_MARKER_FILE);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!("project root must contain a regular non-symlink {PROJECT_MARKER_FILE}")
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if carries_authored_pair(root) {
                Ok(())
            } else {
                bail!("project root must contain a regular {PROJECT_MARKER_FILE}, or the {OPENAPI_FILE} and {QUESTIONS_DIRECTORY} directory an authoring project carries; run `evidencectl new` first")
            }
        }
        Err(error) => {
            Err(error).with_context(|| format!("failed to stat project marker {}", path.display()))
        }
    }
}

/// Whether a root carries the authored pair an Evidence project has held since
/// before the marker existed.
///
/// A symbolic link at either name declares nothing, whatever it points at: a
/// link is how a directory borrows a shape it does not have, and a borrowed
/// shape must not anchor a root this command then writes files into.
fn carries_authored_pair(root: &Path) -> bool {
    fs::symlink_metadata(root.join(OPENAPI_FILE))
        .is_ok_and(|metadata| metadata.file_type().is_file())
        && fs::symlink_metadata(root.join(QUESTIONS_DIRECTORY))
            .is_ok_and(|metadata| metadata.file_type().is_dir())
}

fn editor_files() -> Result<Vec<EditorFile>> {
    let manifest = current_editor_manifest();
    let mut files = Vec::with_capacity(EDITOR_SCHEMA_CATALOG.len() + 4);
    for entry in &EDITOR_SCHEMA_CATALOG {
        files.push(EditorFile {
            relative_path: PathBuf::from(EDITOR_ROOT)
                .join("schemas")
                .join(entry.filename),
            bytes: entry.document.as_bytes().to_vec(),
        });
    }
    files.push(EditorFile {
        relative_path: PathBuf::from(EDITOR_MANIFEST_PATH),
        bytes: pretty_json(&manifest)?,
    });
    files.extend(editor_configuration_files(&manifest.schemas)?);
    Ok(files)
}

fn current_editor_manifest() -> EditorManifest {
    EditorManifest {
        format: EDITOR_MANIFEST_FORMAT.to_string(),
        version: EDITOR_MANIFEST_VERSION,
        evidencectl_version: env!("CARGO_PKG_VERSION").to_string(),
        schemas: EDITOR_SCHEMA_CATALOG
            .iter()
            .map(|entry| EditorManifestSchema {
                kind: entry.name.to_string(),
                path: format!("schemas/{}", entry.filename),
                file_glob: entry.file_glob.to_string(),
                sha256: schema_hash(entry.document.as_bytes()),
            })
            .collect(),
    }
}

/// The editor settings, built from the manifest rather than from the catalogue
/// directly, so that a refresh can rebuild exactly what a prior manifest
/// described and recognize it byte for byte.
fn editor_configuration_files(schemas: &[EditorManifestSchema]) -> Result<Vec<EditorFile>> {
    let schema_mappings = schemas
        .iter()
        .map(|schema| {
            (
                format!("./{EDITOR_ROOT}/{}", schema.path),
                schema.file_glob.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    Ok(vec![
        EditorFile {
            relative_path: PathBuf::from(".vscode/settings.json"),
            bytes: pretty_json(&json!({ "yaml.schemas": schema_mappings.clone() }))?,
        },
        EditorFile {
            relative_path: PathBuf::from(".vscode/extensions.json"),
            bytes: pretty_json(&json!({ "recommendations": ["redhat.vscode-yaml"] }))?,
        },
        EditorFile {
            relative_path: PathBuf::from(".zed/settings.json"),
            bytes: pretty_json(&json!({
                "lsp": {
                    "yaml-language-server": {
                        "settings": {
                            "yaml": {
                                "schemas": schema_mappings
                            }
                        }
                    }
                }
            }))?,
        },
    ])
}

/// Read the manifest a previous run left, and decide which existing files it
/// authorizes this run to replace.
///
/// A manifest identical to the one this run would write means nothing to
/// refresh, and the ordinary byte comparison in preflight covers it.
fn managed_prior_editor(
    root: &Path,
    current_files: &[EditorFile],
) -> Result<Option<ManagedPriorEditor>> {
    let manifest_path = root.join(EDITOR_MANIFEST_PATH);
    let current_manifest = current_files
        .iter()
        .find(|file| file.relative_path == Path::new(EDITOR_MANIFEST_PATH))
        .expect("current editor files contain their manifest");
    let EditorTargetState::Existing(manifest_bytes) = inspect_editor_target(root, &manifest_path)?
    else {
        return Ok(None);
    };
    if manifest_bytes == current_manifest.bytes {
        return Ok(None);
    }

    validate_managed_prior_editor(root, current_files, manifest_bytes)
        .with_context(|| {
            format!(
                "existing editor manifest cannot authorize a managed refresh; {}",
                managed_editor_recovery(current_files)
            )
        })
        .map(Some)
}

/// The way out of a manifest this command cannot read. Everything it writes is
/// generated, so removing the managed set returns the project to one a fresh
/// run configures; naming that set is what keeps the way out from being a
/// guess.
fn managed_editor_recovery(current_files: &[EditorFile]) -> String {
    let mut configuration = current_files
        .iter()
        .filter(|file| !file.relative_path.starts_with(EDITOR_ROOT))
        .map(|file| file.relative_path.display().to_string())
        .collect::<Vec<_>>();
    configuration.sort();
    format!(
        "to configure the project again from scratch, remove {EDITOR_ROOT} and the editor configuration this command writes ({}), then rerun",
        configuration.join(", ")
    )
}

fn validate_managed_prior_editor(
    root: &Path,
    current_files: &[EditorFile],
    manifest_bytes: Vec<u8>,
) -> Result<ManagedPriorEditor> {
    let manifest: EditorManifest = serde_json::from_slice(&manifest_bytes)
        .context("prior editor manifest is not the closed JSON format")?;
    if manifest.format != EDITOR_MANIFEST_FORMAT || manifest.version != EDITOR_MANIFEST_VERSION {
        bail!("prior editor manifest uses an unsupported format or version");
    }
    if manifest.evidencectl_version.is_empty()
        || manifest.evidencectl_version.len() > 128
        || !manifest.evidencectl_version.bytes().all(
            |byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'+'),
        )
    {
        bail!("prior editor manifest has an invalid evidencectl version");
    }
    // A prior manifest may list fewer schemas than the current catalogue, and
    // the entries it lists may be in any order: the catalogue grows as more of
    // the authoring form gains a Rust type behind it, and a project scaffolded
    // by an earlier release is refreshed by a later one rather than left with
    // no run that can ever succeed. Every entry it does list must still be one
    // this command writes, so that the bytes it authorizes replacing are bytes
    // this command put there, and a catalogue entry it omits is a new file to
    // stage rather than a prior file to recognize.
    let mut listed = BTreeSet::new();
    for schema in &manifest.schemas {
        let known = EDITOR_SCHEMA_CATALOG.iter().any(|entry| {
            schema.kind == entry.name
                && schema.path == format!("schemas/{}", entry.filename)
                && schema.file_glob == entry.file_glob
        });
        if !known || !is_schema_hash(&schema.sha256) || !listed.insert(schema.kind.as_str()) {
            bail!(
                "prior editor manifest schema catalog is not part of the expected closed catalog"
            );
        }
    }

    let current_by_path = current_files
        .iter()
        .map(|file| (file.relative_path.clone(), file.bytes.as_slice()))
        .collect::<BTreeMap<_, _>>();
    let mut allowed_existing = BTreeMap::new();
    allowed_existing.insert(PathBuf::from(EDITOR_MANIFEST_PATH), manifest_bytes);

    for schema in &manifest.schemas {
        let relative_path = PathBuf::from(EDITOR_ROOT).join(&schema.path);
        match inspect_editor_target(root, &root.join(&relative_path))? {
            EditorTargetState::Missing => {}
            EditorTargetState::Existing(bytes) => {
                if schema_hash(&bytes) != schema.sha256 {
                    bail!(
                        "prior editor schema does not match its manifest hash: {}",
                        relative_path.display()
                    );
                }
                allowed_existing.insert(relative_path, bytes);
            }
            EditorTargetState::Conflict => bail!(
                "prior editor schema is not a bounded regular file: {}",
                relative_path.display()
            ),
            EditorTargetState::Symlink(path) => bail!(
                "prior editor schema uses a forbidden symlink target or ancestor: {}",
                path.display()
            ),
        }
    }

    for prior_file in editor_configuration_files(&manifest.schemas)? {
        let current = current_by_path
            .get(&prior_file.relative_path)
            .expect("current editor files contain every configuration target");
        match inspect_editor_target(root, &root.join(&prior_file.relative_path))? {
            EditorTargetState::Missing => {}
            EditorTargetState::Existing(bytes)
                if bytes == prior_file.bytes || bytes.as_slice() == *current =>
            {
                allowed_existing.insert(prior_file.relative_path, bytes);
            }
            EditorTargetState::Existing(_) | EditorTargetState::Conflict => bail!(
                "editor configuration was customized and cannot be refreshed automatically: {}",
                prior_file.relative_path.display()
            ),
            EditorTargetState::Symlink(path) => bail!(
                "editor configuration uses a forbidden symlink target or ancestor: {}",
                path.display()
            ),
        }
    }
    Ok(ManagedPriorEditor { allowed_existing })
}

fn schema_hash(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn is_schema_hash(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// The single rendering of every JSON file this command writes, so that
/// rerunning it produces the same bytes and a comparison means something.
fn pretty_json(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .context("failed to serialize deterministic editor configuration")?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Walk a destination one component at a time, refusing a symlink anywhere on
/// the way, and report what is at the end of it.
fn inspect_editor_target(root: &Path, target: &Path) -> Result<EditorTargetState> {
    let relative = target
        .strip_prefix(root)
        .map_err(|_| anyhow!("generated editor path escapes the project root"))?;
    let components = relative.components().collect::<Vec<_>>();
    if components.is_empty() {
        bail!("generated editor path cannot be the project root");
    }

    let mut current = root.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(component) = component else {
            bail!("generated editor path is not normalized");
        };
        current.push(component);
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(EditorTargetState::Missing)
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect {}", current.display()))
            }
        };
        if metadata.file_type().is_symlink() {
            let relative = current
                .strip_prefix(root)
                .map_err(|_| anyhow!("generated editor path escapes the project root"))?;
            return Ok(EditorTargetState::Symlink(relative.to_path_buf()));
        }
        let is_target = index + 1 == components.len();
        if !is_target && !metadata.is_dir() {
            return Ok(EditorTargetState::Conflict);
        }
        if is_target {
            if !metadata.is_file() || metadata.len() > MAX_EDITOR_FILE_BYTES {
                return Ok(EditorTargetState::Conflict);
            }
            let actual = fs::read(&current)
                .with_context(|| format!("failed to read {}", current.display()))?;
            return Ok(EditorTargetState::Existing(actual));
        }
    }
    unreachable!("a non-empty editor path always returns from the component loop")
}

fn publish_editor_files(
    root: &Path,
    files: &[EditorFile],
    states: &[EditorTargetState],
) -> Result<()> {
    let changes = files
        .iter()
        .zip(states)
        .filter(|(file, state)| match state {
            EditorTargetState::Missing => true,
            EditorTargetState::Existing(bytes) => bytes != &file.bytes,
            EditorTargetState::Conflict | EditorTargetState::Symlink(_) => false,
        })
        .collect::<Vec<_>>();
    if changes.is_empty() {
        return Ok(());
    }

    let transaction_root = create_editor_transaction_root(root)?;
    let mut publications = Vec::new();
    let mut created_directories = Vec::new();
    let result = (|| -> Result<()> {
        for (file, _) in &changes {
            write_staged_file(
                &transaction_root.join("new").join(&file.relative_path),
                &file.bytes,
            )?;
        }
        for (file, state) in files.iter().zip(states) {
            if !editor_state_is_unchanged(
                state,
                &inspect_editor_target(root, &root.join(&file.relative_path))?,
            ) {
                bail!(
                    "editor target changed after preflight: {}; inspect it by hand before rerunning",
                    file.relative_path.display()
                );
            }
        }

        for (file, state) in changes {
            maybe_inject_editor_publish_failure()?;
            let target = root.join(&file.relative_path);
            let immediate = inspect_editor_target(root, &target)?;
            if !editor_state_is_unchanged(state, &immediate) {
                bail!(
                    "editor target changed immediately before publication: {}; inspect it by hand before rerunning",
                    file.relative_path.display()
                );
            }
            maybe_inject_editor_target_change(root, &target)?;
            let parent = target
                .parent()
                .ok_or_else(|| anyhow!("generated editor file has no parent"))?;
            ensure_editor_directory(root, parent, &mut created_directories)?;
            let staged = transaction_root.join("new").join(&file.relative_path);
            let backup = if matches!(state, EditorTargetState::Existing(_)) {
                let backup = transaction_root.join("backup").join(&file.relative_path);
                create_dir_owner_only(
                    backup
                        .parent()
                        .ok_or_else(|| anyhow!("editor backup has no parent"))?,
                )?;
                fs::rename(&target, &backup).with_context(|| {
                    format!("failed to stage existing editor file {}", target.display())
                })?;
                Some(backup)
            } else {
                None
            };
            publications.push(EditorPublication {
                target: target.clone(),
                backup,
                expected: file.bytes.clone(),
                installed: false,
            });
            if let (EditorTargetState::Existing(expected), Some(backup)) = (
                state,
                &publications
                    .last()
                    .expect("publication was just recorded")
                    .backup,
            ) {
                let actual = read_editor_transaction_file(backup)?;
                if &actual != expected {
                    bail!(
                        "editor target changed while being staged for publication: {}; the changed bytes will be restored",
                        file.relative_path.display()
                    );
                }
            }
            // Hard links make publication and restoration create-only. A malicious same-user
            // process can still swap a validated ancestor between operations; closing that final
            // boundary needs directory-handle APIs and is deliberately out of scope.
            fs::hard_link(&staged, &target)
                .with_context(|| format!("failed to publish editor file {}", target.display()))?;
            publications
                .last_mut()
                .expect("publication was just recorded")
                .installed = true;
        }
        Ok(())
    })();

    if let Err(error) = result {
        if let Err(rollback_error) =
            rollback_editor_publications(&mut publications, &created_directories)
        {
            return Err(error.context(format!(
                "editor transaction rollback failed: {rollback_error:#}; recoverable backups remain in {}",
                transaction_root.display()
            )));
        }
        if let Err(cleanup_error) = fs::remove_dir_all(&transaction_root)
            .with_context(|| format!("failed to clean up {}", transaction_root.display()))
        {
            return Err(error.context(format!(
                "editor transaction cleanup failed: {cleanup_error:#}"
            )));
        }
        return Err(error.context("editor setup transaction was rolled back"));
    }

    fs::remove_dir_all(&transaction_root)
        .with_context(|| format!("failed to clean up {}", transaction_root.display()))?;
    Ok(())
}

fn editor_state_is_unchanged(expected: &EditorTargetState, actual: &EditorTargetState) -> bool {
    match (expected, actual) {
        (EditorTargetState::Missing, EditorTargetState::Missing) => true,
        (EditorTargetState::Existing(expected), EditorTargetState::Existing(actual)) => {
            expected == actual
        }
        _ => false,
    }
}

fn create_editor_transaction_root(root: &Path) -> Result<PathBuf> {
    for _ in 0..128 {
        let sequence =
            EDITOR_TRANSACTION_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = root.join(format!(
            ".evidence-editor.transaction-{}-{sequence}",
            std::process::id()
        ));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(EDITOR_TRANSACTION_MODE);
        }
        match builder.create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to create editor transaction in {}", root.display())
                })
            }
        }
    }
    bail!("failed to reserve a private editor transaction directory")
}

fn ensure_editor_directory(
    root: &Path,
    directory: &Path,
    created: &mut Vec<PathBuf>,
) -> Result<()> {
    let relative = directory
        .strip_prefix(root)
        .map_err(|_| anyhow!("generated editor directory escapes the project root"))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            bail!("generated editor directory is not normalized");
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => bail!(
                "symlink targets or ancestors are not allowed: {}",
                current.display()
            ),
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => bail!(
                "editor output ancestor is not a directory: {}",
                current.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = fs::DirBuilder::new();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt as _;
                    builder.mode(EDITOR_DIRECTORY_MODE);
                }
                match builder.create(&current) {
                    Ok(()) => created.push(current.clone()),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        let metadata = fs::symlink_metadata(&current).with_context(|| {
                            format!(
                                "failed to inspect editor output ancestor {}",
                                current.display()
                            )
                        })?;
                        if metadata.file_type().is_symlink() || !metadata.is_dir() {
                            bail!("editor output ancestor changed during publication");
                        }
                    }
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!(
                                "failed to create editor output directory {}",
                                current.display()
                            )
                        })
                    }
                }
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect editor output ancestor {}",
                        current.display()
                    )
                })
            }
        }
    }
    Ok(())
}

/// Undo a faulted publication in reverse order, refusing to remove anything
/// whose bytes are no longer the ones this run put there.
fn rollback_editor_publications(
    publications: &mut [EditorPublication],
    created_directories: &[PathBuf],
) -> Result<()> {
    maybe_inject_editor_rollback_failure()?;
    let mut failures = Vec::new();
    for publication in publications.iter_mut().rev() {
        if publication.installed {
            let installed = match read_editor_transaction_file(&publication.target) {
                Ok(installed) => installed,
                Err(error) => {
                    failures.push(format!(
                        "failed to verify {} before rollback: {error:#}",
                        publication.target.display()
                    ));
                    continue;
                }
            };
            if installed != publication.expected {
                failures.push(format!(
                    "refused to remove concurrently changed target {}",
                    publication.target.display()
                ));
                continue;
            }
            if let Err(error) = fs::remove_file(&publication.target) {
                failures.push(format!(
                    "failed to remove {}: {error}",
                    publication.target.display()
                ));
                continue;
            }
            publication.installed = false;
        }
        if let Some(backup) = &publication.backup {
            if let Err(error) = fs::hard_link(backup, &publication.target) {
                failures.push(format!(
                    "failed to restore {} without replacing a concurrent target: {error}",
                    publication.target.display()
                ));
            }
        }
    }
    for directory in created_directories.iter().rev() {
        if let Err(error) = fs::remove_dir(directory) {
            failures.push(format!("failed to remove {}: {error}", directory.display()));
        }
    }
    if !failures.is_empty() {
        bail!("{}", failures.join("; "));
    }
    Ok(())
}

fn read_editor_transaction_file(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect transaction file {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_EDITOR_FILE_BYTES
    {
        bail!("editor transaction file is not a bounded regular file");
    }
    fs::read(path).with_context(|| format!("failed to read transaction file {}", path.display()))
}

/// Write one file of the staging tree, in the mode it will carry once a hard
/// link publishes it into the project.
fn write_staged_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("generated editor file has no parent"))?;
    create_dir_owner_only(parent)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(EDITOR_FILE_MODE);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", path.display()))
}

/// Create a directory of the transaction tree, which never leaves the private
/// transaction root and so never carries a published mode.
fn create_dir_owner_only(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(EDITOR_TRANSACTION_MODE);
    }
    builder
        .create(path)
        .with_context(|| format!("failed to create {}", path.display()))
}

fn validate_relative_editor_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        bail!("editor paths must be non-empty and relative");
    }
    for component in path.components() {
        match component {
            Component::Normal(part) if !part.is_empty() => {}
            _ => bail!("editor paths must be normalized and cannot traverse"),
        }
    }
    Ok(())
}

#[cfg(test)]
fn maybe_inject_editor_publish_failure() -> Result<()> {
    EDITOR_TEST_PUBLISH_FAILURE_AFTER.with(|remaining| match remaining.get() {
        Some(0) => {
            remaining.set(None);
            bail!("injected editor publication failure")
        }
        Some(value) => {
            remaining.set(Some(value - 1));
            Ok(())
        }
        None => Ok(()),
    })
}

#[cfg(not(test))]
fn maybe_inject_editor_publish_failure() -> Result<()> {
    Ok(())
}

#[cfg(test)]
fn maybe_inject_editor_rollback_failure() -> Result<()> {
    EDITOR_TEST_ROLLBACK_FAILURE.with(|failure| {
        if failure.replace(false) {
            bail!("injected editor rollback failure")
        }
        Ok(())
    })
}

#[cfg(not(test))]
fn maybe_inject_editor_rollback_failure() -> Result<()> {
    Ok(())
}

/// Stand in for another process writing a destination in the window between
/// the re-inspection that clears it and the hard link that claims it. Only a
/// test can open that window on purpose, and the two guards on either side of
/// it are unprovable without one.
#[cfg(test)]
fn maybe_inject_editor_target_change(root: &Path, target: &Path) -> Result<()> {
    let relative = target
        .strip_prefix(root)
        .map_err(|_| anyhow!("injected editor target escapes the project root"))?;
    EDITOR_TEST_TARGET_CHANGE.with(|change| {
        let mut change = change.borrow_mut();
        if change
            .as_ref()
            .is_some_and(|(expected, _)| expected == relative)
        {
            let (_, bytes) = change.take().expect("matching target change exists");
            fs::write(target, bytes).with_context(|| {
                format!("failed to inject target change at {}", target.display())
            })?;
        }
        Ok(())
    })
}

#[cfg(not(test))]
fn maybe_inject_editor_target_change(_root: &Path, _target: &Path) -> Result<()> {
    Ok(())
}

fn display_paths(paths: &BTreeSet<PathBuf>) -> String {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_evidence_authoring::default_project_marker_document;

    /// The complete set of files one run owns, as an author would list them.
    const MANAGED_FILES: [&str; 6] = [
        ".evidence-editor/manifest.json",
        ".evidence-editor/schemas/project-marker.schema.json",
        ".evidence-editor/schemas/question.schema.json",
        ".vscode/extensions.json",
        ".vscode/settings.json",
        ".zed/settings.json",
    ];

    fn project(temporary: &tempfile::TempDir) -> PathBuf {
        let project = temporary.path().join("authoring-project");
        fs::create_dir(&project).expect("project directory creates");
        fs::write(
            project.join(PROJECT_MARKER_FILE),
            default_project_marker_document(),
        )
        .expect("project marker writes");
        project
    }

    fn managed_bytes(project: &Path) -> BTreeMap<String, Vec<u8>> {
        MANAGED_FILES
            .iter()
            .map(|relative| {
                (
                    (*relative).to_string(),
                    fs::read(project.join(relative))
                        .unwrap_or_else(|error| panic!("reading {relative}: {error}")),
                )
            })
            .collect()
    }

    #[test]
    fn the_catalog_globs_match_the_layout_the_authoring_crate_owns() {
        let globs = EDITOR_SCHEMA_CATALOG
            .iter()
            .map(|entry| entry.file_glob)
            .collect::<Vec<_>>();
        assert!(globs.contains(&PROJECT_MARKER_FILE));
        assert!(globs.contains(&format!("{QUESTIONS_DIRECTORY}/*.yaml").as_str()));
    }

    #[test]
    fn the_embedded_schemas_are_the_committed_generated_artifact() {
        for entry in &EDITOR_SCHEMA_CATALOG {
            let value: serde_json::Value =
                serde_json::from_str(entry.document).expect("an embedded schema is JSON");
            assert_eq!(
                value.get("$schema").and_then(serde_json::Value::as_str),
                Some("https://json-schema.org/draft/2020-12/schema"),
                "the {} schema is not the generated artifact",
                entry.name
            );
        }
    }

    #[test]
    fn setup_writes_the_complete_managed_set_and_maps_every_schema() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = project(&temporary);
        let report = setup_project_editor(&project).expect("editor setup passes");

        assert_eq!(report.status, "configured");
        let mut written = report.files.clone();
        written.sort();
        assert_eq!(written, MANAGED_FILES);

        let settings: serde_json::Value = serde_json::from_slice(
            &fs::read(project.join(".vscode/settings.json")).expect("VS Code settings read"),
        )
        .expect("VS Code settings are JSON");
        let mappings = settings["yaml.schemas"]
            .as_object()
            .expect("VS Code settings map schemas to globs");
        assert_eq!(mappings.len(), EDITOR_SCHEMA_CATALOG.len());
        for entry in &EDITOR_SCHEMA_CATALOG {
            assert_eq!(
                mappings[&format!("./{EDITOR_ROOT}/schemas/{}", entry.filename)],
                serde_json::Value::String(entry.file_glob.to_string()),
            );
        }

        let zed: serde_json::Value = serde_json::from_slice(
            &fs::read(project.join(".zed/settings.json")).expect("Zed settings read"),
        )
        .expect("Zed settings are JSON");
        assert_eq!(
            zed["lsp"]["yaml-language-server"]["settings"]["yaml"]["schemas"],
            serde_json::Value::Object(mappings.clone()),
        );

        let extensions: serde_json::Value = serde_json::from_slice(
            &fs::read(project.join(".vscode/extensions.json")).expect("recommendations read"),
        )
        .expect("recommendations are JSON");
        assert_eq!(extensions["recommendations"][0], "redhat.vscode-yaml");
    }

    #[test]
    fn the_manifest_records_the_hash_of_every_schema_it_wrote() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = project(&temporary);
        setup_project_editor(&project).expect("editor setup passes");

        let manifest: EditorManifest = serde_json::from_slice(
            &fs::read(project.join(EDITOR_MANIFEST_PATH)).expect("manifest reads"),
        )
        .expect("the manifest is the closed format");
        assert_eq!(manifest.format, EDITOR_MANIFEST_FORMAT);
        assert_eq!(manifest.schemas.len(), EDITOR_SCHEMA_CATALOG.len());
        for schema in &manifest.schemas {
            let written = fs::read(project.join(EDITOR_ROOT).join(&schema.path))
                .unwrap_or_else(|error| panic!("reading {}: {error}", schema.path));
            assert_eq!(schema_hash(&written), schema.sha256);
        }
    }

    #[test]
    fn a_second_run_changes_nothing() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = project(&temporary);
        setup_project_editor(&project).expect("first editor setup passes");
        let before = managed_bytes(&project);

        setup_project_editor(&project).expect("second editor setup passes");
        assert_eq!(managed_bytes(&project), before);
        assert!(
            fs::read_dir(&project)
                .expect("project directory reads")
                .all(|entry| !entry
                    .expect("project entry reads")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".evidence-editor.transaction-")),
            "an unchanged rerun must leave no transaction directory"
        );
    }

    #[test]
    fn a_hand_edited_managed_file_is_kept_and_named() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = project(&temporary);
        setup_project_editor(&project).expect("editor setup passes");

        let authored = b"{\n  \"yaml.schemas\": {},\n  \"editor.tabSize\": 4\n}\n".to_vec();
        fs::write(project.join(".vscode/settings.json"), &authored)
            .expect("author edits their settings");
        let before = managed_bytes(&project);

        let error = setup_project_editor(&project)
            .expect_err("a hand-edited managed file must stop the command");
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains(".vscode/settings.json"), "{diagnostic}");
        assert!(diagnostic.contains("no files were changed"), "{diagnostic}");
        assert_eq!(managed_bytes(&project), before);
    }

    /// The catalogue grows as more of the authoring form gains a Rust type
    /// behind it, so a project scaffolded by an earlier release lists fewer
    /// schemas than the release refreshing it. Picking up the new mapping is
    /// exactly what a manifest exists to authorize.
    #[test]
    fn a_prior_manifest_from_a_smaller_catalog_is_refreshed() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = project(&temporary);
        setup_project_editor(&project).expect("initial editor setup passes");

        // Age the installation down to a single-schema catalogue: a manifest
        // listing only the question schema, settings mapping only it, and no
        // file where the schema that release never wrote now belongs.
        let manifest_path = project.join(EDITOR_MANIFEST_PATH);
        let mut prior_manifest: EditorManifest =
            serde_json::from_slice(&fs::read(&manifest_path).expect("manifest reads"))
                .expect("manifest parses");
        prior_manifest.evidencectl_version = "0.9.0".to_string();
        prior_manifest
            .schemas
            .retain(|schema| schema.kind == "question");
        for file in editor_configuration_files(&prior_manifest.schemas)
            .expect("prior configuration renders")
        {
            fs::write(project.join(&file.relative_path), &file.bytes)
                .expect("prior configuration writes");
        }
        fs::write(
            &manifest_path,
            pretty_json(&prior_manifest).expect("manifest serializes"),
        )
        .expect("prior manifest writes");
        fs::remove_file(
            project
                .join(EDITOR_ROOT)
                .join("schemas/project-marker.schema.json"),
        )
        .expect("the aged installation drops the schema it never had");

        let report = setup_project_editor(&project).expect("a smaller prior catalog refreshes");
        assert_eq!(report.status, "configured");
        let mut written = report.files.clone();
        written.sort();
        assert_eq!(written, MANAGED_FILES);
        for file in editor_files().expect("current editor files") {
            assert_eq!(
                fs::read(project.join(&file.relative_path)).expect("refreshed file reads"),
                file.bytes,
                "{} is not the file this release writes",
                file.relative_path.display()
            );
        }
    }

    #[test]
    fn a_prior_manifest_this_command_cannot_read_names_the_way_out() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = project(&temporary);
        setup_project_editor(&project).expect("initial editor setup passes");

        let manifest_path = project.join(EDITOR_MANIFEST_PATH);
        let mut prior_manifest: EditorManifest =
            serde_json::from_slice(&fs::read(&manifest_path).expect("manifest reads"))
                .expect("manifest parses");
        prior_manifest.schemas[0].kind = "selector".to_string();
        fs::write(
            &manifest_path,
            pretty_json(&prior_manifest).expect("manifest serializes"),
        )
        .expect("unreadable manifest writes");

        let error = setup_project_editor(&project)
            .expect_err("a manifest naming a document kind this release has no schema for stops");
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains(EDITOR_ROOT), "{diagnostic}");
        assert!(diagnostic.contains(".vscode/settings.json"), "{diagnostic}");
        assert!(diagnostic.contains(".zed/settings.json"), "{diagnostic}");
        assert!(diagnostic.contains("rerun"), "{diagnostic}");
    }

    /// The generated configuration is read by whoever opens the project, which
    /// is not always the account that scaffolded it.
    #[cfg(unix)]
    #[test]
    fn what_is_published_is_readable_like_the_rest_of_the_project() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = project(&temporary);
        setup_project_editor(&project).expect("editor setup passes");

        let mode = |path: &Path| {
            fs::symlink_metadata(path)
                .unwrap_or_else(|error| panic!("stat {}: {error}", path.display()))
                .permissions()
                .mode()
                & 0o777
        };
        // Take the expected modes from a plain file and directory created in
        // the same process rather than from fixed numbers, so the assertion
        // holds whatever umask the run carries.
        let reference_file = temporary.path().join("reference-file");
        fs::write(&reference_file, b"").expect("reference file writes");
        let reference_directory = temporary.path().join("reference-directory");
        fs::create_dir(&reference_directory).expect("reference directory creates");
        let expected_file_mode = mode(&reference_file) & 0o644;
        let expected_directory_mode = mode(&reference_directory) & 0o755;

        for relative in MANAGED_FILES {
            assert_eq!(
                mode(&project.join(relative)),
                expected_file_mode,
                "{relative} is not readable by a reader of the project"
            );
        }
        for relative in [EDITOR_ROOT, ".evidence-editor/schemas", ".vscode", ".zed"] {
            assert_eq!(
                mode(&project.join(relative)),
                expected_directory_mode,
                "{relative} is not enterable by a reader of the project"
            );
        }
    }

    #[test]
    fn a_directory_with_neither_the_marker_nor_the_authored_pair_is_refused_before_anything_is_written(
    ) {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let bare = temporary.path().join("not-a-project");
        fs::create_dir(&bare).expect("bare directory creates");

        let error = setup_project_editor(&bare).expect_err("a bare directory is not a project");
        assert!(format!("{error:#}").contains(PROJECT_MARKER_FILE));
        assert!(!bare.join(EDITOR_ROOT).exists());
        assert!(!bare.join(".vscode").exists());
    }

    #[test]
    fn a_root_carrying_the_authored_pair_without_a_marker_is_configured() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = temporary.path().join("unmarked-project");
        fs::create_dir(&project).expect("project directory creates");
        fs::write(project.join(OPENAPI_FILE), "openapi: 3.1.0\n").expect("description writes");
        fs::create_dir(project.join(QUESTIONS_DIRECTORY)).expect("question directory creates");

        let report = setup_project_editor(&project).expect("editor setup passes");

        assert_eq!(report.status, "configured");
        let mut written = report.files.clone();
        written.sort();
        assert_eq!(written, MANAGED_FILES);
        for relative in MANAGED_FILES {
            assert!(
                project.join(relative).is_file(),
                "{relative} was not written"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_openapi_description_does_not_declare_a_root() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let described = temporary.path().join("described.openapi.yaml");
        fs::write(&described, "openapi: 3.1.0\n").expect("description writes");
        let borrower = temporary.path().join("not-a-project");
        fs::create_dir(&borrower).expect("bare directory creates");
        std::os::unix::fs::symlink(&described, borrower.join(OPENAPI_FILE))
            .expect("symlinked description");
        fs::create_dir(borrower.join(QUESTIONS_DIRECTORY)).expect("question directory creates");

        let error =
            setup_project_editor(&borrower).expect_err("a borrowed description declares nothing");
        assert!(format!("{error:#}").contains(PROJECT_MARKER_FILE));
        assert!(!borrower.join(EDITOR_ROOT).exists());
        assert!(!borrower.join(".vscode").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_managed_destination_is_refused() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = project(&temporary);
        let outside = temporary.path().join("outside");
        fs::create_dir(&outside).expect("outside directory creates");
        std::os::unix::fs::symlink(&outside, project.join(".vscode"))
            .expect("symlinked settings directory");

        let error =
            setup_project_editor(&project).expect_err("a symlinked ancestor must be refused");
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("symlink"), "{diagnostic}");
        assert!(
            fs::read_dir(&outside)
                .expect("outside directory reads")
                .next()
                .is_none(),
            "a refused run must not write through a symlink"
        );
    }

    #[test]
    fn a_publication_fault_restores_every_prior_file_and_missing_target() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = project(&temporary);
        setup_project_editor(&project).expect("initial editor setup passes");

        // Age the installation so the rerun has work to do: a prior manifest
        // from another version, and one schema whose recorded hash matches the
        // aged bytes rather than the current ones.
        let schema_path = project
            .join(EDITOR_ROOT)
            .join("schemas/question.schema.json");
        let mut prior_schema = fs::read(&schema_path).expect("question schema reads");
        prior_schema.extend_from_slice(b"\n");
        fs::write(&schema_path, &prior_schema).expect("prior schema writes");
        let manifest_path = project.join(EDITOR_MANIFEST_PATH);
        let mut prior_manifest: EditorManifest =
            serde_json::from_slice(&fs::read(&manifest_path).expect("manifest reads"))
                .expect("manifest parses");
        prior_manifest.evidencectl_version = "0.9.0".to_string();
        let aged = prior_manifest
            .schemas
            .iter_mut()
            .find(|schema| schema.kind == "question")
            .expect("the catalog holds the question schema");
        aged.sha256 = schema_hash(&prior_schema);
        fs::write(
            &manifest_path,
            pretty_json(&prior_manifest).expect("manifest serializes"),
        )
        .expect("prior manifest writes");
        fs::remove_dir_all(project.join(".vscode")).expect("VS Code settings remove");

        let current_files = editor_files().expect("current editor files");
        let before = current_files
            .iter()
            .map(|file| {
                let path = project.join(&file.relative_path);
                (
                    file.relative_path.clone(),
                    path.exists()
                        .then(|| fs::read(path).expect("prior file reads")),
                )
            })
            .collect::<BTreeMap<_, _>>();

        EDITOR_TEST_PUBLISH_FAILURE_AFTER.with(|remaining| remaining.set(Some(3)));
        let error = setup_project_editor(&project)
            .expect_err("an injected late publication fault must roll back");
        assert!(format!("{error:#}").contains("rolled back"));

        for (relative, expected) in before {
            let path = project.join(relative);
            assert_eq!(
                path.exists()
                    .then(|| fs::read(path).expect("file reads after rollback")),
                expected
            );
        }
        assert!(
            !project.join(".vscode").exists(),
            "rollback must remove the directories publication created"
        );
        assert!(
            fs::read_dir(&project)
                .expect("project directory reads")
                .all(|entry| !entry
                    .expect("project entry reads")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".evidence-editor.transaction-")),
            "a completed rollback cleans its transaction staging"
        );
    }

    /// A destination preflight found missing, written by someone else while
    /// this run was staging, belongs to whoever wrote it.
    #[test]
    fn a_destination_appearing_after_preflight_is_preserved() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = project(&temporary);
        setup_project_editor(&project).expect("initial editor setup passes");

        let relative = PathBuf::from(".zed/settings.json");
        let target = project.join(&relative);
        fs::remove_file(&target).expect("managed target removes");
        let concurrent = b"{\n  \"concurrent\": true\n}\n".to_vec();
        EDITOR_TEST_TARGET_CHANGE.with(|change| {
            *change.borrow_mut() = Some((relative, concurrent.clone()));
        });

        let error = setup_project_editor(&project)
            .expect_err("a destination that appeared during publication must not be replaced");
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("rolled back"), "{diagnostic}");
        assert_eq!(
            fs::read(&target).expect("concurrent destination reads"),
            concurrent
        );
        assert!(
            fs::read_dir(&project)
                .expect("project directory reads")
                .all(|entry| !entry
                    .expect("project entry reads")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".evidence-editor.transaction-")),
            "a completed rollback cleans its transaction staging"
        );
    }

    /// A managed file changed between the re-inspection that cleared it and
    /// the hard link that would have claimed it goes back the way it was found,
    /// changed bytes and all.
    #[test]
    fn an_existing_target_changed_after_reinspection_is_restored() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = project(&temporary);
        setup_project_editor(&project).expect("initial editor setup passes");

        let relative = PathBuf::from(EDITOR_ROOT).join("schemas/question.schema.json");
        let schema_path = project.join(&relative);
        let mut prior_schema = fs::read(&schema_path).expect("question schema reads");
        prior_schema.extend_from_slice(b"\n");
        fs::write(&schema_path, &prior_schema).expect("prior schema writes");
        let manifest_path = project.join(EDITOR_MANIFEST_PATH);
        let mut prior_manifest: EditorManifest =
            serde_json::from_slice(&fs::read(&manifest_path).expect("manifest reads"))
                .expect("manifest parses");
        prior_manifest.evidencectl_version = "0.9.0".to_string();
        let aged = prior_manifest
            .schemas
            .iter_mut()
            .find(|schema| schema.kind == "question")
            .expect("the catalog holds the question schema");
        aged.sha256 = schema_hash(&prior_schema);
        let prior_manifest_bytes = pretty_json(&prior_manifest).expect("manifest serializes");
        fs::write(&manifest_path, &prior_manifest_bytes).expect("prior manifest writes");

        let concurrent = b"concurrent schema bytes\n".to_vec();
        EDITOR_TEST_TARGET_CHANGE.with(|change| {
            *change.borrow_mut() = Some((relative, concurrent.clone()));
        });
        let error = setup_project_editor(&project)
            .expect_err("a target changed after reinspection must not be replaced");
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("rolled back"), "{diagnostic}");
        assert!(
            diagnostic.contains("changed while being staged"),
            "{diagnostic}"
        );
        assert_eq!(
            fs::read(&schema_path).expect("concurrent schema reads"),
            concurrent
        );
        assert_eq!(
            fs::read(&manifest_path).expect("prior manifest reads"),
            prior_manifest_bytes
        );
    }

    #[test]
    fn a_rollback_that_cannot_complete_keeps_and_reports_its_backups() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = project(&temporary);
        setup_project_editor(&project).expect("initial editor setup passes");

        let schema_path = project
            .join(EDITOR_ROOT)
            .join("schemas/question.schema.json");
        let mut prior_schema = fs::read(&schema_path).expect("question schema reads");
        prior_schema.extend_from_slice(b"\n");
        fs::write(&schema_path, &prior_schema).expect("prior schema writes");
        let manifest_path = project.join(EDITOR_MANIFEST_PATH);
        let mut prior_manifest: EditorManifest =
            serde_json::from_slice(&fs::read(&manifest_path).expect("manifest reads"))
                .expect("manifest parses");
        prior_manifest.evidencectl_version = "0.9.0".to_string();
        let aged = prior_manifest
            .schemas
            .iter_mut()
            .find(|schema| schema.kind == "question")
            .expect("the catalog holds the question schema");
        aged.sha256 = schema_hash(&prior_schema);
        let prior_manifest_bytes = pretty_json(&prior_manifest).expect("manifest serializes");
        fs::write(&manifest_path, &prior_manifest_bytes).expect("prior manifest writes");

        EDITOR_TEST_PUBLISH_FAILURE_AFTER.with(|remaining| remaining.set(Some(1)));
        EDITOR_TEST_ROLLBACK_FAILURE.with(|failure| failure.set(true));
        let error = setup_project_editor(&project)
            .expect_err("an injected rollback fault must preserve its transaction");
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("rollback failed"), "{diagnostic}");
        assert!(
            diagnostic.contains("recoverable backups remain"),
            "{diagnostic}"
        );

        let transaction_root = fs::read_dir(&project)
            .expect("project directory reads")
            .map(|entry| entry.expect("project entry reads").path())
            .find(|path| {
                path.file_name().is_some_and(|name| {
                    name.to_string_lossy()
                        .starts_with(".evidence-editor.transaction-")
                })
            })
            .expect("a failed rollback keeps its transaction directory");
        assert!(diagnostic.contains(&transaction_root.display().to_string()));
        assert_eq!(
            fs::read(&manifest_path).expect("unpublished prior manifest reads"),
            prior_manifest_bytes
        );
    }
}
