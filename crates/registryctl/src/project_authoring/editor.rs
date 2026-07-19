// SPDX-License-Identifier: Apache-2.0

const EDITOR_ROOT: &str = ".registry-stack-editor";
const EDITOR_MANIFEST_PATH: &str = ".registry-stack-editor/manifest.json";
const EDITOR_MANIFEST_FORMAT: &str = "registry.stack.editor-manifest";
const EDITOR_MANIFEST_VERSION: u8 = 1;
const MAX_EDITOR_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProjectSchemaKind {
    Project,
    Environment,
    Integration,
    Fixture,
    Entity,
}

impl ProjectSchemaKind {
    pub const ALL: [Self; 5] = [
        Self::Project,
        Self::Environment,
        Self::Integration,
        Self::Fixture,
        Self::Entity,
    ];

    pub const fn document(self) -> &'static str {
        self.catalog_entry().document
    }

    pub const fn filename(self) -> &'static str {
        self.catalog_entry().filename
    }

    pub const fn file_glob(self) -> &'static str {
        self.catalog_entry().file_glob
    }

    const fn name(self) -> &'static str {
        self.catalog_entry().name
    }

    const fn catalog_entry(self) -> &'static ProjectSchemaCatalogEntry {
        match self {
            Self::Project => &PROJECT_SCHEMA_CATALOG[0],
            Self::Environment => &PROJECT_SCHEMA_CATALOG[1],
            Self::Integration => &PROJECT_SCHEMA_CATALOG[2],
            Self::Fixture => &PROJECT_SCHEMA_CATALOG[3],
            Self::Entity => &PROJECT_SCHEMA_CATALOG[4],
        }
    }
}

struct ProjectSchemaCatalogEntry {
    kind: ProjectSchemaKind,
    name: &'static str,
    filename: &'static str,
    file_glob: &'static str,
    document: &'static str,
}

// yaml-language-server treats portable fileMatch patterns as suffix matches by
// prepending `**/`. Keep these suffixes limited to Registry Stack's five
// reserved authored layouts. Exact worktree-root matching requires an editor
// extension because the native VS Code and Zed settings expose no root token.
const PROJECT_SCHEMA_CATALOG: [ProjectSchemaCatalogEntry; 5] = [
    ProjectSchemaCatalogEntry {
        kind: ProjectSchemaKind::Project,
        name: "project",
        filename: "project.schema.json",
        file_glob: "registry-stack.yaml",
        document: include_str!("../../schemas/project-authoring/project.schema.json"),
    },
    ProjectSchemaCatalogEntry {
        kind: ProjectSchemaKind::Environment,
        name: "environment",
        filename: "environment.schema.json",
        file_glob: "environments/*.yaml",
        document: include_str!("../../schemas/project-authoring/environment.schema.json"),
    },
    ProjectSchemaCatalogEntry {
        kind: ProjectSchemaKind::Integration,
        name: "integration",
        filename: "integration.schema.json",
        file_glob: "integrations/*/integration.yaml",
        document: include_str!("../../schemas/project-authoring/integration.schema.json"),
    },
    ProjectSchemaCatalogEntry {
        kind: ProjectSchemaKind::Fixture,
        name: "fixture",
        filename: "fixture.schema.json",
        file_glob: "integrations/*/fixtures/*.yaml",
        document: include_str!("../../schemas/project-authoring/fixture.schema.json"),
    },
    ProjectSchemaCatalogEntry {
        kind: ProjectSchemaKind::Entity,
        name: "entity",
        filename: "entity.schema.json",
        file_glob: "entities/*.yaml",
        document: include_str!("../../schemas/project-authoring/entity.schema.json"),
    },
];

#[derive(Debug, Clone)]
pub struct ProjectEditorSetupOptions {
    pub project_directory: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectEditorSetupReport {
    pub schema_version: &'static str,
    pub status: &'static str,
    pub project_directory: String,
    pub files: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectEditorManifest {
    format: String,
    version: u8,
    registryctl_version: String,
    schemas: Vec<ProjectEditorManifestSchema>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectEditorManifestSchema {
    kind: String,
    path: String,
    file_glob: String,
    sha256: String,
}

struct ProjectEditorFile {
    relative_path: PathBuf,
    bytes: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
enum ProjectEditorTargetState {
    Missing,
    Existing(Vec<u8>),
    Conflict,
    Symlink(PathBuf),
}

struct ManagedPriorEditor {
    allowed_existing: BTreeMap<PathBuf, Vec<u8>>,
}

struct ProjectEditorPublication {
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

pub fn setup_registry_project_editor(
    options: &ProjectEditorSetupOptions,
) -> Result<ProjectEditorSetupReport> {
    let root = canonical_root(&options.project_directory)?;
    require_regular_project_marker(&root)?;
    let files = project_editor_files()?;
    let prior = managed_prior_editor(&root, &files)?;

    let mut states = Vec::with_capacity(files.len());
    let mut conflicts = BTreeSet::new();
    let mut symlinks = BTreeSet::new();
    for file in &files {
        validate_relative_authored_path(&file.relative_path)?;
        let target = root.join(&file.relative_path);
        if !target.starts_with(&root) {
            bail!("generated editor path escapes the project root");
        }
        let state = inspect_project_editor_target(&root, &target)?;
        match &state {
            ProjectEditorTargetState::Existing(actual)
                if actual != &file.bytes
                    && !prior.as_ref().is_some_and(|prior| {
                        prior.allowed_existing.get(&file.relative_path) == Some(actual)
                    }) =>
            {
                conflicts.insert(file.relative_path.clone());
            }
            ProjectEditorTargetState::Conflict => {
                conflicts.insert(file.relative_path.clone());
            }
            ProjectEditorTargetState::Symlink(path) => {
                symlinks.insert(path.clone());
            }
            ProjectEditorTargetState::Missing | ProjectEditorTargetState::Existing(_) => {}
        }
        states.push(state);
    }

    if !conflicts.is_empty() || !symlinks.is_empty() {
        let mut causes = Vec::new();
        if !conflicts.is_empty() {
            causes.push(format!(
                "conflicting files: {}",
                display_editor_paths(&conflicts)
            ));
        }
        if !symlinks.is_empty() {
            causes.push(format!(
                "symlink targets or ancestors are not allowed: {}",
                display_editor_paths(&symlinks)
            ));
        }
        bail!(
            "editor setup preflight failed; {}; no files were changed. Preserve these files and install the Registry Stack schema mappings manually, or restore the expected generated files before rerunning the command",
            causes.join("; ")
        );
    }

    publish_project_editor_files(&root, &files, &states)?;

    Ok(ProjectEditorSetupReport {
        schema_version: PROJECT_EDITOR_REPORT_SCHEMA_VERSION,
        status: "configured",
        project_directory: root.display().to_string(),
        files: files
            .iter()
            .map(|file| file.relative_path.display().to_string())
            .collect(),
    })
}

fn require_regular_project_marker(root: &Path) -> Result<()> {
    let path = root.join(PROJECT_FILE);
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("project root must contain a regular {PROJECT_FILE}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("project root must contain a regular non-symlink {PROJECT_FILE}");
    }
    Ok(())
}

fn project_editor_files() -> Result<Vec<ProjectEditorFile>> {
    let manifest = current_project_editor_manifest();
    let mut files = Vec::with_capacity(9);
    for entry in &PROJECT_SCHEMA_CATALOG {
        files.push(ProjectEditorFile {
            relative_path: PathBuf::from(EDITOR_ROOT)
                .join("schemas")
                .join(entry.filename),
            bytes: entry.document.as_bytes().to_vec(),
        });
    }
    files.push(ProjectEditorFile {
        relative_path: PathBuf::from(EDITOR_MANIFEST_PATH),
        bytes: pretty_json(&manifest)?,
    });
    files.extend(project_editor_configuration_files(&manifest.schemas)?);
    Ok(files)
}

fn current_project_editor_manifest() -> ProjectEditorManifest {
    ProjectEditorManifest {
        format: EDITOR_MANIFEST_FORMAT.to_string(),
        version: EDITOR_MANIFEST_VERSION,
        registryctl_version: env!("CARGO_PKG_VERSION").to_string(),
        schemas: PROJECT_SCHEMA_CATALOG
            .iter()
            .map(|entry| ProjectEditorManifestSchema {
                kind: entry.kind.name().to_string(),
                path: format!("schemas/{}", entry.filename),
                file_glob: entry.file_glob.to_string(),
                sha256: schema_hash(entry.document.as_bytes()),
            })
            .collect(),
    }
}

fn project_editor_configuration_files(
    schemas: &[ProjectEditorManifestSchema],
) -> Result<Vec<ProjectEditorFile>> {
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
        ProjectEditorFile {
            relative_path: PathBuf::from(".vscode/settings.json"),
            bytes: pretty_json(&json!({ "yaml.schemas": schema_mappings.clone() }))?,
        },
        ProjectEditorFile {
            relative_path: PathBuf::from(".vscode/extensions.json"),
            bytes: pretty_json(&json!({ "recommendations": ["redhat.vscode-yaml"] }))?,
        },
        ProjectEditorFile {
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

fn managed_prior_editor(
    root: &Path,
    current_files: &[ProjectEditorFile],
) -> Result<Option<ManagedPriorEditor>> {
    let manifest_path = root.join(EDITOR_MANIFEST_PATH);
    let current_manifest = current_files
        .iter()
        .find(|file| file.relative_path == Path::new(EDITOR_MANIFEST_PATH))
        .expect("current editor files contain their manifest");
    let ProjectEditorTargetState::Existing(manifest_bytes) =
        inspect_project_editor_target(root, &manifest_path)?
    else {
        return Ok(None);
    };
    if manifest_bytes == current_manifest.bytes {
        return Ok(None);
    }

    validate_managed_prior_editor(root, current_files, manifest_bytes)
        .context("existing editor manifest cannot authorize a managed refresh")
        .map(Some)
}

fn validate_managed_prior_editor(
    root: &Path,
    current_files: &[ProjectEditorFile],
    manifest_bytes: Vec<u8>,
) -> Result<ManagedPriorEditor> {
    let manifest: ProjectEditorManifest = serde_json::from_slice(&manifest_bytes)
        .context("prior editor manifest is not the closed JSON format")?;
    if manifest.format != EDITOR_MANIFEST_FORMAT || manifest.version != EDITOR_MANIFEST_VERSION {
        bail!("prior editor manifest uses an unsupported format or version");
    }
    if manifest.registryctl_version.is_empty()
        || manifest.registryctl_version.len() > 128
        || !manifest.registryctl_version.bytes().all(|byte| {
            matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'+')
        })
    {
        bail!("prior editor manifest has an invalid registryctl version");
    }
    if manifest.schemas.len() != PROJECT_SCHEMA_CATALOG.len() {
        bail!("prior editor manifest must contain the exact five-schema catalog");
    }
    for (schema, expected) in manifest.schemas.iter().zip(&PROJECT_SCHEMA_CATALOG) {
        if schema.kind != expected.name
            || schema.path != format!("schemas/{}", expected.filename)
            || schema.file_glob != expected.file_glob
            || !is_schema_hash(&schema.sha256)
        {
            bail!("prior editor manifest schema catalog is not the expected closed catalog");
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
        match inspect_project_editor_target(root, &root.join(&relative_path))? {
            ProjectEditorTargetState::Missing => {}
            ProjectEditorTargetState::Existing(bytes) => {
                if schema_hash(&bytes) != schema.sha256 {
                    bail!(
                        "prior editor schema does not match its manifest hash: {}",
                        relative_path.display()
                    );
                }
                allowed_existing.insert(relative_path, bytes);
            }
            ProjectEditorTargetState::Conflict => bail!(
                "prior editor schema is not a bounded regular file: {}",
                relative_path.display()
            ),
            ProjectEditorTargetState::Symlink(path) => bail!(
                "prior editor schema uses a forbidden symlink target or ancestor: {}",
                path.display()
            ),
        }
    }

    for prior_file in project_editor_configuration_files(&manifest.schemas)? {
        let current = current_by_path
            .get(&prior_file.relative_path)
            .expect("current editor files contain every configuration target");
        match inspect_project_editor_target(root, &root.join(&prior_file.relative_path))? {
            ProjectEditorTargetState::Missing => {}
            ProjectEditorTargetState::Existing(bytes)
                if bytes == prior_file.bytes || bytes.as_slice() == *current =>
            {
                allowed_existing.insert(prior_file.relative_path, bytes);
            }
            ProjectEditorTargetState::Existing(_) | ProjectEditorTargetState::Conflict => bail!(
                "editor configuration was customized and cannot be refreshed automatically: {}",
                prior_file.relative_path.display()
            ),
            ProjectEditorTargetState::Symlink(path) => bail!(
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

fn pretty_json(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .context("failed to serialize deterministic editor configuration")?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn inspect_project_editor_target(root: &Path, target: &Path) -> Result<ProjectEditorTargetState> {
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
                return Ok(ProjectEditorTargetState::Missing)
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
            return Ok(ProjectEditorTargetState::Symlink(relative.to_path_buf()));
        }
        let is_target = index + 1 == components.len();
        if !is_target && !metadata.is_dir() {
            return Ok(ProjectEditorTargetState::Conflict);
        }
        if is_target {
            if !metadata.is_file() || metadata.len() > MAX_EDITOR_FILE_BYTES {
                return Ok(ProjectEditorTargetState::Conflict);
            }
            let actual = fs::read(&current)
                .with_context(|| format!("failed to read {}", current.display()))?;
            return Ok(ProjectEditorTargetState::Existing(actual));
        }
    }
    unreachable!("a non-empty editor path always returns from the component loop")
}

fn publish_project_editor_files(
    root: &Path,
    files: &[ProjectEditorFile],
    states: &[ProjectEditorTargetState],
) -> Result<()> {
    let changes = files
        .iter()
        .zip(states)
        .filter(|(file, state)| match state {
            ProjectEditorTargetState::Missing => true,
            ProjectEditorTargetState::Existing(bytes) => bytes != &file.bytes,
            ProjectEditorTargetState::Conflict | ProjectEditorTargetState::Symlink(_) => false,
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
            write_private_file(
                &transaction_root.join("new").join(&file.relative_path),
                &file.bytes,
            )?;
        }
        for (file, state) in files.iter().zip(states) {
            if !project_editor_state_is_unchanged(
                state,
                &inspect_project_editor_target(root, &root.join(&file.relative_path))?,
            ) {
                bail!(
                    "editor target changed after preflight: {}; inspect it manually before rerunning",
                    file.relative_path.display()
                );
            }
        }

        for (file, state) in changes {
            maybe_inject_editor_publish_failure()?;
            let target = root.join(&file.relative_path);
            let immediate = inspect_project_editor_target(root, &target)?;
            if !project_editor_state_is_unchanged(state, &immediate) {
                bail!(
                    "editor target changed immediately before publication: {}; inspect it manually before rerunning",
                    file.relative_path.display()
                );
            }
            maybe_inject_editor_target_change(root, &target)?;
            let parent = target
                .parent()
                .ok_or_else(|| anyhow!("generated editor file has no parent"))?;
            ensure_project_editor_directory(root, parent, &mut created_directories)?;
            let staged = transaction_root.join("new").join(&file.relative_path);
            let backup = if matches!(state, ProjectEditorTargetState::Existing(_)) {
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
            publications.push(ProjectEditorPublication {
                target: target.clone(),
                backup,
                expected: file.bytes.clone(),
                installed: false,
            });
            if let (ProjectEditorTargetState::Existing(expected), Some(backup)) =
                (state, &publications.last().expect("publication was just recorded").backup)
            {
                let actual = read_project_editor_transaction_file(backup)?;
                if &actual != expected {
                    bail!(
                        "editor target changed while being staged for publication: {}; the changed bytes will be restored",
                        file.relative_path.display()
                    );
                }
            }
            // Hard links make publication and restoration create-only. A malicious same-user
            // process can still swap a validated ancestor between operations; closing that final
            // boundary requires directory-handle/openat-style APIs and is intentionally out of scope.
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
            rollback_project_editor_publications(&mut publications, &created_directories)
        {
            return Err(error.context(format!(
                "editor transaction rollback failed: {rollback_error:#}; recoverable backups remain in {}",
                transaction_root.display()
            )));
        }
        if let Err(cleanup_error) = fs::remove_dir_all(&transaction_root)
            .with_context(|| format!("failed to clean up {}", transaction_root.display()))
        {
            return Err(error.context(format!("editor transaction cleanup failed: {cleanup_error:#}")));
        }
        return Err(error.context("editor setup transaction was rolled back"));
    }

    fs::remove_dir_all(&transaction_root)
        .with_context(|| format!("failed to clean up {}", transaction_root.display()))?;
    Ok(())
}

fn project_editor_state_is_unchanged(
    expected: &ProjectEditorTargetState,
    actual: &ProjectEditorTargetState,
) -> bool {
    match (expected, actual) {
        (ProjectEditorTargetState::Missing, ProjectEditorTargetState::Missing) => true,
        (
            ProjectEditorTargetState::Existing(expected),
            ProjectEditorTargetState::Existing(actual),
        ) => expected == actual,
        _ => false,
    }
}

fn create_editor_transaction_root(root: &Path) -> Result<PathBuf> {
    for _ in 0..128 {
        let sequence = EDITOR_TRANSACTION_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = root.join(format!(
            ".registry-stack-editor.transaction-{}-{sequence}",
            std::process::id()
        ));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        match builder.create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to create editor transaction in {}", root.display()))
            }
        }
    }
    bail!("failed to reserve a private editor transaction directory")
}

fn ensure_project_editor_directory(
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
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!("symlink targets or ancestors are not allowed: {}", current.display())
            }
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => bail!("editor output ancestor is not a directory: {}", current.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = fs::DirBuilder::new();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt as _;
                    builder.mode(0o700);
                }
                match builder.create(&current) {
                    Ok(()) => created.push(current.clone()),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        let metadata = fs::symlink_metadata(&current).with_context(|| {
                            format!("failed to inspect editor output ancestor {}", current.display())
                        })?;
                        if metadata.file_type().is_symlink() || !metadata.is_dir() {
                            bail!("editor output ancestor changed during publication");
                        }
                    }
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("failed to create editor output directory {}", current.display())
                        })
                    }
                }
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to inspect editor output ancestor {}", current.display())
                })
            }
        }
    }
    Ok(())
}

fn rollback_project_editor_publications(
    publications: &mut [ProjectEditorPublication],
    created_directories: &[PathBuf],
) -> Result<()> {
    maybe_inject_editor_rollback_failure()?;
    let mut failures = Vec::new();
    for publication in publications.iter_mut().rev() {
        if publication.installed {
            let installed = match read_project_editor_transaction_file(&publication.target) {
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

fn read_project_editor_transaction_file(path: &Path) -> Result<Vec<u8>> {
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
            fs::write(target, bytes)
                .with_context(|| format!("failed to inject target change at {}", target.display()))?;
        }
        Ok(())
    })
}

#[cfg(not(test))]
fn maybe_inject_editor_target_change(_root: &Path, _target: &Path) -> Result<()> {
    Ok(())
}

fn display_editor_paths(paths: &BTreeSet<PathBuf>) -> String {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod editor_transaction_tests {
    use super::*;

    #[test]
    fn publish_failure_restores_prior_files_and_missing_targets() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = temporary.path().join("editor-project");
        fs::create_dir(&project).expect("project directory creates");
        fs::write(project.join(PROJECT_FILE), b"invalid-yaml: [")
            .expect("project marker writes");
        let options = ProjectEditorSetupOptions {
            project_directory: project.clone(),
        };
        setup_registry_project_editor(&options).expect("initial editor setup passes");

        let schema_path = project.join(EDITOR_ROOT).join("schemas/project.schema.json");
        let mut prior_schema = fs::read(&schema_path).expect("project schema reads");
        prior_schema.extend_from_slice(b"\n");
        fs::write(&schema_path, &prior_schema).expect("prior schema writes");
        let manifest_path = project.join(EDITOR_MANIFEST_PATH);
        let mut prior_manifest: ProjectEditorManifest =
            serde_json::from_slice(&fs::read(&manifest_path).expect("manifest reads"))
                .expect("manifest parses");
        prior_manifest.registryctl_version = "0.9.0".to_string();
        prior_manifest.schemas[0].sha256 = schema_hash(&prior_schema);
        fs::write(&manifest_path, pretty_json(&prior_manifest).expect("manifest serializes"))
            .expect("prior manifest writes");
        fs::remove_dir_all(project.join(".vscode")).expect("VS Code settings remove");

        let current_files = project_editor_files().expect("current editor files");
        let before = current_files
            .iter()
            .map(|file| {
                let path = project.join(&file.relative_path);
                (
                    file.relative_path.clone(),
                    path.exists().then(|| fs::read(path).expect("prior file reads")),
                )
            })
            .collect::<BTreeMap<_, _>>();
        EDITOR_TEST_PUBLISH_FAILURE_AFTER.with(|remaining| remaining.set(Some(3)));
        let error = setup_registry_project_editor(&options)
            .expect_err("injected late publication failure must roll back");
        assert!(format!("{error:#}").contains("rolled back"));

        for (relative, expected) in before {
            let path = project.join(relative);
            assert_eq!(
                path.exists().then(|| fs::read(path).expect("file reads after rollback")),
                expected
            );
        }
        assert!(
            !project.join(".vscode").exists(),
            "rollback must remove editor directories created during publication"
        );
        assert!(
            fs::read_dir(&project)
                .expect("project directory reads")
                .all(|entry| !entry
                    .expect("project entry reads")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".registry-stack-editor.transaction-")),
            "transaction staging must be cleaned after rollback"
        );
    }

    #[test]
    fn destination_appearing_after_preflight_is_preserved() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = temporary.path().join("editor-project");
        fs::create_dir(&project).expect("project directory creates");
        fs::write(project.join(PROJECT_FILE), b"invalid-yaml: [")
            .expect("project marker writes");
        let options = ProjectEditorSetupOptions {
            project_directory: project.clone(),
        };
        setup_registry_project_editor(&options).expect("initial editor setup passes");

        let relative = PathBuf::from(".zed/settings.json");
        let target = project.join(&relative);
        fs::remove_file(&target).expect("managed target removes");
        let concurrent = b"{\n  \"concurrent\": true\n}\n".to_vec();
        EDITOR_TEST_TARGET_CHANGE.with(|change| {
            *change.borrow_mut() = Some((relative, concurrent.clone()));
        });

        let error = setup_registry_project_editor(&options)
            .expect_err("concurrently appearing destination must not be replaced");
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
                    .starts_with(".registry-stack-editor.transaction-")),
            "successful rollback cleans transaction staging"
        );
    }

    #[test]
    fn existing_target_changed_after_reinspection_is_restored() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = temporary.path().join("editor-project");
        fs::create_dir(&project).expect("project directory creates");
        fs::write(project.join(PROJECT_FILE), b"invalid-yaml: [")
            .expect("project marker writes");
        let options = ProjectEditorSetupOptions {
            project_directory: project.clone(),
        };
        setup_registry_project_editor(&options).expect("initial editor setup passes");

        let relative = PathBuf::from(EDITOR_ROOT).join("schemas/project.schema.json");
        let schema_path = project.join(&relative);
        let mut prior_schema = fs::read(&schema_path).expect("project schema reads");
        prior_schema.extend_from_slice(b"\n");
        fs::write(&schema_path, &prior_schema).expect("prior schema writes");
        let manifest_path = project.join(EDITOR_MANIFEST_PATH);
        let mut prior_manifest: ProjectEditorManifest =
            serde_json::from_slice(&fs::read(&manifest_path).expect("manifest reads"))
                .expect("manifest parses");
        prior_manifest.registryctl_version = "0.9.0".to_string();
        prior_manifest.schemas[0].sha256 = schema_hash(&prior_schema);
        let prior_manifest_bytes = pretty_json(&prior_manifest).expect("manifest serializes");
        fs::write(&manifest_path, &prior_manifest_bytes).expect("prior manifest writes");

        let concurrent = b"concurrent schema bytes\n".to_vec();
        EDITOR_TEST_TARGET_CHANGE.with(|change| {
            *change.borrow_mut() = Some((relative, concurrent.clone()));
        });
        let error = setup_registry_project_editor(&options)
            .expect_err("concurrently changed existing destination must not be replaced");
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("rolled back"), "{diagnostic}");
        assert!(diagnostic.contains("changed while being staged"), "{diagnostic}");
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
    fn rollback_failure_preserves_and_reports_recoverable_backup() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = temporary.path().join("editor-project");
        fs::create_dir(&project).expect("project directory creates");
        fs::write(project.join(PROJECT_FILE), b"invalid-yaml: [")
            .expect("project marker writes");
        let options = ProjectEditorSetupOptions {
            project_directory: project.clone(),
        };
        setup_registry_project_editor(&options).expect("initial editor setup passes");

        let schema_path = project.join(EDITOR_ROOT).join("schemas/project.schema.json");
        let mut prior_schema = fs::read(&schema_path).expect("project schema reads");
        prior_schema.extend_from_slice(b"\n");
        fs::write(&schema_path, &prior_schema).expect("prior schema writes");
        let manifest_path = project.join(EDITOR_MANIFEST_PATH);
        let mut prior_manifest: ProjectEditorManifest =
            serde_json::from_slice(&fs::read(&manifest_path).expect("manifest reads"))
                .expect("manifest parses");
        prior_manifest.registryctl_version = "0.9.0".to_string();
        prior_manifest.schemas[0].sha256 = schema_hash(&prior_schema);
        fs::write(&manifest_path, pretty_json(&prior_manifest).expect("manifest serializes"))
            .expect("prior manifest writes");

        EDITOR_TEST_PUBLISH_FAILURE_AFTER.with(|remaining| remaining.set(Some(1)));
        EDITOR_TEST_ROLLBACK_FAILURE.with(|failure| failure.set(true));
        let error = setup_registry_project_editor(&options)
            .expect_err("injected rollback failure must preserve its transaction");
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("rollback failed"), "{diagnostic}");
        assert!(diagnostic.contains("recoverable backups remain"), "{diagnostic}");

        let transaction_root = fs::read_dir(&project)
            .expect("project directory reads")
            .map(|entry| entry.expect("project entry reads").path())
            .find(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(
                        ".registry-stack-editor.transaction-",
                    ))
            })
            .expect("failed rollback preserves its transaction directory");
        assert!(diagnostic.contains(&transaction_root.display().to_string()));
        let backup = transaction_root
            .join("backup")
            .join(EDITOR_ROOT)
            .join("schemas/project.schema.json");
        assert_eq!(
            fs::read(&backup).expect("recoverable schema backup reads"),
            prior_schema
        );
        assert_eq!(
            fs::read(&manifest_path).expect("unpublished prior manifest reads"),
            pretty_json(&prior_manifest).expect("prior manifest serializes")
        );
    }
}
