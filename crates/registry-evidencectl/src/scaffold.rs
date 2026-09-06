//! Minimal Evidence project authoring from OpenAPI, a local starter, or a SQLite extract.
//!
//! `new` retains an API description for a later question-authoring step, or
//! creates a runnable synthetic starter around one fixed statement. The
//! starter is an editable example, not a deployment policy or production
//! extract.

use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{bail, Context as _, Result};
use clap::{ArgGroup, Args, ValueEnum};

use crate::{keygen, suggest, tooling_editor};

const RETAINED_OPENAPI_FILE: &str = "source.openapi.yaml";
const MAX_STARTER_FILES: usize = 512;
const MAX_STARTER_BYTES: usize = 16 * 1024 * 1024;
const MAX_STARTER_FILE_BYTES: u64 = 1024 * 1024;
const STARTER_TOP_LEVEL_FILES: &[&str] = &["README.md"];
const STARTER_DIRECTORIES: &[&str] = &[
    "selectors",
    "sources",
    "adapters",
    "schemas",
    "questions",
    "derivations",
    "fixtures",
    "codelists",
    "queries",
    "targets",
];

#[derive(Clone, Debug, ValueEnum)]
pub enum AuthoringProfile {
    /// Development-only authoring with no deployment assurance claim.
    Local,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum AuthoringTransport {
    /// Author a fixed statement over a published SQLite extract.
    SqliteExtract,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("authoring_source")
        .required(true)
        .multiple(false)
        .args(["openapi", "transport", "starter"])
))]
pub struct NewArgs {
    /// New directory to create for the editable authoring project.
    pub directory: PathBuf,

    /// OpenAPI 3.0 or 3.1 document: a local path or an HTTPS URL.
    #[arg(long)]
    pub openapi: Option<String>,

    /// Source transport to author without an API description.
    #[arg(long, value_enum, conflicts_with = "openapi")]
    pub transport: Option<AuthoringTransport>,

    /// Reviewed local starter directory to copy without requiring an API description.
    #[arg(long, conflicts_with_all = ["openapi", "transport"])]
    pub starter: Option<PathBuf>,

    /// Explicit development profile for local authoring.
    #[arg(long, value_enum, required = true)]
    pub profile: Option<AuthoringProfile>,

    /// Compatibility flag; local projects now always generate disposable keys.
    #[arg(long = "generate-keys", requires = "openapi", hide = true)]
    pub _generate_keys: bool,
}

pub fn run(args: NewArgs) -> anyhow::Result<ExitCode> {
    let source = match (args.openapi.as_deref(), args.transport, args.starter.as_deref()) {
        (Some(openapi), None, None) => AuthoringSource::OpenApi(openapi),
        (None, Some(AuthoringTransport::SqliteExtract), None) => AuthoringSource::SqliteExtract,
        (None, None, Some(starter)) => AuthoringSource::Starter(starter),
        (None, None, None) => bail!(
            "pass --openapi <path-or-https-url> for API authoring, --transport sqlite-extract for extract authoring, or --starter <dir> for an offline starter"
        ),
        _ => bail!("--openapi, --transport, and --starter cannot be used together"),
    };
    if args.profile.is_none() {
        bail!(
            "{} authoring requires the explicit development profile `--profile local`",
            source.label()
        );
    }

    validate_new_destination(&args.directory)?;
    let parent = destination_parent(&args.directory)?;
    let retained_openapi = match source {
        AuthoringSource::OpenApi(openapi) => {
            let source = suggest::fetch::spec_source(openapi)?;
            let (_, document) = suggest::load::open_retained(&source)?;
            Some(document)
        }
        AuthoringSource::SqliteExtract => None,
        AuthoringSource::Starter(_) => None,
    };
    let starter_files = match source {
        AuthoringSource::Starter(starter) => collect_starter_files(starter)?,
        AuthoringSource::OpenApi(_) | AuthoringSource::SqliteExtract => Vec::new(),
    };
    // A starter that ships no source (its README asks for one to be imported
    // or authored first) cannot yet prove itself with `fixtures run`, so the
    // printed next step must defer to the starter's own README instead.
    let starter_ships_a_source = starter_files
        .iter()
        .any(|file| file.relative.starts_with("sources"));

    let staging = tempfile::Builder::new()
        .prefix(".evidencectl-new-")
        .tempdir_in(parent)
        .with_context(|| format!("staging the project in {}", parent.display()))?;
    let staged_root = staging.path();

    write_new_file(
        &staged_root.join(".gitignore"),
        b"secrets/\n.evidence/\n",
        0o644,
    )?;
    // A project a reader can edit needs a page naming what was written and what
    // comes next, and the two authoring paths leave different things standing:
    // the starter is a working example, the retained description is an empty
    // frame around one operation not yet selected.
    if !matches!(source, AuthoringSource::Starter(_))
        || !starter_files
            .iter()
            .any(|file| file.relative == Path::new("README.md"))
    {
        write_new_file(&staged_root.join("README.md"), source.readme(), 0o644)?;
    }
    if let Some(document) = retained_openapi.as_ref() {
        write_new_file(
            &staged_root.join(RETAINED_OPENAPI_FILE),
            document.as_bytes(),
            0o644,
        )?;
    }
    write_new_file(
        &staged_root.join(registry_evidence_authoring::PROJECT_MARKER_FILE),
        registry_evidence_authoring::default_project_marker_document().as_bytes(),
        0o644,
    )?;
    for directory in [
        "selectors",
        "sources",
        "adapters",
        "schemas",
        "questions",
        "derivations",
        "fixtures",
    ] {
        fs::create_dir(staged_root.join(directory))
            .with_context(|| format!("creating the empty {directory} directory"))?;
    }
    if matches!(source, AuthoringSource::SqliteExtract) {
        fs::create_dir(staged_root.join("queries"))
            .context("creating the empty queries directory")?;
        write_sqlite_starter(staged_root)?;
    }
    for file in starter_files {
        write_new_file(&staged_root.join(file.relative), &file.contents, 0o644)?;
    }

    keygen::generate_scaffold_key_material(&staged_root.join("secrets"))
        .context("generating unbound local authoring key material")?;

    // Schema mappings belong to a project from its first minute, so that the
    // editor an adopter writes their first question in already knows the form.
    // Staging is the only place this can run without a conflict check that
    // could refuse: nothing else has ever written here.
    tooling_editor::setup_project_editor(staged_root)
        .context("configuring project-local editor schema mappings")?;

    fs::set_permissions(staged_root, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("setting permissions on {}", staged_root.display()))?;
    publish(staging, &args.directory)?;

    println!(
        "Created an editable {} authoring project in {}",
        source.label(),
        args.directory.display()
    );
    println!(
        "  README: {} (what each file holds, and what comes next)",
        args.directory.join("README.md").display()
    );
    if matches!(source, AuthoringSource::OpenApi(_)) {
        println!(
            "  OpenAPI: {} (retained exactly for question authoring)",
            args.directory.join(RETAINED_OPENAPI_FILE).display()
        );
    }
    println!(
        "  selectors: {}",
        args.directory.join("selectors").display()
    );
    println!("  sources: {}", args.directory.join("sources").display());
    if matches!(source, AuthoringSource::SqliteExtract) || args.directory.join("queries").exists() {
        println!("  queries: {}", args.directory.join("queries").display());
    }
    if args.directory.join("targets").exists() {
        println!("  targets: {}", args.directory.join("targets").display());
    }
    println!(
        "  questions: {}",
        args.directory.join("questions").display()
    );
    println!(
        "  derivations: {}",
        args.directory.join("derivations").display()
    );
    println!("  fixtures: {}", args.directory.join("fixtures").display());
    println!(
        "  keys: {} (owner-only, disposable, and unbound)",
        args.directory.join("secrets").display()
    );
    match source {
        AuthoringSource::OpenApi(_) => println!(
            "Next: run `evidencectl source suggest --project {}` to draft one editable source.",
            args.directory.display()
        ),
        AuthoringSource::SqliteExtract => {
            println!(
                "Next: run `evidencectl fixtures run --project {}` to prove the synthetic starter, then edit its source, statement, schemas, derivation, and fixtures together.",
                args.directory.display()
            );
        }
        AuthoringSource::Starter(_) if starter_ships_a_source => println!(
            "Next: run `evidencectl fixtures run --project {}` to prove the copied starter before live credentials.",
            args.directory.display()
        ),
        AuthoringSource::Starter(_) => println!(
            "Next: follow {}/README.md; this starter ships no source, so import or author one before `evidencectl fixtures run --project {}`.",
            args.directory.display(),
            args.directory.display()
        ),
    }
    match source {
        AuthoringSource::OpenApi(_) => println!(
            "No question, fixture case, runtime, target, or deployment bundle was generated."
        ),
        AuthoringSource::SqliteExtract => println!(
            "A synthetic source, question, and fixture were generated. No runtime, target, production extract, or deployment bundle was generated."
        ),
        AuthoringSource::Starter(starter) => println!(
            "Starter files were copied from {}. No OpenAPI, secret, runtime, deployment target, production extract, or deployment bundle was imported.",
            starter.display()
        ),
    }
    Ok(ExitCode::SUCCESS)
}

#[derive(Clone, Copy)]
enum AuthoringSource<'a> {
    OpenApi(&'a str),
    SqliteExtract,
    Starter(&'a Path),
}

impl AuthoringSource<'_> {
    fn label(self) -> &'static str {
        match self {
            Self::OpenApi(_) => "OpenAPI",
            Self::SqliteExtract => "SQLite-extract",
            Self::Starter(_) => "starter",
        }
    }

    fn readme(self) -> &'static [u8] {
        match self {
            Self::OpenApi(_) => include_bytes!("../templates/openapi/README.md"),
            Self::SqliteExtract => include_bytes!("../templates/sqlite-extract/README.md"),
            Self::Starter(_) => include_bytes!("../templates/starter/README.md"),
        }
    }
}

fn validate_new_destination(path: &Path) -> anyhow::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => bail!(
            "refusing to replace existing project path {}; choose a new directory",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("inspecting project path {}", path.display()))
        }
    }
}

struct StarterFile {
    relative: PathBuf,
    contents: Vec<u8>,
}

fn collect_starter_files(root: &Path) -> Result<Vec<StarterFile>> {
    let root = plain_directory(root, "starter directory")?;
    let mut files = Vec::new();
    let mut bytes = 0usize;
    for file in STARTER_TOP_LEVEL_FILES {
        let path = root.join(file);
        if path.exists() {
            push_starter_file(&root, Path::new(file), &mut files, &mut bytes)?;
        }
    }
    for directory in STARTER_DIRECTORIES {
        let path = root.join(directory);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                collect_starter_directory(&root, Path::new(directory), 0, &mut files, &mut bytes)?;
            }
            Ok(_) => bail!("starter entries must be plain files or directories"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspecting starter directory {}", path.display()));
            }
        }
    }
    if files.is_empty() {
        bail!("starter directory contains no ordinary Evidence starter files");
    }
    files.sort_by(|left, right| left.relative.cmp(&right.relative));
    Ok(files)
}

fn collect_starter_directory(
    root: &Path,
    relative: &Path,
    depth: usize,
    files: &mut Vec<StarterFile>,
    bytes: &mut usize,
) -> Result<()> {
    if depth > 16 {
        bail!("starter file nesting is too deep");
    }
    for entry in fs::read_dir(root.join(relative))
        .with_context(|| format!("reading starter directory {}", relative.display()))?
    {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("starter file names must be UTF-8"))?;
        if name.starts_with('.') {
            bail!("starter files must not be hidden control files");
        }
        let child = relative.join(name);
        let metadata = fs::symlink_metadata(root.join(&child))
            .with_context(|| format!("inspecting starter file {}", child.display()))?;
        if metadata.file_type().is_symlink() {
            bail!("starter files must not be symbolic links");
        }
        if metadata.is_dir() {
            collect_starter_directory(root, &child, depth + 1, files, bytes)?;
        } else if metadata.is_file() {
            push_starter_file(root, &child, files, bytes)?;
        } else {
            bail!("starter entries must be plain files or directories");
        }
    }
    Ok(())
}

fn push_starter_file(
    root: &Path,
    relative: &Path,
    files: &mut Vec<StarterFile>,
    bytes: &mut usize,
) -> Result<()> {
    if !starter_relative_path(relative) {
        bail!("starter files must stay in ordinary Evidence authoring directories");
    }
    if files.len() >= MAX_STARTER_FILES {
        bail!("starter directory contains too many files");
    }
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("inspecting starter file {}", relative.display()))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_STARTER_FILE_BYTES
    {
        bail!("starter files must be bounded plain files");
    }
    let contents =
        fs::read(&path).with_context(|| format!("reading starter file {}", relative.display()))?;
    if contents.len() as u64 > MAX_STARTER_FILE_BYTES {
        bail!("starter file exceeds its byte limit");
    }
    *bytes = bytes
        .checked_add(contents.len())
        .ok_or_else(|| anyhow::anyhow!("starter file byte count overflowed"))?;
    if *bytes > MAX_STARTER_BYTES {
        bail!("starter directory exceeds its byte limit");
    }
    files.push(StarterFile {
        relative: relative.to_path_buf(),
        contents,
    });
    Ok(())
}

fn starter_relative_path(relative: &Path) -> bool {
    let text = relative.to_string_lossy();
    if text.is_empty() || text.contains('\\') {
        return false;
    }
    let mut components = relative.components();
    let Some(std::path::Component::Normal(first)) = components.next() else {
        return false;
    };
    let Some(first) = first.to_str() else {
        return false;
    };
    if STARTER_TOP_LEVEL_FILES.contains(&first) {
        return components.next().is_none();
    }
    STARTER_DIRECTORIES.contains(&first)
        && components.all(|component| match component {
            std::path::Component::Normal(part) => part
                .to_str()
                .is_some_and(|part| !part.is_empty() && part != "." && part != ".."),
            _ => false,
        })
}

fn destination_parent(path: &Path) -> anyhow::Result<&Path> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("inspecting project parent {}", parent.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "project parent {} must be an existing plain directory",
            parent.display()
        );
    }
    Ok(parent)
}

fn plain_directory(path: &Path, description: &str) -> Result<PathBuf> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspecting {description}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("{description} must be an existing plain directory");
    }
    fs::canonicalize(path).with_context(|| format!("resolving {description}"))
}

fn write_new_file(path: &Path, contents: &[u8], mode: u32) -> anyhow::Result<()> {
    use std::{fs::OpenOptions, io::Write as _, os::unix::fs::OpenOptionsExt as _};

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating directory {}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("persisting {}", path.display()))
}

const SQLITE_STARTER_FILES: &[(&str, &[u8])] = &[
    (
        "selectors/record-reference-v1.yaml",
        include_bytes!("../templates/sqlite-extract/selectors/record-reference-v1.yaml"),
    ),
    (
        "sources/record-status.yaml",
        include_bytes!("../templates/sqlite-extract/sources/record-status.yaml"),
    ),
    (
        "queries/record-status.sql",
        include_bytes!("../templates/sqlite-extract/queries/record-status.sql"),
    ),
    (
        "adapters/record-status-extract.rhai",
        include_bytes!("../templates/sqlite-extract/adapters/record-status-extract.rhai"),
    ),
    (
        "schemas/record-status-response.schema.yaml",
        include_bytes!("../templates/sqlite-extract/schemas/record-status-response.schema.yaml"),
    ),
    (
        "schemas/record-status-facts.schema.yaml",
        include_bytes!("../templates/sqlite-extract/schemas/record-status-facts.schema.yaml"),
    ),
    (
        "questions/record-status.yaml",
        include_bytes!("../templates/sqlite-extract/questions/record-status.yaml"),
    ),
    (
        "derivations/record-status.rhai",
        include_bytes!("../templates/sqlite-extract/derivations/record-status.rhai"),
    ),
    (
        "fixtures/record-status.yaml",
        include_bytes!("../templates/sqlite-extract/fixtures/record-status.yaml"),
    ),
];

fn write_sqlite_starter(root: &Path) -> anyhow::Result<()> {
    for (relative, contents) in SQLITE_STARTER_FILES {
        write_new_file(&root.join(relative), contents, 0o644)?;
    }
    Ok(())
}

fn publish(staging: tempfile::TempDir, destination: &Path) -> anyhow::Result<()> {
    let staged = staging.keep();
    if let Err(error) = rename_noreplace(&staged, destination) {
        let _ = fs::remove_dir_all(&staged);
        return Err(error).with_context(|| {
            format!(
                "publishing the project without replacing {}",
                destination.display()
            )
        });
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn rename_noreplace(source: &Path, destination: &Path) -> std::io::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        source,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from)
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn rename_noreplace(_source: &Path, _destination: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-replace project publication is unsupported on this platform",
    ))
}
