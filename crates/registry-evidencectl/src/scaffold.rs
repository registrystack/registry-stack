//! Minimal OpenAPI-assisted Evidence project authoring.
//!
//! `new` retains the API description for a later question-authoring step. It
//! does not select an operation or invent Evidence semantics, source policy,
//! runtime configuration, or acceptance cases.

use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{bail, Context as _};
use clap::{Args, ValueEnum};

use crate::{keygen, suggest, tooling_editor};

const RETAINED_OPENAPI_FILE: &str = "source.openapi.yaml";

#[derive(Clone, Debug, ValueEnum)]
pub enum AuthoringProfile {
    /// Development-only authoring with no deployment assurance claim.
    Local,
}

#[derive(Debug, Args)]
pub struct NewArgs {
    /// New directory to create for the editable authoring project.
    pub directory: PathBuf,

    /// OpenAPI 3.0 or 3.1 document: a local path or an HTTPS URL.
    #[arg(long)]
    pub openapi: Option<String>,

    /// Explicit development profile for OpenAPI-assisted authoring.
    #[arg(long, value_enum, requires = "openapi")]
    pub profile: Option<AuthoringProfile>,

    /// Compatibility flag; local projects now always generate disposable keys.
    #[arg(long = "generate-keys", requires = "openapi", hide = true)]
    pub _generate_keys: bool,
}

pub fn run(args: NewArgs) -> anyhow::Result<ExitCode> {
    let openapi = args.openapi.as_ref().context(
        "`evidencectl new` starts from an API description; pass --openapi <path-or-https-url>",
    )?;
    if args.profile.is_none() {
        bail!("OpenAPI authoring requires the explicit development profile `--profile local`");
    }

    validate_new_destination(&args.directory)?;
    let parent = destination_parent(&args.directory)?;
    let source = suggest::fetch::spec_source(openapi)?;
    let (_, document) = suggest::load::open_retained(&source)?;

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
    write_new_file(
        &staged_root.join(RETAINED_OPENAPI_FILE),
        document.as_bytes(),
        0o644,
    )?;
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
        "Created an editable OpenAPI authoring project in {}",
        args.directory.display()
    );
    println!(
        "  OpenAPI: {} (retained exactly for question authoring)",
        args.directory.join(RETAINED_OPENAPI_FILE).display()
    );
    println!(
        "  selectors: {}",
        args.directory.join("selectors").display()
    );
    println!("  sources: {}", args.directory.join("sources").display());
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
    println!(
        "Next: run `evidencectl source suggest --project {}` to draft one editable source.",
        args.directory.display()
    );
    println!("No question, fixture case, runtime, target, or deployment bundle was generated.");
    Ok(ExitCode::SUCCESS)
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
