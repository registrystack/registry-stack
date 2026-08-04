//! Minimal OpenAPI-assisted Evidence project authoring.
//!
//! OpenAPI can describe a source operation and response shape. It cannot
//! decide an adopter's evidence question, authorization, disclosure policy,
//! runtime, or acceptance cases, so this command deliberately emits none of
//! them.

use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{bail, Context as _};
use clap::{Args, ValueEnum};

use crate::{keygen, suggest};

const SIGNING_KEY_ID: &str = "local-signing-key-1";

#[derive(Clone, Debug, ValueEnum)]
pub enum AuthoringProfile {
    /// Development-only authoring with no deployment assurance claim.
    Local,
}

#[derive(Debug, Args)]
pub struct NewArgs {
    /// New directory to create for the incomplete authoring project.
    pub directory: PathBuf,

    /// OpenAPI 3.0 or 3.1 document: a local path or an HTTPS URL.
    #[arg(long)]
    pub openapi: Option<String>,

    /// Explicit development profile for OpenAPI-assisted authoring.
    #[arg(long, value_enum, requires = "openapi")]
    pub profile: Option<AuthoringProfile>,

    /// OpenAPI operation as "METHOD /path/template"; prompted if absent.
    #[arg(long, requires = "openapi")]
    pub operation: Option<String>,

    /// Response projection pointer; repeat once per selected field.
    #[arg(long = "select", requires = "openapi")]
    pub selection: Vec<String>,

    /// Response status code whose schema is drafted.
    #[arg(long, default_value = "200", requires = "openapi")]
    pub status: String,

    /// Response media type whose schema is drafted.
    #[arg(long, default_value = "application/json", requires = "openapi")]
    pub media_type: String,

    /// Sample response used only to suggest schema bounds.
    #[arg(long, requires = "openapi")]
    pub sample: Option<PathBuf>,

    /// Source identifier for the drafted artifacts.
    #[arg(long, requires = "openapi")]
    pub source_id: Option<String>,

    /// Generate disposable, unbound local signing and HMAC material.
    #[arg(long, requires = "openapi")]
    pub generate_keys: bool,
}

pub fn run(args: NewArgs) -> anyhow::Result<ExitCode> {
    let openapi = args.openapi.as_ref().context(
        "`evidencectl new` starts from an API description; pass --openapi <path-or-https-url>",
    )?;
    if args.profile.is_none() {
        bail!("OpenAPI authoring requires the explicit development profile `--profile local`");
    }

    validate_new_destination(&args.directory)?;
    let prepared = suggest::prepare(&suggest::SuggestArgs {
        openapi: openapi.clone(),
        operation: args.operation.clone(),
        status: args.status,
        media_type: args.media_type,
        selection: args.selection,
        sample: args.sample,
        source_id: args.source_id,
        project: None,
        evidence_bin: None,
    })?;

    let parent = destination_parent(&args.directory)?;
    let staging = tempfile::Builder::new()
        .prefix(".evidencectl-new-")
        .tempdir_in(parent)
        .with_context(|| format!("staging the project in {}", parent.display()))?;
    let staged_root = staging.path();

    write_new_file(
        &staged_root.join("bundle/evidence.yaml"),
        render_authoring_bundle(&prepared.artifacts.source_block).as_bytes(),
        0o644,
    )?;
    let written = suggest::emit::write_into_project(staged_root, &prepared.artifacts.files)?;

    if args.generate_keys {
        write_new_file(&staged_root.join(".gitignore"), b"secrets/\n", 0o644)?;
        keygen::generate_scaffold_key_material(&staged_root.join("secrets"), SIGNING_KEY_ID)
            .context("generating unbound local authoring key material")?;
    }

    fs::set_permissions(staged_root, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("setting permissions on {}", staged_root.display()))?;
    let written = written
        .into_iter()
        .map(|path| {
            path.strip_prefix(staged_root)
                .expect("a drafted artifact is inside the staging project")
                .to_path_buf()
        })
        .collect::<Vec<_>>();
    publish(staging, &args.directory)?;

    println!(
        "Created an incomplete OpenAPI authoring project in {}",
        args.directory.display()
    );
    println!(
        "  source draft: {}",
        args.directory.join("bundle/evidence.yaml").display()
    );
    for relative in written {
        println!("  artifact: {}", args.directory.join(relative).display());
    }
    if args.generate_keys {
        println!(
            "  keys: {} (owner-only, disposable, and not bound to this draft)",
            args.directory.join("secrets").display()
        );
    }
    println!(
        "This is not a runnable deployment. Define and review the evidence question separately."
    );
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

fn render_authoring_bundle(source_block: &str) -> String {
    format!(
        "# INCOMPLETE AUTHORING DRAFT. OpenAPI supplies only the source operation\n\
# and response shape. This file is not a runnable Evidence deployment.\n\
version: 1\n\
assuranceProfile: local\n\
{source_block}"
    )
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
