//! Public JWKS assembly from public JWK files. Inputs containing private
//! material are rejected outright.

use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::PathBuf,
    process::ExitCode,
};

use anyhow::{bail, Context, Result};
use clap::Args;
use registry_platform_crypto::{canonicalize_json, PublicJwk};
use serde_json::json;

use crate::OutputFormat;

const OUTPUT_FILE_MODE: u32 = 0o644;

#[derive(Debug, Args)]
pub struct JwksArgs {
    /// Output JWKS document path.
    #[arg(long)]
    pub output: PathBuf,

    /// Overwrite an existing output file.
    #[arg(long)]
    pub force: bool,

    /// Public JWK files to include, in order.
    #[arg(required = true)]
    pub public_jwk_files: Vec<PathBuf>,
}

pub fn run(args: JwksArgs, format: OutputFormat) -> Result<ExitCode> {
    if args.output.exists() && !args.force {
        bail!(
            "refusing to overwrite existing output without --force: {}",
            args.output.display()
        );
    }

    let mut entries = Vec::new();
    // canonical bytes per kid already accepted, so a repeated kid can be
    // recognized as either an identical duplicate or a genuine conflict.
    let mut seen_by_kid: HashMap<String, Vec<u8>> = HashMap::new();

    for path in &args.public_jwk_files {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        // Validates the JWK and hard-rejects any private member (including a
        // "d" value); the error never carries the file's contents.
        let public = PublicJwk::parse(&contents)
            .with_context(|| format!("{} is not a valid public JWK", path.display()))?;
        let kid = public
            .kid
            .clone()
            .ok_or_else(|| anyhow::anyhow!("{} is missing a \"kid\" member", path.display()))?;

        let value: serde_json::Value = serde_json::from_str(&contents)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        let canonical = canonicalize_json(&value)
            .with_context(|| format!("failed to canonicalize {}", path.display()))?;

        match seen_by_kid.get(&kid) {
            Some(existing) if existing == &canonical => continue,
            Some(_) => bail!(
                "conflicting public JWKs share kid \"{kid}\" (last seen at {})",
                path.display()
            ),
            None => {
                seen_by_kid.insert(kid, canonical);
                entries.push(value);
            }
        }
    }

    let mut document = serde_json::to_string_pretty(&serde_json::json!({ "keys": entries }))
        .context("failed to render the JWKS document")?;
    document.push('\n');

    write_owner_file(&args.output, document.as_bytes(), args.force)?;

    match format {
        OutputFormat::Human => println!("wrote {}", args.output.display()),
        OutputFormat::Json => crate::print_report(&crate::command_report(
            "jwks",
            json!({"files": [args.output.display().to_string()]}),
        )),
    }

    Ok(ExitCode::SUCCESS)
}

/// Writes `contents` to `path` at `OUTPUT_FILE_MODE`. A force overwrite first
/// removes anything already at `path`, including a symlink, so the create that
/// follows always creates a fresh file. The mode is then set through that
/// file's own descriptor, never by path, so the umask cannot narrow it and no
/// chmod can land on whatever a symlink now points at.
pub(crate) fn write_owner_file(path: &std::path::Path, contents: &[u8], force: bool) -> Result<()> {
    if force {
        match fs::symlink_metadata(path) {
            Ok(_) => fs::remove_file(path)
                .with_context(|| format!("failed to remove existing {}", path.display()))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("failed to inspect {}", path.display()))
            }
        }
    }
    let mut options = OpenOptions::new();
    options.write(true).mode(OUTPUT_FILE_MODE).create_new(true);
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    // `O_CREAT` applies the process umask, which a hardened operator shell
    // may set to 077; setting the mode again through the open descriptor
    // publishes the file as readable whatever the umask, and cannot land on
    // anything but the file just created.
    file.set_permissions(fs::Permissions::from_mode(OUTPUT_FILE_MODE))
        .with_context(|| format!("failed to set the mode of {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to persist {}", path.display()))?;
    Ok(())
}
