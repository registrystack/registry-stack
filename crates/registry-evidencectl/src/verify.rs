//! Offline response verification delegated entirely to the Evidence core.

use std::{
    fs::{self, File},
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Component, Path, PathBuf},
    process::{Command, ExitCode, Stdio},
};

use anyhow::{bail, Context as _, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::Args;
use zeroize::Zeroize as _;

use crate::dev;

const PRIVATE_FILE_MODE: u32 = 0o600;
const MAX_VERIFIED_BYTES: u64 = 256 * 1024;

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Flattened JWS JSON response returned by Evidence.
    response: PathBuf,

    /// Owner-only verification context retained before the response existed.
    #[arg(long)]
    context: PathBuf,

    /// New owner-only file for the exact verified Evidence payload.
    #[arg(long)]
    output: PathBuf,

    #[arg(long, hide = true)]
    evidence_bin: Option<PathBuf>,
}

pub fn run(args: VerifyArgs) -> Result<ExitCode> {
    validate_output_path(&args.output)?;
    let evidence = dev::resolve_tool_binary(
        "evidence",
        args.evidence_bin.as_deref(),
        "EVIDENCECTL_TEST_EVIDENCE_BIN",
    )?;
    let mut staged = StagedOutput::create(&args.output)?;
    let output_file = staged.file.try_clone()?;
    let status = Command::new(evidence)
        .arg("verify-local-response")
        .arg("--context")
        .arg(&args.context)
        .arg("--response")
        .arg(&args.response)
        .stdin(Stdio::null())
        .stdout(Stdio::from(output_file))
        .stderr(Stdio::null())
        .status()
        .context("failed to invoke Evidence response verification")?;
    if !status.success() {
        bail!("Evidence response verification failed");
    }
    staged.file.sync_all()?;
    validate_private_output(&staged.path, &staged.file)?;
    staged.publish(&args.output)?;
    println!("VERIFIED");
    Ok(ExitCode::SUCCESS)
}

fn validate_output_path(path: &Path) -> Result<()> {
    if path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        bail!("verified output path must be normalized and name one new file");
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => bail!("verified output already exists; refusing to replace it"),
        Err(error) => return Err(error.into()),
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("failed to inspect output directory {}", parent.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::getuid().as_raw()
    {
        bail!("verified output directory must be owned and unsymlinked");
    }
    Ok(())
}

struct StagedOutput {
    path: PathBuf,
    file: File,
    published: bool,
}

impl StagedOutput {
    fn create(output: &Path) -> Result<Self> {
        let parent = output
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        for _ in 0..8 {
            let mut random = [0_u8; 12];
            getrandom::fill(&mut random)?;
            let path = parent.join(format!(".verify-{}", URL_SAFE_NO_PAD.encode(random)));
            random.zeroize();
            match create_private_file(&path) {
                Ok(file) => {
                    return Ok(Self {
                        path,
                        file,
                        published: false,
                    });
                }
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::AlreadyExists) => {
                }
                Err(error) => return Err(error),
            }
        }
        bail!("failed to allocate private verification output")
    }

    fn publish(&mut self, output: &Path) -> Result<()> {
        rename_noreplace(&self.path, output)
            .context("failed to publish verified output without replacing an existing path")?;
        self.published = true;
        Ok(())
    }
}

impl Drop for StagedOutput {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn create_private_file(path: &Path) -> Result<File> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::from_bits_truncate(PRIVATE_FILE_MODE as rustix::fs::RawMode),
    )
    .map_err(std::io::Error::from)
    .with_context(|| format!("failed to create private output {}", path.display()))?;
    let file = File::from(fd);
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o777 != PRIVATE_FILE_MODE
    {
        bail!("private verification output failed its file-safety checks");
    }
    Ok(file)
}

fn validate_private_output(path: &Path, opened: &File) -> Result<()> {
    let path_metadata = fs::symlink_metadata(path)?;
    let open_metadata = opened.metadata()?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || path_metadata.nlink() != 1
        || path_metadata.uid() != rustix::process::getuid().as_raw()
        || path_metadata.permissions().mode() & 0o777 != PRIVATE_FILE_MODE
        || path_metadata.dev() != open_metadata.dev()
        || path_metadata.ino() != open_metadata.ino()
        || open_metadata.len() == 0
        || open_metadata.len() > MAX_VERIFIED_BYTES
    {
        bail!("private verification output failed its file-safety checks");
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
        "atomic no-replace verification publication is unsupported",
    ))
}
