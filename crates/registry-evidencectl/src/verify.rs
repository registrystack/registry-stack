//! Offline response verification delegated to the Evidence relying-party client.

use std::{
    fs::{self, File},
    io::Read as _,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Component, Path, PathBuf},
    process::ExitCode,
};

use anyhow::{bail, Context as _, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::Args;
use registry_evidence_client::RetainedEvidenceVerification;
use registry_platform_crypto::canonicalize_json;
use zeroize::Zeroize as _;

const PRIVATE_FILE_MODE: u32 = 0o600;
const MAX_CONTEXT_BYTES: u64 = 256 * 1024;
const MAX_RESPONSE_BYTES: u64 = 256 * 1024;
const MAX_VERIFIED_BYTES: u64 = 256 * 1024;

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Signed JWS or SD-JWT VC response returned by Evidence Gateway.
    pub(crate) response: PathBuf,

    /// Owner-only verification context retained before the response existed.
    #[arg(long)]
    pub(crate) context: PathBuf,

    /// New owner-only file for the exact verified Evidence Gateway payload.
    #[arg(long)]
    pub(crate) output: PathBuf,
}

pub fn run(args: VerifyArgs) -> Result<ExitCode> {
    validate_output_path(&args.output)?;
    let context = read_bounded_regular_input(&args.context, MAX_CONTEXT_BYTES, true)
        .context("Evidence response verification failed")?;
    let context: RetainedEvidenceVerification = serde_json::from_slice(&context)
        .map_err(|_| anyhow::anyhow!("Evidence response verification failed"))?;
    let response = read_bounded_regular_input(&args.response, MAX_RESPONSE_BYTES, false)
        .context("Evidence response verification failed")?;
    let verified = context
        .verify(&response)
        .map_err(|_| anyhow::anyhow!("Evidence response verification failed"))?;
    let mut output = canonicalize_json(&serde_json::to_value(verified.evidence())?)
        .context("Evidence response verification failed")?;
    output.push(b'\n');
    if output.len() as u64 > MAX_VERIFIED_BYTES {
        bail!("Evidence response verification failed");
    }
    let mut staged = StagedOutput::create(&args.output)?;
    use std::io::Write as _;
    staged.file.write_all(&output)?;
    staged.file.sync_all()?;
    validate_private_output(&staged.path, &staged.file)?;
    staged.publish(&args.output)?;
    println!("VERIFIED");
    Ok(ExitCode::SUCCESS)
}

fn read_bounded_regular_input(
    path: &Path,
    maximum_bytes: u64,
    require_owner_only: bool,
) -> Result<Vec<u8>> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let file = File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() > maximum_bytes
        || (require_owner_only
            && (metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.permissions().mode() & 0o7777 != PRIVATE_FILE_MODE))
    {
        bail!("input is not a bounded regular file");
    }
    let mut bytes = Vec::new();
    file.take(maximum_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > maximum_bytes {
        bail!("input is not a bounded regular file");
    }
    Ok(bytes)
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
