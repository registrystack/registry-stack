//! Closed request preparation for the first local tutorial.
//!
//! This module assembles only the request described by validated ready state.
//! Mint owns authentication and Evidence owns authorization and verification
//! context semantics.

use std::{
    fs::{self, File},
    io::{Read as _, Write as _},
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
};

use anyhow::{anyhow, bail, Context as _, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::{Args, Subcommand};
use registry_platform_crypto::canonicalize_json;
use serde_json::{json, Map, Value};
use zeroize::{Zeroize as _, Zeroizing};

use crate::dev::{self, ReadyDevState};

const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;
const MAX_SELECTOR_VALUE_BYTES: usize = 200;
const MAX_TOKEN_BYTES: usize = 64 * 1024;
const MAX_CONTEXT_BYTES: u64 = 256 * 1024;

#[derive(Debug, Subcommand)]
pub enum RequestCommand {
    /// Prepare the request, authorization header, and verification context.
    Prepare(PrepareArgs),
}

#[derive(Debug, Args)]
pub struct PrepareArgs {
    /// Question defined by the active local project.
    question: String,

    /// Exact purpose declared by the question.
    #[arg(long)]
    purpose: String,

    /// Subject selector as the question's one field=value pair.
    #[arg(long)]
    subject: String,

    /// Safe name for this retained request.
    #[arg(long)]
    name: String,

    /// Project root. Defaults to the current directory.
    #[arg(long, default_value = ".", hide = true)]
    project: PathBuf,

    #[arg(long, hide = true)]
    evidence_bin: Option<PathBuf>,

    #[arg(long, hide = true)]
    mint_bin: Option<PathBuf>,
}

pub fn run(command: RequestCommand) -> Result<ExitCode> {
    match command {
        RequestCommand::Prepare(args) => prepare(args),
    }
}

fn prepare(args: PrepareArgs) -> Result<ExitCode> {
    validate_request_name(&args.name)?;
    let ready = dev::load_ready_state(&args.project)?;
    let (question, subject_value) = validate_closed_inputs(&ready, &args)?;
    let evidence = dev::resolve_tool_binary(
        "evidence",
        args.evidence_bin.as_deref(),
        "EVIDENCECTL_TEST_EVIDENCE_BIN",
    )?;
    let mint = dev::resolve_tool_binary(
        "mint",
        args.mint_bin.as_deref(),
        "EVIDENCECTL_TEST_MINT_BIN",
    )?;

    let requests_root = ensure_requests_root(&ready.project)?;
    let destination = requests_root.join(&args.name);
    require_absent(&destination)?;
    let mut staging = StagingDirectory::create(&requests_root)?;

    let request = closed_request(question, subject_value)?;
    let request_path = staging.path().join("request.json");
    write_private_bytes(&request_path, &request)?;

    let token = obtain_token(&mint, &ready)?;
    let context_path = staging.path().join("verification.json");
    prepare_context(
        &evidence,
        &ready.runtime_path,
        &request_path,
        &context_path,
        &token,
    )?;
    let authorization_path = staging.path().join("authorization.curl");
    write_authorization(&authorization_path, &token)?;
    drop(token);

    validate_private_directory(&requests_root)?;
    staging.publish(&destination)?;

    let relative = Path::new(".evidence/requests").join(&args.name);
    println!(
        "Prepared request: {}",
        relative.join("request.json").display()
    );
    println!(
        "Prepared verification context: {}",
        relative.join("verification.json").display()
    );
    println!(
        "Prepared authorization: {}",
        relative.join("authorization.curl").display()
    );
    Ok(ExitCode::SUCCESS)
}

fn validate_closed_inputs<'a, 'b>(
    ready: &'a ReadyDevState,
    args: &'b PrepareArgs,
) -> Result<(&'a dev::ReadyQuestionState, &'b str)> {
    let question = ready
        .questions
        .iter()
        .find(|question| question.alias == args.question)
        .ok_or_else(|| anyhow!("question does not match the active local project"))?;
    if args.purpose != question.purpose {
        bail!("purpose does not match the active local tutorial question");
    }
    let (field, value) = args
        .subject
        .split_once('=')
        .filter(|(_, value)| !value.contains('='))
        .ok_or_else(|| anyhow!("subject must be exactly one field=value pair"))?;
    if field != question.selector_field {
        bail!("subject field does not match the active local tutorial question");
    }
    if value.is_empty()
        || value.len() > MAX_SELECTOR_VALUE_BYTES
        || value.chars().any(char::is_control)
    {
        bail!("subject value must be non-empty, bounded, and contain no control characters");
    }
    Ok((question, value))
}

fn validate_request_name(name: &str) -> Result<()> {
    let bytes = name.as_bytes();
    if !matches!(bytes.first(), Some(b'a'..=b'z'))
        || bytes.len() > 64
        || bytes[1..].iter().any(|byte| {
            !(byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-'))
        })
    {
        bail!("request name must be a safe lowercase local name");
    }
    Ok(())
}

fn closed_request(question: &dev::ReadyQuestionState, subject_value: &str) -> Result<Vec<u8>> {
    let mut random = [0_u8; 32];
    getrandom::fill(&mut random).context("failed to generate a request nonce")?;
    let nonce = URL_SAFE_NO_PAD.encode(random);
    random.zeroize();
    let selector_values = Value::Object(Map::from_iter([(
        question.selector_field.clone(),
        Value::String(subject_value.to_owned()),
    )]));
    let request = json!({
        "requestNonce": nonce,
        "requirement": question.requirement_uri,
        "purpose": question.purpose,
        "subjects": [{
            "role": question.subject_role,
            "selector": {
                "profile": question.selector_profile,
                "values": selector_values,
            }
        }]
    });
    canonicalize_json(&request).context("failed to serialize the closed Evidence request")
}

fn obtain_token(mint: &Path, ready: &ReadyDevState) -> Result<Zeroizing<String>> {
    let mut child = Command::new(mint)
        .arg("token")
        .arg("--url")
        .arg(&ready.token_url)
        .arg("--client-id")
        .arg(&ready.caller_id)
        .arg("--key")
        .arg(&ready.caller_private_key_path)
        .arg("--audience")
        .arg(&ready.caller_assertion_audience)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to invoke Mint")?;
    let mut stdout = Zeroizing::new(Vec::with_capacity(MAX_TOKEN_BYTES + 2));
    let read_result = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("failed to open Mint token output"))?
        .take((MAX_TOKEN_BYTES + 3) as u64)
        .read_to_end(&mut stdout);
    if read_result.is_err() || stdout.len() > MAX_TOKEN_BYTES + 2 {
        let _ = child.kill();
        let _ = child.wait();
        bail!("Mint did not issue local authorization");
    }
    let status = child.wait().context("failed to wait for Mint")?;
    if !status.success() {
        bail!("Mint did not issue local authorization");
    }
    if std::str::from_utf8(&stdout).is_err() {
        bail!("Mint did not issue local authorization");
    }
    let mut token = Zeroizing::new(
        String::from_utf8(std::mem::take(&mut stdout)).expect("Mint output was validated as UTF-8"),
    );
    if token.ends_with('\n') {
        token.pop();
        if token.ends_with('\r') {
            token.pop();
        }
    }
    if token.is_empty()
        || token.len() > MAX_TOKEN_BYTES
        || token
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
    {
        bail!("Mint did not issue local authorization");
    }
    Ok(token)
}

fn prepare_context(
    evidence: &Path,
    runtime: &Path,
    request: &Path,
    context: &Path,
    token: &str,
) -> Result<()> {
    let context_file = create_private_file(context)?;
    let mut child = Command::new(evidence)
        .arg("--runtime")
        .arg(runtime)
        .arg("prepare-local-verification-context")
        .arg("--request")
        .arg(request)
        .stdin(Stdio::piped())
        .stdout(Stdio::from(context_file.try_clone()?))
        .stderr(Stdio::null())
        .spawn()
        .context("failed to invoke Evidence context preparation")?;
    let write_result = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("failed to open Evidence authorization input"))?
        .write_all(token.as_bytes());
    if write_result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        bail!("Evidence context preparation failed");
    }
    let status = child.wait().context("failed to wait for Evidence")?;
    if !status.success() {
        bail!("Evidence context preparation failed");
    }
    context_file.sync_all()?;
    validate_private_file(context, &context_file, 1, MAX_CONTEXT_BYTES)?;
    Ok(())
}

fn write_authorization(path: &Path, token: &str) -> Result<()> {
    let mut contents = Zeroizing::new(String::with_capacity(token.len() + 36));
    contents.push_str("header = \"Authorization: Bearer ");
    contents.push_str(token);
    contents.push_str("\"\n");
    write_private_bytes(path, contents.as_bytes())
}

fn ensure_requests_root(project: &Path) -> Result<PathBuf> {
    let generated = project.join(".evidence");
    validate_private_directory(&generated)?;
    let requests = generated.join("requests");
    match fs::symlink_metadata(&requests) {
        Ok(_) => validate_private_directory(&requests)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_private_directory(&requests)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(requests)
}

fn require_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => bail!("request name already exists; refusing to replace it"),
        Err(error) => Err(error.into()),
    }
}

struct StagingDirectory {
    path: Option<PathBuf>,
}

impl StagingDirectory {
    fn create(parent: &Path) -> Result<Self> {
        for _ in 0..8 {
            let mut random = [0_u8; 12];
            getrandom::fill(&mut random)?;
            let name = format!(".prepare-{}", URL_SAFE_NO_PAD.encode(random));
            random.zeroize();
            let path = parent.join(name);
            match create_private_directory(&path) {
                Ok(()) => return Ok(Self { path: Some(path) }),
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::AlreadyExists) => {
                }
                Err(error) => return Err(error),
            }
        }
        bail!("failed to allocate private request staging")
    }

    fn path(&self) -> &Path {
        self.path.as_deref().expect("staging remains active")
    }

    fn publish(&mut self, destination: &Path) -> Result<()> {
        let path = self.path();
        rename_noreplace(path, destination)
            .with_context(|| format!("failed to publish request `{}`", destination.display()))?;
        self.path = None;
        Ok(())
    }
}

impl Drop for StagingDirectory {
    fn drop(&mut self) {
        let Some(path) = self.path.take() else {
            return;
        };
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || metadata.is_file() => {
                let _ = fs::remove_file(path);
            }
            Ok(metadata) if metadata.is_dir() => {
                let _ = fs::remove_dir_all(path);
            }
            _ => {}
        }
    }
}

fn create_private_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(PRIVATE_DIRECTORY_MODE);
    builder
        .create(path)
        .with_context(|| format!("failed to create private directory {}", path.display()))?;
    validate_private_directory(path)
}

fn validate_private_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect private directory {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o777 != PRIVATE_DIRECTORY_MODE
    {
        bail!(
            "private directory {} must be owner-only and unsymlinked",
            path.display()
        );
    }
    Ok(())
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
        rustix::fs::Mode::from_bits_truncate(PRIVATE_FILE_MODE as u16),
    )
    .map_err(std::io::Error::from)
    .with_context(|| format!("failed to create private file {}", path.display()))?;
    let file = File::from(fd);
    validate_private_file(path, &file, 0, u64::MAX)?;
    Ok(file)
}

fn write_private_bytes(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = create_private_file(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    validate_private_file(path, &file, contents.len() as u64, contents.len() as u64)
}

fn validate_private_file(
    path: &Path,
    opened: &File,
    minimum_bytes: u64,
    maximum_bytes: u64,
) -> Result<()> {
    let path_metadata = fs::symlink_metadata(path)?;
    let open_metadata = opened.metadata()?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || path_metadata.nlink() != 1
        || path_metadata.uid() != rustix::process::getuid().as_raw()
        || path_metadata.permissions().mode() & 0o777 != PRIVATE_FILE_MODE
        || path_metadata.dev() != open_metadata.dev()
        || path_metadata.ino() != open_metadata.ino()
        || !(minimum_bytes..=maximum_bytes).contains(&open_metadata.len())
    {
        bail!("private request artifact failed its file-safety checks");
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
        "atomic no-replace request publication is unsupported",
    ))
}
