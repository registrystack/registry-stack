//! Closed request preparation for the first local tutorial.
//!
//! This module assembles only the request described by validated ready state.
//! Mint owns authentication and Evidence owns authorization and verification
//! context semantics.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read as _, Write as _},
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
};

use anyhow::{anyhow, bail, Context as _, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::{Args, Subcommand, ValueEnum};
use registry_platform_crypto::canonicalize_json;
use serde_json::{json, Map, Value};
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    access,
    dev::{self, ReadyDevState},
};

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

    /// Subject selector. Repeat role:field=value for a multi-subject question.
    #[arg(long, required = true)]
    subject: Vec<String>,

    /// Safe name for this retained request.
    #[arg(long)]
    name: String,

    /// Registered local application used to request authorization.
    #[arg(long)]
    client: Option<String>,

    /// Response format to request and verify.
    #[arg(long, value_enum, default_value_t = PreparedResponseFormat::SignedJws)]
    format: PreparedResponseFormat,

    /// Project root. Defaults to the current directory.
    #[arg(long, default_value = ".", hide = true)]
    project: PathBuf,

    #[arg(long, hide = true)]
    evidence_bin: Option<PathBuf>,

    #[arg(long, hide = true)]
    mint_bin: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum PreparedResponseFormat {
    SignedJws,
    SdJwtVc,
}

impl PreparedResponseFormat {
    fn as_str(self) -> &'static str {
        match self {
            Self::SignedJws => "signed-jws",
            Self::SdJwtVc => "sd-jwt-vc",
        }
    }
}

pub fn run(command: RequestCommand) -> Result<ExitCode> {
    match command {
        RequestCommand::Prepare(args) => prepare(args),
    }
}

fn prepare(args: PrepareArgs) -> Result<ExitCode> {
    validate_request_name(&args.name)?;
    let ready = dev::load_ready_state(&args.project)?;
    let (question, subjects) = validate_closed_inputs(&ready, &args)?;
    let client = resolve_request_client(&ready, args.client.as_deref())?;
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

    let request = closed_request(question, &subjects)?;
    let request_path = staging.path().join("request.json");
    write_private_bytes(&request_path, &request)?;

    let token = obtain_token(
        &mint,
        &ready.token_url,
        &client.client_id,
        &client.private_key_path,
        &client.assertion_audience,
    )?;
    let context_path = staging.path().join("verification.json");
    prepare_context(
        &evidence,
        &ready.runtime_path,
        &request_path,
        &context_path,
        &token,
        args.format,
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

struct RequestClient {
    client_id: String,
    private_key_path: PathBuf,
    assertion_audience: String,
}

fn resolve_request_client(ready: &ReadyDevState, client_id: Option<&str>) -> Result<RequestClient> {
    match client_id {
        Some(client_id) => {
            if ready.access_policies.is_empty() {
                bail!("--client requires an active generation with explicit access policies");
            }
            let policy_tags = ready
                .access_policies
                .iter()
                .map(|policy| (policy.id.clone(), policy.requester_tag.clone()))
                .collect::<BTreeMap<_, _>>();
            let client = access::resolve_ready_client(&ready.project, client_id, &policy_tags)?;
            Ok(RequestClient {
                client_id: client.client_id,
                private_key_path: client.private_key_path,
                assertion_audience: ready.token_url.clone(),
            })
        }
        None => {
            let caller = ready.caller.as_ref().ok_or_else(|| {
                anyhow!("the active project requires a registered client selected with --client")
            })?;
            Ok(RequestClient {
                client_id: caller.client_id.clone(),
                private_key_path: caller.private_key_path.clone(),
                assertion_audience: caller.assertion_audience.clone(),
            })
        }
    }
}

fn validate_closed_inputs<'a, 'b>(
    ready: &'a ReadyDevState,
    args: &'b PrepareArgs,
) -> Result<(
    &'a dev::ReadyQuestionState,
    Vec<(&'a dev::ReadySubjectState, &'b str)>,
)> {
    let question = ready
        .questions
        .iter()
        .find(|question| question.alias == args.question)
        .ok_or_else(|| anyhow!("question does not match the active local project"))?;
    if args.purpose != question.purpose {
        bail!("purpose does not match the active local tutorial question");
    }
    if args.subject.len() != question.subjects.len() {
        bail!("subject inputs must match the question's complete role set");
    }
    let mut values = BTreeMap::new();
    for input in &args.subject {
        let (binding, value) = input
            .split_once('=')
            .filter(|(_, value)| !value.contains('='))
            .ok_or_else(|| anyhow!("subject must be one field=value or role:field=value pair"))?;
        let (role, field) = match binding.split_once(':') {
            Some((role, field)) if !role.contains(':') && !field.contains(':') => (role, field),
            None if question.subjects.len() == 1 => (question.subjects[0].role.as_str(), binding),
            _ => bail!("multi-subject inputs must use role:field=value"),
        };
        let subject = question
            .subjects
            .iter()
            .find(|subject| subject.role == role)
            .ok_or_else(|| anyhow!("subject role does not match the active local question"))?;
        if field != subject.selector_field || values.insert(role, value).is_some() {
            bail!("subject inputs must contain each declared role and selector exactly once");
        }
        if value.is_empty()
            || value.len() > MAX_SELECTOR_VALUE_BYTES
            || value.chars().any(char::is_control)
        {
            bail!("subject value must be non-empty, bounded, and contain no control characters");
        }
    }
    let subjects = question
        .subjects
        .iter()
        .map(|subject| {
            values
                .get(subject.role.as_str())
                .copied()
                .map(|value| (subject, value))
                .ok_or_else(|| anyhow!("subject inputs do not cover the complete role set"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((question, subjects))
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

fn closed_request(
    question: &dev::ReadyQuestionState,
    subjects: &[(&dev::ReadySubjectState, &str)],
) -> Result<Vec<u8>> {
    let mut random = [0_u8; 32];
    getrandom::fill(&mut random).context("failed to generate a request nonce")?;
    let nonce = URL_SAFE_NO_PAD.encode(random);
    random.zeroize();
    let subjects = subjects
        .iter()
        .map(|(subject, value)| {
            let selector_values = Value::Object(Map::from_iter([(
                subject.selector_field.clone(),
                Value::String((*value).to_owned()),
            )]));
            json!({
                "role": subject.role,
                "selector": {
                    "profile": subject.selector_profile,
                    "values": selector_values,
                }
            })
        })
        .collect::<Vec<_>>();
    let request = json!({
        "requestNonce": nonce,
        "requirement": question.requirement_uri,
        "purpose": question.purpose,
        "subjects": subjects,
    });
    canonicalize_json(&request).context("failed to serialize the closed Evidence request")
}

fn obtain_token(
    mint: &Path,
    token_url: &str,
    client_id: &str,
    private_key_path: &Path,
    assertion_audience: &str,
) -> Result<Zeroizing<String>> {
    let mut child = Command::new(mint)
        .arg("token")
        .arg("--url")
        .arg(token_url)
        .arg("--client-id")
        .arg(client_id)
        .arg("--key")
        .arg(private_key_path)
        .arg("--audience")
        .arg(assertion_audience)
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
        bail!("Registry Mint refused a token for client {client_id}");
    }
    let status = child.wait().context("failed to wait for Mint")?;
    if !status.success() {
        bail!("Registry Mint refused a token for client {client_id}");
    }
    if std::str::from_utf8(&stdout).is_err() {
        bail!("Registry Mint refused a token for client {client_id}");
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
        bail!("Registry Mint refused a token for client {client_id}");
    }
    Ok(token)
}

fn prepare_context(
    evidence: &Path,
    runtime: &Path,
    request: &Path,
    context: &Path,
    token: &str,
    response_format: PreparedResponseFormat,
) -> Result<()> {
    let context_file = create_private_file(context)?;
    let mut child = Command::new(evidence)
        .arg("--runtime")
        .arg(runtime)
        .arg("prepare-local-verification-context")
        .arg("--request")
        .arg(request)
        .arg("--response-format")
        .arg(response_format.as_str())
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
