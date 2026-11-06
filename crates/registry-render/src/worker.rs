//! The supervised worker process. `typst::compile` has no timeout or
//! cancellation parameter, so `serve` renders in a child process it can
//! kill: the only true CPU wall. The child also caps its own address space
//! with RLIMIT_AS before rendering and dies on panic — so a pathological
//! template is isolated bytes, not a degraded service.
//!
//! Protocol: 4-byte little-endian length + JSON, one request and one
//! response per process (spawn-per-request; simple, and recycling after a
//! panic is a process exit).

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use base64::Engine as _;
use registry_platform_yaml::Diagnostic;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::pdf_signature::{PreparedPdf, SignatureField};
use crate::problem::{ProblemKind, RenderProblem};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRequest {
    pub bundle: PathBuf,
    pub document: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    pub data: Value,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub assets: BTreeMap<String, String>,
    /// RFC 3339 issuance time.
    pub issued_at: String,
    #[serde(default)]
    pub strict: bool,
    /// Serve mode pins the package per request, not just at startup: the
    /// worker must verify it and the response must carry the package digest.
    #[serde(default)]
    pub require_package: bool,
    #[serde(default = "default_max_output")]
    pub max_output_bytes: usize,
    #[serde(default = "default_memory_limit")]
    pub memory_limit_bytes: u64,
    /// Present only on a seal request: render with the `signing` member and
    /// append the signature field the parent fixed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal: Option<WorkerSeal>,
}

/// What the parent asks the worker to prepare for a seal. The parent fixes
/// every value, including the signing time and the reserved space, so the
/// worker holds no key and makes no choice; it renders and writes the field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkerSeal {
    /// The template payload's `signing` member.
    pub signing: crate::envelope::SigningPayload,
    /// RFC 3339, whole seconds, UTC: the signature dictionary's `/M`.
    pub signing_time: String,
    /// Bytes reserved for the CMS signature.
    pub contents_capacity: usize,
    /// The signature field's partial name.
    pub field_name: String,
}

impl WorkerSeal {
    fn field(&self) -> Result<SignatureField, RenderProblem> {
        let signing_time = chrono::DateTime::parse_from_rfc3339(&self.signing_time)
            .map_err(|_| {
                RenderProblem::new(
                    ProblemKind::Internal,
                    "the seal request's signing time is not RFC 3339",
                )
            })?
            .with_timezone(&chrono::Utc);
        Ok(SignatureField {
            signing_time,
            contents_capacity: self.contents_capacity,
            field_name: self.field_name.clone(),
        })
    }
}

fn default_max_output() -> usize {
    crate::render::DEFAULT_MAX_OUTPUT_BYTES
}

fn default_memory_limit() -> u64 {
    512 * 1024 * 1024
}

/// A problem as it crosses the process boundary: kind slug plus fields, so
/// the parent reconstructs the same exit codes and HTTP statuses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerProblem {
    pub kind: String,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pointers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<Diagnostic>,
}

impl From<&RenderProblem> for WorkerProblem {
    fn from(problem: &RenderProblem) -> Self {
        Self {
            kind: problem.kind.slug().to_owned(),
            detail: problem.detail.clone(),
            pointers: problem.pointers.clone(),
            locations: problem.locations.clone(),
            diagnostics: problem.diagnostics.clone(),
        }
    }
}

impl WorkerProblem {
    fn into_render_problem(self) -> RenderProblem {
        let kind = ProblemKind::from_slug(&self.kind);
        let mut problem = RenderProblem::new(kind, self.detail);
        problem.pointers = self.pointers;
        problem.locations = self.locations;
        problem.diagnostics = self.diagnostics;
        problem
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRendered {
    pub document_id: String,
    pub pdf_base64: String,
    pub pdf_sha256: String,
    pub data_sha256: String,
    pub document_version: u32,
    pub bundle_version: u32,
    pub bundle_hash: String,
    #[serde(default)]
    pub deps: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// A seal request's answer: the sealed render with its signature field
/// appended. The parent trusts none of it until
/// [`PreparedPdf::check`] accepts the shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerPrepared {
    pub document_id: String,
    pub prepared: PreparedPdf,
    /// The length of the first revision, Render's own PDF, at the start of
    /// `prepared`.
    pub first_revision_len: usize,
    pub data_sha256: String,
    pub document_version: u32,
    pub bundle_version: u32,
    pub bundle_hash: String,
    #[serde(default)]
    pub deps: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "camelCase")]
pub enum WorkerResponse {
    Rendered(Box<WorkerRendered>),
    Prepared(Box<WorkerPrepared>),
    Failed { problem: WorkerProblem },
}

impl ProblemKind {
    pub fn from_slug(slug: &str) -> Self {
        match slug {
            "invalid-argument" => Self::InvalidArgument,
            "manifest-invalid" => Self::ManifestInvalid,
            "bundle-tampered" => Self::BundleTampered,
            "bundle-unsealed" => Self::BundleUnsealed,
            "unknown-document" => Self::UnknownDocument,
            "labels-invalid" => Self::LabelsInvalid,
            "font-invalid" => Self::FontInvalid,
            "data-invalid" => Self::DataInvalid,
            "asset-invalid" => Self::AssetInvalid,
            "issued-at-missing" => Self::IssuedAtMissing,
            "compile-failed" => Self::CompileFailed,
            "strict-warnings" => Self::StrictWarnings,
            "output-too-large" => Self::OutputTooLarge,
            "render-timeout" => Self::RenderTimeout,
            "render-panicked" => Self::RenderPanicked,
            "unauthorized" => Self::Unauthorized,
            "body-too-large" => Self::BodyTooLarge,
            "rate-limited" => Self::RateLimited,
            "audit-failed" => Self::AuditFailed,
            "runtime-invalid" => Self::RuntimeInvalid,
            _ => Self::Internal,
        }
    }
}

fn write_frame(writer: &mut impl Write, value: &Value) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(value).expect("worker frame serializes");
    writer.write_all(&(bytes.len() as u32).to_le_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()
}

fn read_frame(reader: &mut impl Read) -> std::io::Result<Value> {
    let mut len = [0u8; 4];
    reader.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    // Frames carry a PDF in base64; 64 MiB is far beyond any legitimate
    // render and stops a confused peer from ballooning the parent.
    if len > 64 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "worker frame too large",
        ));
    }
    let mut bytes = vec![0u8; len];
    reader.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

/// The child side: one request in, one response out, then exit.
pub fn worker_main() -> i32 {
    let mut stdin = std::io::stdin().lock();
    let request: WorkerRequest = match read_frame(&mut stdin) {
        Ok(value) => match serde_json::from_value(value) {
            Ok(request) => request,
            Err(err) => {
                let problem = RenderProblem::new(
                    ProblemKind::Internal,
                    format!("worker request malformed: {err}"),
                );
                return respond(WorkerResponse::Failed {
                    problem: (&problem).into(),
                });
            }
        },
        Err(err) => {
            eprintln!("registry-render worker: cannot read request: {err}");
            return 11;
        }
    };
    cap_address_space(request.memory_limit_bytes);
    let response = render_in_worker(&request);
    respond(response)
}

fn respond(response: WorkerResponse) -> i32 {
    let mut stdout = std::io::stdout().lock();
    let value = serde_json::to_value(&response).expect("worker response serializes");
    if write_frame(&mut stdout, &value).is_err() {
        return 11;
    }
    0
}

/// Best-effort RLIMIT_AS; a failure to set it is logged, not fatal — the
/// supervisor kill remains the hard wall.
fn cap_address_space(limit: u64) {
    #[cfg(target_os = "linux")]
    {
        use rustix::process::{Resource, Rlimit};
        let lim = Rlimit {
            current: Some(limit),
            maximum: Some(limit),
        };
        if let Err(err) = rustix::process::setrlimit(Resource::As, lim) {
            eprintln!("registry-render worker: cannot set address-space limit: {err}");
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        // RLIMIT_AS is not portable through rustix; the supervisor kill
        // remains the hard resource wall on these platforms.
        let _ = limit;
    }
}

/// Bundle-load problems format host paths (the manifest it cannot read, a
/// symlink the package walk refuses), and in serve mode they cross the pipe to
/// the caller. The bundle root is replaced with `<bundle>` the way render
/// diagnostics already are, in both its given and its canonical spelling.
fn redact_bundle_root(mut problem: RenderProblem, root: &Path) -> RenderProblem {
    let mut roots = vec![root.to_string_lossy().into_owned()];
    if let Ok(canonical) = root.canonicalize() {
        let canonical = canonical.to_string_lossy().into_owned();
        if !roots.contains(&canonical) {
            roots.push(canonical);
        }
    }
    let redact = |text: &str| {
        roots
            .iter()
            .fold(text.to_owned(), |acc, root| acc.replace(root, "<bundle>"))
    };
    problem.detail = redact(&problem.detail);
    problem.locations = problem
        .locations
        .iter()
        .map(|location| redact(location))
        .collect();
    for diagnostic in &mut problem.diagnostics {
        if let Some(source) = &mut diagnostic.source {
            source.file = redact(&source.file);
        }
        for related in &mut diagnostic.related {
            related.file = redact(&related.file);
        }
    }
    problem
}

fn render_in_worker(request: &WorkerRequest) -> WorkerResponse {
    // Serve pins the package per request: the worker verifies the common
    // envelope, captures one immutable product snapshot, binds those consumed
    // bytes to the verified digests, and renders only from that snapshot.
    let bundle = if request.require_package {
        registry_platform_config::package::verify_package(
            &request.bundle,
            &crate::runtime::package_limits(),
            "registry-render package",
        )
        .map_err(|error| {
            let kind = match error.kind() {
                registry_platform_config::package::PackageErrorKind::SumFileMissing => {
                    ProblemKind::BundleUnsealed
                }
                _ => ProblemKind::BundleTampered,
            };
            RenderProblem::new(kind, error.to_string())
        })
        .and_then(|verified| crate::bundle::Bundle::load_package(&request.bundle, &verified))
    } else {
        crate::bundle::Bundle::load_for_preview(&request.bundle)
    };
    let bundle = match bundle {
        Ok(bundle) => bundle,
        Err(problem) => {
            return WorkerResponse::Failed {
                problem: (&redact_bundle_root(problem, &request.bundle)).into(),
            }
        }
    };
    let document = match bundle.document(&request.document) {
        Ok(document) => document,
        Err(problem) => {
            return WorkerResponse::Failed {
                problem: (&problem).into(),
            }
        }
    };
    let issued_at = match chrono::DateTime::parse_from_rfc3339(&request.issued_at) {
        Ok(at) => at.with_timezone(&chrono::Utc),
        Err(err) => {
            return WorkerResponse::Failed {
                problem: (&RenderProblem::new(
                    ProblemKind::InvalidArgument,
                    format!("issuedAt must be RFC 3339: {err}"),
                ))
                    .into(),
            }
        }
    };
    let render_request = crate::render::RenderRequest {
        locale: request.locale.clone(),
        data: request.data.clone(),
        assets: request.assets.clone(),
        issued_at,
    };
    if let Some(seal) = &request.seal {
        return prepare_in_worker(&bundle, document, &render_request, request, seal);
    }
    match crate::render::render_with_limits(
        &bundle,
        document,
        &render_request,
        request.strict,
        request.max_output_bytes,
    ) {
        Ok(rendered) => WorkerResponse::Rendered(Box::new(WorkerRendered {
            document_id: rendered.document_id.clone(),
            pdf_base64: base64::engine::general_purpose::STANDARD.encode(&rendered.pdf),
            pdf_sha256: rendered.pdf_sha256,
            data_sha256: rendered.data_sha256,
            document_version: rendered.document_version,
            bundle_version: rendered.bundle_version,
            bundle_hash: rendered.bundle_hash,
            deps: rendered.deps,
            warnings: rendered.warnings,
        })),
        Err(problem) => WorkerResponse::Failed {
            problem: (&problem).into(),
        },
    }
}

/// Render the sealed first revision and append the parent's signature field.
fn prepare_in_worker(
    bundle: &crate::bundle::Bundle,
    document: &crate::bundle::LoadedDocument,
    render_request: &crate::render::RenderRequest,
    request: &WorkerRequest,
    seal: &WorkerSeal,
) -> WorkerResponse {
    let failed = |problem: RenderProblem| WorkerResponse::Failed {
        problem: (&problem).into(),
    };
    let field = match seal.field() {
        Ok(field) => field,
        Err(problem) => return failed(problem),
    };
    let rendered = match crate::render::render_for_sealing(
        bundle,
        document,
        render_request,
        &seal.signing,
        request.strict,
        request.max_output_bytes,
    ) {
        Ok(rendered) => rendered,
        Err(problem) => return failed(problem),
    };
    let prepared = match crate::pdf_signature::prepare(&rendered.pdf, &field) {
        Ok(prepared) => prepared,
        Err(error) => {
            return failed(RenderProblem::new(
                ProblemKind::Internal,
                format!("the signature field could not be prepared: {error}"),
            ))
        }
    };
    WorkerResponse::Prepared(Box::new(WorkerPrepared {
        document_id: rendered.document_id,
        prepared,
        first_revision_len: rendered.pdf.len(),
        data_sha256: rendered.data_sha256,
        document_version: rendered.document_version,
        bundle_version: rendered.bundle_version,
        bundle_hash: rendered.bundle_hash,
        deps: rendered.deps,
        warnings: rendered.warnings,
    }))
}

/// The parent side of a plain render: see [`exchange`].
pub async fn supervise(
    request: WorkerRequest,
    timeout: Duration,
) -> Result<WorkerRendered, RenderProblem> {
    match exchange(request, timeout).await? {
        WorkerResponse::Rendered(rendered) => Ok(*rendered),
        WorkerResponse::Prepared(_) => Err(unexpected_answer()),
        WorkerResponse::Failed { problem } => Err(problem.into_render_problem()),
    }
}

/// The parent side of a seal request: see [`exchange`]. The answer is
/// untrusted until its shape is checked.
pub async fn supervise_seal(
    request: WorkerRequest,
    timeout: Duration,
) -> Result<WorkerPrepared, RenderProblem> {
    match exchange(request, timeout).await? {
        WorkerResponse::Prepared(prepared) => Ok(*prepared),
        WorkerResponse::Rendered(_) => Err(unexpected_answer()),
        WorkerResponse::Failed { problem } => Err(problem.into_render_problem()),
    }
}

fn unexpected_answer() -> RenderProblem {
    RenderProblem::new(
        ProblemKind::Internal,
        "the render worker answered with another kind of result than requested",
    )
}

/// Spawn a worker, send the request, await the response, kill at the
/// timeout. Spawn-per-request: bounded by the caller's semaphore, recycled
/// by construction.
async fn exchange(
    request: WorkerRequest,
    timeout: Duration,
) -> Result<WorkerResponse, RenderProblem> {
    let exe = std::env::current_exe().map_err(|err| {
        RenderProblem::new(
            ProblemKind::Internal,
            format!("cannot locate the render binary: {err}"),
        )
    })?;
    exchange_with(worker_command(&exe), request, timeout).await
}

/// [`exchange`] over a given worker command, so a test can stand in for the
/// worker.
async fn exchange_with(
    mut command: tokio::process::Command,
    request: WorkerRequest,
    timeout: Duration,
) -> Result<WorkerResponse, RenderProblem> {
    let mut child = command.spawn().map_err(|err| {
        RenderProblem::new(
            ProblemKind::Internal,
            format!("cannot spawn render worker: {err}"),
        )
    })?;
    let mut stderr = child.stderr.take().expect("stderr piped");
    let drain = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut sink = [0u8; 4096];
        while matches!(stderr.read(&mut sink).await, Ok(n) if n > 0) {}
    });
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stdin = child.stdin.take().expect("stdin piped");
    let payload = serde_json::to_vec(&request).expect("worker request serializes");
    let write = async {
        stdin
            .write_all(&(payload.len() as u32).to_le_bytes())
            .await?;
        stdin.write_all(&payload).await?;
        stdin.flush().await
    };
    let mut stdout = child.stdout.take().expect("stdout piped");
    let read = async {
        let mut len = [0u8; 4];
        stdout.read_exact(&mut len).await?;
        let len = u32::from_le_bytes(len) as usize;
        if len > 64 * 1024 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "worker frame too large",
            ));
        }
        let mut bytes = vec![0u8; len];
        stdout.read_exact(&mut bytes).await?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        Ok(value)
    };
    let deadline = tokio::time::Instant::now() + timeout;
    let frame = tokio::time::timeout_at(deadline, async {
        write.await?;
        read.await
    });
    let response = match frame.await {
        Ok(Ok(value)) => value,
        Ok(Err(err)) => {
            let _ = child.kill().await;
            return Err(RenderProblem::new(
                ProblemKind::RenderPanicked,
                format!("render worker failed: {err}"),
            ));
        }
        Err(_) => {
            let _ = child.kill().await;
            return Err(RenderProblem::new(
                ProblemKind::RenderTimeout,
                format!("render exceeded {}s and was killed", timeout.as_secs()),
            ));
        }
    };
    // The answer is in. A worker that does not exit, or a process it started
    // that holds its stderr open, would pin this request and its render
    // permit, so the waits share the render deadline; the answer is kept.
    let mut drain = drain;
    let exited = tokio::time::timeout_at(deadline, async {
        let _ = child.wait().await;
        let _ = (&mut drain).await;
    })
    .await;
    if exited.is_err() {
        let _ = child.kill().await;
        drain.abort();
        tracing::warn!(
            "render worker killed: it did not exit after answering, by the render deadline"
        );
    }
    serde_json::from_value(response).map_err(|err| {
        RenderProblem::new(
            ProblemKind::RenderPanicked,
            format!("render worker returned an unreadable response: {err}"),
        )
    })
}

/// The command every supervised worker (serve and compile) is spawned from.
fn worker_command(exe: &Path) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(exe);
    command
        .arg("__worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Worker stderr is piped and drained, never inherited: a panic
        // message can carry host paths or data fragments, and the operator
        // log is value-free by contract. The parent's problem documents are
        // the diagnosis surface.
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    isolate_environment(&mut command, std::env::vars_os());
    command
}

/// The variables a worker keeps from the parent: the dynamic loader's search
/// paths, because the worker is this same executable and must load the same
/// shared libraries (on macOS development builds, the AWS-LC FIPS library).
const WORKER_ENVIRONMENT: [&str; 3] = [
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH",
    "LD_LIBRARY_PATH",
];

/// The worker runs template code, so it starts from an empty environment:
/// a credential the operator gives the parent as a variable, or through
/// `${VAR}` in the runtime file, is not passed to it. Typst gives templates
/// no environment access; this keeps a Typst defect from becoming one. It
/// does not make the worker a sandbox: it still runs as the parent's user.
fn isolate_environment(
    command: &mut tokio::process::Command,
    parent: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) {
    command.env_clear();
    command.envs(
        parent
            .into_iter()
            .filter(|(name, _)| WORKER_ENVIRONMENT.iter().any(|kept| name == kept)),
    );
}

#[cfg(all(test, unix))]
mod tests {
    use std::collections::BTreeSet;
    use std::ffi::OsString;

    use super::{
        exchange_with, isolate_environment, worker_command, WorkerProblem, WorkerResponse,
        WORKER_ENVIRONMENT,
    };

    fn kept_names(command: &tokio::process::Command) -> BTreeSet<String> {
        command
            .as_std()
            .get_envs()
            .filter(|(_, value)| value.is_some())
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect()
    }

    /// Names (never values) of the variables a command's child prints.
    async fn printed_names(command: &mut tokio::process::Command) -> BTreeSet<String> {
        let output = command.output().await.expect("stand-in runs");
        assert!(output.status.success(), "stand-in exits cleanly");
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.split_once('=').map(|(name, _)| name.to_owned()))
            .collect()
    }

    /// Spawns the production worker command with a stand-in executable that
    /// prints its environment, under this test process's real environment
    /// (cargo sets many variables). Names only: a failure must not print a
    /// value.
    #[tokio::test]
    async fn a_worker_sees_no_parent_variable_beyond_the_loader_paths() {
        assert!(
            std::env::var_os("PATH").is_some(),
            "the test process needs an environment for the worker not to inherit"
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let stand_in = dir.path().join("print-environment");
        std::fs::write(&stand_in, "#!/bin/sh\nexec /usr/bin/env\n").expect("write stand-in");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&stand_in, std::fs::Permissions::from_mode(0o700))
                .expect("make stand-in executable");
        }
        // The shell sets a few variables itself (PWD, SHLVL) even when started
        // with none; anything beyond those came from the parent.
        let from_nothing = printed_names(tokio::process::Command::new(&stand_in).env_clear()).await;
        let names = printed_names(&mut worker_command(&stand_in)).await;
        let unexpected: Vec<&String> = names
            .iter()
            .filter(|name| {
                !WORKER_ENVIRONMENT.contains(&name.as_str()) && !from_nothing.contains(*name)
            })
            .collect();
        assert!(unexpected.is_empty(), "the worker inherited {unexpected:?}");
    }

    // Checked on the command, not by spawning: macOS strips DYLD_ variables
    // from the system binaries a test could spawn to print its environment.
    #[test]
    fn a_worker_keeps_the_parents_loader_paths() {
        let expected: BTreeSet<String> = std::env::vars_os()
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .filter(|name| WORKER_ENVIRONMENT.contains(&name.as_str()))
            .collect();
        let command = worker_command(std::path::Path::new("/usr/bin/env"));
        assert_eq!(kept_names(&command), expected);
    }

    /// A stand-in worker that answers with a framed `Failed` response and
    /// then runs `after` (shell), so a test controls how it exits.
    fn answering_stand_in(dir: &std::path::Path, after: &str) -> std::path::PathBuf {
        let answer = WorkerResponse::Failed {
            problem: WorkerProblem {
                kind: "internal".to_owned(),
                detail: "stand-in answer".to_owned(),
                pointers: Vec::new(),
                locations: Vec::new(),
                diagnostics: Vec::new(),
            },
        };
        let body = serde_json::to_vec(&answer).expect("answer serializes");
        let mut frame = (body.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(&body);
        let frame_file = dir.join("answer.frame");
        std::fs::write(&frame_file, frame).expect("write frame");
        let stand_in = dir.join("answering-worker");
        std::fs::write(
            &stand_in,
            format!("#!/bin/sh\ncat '{}'\n{after}\n", frame_file.display()),
        )
        .expect("write stand-in");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stand_in, std::fs::Permissions::from_mode(0o700))
            .expect("make stand-in executable");
        stand_in
    }

    /// The render deadline bounds the whole exchange: a worker that answers
    /// and then does not exit, or leaves a process holding its stderr open,
    /// is cut off at the deadline and the answer it gave is kept.
    #[tokio::test]
    async fn a_worker_that_lingers_after_answering_is_cut_off_at_the_deadline() {
        let deadline = std::time::Duration::from_secs(1);
        let dir = tempfile::tempdir().expect("tempdir");
        let pid_file = dir.path().join("lingering.pid");
        for after in [
            "exec sleep 10".to_owned(),
            format!("sleep 10 &\necho $! > '{}'\nexit 0", pid_file.display()),
        ] {
            let stand_in = answering_stand_in(dir.path(), &after);
            let started = std::time::Instant::now();
            let answer = exchange_with(
                worker_command(&stand_in),
                super::seal_tests::receipt_request(None),
                deadline,
            )
            .await;
            let elapsed = started.elapsed();
            if let Ok(pid) = std::fs::read_to_string(&pid_file) {
                let status = std::process::Command::new("kill")
                    .arg(pid.trim())
                    .status()
                    .expect("run kill");
                assert!(
                    status.success(),
                    "{after}: the lingering process had ended before the exchange returned"
                );
                std::fs::remove_file(&pid_file).expect("remove pid file");
            }
            match answer {
                Ok(WorkerResponse::Failed { problem }) => {
                    assert_eq!(problem.detail, "stand-in answer");
                }
                other => panic!("{after}: {other:?}"),
            }
            assert!(
                elapsed < std::time::Duration::from_secs(5),
                "{after}: the exchange took {elapsed:?}"
            );
        }
    }

    #[test]
    fn only_the_loader_search_paths_are_kept() {
        let mut command = tokio::process::Command::new("/usr/bin/env");
        isolate_environment(
            &mut command,
            [
                ("DYLD_FALLBACK_LIBRARY_PATH", "/opt/fips/lib"),
                ("DYLD_LIBRARY_PATH", "/opt/other/lib"),
                ("DYLD_INSERT_LIBRARIES", "/opt/insert.dylib"),
                ("LD_LIBRARY_PATH", "/opt/fips/lib"),
                ("LD_PRELOAD", "/opt/preload.so"),
                ("HOME", "/home/render"),
                ("VAULT_TOKEN", "not-a-real-token"),
            ]
            .map(|(name, value)| (OsString::from(name), OsString::from(value))),
        );
        let expected: BTreeSet<String> = WORKER_ENVIRONMENT.map(str::to_owned).into();
        assert_eq!(kept_names(&command), expected);
    }
}

#[cfg(test)]
pub(crate) mod seal_tests {
    use super::*;

    pub(crate) fn receipt_request(seal: Option<WorkerSeal>) -> WorkerRequest {
        let bundle =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/render/bundles/receipt");
        let data: Value = serde_json::from_str(
            &std::fs::read_to_string(bundle.join("fixtures/data.json")).unwrap(),
        )
        .unwrap();
        WorkerRequest {
            bundle,
            document: "receipt".to_owned(),
            locale: Some("fr".to_owned()),
            data,
            assets: BTreeMap::new(),
            issued_at: "2026-09-16T10:32:00Z".to_owned(),
            strict: false,
            require_package: true,
            max_output_bytes: crate::render::DEFAULT_MAX_OUTPUT_BYTES,
            memory_limit_bytes: default_memory_limit(),
            seal,
        }
    }

    /// The packaged receipt, prepared in process for `seal` as a worker
    /// answers the parent.
    pub(crate) fn prepared_receipt(seal: WorkerSeal) -> WorkerPrepared {
        match render_in_worker(&receipt_request(Some(seal))) {
            WorkerResponse::Prepared(prepared) => *prepared,
            other => panic!("seal render: {other:?}"),
        }
    }

    fn seal() -> WorkerSeal {
        WorkerSeal {
            signing: crate::envelope::SigningPayload {
                signer_name: Some("Registry Stack Test Ministry".to_owned()),
                test_only: true,
            },
            signing_time: "2026-11-06T09:15:42Z".to_owned(),
            contents_capacity: 16 * 1024,
            field_name: "RegistrySeal".to_owned(),
        }
    }

    #[test]
    fn a_seal_request_returns_the_prepared_field_over_a_sealed_render() {
        let plain = match render_in_worker(&receipt_request(None)) {
            WorkerResponse::Rendered(rendered) => rendered,
            other => panic!("plain render: {other:?}"),
        };
        let prepared = match render_in_worker(&receipt_request(Some(seal()))) {
            WorkerResponse::Prepared(prepared) => prepared,
            other => panic!("seal render: {other:?}"),
        };
        assert_ne!(
            prepared.data_sha256, plain.data_sha256,
            "the sealed envelope carries the signing member"
        );
        assert_eq!(prepared.document_id, "receipt");
        assert_eq!(prepared.document_version, plain.document_version);
        assert_eq!(prepared.bundle_hash, plain.bundle_hash);
        let first_revision_len = prepared.first_revision_len;
        let checked = prepared
            .prepared
            .clone()
            .check(first_revision_len)
            .expect("the parent accepts the shape");
        assert_eq!(checked.contents_capacity(), 16 * 1024);
        let again = match render_in_worker(&receipt_request(Some(seal()))) {
            WorkerResponse::Prepared(again) => again,
            other => panic!("seal render: {other:?}"),
        };
        assert_eq!(
            again.prepared, prepared.prepared,
            "the same request prepares the same bytes"
        );
    }

    #[test]
    fn a_field_the_worker_cannot_write_is_an_internal_problem() {
        let mut bad = seal();
        bad.field_name = "has.period".to_owned();
        match render_in_worker(&receipt_request(Some(bad))) {
            WorkerResponse::Failed { problem } => assert_eq!(problem.kind, "internal"),
            other => panic!("{other:?}"),
        }
        let mut bad_time = seal();
        bad_time.signing_time = "yesterday".to_owned();
        match render_in_worker(&receipt_request(Some(bad_time))) {
            WorkerResponse::Failed { problem } => assert_eq!(problem.kind, "internal"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_plain_request_frame_carries_no_seal_member() {
        let value = serde_json::to_value(receipt_request(None)).unwrap();
        assert!(value.get("seal").is_none(), "{value}");
    }
}
