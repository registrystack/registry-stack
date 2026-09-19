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
use serde::{Deserialize, Serialize};
use serde_json::Value;

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
    /// Serve mode pins the seal per request, not just at startup: the
    /// worker must load sealed and the response must carry the startup
    /// bundle hash.
    #[serde(default)]
    pub require_sealed: bool,
    #[serde(default = "default_max_output")]
    pub max_output_bytes: usize,
    #[serde(default = "default_memory_limit")]
    pub memory_limit_bytes: u64,
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
}

impl From<&RenderProblem> for WorkerProblem {
    fn from(problem: &RenderProblem) -> Self {
        Self {
            kind: problem.kind.slug().to_owned(),
            detail: problem.detail.clone(),
            pointers: problem.pointers.clone(),
            locations: problem.locations.clone(),
        }
    }
}

impl WorkerProblem {
    fn into_render_problem(self) -> RenderProblem {
        let kind = ProblemKind::from_slug(&self.kind);
        let mut problem = RenderProblem::new(kind, self.detail);
        problem.pointers = self.pointers;
        problem.locations = self.locations;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "camelCase")]
pub enum WorkerResponse {
    Rendered(Box<WorkerRendered>),
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
/// symlink the seal walk refuses), and in serve mode they cross the pipe to
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
    problem
}

fn render_in_worker(request: &WorkerRequest) -> WorkerResponse {
    // Serve pins the seal per request: the worker loads one immutable bundle
    // snapshot every time, verifies the seal over those exact bytes, and
    // renders only from that snapshot. Drift present before capture is
    // refused here; later path changes cannot affect this render.
    let bundle = if request.require_sealed {
        crate::bundle::Bundle::load_sealed(&request.bundle)
    } else {
        crate::bundle::Bundle::load(&request.bundle)
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

/// The parent side: spawn a worker, send the request, await the response,
/// kill at the timeout. Spawn-per-request: bounded by the caller's
/// semaphore, recycled by construction.
pub async fn supervise(
    request: WorkerRequest,
    timeout: Duration,
) -> Result<WorkerRendered, RenderProblem> {
    let exe = std::env::current_exe().map_err(|err| {
        RenderProblem::new(
            ProblemKind::Internal,
            format!("cannot locate the render binary: {err}"),
        )
    })?;
    let mut child = tokio::process::Command::new(exe)
        .arg("__worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Worker stderr is piped and drained, never inherited: a panic
        // message can carry host paths or data fragments, and the operator
        // log is value-free by contract. The parent's problem documents are
        // the diagnosis surface.
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| {
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
    let frame = tokio::time::timeout(timeout, async {
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
    let _ = child.wait().await;
    let _ = drain.await;
    let response: WorkerResponse = serde_json::from_value(response).map_err(|err| {
        RenderProblem::new(
            ProblemKind::RenderPanicked,
            format!("render worker returned an unreadable response: {err}"),
        )
    })?;
    match response {
        WorkerResponse::Rendered(rendered) => Ok(*rendered),
        WorkerResponse::Failed { problem } => Err(problem.into_render_problem()),
    }
}
