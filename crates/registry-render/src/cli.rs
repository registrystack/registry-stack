//! The `registry-render` CLI: init, check, validate, seal, compile,
//! serve, healthcheck. Exit codes come from the problem model.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use clap::{Parser, Subcommand};

/// The release version plus the Typst pin, computed once. Leaked on
/// purpose: a CLI version string lives for the process lifetime.
static CLI_VERSION: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();

fn version_string() -> &'static str {
    CLI_VERSION.get_or_init(|| Box::leak(crate::display_version().into_boxed_str()))
}

use crate::bundle::Bundle;
use crate::problem::RenderProblem;
use crate::render::RenderRequest;
use crate::validate_data;

/// Governed, byte-stable PDF documents from registry data.
#[derive(Debug, Parser)]
#[command(name = "registry-render", version = version_string(), about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Return the public command tree for documentation and completion.
pub fn command() -> clap::Command {
    <Cli as clap::CommandFactory>::command()
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scaffold a working starter bundle.
    Init {
        /// Target directory (created if absent).
        dir: PathBuf,
        /// Label locales for the starter document. Comma-separated or
        /// repeated: `--labels en,fr` and `--labels en --labels fr` match.
        #[arg(long = "labels", value_delimiter = ',')]
        labels: Vec<String>,
    },
    /// Verify a bundle (structure, hashes, label coverage), optionally
    /// sealing it only after verification passes.
    Check {
        /// Bundle directory (default: current directory).
        #[arg(long, default_value = ".")]
        bundle: PathBuf,
        /// Rewrite the manifest hashes, sealing the bundle.
        #[arg(long)]
        seal: bool,
        /// Runtime file whose audit file is proven to resolve under the
        /// given root (the container preflight proof). A stdout audit
        /// destination is refused.
        #[arg(long)]
        runtime: Option<PathBuf>,
        /// Root the audit file must resolve under (with --runtime).
        #[arg(long)]
        require_audit_under: Option<PathBuf>,
    },
    /// Dry-run request data against a document's schema, without rendering.
    Validate {
        /// Bundle directory.
        #[arg(long)]
        bundle: PathBuf,
        /// Document type id, as declared in the manifest.
        #[arg(long = "type")]
        document: String,
        /// JSON file holding the bare `data` object.
        #[arg(long)]
        data: PathBuf,
        /// Primary locale, recorded in the envelope; must be one the
        /// document declares. The template receives every label table
        /// either way.
        #[arg(long)]
        locale: Option<String>,
        /// Machine-readable result on stdout (failures: problem+json on
        /// stderr, typed exit code).
        #[arg(long)]
        json: bool,
    },
    /// Write per-file hashes into the manifest, sealing the bundle.
    Seal {
        /// Bundle directory (default: current directory).
        #[arg(long, default_value = ".")]
        bundle: PathBuf,
    },
    /// Render one document offline.
    Compile {
        /// Bundle directory.
        #[arg(long)]
        bundle: PathBuf,
        /// Document type id, as declared in the manifest.
        #[arg(long = "type")]
        document: String,
        /// JSON file holding the bare `data` object.
        #[arg(long)]
        data: PathBuf,
        /// Primary locale, recorded in the envelope; must be one the
        /// document declares. The template receives every label table
        /// either way.
        #[arg(long)]
        locale: Option<String>,
        /// Issuance time; the document's claim, and the world clock.
        #[arg(long, conflicts_with = "now")]
        issued_at: Option<String>,
        /// Use the current wall clock as issuance time (nondeterministic;
        /// loud opt-in for throwaway previews).
        #[arg(long)]
        now: bool,
        /// Asset `name=path`, path holding base64 text.
        #[arg(long = "asset", value_parser = parse_asset_arg)]
        assets: Vec<(String, PathBuf)>,
        /// Refuse warnings (missing glyphs and friends).
        #[arg(long)]
        strict: bool,
        /// Wall-clock budget for the render in seconds; the render is
        /// killed at this bound (the same supervised-worker wall serve
        /// uses).
        #[arg(long = "timeout")]
        timeout: Option<u64>,
        /// Keep rendering on bundle changes (authoring loop; unsealed
        /// bundles are fine, poll-based). Never returns, so it refuses
        /// `--emit-envelope` rather than ignoring it.
        #[arg(long, conflicts_with = "emit_envelope")]
        watch: bool,
        /// Output PDF path.
        #[arg(long)]
        out: PathBuf,
        /// Machine-readable result on stdout.
        #[arg(long)]
        json: bool,
        /// Write the exact canonical envelope bytes injected into the
        /// template to this path (merge-gate and debugging aid).
        #[arg(long)]
        emit_envelope: Option<PathBuf>,
    },
    /// Serve the HTTP rendering API (see the runtime YAML).
    Serve {
        /// Runtime file naming the bundle, bind address, secrets, and limits.
        #[arg(long, env = "REGISTRY_RENDER_RUNTIME")]
        runtime: Option<PathBuf>,
    },
    /// Probe a running server's /health.
    Healthcheck {
        /// Runtime file naming the server to probe.
        #[arg(long, env = "REGISTRY_RENDER_RUNTIME")]
        runtime: Option<PathBuf>,
    },
    /// Hidden: one supervised render (used by `registry-render serve`).
    #[command(hide = true, name = "__worker")]
    Worker,
}

fn parse_asset_arg(spec: &str) -> Result<(String, PathBuf), String> {
    let (name, path) = spec
        .split_once('=')
        .ok_or_else(|| format!("asset must be name=path, got {spec:?}"))?;
    Ok((name.to_owned(), PathBuf::from(path)))
}

/// Run the CLI. Returns the process exit code.
pub fn run(cli: Cli) -> i32 {
    let json = wants_json(&cli);
    match run_inner(cli) {
        Ok(code) => code,
        Err(problem) => {
            if json {
                // The same RFC 9457 document HTTP callers get, on stderr;
                // stdout stays for successful output. Scripts branch on the
                // typed exit code and read the detail here.
                let document = serde_json::json!({
                    "type": format!("{}/{}", crate::problem::PROBLEM_TYPE_BASE, problem.kind.slug()),
                    "title": problem.kind.slug(),
                    "detail": problem.detail,
                    "pointers": problem.pointers,
                    "locations": problem.locations,
                });
                eprintln!(
                    "{}",
                    serde_json::to_string(&document).expect("problem json")
                );
            } else {
                eprintln!("registry-render: {problem}");
            }
            problem.exit_code()
        }
    }
}

/// Whether the invoked command asked for JSON output (its failures then
/// print as problem documents instead of prose).
fn wants_json(cli: &Cli) -> bool {
    match &cli.command {
        Command::Compile { json, .. } => *json,
        Command::Validate { json, .. } => *json,
        _ => false,
    }
}

fn run_inner(cli: Cli) -> Result<i32, RenderProblem> {
    match cli.command {
        Command::Init { dir, labels } => crate::init::scaffold(&dir, &labels),
        Command::Check {
            bundle,
            seal,
            runtime,
            require_audit_under,
        } => crate::check::run(
            &bundle,
            seal,
            runtime.as_deref(),
            require_audit_under.as_deref(),
        ),
        Command::Seal { bundle } => {
            Bundle::seal(&bundle)?;
            println!("sealed {}", bundle.display());
            Ok(0)
        }
        Command::Validate {
            bundle,
            document,
            data,
            locale,
            json,
        } => {
            let bundle = Bundle::load(&bundle)?;
            let document = bundle.document(&document)?;
            // Validate is a schema dry-run; it needs no issuance time and
            // renders nothing.
            let request = read_request_without_time(&data, &locale)?;
            validate_data(document, &request)?;
            if json {
                println!("{}", serde_json::json!({"valid": true}));
            } else {
                println!("ok");
            }
            Ok(0)
        }
        Command::Compile {
            bundle,
            document,
            data,
            locale,
            issued_at,
            now,
            assets,
            strict,
            timeout,
            watch,
            out,
            json,
            emit_envelope,
        } => {
            let issued = parse_issued_at(issued_at, now)?;
            if now && !json {
                // The loud opt-in the flag's help promises (suppressed under
                // --json, where stderr carries exactly one problem document
                // on failure).
                eprintln!(
                    "note: --now resolves issuedAt to {} (wall clock; output is NOT byte-stable)",
                    issued.to_rfc3339()
                );
            }
            let request = read_request(&data, &locale, &assets, Some(issued))?;
            let timeout = std::time::Duration::from_secs(
                timeout.unwrap_or_else(crate::runtime::default_render_timeout_seconds),
            );
            if watch {
                return watch_loop(&bundle, &document, &request, strict, timeout, &out);
            }
            let loaded = Bundle::load(&bundle).map_err(recovery_hint)?;
            if !loaded.manifest.is_sealed() && !json {
                eprintln!(
                    "note: bundle is unsealed; compile is fine, serve is not (run `registry-render seal` when ready)"
                );
            }
            let document_spec = loaded.document(&document)?.clone();
            let rendered = compile_once(&bundle, &document, &request, strict, timeout)
                .map_err(recovery_hint)?;
            let pdf = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &rendered.pdf_base64,
            )
            .map_err(|_| {
                RenderProblem::new(
                    crate::problem::ProblemKind::Internal,
                    "worker returned an undecodable PDF",
                )
            })?;
            if let Some(path) = emit_envelope {
                // Recompute the envelope beside the worker's authoritative
                // hash; a mismatch would mean the two processes disagree
                // about the injected bytes, which is an internal error.
                let envelope = crate::envelope::build_envelope(&crate::envelope::EnvelopeInput {
                    document_id: &document_spec.spec.id,
                    document_version: document_spec.spec.version,
                    labels: &document_spec.labels,
                    locale: request.locale.as_deref(),
                    issued_at: request.issued_at,
                    data: &request.data,
                    assets: &request.assets,
                });
                let bytes = crate::envelope::canonical_bytes(&envelope)?;
                if crate::hash::sha256_hex(&bytes) != rendered.data_sha256 {
                    return Err(RenderProblem::new(
                        crate::problem::ProblemKind::Internal,
                        "recomputed envelope does not match the worker's dataSha256",
                    ));
                }
                std::fs::write(&path, &bytes).map_err(|err| {
                    RenderProblem::new(
                        crate::problem::ProblemKind::InvalidArgument,
                        format!("cannot write {}: {err}", path.display()),
                    )
                })?;
            }
            std::fs::write(&out, &pdf).map_err(|err| {
                RenderProblem::new(
                    crate::problem::ProblemKind::InvalidArgument,
                    format!("cannot write {}: {err}", out.display()),
                )
            })?;
            if json {
                let summary = serde_json::json!({
                    "pdfPath": out.display().to_string(),
                    "pdfSha256": rendered.pdf_sha256,
                    "dataSha256": rendered.data_sha256,
                    "documentVersion": format!("{} v{}", rendered.document_id, rendered.document_version),
                    "bundleVersion": rendered.bundle_version,
                    "bundleHash": rendered.bundle_hash,
                    "warnings": rendered.warnings,
                    "deps": rendered.deps,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary).expect("summary json")
                );
            } else {
                println!(
                    "wrote {} ({} bytes, pdf sha256 {}, data sha256 {})",
                    out.display(),
                    pdf.len(),
                    rendered.pdf_sha256,
                    rendered.data_sha256
                );
                for warning in &rendered.warnings {
                    eprintln!("warning: {warning}");
                }
            }
            Ok(0)
        }
        Command::Serve { runtime } => {
            let code = crate::server::serve(runtime.as_deref())?;
            Ok(code)
        }
        Command::Healthcheck { runtime } => {
            let code = crate::server::healthcheck(runtime.as_deref())?;
            Ok(code)
        }
        Command::Worker => Ok(crate::worker::worker_main()),
    }
}

pub(crate) fn parse_issued_at(
    issued_at: Option<String>,
    now: bool,
) -> Result<chrono::DateTime<chrono::Utc>, RenderProblem> {
    use crate::problem::ProblemKind;
    if now {
        return Ok(chrono::Utc::now());
    }
    let raw = issued_at.ok_or_else(|| {
        RenderProblem::new(
            ProblemKind::IssuedAtMissing,
            "--issued-at is required (or pass --now explicitly for a nondeterministic preview)",
        )
    })?;
    chrono::DateTime::parse_from_rfc3339(&raw)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|err| {
            RenderProblem::new(
                ProblemKind::InvalidArgument,
                format!("--issued-at must be RFC 3339: {err}"),
            )
        })
}

/// The validate dry-run: data and locale only, no clock. The issuance
/// field is a fixed epoch sentinel the schema check never reads — nothing
/// in the dry-run path may touch the wall clock.
pub(crate) fn read_request_without_time(
    data_path: &Path,
    locale: &Option<String>,
) -> Result<RenderRequest, RenderProblem> {
    read_request(
        data_path,
        locale,
        &[],
        Some(chrono::DateTime::<chrono::Utc>::UNIX_EPOCH),
    )
}

pub(crate) fn read_request(
    data_path: &Path,
    locale: &Option<String>,
    assets: &[(String, PathBuf)],
    issued_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<RenderRequest, RenderProblem> {
    use crate::problem::ProblemKind;
    let bytes = std::fs::read(data_path).map_err(|err| {
        RenderProblem::new(
            ProblemKind::InvalidArgument,
            format!("cannot read {}: {err}", data_path.display()),
        )
    })?;
    let data: serde_json::Value = serde_json::from_slice(&bytes).map_err(|err| {
        RenderProblem::new(
            ProblemKind::DataInvalid,
            format!("{} is not valid JSON: {err}", data_path.display()),
        )
    })?;
    if !data.is_object() {
        return Err(RenderProblem::new(
            ProblemKind::DataInvalid,
            "data must be a JSON object",
        ));
    }
    let mut asset_map = BTreeMap::new();
    for (name, path) in assets {
        let b64 = std::fs::read_to_string(path).map_err(|err| {
            RenderProblem::new(
                ProblemKind::AssetInvalid,
                format!("cannot read asset {name:?}: {err}"),
            )
        })?;
        asset_map.insert(name.clone(), b64.trim().to_owned());
    }
    let issued_at = issued_at.map(Ok).unwrap_or_else(|| {
        Err(RenderProblem::new(
            ProblemKind::IssuedAtMissing,
            "issuedAt is required",
        ))
    })?;
    Ok(RenderRequest {
        locale: locale.clone(),
        data,
        assets: asset_map,
        issued_at,
    })
}

/// One offline render through the same supervised worker serve uses, so the
/// CLI shares serve's timeout semantics: `typst::compile` has no
/// cancellation parameter, and the killable child process is the only true
/// wall. This is also what keeps a pathological template from hanging an
/// authoring loop or a CI job.
fn compile_once(
    bundle_dir: &Path,
    document_id: &str,
    request: &RenderRequest,
    strict: bool,
    timeout: std::time::Duration,
) -> Result<crate::worker::WorkerRendered, RenderProblem> {
    let worker_request = crate::worker::WorkerRequest {
        bundle: bundle_dir.to_path_buf(),
        document: document_id.to_owned(),
        locale: request.locale.clone(),
        data: request.data.clone(),
        assets: request.assets.clone(),
        issued_at: request.issued_at.to_rfc3339(),
        strict,
        require_sealed: false,
        max_output_bytes: crate::render::DEFAULT_MAX_OUTPUT_BYTES,
        memory_limit_bytes: 512 * 1024 * 1024,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| {
            RenderProblem::new(
                crate::problem::ProblemKind::Internal,
                format!("cannot start the render runtime: {err}"),
            )
        })?;
    runtime.block_on(crate::worker::supervise(worker_request, timeout))
}

/// Flush stdout before exiting so summaries never interleave with stderr.
pub fn flush() {
    let _ = std::io::stdout().flush();
}

/// Compile-time wrapper that keeps the authoring loop actionable: a
/// drifted seal after an intentional edit should tell the author how to
/// recover, not accuse them of tampering.
fn recovery_hint(problem: RenderProblem) -> RenderProblem {
    if problem.kind == crate::ProblemKind::BundleTampered {
        let mut problem = problem;
        problem.detail.push_str(
            "; if these edits are yours, run `registry-render seal` to re-seal the bundle",
        );
        problem
    } else {
        problem
    }
}

/// The authoring loop: render now, then re-render whenever the bundle's
/// files change. Poll-based on purpose — no filesystem-event dependency,
/// works everywhere the CLI works, and the loop is for humans, not CI.
/// Every iteration runs through the supervised worker, so one pathological
/// edit costs its timeout, not the session.
fn watch_loop(
    bundle_dir: &Path,
    document_id: &str,
    request: &RenderRequest,
    strict: bool,
    timeout: std::time::Duration,
    out: &Path,
) -> Result<i32, RenderProblem> {
    eprintln!(
        "watching {} (ctrl-c to stop); unsealed bundles are fine while authoring",
        bundle_dir.display()
    );
    let mut last_fingerprint: Option<Vec<(String, std::time::SystemTime, u64)>> = None;
    loop {
        let fingerprint = fingerprint_bundle(bundle_dir, out);
        if Some(&fingerprint) != last_fingerprint.as_ref() {
            match compile_once(bundle_dir, document_id, request, strict, timeout) {
                Ok(rendered) => {
                    let pdf = base64::engine::general_purpose::STANDARD
                        .decode(&rendered.pdf_base64)
                        .map_err(|_| {
                            RenderProblem::new(
                                crate::problem::ProblemKind::Internal,
                                "worker returned an undecodable PDF",
                            )
                        })?;
                    std::fs::write(out, &pdf).map_err(|err| {
                        RenderProblem::new(
                            crate::problem::ProblemKind::InvalidArgument,
                            format!("cannot write {}: {err}", out.display()),
                        )
                    })?;
                    eprintln!(
                        "wrote {} ({} bytes, pdf sha256 {}, {} warning(s))",
                        out.display(),
                        pdf.len(),
                        rendered.pdf_sha256,
                        rendered.warnings.len()
                    );
                    for warning in &rendered.warnings {
                        eprintln!("warning: {warning}");
                    }
                }
                Err(problem) => {
                    eprintln!("registry-render: {problem}");
                }
            }
            last_fingerprint = Some(fingerprint);
        }
        std::thread::sleep(std::time::Duration::from_millis(400));
    }
}

/// Path/mtime/size fingerprint of every file under the bundle, except the
/// output file: writing it must not trigger the next render.
fn fingerprint_bundle(dir: &Path, skip: &Path) -> Vec<(String, std::time::SystemTime, u64)> {
    fn walk(dir: &Path, skip: &Path, out: &mut Vec<(String, std::time::SystemTime, u64)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path == skip {
                continue;
            }
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if name == ".DS_Store" {
                continue;
            }
            if path.is_dir() {
                walk(&path, skip, out);
            } else if let Ok(meta) = entry.metadata() {
                out.push((
                    name,
                    meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH),
                    meta.len(),
                ));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, skip, &mut out);
    out.sort();
    out
}
