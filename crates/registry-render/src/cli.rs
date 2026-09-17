//! The `render` CLI: init, check, validate, seal, compile, serve,
//! healthcheck, audit-verify. Exit codes come from the problem model.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

/// The release version plus the Typst pin, computed once. Leaked on
/// purpose: a CLI version string lives for the process lifetime.
static CLI_VERSION: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();

fn version_string() -> &'static str {
    CLI_VERSION.get_or_init(|| Box::leak(crate::display_version().into_boxed_str()))
}

use crate::bundle::Bundle;
use crate::problem::RenderProblem;
use crate::render::{render, RenderRequest};
use crate::validate_data;

/// Governed, byte-stable PDF documents from registry data.
#[derive(Debug, Parser)]
#[command(name = "render", version = version_string(), about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scaffold a working starter bundle.
    Init {
        /// Target directory (created if absent).
        dir: PathBuf,
        /// Label locales for the starter document.
        #[arg(long = "labels")]
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
        /// Runtime file whose audit directory is proven to resolve under
        /// the given root (the container preflight proof).
        #[arg(long)]
        runtime: Option<PathBuf>,
        /// Root the audit directory must resolve under (with --runtime).
        #[arg(long)]
        require_audit_under: Option<PathBuf>,
    },
    /// Dry-run request data against a document's schema, without rendering.
    Validate {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long = "type")]
        document: String,
        #[arg(long)]
        data: PathBuf,
        #[arg(long)]
        locale: Option<String>,
    },
    /// Write per-file hashes into the manifest, sealing the bundle.
    Seal {
        #[arg(long, default_value = ".")]
        bundle: PathBuf,
    },
    /// Render one document offline.
    Compile {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long = "type")]
        document: String,
        /// JSON file holding the bare `data` object.
        #[arg(long)]
        data: PathBuf,
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
        /// Keep rendering on bundle changes (authoring loop; unsealed
        /// bundles are fine, poll-based).
        #[arg(long)]
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
        #[arg(long, env = "REGISTRY_RENDER_RUNTIME")]
        runtime: Option<PathBuf>,
    },
    /// Probe a running server's /health.
    Healthcheck {
        #[arg(long, env = "REGISTRY_RENDER_RUNTIME")]
        runtime: Option<PathBuf>,
    },
    /// Verify a sealed audit chain end to end.
    AuditVerify {
        #[arg(long, env = "REGISTRY_RENDER_RUNTIME")]
        runtime: Option<PathBuf>,
        /// Ledger directory (alternative to --runtime).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Integrity key reference, for use with --dir.
        #[arg(long = "key")]
        key_ref: Option<String>,
    },
    /// Hidden: one supervised render (used by `render serve`).
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
    match run_inner(cli) {
        Ok(code) => code,
        Err(problem) => {
            eprintln!("render: {problem}");
            problem.exit_code()
        }
    }
}

fn run_inner(cli: Cli) -> Result<i32, RenderProblem> {
    match cli.command {
        Command::Init { dir, labels } => crate::init::scaffold(&dir, &labels),
        Command::Check { bundle, seal, runtime, require_audit_under } => {
            crate::check::run(&bundle, seal, runtime.as_deref(), require_audit_under.as_deref())
        }
        Command::Seal { bundle } => {
            Bundle::seal(&bundle)?;
            println!("sealed {}", bundle.display());
            Ok(0)
        }
        Command::Validate { bundle, document, data, locale } => {
            let bundle = Bundle::load(&bundle)?;
            let document = bundle.document(&document)?;
            // Validate is a schema dry-run; it needs no issuance time and
            // renders nothing.
            let request = read_request_without_time(&data, &locale)?;
            validate_data(document, &request)?;
            println!("ok");
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
            watch,
            out,
            json,
            emit_envelope,
        } => {
            let request = read_request(
                &data,
                &locale,
                &assets,
                Some(parse_issued_at(issued_at, now)?),
            )?;
            if watch {
                return watch_loop(&bundle, &document, &request, strict, &out);
            }
            let bundle = Bundle::load(&bundle).map_err(recovery_hint)?;
            if !bundle.manifest.is_sealed() {
                eprintln!(
                    "note: bundle is unsealed; compile is fine, serve is not (run `render seal` when ready)"
                );
            }
            let document = bundle.document(&document)?;
            let rendered = render(&bundle, document, &request, strict)?;
            if let Some(path) = emit_envelope {
                std::fs::write(&path, &rendered.envelope_bytes).map_err(|err| {
                    RenderProblem::new(
                        crate::problem::ProblemKind::InvalidArgument,
                        format!("cannot write {}: {err}", path.display()),
                    )
                })?;
            }
            std::fs::write(&out, &rendered.pdf).map_err(|err| {
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
                println!("{}", serde_json::to_string_pretty(&summary).expect("summary json"));
            } else {
                println!(
                    "wrote {} ({} bytes, pdf sha256 {}, data sha256 {})",
                    out.display(),
                    rendered.pdf.len(),
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
        Command::AuditVerify { runtime, dir, key_ref } => {
            match (runtime, dir, key_ref) {
                (Some(runtime), _, _) => {
                    let (config, _) = crate::runtime::load(&runtime)?;
                    crate::audit::verify_chain(&runtime, &config.audit.directory, &config.audit.integrity_key_ref)
                }
                (None, Some(dir), Some(key_ref)) => {
                    crate::audit::verify_chain(&dir, &dir, &key_ref)
                }
                _ => Err(RenderProblem::new(
                    crate::problem::ProblemKind::InvalidArgument,
                    "audit-verify needs --runtime <file>, or --dir <dir> together with --key <secret-ref>",
                )),
            }
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

/// The validate dry-run: data and locale only, no clock.
pub(crate) fn read_request_without_time(
    data_path: &Path,
    locale: &Option<String>,
) -> Result<RenderRequest, RenderProblem> {
    read_request(data_path, locale, &[], Some(chrono::Utc::now()))
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
        problem
            .detail
            .push_str("; if these edits are yours, run `render seal` to re-seal the bundle");
        problem
    } else {
        problem
    }
}

/// The authoring loop: render now, then re-render whenever the bundle's
/// files change. Poll-based on purpose — no filesystem-event dependency,
/// works everywhere the CLI works, and the loop is for humans, not CI.
fn watch_loop(
    bundle_dir: &Path,
    document_id: &str,
    request: &RenderRequest,
    strict: bool,
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
            match Bundle::load(bundle_dir).and_then(|bundle| {
                let document = bundle.document(document_id)?.clone();
                render(&bundle, &document, request, strict)
            }) {
                Ok(rendered) => {
                    std::fs::write(out, &rendered.pdf).map_err(|err| {
                        RenderProblem::new(
                            crate::problem::ProblemKind::InvalidArgument,
                            format!("cannot write {}: {err}", out.display()),
                        )
                    })?;
                    eprintln!(
                        "wrote {} ({} bytes, pdf sha256 {}, {} warning(s))",
                        out.display(),
                        rendered.pdf.len(),
                        rendered.pdf_sha256,
                        rendered.warnings.len()
                    );
                    for warning in &rendered.warnings {
                        eprintln!("warning: {warning}");
                    }
                }
                Err(problem) => {
                    eprintln!("render: {problem}");
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
