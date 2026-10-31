// SPDX-License-Identifier: Apache-2.0

//! The `adapter-job` binary entry point: the operator surface of the
//! governed-ingestion job (`products/adapter/CONCEPT.md` section 17.4).
//! Check compiles a job the engine compiles, pass runs one bounded pass
//! or the trigger loop, status counts what the item table holds, inspect
//! reads one item's row, and rescan marks a rescan due and runs it. The
//! output is value-free by default: no item value, no projection, no
//! secret. The store holds no payload to leak.

use clap::{Parser, Subcommand};
use deadpool_postgres::Pool;
use registry_adapter::job::{compile_job, JobError, JobProgram};
use registry_adapter_core::{AdapterJob, AdapterPack, AdapterRuntimeConfig, SourceRouteDecl};
use registry_adapter_job::destination::{FixtureDestination, NullDestination};
use registry_adapter_job::pass::{run_pass, PassOptions, PassReport, StopReason};
use registry_adapter_job::store;
use registry_adapter_job::trigger::{self, Edits, JobState};
use registry_platform_config::{SecretProvider, SecretResolver};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

/// The operator surface of the governed-ingestion job.
#[derive(Parser)]
#[command(
    name = "adapter-job",
    version,
    about = "Run a governed-ingestion job: check, bounded pass, status, inspect, rescan.",
    after_help = "Output is value-free by default. Pass --show-values to include the projected values a dry-run pass would hand off; status, inspect, and check never carry item values."
)]
struct Cli {
    /// Include the projected values a dry-run pass would deliver. The
    /// default omits every item value.
    #[arg(long, global = true)]
    show_values: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Compile a job the way a pass would, with the value-free findings.
    Check {
        /// The job definition file.
        job_yaml: PathBuf,
        /// The pinned adapter pack file.
        #[arg(long)]
        pack: PathBuf,
        /// The operator runtime config file.
        #[arg(long)]
        runtime: PathBuf,
    },
    /// Run one bounded pass (the default, the shape a CronJob drives),
    /// or loop on the job's interval trigger.
    Pass {
        /// The job definition file.
        job_yaml: PathBuf,
        /// The pinned adapter pack file.
        #[arg(long)]
        pack: PathBuf,
        /// The operator runtime config file, whose database block names
        /// the job store's connection references.
        #[arg(long)]
        runtime: PathBuf,
        /// Hand off to the built-in fixture destination, which posts
        /// each deliverable to the receiver at --fixture-url. Loopback
        /// URLs only; a real destination is its own brief.
        #[arg(long, group = "handoff", requires = "fixture_url")]
        fixture: bool,
        /// The loopback URL of the fixture receiver.
        #[arg(long)]
        fixture_url: Option<String>,
        /// Run the pass against the preview destination, which delivers
        /// nothing, acknowledges nothing, and records what a real
        /// destination would have received. Nothing is written.
        #[arg(long, group = "handoff")]
        dry_run: bool,
        /// Loop: sleep until the job's interval trigger is due, run the
        /// pass, and repeat, running a rescan pass when the source's
        /// declared delay says one is due. The default runs one pass.
        #[arg(long)]
        r#loop: bool,
        /// The consecutive item-scoped refusals with one code that stop
        /// a pass with the position unchanged.
        #[arg(long, default_value_t = registry_adapter_job::pass::DEFAULT_REFUSAL_LIMIT)]
        refusal_limit: u32,
    },
    /// Count what the item table holds: statuses, refusal codes, the
    /// schedule, and why the last pass stopped. Value-free.
    Status {
        /// The job definition file.
        job_yaml: PathBuf,
        /// The operator runtime config file, whose database block names
        /// the job store's connection references.
        #[arg(long)]
        runtime: PathBuf,
    },
    /// Read one item's row: its statuses, sequence, and references.
    /// Value-free: the row holds no payload to print.
    Inspect {
        /// The job definition file.
        job_yaml: PathBuf,
        /// The operator runtime config file, whose database block names
        /// the job store's connection references.
        #[arg(long)]
        runtime: PathBuf,
        /// The source item's key.
        #[arg(long)]
        key: String,
    },
    /// Mark a rescan due now, then run one rescan pass from the first
    /// page: unchanged items skip by digest, refused items retry.
    Rescan {
        /// The job definition file.
        job_yaml: PathBuf,
        /// The pinned adapter pack file.
        #[arg(long)]
        pack: PathBuf,
        /// The operator runtime config file, whose database block names
        /// the job store's connection references.
        #[arg(long)]
        runtime: PathBuf,
        /// Hand off to the built-in fixture destination at --fixture-url.
        #[arg(long, group = "handoff", requires = "fixture_url")]
        fixture: bool,
        /// The loopback URL of the fixture receiver.
        #[arg(long)]
        fixture_url: Option<String>,
        /// Run the pass against the preview destination; nothing is
        /// written.
        #[arg(long, group = "handoff")]
        dry_run: bool,
        /// The consecutive item-scoped refusals with one code that stop
        /// a pass with the position unchanged.
        #[arg(long, default_value_t = registry_adapter_job::pass::DEFAULT_REFUSAL_LIMIT)]
        refusal_limit: u32,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("adapter-job: the async runtime could not start: {error}");
            return ExitCode::FAILURE;
        }
    };
    let outcome = match &cli.command {
        Command::Check {
            job_yaml,
            pack,
            runtime: runtime_path,
        } => check(job_yaml, pack, runtime_path),
        Command::Status {
            job_yaml,
            runtime: runtime_path,
        } => runtime.block_on(status(job_yaml, runtime_path)),
        Command::Inspect {
            job_yaml,
            runtime: runtime_path,
            key,
        } => runtime.block_on(inspect(job_yaml, runtime_path, key)),
        Command::Pass {
            job_yaml,
            pack,
            runtime: runtime_path,
            fixture,
            fixture_url,
            dry_run,
            r#loop,
            refusal_limit,
        } => runtime.block_on(pass(
            job_yaml,
            pack,
            runtime_path,
            *fixture,
            fixture_url.as_deref(),
            *dry_run,
            !*r#loop,
            *refusal_limit,
            cli.show_values,
        )),
        Command::Rescan {
            job_yaml,
            pack,
            runtime: runtime_path,
            fixture,
            fixture_url,
            dry_run,
            refusal_limit,
        } => runtime.block_on(rescan(
            job_yaml,
            pack,
            runtime_path,
            *fixture,
            fixture_url.as_deref(),
            *dry_run,
            *refusal_limit,
            cli.show_values,
        )),
    };
    match outcome {
        Ok(code) => code,
        Err(message) => {
            eprintln!("adapter-job: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Compile the job the way the engine compiles it and print the
/// value-free report.
fn check(job_yaml: &Path, pack: &Path, runtime: &Path) -> Result<ExitCode, String> {
    let program = compile(pack, job_yaml, runtime)?;
    let report = serde_json::json!({
        "ok": true,
        "job": {
            "id": program.job.job.id.as_str(),
            "version": program.job.job.version,
        },
        "source": {
            "pack": {
                "id": program.job.source.pack.id.as_str(),
                "version": program.job.source.pack.version,
            },
            "route": program.job.source.route,
        },
        "projectionDigest": program.job.projection_digest(),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("a plain object renders")
    );
    Ok(ExitCode::SUCCESS)
}

/// One bounded pass or the trigger loop.
#[allow(clippy::too_many_arguments)]
async fn pass(
    job_yaml: &Path,
    pack: &Path,
    runtime_path: &Path,
    fixture: bool,
    fixture_url: Option<&str>,
    dry_run: bool,
    once: bool,
    refusal_limit: u32,
    show_values: bool,
) -> Result<ExitCode, String> {
    let program = compile(pack, job_yaml, runtime_path)?;
    let pool = open_pools(runtime_path).await?;
    let preview = NullDestination::new();
    if once {
        let options = PassOptions {
            refusal_limit,
            ..PassOptions::default()
        };
        let report = bounded_pass(
            &program,
            &pool,
            &preview,
            options,
            fixture,
            fixture_url,
            dry_run,
        )
        .await?;
        print_pass_report(&report, dry_run, show_values, &preview);
        return Ok(pass_exit_code(&report));
    }
    // The loop: the interval trigger decides when a pass starts, a
    // rescan source's declared delay decides when a scan runs from the
    // first page, and greedy restarts after a pass that read at least
    // one item.
    let edits = source_edits(pack, program.job.source.route.as_str())?;
    let interval = trigger::interval_trigger(&program.job)
        .cloned()
        .ok_or_else(|| {
            "the job declares no interval trigger, so the loop has no schedule; declare one interval trigger".to_string()
        })?;
    let mut hot = false;
    loop {
        let now = std::time::SystemTime::now();
        let state = job_state(&pool, &program.job).await?;
        let was_hot = hot;
        hot = false;
        let rescan = !was_hot && trigger::rescan_due(&edits, &state, now);
        if !was_hot && !rescan {
            if let Some(wait) = trigger::next_due(&program.job, &state, now) {
                if wait > Duration::ZERO {
                    tokio::select! {
                        _ = tokio::time::sleep(wait) => {}
                        _ = tokio::signal::ctrl_c() => return Ok(ExitCode::SUCCESS),
                    }
                    continue;
                }
            }
        }
        let options = PassOptions {
            refusal_limit,
            rescan,
            dry_run: false,
        };
        let report = bounded_pass(
            &program,
            &pool,
            &preview,
            options,
            fixture,
            fixture_url,
            false,
        )
        .await?;
        print_pass_report(&report, false, show_values, &preview);
        // A greedy trigger starts again immediately after a pass that
        // read at least one item; the Camel port's own skip warning is
        // why the job author has to declare it.
        hot = interval.greedy && report.items_read > 0 && !rescan;
    }
}

/// Mark a rescan due now, then run one rescan pass from the first page.
async fn rescan(
    job_yaml: &Path,
    pack: &Path,
    runtime_path: &Path,
    fixture: bool,
    fixture_url: Option<&str>,
    dry_run: bool,
    refusal_limit: u32,
    show_values: bool,
) -> Result<ExitCode, String> {
    let program = compile(pack, job_yaml, runtime_path)?;
    let edits = source_edits(pack, program.job.source.route.as_str())?;
    if !matches!(edits, Edits::Rescan { .. }) {
        return Err(
            "the job's source route declares edits: ordered, whose edits the position finds; only an edits: rescan source rescans".to_string(),
        );
    }
    let pool = open_pools(runtime_path).await?;
    let preview = NullDestination::new();
    if !dry_run {
        let client = pool
            .get()
            .await
            .map_err(|error| format!("the job store could not be reached: {error}"))?;
        store::ensure_state(&client, program.job.job.id.as_str())
            .await
            .map_err(|error| format!("the job store refused: {error}"))?;
        store::mark_rescan_due(&client, program.job.job.id.as_str())
            .await
            .map_err(|error| format!("the job store refused: {error}"))?;
    }
    let options = PassOptions {
        refusal_limit,
        rescan: true,
        dry_run,
    };
    let report = bounded_pass(
        &program,
        &pool,
        &preview,
        options,
        fixture,
        fixture_url,
        dry_run,
    )
    .await?;
    print_pass_report(&report, dry_run, show_values, &preview);
    Ok(pass_exit_code(&report))
}

/// One bounded pass with the named destination: the fixture destination
/// at its loopback URL, or the preview destination of the dry run. A
/// real destination is its own brief; the seam is the hand-off point it
/// plugs into.
async fn bounded_pass(
    program: &JobProgram,
    pool: &Pool,
    preview: &NullDestination,
    options: PassOptions,
    fixture: bool,
    fixture_url: Option<&str>,
    dry_run: bool,
) -> Result<PassReport, String> {
    if !dry_run && !fixture {
        return Err(
            "name a destination: --destination with --fixture-url, or --dry-run for the operator preview; a real destination plugs into the same seam".to_string(),
        );
    }
    if fixture {
        let url =
            fixture_url.ok_or_else(|| "--fixture-url names the fixture receiver".to_string())?;
        let destination = FixtureDestination::new(url)
            .map_err(|reason| format!("the fixture url was refused: {reason}"))?;
        Ok(run_pass(pool, program, &destination, options).await)
    } else {
        Ok(run_pass(pool, program, preview, options).await)
    }
}

/// Print one pass report, value-free unless the caller asked for the
/// dry-run's recorded projections.
fn print_pass_report(
    report: &PassReport,
    dry_run: bool,
    show_values: bool,
    preview: &NullDestination,
) {
    let stopped = report.stopped.as_ref().map(|reason| {
        serde_json::json!({
            "reason": stop_reason_name(reason),
            "code": reason.stop_text(),
        })
    });
    let mut body = serde_json::json!({
        "itemsRead": report.items_read,
        "itemsNew": report.items_new,
        "itemsChanged": report.items_changed,
        "itemsRedelivered": report.items_redelivered,
        "itemsSkipped": report.items_skipped,
        "itemsAcknowledged": report.items_acknowledged,
        "itemsRefused": report.items_refused,
        "refusalsByCode": report.refusals_by_code,
        "malformedLines": report.malformed_lines,
        "stopped": stopped,
        "overdue": report.overdue,
    });
    if dry_run {
        let delivered = preview
            .recorded()
            .into_iter()
            .map(|(job_id, item)| {
                let mut entry = serde_json::json!({
                    "jobId": job_id,
                    "key": item.key,
                    "sequence": item.sequence,
                    "digest": item.digest,
                    "priorRunId": item.prior_run_id,
                    "admittedBefore": item.admitted_before,
                });
                if show_values {
                    entry
                        .as_object_mut()
                        .expect("an object")
                        .insert("projected".to_string(), item.projected);
                }
                entry
            })
            .collect::<Vec<_>>();
        let members = body.as_object_mut().expect("an object");
        members.insert("dryRun".to_string(), serde_json::json!(true));
        members.insert("wouldDeliver".to_string(), serde_json::json!(delivered));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&body).expect("a plain object renders")
    );
}

fn stop_reason_name(reason: &StopReason) -> &'static str {
    match reason {
        StopReason::LeaseHeld => "lease-held",
        StopReason::PageFault { .. } => "page-fault",
        StopReason::DestinationStop { .. } => "destination-stop",
        StopReason::RefusalLimit { .. } => "refusal-limit",
    }
}

/// A pass leaves the operator's exit code at failure: a stopped pass is
/// a condition an operator or a CronJob acts on.
fn pass_exit_code(report: &PassReport) -> ExitCode {
    if report.stopped.is_some() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Count what the item table holds, value-free.
async fn status(job_yaml: &Path, runtime_path: &Path) -> Result<ExitCode, String> {
    let job = read_job(job_yaml)?;
    let pool = read_pool(runtime_path)?;
    let client = pool
        .get()
        .await
        .map_err(|error| format!("the job store could not be reached: {error}"))?;
    let job_id = job.job.id.as_str();
    store::ensure_state(&client, job_id)
        .await
        .map_err(|error| format!("the job store refused: {error}"))?;
    let counts = store::item_counts(&client, job_id)
        .await
        .map_err(|error| format!("the job store refused: {error}"))?;
    let row = store::read_state(&client, job_id)
        .await
        .map_err(|error| format!("the job store refused: {error}"))?
        .unwrap_or_default();
    let state = trigger_state(&row);
    let overdue = trigger::next_due(&job, &state, std::time::SystemTime::now())
        .is_some_and(|due| due == Duration::ZERO);
    let report = serde_json::json!({
        "job": {"id": job.job.id.as_str(), "version": job.job.version},
        "items": {
            "pending": counts.pending,
            "acknowledged": counts.acknowledged,
            "refused": counts.refused,
        },
        "refusalsByCode": counts.refusals_by_code,
        "schedule": {
            "overdue": overdue,
            "lastPassAt": optional_time(row.last_pass_at),
            "lastPassStop": row.last_pass_stop,
            "leaseExpires": optional_time(row.lease_expires),
            "positionPresent": row.position.is_some(),
            "lastRescanAt": optional_time(row.last_rescan_at),
            "idleStreak": row.idle_streak,
            "errorStreak": row.error_streak,
            "projectionDigest": row.projection_digest,
        },
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("a plain object renders")
    );
    Ok(ExitCode::SUCCESS)
}

/// Read one item's row, value-free.
async fn inspect(job_yaml: &Path, runtime_path: &Path, key: &str) -> Result<ExitCode, String> {
    let job = read_job(job_yaml)?;
    let pool = read_pool(runtime_path)?;
    let client = pool
        .get()
        .await
        .map_err(|error| format!("the job store could not be reached: {error}"))?;
    let record = store::inspect_item(&client, job.job.id.as_str(), key)
        .await
        .map_err(|error| format!("the job store refused: {error}"))?;
    let report = match record {
        Some(record) => serde_json::json!({
            "found": true,
            "item": {
                "key": record.key,
                "lastDigest": record.last_digest,
                "sequence": record.sequence,
                "status": record.status.as_str(),
                "code": record.code,
                "runId": record.run_id,
                "priorRunId": record.prior_run_id,
                "admittedBefore": record.admitted_before,
                "firstSeen": optional_time(Some(record.first_seen)),
                "lastSeen": optional_time(Some(record.last_seen)),
            },
        }),
        None => serde_json::json!({"found": false, "key": key}),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("a plain object renders")
    );
    Ok(ExitCode::SUCCESS)
}

/// Compile the job the engine compiles.
fn compile(pack: &Path, job_yaml: &Path, runtime: &Path) -> Result<JobProgram, String> {
    compile_job(pack, job_yaml, runtime).map_err(|error| job_error_message(&error))
}

/// The value-free rendering of a compile refusal: every diagnostic the
/// compiler carried, code first.
fn job_error_message(error: &JobError) -> String {
    let rendered = error
        .diagnostics
        .iter()
        .map(|diagnostic| {
            format!(
                "{} at {} {}",
                diagnostic.code, diagnostic.path, diagnostic.message
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    format!("the job was refused: {rendered}")
}

/// The job's source route edit property, read from the pinned pack: the
/// declaration the rescan gate runs on. The compile already proved the
/// pack bytes match the job's pin, so reading them again is faithful.
fn source_edits(pack_path: &Path, route: &str) -> Result<Edits, String> {
    let declared = source_route(pack_path, route)?;
    to_edits(&declared)
}

fn source_route(pack_path: &Path, route: &str) -> Result<SourceRouteDecl, String> {
    let pack = read_pack(pack_path)?;
    pack.source_routes
        .iter()
        .find(|declared| declared.id.as_str() == route)
        .cloned()
        .ok_or_else(|| format!("the pinned pack declares no source route {route}"))
}

/// The source route's edit declaration, as the rescan gate reads it.
fn to_edits(declared: &SourceRouteDecl) -> Result<Edits, String> {
    match declared.edits.as_deref() {
        Some("ordered") => Ok(Edits::Ordered),
        Some("rescan") => {
            let delay_seconds = declared.rescan_delay_seconds.ok_or_else(|| {
                "the source route declares edits: rescan with no rescanDelaySeconds".to_string()
            })?;
            Ok(Edits::Rescan { delay_seconds })
        }
        other => Err(format!(
            "the source route declares edits {other:?}, which is neither ordered nor rescan; the job checks refuse it at compile"
        )),
    }
}

/// The job state the schedule reads, from the store row.
async fn job_state(pool: &Pool, job: &AdapterJob) -> Result<JobState, String> {
    let client = pool
        .get()
        .await
        .map_err(|error| format!("the job store could not be reached: {error}"))?;
    let row = store::read_state(&client, job.job.id.as_str())
        .await
        .map_err(|error| format!("the job store refused: {error}"))?
        .unwrap_or_default();
    Ok(trigger_state(&row))
}

fn trigger_state(row: &store::JobStateRow) -> JobState {
    JobState {
        position: row.position.clone(),
        projection_digest: row.projection_digest.clone(),
        lease_expires: row.lease_expires,
        last_pass_at: row.last_pass_at,
        last_pass_stop: row.last_pass_stop.clone(),
        last_rescan_at: row.last_rescan_at,
        idle_streak: u32::try_from(row.idle_streak.max(0)).unwrap_or(u32::MAX),
        error_streak: u32::try_from(row.error_streak.max(0)).unwrap_or(u32::MAX),
    }
}

/// Open the job store: migrate through the migration reference, then
/// hand back the least-privileged runtime pool.
async fn open_pools(runtime_path: &Path) -> Result<Pool, String> {
    let runtime_config = read_runtime(runtime_path)?;
    let resolver = secret_resolver()?;
    let migration_pool = store::build_pool(&runtime_config.database, &resolver, true)
        .map_err(|error| error.to_string())?;
    {
        let client = migration_pool
            .get()
            .await
            .map_err(|error| format!("the job store migration could not connect: {error}"))?;
        store::migrate(&client)
            .await
            .map_err(|error| format!("the job store migration failed: {error}"))?;
    }
    store::build_pool(&runtime_config.database, &resolver, false).map_err(|error| error.to_string())
}

/// The read-only pool of the status and inspect surfaces, from the
/// runtime config's database block.
fn read_pool(runtime_path: &Path) -> Result<Pool, String> {
    let runtime_config = read_runtime(runtime_path)?;
    let resolver = secret_resolver()?;
    store::build_pool(&runtime_config.database, &resolver, false).map_err(|error| error.to_string())
}

fn secret_resolver() -> Result<SecretResolver, String> {
    SecretResolver::new([SecretProvider::Environment], "")
        .map_err(|error| format!("the secret resolver could not start: {error:?}"))
}

/// Read the job definition: the envelope the loader carries, checked
/// here the way the engine checks it before the type parses the body.
fn read_job(path: &Path) -> Result<AdapterJob, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("the job definition could not be read: {error}"))?;
    let job: AdapterJob = serde_norway::from_str(&text)
        .map_err(|error| format!("the job definition was refused: {error}"))?;
    if job.api_version != registry_adapter_core::ADAPTER_JOB_API_VERSION
        || job.kind != registry_adapter_core::ADAPTER_JOB_KIND
    {
        return Err(format!(
            "the job definition carries apiVersion {} and kind {}, not the {} {} this executable reads",
            job.api_version,
            job.kind,
            registry_adapter_core::ADAPTER_JOB_API_VERSION,
            registry_adapter_core::ADAPTER_JOB_KIND,
        ));
    }
    Ok(job)
}

/// Read the pinned pack, for the declarations the compiled program does
/// not carry.
fn read_pack(path: &Path) -> Result<AdapterPack, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("the pack could not be read: {error}"))?;
    serde_norway::from_str(&text).map_err(|error| format!("the pack was refused: {error}"))
}

/// Read the operator runtime config.
fn read_runtime(path: &Path) -> Result<AdapterRuntimeConfig, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("the runtime config could not be read: {error}"))?;
    serde_norway::from_str(&text)
        .map_err(|error| format!("the runtime config was refused: {error}"))
}

/// One timestamp in the operator output: UTC, RFC 3339, or absent.
fn optional_time(at: Option<std::time::SystemTime>) -> Option<String> {
    at.map(|at| {
        let seconds = at
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_secs() as i64)
            .unwrap_or(0);
        chrono::DateTime::from_timestamp(seconds, 0)
            .unwrap_or(chrono::DateTime::UNIX_EPOCH)
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    })
}
