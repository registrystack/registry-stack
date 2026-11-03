// SPDX-License-Identifier: Apache-2.0

//! The `adapter-job` binary entry point: the operator surface of the
//! governed-ingestion job (`products/adapter/CONCEPT.md` section 17.4).
//! Init-store applies the job-store schema without running a job, check
//! compiles a job the engine compiles, pass runs one bounded pass or the
//! trigger loop, status counts what the item table holds, inspect reads
//! one item's row, and rescan marks a rescan due and runs it. The output
//! is value-free by default: no item value, no projection, no secret. The
//! store holds no payload to leak.

use clap::Parser;
use deadpool_postgres::Pool;
use registry_adapter_core::AdapterJob;
use registry_adapter_engine::job::{compile_job_with_runtime, JobError, JobProgram};
use registry_adapter_engine::job_sources::JobRuntimeConfig;
use registry_adapter_job::cli::{Cli, Command, WorkspaceArgs};
use registry_adapter_job::destination::{
    FixtureDestination, JobDestination as DestinationSeam, NullDestination,
};
use registry_adapter_job::pass::{run_pass, PassOptions, PassReport, StopReason};
use registry_adapter_job::runtime_destination::{activate_destination, check_destination_runtime};
use registry_adapter_job::store;
use registry_adapter_job::trigger::{self, Edits, HookPassGate, JobState, LastPass, Step};
use registry_platform_config::SecretResolver;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

fn main() -> ExitCode {
    let cli = Cli::parse();
    #[cfg(feature = "job-rabbitmq")]
    if let Err(error) = registry_adapter_job::tls_provider::initialize() {
        eprintln!("adapter-job: {error}");
        return ExitCode::FAILURE;
    }
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
        Command::InitStore {
            runtime: runtime_path,
        } => runtime.block_on(init_store(runtime_path)),
        Command::Check {
            job_yaml,
            pack,
            runtime: runtime_path,
            workspace,
        } => check(job_yaml, pack, runtime_path, workspace),
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
            workspace,
            fixture,
            fixture_url,
            dry_run,
            r#loop,
            refusal_limit,
        } => runtime.block_on(pass(
            job_yaml,
            pack,
            runtime_path,
            workspace,
            *fixture,
            fixture_url.as_deref(),
            *dry_run,
            !*r#loop,
            *refusal_limit,
            cli.show_values,
        )),
        Command::RebindIdentity {
            job_yaml,
            pack,
            runtime: runtime_path,
            workspace,
        } => runtime.block_on(rebind_identity(job_yaml, pack, runtime_path, workspace)),
        Command::Rescan {
            job_yaml,
            pack,
            runtime: runtime_path,
            workspace,
            fixture,
            fixture_url,
            dry_run,
            refusal_limit,
        } => runtime.block_on(rescan(
            job_yaml,
            pack,
            runtime_path,
            workspace,
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

/// Initialize or advance only the job-store schema. The typed runtime reader
/// checks the whole document, but this command extracts and resolves only its
/// store block: no job is compiled and no source or destination is activated.
async fn init_store(runtime_path: &Path) -> Result<ExitCode, String> {
    let runtime = load_runtime(runtime_path)?;
    let resolver = runtime_secret_resolver(&runtime)?;
    let _pool = open_pool(&runtime, &resolver).await?;
    let report = serde_json::json!({
        "ok": true,
        "schemaVersion": store::SUPPORTED_SCHEMA_VERSION,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("a plain object renders")
    );
    Ok(ExitCode::SUCCESS)
}

/// Compile the job the way the engine compiles it and print the
/// value-free report.
fn check(
    job_yaml: &Path,
    pack: &Path,
    runtime: &Path,
    workspace: &WorkspaceArgs,
) -> Result<ExitCode, String> {
    let runtime_config = load_runtime(runtime)?;
    let resolver = runtime_secret_resolver(&runtime_config)?;
    let program = compile(
        pack,
        job_yaml,
        &runtime_config,
        Arc::clone(&resolver),
        workspace,
    )?;
    check_hook_runtime(&program.job, &runtime_config)?;
    #[cfg(feature = "job-hook")]
    registry_adapter_job::hook_ingress::preflight(&program.job, &runtime_config, &resolver)
        .map_err(|error| error.to_string())?;
    #[cfg(feature = "job-sftp")]
    registry_adapter_job::sftp_source::validate_sftp_host_bindings(&program)?;
    check_destination_runtime(&program.job, &runtime_config)?;
    let destination = match &program.job.destination {
        registry_adapter_core::JobDestination::DirectBreg { binding, mode, .. } => {
            serde_json::json!({
                "type": "direct-breg",
                "binding": binding.as_str(),
                "mode": match mode {
                    registry_adapter_core::DirectBregMode::Immediate => "immediate",
                    registry_adapter_core::DirectBregMode::Proposal => "proposal",
                }
            })
        }
        registry_adapter_core::JobDestination::SignedCoordinatorEvent { binding, .. } => {
            serde_json::json!({
                "type": "signed-coordinator-event",
                "binding": binding.as_str(),
            })
        }
    };
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
        "destination": destination,
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
    workspace: &WorkspaceArgs,
    fixture: bool,
    fixture_url: Option<&str>,
    dry_run: bool,
    once: bool,
    refusal_limit: u32,
    show_values: bool,
) -> Result<ExitCode, String> {
    let runtime = load_runtime(runtime_path)?;
    let resolver = runtime_secret_resolver(&runtime)?;
    let mut program = compile(pack, job_yaml, &runtime, Arc::clone(&resolver), workspace)?;
    check_hook_runtime(&program.job, &runtime)?;
    activate_sources(&mut program, &resolver)?;
    let pool = pass_pool(&runtime, &resolver, dry_run).await?;
    let preview = NullDestination::new();
    if once {
        let destination =
            activate_pass_destination(&program, &runtime, &resolver, fixture, fixture_url, dry_run)
                .await?;
        let options = PassOptions {
            refusal_limit,
            dry_run,
            ..PassOptions::default()
        };
        let report =
            bounded_pass(&program, &pool, &preview, destination.as_deref(), options).await?;
        print_pass_report(&report, dry_run, show_values, &preview);
        return Ok(pass_exit_code(&report));
    }
    let edits = source_edits(&program)?;
    let shutdown = shutdown_requests()?;
    if trigger::interval_trigger(&program.job).is_none() {
        return Err(
            "the job declares no interval trigger, so the loop has no schedule; declare one interval trigger".to_string(),
        );
    }
    let gate = Arc::new(HookPassGate::default());
    // The hook credentials resolve before the destination activates, so a
    // credential fault is not hidden behind an unreachable destination.
    #[cfg(feature = "job-hook")]
    let hook_plan = registry_adapter_job::hook_ingress::activate(
        &program.job,
        &runtime,
        &resolver,
        Arc::clone(&gate),
    )
    .map_err(|error| error.to_string())?;
    let destination =
        activate_pass_destination(&program, &runtime, &resolver, fixture, fixture_url, dry_run)
            .await?;
    #[cfg(feature = "job-hook")]
    if let Some(plan) = hook_plan {
        let server = plan.bind().await.map_err(|error| error.to_string())?;
        let hook_address = server.local_addr().map_err(|error| error.to_string())?;
        eprintln!("adapter.job.hook-listening address={hook_address}");
        let ingress_stop = Arc::new(tokio::sync::Notify::new());
        let loop_future = run_pass_loop(
            &program,
            &pool,
            &preview,
            destination
                .as_deref()
                .expect("a loop always has a non-preview destination"),
            &edits,
            gate,
            shutdown,
            refusal_limit,
            show_values,
        );
        let ingress_stop_for_server = Arc::clone(&ingress_stop);
        let server_future = server.serve(async move {
            ingress_stop_for_server.notified().await;
        });
        tokio::pin!(loop_future);
        tokio::pin!(server_future);
        return tokio::select! {
            result = &mut loop_future => {
                ingress_stop.notify_one();
                server_future.await.map_err(|error| error.to_string())?;
                result
            }
            result = &mut server_future => {
                result.map_err(|error| error.to_string())?;
                Err("adapter.job.hook-serve".to_string())
            }
        };
    }
    run_pass_loop(
        &program,
        &pool,
        &preview,
        destination
            .as_deref()
            .expect("a loop always has a non-preview destination"),
        &edits,
        gate,
        shutdown,
        refusal_limit,
        show_values,
    )
    .await
}

/// A stop request for the long-running loop: SIGTERM, which service managers,
/// `docker stop` and Kubernetes send, or SIGINT (Ctrl+C). The handlers are
/// installed before the first pass, so a request that arrives while a pass is
/// running is kept and the loop stops when that pass ends, rather than the
/// process dying mid-send or the request being lost.
fn shutdown_requests() -> Result<tokio::sync::watch::Receiver<bool>, String> {
    use tokio::signal::unix::{signal, SignalKind};
    let refused =
        |error: std::io::Error| format!("the stop signal handlers could not be installed: {error}");
    let mut terminate = signal(SignalKind::terminate()).map_err(refused)?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(refused)?;
    let (requested, observed) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
        requested.send_replace(true);
    });
    Ok(observed)
}

/// Run the one serialized pass loop. Hook requests only wake this loop; all
/// source, cursor, rescan, and destination choices remain compiled artifacts.
#[allow(clippy::too_many_arguments)]
async fn run_pass_loop(
    program: &JobProgram,
    pool: &Pool,
    preview: &NullDestination,
    destination: &dyn DestinationSeam,
    edits: &Edits,
    gate: Arc<HookPassGate>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    refusal_limit: u32,
    show_values: bool,
) -> Result<ExitCode, String> {
    let mut last = LastPass::NotYet;
    let started = SystemTime::now();
    let delay = trigger::interval_trigger(&program.job)
        .map(|trigger| Duration::from_millis(trigger.delay_milliseconds))
        .ok_or_else(|| "the job declares no interval trigger".to_string())?;
    loop {
        let now = std::time::SystemTime::now();
        // A store that cannot be read (a restart, a failover) does not end
        // the loop: name the closed cause, wait one delay, read again.
        let state = match job_state(pool, &program.job).await {
            Ok(state) => state,
            Err(cause) => {
                eprintln!("{}", store_unreachable_line(&cause, delay));
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {
                        last = LastPass::NotYet;
                        continue;
                    }
                    _ = shutdown.wait_for(|requested| *requested) => return Ok(ExitCode::SUCCESS),
                }
            }
        };
        let step = trigger::next_step(&program.job, edits, &state, last, now, started)
            .ok_or_else(|| "the job declares no interval trigger".to_string())?;
        let rescan = match step {
            Step::Wait(wait) => {
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {
                        last = LastPass::NotYet;
                        continue;
                    }
                    _ = gate.wait_for_hook(), if trigger::hook_ends_the_wait(last) => {
                        let now = SystemTime::now();
                        state.rescan_active || trigger::rescan_due(edits, &state, now)
                    }
                    _ = shutdown.wait_for(|requested| *requested) => return Ok(ExitCode::SUCCESS),
                }
            }
            Step::Run { rescan } => rescan,
        };
        if !gate.begin_pass() {
            return Err("adapter.job.hook-pass-already-running".to_string());
        }
        let options = PassOptions {
            refusal_limit,
            rescan,
            dry_run: false,
        };
        let report = bounded_pass(program, pool, preview, Some(destination), options).await;
        gate.end_pass();
        let report = report?;
        print_pass_report(&report, false, show_values, preview);
        if *shutdown.borrow() {
            return Ok(ExitCode::SUCCESS);
        }
        last = match report.stopped {
            None => LastPass::Settled {
                items_read: report.items_read,
                rescan,
            },
            Some(StopReason::LeaseHeld) => LastPass::LeaseHeld,
            Some(_) => LastPass::Stopped,
        };
    }
}

/// Mark a rescan due now, then run one rescan pass from the first page.
#[allow(clippy::too_many_arguments)]
async fn rescan(
    job_yaml: &Path,
    pack: &Path,
    runtime_path: &Path,
    workspace: &WorkspaceArgs,
    fixture: bool,
    fixture_url: Option<&str>,
    dry_run: bool,
    refusal_limit: u32,
    show_values: bool,
) -> Result<ExitCode, String> {
    let runtime = load_runtime(runtime_path)?;
    let resolver = runtime_secret_resolver(&runtime)?;
    let mut program = compile(pack, job_yaml, &runtime, Arc::clone(&resolver), workspace)?;
    check_hook_runtime(&program.job, &runtime)?;
    activate_sources(&mut program, &resolver)?;
    let edits = source_edits(&program)?;
    if !matches!(edits, Edits::Rescan { .. }) {
        return Err(
            "the job's source route declares edits: ordered, whose edits the position finds; only an edits: rescan source rescans".to_string(),
        );
    }
    let pool = pass_pool(&runtime, &resolver, dry_run).await?;
    let preview = NullDestination::new();
    let destination =
        activate_pass_destination(&program, &runtime, &resolver, fixture, fixture_url, dry_run)
            .await?;
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
    let report = bounded_pass(&program, &pool, &preview, destination.as_deref(), options).await?;
    print_pass_report(&report, dry_run, show_values, &preview);
    Ok(pass_exit_code(&report))
}

/// Accept an intended item-identity change. The receipt goes to standard
/// output for the operator and one audit line to standard error for the
/// supervisor's log, both value-free.
async fn rebind_identity(
    job_yaml: &Path,
    pack: &Path,
    runtime_path: &Path,
    workspace: &WorkspaceArgs,
) -> Result<ExitCode, String> {
    let runtime = load_runtime(runtime_path)?;
    let resolver = runtime_secret_resolver(&runtime)?;
    let program = compile(pack, job_yaml, &runtime, Arc::clone(&resolver), workspace)?;
    let pool = open_pool(&runtime, &resolver).await?;
    let mut client = pool
        .get()
        .await
        .map_err(|error| format!("the job store could not be reached: {error}"))?;
    let job_id = program.job.job.id.as_str();
    let rebound = store::rebind_item_identity(
        &mut client,
        job_id,
        program.item_identity_digest().as_ref(),
    )
    .await
    .map_err(|error| match error {
        store::StoreError::LeaseHeld => {
            "a pass holds the job lease; stop the running pass or loop, then run rebind-identity again".to_string()
        }
        error => format!("the job store refused: {error}"),
    })?;
    if rebound.changed {
        eprintln!(
            "adapter.job.identity-rebound job={job_id} itemsKept={} at={}",
            rebound.items_kept,
            optional_time(Some(SystemTime::now())).unwrap_or_default()
        );
    }
    let report = serde_json::json!({
        "ok": true,
        "jobId": job_id,
        "changed": rebound.changed,
        "itemsKept": rebound.items_kept,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("a plain object renders")
    );
    Ok(ExitCode::SUCCESS)
}

/// Activate one immutable destination client for this command or loop.
/// Preview never resolves destination credentials, and an explicit fixture
/// never falls through to an operational destination.
async fn activate_pass_destination<'a>(
    program: &'a JobProgram,
    runtime: &JobRuntimeConfig,
    resolver: &SecretResolver,
    fixture: bool,
    fixture_url: Option<&str>,
    dry_run: bool,
) -> Result<Option<Box<dyn DestinationSeam + 'a>>, String> {
    if dry_run {
        return Ok(None);
    }
    if fixture {
        let url =
            fixture_url.ok_or_else(|| "--fixture-url names the fixture receiver".to_string())?;
        let destination = FixtureDestination::new(url)
            .map_err(|reason| format!("the fixture url was refused: {reason}"))?;
        return Ok(Some(Box::new(destination)));
    }
    activate_destination(program, runtime, resolver)
        .await
        .map(Some)
}

/// One bounded pass through the destination captured for this process.
async fn bounded_pass(
    program: &JobProgram,
    pool: &Pool,
    preview: &NullDestination,
    destination: Option<&dyn DestinationSeam>,
    options: PassOptions,
) -> Result<PassReport, String> {
    if options.dry_run {
        Ok(run_pass(pool, program, preview, options).await)
    } else {
        let destination =
            destination.ok_or_else(|| "adapter.job.destination-not-activated".to_string())?;
        Ok(run_pass(pool, program, destination, options).await)
    }
}

/// A preview acknowledges nothing: the preview destination's would-be
/// deliveries are listed under `wouldDeliver`, not counted as acknowledged.
fn acknowledged_count(report: &PassReport, dry_run: bool) -> u32 {
    if dry_run {
        0
    } else {
        report.items_acknowledged
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
        let mut stopped = serde_json::json!({
            "reason": stop_reason_name(reason),
            "code": reason.stop_text(),
        });
        if let Some(next) = stop_next_step(reason) {
            stopped
                .as_object_mut()
                .expect("a stop report is an object")
                .insert("next".to_string(), serde_json::json!(next));
        }
        if let StopReason::PageFault {
            record: Some(record),
            ..
        } = reason
        {
            stopped
                .as_object_mut()
                .expect("a stop report is an object")
                .insert(
                    "record".to_string(),
                    serde_json::to_value(record).expect("a record locator is JSON"),
                );
        }
        stopped
    });
    let mut body = serde_json::json!({
        "itemsRead": report.items_read,
        "itemsNew": report.items_new,
        "itemsChanged": report.items_changed,
        "itemsRedelivered": report.items_redelivered,
        "itemsSkipped": report.items_skipped,
        "itemsAcknowledged": acknowledged_count(report, dry_run),
        "itemsRefused": report.items_refused,
        "itemsHeld": report.items_held,
        "refusalsByCode": report.refusals_by_code,
        "holdsByCode": report.holds_by_code,
        "malformedLines": report.malformed_lines,
        "stopped": stopped,
        "stopNotRecorded": report.stop_record_failure,
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

/// The one step that clears a stop an operator can clear, for the stop
/// report. Value-free and fixed per code.
fn stop_next_step(reason: &StopReason) -> Option<&'static str> {
    next_step_for_stop_text(&reason.stop_text())
}

/// The next step for a recorded stop text (`page-fault:<code>`,
/// `destination-stop:<code>`), so `status` can repeat what the pass printed.
fn next_step_for_stop_text(text: &str) -> Option<&'static str> {
    if text.contains(registry_adapter_job::pass::ITEM_IDENTITY_MIGRATION_REQUIRED) {
        Some("If the keyPointer or CSV change is intended, run adapter-job rebind-identity <job.yaml> --pack <pack> --runtime <runtime>; stored items are kept and the new identity reads them as new. Otherwise restore the previous job definition.")
    } else if text.contains(registry_adapter_job::pass::COORDINATOR_IDENTITY_UNRECORDED) {
        Some("A pending signed delivery was staged before store schema 103 recorded its receiver and body identity, so this binary cannot prove a retry is the same event. Restore the pre-upgrade database backup, run passes with the previous binary until adapter-job status lists no pending items, then upgrade and run init-store again.")
    } else if text.contains(registry_adapter_job::pass::COORDINATOR_BODY_CHANGED) {
        Some("A pending delivery was first attempted under a different job.version or projection. Restore the previous job definition, run passes until the pending item settles (adapter-job status lists the pending keys), then ship the change.")
    } else {
        None
    }
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
    let runtime = load_runtime(runtime_path)?;
    let resolver = runtime_secret_resolver(&runtime)?;
    let pool = read_pool(&runtime, &resolver)?;
    let client = pool
        .get()
        .await
        .map_err(|error| format!("the job store could not be reached: {error}"))?;
    require_current_schema(&client, "status").await?;
    // Status is a read: a job no pass has run yet reports the default
    // state, and no row is written for it.
    let job_id = job.job.id.as_str();
    let counts = store::item_counts(&client, job_id)
        .await
        .map_err(|error| format!("the job store refused: {error}"))?;
    let row = store::read_state(&client, job_id)
        .await
        .map_err(|error| format!("the job store refused: {error}"))?
        .unwrap_or_default();
    let now = SystemTime::now();
    let overdue = status_overdue(&job, &row, now);
    let receipt_horizon = match &job.destination {
        registry_adapter_core::JobDestination::DirectBreg {
            receipt_retention_days,
            ..
        } => {
            let horizon =
                store::receipt_horizon_counts(&client, job_id, now, *receipt_retention_days)
                    .await
                    .map_err(|error| format!("the job store refused: {error}"))?;
            Some(serde_json::json!({
                "receiptRetentionDays": receipt_retention_days,
                "pendingNearingHorizon": horizon.nearing,
                "pendingPastHorizon": horizon.expired,
            }))
        }
        registry_adapter_core::JobDestination::SignedCoordinatorEvent { .. } => None,
    };
    let hold_guidance = counts
        .holds_by_code
        .keys()
        .filter_map(|code| {
            let mut guidance = hold_guidance(
                &job.destination,
                store::ItemStatus::Held,
                Some(code),
                HoldGuidanceScope::Aggregate,
            )?;
            guidance
                .as_object_mut()
                .expect("hold guidance is an object")
                .insert(
                    "count".to_string(),
                    serde_json::json!(counts.holds_by_code[code]),
                );
            Some(guidance)
        })
        .collect::<Vec<_>>();
    let report = serde_json::json!({
        "job": {"id": job.job.id.as_str(), "version": job.job.version},
        "items": {
            "pending": counts.pending,
            "acknowledged": counts.acknowledged,
            "refused": counts.refused,
            "held": counts.held,
        },
        "refusalsByCode": counts.refusals_by_code,
        "holdsByCode": counts.holds_by_code,
        "holdGuidance": hold_guidance,
        "pendingKeys": counts.pending_keys,
        "receiptHorizon": receipt_horizon,
        "schedule": {
            "overdue": overdue,
            "lastPassAt": optional_time(row.last_pass_at),
            "lastPassStop": row.last_pass_stop,
            "lastPassStopNext": row
                .last_pass_stop
                .as_deref()
                .and_then(next_step_for_stop_text),
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
    let runtime = load_runtime(runtime_path)?;
    let resolver = runtime_secret_resolver(&runtime)?;
    let pool = read_pool(&runtime, &resolver)?;
    let client = pool
        .get()
        .await
        .map_err(|error| format!("the job store could not be reached: {error}"))?;
    require_current_schema(&client, "inspect").await?;
    let record = store::inspect_item(&client, job.job.id.as_str(), key)
        .await
        .map_err(|error| format!("the job store refused: {error}"))?;
    let report = match record {
        Some(record) => {
            let hold = hold_guidance(
                &job.destination,
                record.status,
                record.code.as_deref(),
                HoldGuidanceScope::Item(
                    record.run_id.as_deref().or(record.prior_run_id.as_deref()),
                ),
            );
            serde_json::json!({
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
                    "hold": hold,
                },
            })
        }
        None => serde_json::json!({"found": false, "key": key}),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("a plain object renders")
    );
    Ok(ExitCode::SUCCESS)
}

/// Whether an existing job's next interval pass is already due. A job
/// with no completed or stopped pass is due according to its initial
/// delay, but is not overdue: there is no prior operator deadline to
/// have missed. The trigger retains its own due-now behavior.
fn status_overdue(job: &AdapterJob, row: &store::JobStateRow, now: SystemTime) -> bool {
    if row.last_pass_at.is_none() {
        return false;
    }
    trigger::next_due(job, &trigger_state(row), now, now).is_some_and(|due| due == Duration::ZERO)
}

/// Whether guidance describes aggregate status or one inspected item.
#[derive(Clone, Copy)]
enum HoldGuidanceScope<'a> {
    /// Status knows counts and codes, not per-item references.
    Aggregate,
    /// Inspect knows the stored destination reference, when one exists.
    Item(Option<&'a str>),
}

/// Static, value-free guidance for a held item. Destination outcomes
/// stay under destination authority, while a changed RabbitMQ delivery
/// also needs broker-policy resolution. The job offers no mutation that
/// releases, accepts, acknowledges, or reconciles held work.
fn hold_guidance(
    destination: &registry_adapter_core::JobDestination,
    status: store::ItemStatus,
    code: Option<&str>,
    scope: HoldGuidanceScope<'_>,
) -> Option<serde_json::Value> {
    if status != store::ItemStatus::Held {
        return None;
    }
    let code = code?;
    let destination_reference = match scope {
        HoldGuidanceScope::Aggregate => None,
        HoldGuidanceScope::Item(reference) => reference,
    };
    let (action_owner, next_action) = if code == "adapter.job.rabbitmq-event-changed" {
        let action = match scope {
            HoldGuidanceScope::Aggregate => {
                "Use inspect on each held item before claiming a destination reference. First establish any possible destination outcome under the destination's own authority. Then the broker operator must resolve the old unsettled delivery by dead-lettering or removing it under approved broker policy. Only after those steps may the publisher/source operator correct its immutable-identity and version-handling logic before publishing legitimate future work under a new immutable message ID. Do not rekey uncertain or already accepted work to force a fresh registration. Publishing a new message ID alone does not clear the old delivery; the Adapter keeps the row held and does not acknowledge or release it, and the unsettled delivery can block later messages at the queue head."
            }
            HoldGuidanceScope::Item(Some(_)) => {
                "First establish the possible outcome for destinationReference under the destination's own authority. Then the broker operator must resolve the old unsettled delivery by dead-lettering or removing it under approved broker policy. Only after those steps may the publisher/source operator correct its immutable-identity and version-handling logic before publishing legitimate future work under a new immutable message ID. Do not rekey uncertain or already accepted work to force a fresh registration. Publishing a new message ID alone does not clear the old delivery; the Adapter keeps the row held and does not acknowledge or release it, and the unsettled delivery can block later messages at the queue head."
            }
            HoldGuidanceScope::Item(None) => {
                "No destination reference is established. First inspect destination admission and idempotency records to establish any possible outcome under the destination's own authority. Then the broker operator must resolve the old unsettled delivery by dead-lettering or removing it under approved broker policy. Only after those steps may the publisher/source operator correct its immutable-identity and version-handling logic before publishing legitimate future work under a new immutable message ID. Do not rekey uncertain or already accepted work to force a fresh registration. Publishing a new message ID alone does not clear the old delivery; the Adapter keeps the row held and does not acknowledge or release it, and the unsettled delivery can block later messages at the queue head."
            }
        };
        ("broker-operator", action)
    } else {
        match destination {
            registry_adapter_core::JobDestination::DirectBreg { .. } => {
                let action = match scope {
                    HoldGuidanceScope::Aggregate => {
                        "Use inspect on each held item before claiming a destination reference. Resolve any BReg outcome under BReg's own authority. The Adapter keeps held items held; unchanged rescans skip them."
                    }
                    HoldGuidanceScope::Item(Some(_)) => {
                        "Resolve the outcome for destinationReference in BReg under BReg's own authority. The Adapter keeps this item held; unchanged rescans skip it."
                    }
                    HoldGuidanceScope::Item(None) => {
                        "No destination reference is established. Inspect BReg admission and idempotency records, then resolve the outcome under BReg's own authority. The Adapter keeps this item held; unchanged rescans skip it."
                    }
                };
                ("breg", action)
            }
            registry_adapter_core::JobDestination::SignedCoordinatorEvent { .. } => {
                let action = match scope {
                    HoldGuidanceScope::Aggregate => {
                        "Use inspect on each held item before claiming a destination reference. Resolve any Run and linked review under Coordinator's own authority. The Adapter keeps held items held; unchanged rescans skip them."
                    }
                    HoldGuidanceScope::Item(Some(_)) => {
                        "Resolve the Run named by destinationReference and any linked review under Coordinator's own authority. The Adapter keeps this item held; unchanged rescans skip it."
                    }
                    HoldGuidanceScope::Item(None) => {
                        "No destination reference is established. Inspect Coordinator admission and event-idempotency records, then resolve the outcome under Coordinator's own authority. The Adapter keeps this item held; unchanged rescans skip it."
                    }
                };
                ("coordinator", action)
            }
        }
    };
    Some(serde_json::json!({
        "code": code,
        "destinationReference": destination_reference,
        "actionOwner": action_owner,
        "nextAction": next_action,
    }))
}

/// Compile the job the engine compiles.
fn compile(
    pack: &Path,
    job_yaml: &Path,
    runtime: &JobRuntimeConfig,
    resolver: Arc<SecretResolver>,
    workspace: &WorkspaceArgs,
) -> Result<JobProgram, String> {
    let directory = pack.parent().unwrap_or_else(|| Path::new("."));
    let profile = workspace
        .profile
        .clone()
        .unwrap_or_else(|| directory.join("profile.yaml"));
    let project = workspace
        .project
        .clone()
        .unwrap_or_else(|| directory.join("project.yaml"));
    compile_job_with_runtime(pack, job_yaml, runtime, resolver, &profile, &project)
        .map_err(|error| job_error_message(&error))
}

fn require_compiled_hooks(job: &AdapterJob) -> Result<(), &'static str> {
    if job.triggers.iter().any(|trigger| trigger.kind == "hook") && !cfg!(feature = "job-hook") {
        return Err("adapter.job.hook-not-compiled");
    }
    Ok(())
}

fn check_hook_runtime(job: &AdapterJob, runtime: &JobRuntimeConfig) -> Result<(), String> {
    require_compiled_hooks(job).map_err(str::to_string)?;
    #[cfg(feature = "job-hook")]
    {
        registry_adapter_job::hook_ingress::validate_hook_runtime(job, runtime)
            .map_err(|error| error.to_string())
    }
    #[cfg(not(feature = "job-hook"))]
    {
        if runtime.hook_ingress.is_some() {
            return Err("adapter.job.hook-not-compiled".to_string());
        }
        Ok(())
    }
}

/// Install the host clients for the enabled source protocols. HTTP/GraphQL
/// and local files execute directly; other protocols use host-owned clients.
fn activate_sources(
    program: &mut JobProgram,
    resolver: &Arc<SecretResolver>,
) -> Result<(), String> {
    #[cfg(feature = "job-postgres")]
    registry_adapter_job::postgres_source::activate_postgres_sources(program, resolver.as_ref())?;
    #[cfg(feature = "job-rabbitmq")]
    registry_adapter_job::rabbitmq_source::activate_rabbitmq_sources(program, resolver.as_ref())?;
    #[cfg(feature = "job-sftp")]
    registry_adapter_job::sftp_source::activate_sftp_sources(program, Arc::clone(resolver))?;
    #[cfg(not(any(
        feature = "job-postgres",
        feature = "job-sftp",
        feature = "job-rabbitmq"
    )))]
    let _ = (program, resolver);
    Ok(())
}

/// The value-free rendering of a compile refusal: every diagnostic the
/// compiler carried, in the same human form `adapterctl` prints (code, file
/// position, pointer, message, and the next step).
fn job_error_message(error: &JobError) -> String {
    let rendered = error
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.render_human().trim_end().to_string())
        .collect::<Vec<_>>()
        .join("\n");
    format!("the job was refused:\n{rendered}")
}

/// The job's source route edit property, from the compiled program's
/// resolved declaration: the declaration the rescan gate runs on, read
/// at compile so the host never re-reads the pack file.
fn source_edits(program: &JobProgram) -> Result<Edits, String> {
    Edits::of(&program.source_route)
}

/// The job state the schedule reads, from the store row.
/// Read the trigger state. The error is the store's closed, value-free cause
/// token (`sqlstate-57P01`, `connection-closed`, `pool-timeout`).
async fn job_state(pool: &Pool, job: &AdapterJob) -> Result<JobState, String> {
    let client = pool
        .get()
        .await
        .map_err(|error| store::pool_cause(&error))?;
    let row = store::read_state(&client, job.job.id.as_str())
        .await
        .map_err(|error| error.cause())?
        .unwrap_or_default();
    Ok(trigger_state(&row))
}

/// The loop's stderr line for a job store it could not read.
fn store_unreachable_line(cause: &str, retry: Duration) -> String {
    format!(
        "adapter.job.store-unreachable cause={cause}: the loop could not read the job state and retries in {} ms; next: check that the store connection reaches PostgreSQL and that the job role can read adapter_job_state (run init-store if the schema is missing)",
        retry.as_millis()
    )
}

fn trigger_state(row: &store::JobStateRow) -> JobState {
    JobState {
        position: row.position.clone(),
        projection_digest: row.projection_digest.clone(),
        lease_expires: row.lease_expires,
        last_pass_at: row.last_pass_at,
        last_pass_stop: row.last_pass_stop.clone(),
        last_rescan_at: row.last_rescan_at,
        rescan_active: row.rescan_active,
        idle_streak: u32::try_from(row.idle_streak.max(0)).unwrap_or(u32::MAX),
        error_streak: u32::try_from(row.error_streak.max(0)).unwrap_or(u32::MAX),
    }
}

/// Open the job store: one pool from the store block's connection
/// reference, migrated before it serves.
async fn open_pool(runtime: &JobRuntimeConfig, resolver: &SecretResolver) -> Result<Pool, String> {
    let store_config = runtime_store(runtime)?;
    let pool = store::build_pool(store_config, resolver).map_err(|error| error.to_string())?;
    let client = pool
        .get()
        .await
        .map_err(|error| format!("the job store migration could not connect: {error}"))?;
    store::migrate(&client)
        .await
        .map_err(|error| format!("the job store migration failed: {error}"))?;
    Ok(pool)
}

/// The pool a pass or rescan runs on: migrated before it serves, or,
/// for a dry run, read-only and refused unless the store already holds
/// this release's schema, so a preview never changes the database.
async fn pass_pool(
    runtime: &JobRuntimeConfig,
    resolver: &SecretResolver,
    dry_run: bool,
) -> Result<Pool, String> {
    if !dry_run {
        return open_pool(runtime, resolver).await;
    }
    let recovery = "run adapter-job init-store --runtime <runtime-config>";
    let pool = read_pool(runtime, resolver)?;
    let client = pool
        .get()
        .await
        .map_err(|error| format!("the job store could not be reached: {error}"))?;
    match store::schema_current(&client).await {
        Ok(()) => {}
        Err(error @ store::StoreError::SchemaBehind { .. }) => {
            return Err(format!("the dry run refused: {error}; {recovery}"))
        }
        Err(error) => return Err(format!("the dry run refused: {error}")),
    }
    drop(client);
    Ok(pool)
}

/// Keep observational commands read-only while giving an uninitialized or
/// older store one explicit recovery command. A newer store is incompatible
/// with this release and retains its own refusal without migration advice.
async fn require_current_schema(
    client: &impl deadpool_postgres::GenericClient,
    operation: &str,
) -> Result<(), String> {
    match store::schema_current(client).await {
        Ok(()) => Ok(()),
        Err(error @ store::StoreError::SchemaBehind { .. }) => Err(format!(
            "the {operation} refused: {error}; run adapter-job init-store --runtime <runtime-config>"
        )),
        Err(error) => Err(format!("the {operation} refused: {error}")),
    }
}

/// The read-only pool of the status and inspect surfaces, from the
/// runtime config's store block.
fn read_pool(runtime: &JobRuntimeConfig, resolver: &SecretResolver) -> Result<Pool, String> {
    let store_config = runtime_store(runtime)?;
    store::build_pool(store_config, resolver).map_err(|error| error.to_string())
}

fn runtime_secret_resolver(runtime: &JobRuntimeConfig) -> Result<Arc<SecretResolver>, String> {
    runtime
        .secret_resolver()
        .map(Arc::new)
        .map_err(|_| "the secret resolver could not start".to_string())
}

/// Read the job definition: the engine boundary's public artifact
/// read, the same envelope, expression, and unknown-key discipline the
/// compile path reads the job through.
fn read_job(path: &Path) -> Result<AdapterJob, String> {
    registry_adapter_engine::load::read_artifact::<AdapterJob>(
        path,
        registry_adapter_core::ADAPTER_JOB_KIND,
        registry_adapter_core::ADAPTER_JOB_API_VERSION,
    )
    .map(|(job, _bytes)| job)
    .map_err(|error| format!("the job definition was refused: {error}"))
}

/// Read the job store block of the operator runtime config through the
/// one reader the compile path shares (`engine::job_sources`), which
/// refuses an undeclared member of the block like any other.
fn load_runtime(path: &Path) -> Result<JobRuntimeConfig, String> {
    JobRuntimeConfig::load(path).map_err(|error| {
        let mut message = format!("the runtime config was refused: {error}");
        if let Some(hint) = JobRuntimeConfig::facade_kind_hint(path, &error) {
            message.push_str("\nhint: ");
            message.push_str(&hint);
        }
        message
    })
}

fn runtime_store(runtime: &JobRuntimeConfig) -> Result<&store::JobStoreConfig, String> {
    runtime
        .store
        .as_ref()
        .ok_or_else(|| "the runtime config carries no store block for the job store".to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use registry_adapter_job::store::ItemStatus;
    use std::time::UNIX_EPOCH;

    fn example_job(file: &str) -> AdapterJob {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        read_job(
            &root
                .join("products/adapter/examples/kobotoolbox-job")
                .join(file),
        )
        .expect("the maintained example job reads")
    }

    #[test]
    fn a_refused_job_definition_names_the_member_and_the_fix() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let source = std::fs::read_to_string(
            root.join("products/adapter/examples/kobotoolbox-job/job.yaml"),
        )
        .expect("the maintained example job reads");
        let refused = source.replacen(
            "  id: kobotoolbox-submissions-example\n",
            "  id: kobotoolbox-submissions-example\n  owner: ops\n",
            1,
        );
        assert_ne!(refused, source, "the fixture edit applied");
        let directory = tempfile::tempdir().expect("a scratch directory");
        let path = directory.path().join("job.yaml");
        std::fs::write(&path, refused).expect("write the job");

        let message = read_job(&path).expect_err("an undeclared member refuses");
        assert!(
            message.contains("/job/owner"),
            "names the member: {message}"
        );
        assert!(
            message.to_lowercase().contains("remove"),
            "names the fix: {message}"
        );
    }

    #[test]
    fn a_preview_reports_no_acknowledged_items() {
        let report = PassReport {
            items_acknowledged: 3,
            ..PassReport::default()
        };
        assert_eq!(acknowledged_count(&report, true), 0);
        assert_eq!(acknowledged_count(&report, false), 3);
    }

    #[test]
    fn body_drift_and_the_identity_fence_each_carry_a_next_step() {
        let drift = StopReason::DestinationStop {
            code: registry_adapter_job::pass::COORDINATOR_BODY_CHANGED.to_owned(),
        };
        let next = stop_next_step(&drift).expect("body drift names its recovery");
        assert!(
            next.contains("Restore the previous job definition"),
            "{next}"
        );
        assert_eq!(
            next_step_for_stop_text("destination-stop:adapter.job.coordinator-body-changed"),
            Some(next),
            "status repeats the pass's next step from the recorded text"
        );
        assert_eq!(next_step_for_stop_text("lease-held"), None);
    }

    #[test]
    fn an_unrecorded_delivery_identity_names_the_settle_first_recovery() {
        let stop = StopReason::DestinationStop {
            code: registry_adapter_job::pass::COORDINATOR_IDENTITY_UNRECORDED.to_owned(),
        };
        let next = stop_next_step(&stop).expect("an unrecorded identity names its recovery");
        for step in [
            "schema 103",
            "backup",
            "previous binary",
            "status",
            "init-store",
        ] {
            assert!(next.contains(step), "missing {step:?}: {next}");
        }
        assert_eq!(
            next_step_for_stop_text("destination-stop:adapter.job.coordinator-identity-unrecorded"),
            Some(next)
        );
    }

    #[test]
    fn an_unreadable_store_line_names_the_cause_the_retry_and_the_fix() {
        let line = store_unreachable_line("sqlstate-57P01", Duration::from_millis(3000));
        assert!(
            line.starts_with("adapter.job.store-unreachable cause=sqlstate-57P01:"),
            "{line}"
        );
        assert!(line.contains("retries in 3000 ms"), "{line}");
        assert!(
            line.contains("next: check that the store connection"),
            "{line}"
        );
    }

    #[test]
    fn a_job_refusal_prints_the_next_step_and_no_empty_pointer() {
        let error = JobError {
            diagnostics: vec![registry_platform_yaml::Diagnostic::error(
                "config.missing-key",
                "",
                "the required member `destination` is missing",
                "Add `destination`.",
            )],
        };
        let message = job_error_message(&error);
        assert!(message.starts_with("the job was refused:\n"), "{message}");
        assert!(message.contains("config.missing-key"), "{message}");
        assert!(message.contains("next: Add `destination`."), "{message}");
        assert!(!message.contains("  at  "), "{message}");
    }

    #[test]
    fn hook_jobs_require_the_explicit_host_feature() {
        let mut job = example_job("job.yaml");
        job.triggers.push(
            serde_json::from_value(serde_json::json!({
                "kind": "hook",
                "path": "/hooks/kobo",
                "binding": "kobo"
            }))
            .expect("a hook trigger"),
        );

        #[cfg(feature = "job-hook")]
        assert_eq!(require_compiled_hooks(&job), Ok(()));
        #[cfg(not(feature = "job-hook"))]
        assert_eq!(
            require_compiled_hooks(&job),
            Err("adapter.job.hook-not-compiled")
        );
    }

    #[test]
    fn fresh_status_is_not_overdue_while_the_scheduler_remains_due_now() {
        let job = example_job("job.yaml");
        let row = store::JobStateRow::default();
        let now = UNIX_EPOCH + Duration::from_secs(10_000);

        assert!(
            !status_overdue(&job, &row, now),
            "a never-run job is due now, not overdue"
        );
        assert_eq!(
            trigger::next_due(&job, &trigger_state(&row), now, now),
            Some(Duration::ZERO),
            "the loop still starts the default zero-initial-delay job immediately"
        );
    }

    #[test]
    fn status_reports_an_existing_late_job_overdue() {
        let job = example_job("job.yaml");
        let now = UNIX_EPOCH + Duration::from_secs(10_000);
        let row = store::JobStateRow {
            last_pass_at: Some(now - Duration::from_secs(61)),
            ..store::JobStateRow::default()
        };

        assert!(
            status_overdue(&job, &row, now),
            "an existing job past its sixty-second interval is overdue"
        );
    }

    #[test]
    fn every_current_hold_code_has_value_free_destination_guidance() {
        let direct = example_job("job.yaml");
        let coordinator = example_job("job.coordinator.yaml");
        let cases = [
            (
                &direct.destination,
                "adapter.job.revised-item",
                "proposal-revised",
                "breg",
            ),
            (
                &direct.destination,
                "adapter.job.breg-receipt-horizon",
                "proposal-horizon",
                "breg",
            ),
            (
                &direct.destination,
                "idempotency.key-reused",
                "proposal-reused",
                "breg",
            ),
            (
                &direct.destination,
                "idempotency.expired",
                "proposal-expired",
                "breg",
            ),
            (
                &coordinator.destination,
                "adapter.job.revised-item",
                "run-revised",
                "coordinator",
            ),
            (
                &coordinator.destination,
                "coordinator.event.start-conflict",
                "run-conflict",
                "coordinator",
            ),
            (
                &direct.destination,
                "adapter.job.rabbitmq-event-changed",
                "message-reference",
                "broker-operator",
            ),
        ];

        for (destination, code, reference, owner) in cases {
            let guidance = hold_guidance(
                destination,
                ItemStatus::Held,
                Some(code),
                HoldGuidanceScope::Item(Some(reference)),
            )
            .unwrap_or_else(|| panic!("{code} has hold guidance"));
            assert_eq!(guidance["code"], code);
            assert_eq!(guidance["destinationReference"], reference);
            assert_eq!(guidance["actionOwner"], owner);
            let action = guidance["nextAction"]
                .as_str()
                .filter(|action| !action.is_empty())
                .unwrap_or_else(|| panic!("{code} names an operator action"));
            if code == "adapter.job.rabbitmq-event-changed" {
                assert!(action.contains("destination's own authority"));
                assert!(action.contains("under approved broker policy"));
                assert!(action.contains("publisher/source operator"));
                assert!(action.contains("legitimate future work"));
                assert!(action.contains("Do not rekey uncertain or already accepted work"));
                assert!(action.contains("Publishing a new message ID alone does not clear"));
                assert!(action.contains("Adapter keeps the row held"));
                assert!(action.contains("does not acknowledge or release it"));
                assert!(action.contains("can block later messages at the queue head"));
                assert!(!action.contains("remains head-blocking"));
            } else {
                assert!(action.contains("own authority"));
                assert!(action.contains("keeps this item held"));
                assert!(action.contains("unchanged rescans skip it"));
                assert!(!action.contains("retry"));
            }
            assert_eq!(
                guidance.as_object().expect("guidance is an object").len(),
                4,
                "guidance carries only code, reference, owner, and a static action"
            );
        }

        assert!(
            hold_guidance(
                &direct.destination,
                ItemStatus::Acknowledged,
                None,
                HoldGuidanceScope::Item(None),
            )
            .is_none(),
            "settled non-held items gain no recovery instruction"
        );
    }

    #[test]
    fn aggregate_and_reference_free_holds_state_what_the_operator_knows() {
        let direct = example_job("job.yaml");
        let coordinator = example_job("job.coordinator.yaml");
        for (destination, code, authority, records) in [
            (
                &direct.destination,
                "idempotency.expired",
                "BReg's own authority",
                "BReg admission and idempotency records",
            ),
            (
                &coordinator.destination,
                "coordinator.event.start-conflict",
                "Coordinator's own authority",
                "Coordinator admission and event-idempotency records",
            ),
        ] {
            let aggregate = hold_guidance(
                destination,
                ItemStatus::Held,
                Some(code),
                HoldGuidanceScope::Aggregate,
            )
            .expect("aggregate status has guidance");
            assert_eq!(aggregate["destinationReference"], serde_json::Value::Null);
            let aggregate_action = aggregate["nextAction"]
                .as_str()
                .expect("aggregate status names an action");
            assert!(aggregate_action.contains("Use inspect on each held item"));
            assert!(aggregate_action.contains(authority));
            assert!(aggregate_action.contains("keeps held items held"));
            assert!(aggregate_action.contains("unchanged rescans skip them"));
            assert!(!aggregate_action.contains("referenced"));
            assert!(!aggregate_action.contains("retry"));

            let without_reference = hold_guidance(
                destination,
                ItemStatus::Held,
                Some(code),
                HoldGuidanceScope::Item(None),
            )
            .expect("the held item has guidance");
            assert_eq!(
                without_reference["destinationReference"],
                serde_json::Value::Null
            );
            let item_action = without_reference["nextAction"]
                .as_str()
                .expect("the held item names an action");
            assert!(item_action.contains("No destination reference is established"));
            assert!(item_action.contains(records));
            assert!(item_action.contains(authority));
            assert!(item_action.contains("keeps this item held"));
            assert!(item_action.contains("unchanged rescans skip it"));
            assert!(!item_action.contains("retry"));
        }
    }

    #[test]
    fn hold_guidance_never_carries_an_item_value_or_a_mutation() {
        let direct = example_job("job.yaml");
        let guidance = hold_guidance(
            &direct.destination,
            ItemStatus::Held,
            Some("idempotency.key-reused"),
            HoldGuidanceScope::Item(Some("proposal-a")),
        )
        .expect("the held item has guidance");
        let rendered = serde_json::to_string(&guidance).expect("guidance renders");

        assert!(!rendered.contains("never-project-this-source-value"));
        assert!(!rendered.contains("mark-accepted"));
        assert!(!rendered.contains("reconcile"));
    }
}
