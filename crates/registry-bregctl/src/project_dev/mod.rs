// SPDX-License-Identifier: Apache-2.0
//! The private runner behind the rstack launcher. The bootstrap binary does
//! not link the database, HTTP server, or signing libraries.

mod bindings;
mod database;
mod issuer;
mod journey;
pub(crate) mod plan;
mod products;

use anyhow::{bail, ensure, Context, Result};
use registry_platform_yaml::{Diagnostic, Report};
use rustix::fs::{flock, FlockOperation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use zeroize::Zeroizing;

use self::{
    database::Database,
    issuer::Issuer,
    plan::{Plan, Product},
    products::{ProductRunner, SchemaPerson},
};

const SCHEMA: &str = "registry.rstack.dev.v1";
const REQUEST: &str = "RSTACK_PROJECT_DEV_REQUEST";
const DATABASE_URL: &str = "RSTACK_DEV_DATABASE_URL";
const CA_FILE: &str = "RSTACK_DEV_DATABASE_CA";
const REPORT: &str = "report.json";
const PENDING: &str = "cleanup-pending.json";
const CLEANUP_CAP: Duration = Duration::from_secs(30 * 60);
const POLL: Duration = Duration::from_millis(100);
// A capture can contain the 1 MiB development plan after JSON escaping,
// selections derived from a second 1 MiB journeys document, facts selected
// from the bounded 4 MiB Casework authoring report, and the remaining paths
// and authority metadata. Keep headroom for those representations while
// retaining one hard bound for both writing and restoring the private input.
const MAXIMUM_CAPTURED_INPUT_BYTES: u64 =
    16 * registry_platform_yaml::MAXIMUM_DOCUMENT_BYTES as u64;
const MAXIMUM_RUN_REPORT_BYTES: u64 = 512 * 1024;

#[derive(clap::Args, Debug)]
pub(crate) struct Args {
    #[arg(long, hide = true)]
    worker: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Check {
        project: PathBuf,
        deny_warnings: bool,
        json: bool,
    },
    Start {
        project: PathBuf,
        ttl: Option<String>,
        json: bool,
    },
    Status {
        run_id: String,
        json: bool,
    },
    Token {
        run_id: String,
        person: String,
        json: bool,
    },
    Stop {
        run_id: String,
        json: bool,
    },
}

impl Request {
    fn json(&self) -> bool {
        match self {
            Self::Check { json, .. }
            | Self::Start { json, .. }
            | Self::Status { json, .. }
            | Self::Token { json, .. }
            | Self::Stop { json, .. } => *json,
        }
    }
}

#[derive(Deserialize, Serialize)]
struct RunInput {
    run_id: String,
    project: PathBuf,
    plan: Plan,
    ttl_seconds: u64,
    schema_people: Vec<SchemaPerson>,
    breg_authority: Option<BregAuthority>,
    casework_principals: BTreeMap<String, String>,
    binaries: BTreeMap<Product, Binaries>,
}

#[derive(Deserialize, Serialize)]
struct BregAuthority {
    principal: String,
    purpose: bool,
    requires_postgis: bool,
    named_clients: BTreeSet<String>,
}

#[derive(Deserialize, Serialize)]
struct Binaries {
    tool: PathBuf,
    runtime: PathBuf,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum WorkerReply {
    Ready { report: Value },
    Failed { error: String },
}

#[derive(Debug, thiserror::Error)]
#[error("run {run_id} still needs cleanup: {detail}")]
struct CleanupPending {
    run_id: String,
    detail: String,
}

/// A run that cannot finish by itself: its supervisor is gone, or cleanup
/// gave up. `facts` carries what an operator needs to release it by hand.
#[derive(Debug, thiserror::Error)]
#[error("{}", recovery_message(run_id, facts))]
struct RecoveryNeeded {
    run_id: String,
    facts: Value,
}

fn recovery_message(run_id: &str, facts: &Value) -> String {
    let mut text = match facts["kind"].as_str() {
        Some("cleanup-pending") => {
            format!("run {run_id} gave up cleanup; release these resources by hand")
        }
        _ => format!(
            "run {run_id} lost its supervisor before cleanup; release these resources by hand"
        ),
    };
    let mut line = |entry: String| {
        text.push_str("\n  ");
        text.push_str(&entry);
    };
    if let Some(directory) = facts["run_directory"].as_str() {
        line(format!("run directory {directory}"));
    }
    for process in facts["processes"].as_array().into_iter().flatten() {
        line(format!(
            "process {} pid {} pgid {}",
            process["product"], process["pid"], process["pgid"]
        ));
    }
    for object in facts["objects"].as_array().into_iter().flatten() {
        let roles: Vec<_> = object["roles"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        line(format!(
            "{} database {} roles {}",
            object["label"].as_str().unwrap_or("?"),
            object["database"].as_str().unwrap_or("?"),
            roles.join(", ")
        ));
    }
    for name in facts["databases_and_roles"]
        .as_array()
        .into_iter()
        .flatten()
    {
        line(format!("database or role {}", name.as_str().unwrap_or("?")));
    }
    if let Some(reason) = facts["unavailable"].as_str() {
        line(format!("some facts are unavailable: {reason}"));
    }
    text
}

/// Everything a lost supervisor leaves behind: the processes it recorded and
/// every database and role its plan provisions.
fn lost_supervisor_facts(root: &Path, run_id: &str) -> Value {
    let mut facts = json!({
        "kind": "lost-supervisor",
        "run_directory": root,
        "processes": recorded_processes(root),
        "objects": [],
    });
    match provisioned_objects(root, run_id) {
        Ok(objects) => facts["objects"] = json!(objects),
        Err(error) => facts["unavailable"] = json!(format!("{error:#}")),
    }
    facts
}

fn recorded_processes(root: &Path) -> Value {
    read_json::<Value>(&root.join("processes.json"), MAXIMUM_RUN_REPORT_BYTES)
        .ok()
        .filter(Value::is_array)
        .unwrap_or_else(|| json!([]))
}

fn provisioned_objects(root: &Path, run_id: &str) -> Result<Vec<Value>> {
    let input: RunInput = read_json(&root.join("input.json"), MAXIMUM_CAPTURED_INPUT_BYTES)
        .context("cannot read the captured development plan")?;
    let spatial = input
        .breg_authority
        .as_ref()
        .is_some_and(|authority| authority.requires_postgis);
    let mut labels = Vec::new();
    for entry in &input.plan.products {
        match entry.product {
            Product::Breg => {
                labels.push(("breg_test", spatial));
                labels.push(("breg", spatial));
            }
            Product::Casework => labels.push(("casework", false)),
        }
    }
    labels
        .into_iter()
        .map(|(label, spatial)| {
            let mut names = database::run_object_names(run_id, label, spatial)?;
            let database = names.pop().context("run has no database name")?;
            Ok(json!({"label": label, "database": database, "roles": names}))
        })
        .collect()
}

fn pending_report(run_id: &str, names: Vec<String>, processes: Value) -> Value {
    json!({"run_id": run_id, "databases_and_roles": names, "processes": processes})
}

/// The delays between cleanup attempts: 2 s doubling to 30 s, until their
/// sum reaches the cap.
fn cleanup_schedule(cap: Duration) -> impl Iterator<Item = Duration> {
    let mut next = Duration::from_secs(2);
    let mut total = Duration::ZERO;
    std::iter::from_fn(move || {
        if total >= cap {
            return None;
        }
        let delay = next;
        total += delay;
        next = (next * 2).min(Duration::from_secs(30));
        Some(delay)
    })
}

/// The wall clock decides expiry, because the monotonic clock stops while a
/// laptop sleeps.
fn expired(now_unix: u64, expires_at: u64) -> bool {
    now_unix >= expires_at
}

fn startup_error(root: &Path, run_id: &str, error: anyhow::Error) -> anyhow::Error {
    if root.exists() {
        CleanupPending {
            run_id: run_id.to_owned(),
            detail: format!("{error:#}"),
        }
        .into()
    } else {
        error
    }
}

pub(crate) fn run(args: Args, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    if let Some(root) = args.worker {
        // The CLI panic hook exits immediately. In the supervisor, unwind so
        // its startup boundary can release the run without exposing payloads.
        std::panic::set_hook(Box::new(|_| {}));
        return match worker(&root, stdout) {
            Ok(()) => 0,
            Err(error) => {
                let _ = reply(
                    stdout,
                    &WorkerReply::Failed {
                        error: format!("{error:#}"),
                    },
                );
                3
            }
        };
    }
    let request = env::var(REQUEST)
        .ok()
        .and_then(|text| serde_json::from_str::<Request>(&text).ok());
    let Some(request) = request else {
        let _ = writeln!(
            stderr,
            "run project development commands through rstack dev"
        );
        return 2;
    };
    let machine = request.json();
    let starting = matches!(&request, Request::Start { .. });
    let outcome = match request {
        Request::Check {
            project,
            deny_warnings,
            ..
        } => return check(&project, deny_warnings, machine, stdout, stderr),
        Request::Start { project, ttl, .. } => start(&project, ttl.as_deref()),
        Request::Status { run_id, .. } => status(&run_id),
        Request::Token { run_id, person, .. } => token(&run_id, &person),
        Request::Stop { run_id, .. } => stop(&run_id),
    };
    let (result, code) = match outcome {
        Ok(value) => {
            let code = u8::from(starting && value["journey"]["result"] == "failed");
            (emit(stdout, &value, machine), code)
        }
        Err(error) if machine => {
            let mut report = json!({
                "schema_version": SCHEMA, "status": "error", "error": format!("{error:#}")
            });
            if let Some(pending) = error.downcast_ref::<CleanupPending>() {
                report["run_id"] = json!(pending.run_id);
                report["cleanup_pending"] = json!(true);
            }
            if let Some(recovery) = error.downcast_ref::<RecoveryNeeded>() {
                report["run_id"] = json!(recovery.run_id);
                report["recovery"] = recovery.facts.clone();
            }
            (writeln!(stdout, "{report}"), 1)
        }
        Err(error) => (writeln!(stderr, "rstack dev: {error:#}"), 1),
    };
    if result.is_ok() {
        code
    } else {
        3
    }
}

fn emit(output: &mut dyn Write, report: &Value, machine: bool) -> std::io::Result<()> {
    if machine {
        return writeln!(output, "{report}");
    }
    let run = report["run_id"].as_str().expect("run report");
    let status = report["status"].as_str().expect("run status");
    writeln!(output, "Run {run} {status}")?;
    if status == "cleanup-pending" {
        let message = recovery_message(run, &report["recovery"]);
        for line in message.lines().skip(1) {
            writeln!(output, "{line}")?;
        }
    }
    if let Some(products) = report["products"].as_object() {
        for (product, url) in products {
            writeln!(output, "  {product} {}", url.as_str().expect("product URL"))?;
        }
    }
    if let Some(result) = report["journey"]["result"].as_str() {
        writeln!(
            output,
            "  Journey {} {result}",
            report["journey"]["id"].as_str().expect("journey ID")
        )?;
        if let Some(steps) = report["journey"]["steps"].as_array() {
            for step in steps.iter().filter(|step| step["result"] == "failed") {
                writeln!(
                    output,
                    "    {} expected HTTP {}, observed {}",
                    step["id"], step["expected_status"], step["status"]
                )?;
                if let Some(reason) = step["reason"].as_str() {
                    writeln!(output, "      {reason}")?;
                }
            }
        }
    }
    if let Some(logs) = report["logs"].as_str() {
        writeln!(output, "  Logs {logs}")?;
    }
    if let Some(people) = report["people"].as_array() {
        for name in people {
            writeln!(
                output,
                "  rstack dev token {run} --as {}",
                name.as_str().expect("person name")
            )?;
        }
    }
    if let Some(credentials) = report["credentials"].as_array() {
        for credential in credentials {
            writeln!(
                output,
                "  {} headers {}",
                credential["product"].as_str().expect("product"),
                credential["header_file"].as_str().expect("header path")
            )?;
        }
    }
    Ok(())
}

fn check(
    project: &Path,
    deny_warnings: bool,
    machine: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let outcome = project
        .canonicalize()
        .context("cannot open the development project directory")
        .and_then(|project| plan::check(&project));
    let (report, exit) = match outcome {
        Ok(report) => {
            let refused = report.has_errors() || (deny_warnings && report.warning_count() > 0);
            (report, u8::from(refused))
        }
        Err(error) => match error.downcast::<Report>() {
            Ok(report) => (report, crate::DOMAIN_REFUSAL_EXIT),
            Err(error) => {
                if let Some(unavailable) = error.downcast_ref::<products::InspectionUnavailable>() {
                    let report = Report::new(vec![Diagnostic::error(
                        "breg.project-dev.check-unavailable",
                        unavailable.field(),
                        unavailable.reason(),
                        unavailable.remedy(),
                    )]);
                    return write_check_report(
                        report,
                        crate::OPERATIONAL_FAILURE_EXIT,
                        machine,
                        stdout,
                        stderr,
                    );
                }
                let (code, action, exit) = if error.is::<io::Error>() {
                    (
                        "breg.project-dev.check-unavailable",
                        "Name a project directory containing a readable dev.yaml.",
                        crate::OPERATIONAL_FAILURE_EXIT,
                    )
                } else {
                    (
                        "breg.project-dev.invalid-plan",
                        "Correct the development plan at the reported field.",
                        crate::DOMAIN_REFUSAL_EXIT,
                    )
                };
                (
                    Report::new(vec![Diagnostic::error(code, "", error.to_string(), action)]),
                    exit,
                )
            }
        },
    };
    write_check_report(report, exit, machine, stdout, stderr)
}

fn write_check_report(
    report: Report,
    exit: u8,
    machine: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let result = if machine {
        let payload = json!({
            "ok": exit == 0,
            "command": "dev-check",
            "status": registry_cli_report::Status::from_exit(exit).as_str(),
            "diagnostics": report.to_json_value(),
        });
        crate::write_ctl_report(stdout, &payload)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else if exit == 0 {
        writeln!(stdout, "Development plan is valid")
            .and_then(|()| write!(stdout, "{}", report.render_human()))
    } else {
        write!(stderr, "{}", report.render_human())
    };
    if result.is_ok() {
        exit
    } else {
        let _ = writeln!(stderr, "rstack dev check: output could not be written");
        crate::OPERATIONAL_FAILURE_EXIT
    }
}

fn start(project: &Path, ttl: Option<&str>) -> Result<Value> {
    let project = project
        .canonicalize()
        .context("cannot open the development project directory")?;
    let plan = plan::load(&project)?;
    let schema_people = products::schema_people(&project, &plan, true)?;
    let signals = signals()?;
    let inspection = products::inspect(&project, &plan, &signals)?;
    let ttl_seconds = parse_ttl(ttl.unwrap_or("30m"))?;
    ensure!(
        env::var_os(DATABASE_URL).is_some_and(|value| !value.is_empty()),
        "supply --database-url or {DATABASE_URL} for a TLS PostgreSQL development server"
    );
    let binaries = plan
        .products
        .iter()
        .map(|entry| Ok((entry.product, binaries(entry.product)?)))
        .collect::<Result<_>>()?;
    let run_id = Uuid::new_v4().simple().to_string();
    let base = state_dir();
    ensure_private(&base, true)?;
    let root = base.canonicalize()?.join(&run_id);
    private_directory(&root)?;
    let input = RunInput {
        run_id,
        project,
        plan,
        ttl_seconds,
        schema_people,
        breg_authority: inspection.breg_authority,
        casework_principals: inspection.casework_principals,
        binaries,
    };
    let preparation = (|| {
        write_private(&root.join("input.json"), &capture_input(&input)?)?;
        let supervisor_log = open_supervisor_log(&root)?;
        Command::new(env::current_exe()?)
            .arg("project-dev")
            .arg("--worker")
            .arg(&root)
            .env_remove(REQUEST)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(supervisor_log))
            .spawn()
            .context("cannot start the development run supervisor")
    })();
    let mut child = match preparation {
        Ok(child) => child,
        Err(error) => {
            let kept = remove_failed_run(&root, &input.run_id)
                .context("cannot remove unstarted run directory")?;
            return Err(note_kept_logs(error, kept));
        }
    };
    let stream = child.stdout.take().expect("startup channel");
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stream)
            .take(MAXIMUM_RUN_REPORT_BYTES)
            .read_line(&mut line)
            .context("cannot read startup report")
            .and_then(|_| {
                serde_json::from_str::<WorkerReply>(&line)
                    .context("missing or invalid startup report")
            });
        let _ = sender.send(result);
    });
    let deadline = Instant::now() + Duration::from_secs(360);
    loop {
        match receiver.recv_timeout(POLL) {
            Ok(Ok(WorkerReply::Ready { report })) => return Ok(report),
            Ok(Ok(WorkerReply::Failed { error })) => {
                let error = anyhow::anyhow!(error);
                let kept_logs = failed_logs_dir(&base, &input.run_id);
                if root.join("worker.lock").exists() {
                    if let Err(cleanup) = stop(&input.run_id) {
                        return Err(startup_error(
                            &root,
                            &input.run_id,
                            error.context(format!(
                                "automatic cleanup could not finish: {cleanup:#}"
                            )),
                        ));
                    }
                } else if root.exists() {
                    remove_failed_run(&root, &input.run_id)
                        .context("cannot remove unstarted run directory")?;
                }
                return Err(note_kept_logs(
                    error,
                    kept_logs.exists().then_some(kept_logs),
                ));
            }
            Ok(Err(error)) => {
                if child.try_wait()?.is_some()
                    && root.exists()
                    && !root.join("worker.lock").exists()
                {
                    remove_failed_run(&root, &input.run_id)
                        .context("cannot remove unstarted run directory")?;
                }
                return Err(startup_error(&root, &input.run_id, error));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(startup_error(
                    &root,
                    &input.run_id,
                    anyhow::anyhow!("the supervisor lost its startup report"),
                ));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if signals.load(Ordering::Relaxed) || Instant::now() >= deadline {
            stop(&input.run_id).map_err(|error| startup_error(&root, &input.run_id, error))?;
            bail!("development run start was interrupted or timed out");
        }
    }
}

fn worker(root: &Path, output: &mut dyn Write) -> Result<()> {
    let name = root
        .file_name()
        .and_then(|value| value.to_str())
        .context("invalid worker run directory")?;
    let expected = run_dir(name)?;
    ensure!(
        expected.canonicalize()? == root,
        "worker run directory differs from the allocated run"
    );
    ensure_private(root, false)?;
    let input = Arc::new(
        read_json::<RunInput>(&root.join("input.json"), MAXIMUM_CAPTURED_INPUT_BYTES)
            .context("cannot restore the captured development plan")?,
    );
    ensure!(
        input.run_id == name,
        "captured development plan has a different run ID"
    );
    let signals = signals()?;
    let mut products = ProductRunner::new(input.clone(), root, &signals)?;
    let lock = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("worker.lock"))?;
    flock(&lock, FlockOperation::LockExclusive)?;
    let mut database = None;
    let mut expiry = None;
    let prepared = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        products.check()?;
        let ca = env::var_os(CA_FILE)
            .map(|path| {
                let bytes = plan::read(Path::new(&path), 1024 * 1024)
                    .context("cannot read the PostgreSQL CA file")?;
                write_private(&root.join("postgres-ca"), &bytes)?;
                Ok::<_, anyhow::Error>(bytes)
            })
            .transpose()?;
        let admin = Zeroizing::new(
            env::var(DATABASE_URL)
                .map_err(|_| anyhow::anyhow!("missing PostgreSQL administrator URL"))?,
        );
        let issuer = Arc::new(Issuer::create(root)?);
        let database = database.insert(Database::connect(&admin, ca.as_deref(), &input.run_id)?);
        let urls = products.start(database, issuer.clone())?;
        let journey = products.journey(&issuer, &urls)?;
        ensure!(
            products.services_alive()?,
            "a product exited during the journey"
        );
        let expires_at = clock()? + input.ttl_seconds;
        expiry = Some(expires_at);
        let report = json!({
            "schema_version": SCHEMA, "run_id": input.run_id, "status": "ready",
            "products": urls, "people": input.plan.people.keys().collect::<Vec<_>>(),
            "journey": journey, "expires_at": expires_at, "logs": root.join("logs"),
        });
        write_private(&root.join(REPORT), &capture_report(&report)?)?;
        Ok::<_, anyhow::Error>(report)
    }))
    .unwrap_or_else(|_| Err(anyhow::anyhow!("development run startup failed internally")));

    let mut failure = None;
    match prepared {
        Ok(report) => {
            if let Err(error) = reply(output, &WorkerReply::Ready { report }) {
                failure = Some(format!("cannot report development run readiness: {error}"));
            } else {
                let deadline = Instant::now() + Duration::from_secs(input.ttl_seconds);
                while Instant::now() < deadline
                    && !stopping(root, &signals)
                    && !expiry.is_some_and(|at| clock().map_or(true, |now| expired(now, at)))
                {
                    if !products.services_alive().unwrap_or(false) {
                        break;
                    }
                    thread::sleep(POLL);
                }
            }
        }
        Err(error) => failure = Some(format!("{error:#}")),
    }
    let stopped = simple_report(&input.run_id, "stopping");
    let mark_stopping = write_private(&root.join(REPORT), &serde_json::to_vec(&stopped)?);
    let mut told_parent = false;
    let mut delays = cleanup_schedule(CLEANUP_CAP);
    loop {
        // Keep the exact ownership list until both the supervised processes
        // and their database resources have been released.
        let cleanup = products
            .stop()
            .and_then(|()| database.as_mut().map_or(Ok(()), Database::cleanup));
        if cleanup.is_ok() {
            break;
        }
        if let Some(error) = failure.as_ref().filter(|_| !told_parent) {
            let _ = reply(
                output,
                &WorkerReply::Failed {
                    error: error.clone(),
                },
            );
            told_parent = true;
        }
        let Some(delay) = delays.next() else {
            let names = database
                .as_ref()
                .map_or_else(Vec::new, Database::pending_names);
            let pending = pending_report(&input.run_id, names, recorded_processes(root));
            write_private(&root.join(PENDING), &serde_json::to_vec(&pending)?)?;
            bail!(
                "run {} gave up cleanup after {} minutes; run rstack dev status {} for the resources to release",
                input.run_id,
                CLEANUP_CAP.as_secs() / 60,
                input.run_id
            );
        };
        thread::sleep(delay);
    }
    // A failed run keeps its logs outside the run directory.
    let removed = if failure.is_some() {
        keep_logs(root, &input.run_id).map(drop)
    } else {
        Ok(())
    }
    .and_then(|()| remove_run_dir(root));
    if let Some(error) = failure.filter(|_| !told_parent) {
        let error = match removed.as_ref() {
            Ok(()) => error,
            Err(cleanup) => format!("{error}; run {} {cleanup}", input.run_id),
        };
        reply(output, &WorkerReply::Failed { error })?;
    }
    removed?;
    // If the root is gone, no stale ready report could have survived.
    mark_stopping?;
    Ok(())
}

fn reply(output: &mut dyn Write, message: &WorkerReply) -> Result<()> {
    serde_json::to_writer(&mut *output, message)?;
    writeln!(output)?;
    output.flush()?;
    Ok(())
}

fn status(run_id: &str) -> Result<Value> {
    let root = run_dir(run_id)?;
    if !root.exists() {
        return Ok(simple_report(run_id, "stopped"));
    }
    let observed = (|| {
        if let Ok(pending) = read_json::<Value>(&root.join(PENDING), MAXIMUM_RUN_REPORT_BYTES) {
            return Ok(pending_status(&root, run_id, pending));
        }
        if supervisor_gone(&root)? {
            return Err(RecoveryNeeded {
                run_id: run_id.to_owned(),
                facts: lost_supervisor_facts(&root, run_id),
            }
            .into());
        }
        let report: Value = read_json(&root.join(REPORT), MAXIMUM_RUN_REPORT_BYTES)
            .context("the development run has not reported readiness")?;
        if report["expires_at"]
            .as_u64()
            .is_some_and(|expiry| clock().is_ok_and(|now| now >= expiry))
        {
            return Ok(simple_report(run_id, "stopping"));
        }
        Ok(report)
    })();
    if observed.is_err() && !root.exists() {
        return Ok(simple_report(run_id, "stopped"));
    }
    observed
}

fn pending_status(root: &Path, run_id: &str, pending: Value) -> Value {
    let mut report = simple_report(run_id, "cleanup-pending");
    report["recovery"] = json!({
        "kind": "cleanup-pending",
        "run_directory": root,
        "databases_and_roles": pending["databases_and_roles"],
        "processes": pending["processes"],
    });
    report
}

fn token(run_id: &str, person: &str) -> Result<Value> {
    ensure!(plan::identifier(person), "invalid test person name");
    let report = status(run_id)?;
    ensure!(
        report["status"] == "ready",
        "development run {run_id} is not ready"
    );
    let root = run_dir(run_id)?;
    let input: RunInput = read_json(&root.join("input.json"), MAXIMUM_CAPTURED_INPUT_BYTES)?;
    let signer = Issuer::load(&root)?;
    let expires = report["expires_at"]
        .as_u64()
        .context("run expiry is missing")?;
    let subject = input
        .plan
        .people
        .get(person)
        .context("test person is not in the run's plan")?;
    let mut credentials = Vec::new();
    for (product, grant) in &subject.grants {
        let token = signer.token(&input, subject, *product, expires)?;
        let path = root.join(format!(
            "headers-{}-{person}-{}",
            product.name(),
            Uuid::new_v4().simple()
        ));
        let headers = match product {
            Product::Breg => format!("Authorization: Bearer {}\n", &*token),
            Product::Casework => format!("Authorization: Bearer {}\nRegistry-Casework-Profile: {}\nRegistry-Review-Profile: {}\n",
                &*token, grant.profile, grant.profile),
        };
        write_private(&path, Zeroizing::new(headers).as_bytes())?;
        credentials
            .push(json!({"product": product, "profile": grant.profile, "header_file": path}));
    }
    Ok(json!({
        "schema_version": SCHEMA, "run_id": run_id, "status": "token",
        "alias": person, "credentials": credentials, "expires_at": expires,
    }))
}

fn stop(run_id: &str) -> Result<Value> {
    let root = run_dir(run_id)?;
    if !root.exists() {
        return Ok(simple_report(run_id, "stopped"));
    }
    if let Err(error) = ensure_private(&root, false) {
        // The supervisor can finish and remove the run between the checks.
        if !root.exists() {
            return Ok(simple_report(run_id, "stopped"));
        }
        return Err(error);
    }
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("stop"))
    {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !root.exists() => {
            return Ok(simple_report(run_id, "stopped"));
        }
        Err(error) => return Err(error).context("cannot signal the run to stop"),
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    while root.exists() {
        ensure!(
            Instant::now() < deadline,
            "run {run_id} is still cleaning up or its cleanup has stalled; run rstack dev status {run_id} to see its state"
        );
        thread::sleep(POLL);
        if !root.exists() {
            break;
        }
        if let Ok(pending) = read_json::<Value>(&root.join(PENDING), MAXIMUM_RUN_REPORT_BYTES) {
            return Err(RecoveryNeeded {
                run_id: run_id.to_owned(),
                facts: pending_status(&root, run_id, pending)["recovery"].clone(),
            }
            .into());
        }
        let gone = supervisor_gone(&root);
        if root.exists() && gone? {
            return Err(RecoveryNeeded {
                run_id: run_id.to_owned(),
                facts: lost_supervisor_facts(&root, run_id),
            }
            .into());
        }
    }
    Ok(simple_report(run_id, "stopped"))
}

fn simple_report(run_id: &str, status: &str) -> Value {
    json!({"schema_version": SCHEMA, "run_id": run_id, "status": status})
}

/// Whether a supervisor that took its lock has since vanished. The lock file
/// appears just before the lock is taken, so a first sighting is confirmed
/// after one poll before it counts.
fn supervisor_gone(root: &Path) -> Result<bool> {
    for attempt in 0..2 {
        if !root.join("worker.lock").exists() || supervisor_running(root)? {
            return Ok(false);
        }
        if attempt == 0 {
            thread::sleep(POLL);
        }
    }
    Ok(true)
}

fn supervisor_running(root: &Path) -> Result<bool> {
    ensure_private(root, false)?;
    let lock =
        File::open(root.join("worker.lock")).context("run supervisor lock is unavailable")?;
    match flock(&lock, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(false),
        Err(rustix::io::Errno::WOULDBLOCK) => Ok(true),
        Err(error) => Err(error).context("cannot check run supervisor lock"),
    }
}

fn signals() -> Result<Arc<AtomicBool>> {
    let terminate = Arc::new(AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        signal_hook::flag::register(signal, terminate.clone())?;
    }
    Ok(terminate)
}

fn stopping(root: &Path, signals: &AtomicBool) -> bool {
    signals.load(Ordering::Relaxed) || root.join("stop").exists()
}

fn binary(product: Product, name: &str) -> Result<PathBuf> {
    let path = env::var_os(name).map(PathBuf::from).with_context(|| {
        format!(
            "{name} is not set; run rstack install {} or set {name}",
            product.name()
        )
    })?;
    let path = path
        .canonicalize()
        .with_context(|| format!("cannot resolve {name}"))?;
    ensure!(path.is_file(), "{name} must be a binary file");
    Ok(path)
}

fn product_tool(product: Product) -> Result<PathBuf> {
    binary(
        product,
        match product {
            Product::Breg => "RSTACK_BREGCTL_BIN",
            Product::Casework => "RSTACK_CASEWORKCTL_BIN",
        },
    )
}

fn binaries(product: Product) -> Result<Binaries> {
    Ok(match product {
        Product::Breg => Binaries {
            tool: product_tool(product)?,
            runtime: binary(product, "RSTACK_BREG_BIN")?,
        },
        Product::Casework => Binaries {
            tool: product_tool(product)?,
            runtime: binary(product, "RSTACK_CASEWORK_BIN")?,
        },
    })
}

fn parse_ttl(value: &str) -> Result<u64> {
    let error = || anyhow::anyhow!("--ttl must be between 1s and 24h, with an s, m, or h suffix");
    let (number, unit) = value
        .split_at_checked(value.len().saturating_sub(1))
        .ok_or_else(error)?;
    let seconds = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        _ => return Err(error()),
    };
    number
        .parse::<u64>()
        .ok()
        .and_then(|value| value.checked_mul(seconds))
        .filter(|seconds| (1..=86400).contains(seconds))
        .ok_or_else(error)
}

fn state_dir() -> PathBuf {
    env::var_os("RSTACK_DEV_STATE_DIR").map_or_else(
        || env::temp_dir().join(format!("rstack-dev-{}", rustix::process::getuid().as_raw())),
        PathBuf::from,
    )
}

fn run_dir(run_id: &str) -> Result<PathBuf> {
    ensure!(
        run_id.len() == 32
            && run_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid run ID; use the ID printed by rstack dev start"
    );
    Ok(state_dir().join(run_id))
}

fn private_directory(path: &Path) -> std::io::Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)
}

fn ensure_private(path: &Path, create: bool) -> Result<()> {
    if create {
        match private_directory(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).context("cannot create the development state directory")
            }
        }
    }
    let info =
        fs::symlink_metadata(path).context("cannot inspect the development state directory")?;
    ensure!(
        info.is_dir()
            && info.uid() == rustix::process::getuid().as_raw()
            && info.mode() & 0o077 == 0,
        "the development state directory must be owner-only and must not be a symlink"
    );
    Ok(())
}

fn capture_input(input: &RunInput) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(input)?;
    ensure!(
        bytes.len() as u64 <= MAXIMUM_CAPTURED_INPUT_BYTES,
        "captured development input exceeds the internal size limit"
    );
    Ok(bytes)
}

fn capture_report(report: &Value) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(report)?;
    ensure!(
        bytes.len() as u64 <= MAXIMUM_RUN_REPORT_BYTES,
        "development run report exceeds the internal size limit"
    );
    Ok(bytes)
}

/// Create `<run>/logs` and the owner-only supervisor log inside it.
fn open_supervisor_log(root: &Path) -> Result<File> {
    match private_directory(&root.join("logs")) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).context("cannot create the development log directory"),
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(root.join("logs").join("supervisor.log"))
        .context("cannot open the supervisor log")
}

fn failed_logs_dir(base: &Path, run_id: &str) -> PathBuf {
    base.join("failed").join(run_id).join("logs")
}

fn has_log_content(logs: &Path) -> Result<bool> {
    let entries = match fs::read_dir(logs) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("cannot read the development log directory"),
    };
    for entry in entries {
        if entry?.metadata()?.len() > 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Move a failed run's non-empty logs to `<state>/failed/<run_id>/logs`.
fn keep_logs(root: &Path, run_id: &str) -> Result<Option<PathBuf>> {
    let logs = root.join("logs");
    if !has_log_content(&logs)? {
        return Ok(None);
    }
    let base = root.parent().context("run directory has no parent")?;
    let target = failed_logs_dir(base, run_id);
    let run = target.parent().expect("failed run directory");
    let failed = run.parent().expect("failed directory");
    ensure_private(failed, true)?;
    match private_directory(run) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).context("cannot create the failed run log directory"),
    }
    ensure_private(run, false)?;
    fs::rename(&logs, &target).context("cannot keep the failed run logs")?;
    Ok(Some(target))
}

fn remove_failed_run(root: &Path, run_id: &str) -> Result<Option<PathBuf>> {
    let kept = keep_logs(root, run_id)?;
    remove_run_dir(root)?;
    Ok(kept)
}

/// Where a run directory goes while it is deleted. The name is not a run ID,
/// so `status` and `stop` never read it as a run.
fn removing_dir(root: &Path) -> Result<PathBuf> {
    let name = root.file_name().context("run directory has no name")?;
    Ok(root.with_file_name(format!(".{}.removing", name.to_string_lossy())))
}

/// Renames the run directory away before deleting it, so `status` sees either
/// the whole run or no run, never a run whose report is already deleted.
fn remove_run_dir(root: &Path) -> Result<()> {
    let doomed = removing_dir(root)?;
    fs::rename(root, &doomed).context("cannot remove run scratch files")?;
    fs::remove_dir_all(&doomed)
        .with_context(|| format!("cannot remove run scratch files at {}", doomed.display()))
}

fn note_kept_logs(error: anyhow::Error, kept: Option<PathBuf>) -> anyhow::Error {
    match kept {
        Some(path) => anyhow::anyhow!("{error:#}; logs kept at {}", path.display()),
        None => error,
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path, limit: u64) -> Result<T> {
    Ok(serde_json::from_slice(&plan::read(path, limit)?)?)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file =
        tempfile::NamedTempFile::new_in(path.parent().context("file has no directory")?)?;
    file.write_all(bytes)?;
    file.persist(path).map_err(|error| error.error)?;
    Ok(())
}

fn clock() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUN_ID: &str = "0123456789abcdef0123456789abcdef";

    fn fake_run(root: &Path, products: Value, postgis: bool) {
        let input = json!({
            "run_id": RUN_ID, "project": "/project", "ttl_seconds": 60,
            "plan": {
                "issuer": "https://issuer.example.invalid",
                "products": products,
                "people": {"operator": {
                    "subject": "operator", "client": "operator-client",
                    "grants": {"breg": {"profile": "operator", "scopes": []}}
                }},
                "journey": {"id": "smoke", "steps": [{
                    "id": "read", "product": "breg", "as": "operator",
                    "method": "GET", "path": "/v1/records",
                    "expect": {"status": 200}
                }]}
            },
            "schema_people": [],
            "breg_authority": {
                "principal": "p", "purpose": false,
                "requires_postgis": postgis, "named_clients": []
            },
            "casework_principals": {},
            "binaries": {}
        });
        fs::write(root.join("input.json"), input.to_string()).unwrap();
    }

    #[test]
    fn ttl_is_bounded_and_requires_a_unit() {
        assert_eq!(parse_ttl("1s").unwrap(), 1);
        assert_eq!(parse_ttl("30m").unwrap(), 1800);
        assert_eq!(parse_ttl("24h").unwrap(), 86400);
        for invalid in ["", "0s", "3600", "25h", "18446744073709551615h", "é"] {
            assert!(parse_ttl(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn expiry_follows_the_wall_clock() {
        assert!(!expired(99, 100));
        assert!(expired(100, 100));
        assert!(expired(101, 100));
    }

    #[test]
    fn cleanup_backs_off_from_two_to_thirty_seconds_and_stops_at_the_cap() {
        let delays: Vec<_> = cleanup_schedule(CLEANUP_CAP).map(|d| d.as_secs()).collect();
        assert_eq!(delays[..6], [2, 4, 8, 16, 30, 30]);
        let total: u64 = delays.iter().sum();
        assert!(total >= CLEANUP_CAP.as_secs());
        assert!(total - delays.last().unwrap() < CLEANUP_CAP.as_secs());
        assert_eq!(cleanup_schedule(Duration::ZERO).count(), 0);
    }

    #[test]
    fn lost_supervisor_facts_name_processes_databases_and_roles() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path();
        fake_run(
            root,
            json!([
                {"product": "breg", "project": ".", "audience": "registry"},
                {"product": "casework", "project": ".", "audience": "casework"}
            ]),
            true,
        );
        fs::write(
            root.join("processes.json"),
            json!([{"product": "breg", "pid": 4242, "pgid": 4242}]).to_string(),
        )
        .unwrap();
        let facts = lost_supervisor_facts(root, RUN_ID);
        assert_eq!(facts["kind"], "lost-supervisor");
        assert_eq!(facts["run_directory"], json!(root));
        assert_eq!(facts["processes"][0]["pgid"], 4242);
        let labels: Vec<_> = facts["objects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|object| object["label"].as_str().unwrap())
            .collect();
        assert_eq!(labels, ["breg_test", "breg", "casework"]);
        let breg = &facts["objects"][1];
        assert_eq!(breg["database"], format!("rstack_{RUN_ID}_breg"));
        // Migration, runtime and the spatial bbox role.
        assert_eq!(breg["roles"].as_array().unwrap().len(), 3);
        assert_eq!(facts["objects"][2]["roles"].as_array().unwrap().len(), 2);
        let text = recovery_message(RUN_ID, &facts);
        assert!(
            text.contains("process \"breg\" pid 4242 pgid 4242"),
            "{text}"
        );
        assert!(
            text.contains(&format!("breg database rstack_{RUN_ID}_breg")),
            "{text}"
        );
    }

    #[test]
    fn lost_supervisor_facts_survive_missing_files() {
        let scratch = tempfile::tempdir().unwrap();
        let facts = lost_supervisor_facts(scratch.path(), RUN_ID);
        assert_eq!(facts["processes"], json!([]));
        assert!(facts["unavailable"].is_string());
    }

    #[test]
    fn a_dead_supervisor_is_detected_only_once_its_lock_file_exists() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().canonicalize().unwrap();
        fs::set_permissions(&root, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        assert!(!supervisor_gone(&root).unwrap());
        let lock = File::create(root.join("worker.lock")).unwrap();
        assert!(supervisor_gone(&root).unwrap());
        flock(&lock, FlockOperation::NonBlockingLockExclusive).unwrap();
        assert!(!supervisor_gone(&root).unwrap());
    }

    #[test]
    fn pending_cleanup_reports_resources_and_processes() {
        let report = pending_report(RUN_ID, vec!["db".into(), "role".into()], json!([]));
        assert_eq!(report["databases_and_roles"], json!(["db", "role"]));
        let status = pending_status(Path::new("/run"), RUN_ID, report);
        assert_eq!(status["status"], "cleanup-pending");
        assert_eq!(status["recovery"]["databases_and_roles"][1], "role");
        let text = recovery_message(RUN_ID, &status["recovery"]);
        assert!(text.contains("database or role role"), "{text}");
    }

    #[test]
    fn a_run_directory_disappears_in_one_step_and_leaves_nothing() {
        let scratch = tempfile::tempdir().unwrap();
        let base = scratch.path().canonicalize().unwrap();
        let root = base.join(RUN_ID);
        private_directory(&root).unwrap();
        fs::write(root.join(REPORT), "{}").unwrap();
        private_directory(&root.join("logs")).unwrap();
        fs::write(root.join("logs").join("breg-check.log"), "boom").unwrap();
        let doomed = removing_dir(&root).unwrap();
        assert_eq!(doomed.parent(), Some(base.as_path()));
        assert!(run_dir(&doomed.file_name().unwrap().to_string_lossy()).is_err());
        remove_run_dir(&root).unwrap();
        assert!(!root.exists());
        assert_eq!(fs::read_dir(&base).unwrap().count(), 0);
    }

    #[test]
    fn failed_run_logs_move_out_of_the_run_directory() {
        let scratch = tempfile::tempdir().unwrap();
        let base = scratch.path().canonicalize().unwrap();
        let root = base.join(RUN_ID);
        private_directory(&root).unwrap();
        open_supervisor_log(&root).unwrap();
        assert_eq!(keep_logs(&root, RUN_ID).unwrap(), None, "empty logs stay");
        fs::write(root.join("logs").join("breg-check.log"), "boom").unwrap();
        let kept = remove_failed_run(&root, RUN_ID).unwrap().unwrap();
        assert_eq!(kept, failed_logs_dir(&base, RUN_ID));
        assert!(!root.exists());
        assert_eq!(
            fs::read_to_string(kept.join("breg-check.log")).unwrap(),
            "boom"
        );
        assert_eq!(
            fs::metadata(base.join("failed")).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(kept.join("supervisor.log")).unwrap().mode() & 0o777,
            0o600
        );
        // `failed` is not a run.
        assert!(run_dir("failed").is_err());
    }

    #[test]
    fn run_reports_are_bounded() {
        assert!(capture_report(&json!({"a": 1})).is_ok());
        let big = json!({"a": "x".repeat(MAXIMUM_RUN_REPORT_BYTES as usize)});
        assert!(capture_report(&big).is_err());
    }

    #[test]
    fn a_missing_binary_names_the_install_command() {
        let error = binaries(Product::Casework).err().unwrap().to_string();
        assert!(error.contains("rstack install casework"), "{error}");
        assert!(error.contains("RSTACK_CASEWORK_BIN"), "{error}");
    }
}
